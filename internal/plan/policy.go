// Package plan previews a replacement policy against a fixed, offline inventory.
// It does not validate policies with Tailscale or make any API calls.
package plan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/tailscale/hujson"
	"tailscale.com/client/tailscale/v2"

	"github.com/huza1fa/taildoc/internal/policy"
)

const maxPolicyBytes = 4 << 20

// Proposal is a parsed replacement policy and the tests it carries.
type Proposal struct {
	ACL      *tailscale.ACL
	Tests    []PolicyTest
	Warnings []string
}

// LoadPolicy reads a proposal and returns only its policy and warnings.
func LoadPolicy(path string) (*tailscale.ACL, []string, error) {
	proposal, err := LoadProposal(path)
	if err != nil {
		return nil, nil, err
	}
	return proposal.ACL, proposal.Warnings, nil
}

// LoadProposal bounds allocation before reading and rejects non-regular files.
// Symlinks to regular files are allowed, as with other local input files.
func LoadProposal(path string) (*Proposal, error) {
	// Check before opening too: opening a named pipe for reading can block.
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat policy %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("policy %q must be a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open policy %q: %w", path, err)
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("policy %q must be a regular file", path)
	}
	if info.Size() > maxPolicyBytes {
		return nil, fmt.Errorf("policy %q exceeds %d byte limit", path, maxPolicyBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxPolicyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read policy %q: %w", path, err)
	}
	proposal, err := parseProposal(data)
	if err != nil {
		return nil, fmt.Errorf("parse policy %q: %w", path, err)
	}
	return proposal, nil
}

// ParsePolicy accepts HuJSON but deliberately rejects ambiguous input and
// unknown packet-rule fields. Ignoring a future restriction could falsely
// report a certain allow. Non-packet sections are disclosed, not evaluated.
func ParsePolicy(data []byte) (*tailscale.ACL, []string, error) {
	proposal, err := parseProposal(data)
	if err != nil {
		return nil, nil, err
	}
	return proposal.ACL, proposal.Warnings, nil
}

func parseProposal(data []byte) (*Proposal, error) {
	if len(data) > maxPolicyBytes {
		return nil, fmt.Errorf("policy exceeds %d byte limit", maxPolicyBytes)
	}
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("policy must be UTF-8")
	}
	if err := checkDepth(data); err != nil {
		return nil, err
	}
	v, err := hujson.Parse(data)
	if err != nil {
		return nil, err
	}
	if _, ok := v.Value.(*hujson.Object); !ok {
		return nil, fmt.Errorf("policy must be an object")
	}
	if err := checkValues(v); err != nil {
		return nil, err
	}
	v.Standardize()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(v.Pack(), &fields); err != nil {
		return nil, err
	}
	var warnings []string
	// Stable ordering makes both diagnostics and machine-readable output repeatable.
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		switch key {
		case "acls", "grants", "groups", "hosts", "tagOwners", "ipsets", "postures", "defaultSrcPosture", "autoApprovers":
		case "tests":
		case "ssh", "sshTests", "nodeAttrs", "derpMap", "disableIPv4", "oneCGNATRoute", "randomizeClientPort", "attrConfig":
			warnings = append(warnings, fmt.Sprintf("Policy section %q is outside this packet-access preview and is not evaluated or validated.", key))
			delete(fields, key)
		default:
			return nil, fmt.Errorf("unknown policy section %q; refusing to ignore possible access semantics", key)
		}
	}
	tests, err := parseTests(fields["tests"])
	if err != nil {
		return nil, err
	}
	delete(fields, "tests")
	for _, key := range []string{"acls", "grants"} {
		if raw, ok := fields[key]; ok {
			if err := checkRules(key, raw); err != nil {
				return nil, err
			}
		}
	}
	// The SDK only models legacy posture arrays. Preserve object assertions too;
	// the evaluator still labels any applicable posture requirement as unknown.
	postures, err := parsePostures(fields["postures"])
	if err != nil {
		return nil, err
	}
	delete(fields, "postures")
	encoded, err := json.Marshal(fields)
	if err != nil {
		return nil, err
	}
	var acl tailscale.ACL
	if err := strictDecode(encoded, &acl); err != nil {
		return nil, err
	}
	acl.Postures = postures
	if err := validateRules(&acl); err != nil {
		return nil, err
	}
	if acl.ACLs == nil && acl.Grants == nil {
		warnings = append(warnings, "Proposed policy omits both acls and grants; the local evaluator uses Tailscale's default allow-all packet policy.")
	}
	return &Proposal{&acl, tests, warnings}, nil
}

func strictDecode(data []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(dst)
}

func checkRules(kind string, raw json.RawMessage) error {
	var rules []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rules); err != nil {
		return fmt.Errorf("%s must be an array of rule objects: %w", kind, err)
	}
	for i, rule := range rules {
		for key := range rule {
			switch key {
			case "src", "dst", "srcPosture":
				continue
			case "ip", "app", "via":
				if kind == "grants" {
					continue
				}
			case "action", "users", "ports", "proto":
				if kind == "acls" {
					continue
				}
			}
			return fmt.Errorf("%s[%d]: unknown field %q", kind, i, key)
		}
		if kind == "acls" && ((rule["src"] != nil && rule["users"] != nil) || (rule["dst"] != nil && rule["ports"] != nil)) {
			return fmt.Errorf("acls[%d]: do not mix src/users or dst/ports aliases", i)
		}
	}
	return nil
}

func validateRules(acl *tailscale.ACL) error {
	checkSelectors := func(src, dst []string) error {
		if len(src) == 0 || len(dst) == 0 {
			return fmt.Errorf("src and dst must be non-empty")
		}
		for _, selectors := range [][]string{src, dst} {
			for _, s := range selectors {
				if strings.TrimSpace(s) == "" {
					return fmt.Errorf("selectors must not be empty")
				}
			}
		}
		return nil
	}
	for i, g := range acl.Grants {
		if err := checkSelectors(g.Source, g.Destination); err != nil {
			return fmt.Errorf("grants[%d]: %w", i, err)
		}
		if len(g.IP) == 0 && len(g.App) == 0 {
			return fmt.Errorf("grants[%d]: ip or app permissions are required", i)
		}
		for _, d := range g.Destination {
			host, _, ok := policy.SplitDestination(d)
			if !ok || host != d {
				return fmt.Errorf("grants[%d]: destination %q must be a selector without ports (use ip for ports)", i, d)
			}
		}
		for _, entry := range g.IP {
			proto, ports, qualified := strings.Cut(entry, ":")
			if !qualified {
				ports = entry
			}
			if len(policy.PortRanges(ports)) == 0 || (qualified && proto != "*" && !policy.ValidProtocol(proto)) {
				return fmt.Errorf("grants[%d]: invalid ip expression %q", i, entry)
			}
		}
	}
	for i, e := range acl.ACLs {
		src, dst := e.Source, e.Destination
		if src == nil {
			src = e.Users
		}
		if dst == nil {
			dst = e.Ports
		}
		if err := checkSelectors(src, dst); err != nil {
			return fmt.Errorf("acls[%d]: %w", i, err)
		}
		if e.Action != "accept" || (e.Protocol != "" && !policy.ValidProtocol(e.Protocol)) {
			return fmt.Errorf("acls[%d]: expected action accept and a valid protocol", i)
		}
		for _, d := range dst {
			if host, _, ok := policy.SplitDestination(d); !ok || host == "" || host == d {
				return fmt.Errorf("acls[%d]: invalid destination %q", i, d)
			}
		}
	}
	return nil
}

func parsePostures(raw json.RawMessage) (map[string][]string, error) {
	if raw == nil {
		return nil, nil
	}
	var entries map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("postures: %w", err)
	}
	postures := make(map[string][]string, len(entries))
	for name, value := range entries {
		var assertions []string
		if len(value) > 0 && value[0] == '{' {
			var posture struct {
				Assertions []string        `json:"assertions"`
				OnFailure  json.RawMessage `json:"onFailure"`
			}
			if err := strictDecode(value, &posture); err != nil {
				return nil, fmt.Errorf("posture %q: %w", name, err)
			}
			assertions = posture.Assertions
		} else if err := json.Unmarshal(value, &assertions); err != nil {
			return nil, fmt.Errorf("posture %q: %w", name, err)
		}
		postures[name] = assertions
	}
	return postures, nil
}

func checkValues(v hujson.Value) error {
	switch value := v.Value.(type) {
	case *hujson.Object:
		seen := make(map[string]bool, len(value.Members))
		for _, member := range value.Members {
			name := member.Name.Value.(hujson.Literal).String()
			if seen[name] {
				return fmt.Errorf("duplicate object key %q", name)
			}
			seen[name] = true
			if err := checkValues(member.Value); err != nil {
				return err
			}
		}
	case *hujson.Array:
		for _, item := range value.Elements {
			if err := checkValues(item); err != nil {
				return err
			}
		}
	case hujson.Literal:
		if value.Kind() == 'n' {
			return fmt.Errorf("null policy values are not supported; use explicit objects or arrays")
		}
	}
	return nil
}

// Bound nesting before invoking the recursive HuJSON parser. Strings and both
// comment forms are skipped; syntax validation remains the parser's job.
func checkDepth(data []byte) error {
	depth := 0
	for i := 0; i < len(data); i++ {
		switch data[i] {
		case '"':
			for i++; i < len(data); i++ {
				if data[i] == '\\' {
					i++
				} else if data[i] == '"' {
					break
				}
			}
		case '/':
			if i+1 < len(data) && data[i+1] == '/' {
				for i += 2; i < len(data) && data[i] != '\n'; i++ {
				}
			} else if i+1 < len(data) && data[i+1] == '*' {
				for i += 2; i+1 < len(data) && !(data[i] == '*' && data[i+1] == '/'); i++ {
				}
				i++
			}
		case '{', '[':
			depth++
			if depth > 128 {
				return fmt.Errorf("policy nesting exceeds 128 levels")
			}
		case '}', ']':
			depth--
		}
	}
	return nil
}
