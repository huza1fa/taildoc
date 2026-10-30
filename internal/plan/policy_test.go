package plan

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/huza1fa/taildoc/internal/policy"
	"github.com/huza1fa/taildoc/internal/tailnet"
)

func TestParseHuJSONAndNormalize(t *testing.T) {
	acl, warnings, err := ParsePolicy([]byte(`{
        // Comments and trailing commas are allowed.
        "groups": {"group:eng": ["alice@example.com",],},
        "hosts": {"db": "100.64.0.2"},
        "ipsets": {"ipset:office": ["100.64.0.0/24"]},
        "tagOwners": {"tag:db": []},
        "autoApprovers": {"routes": {"10.0.0.0/8": ["tag:router"]}},
        "postures": {
            "posture:legacy": ["node:os == 'linux'"],
            "posture:modern": {"assertions": ["node:os == 'linux'"], "onFailure": {"showAlerts": ["warn-in-client"]}},
        },
        "defaultSrcPosture": ["posture:modern"],
        "acls": [{"action": "accept", "users": ["alice@example.com"], "ports": ["tag:db:22,80-81"], "proto": "tcp", "srcPosture": []}],
        "grants": [{"src": ["ipset:office"], "dst": ["db"], "ip": ["udp:53"]}],
        "ssh": [], "tests": [], "sshTests": [],
    }`))
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 2 || !strings.Contains(warnings[0], `"ssh"`) || !strings.Contains(warnings[1], `"sshTests"`) {
		t.Fatalf("unexpected ignored-section warnings: %v", warnings)
	}
	tn := &tailnet.Tailnet{}
	policy.Normalize(tn, acl)
	if len(tn.Postures["posture:modern"]) != 1 || len(tn.Postures["posture:legacy"]) != 1 || !tn.HasAccessRules || len(tn.Grants) != 2 {
		t.Fatalf("lost policy fields: %+v", tn)
	}
	result := policy.Evaluate(tn, policy.Request{SourceLogin: "alice@example.com", DestTags: []string{"tag:db"}, Port: "80", Proto: "tcp"})
	if !result.Allowed || result.Indeterminate {
		t.Fatalf("explicit empty posture must override the default: %+v", result)
	}
	result = policy.Evaluate(tn, policy.Request{SourceIPs: []string{"100.64.0.1"}, DestIPs: []string{"100.64.0.2"}, Port: "53", Proto: "udp"})
	if result.Allowed || !result.Indeterminate {
		t.Fatalf("posture must remain unknown: %+v", result)
	}
}

func TestParseRejectsAmbiguousOrMalformedPolicy(t *testing.T) {
	for _, input := range []string{
		``, `null`, `[]`, `true`, `{} {}`, `{"grants":[]`,
		`{"grants":[],"grants":[]}`, `{"grants":[],"gr\u0061nts":[]}`,
		`{"groups":{"group:eng":[],"group:eng":[]}}`,
		`{"grants":null}`, `{"grants":[null]}`, `{"groups":{"group:eng":[null]}}`,
		`{"Grants":[]}`, `{"grant":[]}`, `{"grants":{}}`,
		`{"grants":[{"src":["*"],"dst":["*"],"ip":["*"],"futureRestriction":true}]}`,
		`{"grants":[{"Src":["*"],"dst":["*"],"ip":["*"]}]}`,
		`{"grants":[{"src":[],"dst":["*"],"ip":["*"]}]}`,
		`{"grants":[{"src":[" "],"dst":["*"],"ip":["*"]}]}`,
		`{"grants":[{"src":["*"],"dst":["*"]}]}`,
		`{"grants":[{"src":["*"],"dst":["*"],"ip":["tcp:70000"]}]}`,
		`{"grants":[{"src":["*"],"dst":["*"],"ip":["tcp:22,bad"]}]}`,
		`{"grants":[{"src":["*"],"dst":["*"],"ip":["future:22"]}]}`,
		`{"grants":[{"src":["*"],"dst":["tag:db:22"],"ip":["*"]}]}`,
		`{"acls":[{"action":"deny","src":["*"],"dst":["*:22"]}]}`,
		`{"acls":[{"src":["*"],"dst":["*:22"]}]}`,
		`{"acls":[{"action":"accept","src":["*"],"dst":["tag:db:70000"]}]}`,
		`{"acls":[{"action":"accept","src":["*"],"dst":["tag:db"]}]}`,
		`{"acls":[{"action":"accept","src":["*"],"dst":[":22"]}]}`,
		`{"acls":[{"action":"accept","src":["*"],"users":["*"],"dst":["*:22"]}]}`,
		`{"acls":[{"action":"accept","src":["*"],"dst":["*:22"],"ports":["*:22"]}]}`,
		`{"acls":[{"action":"accept","src":["*"],"dst":["*:22"],"proto":"bad"}]}`,
		`{"autoApprovers":{"future":[]}}`, `{"hosts":{"db":[]}}`,
		`{"postures":{"posture:bad":{"assertions":[],"futureRestriction":true}}}`,
	} {
		t.Run(input, func(t *testing.T) {
			if _, _, err := ParsePolicy([]byte(input)); err == nil {
				t.Fatalf("accepted unsafe/malformed policy: %s", input)
			}
		})
	}
}

func TestParseLimitsAndDepthScanner(t *testing.T) {
	for _, input := range [][]byte{
		bytes.Repeat([]byte(" "), maxPolicyBytes+1),
		[]byte(strings.Repeat("[", 129) + strings.Repeat("]", 129)),
		{'{', '"', 0xff, '"', ':', '[', ']', '}'},
	} {
		if _, _, err := ParsePolicy(input); err == nil {
			t.Fatal("accepted oversized, deeply nested, or invalid UTF-8 input")
		}
	}
	// Brackets in escaped strings and comments must not consume nesting budget.
	input := `/* ` + strings.Repeat("[", 200) + ` */ {"tests":[{"src":"a\\\"` + strings.Repeat("[", 200) + `"}], // [[[` + "\n\"grants\": [],}"
	if _, _, err := ParsePolicy([]byte(input)); err != nil {
		t.Fatal(err)
	}
}

func TestLoadPolicy(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := LoadPolicy(dir); err == nil {
		t.Fatal("accepted a directory")
	}
	path := filepath.Join(dir, "policy.hujson")
	if _, _, err := LoadPolicy(path); err == nil {
		t.Fatal("accepted missing file")
	}
	if err := os.WriteFile(path, []byte(`{"grants":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadPolicy(path); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked.hujson")
	if err := os.Symlink(path, link); err == nil {
		if _, _, err := LoadPolicy(link); err != nil {
			t.Fatalf("symlink to a regular policy file: %v", err)
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	err = f.Truncate(maxPolicyBytes + 1)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadPolicy(path); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("missing size limit: %v", err)
	}
}

func FuzzParsePolicy(f *testing.F) {
	for _, seed := range []string{`{}`, `{"grants":[]}`, `{"grants":[{"src":["*"],"dst":["*"],"ip":["*"]}]}`, `{"grants":[],"grants":[]}`, `/* comment */ {"postures":{}}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		acl, _, err := ParsePolicy(input)
		if err == nil {
			tn := &tailnet.Tailnet{}
			policy.Normalize(tn, acl)
			policy.Evaluate(tn, policy.Request{SourceLogin: "alice@example.com", DestTags: []string{"tag:db"}, Port: "443", Proto: "tcp"})
		}
	})
}
