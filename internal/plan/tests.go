package plan

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/huza1fa/taildoc/internal/policy"
	"github.com/huza1fa/taildoc/internal/tailnet"
)

// Outcomes of a policy test case.
const (
	TestPassed  = "passed"
	TestFailed  = "failed"
	TestUnknown = "unknown"
)

// PolicyTest is one entry of a policy file's tests section. The SDK's model
// lacks proto, so these are decoded here.
type PolicyTest struct {
	Source string
	Proto  string
	Accept []string
	Deny   []string
}

// TestResult is the outcome of one accept or deny expectation.
type TestResult struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Proto       string `json:"proto,omitempty"`
	Expected    string `json:"expected"` // accept or deny
	Outcome     string `json:"outcome"`
	Reason      string `json:"reason,omitempty"`
}

func parseTests(raw json.RawMessage) ([]PolicyTest, error) {
	if raw == nil {
		return nil, nil
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("tests must be an array of test objects: %w", err)
	}
	tests := make([]PolicyTest, 0, len(entries))
	for i, entry := range entries {
		var e struct {
			Source          string         `json:"src"`
			User            string         `json:"user"`
			Proto           string         `json:"proto"`
			Accept          []string       `json:"accept"`
			Allow           []string       `json:"allow"`
			Deny            []string       `json:"deny"`
			SrcPostureAttrs map[string]any `json:"srcPostureAttrs"`
		}
		if err := strictDecode(entry, &e); err != nil {
			return nil, fmt.Errorf("tests[%d]: %w", i, err)
		}
		if e.Proto != "" && !policy.ValidProtocol(e.Proto) {
			return nil, fmt.Errorf("tests[%d]: invalid protocol %q", i, e.Proto)
		}
		source := e.Source
		if source == "" {
			source = e.User
		}
		tests = append(tests, PolicyTest{source, e.Proto, append(e.Accept, e.Allow...), e.Deny})
	}
	return tests, nil
}

// RunTests evaluates each expectation against a policy using the local
// evaluator. Anything it cannot establish is unknown, not passed.
func RunTests(t *tailnet.Tailnet, tests []PolicyTest) []TestResult {
	results := []TestResult{}
	for _, test := range tests {
		for _, dst := range test.Accept {
			results = append(results, runTest(t, test, dst, "accept"))
		}
		for _, dst := range test.Deny {
			results = append(results, runTest(t, test, dst, "deny"))
		}
	}
	return results
}

func runTest(t *tailnet.Tailnet, test PolicyTest, dst, expected string) TestResult {
	result := TestResult{Source: test.Source, Destination: dst, Proto: test.Proto, Expected: expected, Outcome: TestUnknown}
	req := policy.Request{Proto: test.Proto}
	if result.Reason = testSource(t, test.Source, &req); result.Reason != "" {
		return result
	}
	if result.Reason = testDestination(t, dst, &req); result.Reason != "" {
		return result
	}
	verdict := policy.Evaluate(t, req)
	switch {
	case verdict.Allowed:
		result.Outcome = outcome(expected == "accept")
	case verdict.Indeterminate:
		result.Reason = "the rules that apply cannot be evaluated locally"
	default:
		result.Outcome = outcome(expected == "deny")
	}
	return result
}

func outcome(passed bool) string {
	if passed {
		return TestPassed
	}
	return TestFailed
}

func testSource(t *tailnet.Tailnet, ref string, req *policy.Request) string {
	switch {
	case ref == "":
		return "test has no source"
	case strings.HasPrefix(ref, "tag:"):
		req.SourceTags = []string{ref}
	case strings.Contains(ref, "@"):
		req.SourceLogin = ref
	default:
		d, ip, reason := testHost(t, ref)
		if reason != "" {
			return reason
		}
		if d != nil {
			between := policy.Between(d, nil, "", "")
			req.SourceLogin, req.SourceTags, req.SourceIPs = between.SourceLogin, between.SourceTags, between.SourceIPs
		} else {
			req.SourceIPs = []string{ip}
		}
	}
	return ""
}

func testDestination(t *tailnet.Tailnet, dst string, req *policy.Request) string {
	host, port, ok := policy.SplitDestination(dst)
	if !ok {
		return "destination is not host:port"
	}
	if port != "*" {
		if _, err := strconv.Atoi(port); err != nil {
			return "only a single destination port can be tested"
		}
		req.Port = port
	}
	if strings.HasPrefix(host, "tag:") {
		req.DestTags = []string{host}
		return ""
	}
	d, ip, reason := testHost(t, host)
	if reason != "" {
		return reason
	}
	if d != nil {
		between := policy.Between(nil, d, "", "")
		req.DestOwner, req.DestTags, req.DestIPs = between.DestOwner, between.DestTags, between.DestIPs
	} else {
		req.DestIPs = []string{ip}
	}
	return ""
}

// testHost resolves a name the way policy tests use it: a device, a host alias,
// or an IP address.
func testHost(t *tailnet.Tailnet, ref string) (*tailnet.Device, string, string) {
	target := ref
	if alias, ok := t.Hosts[ref]; ok {
		target = alias
	}
	switch matches := t.MatchDevices(target); len(matches) {
	case 0:
	case 1:
		return matches[0], "", ""
	default:
		return nil, "", fmt.Sprintf("%q matches %d devices", ref, len(matches))
	}
	if _, err := netip.ParseAddr(target); err != nil {
		return nil, "", fmt.Sprintf("%q is not a known device, host alias, or IP", ref)
	}
	return nil, target, ""
}

var failConditions = []string{"gained", "lost", "uncertain", "unknown", "tests"}

// ValidateFailOn rejects conditions that could never trigger, so a typo cannot
// silently disable a gate.
func ValidateFailOn(conditions []string) error {
	for _, c := range conditions {
		if !slices.Contains(failConditions, c) {
			return fmt.Errorf("unknown --fail-on condition %q (want %s)", c, strings.Join(failConditions, ", "))
		}
	}
	return nil
}

// FailureConditions returns the requested conditions the report meets.
func FailureConditions(r Report, conditions []string) []string {
	present := map[string]bool{"unknown": r.Impact.UnknownEvaluations > 0}
	for _, c := range r.Impact.Changes {
		present[c.Kind] = true
	}
	for _, result := range r.Tests {
		switch result.Outcome {
		case TestFailed:
			present["tests"] = true
		case TestUnknown:
			present["unknown"] = true
		}
	}
	met := []string{}
	for _, c := range conditions {
		if present[c] {
			met = append(met, c)
		}
	}
	return met
}
