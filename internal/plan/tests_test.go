package plan

import (
	"context"
	"testing"

	"github.com/huza1fa/taildoc/internal/diff"
	"github.com/huza1fa/taildoc/internal/tailnet"
)

func testTailnet() *tailnet.Tailnet {
	return &tailnet.Tailnet{
		Users: []*tailnet.User{{LoginName: "alice@example.com", Type: "member"}},
		Devices: []*tailnet.Device{
			{ID: "1", Name: "laptop.tail.ts.net.", Hostname: "laptop", Owner: "alice@example.com", Addresses: []string{"100.64.0.1"}},
			{ID: "2", Name: "db.tail.ts.net.", Hostname: "db", Tags: []string{"tag:db"}, Addresses: []string{"100.64.0.2"}},
			{ID: "3", Name: "phone.tail.ts.net.", Hostname: "phone", Owner: "alice@example.com", Addresses: []string{"100.64.0.3"}},
			{ID: "4", Name: "phone-1.tail.ts.net.", Hostname: "phone", Owner: "bob@example.com", Addresses: []string{"100.64.0.4"}},
		},
	}
}

func TestPolicyTestsRunAgainstTheProposal(t *testing.T) {
	proposal, err := parseProposal([]byte(`{
		"hosts": {"db-alias": "100.64.0.2"},
		"grants": [{"src": ["alice@example.com"], "dst": ["tag:db"], "ip": ["tcp:5432"]},
		           {"src": ["tag:db"], "dst": ["tag:db"], "ip": ["tcp:22"], "srcPosture": ["posture:x"]}],
		"tests": [
			{"src": "alice@example.com", "proto": "tcp", "accept": ["tag:db:5432"], "deny": ["tag:db:22"]},
			{"src": "laptop", "accept": ["db-alias:5432", "100.64.0.2:443"]},
			{"user": "alice@example.com", "allow": ["db:5432"]},
			{"src": "tag:db", "accept": ["tag:db:22"]},
			{"src": "phone", "accept": ["db:5432"]},
			{"src": "alice@example.com", "accept": ["db:5432-5433", "missing:22"]}
		]}`))
	if err != nil {
		t.Fatal(err)
	}
	baseline := testTailnet()
	r, err := Preview(context.Background(), baseline, proposal.ACL, proposal.Warnings, diff.ImpactOptions{}, proposal.Tests...)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		TestPassed, TestPassed, // tag selectors
		TestPassed, TestFailed, // alias, then a port the proposal does not allow
		TestPassed,  // user and allow aliases
		TestUnknown, // posture cannot be evaluated
		TestUnknown, // hostname shared by two devices
		TestUnknown, TestUnknown,
	}
	if len(r.Tests) != len(want) {
		t.Fatalf("got %d results: %+v", len(r.Tests), r.Tests)
	}
	for i, w := range want {
		if r.Tests[i].Outcome != w {
			t.Errorf("test %d = %+v, want %s", i, r.Tests[i], w)
		}
	}
}

func TestParseTestsRejectsMalformedEntries(t *testing.T) {
	for _, input := range []string{
		`{"tests": {}}`,
		`{"tests": [{"src": "a", "bogus": []}]}`,
		`{"tests": [{"src": "a", "proto": "nope", "accept": ["b:1"]}]}`,
	} {
		if _, err := parseProposal([]byte(input)); err == nil {
			t.Errorf("%s: expected an error", input)
		}
	}
}

func TestFailureConditions(t *testing.T) {
	r := Report{
		Impact: diff.ImpactReport{Changes: []diff.AccessChange{{Kind: "gained"}}},
		Tests:  []TestResult{{Outcome: TestFailed}},
	}
	all := []string{"gained", "lost", "uncertain", "unknown", "tests"}
	if got := FailureConditions(r, all); len(got) != 2 || got[0] != "gained" || got[1] != "tests" {
		t.Errorf("met = %v", got)
	}
	if got := FailureConditions(Report{}, all); len(got) != 0 {
		t.Errorf("clean report met %v", got)
	}
	r = Report{Tests: []TestResult{{Outcome: TestUnknown}}}
	if got := FailureConditions(r, all); len(got) != 1 || got[0] != "unknown" {
		t.Errorf("unknown test met %v", got)
	}
	if err := ValidateFailOn([]string{"gaind"}); err == nil {
		t.Error("expected a typo to be rejected")
	}
}
