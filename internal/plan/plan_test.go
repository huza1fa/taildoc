package plan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/huza1fa/taildoc/internal/diff"
	"github.com/huza1fa/taildoc/internal/policy"
	"github.com/huza1fa/taildoc/internal/tailnet"
)

func fixture() *tailnet.Tailnet {
	return &tailnet.Tailnet{
		Name: "example.ts.net", CollectedAt: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC), HasAccessRules: true,
		Users: []*tailnet.User{{LoginName: "alice@example.com", Type: "member"}},
		Devices: []*tailnet.Device{
			{ID: "laptop", Hostname: "laptop", Owner: "alice@example.com", Addresses: []string{"100.64.0.1"}},
			{ID: "db", Hostname: "db", Tags: []string{"tag:db"}, Addresses: []string{"100.64.0.2"}},
		},
		Groups: map[string][]string{"group:eng": {"alice@example.com"}},
		Hosts:  map[string]string{"db": "100.64.0.2"},
		Grants: []*tailnet.Grant{{Sources: []string{"group:eng"}, Destinations: []string{"tag:db"}, IP: []string{"tcp:22"}}},
	}
}

func preview(t *testing.T, baseline *tailnet.Tailnet, input string, opts diff.ImpactOptions) Report {
	t.Helper()
	acl, warnings, err := ParsePolicy([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(baseline)
	policyBefore, _ := json.Marshal(acl)
	report, err := Preview(context.Background(), baseline, acl, warnings, opts)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(baseline)
	policyAfter, _ := json.Marshal(acl)
	if !bytes.Equal(before, after) || !bytes.Equal(policyBefore, policyAfter) {
		t.Fatal("preview mutated its inputs")
	}
	if report.BaselineCollectedAt != baseline.CollectedAt {
		t.Fatal("lost collection timestamp")
	}
	return report
}

func TestPreviewGainedLostAndMergedRanges(t *testing.T) {
	r := preview(t, fixture(), `{"grants":[{"src":["alice@example.com"],"dst":["tag:db"],"ip":["tcp:5432-5434","tcp:5435"]}]}`, diff.ImpactOptions{})
	if len(r.Impact.Changes) != 2 {
		t.Fatalf("unexpected access changes: %+v", r.Impact)
	}
	for i, expected := range []struct{ kind, ports string }{{"lost", "22"}, {"gained", "5432-5435"}} {
		c := r.Impact.Changes[i]
		if c.Kind != expected.kind || c.Ports != expected.ports || c.Protocol != "tcp" || c.Source != "laptop" || c.Destination != "db" {
			t.Fatalf("unexpected change: %+v", c)
		}
	}
	if r.Impact.UnknownEvaluations != 0 {
		t.Fatal("known rules yielded uncertainty")
	}
}

func TestPreviewDefaultAllowVersusExplicitEmptyRules(t *testing.T) {
	for _, tc := range []struct {
		input string
		kind  string
		warn  bool
	}{
		{`{}`, "gained", true},
		{`{"grants":[]}`, "lost", false},
		{`{"acls":[]}`, "lost", false},
	} {
		t.Run(tc.input, func(t *testing.T) {
			r := preview(t, fixture(), tc.input, diff.ImpactOptions{Source: "laptop", Destination: "db", Protocols: []string{"tcp"}})
			if len(r.Impact.Changes) == 0 || r.Impact.Changes[0].Kind != tc.kind {
				t.Fatalf("wrong default semantics: %+v", r.Impact)
			}
			if got := strings.Contains(strings.Join(r.Warnings, " "), "default allow-all"); got != tc.warn {
				t.Fatalf("default-policy warning = %v, want %v", got, tc.warn)
			}
		})
	}
}

func TestPreviewReplacesAllPolicyFields(t *testing.T) {
	base := fixture()
	base.TagOwners = map[string][]string{"tag:db": {"alice@example.com"}}
	base.IPSets = map[string][]string{"ipset:office": {"100.64.0.0/24"}}
	base.Postures = map[string][]string{"posture:trusted": {"node:os == 'linux'"}}
	base.DefaultSrcPosture = []string{"posture:trusted"}
	base.AutoApprovers = tailnet.AutoApprovers{Routes: map[string][]string{"10.0.0.0/8": {"tag:db"}}, ExitNode: []string{"tag:db"}}
	base.Devices[1].EnabledRoutes = []string{"10.0.0.0/8"}
	// Replacing the policy must drop the default posture, not just the grants.
	r := preview(t, base, `{"grants":[{"src":["alice@example.com"],"dst":["tag:db"],"ip":["tcp:22"]}]}`, diff.ImpactOptions{Source: "laptop", Destination: "db", Port: "22", Protocols: []string{"tcp"}})
	if len(r.Impact.Changes) != 1 || r.Impact.Changes[0].After != "allowed" || r.Impact.Changes[0].Before != "unknown" {
		t.Fatalf("default posture leaked into candidate: %+v", r.Impact)
	}
	acl, _, _ := ParsePolicy([]byte(`{"grants":[]}`))
	candidate := *base
	policy.Normalize(&candidate, acl)
	if len(candidate.Groups)+len(candidate.TagOwners)+len(candidate.Hosts)+len(candidate.Postures)+len(candidate.IPSets)+len(candidate.DefaultSrcPosture)+len(candidate.AutoApprovers.Routes)+len(candidate.AutoApprovers.ExitNode) != 0 {
		t.Fatal("stale policy fields survived replacement")
	}
	if len(candidate.Devices[1].EnabledRoutes) != 1 || candidate.CollectedAt != base.CollectedAt || candidate.Users[0] != base.Users[0] {
		t.Fatal("replacement altered inventory")
	}
}

func TestPreviewUncertaintyIncludingUnchangedUnknown(t *testing.T) {
	opts := diff.ImpactOptions{Source: "laptop", Destination: "db", Port: "22", Protocols: []string{"tcp"}}
	for _, condition := range []string{`,"srcPosture":["posture:trusted"]`, `,"via":["tag:router"]`} {
		input := `{"grants":[{"src":["alice@example.com"],"dst":["tag:db"],"ip":["tcp:22"]` + condition + `}]}`
		r := preview(t, fixture(), input, opts)
		if len(r.Impact.Changes) != 1 || r.Impact.Changes[0].Kind != "uncertain" || r.Impact.UnknownEvaluations != 1 {
			t.Fatalf("condition was not uncertain: %+v", r.Impact)
		}
		base := fixture()
		acl, _, _ := ParsePolicy([]byte(input))
		policy.Normalize(base, acl)
		r = preview(t, base, input, opts)
		if len(r.Impact.Changes) != 0 || r.Impact.UnknownEvaluations != 2 || !strings.Contains(strings.Join(r.Warnings, " "), "unchanged unknown") {
			t.Fatalf("unchanged uncertainty was hidden: %+v", r)
		}
	}
	// Unknown selectors must never turn into certain allow or certain denial.
	r := preview(t, fixture(), `{"grants":[{"src":["svc:future"],"dst":["tag:db"],"ip":["tcp:22"]}]}`, opts)
	if r.Impact.UnknownEvaluations != 1 || r.Impact.Changes[0].Kind != "uncertain" {
		t.Fatalf("unsupported selector: %+v", r.Impact)
	}
}

func TestPreviewRedundancyAppOnlyAndTaggedIdentity(t *testing.T) {
	base := fixture()
	r := preview(t, base, `{"groups":{"group:eng":["alice@example.com"]},"grants":[{"src":["group:eng"],"dst":["tag:db"],"ip":["tcp:22"]},{"src":["alice@example.com"],"dst":["tag:db"],"ip":["tcp:22"]}]}`, diff.ImpactOptions{})
	if len(r.Impact.Changes) != 0 || len(r.Changes) == 0 {
		t.Fatal("redundant policy change should not change access")
	}
	r = preview(t, base, `{"grants":[{"src":["*"],"dst":["*"],"app":{"example.com/cap":[{}]}}]}`, diff.ImpactOptions{})
	if len(r.Impact.Changes) != 1 || r.Impact.Changes[0].Kind != "lost" {
		t.Fatalf("app capabilities granted packet access: %+v", r.Impact)
	}
	base.Devices[0].Tags = []string{"tag:laptop"}
	r = preview(t, base, `{"grants":[{"src":["alice@example.com"],"dst":["tag:db"],"ip":["*"]}]}`, diff.ImpactOptions{})
	if len(r.Impact.Changes) != 0 {
		t.Fatal("tagged device inherited owner identity")
	}
}

func TestPreviewFiltersLimitsAndCancellation(t *testing.T) {
	acl, _, _ := ParsePolicy([]byte(`{"grants":[]}`))
	for _, opts := range []diff.ImpactOptions{
		{Source: "missing"}, {Destination: "missing"}, {Port: "65536"}, {Protocols: []string{"icmp"}}, {MaxEvaluations: 1},
	} {
		if _, err := Preview(context.Background(), fixture(), acl, nil, opts); err == nil {
			t.Fatalf("accepted bad/expensive scope: %+v", opts)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Preview(ctx, fixture(), acl, nil, diff.ImpactOptions{}); err != context.Canceled {
		t.Fatalf("ignored cancellation: %v", err)
	}
	if _, err := Preview(ctx, &tailnet.Tailnet{}, acl, nil, diff.ImpactOptions{}); err == nil {
		t.Fatal("accepted empty inventory")
	}
	if _, err := Preview(ctx, nil, acl, nil, diff.ImpactOptions{}); err == nil {
		t.Fatal("accepted nil baseline")
	}
	base := fixture()
	base.CollectedAt = time.Time{}
	r, err := Preview(context.Background(), base, acl, nil, diff.ImpactOptions{Source: "laptop", Destination: "laptop"})
	if err != nil || r.Impact.Evaluations != 0 || !strings.Contains(strings.Join(r.Warnings, " "), "No distinct device pairs") || !strings.Contains(strings.Join(r.Warnings, " "), "freshness") {
		t.Fatalf("empty scope/freshness warnings: %+v %v", r, err)
	}
}

func TestPreviewMembershipAndIPSetChanges(t *testing.T) {
	r := preview(t, fixture(), `{"groups":{"group:eng":[]},"grants":[{"src":["group:eng"],"dst":["tag:db"],"ip":["tcp:22"]}]}`, diff.ImpactOptions{Source: "laptop", Destination: "db", Port: "22", Protocols: []string{"tcp"}})
	if len(r.Impact.Changes) != 1 || r.Impact.Changes[0].Kind != "lost" {
		t.Fatalf("removed membership did not remove access: %+v", r.Impact)
	}
	r = preview(t, fixture(), `{"ipsets":{"ipset:office":["100.64.0.0/24"]},"hosts":{"database":"100.64.0.2"},"grants":[{"src":["ipset:office"],"dst":["database"],"ip":["sctp:65535","udp:0"]}]}`, diff.ImpactOptions{Source: "100.64.0.1", Destination: "100.64.0.2", Port: "65535", Protocols: []string{"sctp"}})
	if len(r.Impact.Changes) != 1 || r.Impact.Changes[0].Kind != "gained" || r.Impact.Changes[0].Ports != "65535" || r.Impact.Changes[0].Protocol != "sctp" {
		t.Fatalf("SCTP/IP set/alias or upper port boundary: %+v", r.Impact)
	}
	r = preview(t, fixture(), `{"grants":[{"src":["alice@example.com"],"dst":["tag:db"],"ip":["udp:0"]}]}`, diff.ImpactOptions{Source: "laptop", Destination: "db", Port: "0", Protocols: []string{"udp"}})
	if len(r.Impact.Changes) != 1 || r.Impact.Changes[0].Ports != "0" || r.Impact.Changes[0].Kind != "gained" {
		t.Fatalf("lower port boundary: %+v", r.Impact)
	}
}

func BenchmarkPreview(b *testing.B) {
	base := fixture()
	for i := 2; i < 100; i++ {
		base.Devices = append(base.Devices, &tailnet.Device{ID: fmt.Sprint(i), Hostname: fmt.Sprintf("host-%d", i), Owner: "alice@example.com", Addresses: []string{fmt.Sprintf("100.64.0.%d", i+1)}})
	}
	acl, warnings, err := ParsePolicy([]byte(`{"grants":[{"src":["*"],"dst":["tag:db"],"ip":["tcp:22","tcp:443","udp:53"]}]}`))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Preview(context.Background(), base, acl, warnings, diff.ImpactOptions{}); err != nil {
			b.Fatal(err)
		}
	}
}
