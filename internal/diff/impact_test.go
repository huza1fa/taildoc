package diff

import (
	"context"
	"testing"

	"github.com/huza1fa/taildoc/internal/tailnet"
)

func impactFixture() *tailnet.Tailnet {
	return &tailnet.Tailnet{HasAccessRules: true, Devices: []*tailnet.Device{
		{ID: "laptop", Hostname: "laptop", Owner: "alice@example.com", Addresses: []string{"100.64.0.1"}},
		{ID: "db", Hostname: "db", Tags: []string{"tag:db"}, Addresses: []string{"100.64.0.2"}},
	}, Groups: map[string][]string{"group:eng": {"alice@example.com"}}}
}
func TestAccessImpactIntervalsAndRedundantRules(t *testing.T) {
	oldT, newT := impactFixture(), impactFixture()
	g := &tailnet.Grant{Sources: []string{"group:eng"}, Destinations: []string{"tag:db"}, IP: []string{"tcp:5432-5434"}}
	newT.Grants = []*tailnet.Grant{g}
	r, err := AccessImpact(context.Background(), oldT, newT, ImpactOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Changes) != 1 || r.Changes[0].Kind != "gained" || r.Changes[0].Ports != "5432-5434" || r.Changes[0].Source != "laptop" {
		t.Fatalf("unexpected impact: %+v", r)
	}
	oldT.Grants = []*tailnet.Grant{g, g}
	r, err = AccessImpact(context.Background(), oldT, newT, ImpactOptions{})
	if err != nil || len(r.Changes) != 0 {
		t.Fatalf("redundant rule removal changed access: %+v %v", r, err)
	}
}
func TestAccessImpactMembershipLossAndUncertainty(t *testing.T) {
	oldT, newT := impactFixture(), impactFixture()
	g := &tailnet.Grant{Sources: []string{"group:eng"}, Destinations: []string{"tag:db"}, IP: []string{"tcp:443"}}
	oldT.Grants = []*tailnet.Grant{g}
	newT.Grants = []*tailnet.Grant{g}
	newT.Groups = map[string][]string{"group:eng": {}}
	opts := ImpactOptions{Port: "443", Source: "laptop", Destination: "db"}
	r, err := AccessImpact(context.Background(), oldT, newT, opts)
	if err != nil || len(r.Changes) != 1 || r.Changes[0].Kind != "lost" {
		t.Fatalf("membership loss: %+v %v", r, err)
	}
	newT.Groups = oldT.Groups
	conditional := *g
	conditional.SrcPosture = []string{"posture:trusted"}
	newT.Grants = []*tailnet.Grant{&conditional}
	r, err = AccessImpact(context.Background(), oldT, newT, opts)
	if err != nil || len(r.Changes) != 1 || r.Changes[0].Kind != "uncertain" || r.Changes[0].After != "unknown" {
		t.Fatalf("uncertainty: %+v %v", r, err)
	}
}
func TestImpactBudgetCancellationAndAbsentDevices(t *testing.T) {
	oldT, newT := impactFixture(), impactFixture()
	if _, err := AccessImpact(context.Background(), oldT, newT, ImpactOptions{MaxEvaluations: 1}); err == nil {
		t.Fatal("missing cost limit")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := AccessImpact(ctx, oldT, newT, ImpactOptions{}); err == nil {
		t.Fatal("ignored cancellation")
	}
	oldT.Devices = nil
	newT.HasAccessRules = false
	r, err := AccessImpact(context.Background(), oldT, newT, ImpactOptions{Port: "443", Protocols: []string{"tcp"}})
	if err != nil || len(r.Changes) != 2 || r.Changes[0].Before != "absent" {
		t.Fatalf("new devices: %+v %v", r, err)
	}
}
