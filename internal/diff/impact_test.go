package diff

import (
	"context"
	"fmt"
	"reflect"
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

func TestImpactRejectsDuplicateDeviceIdentity(t *testing.T) {
	tn := impactFixture()
	tn.Devices = append(tn.Devices, tn.Devices[0])
	if _, err := AccessImpact(context.Background(), tn, impactFixture(), ImpactOptions{}); err == nil {
		t.Fatal("duplicate identities would silently drop devices from the comparison")
	}
}

func fleet(n int, grants ...*tailnet.Grant) *tailnet.Tailnet {
	t := &tailnet.Tailnet{HasAccessRules: true, Grants: grants, Groups: map[string][]string{"group:eng": {"owner0@example.com"}}}
	for i := 0; i < n; i++ {
		t.Devices = append(t.Devices, &tailnet.Device{
			ID: fmt.Sprintf("n%d", i), Hostname: fmt.Sprintf("host%d", i),
			Owner:     fmt.Sprintf("owner%d@example.com", i%3),
			Addresses: []string{fmt.Sprintf("100.64.%d.%d", i/250, i%250+1)},
		})
	}
	return t
}

func TestAccessImpactScalesWithIdentitiesNotDevices(t *testing.T) {
	oldT := fleet(600)
	newT := fleet(600, &tailnet.Grant{Sources: []string{"group:eng"}, Destinations: []string{"autogroup:self"}, IP: []string{"tcp:22"}})
	r, err := AccessImpact(context.Background(), oldT, newT, ImpactOptions{Protocols: []string{"tcp"}, Port: "22"})
	if err != nil {
		t.Fatalf("600 devices sharing 3 identities should fit the budget: %v", err)
	}
	// owner0 has 200 devices, each reaching the other 199.
	if len(r.Changes) != 200*199 {
		t.Fatalf("changes = %d, want %d", len(r.Changes), 200*199)
	}
}

// Sharing results must never change the answer: compare against evaluating
// every pair directly, across rule shapes that depend on each device attribute.
func TestAccessImpactMatchesPairwiseEvaluation(t *testing.T) {
	rules := map[string]*tailnet.Grant{
		"identity":  {Sources: []string{"group:eng"}, Destinations: []string{"*"}, IP: []string{"tcp:22"}},
		"self":      {Sources: []string{"*"}, Destinations: []string{"autogroup:self"}, IP: []string{"tcp:22"}},
		"source ip": {Sources: []string{"100.64.0.2"}, Destinations: []string{"*"}, IP: []string{"tcp:22"}},
		"dest ip":   {Sources: []string{"*"}, Destinations: []string{"100.64.0.5"}, IP: []string{"tcp:22"}},
		"ipset":     {Sources: []string{"*"}, Destinations: []string{"ipset:few"}, IP: []string{"tcp:22"}},
	}
	for name, rule := range rules {
		t.Run(name, func(t *testing.T) {
			oldT, newT := fleet(9), fleet(9, rule)
			newT.IPSets = map[string][]string{"ipset:few": {"add 100.64.0.0/24", "remove 100.64.0.3"}}
			newT.Devices[4].Owner, newT.Devices[4].Tags = "", []string{"tag:db"}
			r, err := AccessImpact(context.Background(), oldT, newT, ImpactOptions{Protocols: []string{"tcp"}, Port: "22"})
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]bool{}
			for _, c := range r.Changes {
				got[c.Source+">"+c.Destination] = true
			}
			want := map[string]bool{}
			for i, s := range oldT.Devices {
				for j, d := range oldT.Devices {
					if i == j {
						continue
					}
					before := accessState(oldT, s, d, 22, "tcp")
					after := accessState(newT, newT.Devices[i], newT.Devices[j], 22, "tcp")
					if before != after {
						want[s.Hostname+">"+d.Hostname] = true
					}
				}
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("shared evaluation differs from pairwise:\n got %v\nwant %v", got, want)
			}
		})
	}
}

func TestImpactLabelsDisambiguateSharedHostnames(t *testing.T) {
	oldT := fleet(2)
	oldT.Devices[0].Hostname, oldT.Devices[0].Name = "laptop", "laptop.tail.ts.net."
	oldT.Devices[1].Hostname, oldT.Devices[1].Name = "laptop", "laptop-1.tail.ts.net."
	newT := fleet(2, &tailnet.Grant{Sources: []string{"*"}, Destinations: []string{"*"}, IP: []string{"tcp:22"}})
	newT.Devices[0], newT.Devices[1] = oldT.Devices[0], oldT.Devices[1]
	r, err := AccessImpact(context.Background(), oldT, newT, ImpactOptions{Protocols: []string{"tcp"}, Port: "22"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Changes) != 2 || r.Changes[0].Source == r.Changes[1].Source {
		t.Fatalf("changes = %+v", r.Changes)
	}
}
