package cli

import (
	"strings"
	"testing"

	"github.com/huza1fa/taildoc/internal/tailnet"
)

func sharedHostnameTailnet() *tailnet.Tailnet {
	return &tailnet.Tailnet{Devices: []*tailnet.Device{
		{Name: "laptop.tail.ts.net.", Hostname: "laptop", Owner: "alice@example.com", Addresses: []string{"100.64.0.1"}},
		{Name: "laptop-1.tail.ts.net.", Hostname: "laptop", Owner: "bob@example.com", Addresses: []string{"100.64.0.2"}},
	}}
}

func TestExplainRefusesAmbiguousDevices(t *testing.T) {
	tn := sharedHostnameTailnet()
	if _, _, err := resolveSource(tn, "laptop"); err == nil || !strings.Contains(err.Error(), "bob@example.com") {
		t.Errorf("resolveSource error = %v", err)
	}
	if _, _, err := resolveDestination(tn, "laptop"); err == nil || !strings.Contains(err.Error(), "laptop-1.tail.ts.net") {
		t.Errorf("resolveDestination error = %v", err)
	}
}

func TestExplainResolvesUniqueReferences(t *testing.T) {
	tn := sharedHostnameTailnet()
	for _, ref := range []string{"laptop-1", "laptop-1.tail.ts.net.", "100.64.0.2"} {
		d, _, err := resolveSource(tn, ref)
		if err != nil || d == nil || d.Owner != "bob@example.com" {
			t.Errorf("resolveSource(%q) = %+v, %v", ref, d, err)
		}
	}
}
