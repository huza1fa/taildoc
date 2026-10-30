package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/huza1fa/taildoc/internal/snapshot"
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

func TestExplainExitCodes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json")
	tn := sharedHostnameTailnet()
	tn.HasAccessRules = true
	tn.Devices = append(tn.Devices, &tailnet.Device{ID: "3", Name: "db.tail.ts.net.", Hostname: "db", Tags: []string{"tag:db"}, Addresses: []string{"100.64.0.3"}})
	tn.Grants = []*tailnet.Grant{
		{Sources: []string{"bob@example.com", "tag:db"}, Destinations: []string{"tag:db"}, IP: []string{"tcp:5432"}},
		{Sources: []string{"alice@example.com"}, Destinations: []string{"tag:db"}, IP: []string{"tcp:22"}, SrcPosture: []string{"posture:x"}},
	}
	if err := snapshot.Save(tn, path); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		src, dst string
		want     int
	}{
		{"laptop-1", "db:5432", 0},
		{"tag:db", "db:5432", 0},
		{"laptop", "db:5432", 1}, // ambiguous hostname
		{"laptop.tail.ts.net.", "db:5432", 4},
		{"laptop.tail.ts.net.", "db:22", 5},
	} {
		if got := Run([]string{"explain", "--snapshot", path, "--json", "--exit-code", c.src, c.dst}); got != c.want {
			t.Errorf("explain %s %s exit = %d, want %d", c.src, c.dst, got, c.want)
		}
	}
	if got := Run([]string{"explain", "--snapshot", path, "--json", "laptop.tail.ts.net.", "db:5432"}); got != 0 {
		t.Errorf("without --exit-code a denial must exit 0, got %d", got)
	}
}
