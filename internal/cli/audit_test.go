package cli

import (
	"path/filepath"
	"testing"

	"github.com/huza1fa/taildoc/internal/audit"
	"github.com/huza1fa/taildoc/internal/snapshot"
	"github.com/huza1fa/taildoc/internal/tailnet"
)

func TestExceedsFailOn(t *testing.T) {
	cases := []struct {
		counts map[audit.Severity]int
		failOn string
		want   bool
	}{
		{map[audit.Severity]int{audit.High: 1}, "high", true},
		{map[audit.Severity]int{audit.High: 1}, "info", true},
		{map[audit.Severity]int{audit.Medium: 1}, "high", false},
		{map[audit.Severity]int{audit.Medium: 1}, "medium", true},
		{map[audit.Severity]int{audit.Info: 1}, "low", false},
		{map[audit.Severity]int{audit.High: 0}, "high", false},
		{map[audit.Severity]int{audit.High: 1}, "none", false},
		{map[audit.Severity]int{}, "info", false},
	}
	for _, c := range cases {
		if got := exceedsFailOn(c.counts, c.failOn); got != c.want {
			t.Errorf("exceedsFailOn(%v, %q) = %t, want %t", c.counts, c.failOn, got, c.want)
		}
	}
}

func TestAuditExitCodes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json")
	tn := &tailnet.Tailnet{Grants: []*tailnet.Grant{{Sources: []string{"*"}, Destinations: []string{"*"}, IP: []string{"*"}}}}
	if err := snapshot.Save(tn, path); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		args []string
		want int
	}{
		{[]string{"--fail-on", "high"}, 3},
		{[]string{"--fail-on", "high", "--only", "stale-devices"}, 0},
		{[]string{"--fail-on", "nope"}, 2},
		{[]string{"--only", "typo-check"}, 2},
		{[]string{"--output", "yaml"}, 2},
	} {
		args := append([]string{"audit", "--snapshot", path, "--output", "json"}, c.args...)
		if got := Run(args); got != c.want {
			t.Errorf("audit %v exit = %d, want %d", c.args, got, c.want)
		}
	}
}
