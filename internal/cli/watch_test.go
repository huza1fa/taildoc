package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/huza1fa/taildoc/internal/tailnet"
)

func TestWatchOncePrintsBaseline(t *testing.T) {
	var out bytes.Buffer
	calls := 0
	err := watch(context.Background(), 5*time.Second, true, func(context.Context) (*tailnet.Tailnet, error) {
		calls++
		return &tailnet.Tailnet{
			Devices: []*tailnet.Device{{ID: "d1"}},
			Users:   []*tailnet.User{{LoginName: "alice@example.com"}},
			Grants:  []*tailnet.Grant{{}},
		}, nil
	}, &out)
	if err != nil {
		t.Fatalf("watch: %v", err)
	}
	if calls != 1 {
		t.Errorf("collect calls = %d, want 1", calls)
	}
	if got := out.String(); !strings.Contains(got, "Baseline: 1 device(s), 1 user(s), 1 grant(s)") {
		t.Errorf("baseline output = %q", got)
	}
}

func TestCommandContextLeavesWatchUnbounded(t *testing.T) {
	base := context.Background()
	watchCtx, watchCancel := commandContext(base, "watch")
	defer watchCancel()
	if _, ok := watchCtx.Deadline(); ok {
		t.Fatal("watch context unexpectedly has a deadline")
	}
	otherCtx, otherCancel := commandContext(base, "inventory")
	defer otherCancel()
	if _, ok := otherCtx.Deadline(); !ok {
		t.Fatal("one-shot command context should have a deadline")
	}
}
