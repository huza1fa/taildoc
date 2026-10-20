package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/huza1fa/taildoc/internal/diff"
	"github.com/huza1fa/taildoc/internal/history"
)

func TestOfflineAccessImpactCLI(t *testing.T) {
	out := captureStdout(t, func() {
		code := Run([]string{"diff", "--impact", "--output", "json", "--source", "laptop", "--destination", "db-prod", "--port", "5432", "../../examples/demo-before.json", "../../examples/demo-after.json"})
		if code != 0 {
			t.Fatalf("diff exit %d", code)
		}
	})
	var got struct {
		Impact diff.ImpactReport `json:"impact"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Impact.Changes) != 1 || got.Impact.Changes[0].Kind != "gained" || got.Impact.Changes[0].Ports != "5432" {
		t.Fatalf("unexpected impact: %s", out)
	}
}
func TestOfflineHistoryCLI(t *testing.T) {
	db := filepath.Join(t.TempDir(), "history.db")
	for i, snap := range []string{"demo-before.json", "demo-after.json", "demo-before.json"} {
		out := captureStdout(t, func() {
			if code := Run([]string{"history", "--db", db, "--record", "--snapshot", "../../examples/" + snap, "--output", "json"}); code != 0 {
				t.Fatalf("record exit %d", code)
			}
		})
		var run history.Run
		if err := json.Unmarshal([]byte(out), &run); err != nil {
			t.Fatal(err)
		}
		if i == 2 && run.Events[0].Status != history.Reopened {
			t.Fatalf("returning finding not reopened: %s", out)
		}
	}
	out := captureStdout(t, func() {
		if code := Run([]string{"history", "--db", db, "--limit", "1", "--status", "reopened", "--severity", "low", "--check", "key-expiry", "--output", "json"}); code != 0 {
			t.Fatalf("history exit %d", code)
		}
	})
	var runs []history.Run
	if err := json.Unmarshal([]byte(out), &runs); err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || len(runs[0].Events) != 1 || runs[0].Events[0].Status != history.Reopened {
		t.Fatalf("filter failed: %s", out)
	}
}
func TestInvalidOptionsFailBeforeSideEffects(t *testing.T) {
	db := filepath.Join(t.TempDir(), "must-not-exist.db")
	for _, args := range [][]string{
		{"history", "--db", db, "--limit", "-1"}, {"history", "--db", db, "--since", "yesterday"},
		{"history", "--db", db, "--status", "bogus"}, {"history", "--db", db, "--record", "--status", "new"},
		{"diff", "--impact", "--port", "70000", "missing.json"}, {"diff", "--impact", "--proto", "bogus", "missing.json"},
		{"audit", "--only", "typo"}, {"audit", "--output", "bogus"}, {"inventory", "--output", "bogus"},
		{"completion", "bogus"}, {"auth", "bogus"}, {"explain", "--proto", "bogus", "laptop", "db"},
	} {
		if code := Run(args); code != 2 {
			t.Errorf("%v returned %d, want 2", args, code)
		}
	}
	if _, err := os.Stat(db); !os.IsNotExist(err) {
		t.Fatalf("invalid history options created a DB: %v", err)
	}
}
