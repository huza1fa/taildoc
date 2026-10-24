package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/huza1fa/taildoc/internal/plan"
	"github.com/huza1fa/taildoc/internal/snapshot"
)

func policyFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.hujson")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPlanCLIEntirelyOfflineAndReadOnly(t *testing.T) {
	oldTransport := http.DefaultTransport
	http.DefaultTransport = rejectPlanNetwork{t}
	defer func() { http.DefaultTransport = oldTransport }()
	// Credentials must not be read, validated, or overwritten.
	config := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("TAILDOC_CONFIG", config)
	t.Setenv("TS_ACCESS_TOKEN", "not-a-real-token")
	path := policyFile(t, `{
        "groups":{"group:engineering":["alice@example.com"]},
        "tagOwners":{"tag:db":["bob@example.com"]},
        "grants":[{"src":["group:engineering"],"dst":["tag:db"],"ip":["tcp:22","tcp:5432"]}],
    }`)
	snapPath := filepath.Join(t.TempDir(), "baseline.json")
	data, err := os.ReadFile("../../examples/demo-before.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(snapPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	policyBefore, _ := os.ReadFile(path)
	args := []string{"plan", "--snapshot", snapPath, "--policy", path, "--source", "laptop", "--destination", "db-prod", "--port", "5432", "--proto", "tcp,tcp", "--output", "json"}
	out := captureStdout(t, func() {
		if code := Run(args); code != 0 {
			t.Fatalf("plan exit %d", code)
		}
	})
	var report plan.Report
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if report.Impact.Evaluations != 2 || len(report.Impact.Changes) != 1 || report.Impact.Changes[0].Kind != "gained" || report.Impact.Changes[0].Ports != "5432" || report.BaselineCollectedAt.IsZero() {
		t.Fatalf("unexpected plan: %s", out)
	}
	for file, before := range map[string][]byte{path: policyBefore, snapPath: data} {
		after, err := os.ReadFile(file)
		if err != nil || string(after) != string(before) {
			t.Fatalf("plan modified %s: %v", file, err)
		}
	}
	if _, err := os.Stat(config); !os.IsNotExist(err) {
		t.Fatalf("plan touched auth config: %v", err)
	}
	// Text and JSON use the same scope and report the same gained access.
	args[len(args)-1] = "text"
	out = captureStdout(t, func() {
		if code := Run(args); code != 0 {
			t.Fatalf("text plan exit %d", code)
		}
	})
	for _, want := range []string{"Offline policy plan", "Baseline collected:", "gained: laptop -> db-prod tcp/5432", "not Tailscale policy validation"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %s", want, out)
		}
	}
}

type rejectPlanNetwork struct{ t *testing.T }

func (r rejectPlanNetwork) RoundTrip(*http.Request) (*http.Response, error) {
	r.t.Error("offline plan attempted a network request")
	return nil, fmt.Errorf("network is forbidden during offline plan")
}

func TestPlanCLIInvalidUsageAndInput(t *testing.T) {
	for _, args := range [][]string{
		{"plan"}, {"plan", "--snapshot", "missing"}, {"plan", "--policy", "missing"},
		{"plan", "--snapshot", "missing", "--policy", "missing", "unexpected"},
		{"plan", "--snapshot", "missing", "--policy", "missing", "--output", "yaml"},
		{"plan", "--snapshot", "missing", "--policy", "missing", "--port", "-1"},
		{"plan", "--snapshot", "missing", "--policy", "missing", "--port", "22-23"},
		{"plan", "--snapshot", "missing", "--policy", "missing", "--proto", "icmp"},
		{"plan", "--snapshot", "missing", "--policy", "missing", "--proto", "tcp,"},
		{"plan", "--bogus"},
	} {
		if code := Run(args); code != 2 {
			t.Errorf("%v: exit %d, want usage error", args, code)
		}
	}
	valid := policyFile(t, `{"grants":[]}`)
	bad := policyFile(t, `{"grants":null}`)
	empty := policyFile(t, `{}`)
	for _, args := range [][]string{
		{"plan", "--snapshot", "missing", "--policy", valid},
		{"plan", "--snapshot", "../../examples/demo-before.json", "--policy", "missing"},
		{"plan", "--snapshot", "../../examples/demo-before.json", "--policy", bad},
		{"plan", "--snapshot", empty, "--policy", valid},
		{"plan", "--snapshot", "../../examples/demo-before.json", "--policy", valid, "--source", "missing"},
	} {
		if code := Run(args); code != 1 {
			t.Errorf("%v: exit %d, want input error", args, code)
		}
	}
	for _, args := range [][]string{{"plan", "--help"}, {"help", "plan"}} {
		out := captureStdout(t, func() {
			if code := Run(args); code != 0 {
				t.Fatalf("help exit %d", code)
			}
		})
		if !strings.Contains(out, "--policy") || !strings.Contains(out, "Entirely offline") {
			t.Fatal("missing plan help")
		}
	}
}

func TestPlanCLIReportsUnknownAndEscapesTerminalControls(t *testing.T) {
	base, err := snapshot.Load("../../examples/demo-before.json")
	if err != nil {
		t.Fatal(err)
	}
	base.Grants[0].SrcPosture = []string{"posture:trusted"}
	base.Devices[0].Hostname = "laptop\x1b[2J\nforged-output"
	snapPath := filepath.Join(t.TempDir(), "snapshot.json")
	if err := snapshot.Save(base, snapPath); err != nil {
		t.Fatal(err)
	}
	path := policyFile(t, `{"groups":{"group:engineering":["alice@example.com"]},"grants":[{"src":["group:engineering"],"dst":["tag:db"],"ip":["tcp:22"],"srcPosture":["posture:trusted"]}]}`)
	out := captureStdout(t, func() {
		if code := Run([]string{"plan", "--snapshot", snapPath, "--policy", path, "--source", "d-laptop", "--destination", "d-db", "--port", "22", "--proto", "tcp"}); code != 0 {
			t.Fatalf("plan exit %d", code)
		}
	})
	if !strings.Contains(out, "2 unknown") || !strings.Contains(out, "unchanged unknown") {
		t.Fatalf("unknown paths hidden: %s", out)
	}
	// A gained path prints the untrusted device name; escape it in terminal output.
	path = policyFile(t, `{"grants":[{"src":["*"],"dst":["tag:db"],"ip":["tcp:443"]}]}`)
	out = captureStdout(t, func() {
		if code := Run([]string{"plan", "--snapshot", snapPath, "--policy", path, "--port", "443"}); code != 0 {
			t.Fatalf("plan exit %d", code)
		}
	})
	if strings.Contains(out, "\x1b") || strings.Contains(out, "\nforged-output") || !strings.Contains(out, `laptop\x1b[2J\nforged-output`) {
		t.Fatalf("terminal control injection: %q", out)
	}
}

func TestPlanShellCompletions(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		out := captureStdout(t, func() {
			if code := Run([]string{"completion", shell}); code != 0 {
				t.Fatalf("completion exit %d", code)
			}
		})
		if !strings.Contains(out, "plan") || !strings.Contains(out, "policy") {
			t.Fatalf("missing plan completion for %s", shell)
		}
	}
}
