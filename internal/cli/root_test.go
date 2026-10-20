package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/huza1fa/taildoc/internal/tailnet"
)

func TestCommandExitCodes(t *testing.T) {
	for _, tc := range []struct {
		args []string
		code int
	}{
		{[]string{"explain", "--help"}, 0}, {[]string{"inventory", "--bogus"}, 2},
		{[]string{"explain"}, 2}, {[]string{"diff"}, 2}, {[]string{"not-a-command"}, 2},
		{[]string{"inventory", "--snapshot", "/does-not-exist"}, 1},
	} {
		if got := Run(tc.args); got != tc.code {
			t.Errorf("%v exit %d, want %d", tc.args, got, tc.code)
		}
	}
}
func TestExplainCLIEnforcesLegacyPorts(t *testing.T) {
	tn := &tailnet.Tailnet{HasAccessRules: true, Devices: []*tailnet.Device{
		{Hostname: "laptop", Owner: "alice@example.com", Addresses: []string{"100.64.0.1"}},
		{Hostname: "db", Tags: []string{"tag:db"}, Addresses: []string{"100.64.0.2"}},
	}, Grants: []*tailnet.Grant{{Sources: []string{"alice@example.com"}, Destinations: []string{"tag:db:22"}, Legacy: true}}}
	data, _ := json.Marshal(tn)
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if code := Run([]string{"explain", "--snapshot", path, "--json", "laptop", "db:443"}); code != 0 {
			t.Fatalf("exit %d", code)
		}
	})
	var result struct{ Allowed, Indeterminate bool }
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if result.Allowed || result.Indeterminate {
		t.Fatalf("incorrect result: %s", out)
	}
}
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stdout
	file, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = file
	defer func() { os.Stdout = old; file.Close() }()
	f()
	data, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
