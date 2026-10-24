package collector

import (
	"context"
	"github.com/huza1fa/taildoc/internal/policy"
	"github.com/huza1fa/taildoc/internal/tailnet"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"tailscale.com/client/tailscale/v2"
	"testing"
)

func TestNormalizeTag(t *testing.T) {
	cases := []struct{ in, want string }{
		{"prod", "tag:prod"},
		{"tag:prod", "tag:prod"},
	}
	for _, c := range cases {
		tn := &tailnet.Tailnet{}
		policy.Normalize(tn, &tailscale.ACL{TagOwners: map[string][]string{c.in: {"alice@example.com"}}})
		if _, ok := tn.TagOwners[c.want]; !ok {
			t.Errorf("normalizing %q did not produce %q", c.in, c.want)
		}
	}
}

func TestCollectRequiresToken(t *testing.T) {
	t.Setenv("TS_ACCESS_TOKEN", "")
	t.Setenv("TAILDOC_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	if _, err := Collect(context.Background()); err == nil {
		t.Fatal("expected error when TS_ACCESS_TOKEN is unset")
	} else if !strings.Contains(err.Error(), "TS_ACCESS_TOKEN") {
		t.Errorf("error should mention TS_ACCESS_TOKEN, got: %v", err)
	}
}

func TestCollectUnauthenticatedHintsAuthLogin(t *testing.T) {
	t.Setenv("TS_ACCESS_TOKEN", "")
	t.Setenv("TAILDOC_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	_, err := Collect(context.Background())
	if err == nil {
		t.Fatal("expected error when no credentials are available")
	}
	if !strings.Contains(err.Error(), "auth login") {
		t.Errorf("error should hint at `taildoc auth login`, got: %v", err)
	}
}

func TestPolicyCollectionPreservesLegacyRestrictions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"acls":[{"action":"accept","src":["alice@example.com"],"dst":["tag:db:22,80-81"],"proto":"tcp"},{"action":"accept","users":["bob@example.com"],"ports":["tag:db:53"],"proto":"udp","srcPosture":["posture:trusted"]}],"ipsets":{"ipset:office":["100.64.0.0/24"]}}`))
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	tn := &tailnet.Tailnet{}
	if err := collectPolicy(context.Background(), &tailscale.Client{BaseURL: base, Tailnet: "test"}, tn); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		port, proto string
		want        bool
	}{{"22", "tcp", true}, {"80", "tcp", true}, {"81", "tcp", true}, {"443", "tcp", false}, {"22", "udp", false}} {
		got := policy.Evaluate(tn, policy.Request{SourceLogin: "alice@example.com", DestTags: []string{"tag:db"}, Port: tc.port, Proto: tc.proto})
		if got.Allowed != tc.want {
			t.Errorf("%s/%s: %+v", tc.proto, tc.port, got)
		}
	}
	got := policy.Evaluate(tn, policy.Request{SourceLogin: "bob@example.com", DestTags: []string{"tag:db"}, Port: "53", Proto: "udp"})
	if got.Allowed || !got.Indeterminate {
		t.Fatalf("legacy posture lost: %+v", got)
	}
	if len(tn.IPSets["ipset:office"]) != 1 {
		t.Fatal("IP sets lost")
	}
}
