package collector

import (
	"context"
	"encoding/json"
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

func fakeAPI(t *testing.T, overrides map[string]http.HandlerFunc) *tailscale.Client {
	t.Helper()
	routes := map[string]string{
		"/api/v2/tailnet/-/users": `{"users":[{"id":"u1","loginName":"alice@example.com","role":"owner","status":"active","type":"member"}]}`,
		"/api/v2/tailnet/-/devices": `{"devices":[
			{"id":"1","name":"laptop.tail.ts.net","hostname":"laptop","user":"alice@example.com","addresses":["100.64.0.1"],"authorized":true},
			{"id":"2","name":"router.tail.ts.net","hostname":"router","user":"alice@example.com","tags":["tag:infra"],"addresses":["100.64.0.2"],"authorized":true}]}`,
		"/api/v2/tailnet/-/acl": `{"grants":[{"src":["*"],"dst":["tag:infra"],"ip":["tcp:22"]}],
			"ssh":[{"action":"accept","src":["autogroup:member"],"dst":["tag:infra"],"users":["root"]}],
			"nodeAttrs":[{"target":["tag:web"],"attr":["funnel"]}]}`,
		"/api/v2/tailnet/-/keys":     `{"keys":[{"id":"k1"},{"id":"k2"},{"id":"k3"}]}`,
		"/api/v2/tailnet/-/keys/k1":  `{"id":"k1","keyType":"auth","key":"tskey-auth-SECRET","description":"ci","expires":"2030-01-01T00:00:00Z","capabilities":{"devices":{"create":{"reusable":true,"preauthorized":true,"tags":["tag:ci"]}}}}`,
		"/api/v2/tailnet/-/keys/k2":  `{"id":"k2","keyType":"client","description":"an oauth client"}`,
		"/api/v2/tailnet/-/keys/k3":  `{"id":"k3","keyType":"auth","invalid":true}`,
		"/api/v2/tailnet/-/settings": `{"devicesApprovalOn":true,"usersApprovalOn":false,"devicesAutoUpdatesOn":true,"devicesKeyDurationDays":90}`,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h, ok := overrides[r.URL.Path]; ok {
			h(w, r)
			return
		}
		body, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	base, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &tailscale.Client{BaseURL: base, APIKey: "k", Tailnet: "-"}
}

func TestCollectFromNormalizesEverySource(t *testing.T) {
	tn, err := collectFrom(context.Background(), fakeAPI(t, nil), "-")
	if err != nil {
		t.Fatal(err)
	}
	if len(tn.Users) != 1 || len(tn.Devices) != 2 || len(tn.Grants) != 1 || len(tn.CollectionGaps) != 0 {
		t.Fatalf("collected %+v", tn)
	}
	if tn.Devices[0].Owner != "alice@example.com" || tn.Devices[1].Owner != "" {
		t.Errorf("owners = %q, %q; tagged devices must have none", tn.Devices[0].Owner, tn.Devices[1].Owner)
	}
	if len(tn.SSHRules) != 1 || tn.SSHRules[0].Users[0] != "root" {
		t.Errorf("ssh rules = %+v", tn.SSHRules)
	}
	if len(tn.NodeAttrs) != 1 || tn.NodeAttrs[0].Attrs[0] != "funnel" {
		t.Errorf("node attrs = %+v", tn.NodeAttrs)
	}
	if len(tn.AuthKeys) != 1 || tn.AuthKeys[0].ID != "k1" || !tn.AuthKeys[0].Reusable || !tn.AuthKeys[0].Preauthorized {
		t.Errorf("auth keys = %+v; want only the valid auth key", tn.AuthKeys)
	}
	if tn.Settings == nil || !tn.Settings.DevicesApprovalOn || tn.Settings.UsersApprovalOn || tn.Settings.DevicesKeyDurationDays != 90 {
		t.Errorf("settings = %+v", tn.Settings)
	}
}

func TestSnapshotNeverContainsAuthKeySecret(t *testing.T) {
	tn, err := collectFrom(context.Background(), fakeAPI(t, nil), "-")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(tn)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "SECRET") {
		t.Fatalf("auth key secret reached the snapshot: %s", data)
	}
}

func TestCollectToleratesUnreadableOptionalData(t *testing.T) {
	forbidden := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"insufficient scope"}`))
	}
	tn, err := collectFrom(context.Background(), fakeAPI(t, map[string]http.HandlerFunc{
		"/api/v2/tailnet/-/keys":     forbidden,
		"/api/v2/tailnet/-/settings": forbidden,
	}), "-")
	if err != nil {
		t.Fatalf("optional data must not fail collection: %v", err)
	}
	if len(tn.CollectionGaps) != 2 || !strings.HasPrefix(tn.CollectionGaps[0], "auth keys:") || !strings.HasPrefix(tn.CollectionGaps[1], "tailnet settings:") {
		t.Fatalf("gaps = %q", tn.CollectionGaps)
	}
	if tn.Settings != nil || len(tn.AuthKeys) != 0 {
		t.Fatalf("unexpected optional data: %+v", tn)
	}
}

func TestCollectFailsOnRequiredData(t *testing.T) {
	forbidden := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }
	for _, path := range []string{"/api/v2/tailnet/-/users", "/api/v2/tailnet/-/devices", "/api/v2/tailnet/-/acl"} {
		if _, err := collectFrom(context.Background(), fakeAPI(t, map[string]http.HandlerFunc{path: forbidden}), "-"); err == nil {
			t.Errorf("%s: expected an error", path)
		}
	}
}
