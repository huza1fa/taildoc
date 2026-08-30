package snapshot

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/huza1fa/taildoc/internal/tailnet"
)

func fixture() *tailnet.Tailnet {
	created := time.Date(2024, 3, 1, 10, 0, 0, 0, time.UTC)
	lastSeen := time.Date(2026, 8, 20, 18, 30, 15, 123456789, time.UTC)
	expires := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	return &tailnet.Tailnet{
		Name:        "example.ts.net",
		CollectedAt: lastSeen,
		Users: []*tailnet.User{
			{
				ID:                 "u1",
				LoginName:          "alice@example.com",
				DisplayName:        "Alice",
				Role:               "owner",
				Status:             "active",
				Type:               "member",
				Created:            created,
				LastSeen:           lastSeen,
				CurrentlyConnected: true,
				DeviceCount:        2,
			},
			{
				ID:          "u2",
				LoginName:   "svc-deploy@example.com",
				Role:        "member",
				Status:      "active",
				Type:        "service",
				Created:     created,
				DeviceCount: 0,
			},
		},
		Devices: []*tailnet.Device{
			{
				ID:                        "d1",
				NodeID:                    "n1",
				Name:                      "web01.example.ts.net.",
				Hostname:                  "web01",
				OS:                        "linux",
				ClientVersion:             "1.80.0",
				Owner:                     "alice@example.com",
				Tags:                      []string{"tag:prod", "tag:web"},
				Addresses:                 []string{"100.64.0.1", "fd7a:115c:a1e0::1"},
				AdvertisedRoutes:          []string{"10.0.0.0/24"},
				EnabledRoutes:             []string{"10.0.0.0/24"},
				Online:                    true,
				Authorized:                true,
				KeyExpiryDisabled:         true,
				BlocksIncomingConnections: false,
				UpdateAvailable:           true,
				IsEphemeral:               false,
				IsExternal:                false,
				SSHEnabled:                true,
				Created:                   created,
				LastSeen:                  lastSeen,
				Expires:                   expires,
			},
			{
				ID:                "d2",
				NodeID:            "n2",
				Name:              "ephem.example.ts.net.",
				Hostname:          "ephem",
				OS:                "macos",
				Tags:              []string{"tag:ci"},
				Addresses:         []string{"100.64.0.2"},
				Online:            false,
				Authorized:        true,
				IsEphemeral:       true,
				IsExternal:        true,
				KeyExpiryDisabled: false,
			},
		},
		Groups: map[string][]string{
			"group:admins": {"alice@example.com"},
			"group:oncall": {"alice@example.com", "bob@example.com"},
		},
		TagOwners: map[string][]string{
			"tag:prod": {"group:admins"},
			"tag:web":  {"alice@example.com"},
		},
		Hosts: map[string]string{
			"web01": "100.64.0.1",
			"db01":  "100.64.0.3",
		},
		Grants: []*tailnet.Grant{
			{
				Sources:      []string{"group:oncall"},
				Destinations: []string{"tag:prod"},
				IP:           []string{"*:*"},
				Legacy:       false,
			},
			{
				Sources:      []string{"tag:ci"},
				Destinations: []string{"db01"},
				IP:           []string{"tcp:5432"},
				App: map[string][]map[string]any{
					"tailscale.com/app/http": {
						{"method": "GET"},
					},
				},
				SrcPosture: []string{"posture:trusted"},
				Via:        []string{"via:jump"},
				Legacy:     true,
			},
		},
		Postures: map[string][]string{
			"posture:trusted": {"node:os = linux", "node:tsVersion >= 1.80"},
		},
		AutoApprovers: tailnet.AutoApprovers{
			Routes: map[string][]string{
				"10.0.0.0/24": {"tag:web"},
			},
			ExitNode: []string{"group:admins"},
			Services: map[string][]string{
				"ssh:22": {"tag:prod"},
			},
		},
	}
}

func TestRoundTrip(t *testing.T) {
	in := fixture()
	path := filepath.Join(t.TempDir(), "snap.json")

	if err := Save(in, path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved file: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("saved file is empty")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot mode = %o, want 600", info.Mode().Perm())
	}

	out, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round-trip mismatch:\nwant %+v\ngot  %+v", in, out)
	}
}

func TestSaveDefaultReturnsReadablePath(t *testing.T) {
	dir := t.TempDir()
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWd)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	path, err := SaveDefault(fixture())
	if err != nil {
		t.Fatalf("SaveDefault: %v", err)
	}

	if filepath.Dir(path) != "." {
		t.Fatalf("expected path in cwd, got %q", path)
	}
	if want := "taildoc-snapshot-"; len(path) < len(want) || path[:len(want)] != want {
		t.Fatalf("unexpected filename %q", path)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not written: %v", err)
	}

	out, err := Load(path)
	if err != nil {
		t.Fatalf("Load after SaveDefault: %v", err)
	}
	if out.Name != fixture().Name {
		t.Fatalf("round-trip name mismatch: %q vs %q", out.Name, fixture().Name)
	}
}

func TestLoadErrorsOnBadFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("expected error loading missing file")
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(bad, []byte("{not json"), 0o644)
	if _, err := Load(bad); err == nil {
		t.Fatal("expected error loading invalid JSON")
	}
}
