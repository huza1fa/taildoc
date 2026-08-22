package tailnet

import "testing"

func testTailnet() *Tailnet {
	return &Tailnet{
		Users: []*User{
			{LoginName: "alice@example.com", DisplayName: "Alice", Role: "member"},
			{LoginName: "bob@example.com", Role: "owner"},
		},
		Devices: []*Device{
			{
				Hostname:  "laptop",
				Name:      "laptop.tailnet-name.ts.net.",
				Owner:     "alice@example.com",
				Addresses: []string{"100.64.0.1"},
			},
			{
				Hostname:  "db-prod",
				Tags:      []string{"tag:prod"},
				Addresses: []string{"100.64.0.2"},
			},
			{
				Hostname: "web-01",
				Tags:     []string{"tag:web"},
			},
		},
		Groups: map[string][]string{
			"group:engineering": {"alice@example.com"},
			"group:ops":         {"bob@example.com", "carol@example.com"},
		},
	}
}

func TestCanManage(t *testing.T) {
	cases := []struct {
		role string
		want bool
	}{
		{"owner", true},
		{"admin", true},
		{"network-admin", true},
		{"it-admin", true},
		{"member", false},
		{"", false},
	}
	for _, c := range cases {
		if got := CanManage(c.role); got != c.want {
			t.Errorf("CanManage(%q) = %v, want %v", c.role, got, c.want)
		}
	}
}

func TestFindDevice(t *testing.T) {
	tt := testTailnet()
	cases := []struct {
		ref      string
		hostname string
	}{
		{"laptop", "laptop"},                      // hostname
		{"laptop.tailnet-name.ts.net.", "laptop"}, // full DNS name
		{"100.64.0.2", "db-prod"},                 // tailscale IP
		{"nope", ""},                              // no match
	}
	for _, c := range cases {
		d := tt.FindDevice(c.ref)
		if c.hostname == "" {
			if d != nil {
				t.Errorf("FindDevice(%q) = %q, want nil", c.ref, d.Hostname)
			}
			continue
		}
		if d == nil || d.Hostname != c.hostname {
			t.Errorf("FindDevice(%q) = %v, want %q", c.ref, d, c.hostname)
		}
	}
}

func TestFindUser(t *testing.T) {
	tt := testTailnet()
	if u := tt.FindUser("alice@example.com"); u == nil || u.LoginName != "alice@example.com" {
		t.Errorf("FindUser by login failed: %v", u)
	}
	if u := tt.FindUser("Alice"); u == nil || u.LoginName != "alice@example.com" {
		t.Errorf("FindUser by display name failed: %v", u)
	}
	if u := tt.FindUser("nobody@example.com"); u != nil {
		t.Errorf("FindUser(nobody) = %v, want nil", u)
	}
}

func TestDevicesWithTag(t *testing.T) {
	tt := testTailnet()
	got := tt.DevicesWithTag("tag:prod")
	if len(got) != 1 || got[0].Hostname != "db-prod" {
		t.Errorf("DevicesWithTag(tag:prod) = %v, want [db-prod]", got)
	}
	if got := tt.DevicesWithTag("tag:missing"); len(got) != 0 {
		t.Errorf("DevicesWithTag(missing) = %v, want empty", got)
	}
}

func TestGroupsOfUser(t *testing.T) {
	tt := testTailnet()
	groups := tt.GroupsOfUser("alice@example.com")
	if len(groups) != 1 || groups[0] != "group:engineering" {
		t.Errorf("GroupsOfUser(alice) = %v, want [group:engineering]", groups)
	}
	if got := tt.GroupsOfUser("nobody@example.com"); len(got) != 0 {
		t.Errorf("GroupsOfUser(nobody) = %v, want empty", got)
	}
}
