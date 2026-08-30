package diff

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/huza1fa/taildoc/internal/tailnet"
)

func baseTailnet() *tailnet.Tailnet {
	ts := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	return &tailnet.Tailnet{
		Name:        "example.ts.net",
		CollectedAt: ts,
		Users: []*tailnet.User{
			{ID: "u1", LoginName: "alice@example.com", Role: "owner", LastSeen: ts},
			{ID: "u2", LoginName: "bob@example.com", Role: "member"},
		},
		Devices: []*tailnet.Device{
			{
				ID:               "d1",
				Name:             "web01.example.ts.net.",
				Hostname:         "web01",
				Owner:            "alice@example.com",
				Tags:             []string{"tag:web", "tag:prod"},
				Addresses:        []string{"100.64.0.1"},
				AdvertisedRoutes: []string{"10.0.0.0/24"},
				EnabledRoutes:    []string{"10.0.0.0/24"},
				Online:           true,
				Authorized:       true,
			},
			{
				ID:         "d2",
				Hostname:   "laptop",
				Owner:      "bob@example.com",
				Tags:       []string{"tag:dev"},
				Addresses:  []string{"100.64.0.2"},
				Authorized: true,
			},
		},
		Groups: map[string][]string{
			"group:oncall": {"alice@example.com", "bob@example.com"},
		},
		Grants: []*tailnet.Grant{
			{
				Sources:      []string{"group:oncall"},
				Destinations: []string{"tag:prod"},
				IP:           []string{"*:*"},
			},
			{
				Sources:      []string{"tag:ci"},
				Destinations: []string{"db01"},
				IP:           []string{"tcp:5432"},
				Legacy:       true,
			},
		},
	}
}

func TestDiffNoChanges(t *testing.T) {
	oldT := baseTailnet()
	newT := baseTailnet()
	if got := Diff(oldT, newT); got != nil {
		t.Fatalf("expected no changes, got %+v", got)
	}
}

func TestDiffDeviceTagChange(t *testing.T) {
	oldT := baseTailnet()
	newT := baseTailnet()
	newT.Devices[0].Tags = []string{"tag:web"}
	newT.Devices[1].Online = false

	got := Diff(oldT, newT)
	if len(got) != 1 {
		t.Fatalf("want 1 change, got %d: %+v", len(got), got)
	}
	c := got[0]
	if c.Kind != "changed" || c.What != "device web01 (d1)" {
		t.Fatalf("unexpected change: %+v", c)
	}
	if c.Detail == "" || !strings.Contains(c.Detail, "tags") || !strings.Contains(c.Detail, "tag:prod") {
		t.Fatalf("detail should name tags field and removed tag, got %q", c.Detail)
	}

	// reversed direction should also report a changed device
	back := Diff(newT, oldT)
	if len(back) != 1 || back[0].Kind != "changed" {
		t.Fatalf("reversed diff unexpected: %+v", back)
	}
}

func TestDiffGrantAddedRemoved(t *testing.T) {
	oldT := baseTailnet()
	newT := baseTailnet()

	// remove the legacy grant
	newT.Grants = newT.Grants[:1]
	// add a new grant
	newT.Grants = append(newT.Grants, &tailnet.Grant{
		Sources:      []string{"tag:ci"},
		Destinations: []string{"cache"},
		IP:           []string{"tcp:6379"},
	})

	got := Diff(oldT, newT)
	if len(got) != 2 {
		t.Fatalf("want 2 changes, got %d: %+v", len(got), got)
	}
	kinds := map[string]Change{}
	for _, c := range got {
		kinds[c.Kind+":"+c.What] = c
	}
	removed, ok := kinds["removed:grant [tag:ci]|[db01]|[tcp:5432]|null|[]|[]|true"]
	if !ok {
		t.Fatalf("missing removed legacy grant: %+v", got)
	}
	if removed.Detail != "legacy acl" {
		t.Fatalf("removed grant detail = %q, want \"legacy acl\"", removed.Detail)
	}
	added, ok := kinds["added:grant [tag:ci]|[cache]|[tcp:6379]|null|[]|[]|false"]
	if !ok {
		t.Fatalf("missing added grant: %+v", got)
	}
	if added.Detail != "grant" {
		t.Fatalf("added grant detail = %q, want \"grant\"", added.Detail)
	}
}

func TestDiffUserAddedRemoved(t *testing.T) {
	oldT := baseTailnet()
	newT := baseTailnet()
	// new drops bob (removed) and gains carol (added)
	newT.Users = append(newT.Users[:1:1], &tailnet.User{ID: "u3", LoginName: "carol@example.com"})

	got := Diff(oldT, newT)
	if len(got) != 2 {
		t.Fatalf("want 2 changes, got %d: %+v", len(got), got)
	}
	if got[0].Kind != "added" || got[0].What != "user carol@example.com" {
		t.Fatalf("first change should be carol added, got %+v", got[0])
	}
	if got[1].Kind != "removed" || got[1].What != "user bob@example.com" {
		t.Fatalf("second change should be bob removed, got %+v", got[1])
	}
}

func TestDiffGroupMemberChange(t *testing.T) {
	oldT := baseTailnet()
	newT := baseTailnet()
	newT.Groups["group:oncall"] = []string{"alice@example.com", "carol@example.com"}

	got := Diff(oldT, newT)
	if len(got) != 1 {
		t.Fatalf("want 1 change, got %d: %+v", len(got), got)
	}
	c := got[0]
	if c.Kind != "changed" || c.What != "group group:oncall" {
		t.Fatalf("unexpected change: %+v", c)
	}
	if !strings.Contains(c.Detail, "added carol@example.com") || !strings.Contains(c.Detail, "removed bob@example.com") {
		t.Fatalf("unexpected detail: %q", c.Detail)
	}
}

func TestDiffDeterministic(t *testing.T) {
	mutate := func(t *tailnet.Tailnet) {
		t.Users = append(t.Users, &tailnet.User{LoginName: "zoe@example.com"})
		t.Devices = append(t.Devices, &tailnet.Device{ID: "d9", Hostname: "newbox"})
		t.Grants = t.Grants[1:]
		t.Groups["group:oncall"] = []string{"carol@example.com"}
		t.Devices[0].Authorized = false
		t.Devices[0].EnabledRoutes = nil
	}
	oldT := baseTailnet()
	newA := baseTailnet()
	newB := baseTailnet()
	mutate(newA)
	mutate(newB)

	a := Diff(oldT, newA)
	b := Diff(oldT, newB)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("diff not deterministic:\n%+v\nvs\n%+v", a, b)
	}

	// ordering: all added before removed before changed
	lastRank := -1
	for _, c := range a {
		r := rank(c.Kind)
		if r < lastRank {
			t.Fatalf("ordering violated at %+v", c)
		}
		lastRank = r
	}
	for i := 1; i < len(a); i++ {
		if rank(a[i].Kind) == rank(a[i-1].Kind) && a[i-1].What > a[i].What {
			t.Fatalf("What not sorted within kind: %q > %q", a[i-1].What, a[i].What)
		}
	}
}

func TestDiffPolicyControlsAndConditionalGrant(t *testing.T) {
	oldT := baseTailnet()
	newT := baseTailnet()
	oldT.Hosts = map[string]string{"db": "100.64.0.3"}
	newT.Hosts = map[string]string{"db": "100.64.0.4"}
	oldT.TagOwners = map[string][]string{"tag:prod": {"alice@example.com"}}
	newT.TagOwners = map[string][]string{"tag:prod": {"bob@example.com"}}
	oldT.Grants[0].SrcPosture = []string{"posture:trusted"}
	newT.Grants[0].SrcPosture = nil
	changes := Diff(oldT, newT)
	joined := fmt.Sprint(changes)
	for _, want := range []string{"host alias db", "tag owner tag:prod", "posture:trusted"} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected %q in %s", want, joined)
		}
	}
}

func rank(kind string) int {
	switch kind {
	case "added":
		return 0
	case "removed":
		return 1
	default:
		return 2
	}
}
