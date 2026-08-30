package audit

import (
	"strings"
	"testing"
	"time"

	"github.com/huza1fa/taildoc/internal/tailnet"
)

func TestRunSortsFindingsBySeverity(t *testing.T) {
	tt := &tailnet.Tailnet{
		Devices: []*tailnet.Device{
			{Hostname: "stale", LastSeen: time.Now().Add(-100 * 24 * time.Hour)},
			{Hostname: "expiring", Expires: time.Now().Add(5 * 24 * time.Hour)},
		},
	}
	findings := Run(tt)
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings, got %d", len(findings))
	}
	for i := 1; i < len(findings); i++ {
		if severityOrder[findings[i].Severity] < severityOrder[findings[i-1].Severity] {
			t.Fatalf("findings not sorted by severity: %s before %s",
				findings[i-1].Severity, findings[i].Severity)
		}
	}
}

func TestRunEmptyTailnet(t *testing.T) {
	if findings := Run(&tailnet.Tailnet{}); len(findings) != 0 {
		t.Errorf("expected no findings for empty tailnet, got %d: %+v", len(findings), findings)
	}
}

func TestCheckStaleDevices(t *testing.T) {
	now := time.Now()
	tt := &tailnet.Tailnet{
		Devices: []*tailnet.Device{
			{Hostname: "online", Online: true, LastSeen: now.Add(-200 * 24 * time.Hour)},
			{Hostname: "ephemeral", IsEphemeral: true, LastSeen: now.Add(-200 * 24 * time.Hour)},
			{Hostname: "never-seen"},
			{Hostname: "stale-90", LastSeen: now.Add(-100 * 24 * time.Hour)},
			{Hostname: "stale-30", LastSeen: now.Add(-60 * 24 * time.Hour)},
			{Hostname: "fresh", LastSeen: now.Add(-time.Hour)},
		},
	}
	findings := checkStaleDevices(tt)
	var titles []string
	for _, f := range findings {
		titles = append(titles, f.Title)
	}
	joined := strings.Join(titles, "\n")
	if !strings.Contains(joined, "1 device(s) unseen for over 90 days") {
		t.Errorf("expected stale90 finding, got:\n%s", joined)
	}
	if !strings.Contains(joined, "1 device(s) unseen for over 30 days") {
		t.Errorf("expected stale30 finding, got:\n%s", joined)
	}
}

func TestCheckKeyExpiry(t *testing.T) {
	tt := &tailnet.Tailnet{
		Devices: []*tailnet.Device{
			{Hostname: "expired", Expires: time.Now().Add(-time.Hour)},
			{Hostname: "expiring", Expires: time.Now().Add(3 * 24 * time.Hour)},
			{Hostname: "permanent", KeyExpiryDisabled: true},
			{Hostname: "healthy", Expires: time.Now().Add(365 * 24 * time.Hour)},
		},
	}
	findings := checkKeyExpiry(tt)
	joined := ""
	for _, f := range findings {
		joined += f.Title + "\n"
	}
	for _, want := range []string{
		"1 device(s) with expired node keys",
		"1 device(s) with keys expiring within 14 days",
		"1 device(s) with key expiry disabled",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing finding %q in:\n%s", want, joined)
		}
	}
}

func TestCheckBroadGrants(t *testing.T) {
	tt := &tailnet.Tailnet{
		Grants: []*tailnet.Grant{
			{Sources: []string{"*"}, Destinations: []string{"*"}, IP: []string{"*:*"}},
			{Sources: []string{"tag:web"}, Destinations: []string{"tag:prod"}, IP: []string{"tcp:443"}},
		},
	}
	findings := checkBroadGrants(tt)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != High || findings[0].Title != "Grant allows everything to everyone" {
		t.Errorf("unexpected finding: %+v", findings[0])
	}
}

func TestCheckBroadGrantsAllPortsWithSrc(t *testing.T) {
	tt := &tailnet.Tailnet{
		Grants: []*tailnet.Grant{
			{Sources: []string{"group:eng"}, Destinations: []string{"tag:db"}, IP: []string{"*:*"}},
		},
	}
	findings := checkBroadGrants(tt)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != Medium {
		t.Errorf("expected Medium severity, got %s", findings[0].Severity)
	}
}

func TestCheckBroadGrantsRequiresWildcardSourceForEverything(t *testing.T) {
	tt := &tailnet.Tailnet{Grants: []*tailnet.Grant{{Sources: []string{"group:ops"}, Destinations: []string{"*"}, IP: []string{"tcp:*"}}}}
	findings := checkBroadGrants(tt)
	if len(findings) != 1 || findings[0].Title != "Grant allows all ports" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
}

func TestCheckBroadGrantsFindsWildcardSourceToTag(t *testing.T) {
	tt := &tailnet.Tailnet{Grants: []*tailnet.Grant{{Sources: []string{"*"}, Destinations: []string{"tag:prod"}, IP: []string{"tcp:*"}}}}
	findings := checkBroadGrants(tt)
	if len(findings) != 1 || findings[0].Title != "Grant allows all ports" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
}

func TestCheckUnapprovedRoutes(t *testing.T) {
	tt := &tailnet.Tailnet{
		Devices: []*tailnet.Device{
			{
				Hostname:         "router",
				Owner:            "alice@example.com",
				AdvertisedRoutes: []string{"10.0.0.0/24", "10.0.1.0/24"},
				EnabledRoutes:    []string{"10.0.0.0/24"},
			},
		},
	}
	findings := checkUnapprovedRoutes(tt)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != Medium {
		t.Errorf("expected Medium severity, got %s", f.Severity)
	}
	if !strings.Contains(f.Title, "router advertises route(s) that are not enabled") {
		t.Errorf("unexpected title: %q", f.Title)
	}
	if len(f.Evidence) < 2 || !strings.Contains(f.Evidence[1], "10.0.1.0/24") {
		t.Errorf("evidence should name the unapproved route: %v", f.Evidence)
	}
}

func TestCheckSingleExitNode(t *testing.T) {
	one := &tailnet.Tailnet{
		Devices: []*tailnet.Device{
			{Hostname: "exit-1", Online: true, Authorized: true, EnabledRoutes: []string{"0.0.0.0/0"}},
		},
	}
	if findings := checkSingleExitNode(one); len(findings) != 1 {
		t.Errorf("expected finding for single exit node, got %d", len(findings))
	}

	two := &tailnet.Tailnet{
		Devices: []*tailnet.Device{
			{Hostname: "exit-1", Online: true, Authorized: true, EnabledRoutes: []string{"0.0.0.0/0"}},
			{Hostname: "exit-2", Online: true, Authorized: true, EnabledRoutes: []string{"::/0"}},
		},
	}
	if findings := checkSingleExitNode(two); findings != nil {
		t.Errorf("expected no finding for multiple exit nodes, got %+v", findings)
	}
}

func TestCheckOrphanedTags(t *testing.T) {
	tt := &tailnet.Tailnet{
		Devices: []*tailnet.Device{
			{Hostname: "web-01", Tags: []string{"tag:owned"}},
			{Hostname: "db-01", Tags: []string{"tag:mystery"}},
		},
		TagOwners: map[string][]string{
			"tag:owned": {"alice@example.com"},
			"tag:gone":  {"bob@example.com"},
		},
	}
	findings := checkOrphanedTags(tt)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (orphan tag + unused tag), got %d: %+v", len(findings), findings)
	}
	foundOrphan, foundUnused := false, false
	for _, f := range findings {
		switch {
		case strings.Contains(f.Title, "tag:mystery"):
			foundOrphan = true
			if f.Severity != Medium {
				t.Errorf("orphan tag should be Medium, got %s", f.Severity)
			}
		case strings.Contains(f.Title, "unused"):
			foundUnused = true
			if !strings.Contains(strings.Join(f.Evidence, " "), "tag:gone") {
				t.Errorf("unused-tag evidence should name tag:gone: %v", f.Evidence)
			}
		}
	}
	if !foundOrphan || !foundUnused {
		t.Errorf("expected orphan and unused tag findings, got %+v", findings)
	}
}

func TestCheckInactiveUsers(t *testing.T) {
	tt := &tailnet.Tailnet{
		Users: []*tailnet.User{
			{LoginName: "old@example.com", Status: "idle", LastSeen: time.Now().Add(-120 * 24 * time.Hour)},
			{LoginName: "recent@example.com", Status: "active", LastSeen: time.Now().Add(-time.Hour)},
			{LoginName: "away@example.com", Status: "idle", LastSeen: time.Now().Add(-10 * 24 * time.Hour)},
		},
		Groups: map[string][]string{
			"group:veterans": {"old@example.com"},
		},
	}
	findings := checkInactiveUsers(tt)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Title, "1 user(s) inactive") {
		t.Errorf("unexpected title: %q", findings[0].Title)
	}
	if ev := strings.Join(findings[0].Evidence, " "); !strings.Contains(ev, "old@example.com") {
		t.Errorf("evidence should name the inactive user: %v", findings[0].Evidence)
	}
}

func TestCheckPrivilegedUserDevices(t *testing.T) {
	tt := &tailnet.Tailnet{
		Devices: []*tailnet.Device{
			{Hostname: "laptop-router", Owner: "alice@example.com", AdvertisedRoutes: []string{"192.168.1.0/24"}},
			{Hostname: "laptop", Owner: "alice@example.com"},
			{Hostname: "infra-router", Tags: []string{"tag:infra"}, Owner: "", AdvertisedRoutes: []string{"10.0.0.0/16"}},
		},
	}
	findings := checkPrivilegedUserDevices(tt)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for the owned router, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Title, "laptop-router") {
		t.Errorf("finding should reference laptop-router: %q", findings[0].Title)
	}
}
