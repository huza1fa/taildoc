package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/huza1fa/taildoc/internal/audit"
	"github.com/huza1fa/taildoc/internal/graph"
	"github.com/huza1fa/taildoc/internal/tailnet"
)

func fixtureTailnet() *tailnet.Tailnet {
	now := time.Now()
	t := &tailnet.Tailnet{
		Name:        "example.ts.net",
		CollectedAt: now,
		Groups:      map[string][]string{},
		TagOwners:   map[string][]string{},
		Hosts:       map[string]string{},
		Postures:    map[string][]string{},
	}
	t.Users = []*tailnet.User{
		{ID: "u1", LoginName: "alice@example.com", DisplayName: "Alice", Role: "owner"},
		{ID: "u2", LoginName: "bob@example.com", DisplayName: "Bob", Role: "member"},
	}
	t.Devices = []*tailnet.Device{
		{
			ID:               "d1",
			Hostname:         "web-1",
			Name:             "web-1.example.ts.net.",
			OS:               "linux",
			ClientVersion:    "1.80.0",
			Owner:            "alice@example.com",
			Addresses:        []string{"100.64.0.1"},
			Online:           true,
			Authorized:       true,
			Expires:          now.Add(365 * 24 * time.Hour),
			AdvertisedRoutes: []string{"10.0.0.0/24", "10.0.1.0/24"},
			EnabledRoutes:    []string{"10.0.0.0/24"},
			LastSeen:         now,
		},
		{
			ID:        "d2",
			Hostname:  "stale-db",
			Name:      "stale-db.example.ts.net.",
			OS:        "linux",
			Owner:     "bob@example.com",
			Addresses: []string{"100.64.0.2"},
			Expires:   now.Add(-48 * time.Hour),
			LastSeen:  now.Add(-120 * 24 * time.Hour),
		},
		{
			ID:                "d3",
			Hostname:          "tagged-node",
			Name:              "tagged-node.example.ts.net.",
			OS:                "windows",
			Tags:              []string{"tag:prod", "tag:web"},
			Addresses:         []string{"100.64.0.3"},
			KeyExpiryDisabled: true,
			LastSeen:          now,
		},
	}
	t.Grants = []*tailnet.Grant{
		{Sources: []string{"group:devs"}, Destinations: []string{"tag:prod"}, IP: []string{"tcp:5432"}},
		{Sources: []string{"tag:prod"}, Destinations: []string{"*"}, IP: []string{"*:*"}, Legacy: true},
	}
	return t
}

func key(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "shift+tab":
		return tea.KeyMsg{Type: tea.KeyShiftTab}
	case "left":
		return tea.KeyMsg{Type: tea.KeyLeft}
	case "right":
		return tea.KeyMsg{Type: tea.KeyRight}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
	}
}

func send(m model, s string) model {
	next, _ := m.Update(key(s))
	return next.(model)
}

func resize(m model, w, h int) model {
	next, _ := m.Update(tea.WindowSizeMsg{Width: w, Height: h})
	return next.(model)
}

func TestTabSwitching(t *testing.T) {
	m := newModel(fixtureTailnet())
	if m.activeTab != tabOverview {
		t.Fatalf("default tab = %v, want Overview", m.activeTab)
	}

	m = send(m, "2")
	if m.activeTab != tabDevices {
		t.Fatalf("after '2' tab = %v, want Devices", m.activeTab)
	}

	m = send(m, "3")
	if m.activeTab != tabGraph {
		t.Fatalf("after '3' tab = %v, want Graph", m.activeTab)
	}

	m = send(m, "right")
	if m.activeTab != tabOverview {
		t.Fatalf("right from Graph should wrap to Overview, got %v", m.activeTab)
	}

	m = send(m, "left")
	if m.activeTab != tabGraph {
		t.Fatalf("left from Overview should wrap to Graph, got %v", m.activeTab)
	}

	m = send(m, "tab")
	if m.activeTab != tabOverview {
		t.Fatalf("tab cycles forward, got %v", m.activeTab)
	}

	m = send(m, "shift+tab")
	if m.activeTab != tabGraph {
		t.Fatalf("shift+tab cycles backward, got %v", m.activeTab)
	}

	m = send(m, "1")
	if m.activeTab != tabOverview {
		t.Fatalf("after '1' tab = %v, want Overview", m.activeTab)
	}
}

func TestQuitFlag(t *testing.T) {
	for _, k := range []string{"q", "ctrl+c"} {
		m := newModel(fixtureTailnet())
		m = send(m, k)
		if !m.quitting {
			t.Errorf("key %q should set quitting flag", k)
		}
		if got := m.View(); got != "" {
			t.Errorf("View after quit = %q, want empty", got)
		}
	}
}

func TestFindingDetailToggle(t *testing.T) {
	m := newModel(fixtureTailnet())
	findings := audit.Run(fixtureTailnet())
	if len(findings) == 0 {
		t.Skip("fixture produced no findings; detail toggle untestable")
	}
	if len(m.findingList.Items()) != len(findings) {
		t.Fatalf("list items = %d, want %d", len(m.findingList.Items()), len(findings))
	}

	if m.findingDetailOpen {
		t.Fatal("detail should start closed")
	}

	m = resize(m, 120, 40)
	m = send(m, "enter")
	if !m.findingDetailOpen {
		t.Fatal("enter on findings list should open detail")
	}
	if m.selectedFinding != 0 {
		t.Fatalf("selected finding = %d, want 0 (first item)", m.selectedFinding)
	}
	if m.findings[m.selectedFinding].Severity != findings[0].Severity ||
		m.findings[m.selectedFinding].Title != findings[0].Title {
		t.Fatalf("detail finding mismatch: got %+v want %+v",
			m.findings[m.selectedFinding], findings[0])
	}

	// Keys do not leak into widgets behind the overlay.
	before := m.findingList.Index()
	m = send(m, "down")
	if m.findingList.Index() != before {
		t.Error("arrow keys should not reach the list while overlay is open")
	}

	view := m.View()
	if view == "" {
		t.Fatal("overlay view should not be empty")
	}
	for _, want := range []string{"Evidence", "Why it matters", "Next step"} {
		if !strings.Contains(view, want) {
			t.Errorf("finding detail view missing section %q", want)
		}
	}

	m = send(m, "esc")
	if m.findingDetailOpen {
		t.Fatal("esc should close finding detail")
	}
}

func TestDeviceDetailToggle(t *testing.T) {
	m := newModel(fixtureTailnet())
	m = send(m, "2")
	if m.activeTab != tabDevices {
		t.Fatal("expected devices tab")
	}

	m = resize(m, 120, 40)
	m = send(m, "enter")
	if m.deviceDetail == nil {
		t.Fatal("enter on device table should open device detail")
	}
	if m.deviceDetail.Hostname != "web-1" {
		t.Fatalf("device detail = %q, want web-1 (first row)", m.deviceDetail.Hostname)
	}

	view := m.View()
	for _, want := range []string{"100.64.0.1", "10.0.0.0/24", "enabled", "advertised"} {
		if !strings.Contains(view, want) {
			t.Errorf("device detail view missing %q", want)
		}
	}

	m = send(m, "esc")
	if m.deviceDetail != nil {
		t.Fatal("esc should close device detail")
	}
}

func TestDeviceRows(t *testing.T) {
	rows := deviceRows(fixtureTailnet())
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	wantCells := 5
	for i, r := range rows {
		if len(r) != wantCells {
			t.Fatalf("row %d has %d cells, want %d", i, len(r), wantCells)
		}
	}

	web := rows[0]
	if web[0] != "web-1" || web[1] != "linux" {
		t.Errorf("row 0 identity cells = %v, want [web-1 linux]", web[:2])
	}
	if web[2] != "alice@example.com" {
		t.Errorf("owner cell = %q, want alice@example.com", web[2])
	}
	tagged := rows[2]
	if tagged[0] != "tagged-node" {
		t.Errorf("hostname cell = %q, want tagged-node", tagged[0])
	}
	wantTags := "tag:prod,tag:web"
	if tagged[2] != wantTags {
		t.Errorf("tags cell = %q, want %q", tagged[2], wantTags)
	}
	if !strings.Contains(tagged[4], "no expiry") {
		t.Errorf("key cell for disabled expiry = %q, want to contain 'no expiry'", tagged[4])
	}
	if !strings.Contains(rows[1][4], "expired") {
		t.Errorf("key cell for expired key = %q, want 'expired'", rows[1][4])
	}
	if !strings.Contains(web[3], "online") || !strings.Contains(rows[1][3], "offline") {
		t.Errorf("online cells = %q / %q, want online/offline states", web[3], rows[1][3])
	}
}

func TestDeviceSortCycles(t *testing.T) {
	m := newModel(fixtureTailnet())
	m = send(m, "2")
	m = send(m, "s")
	if m.deviceSort != sortStatus || m.deviceOrder[0].Hostname != "web-1" {
		t.Fatalf("status sort = %v, first device = %q", m.deviceSort, m.deviceOrder[0].Hostname)
	}
	m = send(m, "s")
	if m.deviceSort != sortOwner || m.deviceOrder[0].Hostname != "web-1" {
		t.Fatalf("owner sort = %v, first device = %q", m.deviceSort, m.deviceOrder[0].Hostname)
	}
}

func TestGraphLines(t *testing.T) {
	edges := graph.Edges(fixtureTailnet())
	if len(edges) != 2 {
		t.Fatalf("fixture edges = %d, want 2", len(edges))
	}
	lines := graphLines(edges)
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2", len(lines))
	}
	want := "group:devs -> tag:prod [tcp:5432]"
	if lines[0] != want {
		t.Errorf("line 0 = %q, want %q", lines[0], want)
	}
	if !strings.Contains(lines[1], "*:*") || !strings.Contains(lines[1], "(legacy)") {
		t.Errorf("legacy line = %q, want ports and legacy marker", lines[1])
	}
	if empty := graphLines(nil); empty[0] != "no grants found in policy" {
		t.Errorf("empty edges line = %q", empty[0])
	}
}

func TestSeverityCounts(t *testing.T) {
	counts := severityCounts([]audit.Finding{
		{Severity: audit.High},
		{Severity: audit.High},
		{Severity: audit.Low},
	})
	if counts[audit.High] != 2 || counts[audit.Low] != 1 || counts[audit.Medium] != 0 {
		t.Fatalf("counts = %+v", counts)
	}
}
