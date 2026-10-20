package tui

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/huza1fa/taildoc/internal/tailnet"
)

func TestDeviceSearchAndSelection(t *testing.T) {
	m := resize(newModel(fixtureTailnet()), 100, 30)
	m = send(m, "2")
	m = send(m, "/")
	m = send(m, "100.64.0.3")
	if len(m.deviceOrder) != 1 || m.deviceOrder[0].Hostname != "tagged-node" {
		t.Fatalf("search: %+v", m.deviceOrder)
	}
	m = send(m, "enter")
	m = send(m, "enter")
	if m.deviceDetail == nil || m.deviceDetail.ID != "d3" {
		t.Fatal("search selected wrong device")
	}
	m = send(m, "esc")
	m = send(m, "esc")
	if len(m.deviceOrder) != 3 {
		t.Fatal("escape did not clear search")
	}
	m = send(m, "/")
	m = send(m, "q")
	if m.quitting {
		t.Fatal("q in search quit the app")
	}
	m = send(m, "ctrl+c")
	if !m.quitting {
		t.Fatal("Ctrl-C did not quit during search")
	}
}
func TestExplainWorkflowAndOverlayIsolation(t *testing.T) {
	tn := fixtureTailnet()
	tn.HasAccessRules = true
	tn.Grants = []*tailnet.Grant{{Sources: []string{"alice@example.com"}, Destinations: []string{"tag:prod"}, IP: []string{"tcp:443"}}}
	m := resize(newModel(tn), 100, 30)
	m = send(m, "2")
	m.selectDevice("d1")
	m = send(m, "e")
	m.selectDevice("d3")
	m = send(m, "enter")
	if !m.explainEditing || m.explainSource.ID != "d1" || m.explainTarget.ID != "d3" {
		t.Fatalf("selection failed: %+v", m)
	}
	m.explainPort.SetValue("70000")
	m = send(m, "enter")
	if !m.explainEditing || m.message == "" {
		t.Fatal("invalid port was accepted")
	}
	m.explainPort.SetValue("443")
	m = send(m, "tab")
	if m.explainField != 1 {
		t.Fatal("protocol input not focused")
	}
	m = send(m, "enter")
	if !m.explanationOpen || !m.explainResult.Allowed {
		t.Fatalf("evaluation failed: %+v", m.explainResult)
	}
	if view := m.View(); !strings.Contains(view, "POLICY ALLOWED") || !strings.Contains(view, "web-1") {
		t.Fatalf("missing explanation: %s", view)
	}
	active := m.activeTab
	m = send(m, "1")
	if m.activeTab != active {
		t.Fatal("tab shortcut leaked behind overlay")
	}
	m = send(m, "esc")
	if m.explanationOpen || m.explainSource != nil {
		t.Fatal("escape did not close workflow")
	}
}
func TestRefreshFailureAndSelectionRetention(t *testing.T) {
	m := resize(newModel(fixtureTailnet()), 100, 30)
	m.activeTab = tabDevices
	m.selectDevice("d3")
	calls := 0
	m.refresh = func(ctx context.Context) (*tailnet.Tailnet, error) {
		calls++
		if _, ok := ctx.Deadline(); !ok {
			t.Error("refresh has no deadline")
		}
		tn := fixtureTailnet()
		tn.CollectedAt = tn.CollectedAt.Add(time.Hour)
		return tn, nil
	}
	next, cmd := m.Update(key("r"))
	m = next.(model)
	if !m.refreshing || cmd == nil {
		t.Fatal("refresh did not start")
	}
	_, duplicate := m.Update(key("r"))
	if duplicate != nil {
		t.Fatal("duplicate refresh started")
	}
	next, _ = m.Update(cmd())
	m = next.(model)
	if calls != 1 || m.refreshing || m.currentDevice().ID != "d3" || m.activeTab != tabDevices {
		t.Fatal("refresh lost state")
	}
	before := m.tailnet
	next, _ = m.Update(refreshedMsg{err: errors.New("offline")})
	m = next.(model)
	if m.tailnet != before || !strings.Contains(m.message, "offline") {
		t.Fatal("failed refresh discarded snapshot")
	}
}
func TestSnapshotExpiryUsesCollectionTime(t *testing.T) {
	tn := fixtureTailnet()
	tn.CollectedAt = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	tn.Devices[0].Expires = tn.CollectedAt.Add(365 * 24 * time.Hour)
	m := newModel(tn)
	m.selectDevice("d1")
	if strings.Contains(m.renderDeviceDetail(tn.Devices[0]), "expired") {
		t.Fatal("snapshot expiry used wall clock")
	}
	for i, d := range m.deviceOrder {
		if d.ID == "d1" && !strings.Contains(m.deviceTable.Rows()[i][4], "ok") {
			t.Fatal("table expiry used wall clock")
		}
	}
}
func TestResizeAndRefreshDuringSearch(t *testing.T) {
	m := resize(newModel(fixtureTailnet()), 80, 24)
	m.activeTab = tabDevices
	m = send(m, "/")
	m = send(m, "tag:prod")
	next, _ := m.Update(tea.WindowSizeMsg{Width: 90, Height: 25})
	m = next.(model)
	if !m.searchingDevices || len(m.deviceOrder) != 1 {
		t.Fatal("resize lost filter")
	}
	next, _ = m.Update(refreshedMsg{tailnet: fixtureTailnet()})
	m = next.(model)
	if !m.searchingDevices || len(m.deviceOrder) != 1 {
		t.Fatal("refresh lost filter")
	}
}

func TestViewsFitCommonTerminalSizes(t *testing.T) {
	for _, size := range [][2]int{{80, 24}, {120, 40}, {60, 20}} {
		m := resize(newModel(fixtureTailnet()), size[0], size[1])
		for _, tab := range []tab{tabOverview, tabDevices, tabGraph} {
			m.activeTab = tab
			view := m.View()
			if width := lipgloss.Width(view); width > size[0] {
				t.Errorf("tab %v at %v renders width %d", tab, size, width)
			}
			if height := strings.Count(view, "\n") + 1; height > size[1] {
				t.Errorf("tab %v at %v renders %d lines", tab, size, height)
			}
		}
	}
}
