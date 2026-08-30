package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/huza1fa/taildoc/internal/audit"
	"github.com/huza1fa/taildoc/internal/graph"
	"github.com/huza1fa/taildoc/internal/tailnet"
)

type tab int

const (
	tabOverview tab = iota
	tabDevices
	tabGraph
	tabCount
)

var tabNames = [tabCount]string{"Overview", "Devices", "Graph"}

type findingItem struct {
	f     audit.Finding
	index int
}

func (i findingItem) Title() string       { return i.f.Title }
func (i findingItem) Description() string { return string(i.f.Severity) }
func (i findingItem) FilterValue() string { return i.f.Title + " " + string(i.f.Severity) }

type model struct {
	tailnet  *tailnet.Tailnet
	findings []audit.Finding
	edges    []graph.Edge

	activeTab tab
	quitting  bool

	findingList list.Model
	deviceTable table.Model
	graphView   viewport.Model
	detailView  viewport.Model

	deviceOrder []*tailnet.Device

	findingDetailOpen bool
	selectedFinding   int
	deviceDetail      *tailnet.Device

	width, height int
}

// newModel builds the TUI model from a collected tailnet snapshot.
// All data is captured up front; there is no live refresh in v1.
func newModel(t *tailnet.Tailnet) model {
	findings := audit.Run(t)
	items := make([]list.Item, len(findings))
	for i, f := range findings {
		items[i] = findingItem{f: f, index: i}
	}
	l := list.New(items, list.NewDefaultDelegate(), 0, 0)
	l.Title = "Findings"
	l.SetShowStatusBar(false)
	l.SetShowPagination(true)
	l.SetFilteringEnabled(false)
	l.DisableQuitKeybindings()

	cols := []table.Column{
		{Title: "Hostname", Width: 24},
		{Title: "OS", Width: 10},
		{Title: "Owner/Tags", Width: 30},
		{Title: "Online", Width: 12},
		{Title: "Key", Width: 12},
	}
	tb := table.New(
		table.WithColumns(cols),
		table.WithRows(deviceRows(t)),
		table.WithFocused(true),
		table.WithHeight(0),
	)
	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(colorDim).
		Bold(true)
	s.Selected = s.Selected.
		Foreground(lipgloss.NoColor{}).
		Background(lipgloss.AdaptiveColor{Light: "#E5E7EB", Dark: "#374151"}).
		Bold(false)
	tb.SetStyles(s)

	gv := viewport.New(0, 0)
	gv.SetContent(strings.Join(graphLines(graph.Edges(t)), "\n"))
	dv := viewport.New(0, 0)

	return model{
		tailnet:     t,
		findings:    findings,
		edges:       graph.Edges(t),
		deviceOrder: t.Devices,
		findingList: l,
		deviceTable: tb,
		graphView:   gv,
		detailView:  dv,
	}
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.resize()

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			m.quitting = true
			return m, tea.Quit
		case "esc":
			if m.findingDetailOpen {
				m.findingDetailOpen = false
				return m, nil
			}
			if m.deviceDetail != nil {
				m.deviceDetail = nil
				return m, nil
			}
		case "1":
			m.activeTab = tabOverview
			return m, nil
		case "2":
			m.activeTab = tabDevices
			return m, nil
		case "3":
			m.activeTab = tabGraph
			return m, nil
		case "tab", "right":
			m.activeTab = (m.activeTab + 1) % tabCount
			return m, nil
		case "shift+tab", "left":
			m.activeTab = (m.activeTab + tabCount - 1) % tabCount
			return m, nil
		case "enter":
			m.selectItem()
			return m, nil
		}
	}

	// While a detail overlay is open, keys do not reach the widgets behind it.
	if m.findingDetailOpen || m.deviceDetail != nil {
		var cmd tea.Cmd
		m.detailView, cmd = m.detailView.Update(msg)
		return m, cmd
	}

	var cmd tea.Cmd
	switch m.activeTab {
	case tabDevices:
		m.deviceTable, cmd = m.deviceTable.Update(msg)
	case tabGraph:
		m.graphView, cmd = m.graphView.Update(msg)
	default:
		m.findingList, cmd = m.findingList.Update(msg)
	}
	return m, cmd
}

// selectItem handles Enter on the focused tab's primary widget.
// Must be called on an addressable model so mutations stick.
func (m *model) selectItem() {
	switch m.activeTab {
	case tabOverview:
		if sel, ok := m.findingList.SelectedItem().(findingItem); ok {
			m.selectedFinding = sel.index
			m.findingDetailOpen = true
			m.refreshDetail()
		}
	case tabDevices:
		if idx := m.deviceTable.Cursor(); idx >= 0 && idx < len(m.deviceOrder) {
			m.deviceDetail = m.deviceOrder[idx]
			m.refreshDetail()
		}
	}
}

func (m *model) resize() {
	if m.width == 0 || m.height == 0 {
		return
	}
	const chrome = 4 // tabs header + status bar padding allowance
	h := max(m.height-chrome, 5)
	m.findingList.SetSize(m.width-2, h-2)
	m.deviceTable.SetWidth(m.width - 2)
	m.deviceTable.SetHeight(h - 3)
	m.graphView.Width = m.width - 2
	m.graphView.Height = h - 2
	m.refreshDetail()
}

func (m *model) refreshDetail() {
	if m.width == 0 || (!m.findingDetailOpen && m.deviceDetail == nil) {
		return
	}
	m.detailView.Width = max(m.width-8, 20)
	m.detailView.Height = max(m.height-6, 3)
	if m.findingDetailOpen && len(m.findings) > m.selectedFinding {
		m.detailView.SetContent(m.renderFindingDetail(m.findings[m.selectedFinding]))
	} else if m.deviceDetail != nil {
		m.detailView.SetContent(m.renderDeviceDetail(m.deviceDetail))
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// deviceRows builds the devices table rows from a snapshot. Row cells:
// Hostname, OS, Owner/Tags, Online status, Key expiry state. The selected
// device is resolved through deviceOrder (parallel to rows).
func deviceRows(t *tailnet.Tailnet) []table.Row {
	rows := make([]table.Row, 0, len(t.Devices))
	for _, d := range t.Devices {
		rows = append(rows, table.Row{
			d.Hostname,
			d.OS,
			ownerTagCell(d),
			onlineCell(d.Online),
			keyExpiryCell(d),
		})
	}
	return rows
}

func ownerTagCell(d *tailnet.Device) string {
	parts := make([]string, 0, 2)
	if d.Owner != "" {
		parts = append(parts, d.Owner)
	}
	if len(d.Tags) > 0 {
		parts = append(parts, strings.Join(d.Tags, ","))
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " ")
}

func onlineCell(online bool) string {
	if online {
		return lipgloss.NewStyle().Foreground(colorGood).Render("● online")
	}
	return lipgloss.NewStyle().Foreground(colorDim).Render("○ offline")
}

func keyExpiryCell(d *tailnet.Device) string {
	style := lipgloss.NewStyle()
	switch {
	case d.KeyExpiryDisabled:
		return style.Foreground(colorMedium).Render("no expiry")
	case d.Expires.IsZero():
		return style.Foreground(colorDim).Render("-")
	case time.Until(d.Expires) < 0:
		return style.Foreground(colorHigh).Render("expired")
	case time.Until(d.Expires) < 30*24*time.Hour:
		return style.Foreground(colorMedium).Render("expiring")
	default:
		return style.Foreground(colorGood).Render("ok")
	}
}

// graphLines renders grant edges as plain text lines "src -> dst [ports]".
func graphLines(edges []graph.Edge) []string {
	if len(edges) == 0 {
		return []string{"no grants found in policy"}
	}
	lines := make([]string, 0, len(edges))
	for _, e := range edges {
		suffix := ""
		if e.Legacy {
			suffix = " (legacy)"
		}
		lines = append(lines, fmt.Sprintf("%s -> %s [%s]%s", e.Src, e.Dst, e.Label, suffix))
	}
	return lines
}

// severityCounts tallies findings by severity for the overview summary.
func severityCounts(findings []audit.Finding) map[audit.Severity]int {
	counts := map[audit.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}
