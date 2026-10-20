package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/huza1fa/taildoc/internal/audit"
	"github.com/huza1fa/taildoc/internal/graph"
	"github.com/huza1fa/taildoc/internal/policy"
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
	deviceSort  deviceSort

	findingDetailOpen bool
	selectedFinding   int
	deviceDetail      *tailnet.Device

	width, height    int
	ctx              context.Context
	refresh          func(context.Context) (*tailnet.Tailnet, error)
	refreshing       bool
	message          string
	snapshot         bool
	deviceSearch     textinput.Model
	searchingDevices bool
	explainSource    *tailnet.Device
	explainTarget    *tailnet.Device
	explainPort      textinput.Model
	explainProto     textinput.Model
	explainEditing   bool
	explainField     int
	explanationOpen  bool
	explainResult    policy.Result
}

type deviceSort int

const (
	sortHostname deviceSort = iota
	sortStatus
	sortOwner
)

// newModel builds the TUI model from a collected tailnet snapshot.
// A refresh callback may be attached by Run. Every view uses one snapshot.
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
	// Findings are often long enough that the built-in filter is a much faster
	// way to get back to a particular issue than scrolling.
	l.SetFilteringEnabled(true)
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
		BorderTop(false).BorderLeft(false).BorderRight(false).BorderBottom(true).
		Bold(true)
	s.Selected = s.Selected.
		Foreground(lipgloss.NoColor{}).
		Background(lipgloss.AdaptiveColor{Light: "#E5E7EB", Dark: "#374151"}).
		Bold(false)
	tb.SetStyles(s)

	gv := viewport.New(0, 0)
	gv.SetContent(strings.Join(graphLines(graph.Edges(t)), "\n"))
	dv := viewport.New(0, 0)

	search := textinput.New()
	search.Prompt = "Search: "
	search.CharLimit = 256
	port := textinput.New()
	port.Prompt = "Port: "
	port.CharLimit = 5
	port.SetValue("443")
	proto := textinput.New()
	proto.Prompt = "Protocol: "
	proto.CharLimit = 4
	proto.SetValue("tcp")
	m := model{
		tailnet:     t,
		findings:    findings,
		edges:       graph.Edges(t),
		deviceOrder: append([]*tailnet.Device(nil), t.Devices...),
		findingList: l,
		deviceTable: tb,
		graphView:   gv,
		detailView:  dv,
		ctx:         context.Background(), deviceSearch: search, explainPort: port, explainProto: proto,
	}
	m.rebuildDevices()
	return m
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	next, cmd := m.update(msg)
	result := next.(model)
	result.layout()
	return result, cmd
}
func (m model) update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.resize()
		return m, nil
	case refreshedMsg:
		m.refreshing = false
		if msg.err != nil {
			m.message = "Refresh failed: " + msg.err.Error()
			return m, nil
		}
		if msg.tailnet == nil {
			m.message = "Refresh failed: no data returned"
			return m, nil
		}
		selected := deviceRef(m.currentDevice())
		next := newModel(msg.tailnet)
		next.ctx, next.refresh, next.snapshot = m.ctx, m.refresh, m.snapshot
		next.width, next.height, next.activeTab = m.width, m.height, m.activeTab
		next.deviceSort = m.deviceSort
		next.deviceSearch = m.deviceSearch
		next.searchingDevices = m.searchingDevices
		if value := m.findingList.FilterValue(); value != "" {
			next.findingList.SetFilterText(value)
			next.findingList.SetFilterState(m.findingList.FilterState())
		}
		next.rebuildDevices()
		next.selectDevice(selected)
		next.resize()
		next.message = "Refreshed successfully"
		return next, nil
	case tea.KeyMsg:
		k := msg.String()
		if k == "ctrl+c" {
			m.quitting = true
			return m, tea.Quit
		}
		if m.explainEditing {
			return m.updateExplainInput(msg)
		}
		if m.searchingDevices {
			switch k {
			case "enter":
				m.searchingDevices = false
				m.deviceSearch.Blur()
				return m, nil
			case "esc":
				m.searchingDevices = false
				m.deviceSearch.SetValue("")
				m.deviceSearch.Blur()
				m.rebuildDevices()
				return m, nil
			}
			var cmd tea.Cmd
			m.deviceSearch, cmd = m.deviceSearch.Update(msg)
			m.rebuildDevices()
			return m, cmd
		}
		if m.activeTab == tabOverview && m.findingList.FilterState() == list.Filtering {
			var cmd tea.Cmd
			m.findingList, cmd = m.findingList.Update(msg)
			return m, cmd
		}
		if k == "q" {
			m.quitting = true
			return m, tea.Quit
		}
		if m.findingDetailOpen || m.deviceDetail != nil || m.explanationOpen {
			if k == "esc" {
				m.findingDetailOpen = false
				m.deviceDetail = nil
				m.explanationOpen = false
				m.explainSource = nil
				m.explainTarget = nil
				return m, nil
			}
			var cmd tea.Cmd
			m.detailView, cmd = m.detailView.Update(msg)
			return m, cmd
		}
		switch k {
		case "r":
			if m.refresh != nil && !m.refreshing {
				m.refreshing = true
				m.message = "Refreshing…"
				refresh, ctx := m.refresh, m.ctx
				return m, func() tea.Msg {
					ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
					defer cancel()
					t, err := refresh(ctx)
					return refreshedMsg{t, err}
				}
			}
			return m, nil
		case "esc":
			if m.explainSource != nil {
				m.explainSource = nil
				m.message = "Access selection cancelled"
				return m, nil
			}
			if m.activeTab == tabDevices {
				m.deviceSearch.SetValue("")
				m.rebuildDevices()
				return m, nil
			}
		case "/":
			if m.activeTab == tabDevices {
				m.searchingDevices = true
				return m, m.deviceSearch.Focus()
			}
		case "e":
			if m.activeTab == tabDevices && m.currentDevice() != nil {
				m.explainSource = m.currentDevice()
				m.message = "Choose a destination and press Enter"
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
			if m.activeTab == tabDevices && m.explainSource != nil && m.currentDevice() != nil {
				m.explainTarget = m.currentDevice()
				m.explainEditing = true
				m.explainField = 0
				m.message = ""
				return m, m.explainPort.Focus()
			}
			m.selectItem()
			return m, nil
		case "s":
			if m.activeTab == tabDevices {
				m.cycleDeviceSort()
				return m, nil
			}
		}
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

type refreshedMsg struct {
	tailnet *tailnet.Tailnet
	err     error
}

func deviceRef(d *tailnet.Device) string {
	if d == nil {
		return ""
	}
	if d.ID != "" {
		return d.ID
	}
	return d.Hostname
}
func (m model) currentDevice() *tailnet.Device {
	i := m.deviceTable.Cursor()
	if i < 0 || i >= len(m.deviceOrder) {
		return nil
	}
	return m.deviceOrder[i]
}
func (m *model) selectDevice(ref string) {
	for i, d := range m.deviceOrder {
		if deviceRef(d) == ref {
			m.deviceTable.SetCursor(i)
			return
		}
	}
}
func (m *model) cycleDeviceSort() { m.deviceSort = (m.deviceSort + 1) % 3; m.rebuildDevices() }
func (m *model) rebuildDevices() {
	selected := deviceRef(m.currentDevice())
	query := strings.ToLower(m.deviceSearch.Value())
	m.deviceOrder = nil
	for _, d := range m.tailnet.Devices {
		text := strings.ToLower(strings.Join([]string{d.Hostname, d.Name, d.Owner, d.OS, strings.Join(d.Tags, " "), strings.Join(d.Addresses, " ")}, " "))
		if strings.Contains(text, query) {
			m.deviceOrder = append(m.deviceOrder, d)
		}
	}
	sort.SliceStable(m.deviceOrder, func(i, j int) bool {
		a, b := m.deviceOrder[i], m.deviceOrder[j]
		switch m.deviceSort {
		case sortStatus:
			if a.Online != b.Online {
				return a.Online
			}
		case sortOwner:
			ao, bo := ownerTagCell(a), ownerTagCell(b)
			if ao != bo {
				return ao < bo
			}
		}
		return a.Hostname < b.Hostname
	})
	rows := deviceRowsFor(m.deviceOrder)
	for i, d := range m.deviceOrder {
		rows[i][4] = keyExpiryCellAt(d, m.referenceTime())
	}
	m.deviceTable.SetRows(rows)
	m.selectDevice(selected)
}
func (m model) referenceTime() time.Time {
	if !m.tailnet.CollectedAt.IsZero() {
		return m.tailnet.CollectedAt
	}
	return time.Now()
}
func (m model) updateExplainInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.explainEditing = false
		m.explainTarget = nil
		m.explainPort.Blur()
		m.explainProto.Blur()
		return m, nil
	case "tab", "shift+tab":
		m.explainField = 1 - m.explainField
		if m.explainField == 0 {
			m.explainProto.Blur()
			return m, m.explainPort.Focus()
		}
		m.explainPort.Blur()
		return m, m.explainProto.Focus()
	case "enter":
		port, proto := m.explainPort.Value(), strings.ToLower(m.explainProto.Value())
		ranges := policy.PortRanges(port)
		if len(ranges) != 1 || ranges[0][0] != ranges[0][1] {
			m.message = "Enter a destination port from 0 to 65535"
			return m, nil
		}
		if proto != "tcp" && proto != "udp" && proto != "sctp" {
			m.message = "Protocol must be tcp, udp, or sctp"
			return m, nil
		}
		m.explainResult = policy.Evaluate(m.tailnet, policy.Between(m.explainSource, m.explainTarget, port, proto))
		m.explainEditing = false
		m.explanationOpen = true
		m.message = ""
		m.explainPort.Blur()
		m.explainProto.Blur()
		m.refreshDetail()
		m.detailView.GotoTop()
		return m, nil
	}
	var cmd tea.Cmd
	if m.explainField == 0 {
		m.explainPort, cmd = m.explainPort.Update(msg)
	} else {
		m.explainProto, cmd = m.explainProto.Update(msg)
	}
	return m, cmd
}

func (m model) deviceSortLabel() string {
	switch m.deviceSort {
	case sortStatus:
		return "status"
	case sortOwner:
		return "owner/tag"
	default:
		return "hostname"
	}
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
	m.findingList.SetWidth(max(m.width-2, 1))
	m.deviceTable.SetWidth(max(m.width-2, 1))
	cells := max(m.width-12, 25) // five cells, each with one column of padding per side
	osWidth, onlineWidth, keyWidth := 7, 9, 10
	if m.width < 70 {
		osWidth, onlineWidth, keyWidth = 4, 7, 7
	}
	flexible := max(cells-osWidth-onlineWidth-keyWidth, 10)
	hostWidth := max(flexible*40/100, 5)
	m.deviceTable.SetColumns([]table.Column{
		{Title: "Hostname", Width: hostWidth}, {Title: "OS", Width: osWidth},
		{Title: "Owner/Tags", Width: flexible - hostWidth}, {Title: "Online", Width: onlineWidth}, {Title: "Key", Width: keyWidth},
	})
	m.layout()
	m.graphView.Width = m.width - 2
	m.graphView.Height = max(m.graphView.Height, 1)
	m.refreshDetail()
}

func (m *model) refreshDetail() {
	if m.width == 0 || (!m.findingDetailOpen && m.deviceDetail == nil && !m.explanationOpen) {
		return
	}
	m.detailView.Width = max(m.width-8, 20)
	m.detailView.Height = max(m.height-6, 3)
	if m.explanationOpen {
		m.detailView.SetContent(m.renderExplanation())
	} else if m.findingDetailOpen && len(m.findings) > m.selectedFinding {
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
	return deviceRowsFor(t.Devices)
}

func deviceRowsFor(devices []*tailnet.Device) []table.Row {
	rows := make([]table.Row, 0, len(devices))
	for _, d := range devices {
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

func keyExpiryCell(d *tailnet.Device) string { return keyExpiryCellAt(d, time.Now()) }
func keyExpiryCellAt(d *tailnet.Device, at time.Time) string {
	style := lipgloss.NewStyle()
	switch {
	case d.KeyExpiryDisabled:
		return style.Foreground(colorMedium).Render("no expiry")
	case d.Expires.IsZero():
		return style.Foreground(colorDim).Render("-")
	case d.Expires.Sub(at) < 0:
		return style.Foreground(colorHigh).Render("expired")
	case d.Expires.Sub(at) < 30*24*time.Hour:
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

// Keep widget pagination and scroll heights in sync with what View renders.
func (m *model) layout() {
	if m.width == 0 || m.height == 0 {
		return
	}
	content := max(m.height-lipgloss.Height(m.renderTabs())-lipgloss.Height(m.statusBar()), 1)
	m.findingList.SetHeight(max(content-lipgloss.Height(m.overviewHeader()), 1))
	m.deviceTable.SetHeight(max(content-lipgloss.Height(m.devicesHeader()), 1))
	m.graphView.Height = max(content-1, 1)
	m.deviceSearch.Width = max(m.width-12, 10)
}
