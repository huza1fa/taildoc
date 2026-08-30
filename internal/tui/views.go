package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/huza1fa/taildoc/internal/audit"
	"github.com/huza1fa/taildoc/internal/tailnet"
)

func (m model) View() string {
	if m.quitting {
		return ""
	}
	if m.width == 0 {
		return dimStyle.Render("Loading taildoc…")
	}

	if m.findingDetailOpen && len(m.findings) > 0 {
		return overlayBoxStyle.Width(max(m.width-4, 24)).Render(m.detailView.View())
	}
	if m.deviceDetail != nil {
		return overlayBoxStyle.Width(max(m.width-4, 24)).Render(m.detailView.View())
	}

	var body string
	switch m.activeTab {
	case tabDevices:
		body = m.renderDevicesTab()
	case tabGraph:
		body = m.renderGraphTab()
	default:
		body = m.renderOverviewTab()
	}

	return lipgloss.JoinVertical(lipgloss.Left, m.renderTabs(), body, m.statusBar())
}

func (m model) renderTabs() string {
	cells := make([]string, tabCount)
	for i, name := range tabNames {
		style := tabInactiveStyle
		if tab(i) == m.activeTab {
			style = tabActiveStyle
		}
		cells[i] = style.Render(fmt.Sprintf("%d %s", i+1, name))
	}
	header := lipgloss.JoinHorizontal(lipgloss.Top, cells...)
	title := appTitleStyle.Render("taildoc")
	gap := m.width - lipgloss.Width(header) - lipgloss.Width(title)
	if gap > 0 {
		return lipgloss.JoinHorizontal(lipgloss.Top, title, strings.Repeat(" ", gap), header)
	}
	return header
}

func (m model) renderOverviewTab() string {
	t := m.tailnet
	counts := severityCounts(m.findings)

	lines := []string{
		detailLabelStyle.Render("Tailnet") + "  " + orDash(t.Name),
		fmt.Sprintf("%s %d   %s %d   %s %d",
			detailLabelStyle.Render("Users"), len(t.Users),
			detailLabelStyle.Render("Devices"), len(t.Devices),
			detailLabelStyle.Render("Grants"), len(t.Grants)),
		"",
		sevBadge("HIGH") + fmt.Sprint(counts[audit.High]),
		sevBadge("MEDIUM") + fmt.Sprint(counts[audit.Medium]),
		sevBadge("LOW") + fmt.Sprint(counts[audit.Low]),
		sevBadge("INFO") + fmt.Sprint(counts[audit.Info]),
		"",
	}
	header := headerBoxStyle.Render(lipgloss.JoinVertical(lipgloss.Left, lines...))

	m.findingList.SetHeight(max(m.height-lipgloss.Height(header)-3, 5))
	listView := m.findingList.View()

	return lipgloss.JoinVertical(lipgloss.Left, header, listView)
}

func (m model) renderDevicesTab() string {
	m.deviceTable.SetHeight(max(m.height-4, 5))
	return m.deviceTable.View()
}

func (m model) renderGraphTab() string {
	header := detailLabelStyle.Render(fmt.Sprintf("Grant edges (%d)", len(m.edges))) +
		"  " + dimStyle.Render("↑/↓ scroll")
	m.graphView.Height = max(m.height-5, 5)
	return lipgloss.JoinVertical(lipgloss.Left, header, m.graphView.View())
}

func (m model) statusBar() string {
	left := statusActiveTabStyle.Render(tabNames[m.activeTab])
	mid := dimStyle.Render(fmt.Sprintf(" %d devices · %d users · %d findings ",
		len(m.tailnet.Devices), len(m.tailnet.Users), len(m.findings)))
	right := "1-3 tabs · ←→/tab switch · enter details · esc back · q quit"
	pad := m.width - lipgloss.Width(left) - lipgloss.Width(mid) - lipgloss.Width(right)
	if pad < 1 {
		pad = 1
	}
	return statusBarStyle.Render(left + mid + strings.Repeat(" ", pad) + right)
}

// renderFindingDetail shows the full finding as a full-screen overlay.
func (m model) renderFindingDetail(f audit.Finding) string {
	lines := []string{
		sevBadge(string(f.Severity)) + lipgloss.NewStyle().Bold(true).Render(f.Title),
		"",
		wrap(f.Detail, max(m.width-10, 40)),
	}
	if len(f.Evidence) > 0 {
		lines = append(lines, "", detailLabelStyle.Render("Evidence"))
		for _, e := range f.Evidence {
			lines = append(lines, bulletStyle.Render("  • ")+e)
		}
	}
	if f.Why != "" {
		lines = append(lines, "", detailLabelStyle.Render("Why it matters"), wrap(f.Why, max(m.width-12, 38)))
	}
	if f.Next != "" {
		lines = append(lines, "", detailLabelStyle.Render("Next step"), wrap(f.Next, max(m.width-12, 38)))
	}
	lines = append(lines, "", dimStyle.Render("up/down scroll · esc back"))
	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

func (m model) renderDeviceDetail(d *tailnet.Device) string {
	lines := []string{
		appTitleStyle.Render("Device: " + d.Hostname),
		"",
		row("Name", d.Name),
		row("OS / Version", d.OS+" "+orDash(d.ClientVersion)),
		row("Owner", orDash(d.Owner)),
		row("Tags", orDash(strings.Join(d.Tags, ", "))),
		row("Addresses", orDash(strings.Join(d.Addresses, ", "))),
		row("Online", boolLabel(d.Online)),
		row("Authorized", boolLabel(d.Authorized)),
		row("SSH enabled", boolLabel(d.SSHEnabled)),
		row("Key expires", keyExpiryLong(d)),
		row("Version", orDash(d.ClientVersion)),
		"",
		detailLabelStyle.Render("Routes"),
		routesBlock(d),
		"",
		dimStyle.Render("up/down scroll · esc back"),
	}
	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

func routesBlock(d *tailnet.Device) string {
	var lines []string
	seen := map[string]bool{}
	addRoute := func(r string, isEnabled bool) {
		if r == "" || seen[r] {
			return
		}
		seen[r] = true
		state := dimStyle.Render("advertised")
		if isEnabled {
			state = lipgloss.NewStyle().Foreground(colorGood).Render("enabled   ")
		}
		lines = append(lines, "  "+state+"  "+r)
	}
	for _, r := range d.EnabledRoutes {
		addRoute(r, true)
	}
	for _, r := range d.AdvertisedRoutes {
		addRoute(r, false)
	}
	if len(lines) == 0 {
		return dimStyle.Render("  none advertised")
	}
	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

func keyExpiryLong(d *tailnet.Device) string {
	switch {
	case d.KeyExpiryDisabled:
		return "disabled (key never expires)"
	case d.Expires.IsZero():
		return "-"
	case time.Until(d.Expires) < 0:
		return d.Expires.Format(time.RFC3339) + " (expired)"
	default:
		return d.Expires.Format(time.RFC3339)
	}
}

// wrap is a minimal word-wrapping helper for detail text.
func wrap(s string, width int) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	lineLen := 0
	for i, w := range words {
		if i > 0 && lineLen+1+len(w) > width {
			b.WriteString("\n")
			lineLen = 0
		} else if i > 0 {
			b.WriteString(" ")
			lineLen++
		}
		b.WriteString(w)
		lineLen += len(w)
	}
	return b.String()
}

func row(label, value string) string {
	return fmt.Sprintf("  %-14s %s", detailLabelStyle.Render(label), value)
}

func boolLabel(b bool) string {
	if b {
		return lipgloss.NewStyle().Foreground(colorGood).Render("yes")
	}
	return lipgloss.NewStyle().Foreground(colorDim).Render("no")
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
