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

	if m.width < 45 || m.height < 12 {
		return "Resize the terminal to at least 45 columns × 12 rows. Press q to quit."
	}
	if m.explainEditing {
		return m.renderExplainInput()
	}
	if m.explanationOpen {
		return overlayBoxStyle.Width(max(m.width-4, 24)).Render(m.detailView.View())
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

func (m model) overviewHeader() string {
	t := m.tailnet
	counts := severityCounts(m.findings)
	lines := []string{
		detailLabelStyle.Render("Tailnet") + "  " + orDash(t.Name),
		fmt.Sprintf("Users %d · Devices %d · Grants %d", len(t.Users), len(t.Devices), len(t.Grants)),
		"",
		sevBadge("HIGH") + fmt.Sprint(counts[audit.High]) + "  " + sevBadge("MEDIUM") + fmt.Sprint(counts[audit.Medium]) + "  " + sevBadge("LOW") + fmt.Sprint(counts[audit.Low]) + "  " + sevBadge("INFO") + fmt.Sprint(counts[audit.Info]),
	}
	return headerBoxStyle.Width(max(m.width-4, 1)).Render(strings.Join(lines, "\n"))
}
func (m model) devicesHeader() string {
	header := detailLabelStyle.Render("Devices") + "  " + dimStyle.Render("s sort: "+m.deviceSortLabel())
	if m.searchingDevices || m.deviceSearch.Value() != "" {
		header += "\n" + m.deviceSearch.View()
	}
	if m.explainSource != nil {
		header += "\nSource: " + m.explainSource.Hostname + " · select destination, Enter · Esc cancel"
	}
	return lipgloss.NewStyle().Width(max(m.width-2, 1)).Render(header)
}
func (m model) renderOverviewTab() string {
	return lipgloss.JoinVertical(lipgloss.Left, m.overviewHeader(), m.findingList.View())
}
func (m model) renderDevicesTab() string {
	return lipgloss.JoinVertical(lipgloss.Left, m.devicesHeader(), m.deviceTable.View())
}
func (m model) renderGraphTab() string {
	header := detailLabelStyle.Render(fmt.Sprintf("Grant edges (%d)", len(m.edges))) + "  " + dimStyle.Render("↑/↓ scroll")
	return lipgloss.JoinVertical(lipgloss.Left, header, m.graphView.View())
}

func (m model) statusBar() string {
	stamp := "unknown"
	if !m.tailnet.CollectedAt.IsZero() {
		stamp = m.tailnet.CollectedAt.Format("2006-01-02 15:04:05 MST")
	}
	mode := "live"
	if m.snapshot {
		mode = "snapshot"
	}
	status := fmt.Sprintf("%s · %d devices · collected %s (%s)", tabNames[m.activeTab], len(m.tailnet.Devices), stamp, mode)
	if m.message != "" {
		status += "\n" + m.message
	}
	hints := "1–3 tabs · / search · s sort · e source · Enter details/destination · r refresh · q quit"
	if m.width < 90 {
		hints = "1–3 tabs · / search · s sort · e explain · r refresh · q quit"
	}
	return statusBarStyle.Width(max(m.width-2, 1)).Render(status + "\n" + hints)
}

func (m model) renderExplainInput() string {
	lines := []string{
		"Explain packet access", "",
		m.explainSource.Hostname + " → " + m.explainTarget.Hostname,
		"", m.explainPort.View(), m.explainProto.View(), "",
		"Tab switches fields · Enter evaluates · Esc selects another destination",
	}
	if m.message != "" {
		lines = append(lines, "", m.message)
	}
	return overlayBoxStyle.Width(max(m.width-4, 24)).Render(strings.Join(lines, "\n"))
}
func (m model) renderExplanation() string {
	result := "POLICY DENIED"
	if m.explainResult.Allowed {
		result = "POLICY ALLOWED"
	} else if m.explainResult.Indeterminate {
		result = "CANNOT DETERMINE"
	}
	lines := []string{"Access explanation", m.explainSource.Hostname + " → " + m.explainTarget.Hostname + " " + m.explainProto.Value() + "/" + m.explainPort.Value(), "", result}
	if m.explainResult.DefaultAllowed {
		lines = append(lines, "No access rules are configured; the default policy permits access.")
	}
	for _, match := range m.explainResult.Matches {
		lines = append(lines, "", "src: "+strings.Join(match.Grant.Sources, ", "), "dst: "+strings.Join(match.Grant.Destinations, ", "))
		for _, chain := range match.Chain {
			lines = append(lines, "  • "+chain)
		}
	}
	if result == "POLICY DENIED" {
		lines = append(lines, "No matching allow path for this device pair, protocol, and port.")
	}
	for _, u := range m.explainResult.Unsupported {
		lines = append(lines, "", u.Selector+": "+u.Reason)
	}
	lines = append(lines, "", "Policy only: this does not test listeners or runtime connectivity.", "↑/↓ scroll · Esc back")
	return lipgloss.NewStyle().Width(max(m.width-10, 20)).Render(strings.Join(lines, "\n"))
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
		row("Key expires", keyExpiryLongAt(d, m.referenceTime())),
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

func keyExpiryLongAt(d *tailnet.Device, at time.Time) string {
	switch {
	case d.KeyExpiryDisabled:
		return "disabled (key never expires)"
	case d.Expires.IsZero():
		return "-"
	case d.Expires.Sub(at) < 0:
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
