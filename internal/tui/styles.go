// Package tui implements the interactive terminal UI for Taildoc snapshots.
// Data collection happens in the caller; this package only renders.
package tui

import "github.com/charmbracelet/lipgloss"

var (
	colorHigh   = lipgloss.AdaptiveColor{Light: "#B3261E", Dark: "#F87171"} // red
	colorMedium = lipgloss.AdaptiveColor{Light: "#9A6700", Dark: "#FBBF24"} // amber/yellow
	colorLow    = lipgloss.AdaptiveColor{Light: "#0969DA", Dark: "#60A5FA"} // blue
	colorInfo   = lipgloss.AdaptiveColor{Light: "#57606A", Dark: "#9CA3AF"} // gray
	colorGood   = lipgloss.AdaptiveColor{Light: "#1A7F37", Dark: "#4ADE80"} // green
	colorAccent = lipgloss.AdaptiveColor{Light: "#8250DF", Dark: "#C084FC"} // purple
	colorDim    = lipgloss.AdaptiveColor{Light: "#6E7781", Dark: "#6B7280"}
)

var (
	appTitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorAccent).
			Padding(0, 1)

	tabActiveStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.AdaptiveColor{Light: "#FFFFFF", Dark: "#111827"}).
			Background(colorAccent).
			Padding(0, 2)

	tabInactiveStyle = lipgloss.NewStyle().
				Foreground(colorDim).
				Padding(0, 2)

	headerBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorDim).
			Padding(0, 1)

	severityBadge = func(s string, c lipgloss.TerminalColor) lipgloss.Style {
		return lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.AdaptiveColor{Light: "#FFFFFF", Dark: "#111827"}).
			Background(c).
			Padding(0, 1).
			MarginRight(1)
	}

	statusBarStyle = lipgloss.NewStyle().
			Background(lipgloss.AdaptiveColor{Light: "#EFF1F3", Dark: "#1F2430"}).
			Foreground(colorDim).
			Padding(0, 1)

	statusActiveTabStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorAccent)

	overlayBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorAccent).
			Padding(1, 2)

	detailLabelStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorAccent)

	dimStyle = lipgloss.NewStyle().Foreground(colorDim)

	bulletStyle = lipgloss.NewStyle().Foreground(colorDim)
)

func sevBadge(sev string) string {
	switch sev {
	case "HIGH":
		return severityBadge(sev, colorHigh).Render(sev)
	case "MEDIUM":
		return severityBadge(sev, colorMedium).Render(sev)
	case "LOW":
		return severityBadge(sev, colorLow).Render(sev)
	default:
		return severityBadge(sev, colorInfo).Render(sev)
	}
}
