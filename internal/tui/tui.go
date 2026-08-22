// Package tui entry point: Run starts the interactive bubbletea program
// over an already-collected tailnet snapshot.
package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/huza1fa/taildoc/internal/tailnet"
)

// Run launches the TUI with the given tailnet snapshot. The snapshot is
// treated as static; there is no live refresh in v1 (restart the command
// to re-collect).
func Run(t *tailnet.Tailnet) error {
	if _, err := tea.NewProgram(newModel(t), tea.WithAltScreen()).Run(); err != nil {
		return err
	}
	return nil
}
