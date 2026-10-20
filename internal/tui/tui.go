// Package tui entry point: Run starts the interactive bubbletea program
// over an already-collected tailnet snapshot.
package tui

import (
	"context"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/huza1fa/taildoc/internal/tailnet"
)

// Run launches the TUI with the given tailnet snapshot. The snapshot is
// refreshed only when the user asks and a Refresh callback is supplied.
type Options struct {
	Context  context.Context
	Refresh  func(context.Context) (*tailnet.Tailnet, error)
	Snapshot bool
}

func Run(t *tailnet.Tailnet, options ...Options) error {
	m := newModel(t)
	if len(options) > 0 {
		opts := options[0]
		m.refresh, m.snapshot = opts.Refresh, opts.Snapshot
		if opts.Context != nil {
			m.ctx = opts.Context
		}
	}
	if os.Getenv("NO_COLOR") != "" {
		lipgloss.SetColorProfile(termenv.Ascii)
	}
	if _, err := tea.NewProgram(m, tea.WithAltScreen(), tea.WithContext(m.ctx)).Run(); err != nil {
		return err
	}
	return nil
}
