package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/huza1fa/taildoc/internal/snapshot"
	"github.com/huza1fa/taildoc/internal/tailnet"
	"github.com/huza1fa/taildoc/internal/tui"
)

// runUI launches the interactive TUI. Data is collected up front (or loaded
// from --snapshot); the TUI works over a static snapshot for v1.
func runUI(ctx context.Context, args []string) error {
	fs := newFlagSet("ui")
	snapshotPath := fs.String("snapshot", "", "load a saved snapshot JSON instead of collecting live")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var (
		t   *tailnet.Tailnet
		err error
	)
	switch {
	case *snapshotPath != "":
		t, err = snapshot.Load(*snapshotPath)
		if err == nil {
			fmt.Fprintf(os.Stderr, "loaded snapshot %s (collected %s)\n",
				*snapshotPath, t.CollectedAt.Format(time.RFC3339))
		}
	default:
		t, err = collect(ctx)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "taildoc ui: %v\n", err)
		fmt.Fprintln(os.Stderr, "hint: set TS_ACCESS_TOKEN, run `taildoc auth login`, or pass --snapshot FILE")
		return err
	}

	return tui.Run(t)
}

var colorEnabled = detectColor()

func detectColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

const (
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiBlue   = "\033[34m"
	ansiGray   = "\033[90m"
	ansiBold   = "\033[1m"
	ansiReset  = "\033[0m"
)

func colorize(code, s string) string {
	if !colorEnabled || s == "" {
		return s
	}
	return code + s + ansiReset
}

func bold(s string) string   { return colorize(ansiBold, s) }
func red(s string) string    { return colorize(ansiRed, s) }
func green(s string) string  { return colorize(ansiGreen, s) }
func yellow(s string) string { return colorize(ansiYellow, s) }
func blue(s string) string   { return colorize(ansiBlue, s) }
func gray(s string) string   { return colorize(ansiGray, s) }

func dim(format string, a ...any) string {
	if len(a) == 0 {
		return gray(format)
	}
	return gray(fmt.Sprintf(format, a...))
}
