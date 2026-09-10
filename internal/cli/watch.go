package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/huza1fa/taildoc/internal/diff"
	"github.com/huza1fa/taildoc/internal/tailnet"
)

const minimumWatchInterval = 5 * time.Second

func runWatch(ctx context.Context, args []string) error {
	fs := newFlagSet("watch")
	interval := fs.Duration("interval", 30*time.Second, "refresh interval (minimum 5s)")
	once := fs.Bool("once", false, "collect and print the initial inventory summary, then exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: taildoc watch [--interval DURATION] [--once]")
	}
	if *interval < minimumWatchInterval {
		return fmt.Errorf("--interval must be at least %s", minimumWatchInterval)
	}
	return watch(ctx, *interval, *once, collect, os.Stdout)
}

type collectTailnet func(context.Context) (*tailnet.Tailnet, error)

func watch(ctx context.Context, interval time.Duration, once bool, collectFn collectTailnet, out io.Writer) error {
	previous, err := collectFn(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Baseline: %d device(s), %d user(s), %d grant(s)\n", len(previous.Devices), len(previous.Users), len(previous.Grants))
	if once {
		return nil
	}
	fmt.Fprintf(out, "Watching every %s; press Ctrl-C to stop.\n", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			current, err := collectFn(ctx)
			if err != nil {
				fmt.Fprintf(out, "[%s] refresh failed: %v\n", time.Now().Format(time.RFC3339), err)
				continue
			}
			changes := diff.Diff(previous, current)
			if len(changes) > 0 {
				fmt.Fprintf(out, "[%s] %d change(s)\n", time.Now().Format(time.RFC3339), len(changes))
				writeChanges(out, changes)
			}
			previous = current
		}
	}
}

func writeChanges(out io.Writer, changes []diff.Change) {
	for _, change := range changes {
		prefix := "~"
		switch change.Kind {
		case "added":
			prefix = "+"
		case "removed":
			prefix = "-"
		}
		if change.Detail == "" {
			fmt.Fprintf(out, "  %s %s\n", prefix, change.What)
			continue
		}
		fmt.Fprintf(out, "  %s %s — %s\n", prefix, change.What, change.Detail)
	}
}
