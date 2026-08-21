// Package cli implements Taildoc's commands.
package cli

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/huza1fa/taildoc/internal/collector"
	"github.com/huza1fa/taildoc/internal/tailnet"
)

// Run executes the CLI with the given arguments and returns an exit code.
func Run(args []string) int {
	if len(args) < 1 {
		usage()
		return 2
	}

	ctx := context.Background()

	var err error
	switch args[0] {
	case "inventory":
		err = runInventory(ctx, args[1:])
	case "audit":
		err = runAudit(ctx, args[1:])
	case "explain":
		err = runExplain(ctx, args[1:])
	case "help", "-h", "--help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
		usage()
		return 2
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func usage() {
	fmt.Print(`taildoc — operational visibility and analysis for Tailscale tailnets

Usage:
  taildoc inventory                     Show a normalized view of the tailnet
  taildoc audit                         Analyze the tailnet for problems
  taildoc explain <source> <dest>       Explain access between two resources

Authentication:
  Set TS_ACCESS_TOKEN to a Tailscale API key created by an admin or
  network admin: https://login.tailscale.com/admin/settings/keys
`)
}

func collect(ctx context.Context) (*tailnet.Tailnet, error) {
	return collector.Collect(ctx)
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	return fs
}
