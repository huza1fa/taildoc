// Package cli implements Taildoc's commands.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/huza1fa/taildoc/internal/collector"
	"github.com/huza1fa/taildoc/internal/tailnet"
)

// Version is set at build time via -ldflags "-X ...cli.Version=vX.Y.Z".
var Version = "dev"

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
	case "diff":
		err = runDiff(ctx, args[1:])
	case "snapshot":
		err = runSnapshot(ctx, args[1:])
	case "graph":
		err = runGraph(ctx, args[1:])
	case "history":
		err = runHistory(ctx, args[1:])
	case "ui":
		err = runUI(ctx, args[1:])
	case "auth":
		err = runAuth(ctx, args[1:])
	case "help", "-h", "--help":
		if len(args) > 1 {
			if text, ok := cmdHelp[args[1]]; ok {
				fmt.Print(text)
				return 0
			}
			fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[1])
			usage()
			return 2
		}
		usage()
		return 0
	case "--version", "-v", "version":
		fmt.Printf("taildoc %s\n", Version)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
		usage()
		return 2
	}

	if err != nil {
		if errors.Is(err, ErrSeverityExceeded) {
			fmt.Fprintln(os.Stderr, "error: findings met or exceeded --fail-on threshold")
			return 3
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func usage() {
	fmt.Print(`taildoc — operational visibility and explainable policy analysis for Tailscale

Usage:
  taildoc <command> [flags]

Commands:
  auth login|status|logout            Connect to your tailnet (API key or OAuth client)
  inventory                           Show a normalized view of the tailnet
  audit                               Analyze the tailnet for problems
      --output text|json|sarif|markdown   Output format (default text)
      --fail-on info|low|medium|high      Exit 3 if findings meet threshold
  explain <source> <dest[:port]>      Explain access between two resources
  snapshot [--output file]            Save a tailnet snapshot to JSON
  diff <old.json> [new.json]          Diff two snapshots (second defaults to live)
  graph                               Render grant relationships
      --format mermaid|dot                Diagram format (default mermaid)
      --output file                       Write to file instead of stdout
  history                             Findings over time
      --db path                           SQLite database (default taildoc.db)
      --record                            Audit now and store results
  ui                                  Interactive terminal dashboard
      [--snapshot file]                   Browse a saved snapshot instead of live

First run:
  Run "taildoc auth login" to connect interactively, or set TS_ACCESS_TOKEN.
  API keys: https://login.tailscale.com/admin/settings/keys
  OAuth clients: https://login.tailscale.com/admin/settings/oauth

Exit codes:
  0 success    1 error    2 bad usage    3 findings met --fail-on threshold

More help:
  taildoc help <command> shows flags for a single command.
`)
}

var cmdHelp = map[string]string{
	"auth": `taildoc auth — connect to your tailnet

Usage:
  taildoc auth login  [--apikey KEY | --oauth-client-id ID --oauth-client-secret SECRET] [--tailnet NAME]
  taildoc auth status
  taildoc auth logout

Credentials are verified against the live API before being saved to
~/.config/taildoc/config.json (mode 0600). TS_ACCESS_TOKEN takes precedence
over the stored config.
`,
	"inventory": `taildoc inventory — normalized view of users, devices, groups, grants, and routers

Usage:
  taildoc inventory
`,
	"audit": `taildoc audit — analyze the tailnet and produce explainable findings

Usage:
  taildoc audit [--output FORMAT] [--fail-on SEVERITY]

Flags:
  --output text|json|sarif|markdown   Output format (default text)
  --fail-on info|low|medium|high      Exit with code 3 when findings meet or
                                      exceed this severity (default none)

Examples:
  taildoc audit --fail-on high        CI gate: fail on any high finding
  taildoc audit --output sarif        Upload result to GitHub code scanning
`,
	"explain": `taildoc explain — explain access between two resources

Usage:
  taildoc explain <source> <destination[:port]>

Source is a device hostname, IP, or user login. Destination may add a port,
e.g. "db-prod:5432".
`,
	"snapshot": `taildoc snapshot — save the current tailnet state to JSON

Usage:
  taildoc snapshot [--output FILE]

Without --output, writes taildoc-snapshot-<timestamp>.json to the current
directory and prints its path.
`,
	"diff": `taildoc diff — compare two snapshots

Usage:
  taildoc diff <old.json> [new.json]

With one argument, compares the saved snapshot against live tailnet data.
`,
	"graph": `taildoc graph — render grant relationships as a diagram

Usage:
  taildoc graph [--format mermaid|dot] [--output FILE]

Mermaid output pastes directly into GitHub markdown; dot renders with Graphviz.
`,
	"history": `taildoc history — track findings over time

Usage:
  taildoc history [--db PATH] [--record]

  --record   Audit now, report which findings are new since first run, store.
  --db       SQLite database path (default taildoc.db)
`,
	"ui": `taildoc ui — interactive terminal dashboard

Usage:
  taildoc ui [--snapshot FILE]

Tabs: overview with findings, device table, grant graph.
Keys: 1-3/tab switch · enter details · esc close · q quit.

With --snapshot, browses a saved snapshot file instead of live data.
`,
}

func collect(ctx context.Context) (*tailnet.Tailnet, error) {
	return collector.Collect(ctx)
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	return fs
}
