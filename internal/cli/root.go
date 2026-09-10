// Package cli implements Taildoc's commands.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

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

	baseCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := commandContext(baseCtx, args[0])
	defer cancel()

	var err error
	switch args[0] {
	case "inventory":
		err = runInventory(ctx, args[1:])
	case "audit":
		err = runAudit(ctx, args[1:])
	case "explain":
		err = runExplain(ctx, args[1:])
	case "find":
		err = runFind(ctx, args[1:])
	case "show":
		err = runShow(ctx, args[1:])
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
	case "completion":
		err = runCompletion(args[1:])
	case "doctor":
		err = runDoctor(ctx, args[1:])
	case "watch":
		err = runWatch(ctx, args[1:])
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
		if errors.Is(err, ErrDoctorFailed) {
			return 1
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

// commandContext gives one-shot commands a bounded lifetime while allowing
// watch to continue until the user interrupts it.
func commandContext(base context.Context, command string) (context.Context, context.CancelFunc) {
	if command == "watch" {
		return base, func() {}
	}
	return context.WithTimeout(base, 60*time.Second)
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
       --snapshot file                     Analyze saved data instead of live data
  explain <source> <dest[:port]>      Explain access between two resources
  find [--snapshot file] <query>      Search devices, users, tags, groups, and hosts
  show [--snapshot file] <resource>   Show a resource and its related policy
  snapshot [--output file]            Save a tailnet snapshot to JSON
  diff <old.json> [new.json]          Diff two snapshots (second defaults to live)
   graph                               Render grant relationships
       --format mermaid|dot                Diagram format (default mermaid)
       --output file                       Write to file instead of stdout
       --snapshot file                     Render saved data instead of live data
  history                             Findings over time
      --db path                           SQLite database (default taildoc.db)
      --record                            Audit now and store results
  ui                                  Interactive terminal dashboard
      [--snapshot file]                   Browse a saved snapshot instead of live
  completion <bash|zsh|fish>           Generate shell completion
  doctor [--check-api] [--collect]     Check local setup and optional API readiness
  watch [--interval 30s] [--once]      Follow live inventory changes until interrupted

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
  taildoc auth login  [--apikey-stdin | --oauth-client-id ID --oauth-client-secret-stdin] [--tailnet NAME]
  taildoc auth status
  taildoc auth logout

Credentials are verified against the live API before being saved to
~/.config/taildoc/config.json (mode 0600). TS_ACCESS_TOKEN takes precedence
over the stored config.
`,
  "inventory": `taildoc inventory — normalized view of users, devices, groups, grants, and routers

Usage:
  taildoc inventory [--snapshot FILE] [--output text|json]
`,
	"audit": `taildoc audit — analyze the tailnet and produce explainable findings

Usage:
  taildoc audit [--output FORMAT] [--fail-on SEVERITY] [--snapshot FILE] [--only CHECKS] [--exclude CHECKS]

Flags:
  --output text|json|sarif|markdown   Output format (default text)
  --fail-on info|low|medium|high      Exit with code 3 when findings meet or
                                      exceed this severity (default none)
  --only a,b --exclude c              Run/skip named checks (see --list-checks)
  --list-checks                       List available check names

Examples:
  taildoc audit --fail-on high        CI gate: fail on any high finding
  taildoc audit --output sarif        Upload result to GitHub code scanning
  taildoc audit --only broad-grants,orphaned-tags
`,
	"explain": `taildoc explain — explain access between two resources

Usage:
  taildoc explain [--snapshot FILE] [--proto PROTO] [--json] <source> <destination[:port]>

Source is a device hostname, IP, or user login. Destination may add a port,
e.g. "db-prod:5432".
`,
	"find": `taildoc find — quickly locate a tailnet resource

Usage:
  taildoc find [--snapshot FILE] <query>

Searches hostnames, DNS names, Tailscale IPs, users, tags, groups, and host
aliases. Matches are case-insensitive substrings with fuzzy matching as a
fallback. Use "taildoc show <resource>" to drill into a result.
`,
	"show": `taildoc show — show a device, user, tag, group, or host alias

Usage:
  taildoc show [--snapshot FILE] <resource>

Shows related ownership, devices, group membership, routes, and policy grants.
Use "taildoc find <query>" when you do not know the exact resource name.
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
  taildoc graph [--format mermaid|dot] [--output FILE] [--snapshot FILE]

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
	"doctor": `taildoc doctor — check Taildoc setup without exposing credentials

Usage:
  taildoc doctor [--check-api] [--collect]

By default, checks credential availability, config parsing, and permissions
locally. --check-api verifies credentials with a read-only API request.
--collect exercises the full live collection required by inventory and audit.
`,
	"watch": `taildoc watch — follow inventory changes

Usage:
  taildoc watch [--interval DURATION] [--once]

Collects a baseline, then prints only inventory and policy changes. It makes
read-only API calls and keeps no files. Press Ctrl-C to stop.
`,
	"completion": `taildoc completion — generate shell completion

Usage:
  taildoc completion <bash|zsh|fish>

Examples:
  source <(taildoc completion bash)
  taildoc completion zsh > "${fpath[1]}/_taildoc"
  taildoc completion fish > ~/.config/fish/completions/taildoc.fish
`,
}

func collect(ctx context.Context) (*tailnet.Tailnet, error) {
	return collector.Collect(ctx)
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	return fs
}
