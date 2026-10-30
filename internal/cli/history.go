package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/huza1fa/taildoc/internal/audit"
	"github.com/huza1fa/taildoc/internal/history"
	"github.com/huza1fa/taildoc/internal/snapshot"
	"github.com/huza1fa/taildoc/internal/tailnet"
)

func runHistory(ctx context.Context, args []string) error {
	fs := newFlagSet("history")
	dbPath := fs.String("db", "", "SQLite history database (default: history.db in the taildoc config directory)")
	record := fs.Bool("record", false, "audit and record findings")
	snapshotPath := fs.String("snapshot", "", "record an audit of a saved snapshot")
	limit := fs.Int("limit", 10, "maximum recent runs to show (0 for all)")
	since := fs.String("since", "", "show runs since RFC3339 timestamp")
	status := fs.String("status", "", "filter new, ongoing, resolved, or reopened")
	severity := fs.String("severity", "", "filter high, medium, low, or info")
	check := fs.String("check", "", "filter a named audit check")
	output := fs.String("output", "text", "text or json")
	prune := fs.Int("prune", -1, "keep only the newest N runs")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usageErrorf("usage: taildoc history [--record] [--db PATH] [--limit N] [--status STATUS]")
	}
	if *output != "text" && *output != "json" {
		return usageErrorf("unknown history output %q", *output)
	}
	var err error
	q := history.Query{Limit: *limit, Status: history.Status(*status), Severity: history.ParseSeverity(*severity), RuleID: *check}
	if *since != "" {
		if q.Since, err = time.Parse(time.RFC3339, *since); err != nil {
			return usageErrorf("invalid --since: %v", err)
		}
	}
	if err := history.ValidateQuery(q); err != nil {
		return usageErrorf("%v", err)
	}
	if *snapshotPath != "" && !*record {
		return usageErrorf("--snapshot requires --record")
	}
	if *record && (*since != "" || *status != "" || *severity != "" || *check != "") {
		return usageErrorf("history display filters cannot be used with --record")
	}
	if *prune != -1 && *prune < 1 {
		return usageErrorf("--prune must keep at least 1 run")
	}
	if *dbPath == "" {
		if *dbPath, err = history.DefaultPath(); err != nil {
			return err
		}
	}
	store, err := history.Open(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()
	pruneRuns := func() error {
		if *prune == -1 {
			return nil
		}
		removed, err := store.Prune(*prune)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Pruned %d run(s).\n", removed)
		return nil
	}
	if *record {
		var tn *tailnet.Tailnet
		if *snapshotPath != "" {
			tn, err = snapshot.Load(*snapshotPath)
		} else {
			tn, err = collect(ctx)
		}
		if err != nil {
			return err
		}
		at := time.Now()
		findings := audit.Run(tn)
		events, err := store.Preview(findings, at)
		if err != nil {
			return err
		}
		if err = store.Record(findings, at); err != nil {
			return err
		}
		run := history.Run{At: at, Events: events}
		if *output == "json" {
			if err := json.NewEncoder(os.Stdout).Encode(run); err != nil {
				return err
			}
			return pruneRuns()
		}
		fmt.Printf("Recorded %d finding(s). Lifecycle compared with the previous run:\n", len(findings))
		printHistoryRun(run)
		return pruneRuns()
	}
	if *prune != -1 {
		return pruneRuns()
	}
	runs, err := store.Timeline(q)
	if err != nil {
		return err
	}
	if *output == "json" {
		return json.NewEncoder(os.Stdout).Encode(runs)
	}
	if len(runs) == 0 {
		fmt.Println("No history matches. Use `taildoc history --record` to capture an audit.")
		return nil
	}
	for _, r := range runs {
		printHistoryRun(r)
	}
	return nil
}
func printHistoryRun(r history.Run) {
	counts := map[history.Status]int{}
	for _, e := range r.Events {
		counts[e.Status]++
	}
	fmt.Printf("\n%s — %d new, %d ongoing, %d resolved, %d reopened\n", r.At.Format(time.RFC3339), counts[history.New], counts[history.Ongoing], counts[history.Resolved], counts[history.Reopened])
	for _, e := range r.Events {
		fmt.Printf("  %s %s: %s\n", e.Status, e.Finding.Severity, e.Finding.Title)
	}
}
