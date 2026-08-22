package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/huza1fa/taildoc/internal/audit"
	"github.com/huza1fa/taildoc/internal/history"
)

func runHistory(ctx context.Context, args []string) error {
	fs := newFlagSet("history")
	dbPath := fs.String("db", "taildoc.db", "path to the SQLite history database")
	record := fs.Bool("record", false, "collect live data, run the audit, and record findings")
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, err := history.Open(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()

	if *record {
		return historyRecord(ctx, store)
	}
	return historyShow(store)
}

func historyRecord(ctx context.Context, store *history.Store) error {
	t, err := collect(ctx)
	if err != nil {
		return err
	}

	findings := audit.Run(t)
	newFindings, err := store.NewFindings(findings)
	if err != nil {
		return err
	}
	if err := store.Record(findings, time.Now()); err != nil {
		return err
	}

	counts := map[audit.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	fmt.Printf("Recorded %d finding(s): %d high, %d medium, %d low, %d info\n",
		len(findings), counts[audit.High], counts[audit.Medium], counts[audit.Low], counts[audit.Info])
	fmt.Printf("New since first recorded run: %d\n", len(newFindings))
	for _, f := range newFindings {
		fmt.Printf("  NEW %s: %s\n", f.Severity, f.Title)
	}
	return nil
}

func historyShow(store *history.Store) error {
	last, ok, err := store.LatestRun()
	if err != nil {
		return err
	}
	if !ok {
		fmt.Println("No recorded runs yet. Run `taildoc history --record` to capture one.")
		return nil
	}

	runs, err := store.Runs()
	if err != nil {
		return err
	}

	fmt.Printf("Last run: %s (%d run(s) recorded)\n", last.Format("2006-01-02 15:04:05 MST"), len(runs))

	for _, at := range runs {
		findings, err := store.FindingsAt(at)
		if err != nil {
			return err
		}
		counts := map[audit.Severity]int{}
		for _, f := range findings {
			counts[f.Severity]++
		}
		fmt.Printf("\n%s — %d finding(s) (%d high, %d medium, %d low, %d info)\n",
			at.Format("2006-01-02 15:04:05 MST"), len(findings),
			counts[audit.High], counts[audit.Medium], counts[audit.Low], counts[audit.Info])
		for _, f := range findings {
			fmt.Printf("  %s: %s\n", f.Severity, f.Title)
		}
	}
	return nil
}
