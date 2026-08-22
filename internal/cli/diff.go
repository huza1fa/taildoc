package cli

import (
	"context"
	"fmt"

	"github.com/huza1fa/taildoc/internal/diff"
	"github.com/huza1fa/taildoc/internal/snapshot"
	"github.com/huza1fa/taildoc/internal/tailnet"
)

func runDiff(ctx context.Context, args []string) error {
	fs := newFlagSet("diff")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) < 1 || len(rest) > 2 {
		return fmt.Errorf("usage: taildoc diff <old.json> [new.json]")
	}

	oldT, err := snapshot.Load(rest[0])
	if err != nil {
		return err
	}

	var newT *tailnet.Tailnet
	if len(rest) == 2 {
		newT, err = snapshot.Load(rest[1])
	} else {
		newT, err = collect(ctx)
	}
	if err != nil {
		return err
	}

	printChanges(diff.Diff(oldT, newT))
	return nil
}

func printChanges(changes []diff.Change) {
	counts := map[string]int{}
	for _, c := range changes {
		counts[c.Kind]++
	}
	fmt.Printf("%d change(s): %d added, %d removed, %d changed\n",
		len(changes), counts["added"], counts["removed"], counts["changed"])
	if len(changes) == 0 {
		fmt.Println("Snapshots are identical.")
		return
	}
	for _, c := range changes {
		prefix := "~"
		switch c.Kind {
		case "added":
			prefix = "+"
		case "removed":
			prefix = "-"
		}
		if c.Detail != "" {
			fmt.Printf("  %s %s — %s\n", prefix, c.What, c.Detail)
		} else {
			fmt.Printf("  %s %s\n", prefix, c.What)
		}
	}
}
