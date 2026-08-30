package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/huza1fa/taildoc/internal/fileutil"
	"github.com/huza1fa/taildoc/internal/graph"
	"github.com/huza1fa/taildoc/internal/snapshot"
	"github.com/huza1fa/taildoc/internal/tailnet"
)

func runGraph(ctx context.Context, args []string) error {
	fs := newFlagSet("graph")
	format := fs.String("format", "mermaid", "output format: mermaid or dot")
	output := fs.String("output", "", "write to file instead of stdout")
	snapshotPath := fs.String("snapshot", "", "render a saved snapshot instead of collecting live data")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: taildoc graph [--format mermaid|dot] [--output FILE]")
	}

	var (
		t   *tailnet.Tailnet
		err error
	)
	if *snapshotPath != "" {
		t, err = snapshot.Load(*snapshotPath)
	} else {
		t, err = collect(ctx)
	}
	if err != nil {
		return err
	}

	var out string
	switch *format {
	case "mermaid":
		out = graph.Mermaid(t)
	case "dot":
		out = graph.DOT(t)
	default:
		return fmt.Errorf("unknown format %q (want mermaid or dot)", *format)
	}

	if *output == "" {
		fmt.Print(out)
		return nil
	}

	if err := fileutil.WriteFileAtomic(*output, []byte(out), 0o600); err != nil {
		return err
	}
	edges := graph.Edges(t)
	fmt.Fprintf(os.Stderr, "wrote %s graph: %d grants -> %d edges to %s\n",
		*format, len(t.Grants), len(edges), *output)
	return nil
}
