package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/huza1fa/taildoc/internal/graph"
)

func runGraph(ctx context.Context, args []string) error {
	fs := newFlagSet("graph")
	format := fs.String("format", "mermaid", "output format: mermaid or dot")
	output := fs.String("output", "", "write to file instead of stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}

	t, err := collect(ctx)
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

	if err := os.WriteFile(*output, []byte(out), 0o644); err != nil {
		return err
	}
	edges := graph.Edges(t)
	fmt.Fprintf(os.Stderr, "wrote %s graph: %d grants -> %d edges to %s\n",
		*format, len(t.Grants), len(edges), *output)
	return nil
}
