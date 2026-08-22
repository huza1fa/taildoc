package cli

import (
	"context"
	"fmt"

	"github.com/huza1fa/taildoc/internal/snapshot"
)

func runSnapshot(ctx context.Context, args []string) error {
	fs := newFlagSet("snapshot")
	output := fs.String("output", "", "write snapshot to this path instead of a timestamped file in the current directory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	t, err := collect(ctx)
	if err != nil {
		return err
	}

	path := *output
	if path != "" {
		if err := snapshot.Save(t, path); err != nil {
			return err
		}
	} else {
		path, err = snapshot.SaveDefault(t)
		if err != nil {
			return err
		}
	}
	fmt.Println(path)
	return nil
}
