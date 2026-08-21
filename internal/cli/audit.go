package cli

import (
	"context"
	"fmt"

	"github.com/huza1fa/taildoc/internal/audit"
)

func runAudit(ctx context.Context, args []string) error {
	fs := newFlagSet("audit")
	if err := fs.Parse(args); err != nil {
		return err
	}

	t, err := collect(ctx)
	if err != nil {
		return err
	}

	findings := audit.Run(t)

	counts := map[audit.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	fmt.Printf("Audited %d device(s), %d user(s), %d grant(s)\n\n",
		len(t.Devices), len(t.Users), len(t.Grants))

	if len(findings) == 0 {
		fmt.Println("No findings. Nothing looked obviously wrong (this is not a guarantee).")
		return nil
	}

	fmt.Printf("Findings: %d high, %d medium, %d low, %d info\n\n",
		counts[audit.High], counts[audit.Medium], counts[audit.Low], counts[audit.Info])

	for _, f := range findings {
		printFinding(f)
	}
	return nil
}

func printFinding(f audit.Finding) {
	fmt.Printf("%s: %s\n", f.Severity, f.Title)
	fmt.Printf("  What:   %s\n", f.Detail)
	if len(f.Evidence) > 0 {
		fmt.Println("  Evidence:")
		for _, e := range f.Evidence {
			fmt.Printf("    - %s\n", e)
		}
	}
	fmt.Printf("  Why:    %s\n", f.Why)
	fmt.Printf("  Next:   %s\n\n", f.Next)
}
