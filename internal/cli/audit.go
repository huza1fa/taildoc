package cli

import (
	"context"
	"fmt"

	"github.com/huza1fa/taildoc/internal/audit"
)

func runAudit(ctx context.Context, args []string) error {
	fs := newFlagSet("audit")
	output := fs.String("output", "text", "output format: text, json, sarif, markdown")
	failOn := fs.String("fail-on", "none", "fail if findings meet or exceed this severity: none, info, low, medium, high")
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

	switch *output {
	case "text":
		fmt.Printf("%s\n\n", bold(fmt.Sprintf("Audited %d device(s), %d user(s), %d grant(s)",
			len(t.Devices), len(t.Users), len(t.Grants))))

		if len(findings) == 0 {
			fmt.Printf("%s Nothing looked obviously wrong (this is not a guarantee).\n", green("✓"))
			break
		}

		summary := fmt.Sprintf("Findings: %s, %s, %s, %s",
			red(fmt.Sprintf("%d high", counts[audit.High])),
			yellow(fmt.Sprintf("%d medium", counts[audit.Medium])),
			blue(fmt.Sprintf("%d low", counts[audit.Low])),
			dim("%d info", counts[audit.Info]))
		fmt.Printf("%s\n\n", summary)

		for _, f := range findings {
			printFinding(f)
		}
	case "json", "sarif":
		var data []byte
		if *output == "json" {
			data, err = audit.RenderJSON(findings)
		} else {
			data, err = audit.RenderSARIF(findings)
		}
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	case "markdown":
		data, rerr := audit.RenderMarkdown(findings, counts)
		if rerr != nil {
			return rerr
		}
		fmt.Print(string(data))
	default:
		return fmt.Errorf("unknown --output %q (want text, json, sarif, or markdown)", *output)
	}

	if exceedsFailOn(counts, *failOn) {
		return ErrSeverityExceeded
	}
	return nil
}

func severityRank(s audit.Severity) int {
	switch s {
	case audit.High:
		return 4
	case audit.Medium:
		return 3
	case audit.Low:
		return 2
	case audit.Info:
		return 1
	default:
		return 0
	}
}

func exceedsFailOn(counts map[audit.Severity]int, failOn string) bool {
	var threshold int
	switch failOn {
	case "high":
		threshold = severityRank(audit.High)
	case "medium":
		threshold = severityRank(audit.Medium)
	case "low":
		threshold = severityRank(audit.Low)
	case "info":
		threshold = severityRank(audit.Info)
	case "none":
		return false
	default:
		return false
	}
	for sev, n := range counts {
		if n > 0 && severityRank(sev) >= threshold {
			return true
		}
	}
	return false
}

func severityColor(s audit.Severity) func(string) string {
	switch s {
	case audit.High:
		return red
	case audit.Medium:
		return yellow
	case audit.Low:
		return blue
	default:
		return gray
	}
}

func printFinding(f audit.Finding) {
	sev := severityColor(f.Severity)(string(f.Severity))
	fmt.Printf("%s %s\n", bold(sev), f.Title)
	fmt.Printf("  %s %s\n", dim("What:  "), f.Detail)
	if len(f.Evidence) > 0 {
		fmt.Println(dim("  Evidence:"))
		for _, e := range f.Evidence {
			fmt.Printf("    %s %s\n", dim("-"), e)
		}
	}
	fmt.Printf("  %s %s\n", dim("Why:   "), f.Why)
	fmt.Printf("  %s %s\n\n", dim("Next:  "), green(f.Next))
}
