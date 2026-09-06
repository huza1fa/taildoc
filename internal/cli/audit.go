package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/huza1fa/taildoc/internal/audit"
	"github.com/huza1fa/taildoc/internal/snapshot"
	"github.com/huza1fa/taildoc/internal/tailnet"
)

func runAudit(ctx context.Context, args []string) error {
	fs := newFlagSet("audit")
	output := fs.String("output", "text", "output format: text, json, sarif, markdown")
	failOn := fs.String("fail-on", "none", "fail if findings meet or exceed this severity: none, info, low, medium, high")
	snapshotPath := fs.String("snapshot", "", "audit a saved snapshot instead of collecting live data")
	only := fs.String("only", "", "comma-separated checks to run (see --list-checks)")
	exclude := fs.String("exclude", "", "comma-separated checks to skip")
	listChecks := fs.Bool("list-checks", false, "list available checks and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *listChecks {
		for _, n := range audit.CheckNames {
			fmt.Println(n)
		}
		return nil
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: taildoc audit [--output FORMAT] [--fail-on SEVERITY]")
	}
	if !validFailOn(*failOn) {
		return fmt.Errorf("unknown --fail-on %q (want none, info, low, medium, or high)", *failOn)
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

	findings := audit.RunFiltered(t, splitCSV(*only), splitCSV(*exclude))

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

func validFailOn(s string) bool {
	switch s {
	case "none", "info", "low", "medium", "high":
		return true
	default:
		return false
	}
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
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
