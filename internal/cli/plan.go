package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/huza1fa/taildoc/internal/plan"
	"github.com/huza1fa/taildoc/internal/snapshot"
)

func runPlan(ctx context.Context, args []string) error {
	fs := newFlagSet("plan")
	snapshotPath := fs.String("snapshot", "", "required baseline snapshot (never collects live data)")
	policyPath := fs.String("policy", "", "required proposed replacement HuJSON policy")
	output := fs.String("output", "text", "output format: text or json")
	source := fs.String("source", "", "limit impact to a source device name, ID, or IP")
	destination := fs.String("destination", "", "limit impact to a destination device name, ID, or IP")
	port := fs.String("port", "", "limit impact to one destination port")
	proto := fs.String("proto", "tcp,udp", "impact protocols: tcp,udp,sctp")
	failOn := fs.String("fail-on", "", "exit 3 on any of: gained, lost, uncertain, unknown, tests")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *snapshotPath == "" || *policyPath == "" {
		return usageErrorf("usage: taildoc plan --snapshot FILE --policy FILE [--output text|json] [--source DEVICE] [--destination DEVICE] [--port PORT] [--proto tcp,udp,sctp] [--fail-on CONDITIONS]")
	}
	conditions := splitCSV(*failOn)
	if err := plan.ValidateFailOn(conditions); err != nil {
		return usageErrorf("%v", err)
	}
	if *output != "text" && *output != "json" {
		return usageErrorf("unknown plan output %q", *output)
	}
	opts, err := impactOptions(*source, *destination, *port, *proto)
	if err != nil {
		return err
	}
	proposal, err := plan.LoadProposal(*policyPath)
	if err != nil {
		return err
	}
	baseline, err := snapshot.Load(*snapshotPath)
	if err != nil {
		return err
	}
	report, err := plan.Preview(ctx, baseline, proposal.ACL, proposal.Warnings, opts, proposal.Tests...)
	if err != nil {
		return err
	}
	if *output == "json" {
		if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
			return err
		}
	} else {
		printPlan(report)
	}
	if met := plan.FailureConditions(report, conditions); len(met) > 0 {
		return fmt.Errorf("%w: %s", ErrPlanFailed, strings.Join(met, ", "))
	}
	return nil
}

func printPlan(report plan.Report) {
	fmt.Println("Offline policy plan (no changes applied)")
	if !report.BaselineCollectedAt.IsZero() {
		fmt.Printf("Baseline collected: %s\n", report.BaselineCollectedAt.Format("2006-01-02T15:04:05Z07:00"))
	}
	for _, warning := range report.Warnings {
		fmt.Printf("Warning: %s\n", terminalText(warning))
	}
	fmt.Printf("\nPolicy changes (%d)\n", len(report.Changes))
	for _, change := range report.Changes {
		fmt.Printf("  %s: %s", change.Kind, terminalText(change.What))
		if change.Detail != "" {
			fmt.Printf(" — %s", terminalText(change.Detail))
		}
		fmt.Println()
	}
	printImpact(report.Impact)
	if len(report.Tests) > 0 {
		counts := map[string]int{}
		for _, r := range report.Tests {
			counts[r.Outcome]++
		}
		fmt.Printf("\nPolicy tests (%d passed, %d failed, %d unknown)\n", counts[plan.TestPassed], counts[plan.TestFailed], counts[plan.TestUnknown])
		for _, r := range report.Tests {
			if r.Outcome == plan.TestPassed {
				continue
			}
			fmt.Printf("  %s: %s -> %s expected %s", r.Outcome, terminalText(r.Source), terminalText(r.Destination), r.Expected)
			if r.Reason != "" {
				fmt.Printf(" (%s)", terminalText(r.Reason))
			}
			fmt.Println()
		}
	}
}

// Escape terminal control characters from untrusted policy and device names
// without adding surrounding quotes to otherwise readable text.
func terminalText(s string) string {
	quoted := strconv.Quote(s)
	return quoted[1 : len(quoted)-1]
}
