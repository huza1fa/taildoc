package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/huza1fa/taildoc/internal/diff"
	"github.com/huza1fa/taildoc/internal/policy"
	"github.com/huza1fa/taildoc/internal/snapshot"
	"github.com/huza1fa/taildoc/internal/tailnet"
)

func runDiff(ctx context.Context, args []string) error {
	fs := newFlagSet("diff")
	impact := fs.Bool("impact", false, "also compare effective packet access between collected devices")
	output := fs.String("output", "text", "output format: text or json")
	source := fs.String("source", "", "limit impact to a source device name, ID, or IP")
	destination := fs.String("destination", "", "limit impact to a destination device name, ID, or IP")
	port := fs.String("port", "", "limit impact to one destination port")
	proto := fs.String("proto", "tcp,udp", "impact protocols: tcp,udp,sctp")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *output != "text" && *output != "json" {
		return usageErrorf("unknown diff output %q", *output)
	}
	if !*impact && (*source != "" || *destination != "" || *port != "" || *proto != "tcp,udp") {
		return usageErrorf("--source, --destination, --port, and --proto require --impact")
	}
	var opts diff.ImpactOptions
	if *impact {
		var err error
		opts, err = impactOptions(*source, *destination, *port, *proto)
		if err != nil {
			return err
		}
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

	changes := diff.Diff(oldT, newT)
	if changes == nil {
		changes = []diff.Change{}
	}
	var report *diff.ImpactReport
	if *impact {
		result, err := diff.AccessImpact(ctx, oldT, newT, opts)
		if err != nil {
			return err
		}
		report = &result
	}
	if *output == "json" {
		return json.NewEncoder(os.Stdout).Encode(struct {
			Changes []diff.Change      `json:"changes"`
			Impact  *diff.ImpactReport `json:"impact,omitempty"`
		}{changes, report})
	}
	printChanges(changes)
	if report != nil {
		printImpact(*report)
	}
	return nil
}

func impactOptions(source, destination, port, proto string) (diff.ImpactOptions, error) {
	if port != "" {
		ranges := policy.PortRanges(port)
		if len(ranges) != 1 || ranges[0][0] != ranges[0][1] {
			return diff.ImpactOptions{}, usageErrorf("impact port must be a number from 0 to 65535")
		}
	}
	protocols := strings.Split(proto, ",")
	for _, p := range protocols {
		if p != "tcp" && p != "udp" && p != "sctp" {
			return diff.ImpactOptions{}, usageErrorf("impact protocol must be tcp, udp, or sctp")
		}
	}
	return diff.ImpactOptions{Source: source, Destination: destination, Port: port, Protocols: protocols}, nil
}

func printImpact(report diff.ImpactReport) {
	fmt.Printf("\nAccess impact (%d evaluations, %d unknown)\n%s\n", report.Evaluations, report.UnknownEvaluations, report.Scope)
	for _, c := range report.Changes {
		fmt.Printf("  %s: %s -> %s %s/%s (%s -> %s)\n", c.Kind, terminalText(c.Source), terminalText(c.Destination), c.Protocol, c.Ports, c.Before, c.After)
	}
	if len(report.Changes) == 0 {
		fmt.Println("No access changes detected in the selected scope.")
	}
	if report.UnknownEvaluations > 0 {
		fmt.Println("Some paths could not be determined, including any unchanged unknown paths; this is not a complete safety assessment.")
	}
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
