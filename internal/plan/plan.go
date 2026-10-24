package plan

import (
	"context"
	"fmt"
	"time"

	"tailscale.com/client/tailscale/v2"

	"github.com/huza1fa/taildoc/internal/diff"
	"github.com/huza1fa/taildoc/internal/policy"
	"github.com/huza1fa/taildoc/internal/tailnet"
)

type Report struct {
	BaselineCollectedAt time.Time         `json:"baseline_collected_at"`
	Warnings            []string          `json:"warnings"`
	Changes             []diff.Change     `json:"changes"`
	Impact              diff.ImpactReport `json:"impact"`
}

// Preview applies a complete replacement policy to a shallow inventory copy.
// Neither the baseline nor the policy is mutated; devices, users, tags, and
// route approvals stay fixed, isolating policy effects from inventory drift.
func Preview(ctx context.Context, baseline *tailnet.Tailnet, acl *tailscale.ACL, warnings []string, opts diff.ImpactOptions) (Report, error) {
	var report Report
	if baseline == nil || acl == nil {
		return report, fmt.Errorf("plan requires a snapshot and proposed policy")
	}
	if len(baseline.Devices) == 0 {
		return report, fmt.Errorf("snapshot contains no devices; cannot preview device access")
	}
	candidate := *baseline
	policy.Normalize(&candidate, acl)
	impact, err := diff.AccessImpact(ctx, baseline, &candidate, opts)
	if err != nil {
		return report, err
	}
	report.BaselineCollectedAt = baseline.CollectedAt
	report.Impact = impact
	report.Changes = diff.Diff(baseline, &candidate)
	if report.Changes == nil {
		report.Changes = []diff.Change{}
	}
	report.Warnings = append([]string{
		"Offline estimate using the snapshot inventory and supported packet-policy semantics only; not Tailscale policy validation or a connectivity test.",
		"Only distinct collected device pairs are compared. SSH, application capabilities, subnet/service destinations, runtime state, and future inventory changes are not evaluated.",
		"Inventory, device tags, and enabled routes stay fixed; changes to tag owners or auto approvers do not simulate re-tagging or route approval.",
	}, warnings...)
	if baseline.CollectedAt.IsZero() {
		report.Warnings = append(report.Warnings, "Snapshot collection time is unavailable; inventory freshness cannot be established.")
	}
	if impact.UnknownEvaluations > 0 {
		report.Warnings = append(report.Warnings, fmt.Sprintf("%d of %d access evaluations are unknown (including unchanged unknown paths); no complete safety conclusion is possible.", impact.UnknownEvaluations, impact.Evaluations))
	}
	if impact.Evaluations == 0 {
		report.Warnings = append(report.Warnings, "No distinct device pairs were evaluated in the selected scope.")
	}
	return report, nil
}
