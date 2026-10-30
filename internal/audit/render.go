package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	ShortDescription sarifMessage `json:"shortDescription"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

// sarifArtifact anchors findings. They describe a tailnet rather than a source
// line, but code scanning discards results without a location.
const sarifArtifact = "policy.hujson"

func RenderJSON(fs []Finding) ([]byte, error) {
	if fs == nil {
		fs = []Finding{} // consumers expect an array, even when clean
	}
	return json.Marshal(fs)
}

func RenderSARIF(fs []Finding) ([]byte, error) {
	results := make([]sarifResult, 0, len(fs))
	rules := []sarifRule{}
	seenRules := map[string]bool{}
	for _, f := range fs {
		evidence := append([]string(nil), f.Evidence...)
		sort.Strings(evidence)
		sum := sha256.Sum256([]byte(string(f.Severity) + "\x00" + f.Title + "\x00" + f.Detail + "\x00" + strings.Join(evidence, "\x00")))
		if f.RuleID != "" && f.Subject != "" {
			sum = sha256.Sum256([]byte(f.RuleID + "\x00" + f.Subject))
		}
		ruleID := f.RuleID
		if ruleID == "" {
			ruleSum := sha256.Sum256([]byte(f.Why + "\x00" + f.Next))
			ruleID = "TD-" + strings.ToUpper(hex.EncodeToString(ruleSum[:6]))
		}
		if !seenRules[ruleID] {
			seenRules[ruleID] = true
			rules = append(rules, sarifRule{ruleID, sarifMessage{orDefault(checkSummaries[ruleID], f.Title)}})
		}
		results = append(results, sarifResult{
			RuleID: ruleID,
			Level:  sarifLevel(f.Severity),
			Message: sarifMessage{
				Text: f.Title + ": " + f.Detail,
			},
			Locations: []sarifLocation{{sarifPhysicalLocation{sarifArtifactLocation{sarifArtifact}, sarifRegion{1}}}},
			PartialFingerprints: map[string]string{
				"taildocFindingSha256": hex.EncodeToString(sum[:]),
			},
			Properties: map[string]any{
				"severity": string(f.Severity),
				"why":      f.Why,
				"next":     f.Next,
				"evidence": f.Evidence,
			},
		})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	report := sarifReport{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "taildoc",
				InformationURI: "https://github.com/huza1fa/taildoc",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	return json.Marshal(report)
}

func sarifLevel(s Severity) string {
	switch s {
	case High:
		return "error"
	case Medium:
		return "warning"
	default:
		return "note"
	}
}

func RenderMarkdown(fs []Finding, counts map[Severity]int) ([]byte, error) {
	out := "# Taildoc Audit Report\n\n"
	out += fmt.Sprintf("Findings: %d high, %d medium, %d low, %d info (%d total)\n\n",
		counts[High], counts[Medium], counts[Low], counts[Info], len(fs))
	for _, f := range fs {
		out += fmt.Sprintf("## %s: %s\n\n", f.Severity, f.Title)
		out += f.Detail + "\n\n"
		if len(f.Evidence) > 0 {
			out += "Evidence:\n"
			for _, e := range f.Evidence {
				out += "- " + e + "\n"
			}
			out += "\n"
		}
		out += "Why: " + f.Why + "\n\n"
		out += "Next: " + f.Next + "\n\n"
	}
	return []byte(out), nil
}
