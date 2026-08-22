package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifDriver struct {
	Name string `json:"name"`
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

func RenderJSON(fs []Finding) ([]byte, error) {
	return json.Marshal(fs)
}

func RenderSARIF(fs []Finding) ([]byte, error) {
	results := make([]sarifResult, 0, len(fs))
	for i, f := range fs {
		sum := sha256.Sum256([]byte(string(f.Severity) + "\x00" + f.Title))
		results = append(results, sarifResult{
			RuleID: fmt.Sprintf("TD%03d", i),
			Level:  sarifLevel(f.Severity),
			Message: sarifMessage{
				Text: f.Title + ": " + f.Detail,
			},
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
	report := sarifReport{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: "taildoc"}},
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
