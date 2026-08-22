package audit

import (
	"encoding/json"
	"strings"
	"testing"
)

func sampleFindings() []Finding {
	return []Finding{
		{
			Severity: High,
			Title:    "Grant allows everything to everyone",
			Detail:   "A grant matches every source, every destination, on all ports.",
			Evidence: []string{"src: *", "dst: *"},
			Why:      "Neutralizes access control.",
			Next:     "Replace with explicit grants.",
		},
		{
			Severity: Medium,
			Title:    "Expired node keys",
			Detail:   "Two devices cannot reconnect.",
			Evidence: []string{"device: host-a"},
			Why:      "Forgotten devices.",
			Next:     "Renew or delete.",
		},
		{
			Severity: Low,
			Title:    "Only one exit node exists",
			Detail:   "Single point of failure.",
			Why:      "Availability risk.",
			Next:     "Add another exit node.",
		},
		{
			Severity: Info,
			Title:    "Update available",
			Detail:   "Some clients are outdated.",
			Why:      "Missing fixes.",
			Next:     "Update clients.",
		},
	}
}

func TestRenderJSONRoundTrip(t *testing.T) {
	fs := sampleFindings()
	data, err := RenderJSON(fs)
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	var got []Finding
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != len(fs) {
		t.Fatalf("got %d findings, want %d", len(got), len(fs))
	}
	for i := range fs {
		want, gotF := fs[i], got[i]
		if gotF.Severity != want.Severity || gotF.Title != want.Title || gotF.Detail != want.Detail ||
			gotF.Why != want.Why || gotF.Next != want.Next {
			t.Errorf("finding %d = %+v, want %+v", i, gotF, want)
		}
		if strings.Join(gotF.Evidence, "|") != strings.Join(want.Evidence, "|") {
			t.Errorf("finding %d evidence = %v, want %v", i, gotF.Evidence, want.Evidence)
		}
	}
}

type sarifDoc struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name string `json:"name"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			PartialFingerprints map[string]string `json:"partialFingerprints"`
			Properties          map[string]any    `json:"properties"`
		} `json:"results"`
	} `json:"runs"`
}

func TestRenderSARIF(t *testing.T) {
	fs := sampleFindings()
	data, err := RenderSARIF(fs)
	if err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}
	var doc sarifDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", doc.Version)
	}
	if !strings.Contains(doc.Schema, "sarif-2.1.0") {
		t.Errorf("$schema = %q, want sarif-2.1.0 schema URL", doc.Schema)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs length = %d, want 1", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "taildoc" {
		t.Errorf("driver name = %q, want taildoc", run.Tool.Driver.Name)
	}
	wantLevels := []string{"error", "warning", "note", "note"}
	if len(run.Results) != len(fs) {
		t.Fatalf("results length = %d, want %d", len(run.Results), len(fs))
	}
	for i, res := range run.Results {
		if res.RuleID == "" {
			t.Errorf("result %d has empty ruleId", i)
		}
		if res.Level != wantLevels[i] {
			t.Errorf("result %d level = %q, want %q", i, res.Level, wantLevels[i])
		}
		wantText := fs[i].Title + ": " + fs[i].Detail
		if res.Message.Text != wantText {
			t.Errorf("result %d message.text = %q, want %q", i, res.Message.Text, wantText)
		}
		if fp, ok := res.PartialFingerprints["taildocFindingSha256"]; !ok || fp == "" {
			t.Errorf("result %d missing partialFingerprints hash", i)
		}
		if res.Properties["severity"] != string(fs[i].Severity) {
			t.Errorf("result %d properties.severity = %v, want %s", i, res.Properties["severity"], fs[i].Severity)
		}
		if _, ok := res.Properties["evidence"]; !ok && fs[i].Evidence != nil {
			t.Errorf("result %d missing properties.evidence", i)
		}
	}
}

func TestRenderMarkdown(t *testing.T) {
	fs := sampleFindings()
	counts := map[Severity]int{High: 1, Medium: 1, Low: 1, Info: 1}
	data, err := RenderMarkdown(fs, counts)
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	s := string(data)
	for _, want := range []string{
		"# Taildoc Audit Report",
		"## HIGH: Grant allows everything to everyone",
		"## MEDIUM: Expired node keys",
		"## LOW: Only one exit node exists",
		"## INFO: Update available",
		"- src: *",
		"Why: Neutralizes access control.",
		"Next: Replace with explicit grants.",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
}

func TestRenderMarkdownEmpty(t *testing.T) {
	data, err := RenderMarkdown(nil, nil)
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if !strings.Contains(string(data), "# Taildoc Audit Report") {
		t.Error("empty report missing title")
	}
}
