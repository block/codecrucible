package sarif

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestReviewPresentationKeepsAssessmentsInProperties(t *testing.T) {
	doc := WithFindingIDs(Build(AnalysisResult{SecurityIssues: []SecurityIssue{{Issue: "Unsafe output", FilePath: "a.go", StartLine: 1, Summary: "A source assertion needs checking."}}}, nil, BuilderConfig{}))
	p := doc.Runs[0].Results[0].Properties
	confidence := 0.0
	p.AuditStatus = "unverified"
	p.AuditConfidence = &confidence
	p.AuditJustification = "GATE 0: unknown"
	p.AuditGates = []AuditGate{{ID: "production_reachability", Status: "unknown", Reason: "Missing caller"}}
	p.AuditReasons = []string{"below_confidence_threshold"}
	p.DecisionReview = &DecisionAssessment{Status: "contradicted", Checks: []DecisionCheck{{Assertion: "The output includes <script>.", Status: "contradicted"}}}
	p.DecisionCWE = &CWEAssessment{Status: "uncertain", Proposed: "CWE-79"}
	got := ReviewPresentation(doc)
	rule := got.Runs[0].Tool.Driver.Rules[0]
	visible := got.Runs[0].Results[0].Message.Text + rule.FullDescription.Text + rule.Help.Text + rule.Help.Markdown
	for _, metadata := range []string{"unverified", "GATE 0", "contradicted", "<script>", "CWE classification", p.FindingID} {
		if strings.Contains(visible, metadata) {
			t.Fatalf("metadata %q in description: %s", metadata, visible)
		}
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip SARIFDocument
	if err := json.Unmarshal(data, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(roundTrip.Runs[0].Results[0].Properties, got.Runs[0].Results[0].Properties) {
		t.Fatal("metadata lost during serialization")
	}
	if !reflect.DeepEqual(p.AuditGates, got.Runs[0].Results[0].Properties.AuditGates) || got.Runs[0].Results[0].Properties.FindingID != p.FindingID {
		t.Fatal("assessment or identity lost")
	}
}

func TestReviewPresentation(t *testing.T) {
	details := "Payload: <script>alert(1)</script> & `literal`\n\n[Audit confidence: 90%] GATE 0: verbose reasoning."
	doc := Build(AnalysisResult{SecurityIssues: []SecurityIssue{
		{Issue: "Shared issue", FilePath: "a.go", StartLine: 1, TechnicalDetails: details, Summary: "Attacker-controlled input reaches an unsafe sink.", Remediation: "Validate input before calling the sink."},
		{Issue: "Shared issue", FilePath: "b.go", StartLine: 1, TechnicalDetails: "Other location details", Summary: "Another entry point lacks validation."},
	}}, nil, BuilderConfig{})
	before, _ := json.Marshal(doc)
	got := ReviewPresentation(doc)
	if got.Runs[0].Results[0].Message.Text != "Shared issue" {
		t.Fatal("verbose inline annotation", got.Runs[0].Results[0].Message)
	}
	rule := got.Runs[0].Tool.Driver.Rules[0]
	if rule.ID != doc.Runs[0].Tool.Driver.Rules[0].ID || len(got.Runs[0].Tool.Driver.Rules) != 1 {
		t.Fatal("alert identity changed")
	}
	for _, want := range []string{"a.go:1", "b.go:1", "Attacker-controlled input", "Another entry point", "Validate input"} {
		if !strings.Contains(rule.Help.Text, want) {
			t.Fatal("missing issue description", want, rule.Help)
		}
	}
	if strings.Contains(rule.Help.Text+rule.Help.Markdown, "GATE 0") || strings.Contains(rule.Help.Markdown, "<script>") ||
		!strings.Contains(rule.Help.Markdown, "<details>") || !strings.Contains(rule.Help.Markdown, "&lt;script&gt;") {
		t.Fatal("verbose evidence not safely separated", rule.Help)
	}
	if got.Runs[0].Results[0].Properties.TechnicalDetails != strings.Split(details, "\n\n")[0] || got.Runs[0].Results[0].Properties.AuditJustification != "GATE 0: verbose reasoning." ||
		got.Runs[0].Results[1].Properties.TechnicalDetails != "Other location details" {
		t.Fatal("evidence lost or mixed")
	}
	after, _ := json.Marshal(doc)
	if string(before) != string(after) {
		t.Fatal("input snapshot mutated")
	}
	if !reflect.DeepEqual(got, ReviewPresentation(got)) {
		t.Fatal("presentation is not idempotent")
	}
}

func TestBuildCodeFlows(t *testing.T) {
	files := FileMap{"source.go": "input\nforward\n", "sink.go": "check\nexecute\n"}
	steps := []CodePathStep{{"source.go", 1, 2, "User input enters here"}, {"sink.go", 2, 2, "Input reaches the unsafe operation"}}
	flows := BuildCodeFlows(steps, files)
	if len(flows) != 1 || len(flows[0].ThreadFlows) != 1 {
		t.Fatal(flows)
	}
	locations := flows[0].ThreadFlows[0].Locations
	if len(locations) != 2 || locations[1].ExecutionOrder != 2 || locations[1].Location.PhysicalLocation.Region.Snippet.Text != "execute" {
		t.Fatal("incorrect ordered path", locations)
	}
	data, err := json.Marshal(Build(AnalysisResult{SecurityIssues: []SecurityIssue{{Issue: "Unsafe operation", FilePath: "sink.go", StartLine: 2, CodePath: steps}}}, files, BuilderConfig{}))
	if err != nil || !strings.Contains(string(data), `"codeFlows":[{"threadFlows":[{"locations":`) {
		t.Fatalf("missing SARIF path: %s, %v", data, err)
	}
	for _, invalid := range []CodePathStep{
		{"missing.go", 1, 1, "unknown"}, {"source.go", 0, 1, "zero"}, {"source.go", 2, 1, "reversed"},
		{"source.go", 1, 3, "past EOF"}, {"../source.go", 1, 1, "traversal"}, {"/source.go", 1, 1, "absolute"},
		{"source.go", 1, 1, ""},
	} {
		if got := BuildCodeFlows([]CodePathStep{steps[0], invalid, steps[1]}, files); got != nil {
			t.Fatal("invalid path accepted", invalid)
		}
	}
}

func TestReviewLegacyFallbackAndUncertainty(t *testing.T) {
	doc := Build(AnalysisResult{SecurityIssues: []SecurityIssue{{Issue: "Issue", TechnicalDetails: "[UNVERIFIED]\n\nRelevant explanation.\n\n[Audit confidence: 30%] GATE 0: full audit."}}}, nil, BuilderConfig{})
	doc.Runs[0].Results[0].Properties.AuditStatus = "unverified"
	got := ReviewPresentation(doc)
	if got.Runs[0].Results[0].Properties.Summary != "Relevant explanation." || got.Runs[0].Results[0].Message.Text != "Issue" || got.Runs[0].Results[0].Properties.AuditStatus != "unverified" {
		t.Fatal(got)
	}
	doc.Runs[0].Results[0].Properties.AuditStatus = "not_audited"
	if got := ReviewPresentation(doc); got.Runs[0].Results[0].Message.Text != "Issue" || got.Runs[0].Results[0].Properties.AuditStatus != "not_audited" {
		t.Fatal("unaudited status lost or leaked into annotation")
	}
}
