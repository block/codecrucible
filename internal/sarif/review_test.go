package sarif

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestReviewPresentation(t *testing.T) {
	details := "Payload: <script>alert(1)</script> & `literal`"
	doc := Build(AnalysisResult{SecurityIssues: []SecurityIssue{
		{Issue: "Shared issue", FilePath: "a.go", StartLine: 1, Severity: 8, CWEID: "CWE-79", TechnicalDetails: details, Summary: "Attacker-controlled input reaches an unsafe sink.", Remediation: "Validate input before calling the sink."},
		{Issue: "Shared issue", FilePath: "b.go", StartLine: 1, Severity: 4, CWEID: "CWE-80", TechnicalDetails: "Other location details", Summary: "Another entry point lacks validation."},
	}}, nil, BuilderConfig{})
	before, _ := json.Marshal(doc)
	got := ReviewPresentation(doc)
	run := got.Runs[0]
	if len(run.Tool.Driver.Rules) != 1 || run.Tool.Driver.Rules[0].ID != doc.Runs[0].Tool.Driver.Rules[0].ID {
		t.Fatal("alert identity changed")
	}
	a, b := run.Results[0], run.Results[1]
	if a.Message.Text != "Attacker-controlled input reaches an unsafe sink." || b.Message.Text != "Another entry point lacks validation." {
		t.Fatal("message is not the finding's own summary", a.Message, b.Message)
	}
	if !strings.Contains(a.Message.Markdown, "Validate input") || !strings.Contains(a.Message.Markdown, "&lt;script&gt;") ||
		strings.Contains(a.Message.Markdown, "<script>") {
		t.Fatal("writeup missing remediation or safely escaped details", a.Message.Markdown)
	}
	// Each writeup stands alone: no sibling text in the result or shared rule.
	for _, leak := range []string{"Another entry point", "Other location details", "b.go"} {
		if strings.Contains(a.Message.Text+a.Message.Markdown, leak) {
			t.Fatal("sibling finding leaked into writeup", leak)
		}
	}
	rule := run.Tool.Driver.Rules[0]
	for _, leak := range []string{"Attacker-controlled", "Another entry point", "a.go", "b.go"} {
		if strings.Contains(rule.Help.Text+rule.Help.Markdown+rule.FullDescription.Text, leak) {
			t.Fatal("finding-specific text in shared rule", leak, rule)
		}
	}
	if *a.Properties.Severity != 8 || a.Properties.CWE != "CWE-79" || *b.Properties.Severity != 4 || b.Properties.CWE != "CWE-80" ||
		a.Level != "error" || b.Level != "warning" {
		t.Fatal("findings sharing a rule did not keep their own severity and CWE", a.Properties, b.Properties)
	}
	if rule.Properties["security-severity"] != "8.0" {
		t.Fatal("rule severity is not the worst finding", rule.Properties)
	}
	if a.Properties.AuditStatus != "not_audited" || a.Properties.Verified {
		t.Fatal("unaudited finding presented as verified", a.Properties)
	}
	if a.Properties.FindingID == "" || a.Properties.FindingID == b.Properties.FindingID {
		t.Fatal("findings lack unique IDs", a.Properties.FindingID, b.Properties.FindingID)
	}
	if a.Properties.TechnicalDetails != details || b.Properties.TechnicalDetails != "Other location details" {
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

func TestReviewPresentationVerificationState(t *testing.T) {
	confidence := 0.9
	doc := Build(AnalysisResult{SecurityIssues: []SecurityIssue{
		{Issue: "Confirmed", FilePath: "a.go", StartLine: 1, Severity: 5},
		{Issue: "Rejected", FilePath: "b.go", StartLine: 1, Severity: 9},
		{Issue: "Confirmed", FilePath: "c.go", StartLine: 1, Severity: 3},
	}}, nil, BuilderConfig{})
	results := doc.Runs[0].Results
	for i := range results {
		results[i].Properties.AuditConfidence = &confidence
		results[i].Properties.AuditStatus = "confirmed"
	}
	results[1].Properties.AuditStatus = "rejected"
	results[1].Suppressions = []SARIFSuppression{{Kind: "external", Status: "accepted", Justification: "guarded"}}
	results[2].Suppressions = []SARIFSuppression{{Kind: "external", Status: "accepted"}}
	got := ReviewPresentation(doc).Runs[0]
	if !got.Results[0].Properties.Verified || got.Results[1].Properties.Verified || got.Results[2].Properties.Verified {
		t.Fatal("verified must mean affirmed by audit and not suppressed")
	}
	if !strings.Contains(got.Results[0].Message.Markdown, "confidence 90%") || !strings.Contains(got.Results[1].Message.Markdown, "Rejected") {
		t.Fatal("writeup status does not reflect finding state")
	}
	for _, rule := range got.Tool.Driver.Rules {
		want := map[string]string{"Confirmed": "5.0", "Rejected": "9.0"}[rule.ShortDescription.Text]
		if rule.Properties["security-severity"] != want {
			t.Fatal("rule severity must follow active findings first", rule.ShortDescription.Text, rule.Properties)
		}
	}
}

func TestFindingIDsAreStableAndUnique(t *testing.T) {
	files := FileMap{"a.go": "package a\n\nfunc f() { exec(input) }\nfunc g() { exec(input) }\n"}
	scan := func(title, details string, line int) SARIFResult {
		doc := AssignFindingIDs(Build(AnalysisResult{SecurityIssues: []SecurityIssue{
			{Issue: title, FilePath: "a.go", StartLine: line, CWEID: "CWE-78", TechnicalDetails: details},
		}}, files, BuilderConfig{}))
		return doc.Runs[0].Results[0]
	}
	first := scan("Command injection", "first wording", 3)
	reworded := scan("OS command injection via f", "second wording", 3)
	if first.Properties.FindingID != reworded.Properties.FindingID {
		t.Fatal("model wording changed the finding ID")
	}
	if first.PartialFingerprints[FingerprintKey] == "" || !strings.HasPrefix(first.Properties.FindingID, "CC-") {
		t.Fatal("missing fingerprint or ID format", first)
	}
	shifted := FileMap{"a.go": "package a\n\n// added\nfunc f() { exec(input) }\n"}
	moved := AssignFindingIDs(Build(AnalysisResult{SecurityIssues: []SecurityIssue{
		{Issue: "Command injection", FilePath: "a.go", StartLine: 4, CWEID: "CWE-78"},
	}}, shifted, BuilderConfig{})).Runs[0].Results[0]
	if moved.Properties.FindingID != first.Properties.FindingID {
		t.Fatal("an unrelated line shift changed the finding ID")
	}

	// Lines 3 and 4 flag identical source text: still distinct findings.
	doc := AssignFindingIDs(Build(AnalysisResult{SecurityIssues: []SecurityIssue{
		{Issue: "Command injection", FilePath: "a.go", StartLine: 3, EndLine: 3, CWEID: "CWE-78"},
		{Issue: "Command injection", FilePath: "a.go", StartLine: 4, EndLine: 4, CWEID: "CWE-78"},
	}}, FileMap{"a.go": "\n\nexec(input)\nexec(input)\n"}, BuilderConfig{}))
	if doc.Runs[0].Results[0].Properties.FindingID == doc.Runs[0].Results[1].Properties.FindingID {
		t.Fatal("colliding findings share an ID")
	}
	// Assigned IDs survive later changes such as an audit-refined CWE.
	doc.Runs[0].Results[0].Properties.CWE = "CWE-77"
	if again := AssignFindingIDs(doc); again.Runs[0].Results[0].Properties.FindingID != doc.Runs[0].Results[0].Properties.FindingID {
		t.Fatal("existing finding ID was replaced")
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
	r := got.Runs[0].Results[0]
	if r.Properties.Summary != "Relevant explanation." || r.Message.Text != "Relevant explanation." ||
		r.Properties.Verified || !strings.Contains(r.Message.Markdown, "Unverified") {
		t.Fatal(got)
	}
	doc.Runs[0].Results[0].Properties.AuditStatus = "not_audited"
	if !strings.Contains(ReviewPresentation(doc).Runs[0].Results[0].Message.Markdown, "Not audited") {
		t.Fatal("unaudited finding not visible")
	}
}

func TestReviewStatusNamesDuplicateAndCrux(t *testing.T) {
	dup := SARIFResult{Properties: &FindingProperties{AuditStatus: "duplicate", DuplicateOf: "cc-1"},
		Suppressions: []SARIFSuppression{{Kind: "external", Status: "accepted"}}}
	if got := reviewStatus(dup); got != "Duplicate of cc-1" {
		t.Errorf("duplicate status = %q", got)
	}
	open := SARIFResult{Properties: &FindingProperties{AuditStatus: "unverified", AuditCrux: "whether the caller checks the role"}}
	if got := reviewStatus(open); !strings.HasSuffix(got, ". Open question: whether the caller checks the role") {
		t.Errorf("unverified status = %q", got)
	}
}
