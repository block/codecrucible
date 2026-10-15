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
		{Issue: "Shared issue", FilePath: "a.go", StartLine: 1, Severity: 8, CWEID: "CWE-79", TechnicalDetails: details, Summary: "Attacker-controlled input reaches an unsafe sink. It is not encoded.", Remediation: "Validate input before calling the sink."},
		{Issue: "Shared issue", FilePath: "b.go", StartLine: 1, Severity: 4, CWEID: "CWE-80", TechnicalDetails: "Other location details", Summary: "Another entry point lacks validation."},
	}}, nil, BuilderConfig{})
	before, _ := json.Marshal(doc)
	got := ReviewPresentation(doc)
	run := got.Runs[0]
	a, b := run.Results[0], run.Results[1]
	// Findings sharing a title get their own rules, keyed by finding ID.
	if len(run.Tool.Driver.Rules) != 2 || a.RuleID != rulePrefix+a.Properties.FindingID || b.RuleID != rulePrefix+b.Properties.FindingID {
		t.Fatal("each finding needs its own rule", run.Tool.Driver.Rules)
	}
	ruleA, ruleB := run.Tool.Driver.Rules[0], run.Tool.Driver.Rules[1]
	if ruleA.ID != a.RuleID || ruleB.ID != b.RuleID || ruleA.ShortDescription.Text != "Shared issue" {
		t.Fatal("rules do not match their findings", ruleA, ruleB)
	}
	if a.Message.Text != "Attacker-controlled input reaches an unsafe sink. Not audited; review manually." || a.Message.Markdown != "" {
		t.Fatal("annotation is not the finding's first sentence and status", a.Message)
	}
	if ruleA.FullDescription.Text != "Attacker-controlled input reaches an unsafe sink. It is not encoded." {
		t.Fatal("rule description is not the finding's summary", ruleA.FullDescription)
	}
	help := ruleA.Help.Markdown
	if !strings.Contains(help, "Validate input") || !strings.Contains(help, "&lt;script&gt;") || strings.Contains(help, "<script>") ||
		!strings.Contains(help, "<code>literal</code>") || !strings.Contains(ruleA.Help.Text, details) {
		t.Fatal("writeup missing remediation or safely escaped details", ruleA.Help)
	}
	// Each writeup stands alone: no sibling text in the result or its rule.
	for _, leak := range []string{"Another entry point", "Other location details"} {
		if strings.Contains(a.Message.Text+ruleA.Help.Text+ruleA.Help.Markdown+ruleA.FullDescription.Text, leak) {
			t.Fatal("sibling finding leaked into writeup", leak)
		}
	}
	if *a.Properties.Severity != 8 || a.Properties.CWE != "CWE-79" || *b.Properties.Severity != 4 || b.Properties.CWE != "CWE-80" ||
		a.Level != "error" || b.Level != "warning" {
		t.Fatal("findings sharing a title did not keep their own severity and CWE", a.Properties, b.Properties)
	}
	if ruleA.Properties["security-severity"] != "8.0" || ruleB.Properties["security-severity"] != "4.0" ||
		!reflect.DeepEqual(ruleB.Properties["tags"], []string{"security", "external/cwe/cwe-80"}) || ruleB.Relationships[0].Target.ID != "CWE-80" {
		t.Fatal("rule metadata is not its finding's", ruleA.Properties, ruleB)
	}
	taxa := map[string]bool{}
	for _, taxon := range run.Taxonomies[0].Taxa {
		taxa[taxon.ID] = true
	}
	if !taxa["CWE-79"] || !taxa["CWE-80"] {
		t.Fatal("rule relationship lacks a taxon", run.Taxonomies)
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
	if !strings.Contains(got.Results[0].Message.Text, "confidence 90%") || !strings.Contains(got.Tool.Driver.Rules[1].Help.Markdown, "Rejected") {
		t.Fatal("writeup status does not reflect finding state")
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
	if r.Properties.Summary != "Relevant explanation." || !strings.HasPrefix(r.Message.Text, "Relevant explanation. Unverified") ||
		r.Properties.Verified || !strings.Contains(got.Runs[0].Tool.Driver.Rules[0].Help.Markdown, "Unverified") {
		t.Fatal(got)
	}
	doc.Runs[0].Results[0].Properties.AuditStatus = "not_audited"
	if !strings.Contains(ReviewPresentation(doc).Runs[0].Results[0].Message.Text, "Not audited") {
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

func TestMarkdownTextEscaping(t *testing.T) {
	// GitHub renders HTML entities but not backslash-escaped ones.
	if got := markdownText("system('cmd') # *x*"); got != "system(&#39;cmd&#39;) \\# \\*x\\*" {
		t.Errorf("markdownText = %q", got)
	}
	if got := markdownText("call `a<b>` then `c`"); got != "call <code>a&lt;b&gt;</code> then <code>c</code>" {
		t.Errorf("code spans = %q", got)
	}
	if got := markdownText("unbalanced ` tick"); got != "unbalanced \\` tick" {
		t.Errorf("unbalanced = %q", got)
	}
}

func TestFirstSentence(t *testing.T) {
	for in, want := range map[string]string{
		"One. Two.":                "One",
		"Calls os.system(). Then.": "Calls os.system()",
		"No terminator":            "No terminator",
		"Ends here.":               "Ends here",
	} {
		if got := firstSentence(in); got != want {
			t.Errorf("firstSentence(%q) = %q, want %q", in, got, want)
		}
	}
}
