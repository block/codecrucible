package sarif

import (
	"testing"

	"github.com/block/codecrucible/internal/auditcore"
)

// Two independently fixable command-injection sinks happen to be on one line.
// The model supplies distinct structured source/sink evidence, with or without
// a rendered code_path. Exact file:line equality does not make them one cause.
func TestReviewDedupPreservesDistinctInitialEvidence(t *testing.T) {
	files := FileMap{
		"handler.go": "package app\nfunc run(req Request) {\n first := req.First\n second := req.Second\n exec.Command(\"sh\", \"-c\", first).Run(); exec.Command(\"sh\", \"-c\", second).Run()\n}\n",
	}
	issues := []SecurityIssue{
		{Issue: "First command injection", FilePath: "handler.go", StartLine: 5, EndLine: 5, CWEID: "CWE-78", Severity: 9,
			TechnicalDetails: "req.First reaches the first shell invocation; replace the first invocation with a fixed command and separate arguments.",
			FindingEvidence: []auditcore.NamedEvidence{
				{Kind: "source", Evidence: auditcore.Evidence{File: "handler.go", Start: 3, End: 3, Quote: "first := req.First"}},
				{Kind: "sink", Evidence: auditcore.Evidence{File: "handler.go", Start: 5, End: 5, Quote: "exec.Command(\"sh\", \"-c\", first).Run()"}},
			}},
		{Issue: "Second command injection", FilePath: "handler.go", StartLine: 5, EndLine: 5, CWEID: "CWE-78", Severity: 9,
			TechnicalDetails: "req.Second reaches the second shell invocation; replace the second invocation with a fixed command and separate arguments.",
			FindingEvidence: []auditcore.NamedEvidence{
				{Kind: "source", Evidence: auditcore.Evidence{File: "handler.go", Start: 4, End: 4, Quote: "second := req.Second"}},
				{Kind: "sink", Evidence: auditcore.Evidence{File: "handler.go", Start: 5, End: 5, Quote: "exec.Command(\"sh\", \"-c\", second).Run()"}},
			}},
	}
	doc := Build(AnalysisResult{SecurityIssues: issues}, files, BuilderConfig{})
	got := PostProcess(Merge([]SARIFDocument{doc}))
	if n := len(got.Runs[0].Results); n != 2 {
		t.Fatalf("lost an independently fixable finding before audit: got %d results from 2 distinct structured source/sink evidence sets", n)
	}
}

func initialEvidence(file string, source, sink int) []auditcore.NamedEvidence {
	return []auditcore.NamedEvidence{
		{Kind: "source", Evidence: auditcore.Evidence{File: file, Start: source, End: source}},
		{Kind: "sink", Evidence: auditcore.Evidence{File: file, Start: sink, End: sink}},
	}
}

// Structured evidence and a rendered code flow describing the same source and
// sink are one defect, however each report chose to express it.
func TestReviewDedupMatchesInitialEvidenceToCodeFlow(t *testing.T) {
	rule := makeRule("query", "8", "cwe-89")
	a, b := makeResult("query", "a.go", 10, "error"), makeResult("query", "a.go", 10, "error")
	a.Properties = &FindingProperties{InitialEvidence: initialEvidence("a.go", 2, 10)}
	b.CodeFlows = []SARIFCodeFlow{{ThreadFlows: []SARIFThreadFlow{{Locations: []SARIFThreadFlowLocation{
		{Location: makeResult("query", "a.go", 2, "error").Locations[0]},
		{Location: makeResult("query", "a.go", 6, "error").Locations[0]},
		{Location: makeResult("query", "a.go", 10, "error").Locations[0]},
	}}}}}
	if n := len(PostProcess(testDoc([]SARIFRule{rule}, []SARIFResult{a, b}, nil)).Runs[0].Results); n != 1 {
		t.Fatalf("same source/sink expressed as evidence and as a flow: got %d results, want 1", n)
	}
}

// Guards describe mitigations, not the defect, so citing different guards does
// not split one source-to-sink defect into two findings.
func TestReviewDedupIgnoresGuardEvidenceForIdentity(t *testing.T) {
	rule := makeRule("query", "8", "cwe-89")
	a, b := makeResult("query", "a.go", 10, "error"), makeResult("query", "a.go", 10, "error")
	a.Properties = &FindingProperties{InitialEvidence: append(initialEvidence("a.go", 2, 10), auditcore.NamedEvidence{Kind: "guard", Evidence: auditcore.Evidence{File: "a.go", Start: 4, End: 4}})}
	b.Properties = &FindingProperties{InitialEvidence: append(initialEvidence("a.go", 2, 10), auditcore.NamedEvidence{Kind: "guard", Evidence: auditcore.Evidence{File: "a.go", Start: 7, End: 7}})}
	if n := len(PostProcess(testDoc([]SARIFRule{rule}, []SARIFResult{a, b}, nil)).Runs[0].Results); n != 1 {
		t.Fatalf("guard citations split one defect: got %d results, want 1", n)
	}
}

// An anchorless report must not be folded into one of several distinct
// structured-evidence findings: its identity is ambiguous.
func TestReviewDedupKeepsAnchorlessReportApartFromConflictingEvidence(t *testing.T) {
	rule := makeRule("query", "8", "cwe-89")
	a, b, c := makeResult("query", "a.go", 10, "error"), makeResult("query", "a.go", 10, "error"), makeResult("query", "a.go", 10, "error")
	a.Properties = &FindingProperties{InitialEvidence: initialEvidence("a.go", 2, 10)}
	b.Properties = &FindingProperties{InitialEvidence: initialEvidence("a.go", 3, 10)}
	for _, docs := range [][]SARIFDocument{
		{testDoc([]SARIFRule{rule}, []SARIFResult{a, b, c}, nil)},
		{testDoc([]SARIFRule{rule}, []SARIFResult{a}, nil), testDoc([]SARIFRule{rule}, []SARIFResult{b}, nil), testDoc([]SARIFRule{rule}, []SARIFResult{c}, nil)},
	} {
		if n := len(PostProcess(Merge(docs)).Runs[0].Results); n != 3 {
			t.Fatalf("got %d results, want 3", n)
		}
	}
}

// sameLineShellCalls reports two shell calls on one line fed by two sources
// on one line. The line coordinates are identical; only the quoted
// expressions tell the defects apart.
func sameLineShellCalls(sourceA, sinkA, sourceB, sinkB string) (FileMap, []SecurityIssue) {
	files := FileMap{
		"handler.go": "package app\nfunc run(req Request) {\n first, second := req.First, req.Second\n _ = 0\n exec.Command(\"sh\", \"-c\", first).Run(); exec.Command(\"sh\", \"-c\", second).Run()\n}\n",
	}
	issue := func(title, source, sink string) SecurityIssue {
		return SecurityIssue{Issue: title, FilePath: "handler.go", StartLine: 5, EndLine: 5, CWEID: "CWE-78", Severity: 9,
			TechnicalDetails: title + " reaches a shell invocation; use a fixed command with separate arguments.",
			FindingEvidence: []auditcore.NamedEvidence{
				{Kind: "source", Evidence: auditcore.Evidence{File: "handler.go", Start: 3, End: 3, Quote: source}},
				{Kind: "sink", Evidence: auditcore.Evidence{File: "handler.go", Start: 5, End: 5, Quote: sink}},
			}}
	}
	return files, []SecurityIssue{issue("First command injection", sourceA, sinkA), issue("Second command injection", sourceB, sinkB)}
}

func TestReviewDedupPreservesDistinctSameLineExpressions(t *testing.T) {
	files, issues := sameLineShellCalls(
		"req.First", `exec.Command("sh", "-c", first).Run()`,
		"req.Second", `exec.Command("sh", "-c", second).Run()`)
	doc := Build(AnalysisResult{SecurityIssues: issues}, files, BuilderConfig{})
	if n := len(PostProcess(Merge([]SARIFDocument{doc})).Runs[0].Results); n != 2 {
		t.Fatalf("collapsed two shell calls with distinct quoted expressions on shared lines: got %d results, want 2", n)
	}
	// The same pair reported by separate analysis documents must survive the
	// cross-document merge too.
	first := Build(AnalysisResult{SecurityIssues: issues[:1]}, files, BuilderConfig{})
	second := Build(AnalysisResult{SecurityIssues: issues[1:]}, files, BuilderConfig{})
	if n := len(Merge([]SARIFDocument{first, second}).Runs[0].Results); n != 2 {
		t.Fatalf("merge collapsed distinct same-line expressions: got %d results, want 2", n)
	}
}

// Quoting the same expression with different spacing, or quoting part of
// it, is rewording, not a second defect.
func TestReviewDedupMergesRewordedSameLineExpressions(t *testing.T) {
	files, issues := sameLineShellCalls(
		"req.First", `exec.Command("sh", "-c", first).Run()`,
		"first, second := req.First", `exec.Command("sh","-c",first)`)
	doc := Build(AnalysisResult{SecurityIssues: issues}, files, BuilderConfig{})
	if n := len(PostProcess(Merge([]SARIFDocument{doc})).Runs[0].Results); n != 1 {
		t.Fatalf("reworded quotes of one defect: got %d results, want 1", n)
	}
}
