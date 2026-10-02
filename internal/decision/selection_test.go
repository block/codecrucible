package decision

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestClaimEvidencePrioritizesFunctionGuardsAndDependencies(t *testing.T) {
	files := map[string]string{
		"handler.go": "package app\nfunc Handle(input string) {\n if !Allowed(input) { return }\n Sink(input)\n}\n" + strings.Repeat("// unrelated padding\n", 3000) + "func Unrelated() {}\n",
		"guard.go":   "package app\nfunc Allowed(input string) bool { return input == \"safe\" }\n",
		"route.go":   "package app\nfunc Route() { Handle(Request()) }\n",
		"unused.go":  "package app\n" + strings.Repeat("// irrelevant dependency\n", 3000) + "func Unused() {}\n",
	}
	graph := map[string][]string{"handler.go": {"guard.go", "unused.go"}, "route.go": {"handler.go"}}
	index := NewEvidenceIndex(files, graph)
	selection := index.Select([]SourceRange{{Path: "handler.go", Start: 4, End: 4}}, 4000)
	if !selection.Complete() {
		t.Fatalf("unrelated file exhausted evidence: %+v", selection.Gaps)
	}
	text := ""
	for _, e := range selection.Evidence {
		text += e.Text + "\n"
	}
	for _, want := range []string{"if !Allowed(input)", "func Allowed", "func Route"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %s: %s", want, text)
		}
	}
	if strings.Contains(text, "padding") || strings.Contains(text, "Unused") {
		t.Fatal("included unrelated code")
	}
	encoded, _ := json.Marshal(selection.Evidence)
	if len(encoded) > 4000 {
		t.Fatalf("evidence exceeded budget: %d", len(encoded))
	}
	if !reflect.DeepEqual(selection, index.Select([]SourceRange{{Path: "handler.go", Start: 4, End: 4}}, 4000)) {
		t.Fatal("nondeterministic evidence selection")
	}
}
func TestClaimEvidenceReportsMissingInvalidAndBudgetGaps(t *testing.T) {
	index := NewEvidenceIndex(map[string]string{"a.go": "package app\nfunc Handle() {\n Sink()\n}\n"}, nil)
	for _, tc := range []struct {
		name   string
		span   SourceRange
		budget int
		reason string
	}{
		{"missing", SourceRange{Path: "absent.go", Start: 1, End: 1}, 4000, "missing_source"},
		{"invalid", SourceRange{Path: "a.go", Start: 999, End: 999}, 4000, "invalid_location"},
		{"budget", SourceRange{Path: "a.go", Start: 3, End: 3}, 1, "evidence_budget"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := index.Select([]SourceRange{tc.span}, tc.budget)
			if got.Complete() {
				t.Fatal("incomplete source accepted")
			}
			found := false
			for _, gap := range got.Gaps {
				if gap.Reason == tc.reason {
					found = true
				}
			}
			if !found {
				t.Fatalf("missing categorical gap %s: %+v", tc.reason, got.Gaps)
			}
		})
	}
}
func TestClaimEvidenceConservativelyIncludesUnparsedFiles(t *testing.T) {
	index := NewEvidenceIndex(map[string]string{"a.py": "if allowed():\n    execute()\n"}, nil)
	got := index.Select([]SourceRange{{Path: "a.py", Start: 2, End: 2}}, 2000)
	if !got.Complete() || len(got.Evidence) != 1 || !strings.Contains(got.Evidence[0].Text, "if allowed") {
		t.Fatalf("lost enclosing control: %+v", got)
	}
}

func TestClaimEvidenceMissingDependencyCannotBecomeComplete(t *testing.T) {
	index := NewEvidenceIndex(map[string]string{"a.go": "package app\nfunc Handle() { Guard(); Sink() }\n"}, map[string][]string{"a.go": {"missing.go"}})
	got := index.Select([]SourceRange{{Path: "a.go", Start: 2, End: 2}}, 4000)
	if got.Complete() || len(got.Gaps) != 1 || got.Gaps[0].Reason != "missing_source" || got.Gaps[0].Path != "missing.go" {
		t.Fatalf("missing dependency hidden: %+v", got)
	}
	recorder := Recorder{}
	recorder.Skip("audit", "active", "incomplete_source_coverage")
	recorder.FindingCoverage("immutable-finding", got)
	data, _ := json.Marshal(recorder.Report())
	if strings.Contains(string(data), "Guard(); Sink()") || recorder.Records[0].Subject != "immutable-finding" || len(recorder.Records[0].CoverageGaps) != 1 {
		t.Fatal("missing safe per-finding coverage diagnostics")
	}
}

func TestCallbackEvidenceIncludesRegistrationWithoutUnrelatedHandlerExpansion(t *testing.T) {
	files := map[string]string{
		"handler.go": "package app\nfunc Handle() { Shared(); Sink() }\n",
		"shared.go":  "package app\nfunc Shared() {}\n",
		"auth.go":    "package app\nfunc Auth() { if !Trusted() { return } }\n",
		"other.go":   "package app\nfunc Other() { Shared()\n" + strings.Repeat(" println(\"unrelated\")\n", 300) + "}\n",
		"router.go":  "package app\nfunc Routes() { Use(Auth); Get(\"/one\", Handle); Get(\"/two\", Other) }\n",
		"main.go":    "package app\nfunc main() { Routes() }\n",
	}
	graph := map[string][]string{"handler.go": {"shared.go"}, "other.go": {"shared.go"}, "router.go": {"handler.go", "other.go", "auth.go"}, "main.go": {"router.go"}}
	got := NewEvidenceIndex(files, graph).Select([]SourceRange{{Path: "handler.go", Start: 2}}, 4000)
	if !got.Complete() {
		t.Fatalf("unrelated handler consumed evidence: %+v", got.Gaps)
	}
	text := ""
	for _, e := range got.Evidence {
		text += e.Text + "\n"
	}
	for _, want := range []string{"func Handle", "func Shared", "Get(\"/one\", Handle)", "Use(Auth)", "func Auth", "func main"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing callback context %s", want)
		}
	}
	if strings.Contains(text, "func Other") {
		t.Fatal("expanded unrelated sibling handler")
	}
}

func TestGroupingEvidenceFindsRelevantDefinitionsBelowHeaders(t *testing.T) {
	file := "package app\n" + strings.Repeat("// License\n", 300) + "func Customer() { QueryCustomer() }\n"
	index := NewEvidenceIndex(map[string]string{"a.go": file}, nil)
	evidence := index.RelevantEvidence("a.go", map[string]bool{"QueryCustomer": true}, 2000)
	if len(evidence) != 1 || strings.Contains(evidence[0].Text, "License") {
		t.Fatal("license text displaced the relevant declaration")
	}
	file = "package app\n" + strings.Repeat("\n", 300) + "func Customer() { QueryCustomer() }\n"
	index = NewEvidenceIndex(map[string]string{"a.go": file}, nil)
	evidence = index.RelevantEvidence("a.go", map[string]bool{"QueryCustomer": true}, 2000)
	if len(evidence) != 1 || !strings.Contains(evidence[0].Text, "QueryCustomer()") || evidence[0].Start < 300 {
		t.Fatalf("missing relevant body: %+v", evidence)
	}
}
