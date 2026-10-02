package decision

import "testing"

func TestCitedSelectionDoesNotRequireUnrelatedCallers(t *testing.T) {
	files := map[string]string{"a.go": "package app\nfunc bad(x string) { sink(x) }\nfunc caller() { bad(input()) }\n", "missing.go": "not admitted"}
	index := NewEvidenceIndex(files, map[string][]string{"a.go": {"unavailable.go"}})
	s := index.SelectCited([]SourceRange{{Path: "a.go", Start: 2}}, 1000)
	if !s.Complete() || len(s.Evidence) != 1 || s.Evidence[0].Start != 2 || s.Evidence[0].End != 2 {
		t.Fatalf("unexpected evidence: %+v", s)
	}
	for _, spans := range [][]SourceRange{nil, {{Path: "a.go", Start: 900}}, {{Path: "unknown.go", Start: 1}}} {
		if index.SelectCited(spans, 1000).Complete() {
			t.Fatal("invalid citation marked complete")
		}
	}
	if index.SelectCited([]SourceRange{{Path: "a.go", Start: 2}}, 1).Complete() {
		t.Fatal("budget bypass")
	}
}
