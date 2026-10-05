package decision

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRelatedEvidenceFindsTemplateAttachmentAndHonorsBudget(t *testing.T) {
	files := map[string]string{
		"client.js":      "const el = document.getElementById('preview');\nif (el) el.innerHTML = location.hash;",
		"page.html":      "<div id='preview'></div>\n<script src='client.js'></script>",
		"unrelated.html": "<p>Other page</p>",
	}
	index := NewEvidenceIndex(files, nil)
	anchors := index.SelectCited([]SourceRange{{Path: "client.js", Start: 2, End: 2}}, 9000)
	got := index.RelatedEvidence(anchors.Evidence, 7000)
	if len(got) != 1 || got[0].Path != "page.html" {
		t.Fatalf("template relation missing: %+v", got)
	}
	if len(index.RelatedEvidence(anchors.Evidence, 1)) != 0 {
		t.Fatal("ignored evidence byte budget")
	}
	if !anchors.Complete() || len(anchors.Evidence) != 1 {
		t.Fatal("retrieval mutated mandatory source")
	}
}

func TestRelatedEvidenceOmitsAlreadySuppliedFilesButFollowsTheirDefinitions(t *testing.T) {
	files := map[string]string{"handler.go": `package app
func handler(input string) {
 if !allowed(input) { return }
 execute(input)
}
func allowed(input string) bool { return validateInput(input) }
func register() { router.Handle(handler) }
func unrelated() { other() }
`, "validation.go": "package app\nfunc validateInput(input string) bool { return input == \"known\" }\n"}
	index := NewEvidenceIndex(files, map[string][]string{"handler.go": {"validation.go"}})
	anchors := index.SelectCited([]SourceRange{{Path: "handler.go", Start: 4}}, 9000)
	got := index.RelatedEvidence(anchors.Evidence, 7000)
	if len(got) != 1 || got[0].Path != "validation.go" {
		t.Fatalf("follow same-file definitions without repeating already supplied source: %+v", got)
	}
}

func TestRelatedEvidenceBudgetExcludesMandatorySource(t *testing.T) {
	files := map[string]string{
		"handler.go": "package app\nfunc handler(input string) {\n" + strings.Repeat(" // mandatory source padding\n", 80) + " if allowed(input) { execute(input) }\n}\n",
		"guard.go":   "package app\nfunc allowed(input string) bool { return input == \"known\" }\n",
	}
	index := NewEvidenceIndex(files, map[string][]string{"handler.go": {"guard.go"}})
	anchors := index.SelectCited([]SourceRange{{Path: "handler.go", Start: 2}}, 9000)
	const budget = 500
	got := index.RelatedEvidence(anchors.Evidence, budget)
	if len(got) != 1 || got[0].Path != "guard.go" {
		t.Fatalf("mandatory source consumed optional budget: %+v", got)
	}
	encoded, _ := json.Marshal(got)
	if len(encoded) > budget {
		t.Fatalf("optional evidence exceeds budget: %d > %d", len(encoded), budget)
	}
}

func TestRelatedEvidenceKeepsCompleteDeclarations(t *testing.T) {
	guard := "func allowed(input string) bool {\n" + strings.Repeat(" // preserve guard context\n", 30) + " return input == \"known\"\n}"
	files := map[string]string{
		"handler.go": "package app\nfunc handler(input string) { if allowed(input) { execute(input) } }\n",
		"guard.go":   "package app\n" + guard + "\n",
	}
	index := NewEvidenceIndex(files, map[string][]string{"handler.go": {"guard.go"}})
	anchors := index.SelectCited([]SourceRange{{Path: "handler.go", Start: 2}}, 9000)
	got := index.RelatedEvidence(anchors.Evidence, 7000)
	if len(got) != 1 || got[0].Text != guard {
		t.Fatalf("a declaration must not become independently selectable fragments: %+v", got)
	}
	if got := index.RelatedEvidence(anchors.Evidence, 500); len(got) != 0 {
		t.Fatalf("oversized declaration must be omitted in full: %+v", got)
	}
}

func TestRelatedEvidencePrioritizesSourceRelationsOverFilenameMentions(t *testing.T) {
	files := map[string]string{
		"handler.go": "package app\nfunc handler(input string) { if allowed(input) { execute(input) } }\n",
		"z_guard.go": "package app\nfunc allowed(input string) bool { return input == \"known\" }\n",
		"a.html":     "<!-- handler.go is mentioned here, but no executable attachment is shown. -->",
	}
	index := NewEvidenceIndex(files, map[string][]string{"handler.go": {"z_guard.go"}})
	anchors := index.SelectCited([]SourceRange{{Path: "handler.go", Start: 2}}, 9000)
	got := index.RelatedEvidence(anchors.Evidence, 500)
	if len(got) != 1 || got[0].Path != "z_guard.go" {
		t.Fatalf("filename-only match displaced a referenced declaration: %+v", got)
	}
}
