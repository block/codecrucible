package decision

import "testing"

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
