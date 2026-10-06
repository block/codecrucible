package llm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func commonPrefix(a, b string) string {
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}
	return a[:n]
}

// Provider prefix caches only serve the leading bytes shared between calls,
// so per-call content must come after everything that is constant per scan.
func TestAssembleMessages_ChunksShareStaticPrefix(t *testing.T) {
	loader := NewPromptLoader(os.DirFS("../../prompts/default"))
	chunk := func(i int, manifest, xml string) string {
		msgs, err := loader.AssembleMessages(PromptParams{
			RepoName: "repo", XML: xml, Schema: `{"type":"object"}`, Manifest: []string{manifest},
			ChunkIndex: i, ChunkTotal: 2, CustomRequirements: "custom-requirement", SupplementaryContext: "supplementary-spec",
		})
		if err != nil {
			t.Fatal(err)
		}
		return msgs[0].Content + msgs[1].Content
	}
	prefix := commonPrefix(chunk(0, "b.go", "<file>a</file>"), chunk(1, "a.go", "<file>b</file>"))
	for _, static := range []string{"### ", "custom-requirement", "supplementary-spec"} {
		if !strings.Contains(prefix, static) {
			t.Errorf("static content %q is outside the shared prefix", static)
		}
	}
	if strings.Contains(prefix, "chunk 1 of 2") {
		t.Error("per-chunk note is inside the shared prefix")
	}
}

func TestAssembleAuditMessages_BatchesShareStaticPrefix(t *testing.T) {
	sets, err := filepath.Glob("../../prompts/*/audit.yaml")
	if err != nil || len(sets) == 0 {
		t.Fatalf("no prompt sets: %v", err)
	}
	for _, path := range sets {
		dir := filepath.Dir(path)
		t.Run(filepath.Base(dir), func(t *testing.T) {
			loader := NewPromptLoader(os.DirFS(dir))
			batch := func(claims, code, cweID string) string {
				msgs, err := loader.AssembleAuditMessages(AuditParams{
					RepoName: "repo", FindingsJSON: claims, CodeContext: code, CWEIDs: []string{cweID},
					Schema: `{"schema-marker":true}`, ProductionOnly: true, SupplementaryContext: "supplementary-spec",
				})
				if err != nil {
					t.Fatal(err)
				}
				return msgs[0].Content + msgs[1].Content
			}
			first := batch(`{"claims_to_verify":[{"finding_id":"a"}]}`, `<file path="a.go">a</file>`, "CWE-89")
			second := batch(`{"claims_to_verify":[{"finding_id":"b"}]}`, `<file path="b.go">b</file>`, "CWE-78")
			prefix := commonPrefix(first, second)
			// Exposure is classified for every claim and never gates validity.
			if !strings.Contains(prefix, "DEPLOYMENT EXPOSURE") || strings.Contains(first, "production_reachability") || strings.Contains(first, "GATE 0") {
				t.Error("prompt still gates validity on production reachability")
			}
			for _, static := range []string{"schema-marker", "supplementary-spec"} {
				if !strings.Contains(prefix, static) {
					t.Errorf("static content %q is outside the shared prefix", static)
				}
			}
			// The batch data closes the prompt, followed by a recency reminder.
			schema := strings.LastIndex(prefix, "schema-marker")
			claims, code := strings.Index(first, `"finding_id":"a"`), strings.Index(first, `<file path="a.go">`)
			if claims < schema || code < claims || !strings.Contains(first[code:], "END OF BATCH DATA") {
				t.Errorf("batch data out of order: schema=%d claims=%d code=%d", schema, claims, code)
			}
		})
	}
}
