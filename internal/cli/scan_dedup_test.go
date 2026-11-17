package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/block/codecrucible/internal/auditcore"
	"github.com/block/codecrucible/internal/sarif"
)

const sameLineSinksSource = "package app\nfunc run(req Request) {\n first := req.First\n second := req.Second\n exec.Command(\"sh\", \"-c\", first).Run(); exec.Command(\"sh\", \"-c\", second).Run()\n}\n"

// A full scan must not merge two independently fixable findings that share a
// file, line and CWE but cite distinct structured source/sink evidence.
func TestScanKeepsSameLineFindingsWithDistinctEvidence(t *testing.T) {
	sink := auditcore.Evidence{File: "handler.go", Start: 5, End: 5}
	issues := []sarif.SecurityIssue{
		{Issue: "First command injection", FilePath: "handler.go", StartLine: 5, EndLine: 5, CWEID: "CWE-78", Severity: 9,
			TechnicalDetails: "req.First reaches the first shell invocation.",
			FindingEvidence: []auditcore.NamedEvidence{
				{Kind: "source", Evidence: auditcore.Evidence{File: "handler.go", Start: 3, End: 3, Quote: "first := req.First"}},
				{Kind: "sink", Evidence: sink},
			}},
		{Issue: "Second command injection", FilePath: "handler.go", StartLine: 5, EndLine: 5, CWEID: "CWE-78", Severity: 9,
			TechnicalDetails: "req.Second reaches the second shell invocation.",
			FindingEvidence: []auditcore.NamedEvidence{
				{Kind: "source", Evidence: auditcore.Evidence{File: "handler.go", Start: 4, End: 4, Quote: "second := req.Second"}},
				{Kind: "sink", Evidence: sink},
			}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		prompt := ""
		for _, m := range req.Messages {
			prompt += m.Content + "\n"
		}
		var content []byte
		if i := strings.Index(prompt, `{"claims_to_verify":[`); i >= 0 {
			var envelope struct {
				Claims []struct {
					Issue string `json:"issue"`
					Path  string `json:"file_path"`
					Line  int    `json:"start_line"`
				} `json:"claims_to_verify"`
			}
			if err := json.NewDecoder(strings.NewReader(prompt[i:])).Decode(&envelope); err != nil {
				t.Error(err)
			}
			var verdicts []AuditedFinding
			for _, c := range envelope.Claims {
				verdicts = append(verdicts, AuditedFinding{OriginalIssue: c.Issue, FilePath: c.Path, StartLine: c.Line, Verdict: "confirmed", Confidence: .9})
			}
			content, _ = json.Marshal(AuditResult{AuditedFindings: verdicts})
		} else {
			content, _ = json.Marshal(sarif.AnalysisResult{SecurityIssues: issues})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"model": "replay-test", "choices": []any{map[string]any{"message": map[string]any{"content": string(content)}, "finish_reason": "stop"}}, "usage": map[string]int{"prompt_tokens": 100, "completion_tokens": 50}})
	}))
	defer srv.Close()
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "handler.go"), []byte(sameLineSinksSource), 0600); err != nil {
		t.Fatal(err)
	}
	artifacts, err := runReplayScan(t, repo, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"analysis.sarif", "final.sarif"} {
		if n := len(readSARIF(t, filepath.Join(artifacts, name)).Runs[0].Results); n != 2 {
			t.Fatalf("%s: got %d results, want 2 distinct same-line findings", name, n)
		}
	}
}
