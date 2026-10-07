package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/sarif"
)

const replaySource = "package app\n\nfunc Query(db DB, id string) {\n\tdb.Exec(\"SELECT * FROM t WHERE id = \" + id)\n}\n\nfunc Run(cmd string) {\n\texec.Command(\"sh\", \"-c\", cmd).Run()\n}\n"

type replayServer struct {
	analysisCalls int
	auditPrompts  []string
}

func (s *replayServer) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
		if i := strings.LastIndex(prompt, `{"claims_to_verify":`); i >= 0 {
			s.auditPrompts = append(s.auditPrompts, prompt)
			var envelope struct {
				Claims []struct {
					ID    string `json:"finding_id"`
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
				verdicts = append(verdicts, AuditedFinding{FindingID: c.ID, OriginalIssue: c.Issue, FilePath: c.Path, StartLine: c.Line, Verdict: "confirmed", Confidence: .9, ClaimCoverage: "complete"})
			}
			content, _ = json.Marshal(AuditResult{AuditedFindings: verdicts})
		} else {
			s.analysisCalls++
			content, _ = json.Marshal(sarif.AnalysisResult{SecurityIssues: []sarif.SecurityIssue{
				{Issue: "SQL injection", FilePath: "app.go", StartLine: 4, EndLine: 4, Severity: 8, CWEID: "CWE-89", TechnicalDetails: "id is concatenated into the query.", Summary: "SQL injection in Query."},
				{Issue: "Command injection", FilePath: "app.go", StartLine: 8, EndLine: 8, Severity: 9, CWEID: "CWE-78", TechnicalDetails: "cmd reaches sh -c.", Summary: "Shell injection in Run."},
			}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"model": "replay-test", "choices": []any{map[string]any{"message": map[string]any{"content": string(content)}, "finish_reason": "stop"}}, "usage": map[string]int{"prompt_tokens": 100, "completion_tokens": 50}})
	}
}

func runReplayScan(t *testing.T, repo, url string, extra ...string) (string, error) {
	t.Helper()
	oldV := v
	t.Cleanup(func() { v = oldV })
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	cfg := fmt.Sprintf("provider: openai\nmodel: replay-test\nopenai-api-key: test\nbase-url: %s\ncontext-limit: 100000\nmax-output-tokens: 4096\n", url)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	prompts, err := filepath.Abs("../../prompts/default")
	if err != nil {
		t.Fatal(err)
	}
	artifacts := t.TempDir()
	cmd := NewRootCommand()
	cmd.SetArgs(append([]string{"--config", cfgPath, "scan", repo, "--prompts-dir", prompts, "--skip-feature-detection",
		"--output", filepath.Join(artifacts, "final.sarif"), "--phase-output-dir", artifacts, "--max-cost", "0"}, extra...))
	return artifacts, cmd.Execute()
}

func readSARIF(t *testing.T, path string) sarif.SARIFDocument {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc sarif.SARIFDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestAuditReplayReusesAnalysisClaims(t *testing.T) {
	server := &replayServer{}
	srv := httptest.NewServer(server.handler(t))
	defer srv.Close()
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "app.go"), []byte(replaySource), 0600); err != nil {
		t.Fatal(err)
	}

	first, err := runReplayScan(t, repo, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if server.analysisCalls != 1 || len(server.auditPrompts) != 1 {
		t.Fatalf("baseline calls analysis=%d audit=%d", server.analysisCalls, len(server.auditPrompts))
	}
	baseline := readSARIF(t, filepath.Join(first, "final.sarif"))

	second, err := runReplayScan(t, repo, srv.URL, "--audit-from", filepath.Join(first, "analysis.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	if server.analysisCalls != 1 || len(server.auditPrompts) != 2 {
		t.Fatalf("replay made analysis calls: analysis=%d audit=%d", server.analysisCalls, len(server.auditPrompts))
	}
	if server.auditPrompts[0] != server.auditPrompts[1] {
		t.Fatalf("replayed audit input differs from the original:\n%s\n---\n%s", server.auditPrompts[0], server.auditPrompts[1])
	}
	if _, err := os.Stat(filepath.Join(second, "analysis.sarif")); !os.IsNotExist(err) {
		t.Fatal("replay rewrote the analysis artifact")
	}
	replayed := readSARIF(t, filepath.Join(second, "final.sarif"))
	if len(replayed.Runs[0].Results) != len(baseline.Runs[0].Results) {
		t.Fatalf("finding count %d, want %d", len(replayed.Runs[0].Results), len(baseline.Runs[0].Results))
	}
	for i, r := range replayed.Runs[0].Results {
		want := baseline.Runs[0].Results[i].Properties
		if r.Properties.FindingID != want.FindingID || r.Properties.AuditStatus != "confirmed" || r.Properties.TechnicalDetails != want.TechnicalDetails {
			t.Fatalf("replayed finding %d = %+v, want %+v", i, r.Properties, want)
		}
	}
	meta := replayed.Runs[0].Properties.CodeCrucible
	if meta.Recipe.AuditReplay == nil || meta.Recipe.AuditReplay.SHA256 == "" || meta.Recipe.AuditReplay.Findings != 2 || meta.Recipe.AuditReplay.ArtifactStage != "analysis" {
		t.Fatalf("missing replay identity: %+v", meta.Recipe.AuditReplay)
	}
	if meta.Execution.Phases["analysis"].Status != "skipped" || meta.Execution.Phases["audit"].Status != "completed" {
		t.Fatalf("phase states: %+v", meta.Execution.Phases)
	}

	// Audited output cannot be replayed: it would audit the auditor.
	for _, stage := range []string{"audit.sarif", "final.sarif"} {
		if _, err := runReplayScan(t, repo, srv.URL, "--audit-from", filepath.Join(first, stage)); err == nil || !strings.Contains(err.Error(), "pre-audit") {
			t.Fatalf("%s accepted for replay: %v", stage, err)
		}
	}
	if _, err := runReplayScan(t, repo, srv.URL, "--audit-from", filepath.Join(first, "analysis.sarif"), "--skip-audit"); err == nil {
		t.Fatal("--skip-audit accepted with --audit-from")
	}
}

func TestAuditReplayAcceptsSkipAuditOutputAndReportsDrift(t *testing.T) {
	server := &replayServer{}
	srv := httptest.NewServer(server.handler(t))
	defer srv.Close()
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "app.go"), []byte(replaySource), 0600); err != nil {
		t.Fatal(err)
	}
	first, err := runReplayScan(t, repo, srv.URL, "--skip-audit")
	if err != nil {
		t.Fatal(err)
	}
	files := ingest.FileMap{"app.go": replaySource}
	doc, source, err := loadAuditReplay(filepath.Join(first, "final.sarif"), files)
	if err != nil {
		t.Fatal(err)
	}
	if source.ArtifactStage != "final" || source.MissingFiles != 0 || source.ChangedSnippets != 0 {
		t.Fatalf("unexpected source: %+v", source)
	}
	if got := doc.Runs[0].Results[0].Message.Text; got != "id is concatenated into the query." {
		t.Fatalf("analysis evidence not restored to the audit input: %q", got)
	}
	if doc.Runs[0].Results[0].Properties.TechnicalDetails != "" || doc.Runs[0].Properties != nil {
		t.Fatal("presentation fields leaked into the replay input")
	}

	changed := ingest.FileMap{"app.go": strings.Replace(replaySource, "exec.Command", "safeCommand", 1)}
	if _, source, err = loadAuditReplay(filepath.Join(first, "final.sarif"), changed); err != nil || source.ChangedSnippets != 1 || source.MissingFiles != 0 {
		t.Fatalf("snippet drift not reported: %+v %v", source, err)
	}
	// A replay against the wrong root would audit every claim without source.
	if _, _, err = loadAuditReplay(filepath.Join(first, "final.sarif"), ingest.FileMap{}); err == nil || !strings.Contains(err.Error(), "none of the 2 findings") {
		t.Fatalf("replay without any source accepted: %v", err)
	}
}
