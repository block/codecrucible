package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/block/codecrucible/internal/chunk"
	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/llm"
	"github.com/block/codecrucible/internal/sarif"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func resolvedMetadataConfig(t *testing.T) *config.Config {
	t.Helper()
	vp := viper.New()
	config.SetDefaults(vp)
	vp.Set("provider", "openai")
	vp.Set("model", "gpt-5.5")
	vp.Set("openai-api-key", "credential-sentinel")
	cfg, err := config.Load(vp)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.ResolvePhases(cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func metadataSnapshot(t *testing.T, cfg *config.Config) *sarif.ScanMetadata {
	t.Helper()
	doc, err := prepareSARIF(sarif.Build(sarif.AnalysisResult{}, nil, sarif.BuilderConfig{}), newScanMetadata(cfg), "final")
	if err != nil {
		t.Fatal(err)
	}
	return doc.Runs[0].Properties.CodeCrucible
}

func TestMetadataResolvedPrecedence(t *testing.T) {
	vp := viper.New()
	config.SetDefaults(vp)
	config.BindEnvVars(vp)
	vp.SetConfigType("yaml")
	if err := vp.ReadConfig(strings.NewReader("provider: openai\nmodel: gpt-5.5\ncontext-limit: 10000\nphases:\n  audit:\n    provider: google\n    model: gemini-3.1-pro-preview\n    max-output-tokens: 2048\n")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONTEXT_LIMIT", "20000")
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flags.Int("context-limit", 0, "")
	if err := flags.Set("context-limit", "30000"); err != nil {
		t.Fatal(err)
	}
	if err := vp.BindPFlag("context-limit", flags.Lookup("context-limit")); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(vp)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.ResolvePhases(cfg); err != nil {
		t.Fatal(err)
	}
	m := metadataSnapshot(t, cfg)
	if m.Recipe.Phases["analysis"].ContextLimit != 30000 || m.Recipe.Phases["feature-detection"].ContextLimit != 30000 {
		t.Fatal("lost effective overrides/inheritance")
	}
	audit := m.Recipe.Phases["audit"]
	if audit.Provider != "google" || audit.Model != "gemini-3.1-pro-preview" || audit.MaxOutputTokens != 2048 {
		t.Fatalf("audit = %+v", audit)
	}
	if audit.RequestTimeoutSeconds != 600 || audit.Tokenizer == "" {
		t.Fatal("missing defaults")
	}
}

func TestEmptyScanMetadataOnStdout(t *testing.T) {
	cfg := resolvedMetadataConfig(t)
	cfg.PhaseOutputDir = t.TempDir()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = writer
	t.Cleanup(func() { os.Stdout = original; reader.Close(); writer.Close() })
	output := make(chan []byte, 1)
	go func() { data, _ := io.ReadAll(reader); output <- data }()
	err = outputEmptySARIF(cfg)
	writer.Close()
	os.Stdout = original
	if err != nil {
		t.Fatal(err)
	}
	var doc sarif.SARIFDocument
	if err := json.Unmarshal(<-output, &doc); err != nil {
		t.Fatal(err)
	}
	m := doc.Runs[0].Properties.CodeCrucible
	if m.Execution.ArtifactStage != "final" || len(doc.Runs[0].Results) != 0 {
		t.Fatal("incorrect empty output")
	}
	for _, phase := range m.Execution.Phases {
		if phase.Status != "skipped" || phase.Reason != "no source files" {
			t.Fatal(phase)
		}
	}
	data, err := os.ReadFile(filepath.Join(cfg.PhaseOutputDir, "analysis.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Runs[0].Properties.CodeCrucible.Execution.ArtifactStage != "analysis" {
		t.Fatal("missing empty analysis snapshot")
	}
}

func TestScanMetadataWithoutFindings(t *testing.T) {
	for _, failAnalysis := range []bool{false, true} {
		t.Run(map[bool]string{false: "zero-findings", true: "failed-analysis"}[failAnalysis], func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if failAnalysis {
					http.Error(w, "unsupported model", http.StatusBadRequest)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": `{"security_issues":[]}`}, "finish_reason": "stop"}}})
			}))
			defer server.Close()
			dir := createTestRepo(t)
			out := filepath.Join(t.TempDir(), "scan.sarif")
			old := v
			t.Cleanup(func() { v = old })
			v = viper.New()
			config.SetDefaults(v)
			v.Set("provider", "openai")
			v.Set("model", "gpt-5.5")
			v.Set("openai-api-key", "test-key")
			v.Set("base-url", server.URL)
			v.Set("prompts-dir", "../../prompts/default")
			v.Set("skip-feature-detection", true)
			v.Set("output", out)
			cmd := &cobra.Command{}
			cmd.SetContext(context.Background())
			err := runScan(cmd, []string{dir})
			if (err != nil) != failAnalysis {
				t.Fatalf("scan error = %v", err)
			}
			data, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			var doc sarif.SARIFDocument
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			m := doc.Runs[0].Properties.CodeCrucible
			if len(doc.Runs[0].Results) != 0 || m.Execution.Phases["audit"].Reason != "no findings" {
				t.Fatal("wrong empty result metadata")
			}
			if (m.Execution.Phases["analysis"].Status == "failed") != failAnalysis {
				t.Fatal("incorrect analysis status")
			}
			if doc.Runs[0].Tool.Driver.Version != version {
				t.Fatal("lost build version")
			}
		})
	}
}

func TestMetadataPrivacyAndRecipeFingerprint(t *testing.T) {
	cfg := resolvedMetadataConfig(t)
	pc := &cfg.Phases.Analysis
	pc.BaseURL = "https://user-sentinel:password-sentinel@example.com/v1?key=query-sentinel#fragment-sentinel"
	pc.Headers = []string{"Authorization: header-sentinel"}
	pc.ModelParams = map[string]any{
		"temperature": 0.4, "reasoning_effort": "high", "api_key": "param-key-sentinel",
		"thinking": map[string]any{"type": "enabled", "budget_tokens": 4000, "secret": "nested-sentinel"},
		"user":     "freeform-sentinel", "stop": []string{"stop-sentinel"},
	}
	cfg.CustomRequirements = "requirements-sentinel"
	cfg.ContextSources = []config.ContextSource{{Name: "notes", Type: "inline", Location: "context-sentinel"}}
	m := metadataSnapshot(t, cfg)
	data, _ := json.Marshal(m)
	if bytes.Contains(data, []byte("sentinel")) {
		t.Fatalf("sensitive text leaked: %s", data)
	}
	if got := m.Recipe.Phases["analysis"].BaseURL; got != "https://example.com/v1" {
		t.Fatal(got)
	}
	params := m.Recipe.Phases["analysis"].ModelParams
	if params["temperature"] != 0.4 || params["reasoning_effort"] != "high" {
		t.Fatal(params)
	}
	if params["user"].(map[string]any)["omitted"] != true {
		t.Fatal("missing omission marker")
	}
	cfg.Output = "/different/output.sarif"
	cfg.PhaseOutputDir = "/another/output"
	pc.APIKey = "changed-key"
	pc.Headers = []string{"Authorization: different-header"}
	pc.BaseURL = "https://new-user:new-password@example.com/v1?key=changed#changed"
	pc.ModelParams["api_key"] = "changed-param-key"
	if got := metadataSnapshot(t, cfg).RecipeFingerprint; got != m.RecipeFingerprint {
		t.Fatal("credentials or output path changed fingerprint")
	}
	pc.ModelParams["temperature"] = 0.8
	if metadataSnapshot(t, cfg).RecipeFingerprint == m.RecipeFingerprint {
		t.Fatal("parameter change did not change fingerprint")
	}
	pc.ModelParams["temperature"] = 0.4
	cfg.CustomRequirements += " different"
	if metadataSnapshot(t, cfg).RecipeFingerprint == m.RecipeFingerprint {
		t.Fatal("requirements change did not change fingerprint")
	}
}

func TestMetadataSnapshotAndFallback(t *testing.T) {
	cfg := resolvedMetadataConfig(t)
	m := newScanMetadata(cfg)
	doc := sarif.Build(sarif.AnalysisResult{}, nil, sarif.BuilderConfig{ToolVersion: "wrong-first-chunk-version"})
	analysis, err := prepareSARIF(doc, m, "analysis")
	if err != nil {
		t.Fatal(err)
	}
	before := analysis.Runs[0].Properties.CodeCrucible
	setPhaseStatus(m, "audit", "completed", "")
	recordActualPhase(m, "audit", cfg.Phases.Analysis, cfg, true)
	final, err := prepareSARIF(doc, m, "final")
	if err != nil {
		t.Fatal(err)
	}
	after := final.Runs[0].Properties.CodeCrucible
	if before.Execution.Phases["audit"].Status != "pending" || after.Execution.Phases["audit"].Status != "completed" {
		t.Fatal("mutable snapshots")
	}
	if after.Execution.Phases["audit"].Fallback != "analysis client" || after.Execution.Phases["audit"].Actual.Model != cfg.Phases.Analysis.ModelCfg.Name {
		t.Fatal("missing actual fallback")
	}
	if before.RecipeFingerprint != after.RecipeFingerprint {
		t.Fatal("outcome changed recipe fingerprint")
	}
	if final.Runs[0].Tool.Driver.Version != version || after.Recipe.ToolCommit != commit {
		t.Fatal("lost build identity")
	}
}

func TestMetadataContextFingerprintsAndPacking(t *testing.T) {
	cfg := resolvedMetadataConfig(t)
	cfg.ContextSources = []config.ContextSource{
		{Name: "failed", Type: "path", Location: filepath.Join(t.TempDir(), "missing")},
		{Name: "reference", Type: "inline", Location: strings.Repeat("reference-sentinel ", 100), Priority: 5},
	}
	loader, err := resolvePromptLoader("../../prompts/default")
	if err != nil {
		t.Fatal(err)
	}
	m := newScanMetadata(cfg)
	counter := chunk.NewTokenCounter("cl100k_base", nil)
	_, _, err = loadSupplementaryContext(context.Background(), cfg, counter, loader, 1000, m)
	if err != nil {
		t.Fatal(err)
	}
	if m.Execution.ContextSources[0].Status != "empty_or_failed" || m.Execution.ContextSources[1].Status != "loaded" {
		t.Fatal(m.Execution.ContextSources)
	}
	first := m.Recipe.ContextSources[1].ContentFingerprint
	if first == "" || m.Execution.ContextPacking["analysis"].Truncated != "reference" {
		t.Fatal("missing content digest or truncation")
	}
	data, _ := json.Marshal(m)
	if bytes.Contains(data, []byte("reference-sentinel")) {
		t.Fatal("context content leaked")
	}
	cfg.ContextSources[1].Location += " changed"
	next := newScanMetadata(cfg)
	_, _, err = loadSupplementaryContext(context.Background(), cfg, counter, loader, 1000, next)
	if err != nil {
		t.Fatal(err)
	}
	if next.Recipe.ContextSources[1].ContentFingerprint == first {
		t.Fatal("context edit did not change fingerprint")
	}
}

func TestAuditDescriptionsFollowFinalVerdicts(t *testing.T) {
	doc := sarif.Build(sarif.AnalysisResult{SecurityIssues: []sarif.SecurityIssue{
		{Issue: "Shared", FilePath: "a.go", StartLine: 1, TechnicalDetails: "REMOVE ME", Severity: 8},
		{Issue: "Shared", FilePath: "b.go", StartLine: 1, TechnicalDetails: "OLD DETAILS", Severity: 8},
	}}, nil, sarif.BuilderConfig{})
	audit := AuditResult{
		AuditedFindings: []AuditedFinding{
			{OriginalIssue: "Shared", FilePath: "a.go", StartLine: 1, Verdict: "rejected", BlockingCode: "return nil", Confidence: 1, ClaimCoverage: "complete", BlockingEvidence: &AuditBlockingEvidence{Path: "a.go", Start: 1, End: 1, Quote: "return nil", BlocksAllPaths: true, Reason: "executable_protection"}},
			{OriginalIssue: "Shared", FilePath: "b.go", StartLine: 1, Verdict: "unverified", RefinedTechnicalDetails: "FINAL DETAILS", Justification: "chain uncertain", Confidence: .1},
		},
		NewFindings: []NewFinding{{Issue: "New issue", FilePath: "c.go", StartLine: 1, TechnicalDetails: "NEW EVIDENCE", Severity: 9, Confidence: .9}},
	}
	final, err := prepareSARIF(applyFixtureAuditVerdicts(doc, audit, ingest.FileMap{"a.go": "return nil"}, .3), nil, "final")
	if err != nil {
		t.Fatal(err)
	}
	if len(final.Runs[0].Results) != 2 {
		t.Fatal("wrong final finding count")
	}
	for _, rule := range final.Runs[0].Tool.Driver.Rules {
		for _, evidence := range []string{"REMOVE ME", "FINAL DETAILS"} {
			if strings.Contains(rule.Help.Text+rule.Help.Markdown, evidence) {
				t.Fatal("stale evidence in issue help", rule.Help)
			}
		}
	}
	for _, result := range final.Runs[0].Results {
		message := result.Properties.TechnicalDetails
		if strings.Contains(result.Message.Text, "DETAILS") || strings.Contains(result.Message.Text, "EVIDENCE") {
			t.Fatal("verbose evidence in inline annotation", result.Message)
		}
		if strings.Contains(message, "REMOVE ME") || strings.Contains(message, "FINAL DETAILS") {
			t.Fatal("stale evidence", message)
		}
		switch result.Locations[0].PhysicalLocation.ArtifactLocation.URI {
		case "b.go":
			if !strings.Contains(result.Message.Text, "Unverified") {
				t.Fatal("uncertainty missing from annotation", result.Message)
			}
			for _, evidence := range []string{"OLD DETAILS"} {
				if !strings.Contains(message, evidence) {
					t.Fatal("lost audit refinement or caveat", message)
				}
			}
			if strings.Contains(message, "NEW EVIDENCE") {
				t.Fatal("new finding leaked into existing result", message)
			}
		case "c.go":
			if message != "NEW EVIDENCE\n\n[Audit confidence: 90%]" {
				t.Fatal("incorrect new finding evidence", message)
			}
		default:
			t.Fatal("unexpected surviving result", result)
		}
	}
}

func TestScanArtifactsIncludeFinalEvidenceAndMetadata(t *testing.T) {
	for _, mode := range []string{"audited", "audit-failed", "audit-timeout"} {
		t.Run(mode, func(t *testing.T) {
			failAudit := mode != "audited"
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if calls > 1 && failAudit {
					if mode == "audit-timeout" {
						select {
						case <-r.Context().Done():
						case <-time.After(2 * time.Second):
						}
						return
					}
					http.Error(w, "unsupported model", http.StatusBadRequest)
					return
				}
				content := `{"security_issues":[{"issue":"Reflected XSS","file_path":"src/main.go","start_line":1,"technical_details":"Initial evidence: <img src=x onerror=alert(1)> bypasses \\*.","severity":8,"cwe_id":"CWE-79"}]}`
				if calls > 1 {
					var request llm.ChatRequest
					if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
						t.Error(err)
						return
					}
					content = `{"audited_findings":[{"finding_id":"` + requestedClaims(t, request)[0].FindingID + `","original_issue":"Reflected XSS","file_path":"src/main.go","start_line":1,"verdict":"refined","claim_coverage":"complete","confidence":0.9,"refined_technical_details":"Final evidence: <script>alert(1)</script> bypasses \\*.","justification":"Validated chain"}]}`
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": content}, "finish_reason": "stop"}}})
			}))
			defer server.Close()
			dir := createTestRepo(t)
			out := filepath.Join(t.TempDir(), "scan.sarif")
			old := v
			t.Cleanup(func() { v = old })
			v = viper.New()
			config.SetDefaults(v)
			v.Set("provider", "openai")
			v.Set("model", "gpt-5.5")
			v.Set("openai-api-key", "credential-sentinel")
			v.Set("base-url", server.URL)
			v.Set("prompts-dir", "../../prompts/default")
			v.Set("skip-feature-detection", true)
			v.Set("output", out)
			if mode == "audit-timeout" {
				v.Set("request-timeout", 1)
			}
			// Invalid audit client triggers the existing analysis-client fallback.
			v.Set("phases.audit.provider", "unknown-provider")
			cmd := &cobra.Command{}
			cmd.SetContext(context.Background())
			err := runScan(cmd, []string{dir})
			if err != nil {
				t.Fatalf("scan error = %v, failAudit = %v", err, failAudit)
			}
			var recipeFingerprint string
			for _, stage := range []string{"analysis", "audit", "final"} {
				path := strings.TrimSuffix(out, ".sarif") + "." + stage + ".sarif"
				if stage == "final" {
					path = out
				}
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(data, []byte("credential-sentinel")) {
					t.Fatal("credential leak")
				}
				var doc sarif.SARIFDocument
				if err := json.Unmarshal(data, &doc); err != nil {
					t.Fatal(err)
				}
				m := doc.Runs[0].Properties.CodeCrucible
				if m.SchemaVersion != 1 || m.Execution.ArtifactStage != stage || m.Recipe.Prompts.Fingerprint == "" {
					t.Fatal("missing metadata")
				}
				if recipeFingerprint == "" {
					recipeFingerprint = m.RecipeFingerprint
				}
				if m.RecipeFingerprint != recipeFingerprint {
					t.Fatal("recipe changed between artifacts")
				}
				if m.Execution.Chunks.Completed != 1 {
					t.Fatal(m.Execution.Chunks)
				}
				want := `Initial evidence: <img src=x onerror=alert(1)> bypasses \*.`
				if stage != "analysis" {
					state := m.Execution.Phases["audit"]
					if state.Fallback != "analysis client" || state.Actual.Provider != "openai" {
						t.Fatal(state)
					}
					if failAudit {
						if state.Status != "incomplete" {
							t.Fatal(state)
						}
						inv := doc.Runs[0].Invocations[0]
						if !inv.ExecutionSuccessful || len(inv.ToolExecutionNotifications) != 1 || inv.ToolExecutionNotifications[0].Level != "warning" {
							t.Fatal("incomplete audit must warn without failing CI", inv)
						}
						if doc.Runs[0].Results[0].Properties.AuditStatus != "not_audited" {
							t.Fatal("unaudited finding is not marked")
						}
					} else {
						want = "Final evidence: <script>alert(1)</script> bypasses \\*.\n\n[Audit confidence: 90%] Validated chain"
						if state.Status != "completed" {
							t.Fatal(state)
						}
					}
				}
				rule := doc.Runs[0].Tool.Driver.Rules[0]
				if rule.FullDescription == nil || rule.FullDescription.Text == "" || rule.Help == nil || rule.Help.Text == "" {
					t.Fatal("incorrect description", rule)
				}
				if !strings.Contains(rule.Help.Text, "evidence:") || !strings.Contains(rule.Help.Markdown, "<details>") || strings.Contains(rule.Help.Markdown, "<script>") {
					t.Fatal("issue help missing readable summary or escaped details", rule.Help)
				}
				result := doc.Runs[0].Results[0]
				if result.Properties.TechnicalDetails != want || strings.Contains(result.Message.Text, "evidence:") {
					t.Fatalf("%s artifact lost evidence or retained a verbose annotation: %+v", stage, result)
				}
			}
		})
	}
}
