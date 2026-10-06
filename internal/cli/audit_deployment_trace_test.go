package cli

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/decision"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/llm"
	"github.com/block/codecrucible/internal/sarif"
	"github.com/block/codecrucible/internal/tokenestimate"
)

func TestDeploymentTracesReachAuditor(t *testing.T) {
	walked := []ingest.SourceFile{
		{Path: "main.go", Content: "package main\n\nfunc main() {\n\thttp.HandleFunc(\"/debug\", debug)\n}\n"},
		{Path: "debug.go", Content: "package main\n\nfunc debug(w http.ResponseWriter, r *http.Request) {\n\tif os.Getenv(\"ENABLE_DEBUG\") == \"1\" {\n\t\trun(r.FormValue(\"cmd\"))\n\t}\n}\n"},
		{Path: ".github/workflows/deploy.yml", Content: "env:\n  ENABLE_DEBUG: \"1\"\n"},
	}
	filtered := walked[:2]
	files := ingest.FlattenFileMapOnly(filtered).FileMap
	doc := sarif.WithFindingIDs(sarif.Build(sarif.AnalysisResult{SecurityIssues: []sarif.SecurityIssue{{Issue: "Command injection", FilePath: "debug.go", StartLine: 5, Severity: 9}}}, sarif.FileMap(files), sarif.BuilderConfig{}))
	cfg := &config.Config{AuditDeploymentTrace: true}
	traces := auditDeploymentTraces(cfg, doc, walked, filtered, files, nil)
	if len(traces) != 1 {
		t.Fatalf("traces = %v", traces)
	}
	client := auditClientFunc(func(_ context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
		var prompt string
		for _, m := range req.Messages {
			prompt += m.Content
		}
		trace := prompt[strings.Index(prompt, "<deployment_trace finding_id"):]
		for _, want := range []string{`entry_point_found="true"`, `config_keys="ENABLE_DEBUG"`, "registration main.go:", "config_setting .github/workflows/deploy.yml:2-2", `ENABLE_DEBUG: "1"`, "deployment_trace_notes"} {
			if !strings.Contains(prompt, want) {
				t.Errorf("audit prompt lacks %q", want)
			}
		}
		// debug.go is supplied in full, so its steps cite location only.
		if strings.Contains(trace, `if os.Getenv("ENABLE_DEBUG")`) {
			t.Error("trace repeats a file supplied in full")
		}
		return verdictResponse(requestedClaims(t, req)...), nil
	})
	if _, _, _, err := runAuditPhase(context.Background(), doc, "fixture", client, "", config.ModelConfig{Name: "test"}, llm.NewPromptLoader(os.DirFS("../../prompts/default")), llm.OutputModeNone, files, .3, nil, "", 1, 1, true, tokenestimate.New(tokenestimate.Model{}, nil), nil, traces); err != nil {
		t.Fatal(err)
	}
	if auditDeploymentTraces(&config.Config{}, doc, walked, filtered, files, nil) != nil {
		t.Fatal("traces built while disabled")
	}
}

func TestRenderDeploymentTracesDedupesAndBudgets(t *testing.T) {
	step := func(id, text string) decision.TraceStep {
		return decision.TraceStep{Kind: "caller", Evidence: decision.Evidence{ID: id, Path: "x.go", Start: 1, End: 1, Text: text}}
	}
	big := strings.Repeat("x", traceBatchBudget/2)
	traces := map[string]decision.DeploymentTrace{
		"a": {Steps: []decision.TraceStep{step("shared", "shared-text"), step("a1", big)}},
		"b": {Steps: []decision.TraceStep{step("shared", "shared-text")}},
		"c": {Steps: []decision.TraceStep{step("c1", big)}},
	}
	out := renderDeploymentTraces([]string{"a", "b", "c"}, traces, map[string]bool{}, map[string]bool{})
	if strings.Count(out, "shared-text") != 1 || strings.Count(out, "caller x.go:1-1") != 3 {
		t.Fatalf("shared evidence not deduplicated:\n%s", out[:200])
	}
	if !strings.Contains(out, `finding_id="c" omitted="batch_trace_budget"`) || len(out) > traceBatchBudget+len(deploymentTraceNote)+200 {
		t.Fatalf("batch budget not applied: %d bytes", len(out))
	}
}
