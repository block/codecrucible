package cli

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/block/codecrucible/internal/chunk"
	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/llm"
)

// In tool-use mode the schema is part of every request's input, so the
// estimate must measure the schema the scan will actually send for the prompt
// set's audit contract: v3 prompt sets use the v3 analysis and audit schemas.
// Comparing tool-use with JSON-schema mode isolates exactly the schema's share.
func TestCostPlanMeasuresTheContractSchemas(t *testing.T) {
	for _, tc := range []struct {
		dir             string
		analysis, audit *json.RawMessage
	}{
		{"../../prompts/default", llm.SecurityAnalysisSchema(), llm.AuditSchema()},
		{"../../prompts/core", llm.SecurityAnalysisSchemaV3(), llm.AuditSchemaV3()},
	} {
		t.Run(tc.dir, func(t *testing.T) {
			loader, err := resolvePromptLoader(tc.dir)
			if err != nil {
				t.Fatal(err)
			}
			counter := chunk.NewTokenCounter("", nil)
			flat := ingest.Flatten([]ingest.SourceFile{{Path: "a.go", Content: strings.Repeat("var value = 123\n", 20), LineCount: 20, Language: "go"}}, ingest.FlattenConfig{})
			flat.Tokens = counter.Count(flat.XML)
			plan := func(model string) scanCostEstimate {
				m := config.ModelConfig{Name: model, ContextLimit: 1000000, MaxOutputTokens: 1000, InputPricePerM: 1, OutputPricePerM: 1, SupportsStructuredOutput: true}
				cfg := &config.Config{Phases: config.Phases{Analysis: config.PhaseConfig{ModelCfg: m}, Audit: config.PhaseConfig{ModelCfg: m}}}
				e, err := planScanCost(flat, cfg, loader, "repo", counter, nil)
				if err != nil {
					t.Fatal(err)
				}
				if e.plan.Chunks != 1 || e.plan.AuditBatches != 1 {
					t.Fatalf("scenario changed: chunks=%d batches=%d", e.plan.Chunks, e.plan.AuditBatches)
				}
				return e
			}
			tool, jsonMode := plan("claude-test"), plan("gpt-test")
			if got, want := (tool.AnalysisInput-jsonMode.AnalysisInput)*1e6, float64(counter.Count(string(*tc.analysis))); math.Abs(got-want) > 0.5 {
				t.Errorf("analysis schema tokens priced = %.0f, want %.0f", got, want)
			}
			if got, want := (tool.AuditInput-jsonMode.AuditInput)*1e6, float64(counter.Count(string(*tc.audit))); math.Abs(got-want) > 0.5 {
				t.Errorf("audit schema tokens priced = %.0f, want %.0f", got, want)
			}
		})
	}
}
