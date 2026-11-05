package cli

import (
	"bytes"
	"fmt"
	"github.com/block/codecrucible/internal/chunk"
	"github.com/block/codecrucible/internal/ingest"
	"math"
	"path/filepath"
	"strings"
	"testing"

	"github.com/block/codecrucible/internal/config"
)

func TestPlanningCost(t *testing.T) {
	cfg := &config.Config{Phases: config.Phases{
		Analysis: config.PhaseConfig{ModelCfg: config.ModelConfig{InputPricePerM: 2, OutputPricePerM: 8}},
		Audit:    config.PhaseConfig{ModelCfg: config.ModelConfig{InputPricePerM: 2, OutputPricePerM: 8}},
	}}
	for _, tc := range []struct {
		tokens int
		skip   bool
		want   float64
	}{
		{320583, false, 2.003652},
		{320583, true, 1.001826},
		{0, false, 0},
	} {
		cfg.SkipAudit = tc.skip
		if got := estimateScanCost(tc.tokens, cfg).Planning; math.Abs(got-tc.want) > 1e-9 {
			t.Errorf("tokens=%d skip=%v: got %v want %v", tc.tokens, tc.skip, got, tc.want)
		}
	}
	cfg.SkipAudit = false
	cfg.Phases.Audit.ModelCfg = config.ModelConfig{InputPricePerM: 1, OutputPricePerM: 4}
	if got := estimateScanCost(320000, cfg).Planning; got != 1.5 {
		t.Fatalf("per-phase pricing ignored: %v", got)
	}
}

func TestScanCostEstimateMixedProvidersAndBudget(t *testing.T) {
	cfg := &config.Config{Phases: config.Phases{
		Analysis: config.PhaseConfig{Provider: "anthropic", ModelCfg: config.ModelConfig{Name: "analysis", InputPricePerM: 2, OutputPricePerM: 8}},
		Audit:    config.PhaseConfig{Provider: "google", ModelCfg: config.ModelConfig{Name: "audit", InputPricePerM: 1, OutputPricePerM: 4}},
	}}
	estimate := estimateScanCost(320000, cfg)
	if estimate.AnalysisInput != 0.64 || estimate.AuditInput != 0.32 || estimate.TotalInput != 0.96 || estimate.Planning != 1.5 || estimate.AllowanceLow != 3 || estimate.AllowanceHigh != 4.5 {
		t.Fatalf("unexpected estimate: %+v", estimate)
	}
	if estimate.checkBudget(0.95) == nil {
		t.Fatal("budget should reject input estimate")
	}
	for _, budget := range []float64{0, 0.96, 1} {
		if err := estimate.checkBudget(budget); err != nil {
			t.Fatal(err)
		}
	}
	var summary bytes.Buffer
	estimate.writeSummary(&summary)
	for _, text := range []string{"$0.6400", "$0.3200 (model: audit)", "$0.9600", "$1.5000", "$3.00–$4.50"} {
		if !strings.Contains(summary.String(), text) {
			t.Errorf("missing %s", text)
		}
	}
	cfg.SkipAudit = true
	estimate = estimateScanCost(320000, cfg)
	summary.Reset()
	estimate.writeSummary(&summary)
	if estimate.TotalInput != 0.64 || estimate.AuditInput != 0 || strings.Contains(summary.String(), "Estimated audit input") {
		t.Fatal("disabled audit included")
	}
	cfg.SkipAudit = false
	cfg.AuditFrom = "analysis.sarif"
	estimate = estimateScanCost(320000, cfg)
	if estimate.AnalysisInput != 0 || estimate.AuditInput != 0.32 || estimate.TotalInput != 0.32 || estimate.Planning != 0.5 {
		t.Fatalf("audit replay estimate includes analysis: %+v", estimate)
	}
}

func TestCostPlanUsesPromptBudgetAndAuditBatches(t *testing.T) {
	loader, err := resolvePromptLoader("../../prompts/default")
	if err != nil {
		t.Fatal(err)
	}
	counter := chunk.NewTokenCounter("", nil)
	files := []ingest.SourceFile{}
	for i := 0; i < 4; i++ {
		files = append(files, ingest.SourceFile{Path: fmt.Sprintf("src/f%d.go", i), Content: strings.Repeat("var value = 123\n", 80), LineCount: 80, Language: "go"})
	}
	flat := ingest.Flatten(files, ingest.FlattenConfig{})
	flat.Tokens = counter.Count(flat.XML)
	cfg := &config.Config{AuditBatchSize: 2, Phases: config.Phases{
		Analysis: config.PhaseConfig{ModelCfg: config.ModelConfig{Name: "analysis", ContextLimit: 30000, MaxOutputTokens: 1000, InputPricePerM: 2, OutputPricePerM: 8}},
		Audit:    config.PhaseConfig{ModelCfg: config.ModelConfig{Name: "audit", ContextLimit: 40000, MaxOutputTokens: 1000, InputPricePerM: 1, OutputPricePerM: 4}},
	}}
	first, err := planScanCost(flat, cfg, loader, "repo", counter, nil)
	if err != nil {
		t.Fatal(err)
	}
	parts, err := chunk.NewChunker(counter, nil).Chunk(flat, first.plan.SourceBudget, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.plan.Chunks != len(parts) || first.plan.SourceBudget >= 24000-1000 || first.plan.AuditBatches != 2 {
		t.Fatalf("incorrect plan: %+v", first.plan)
	}
	cfg.CustomRequirements = strings.Repeat("Check all boundaries carefully. ", 500)
	larger, err := planScanCost(flat, cfg, loader, "repo", counter, nil)
	if err != nil {
		t.Fatal(err)
	}
	if larger.plan.SourceBudget >= first.plan.SourceBudget || larger.AnalysisInput <= first.AnalysisInput {
		t.Fatalf("prompt growth ignored: %+v -> %+v", first, larger)
	}
	cfg.AuditBatchSize = 1
	repeated, err := planScanCost(flat, cfg, loader, "repo", counter, nil)
	if err != nil {
		t.Fatal(err)
	}
	if repeated.plan.AuditBatches != 4 || math.Abs(repeated.AuditInput-2*larger.AuditInput) > 1e-9 {
		t.Fatal("audit batches not priced separately")
	}
	cfg.SkipAudit = true
	disabled, err := planScanCost(flat, cfg, loader, "repo", counter, nil)
	if err != nil {
		t.Fatal(err)
	}
	if disabled.AuditInput != 0 || disabled.plan.AuditBatches != 0 || disabled.Planning >= repeated.Planning {
		t.Fatal("disabled audit still priced")
	}
	// Audit work must change the same gate used before client construction.
	threshold := (disabled.Planning + repeated.Planning) / 2
	if disabled.checkBudget(threshold) != nil || repeated.checkBudget(threshold) == nil {
		t.Fatal("audit excluded from budget decision")
	}
	cfg.SkipAudit = false
	cfg.Phases.Audit.ModelCfg.ContextLimit = 3000
	capped, err := planScanCost(flat, cfg, loader, "repo", counter, nil)
	if err != nil {
		t.Fatal(err)
	}
	if capped.AuditInput > float64(capped.plan.AuditBatches)*0.002 {
		t.Fatal("audit estimate exceeds input capacity")
	}
	cfg.Phases.Audit.ModelCfg.InputPricePerM = 0
	unknown, err := planScanCost(flat, cfg, loader, "repo", counter, nil)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	unknown.writeSummary(&output)
	if unknown.checkBudget(100) == nil || !strings.Contains(output.String(), "not free") {
		t.Fatal("unpriced audit treated as free")
	}
}

func TestScanPreflightRejectsBeforeProviderCall(t *testing.T) {
	dir := createTestRepo(t)
	prompts, err := filepath.Abs("../../prompts/default")
	if err != nil {
		t.Fatal(err)
	}
	cmd := NewRootCommand()
	cmd.SetArgs([]string{"scan", dir, "--prompts-dir", prompts, "--model", "gpt-5.5", "--max-cost", "0.01"})
	err = cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "exceeds --max-cost") {
		t.Fatalf("expected preflight rejection before credentials/network: %v", err)
	}
}
