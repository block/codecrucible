package cli

import (
	"bytes"
	"fmt"
	"github.com/block/codecrucible/internal/chunk"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"log/slog"
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
	if repeated.plan.AuditBatches != 4 || repeated.AuditInput <= larger.AuditInput || repeated.AuditInput >= 2*larger.AuditInput {
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
	threshold := (disabled.TotalInput + repeated.TotalInput) / 2
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

func TestUnpricedBudgetDefaultWarnsButExplicitLimitRejects(t *testing.T) {
	e := scanCostEstimate{plan: &scanCostPlan{Unpriced: []string{"analysis (unregistered)"}}}
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	if err := e.checkConfiguredBudget(25, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "default $25 cap is not being enforced") {
		t.Fatal(logs.String())
	}
	if err := e.checkConfiguredBudget(25, true); err == nil || !strings.Contains(err.Error(), "--max-cost 0") {
		t.Fatalf("explicit limit must reject with remedy: %v", err)
	}
	if err := e.checkConfiguredBudget(0, true); err != nil {
		t.Fatal(err)
	}
	settings := viper.New()
	config.SetDefaults(settings)
	cmd := &cobra.Command{}
	cmd.Flags().Float64("max-cost", 25, "")
	if explicitMaxCost(cmd, settings, 25) {
		t.Fatal("default treated as explicit")
	}
	if err := settings.ReadConfig(strings.NewReader("max-cost: 25\n")); err == nil {
		t.Fatal("config type should be required")
	}
	settings.SetConfigType("yaml")
	if err := settings.ReadConfig(strings.NewReader("max-cost: 25\n")); err != nil {
		t.Fatal(err)
	}
	if !explicitMaxCost(cmd, settings, 25) {
		t.Fatal("explicit config default-value limit ignored")
	}
	settings = viper.New()
	t.Setenv("MAX_COST", "25")
	if !explicitMaxCost(cmd, settings, 25) {
		t.Fatal("environment limit ignored")
	}
	t.Setenv("MAX_COST", "")
	if err := cmd.Flags().Set("max-cost", "25"); err != nil {
		t.Fatal(err)
	}
	if !explicitMaxCost(cmd, settings, 25) {
		t.Fatal("explicit flag default-value limit ignored")
	}
}

func TestCostPlanMediumRepoDoesNotRepeatAllSourcePerBatch(t *testing.T) {
	loader, err := resolvePromptLoader("../../prompts/default")
	if err != nil {
		t.Fatal(err)
	}
	counter := chunk.NewTokenCounter("", nil)
	var files []ingest.SourceFile
	for i := 0; i < 1200; i++ {
		files = append(files, ingest.SourceFile{Path: fmt.Sprintf("src/f%04d.go", i), Content: strings.Repeat("var value = 123\n", 420), LineCount: 420, Language: "go"})
	}
	flat := ingest.Flatten(files, ingest.FlattenConfig{})
	flat.Tokens = counter.Count(flat.XML)
	model := config.ModelConfig{Name: "priced", ContextLimit: 200000, MaxOutputTokens: 16000, InputPricePerM: 2, OutputPricePerM: 10}
	cfg := &config.Config{AuditBatchSize: 25, Phases: config.Phases{Analysis: config.PhaseConfig{ModelCfg: model}, Audit: config.PhaseConfig{ModelCfg: model}}}
	if err := estimateScanCost(flat.Tokens, cfg).checkBudget(config.DefaultMaxCost); err != nil {
		t.Fatalf("fixture must pass base input gate: %v", err)
	}
	e, err := planScanCost(flat, cfg, loader, "synthetic", counter, nil)
	if err != nil {
		t.Fatal(err)
	}
	if e.plan.AuditBatches != 48 || e.checkBudget(config.DefaultMaxCost) != nil {
		t.Fatalf("medium repo incorrectly blocked (%d tokens): %+v", flat.Tokens, e)
	}
	// Includes one source pass plus per-batch prompt/retrieval, far below
	// charging the model's full input capacity 48 times.
	if e.AuditInput >= 14 {
		t.Fatalf("source charged repeatedly: %f", e.AuditInput)
	}
	t.Logf("tokens=%d input=$%.4f scenario output bound=$%.4f", flat.Tokens, e.TotalInput, e.Planning)
}

func TestInputGateAndMixedPricing(t *testing.T) {
	e := scanCostEstimate{TotalInput: 20, Planning: 40, plan: &scanCostPlan{}}
	if err := e.checkBudget(25); err != nil {
		t.Fatalf("output silently tightened gate: %v", err)
	}
	e.TotalInput = 26
	if err := e.checkBudget(25); err == nil || !strings.Contains(err.Error(), "input + maximum output") {
		t.Fatalf("missing input-gate diagnostic: %v", err)
	}
}

func TestMixedPricingKeepsPricedGate(t *testing.T) {
	e := scanCostEstimate{TotalInput: 26, Planning: 40, plan: &scanCostPlan{}}
	e.plan.Unpriced = []string{"audit (unpriced)"}
	if err := e.checkConfiguredBudget(25, false); err == nil {
		t.Fatal("unpriced audit disabled priced analysis gate")
	}
	e.TotalInput = 20
	if err := e.checkConfiguredBudget(25, false); err != nil {
		t.Fatal(err)
	}
	if err := e.checkConfiguredBudget(25, true); err == nil {
		t.Fatal("explicit gate accepted incomplete estimate")
	}
	var summary bytes.Buffer
	e.writeSummary(&summary)
	if !strings.Contains(summary.String(), "Input + maximum output upper bound (scenario)") {
		t.Fatal(summary.String())
	}
}
