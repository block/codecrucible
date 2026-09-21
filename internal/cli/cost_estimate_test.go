package cli

import (
	"bytes"
	"math"
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
}
