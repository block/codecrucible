package cli

import (
	"math"
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
		if got := estimatePlanningCost(tc.tokens, cfg); math.Abs(got-tc.want) > 1e-9 {
			t.Errorf("tokens=%d skip=%v: got %v want %v", tc.tokens, tc.skip, got, tc.want)
		}
	}
	cfg.SkipAudit = false
	cfg.Phases.Audit.ModelCfg = config.ModelConfig{InputPricePerM: 1, OutputPricePerM: 4}
	if got := estimatePlanningCost(320000, cfg); got != 1.5 {
		t.Fatalf("per-phase pricing ignored: %v", got)
	}
}
