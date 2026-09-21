package cli

import (
	"math"

	"github.com/block/codecrucible/internal/config"
)

// estimatePlanningCost is an illustrative input+output scenario, not a quota
// reservation or worst-case bound. Keep it separate from the existing input
// preflight check and usage-based runtime cost accounting. Audit is modeled as
// one additional repository-sized pass; actual batches depend on findings.
func estimatePlanningCost(sourceTokens int, cfg *config.Config) float64 {
	input := int(math.Ceil(float64(sourceTokens) * 1.25))
	output := int(math.Ceil(float64(input) / 16))
	cost := cfg.Phases.Analysis.ModelCfg.EstimateCost(input, output)
	if !cfg.SkipAudit {
		cost += cfg.Phases.Audit.ModelCfg.EstimateCost(input, output)
	}
	return cost
}
