package cli

import (
	"fmt"
	"io"
	"math"

	"github.com/block/codecrucible/internal/config"
)

// scanCostEstimate contains provider-independent preflight estimates. Pricing
// and long-context tiers remain owned by config.ModelConfig, which is also used
// to price reported usage during execution.
type scanCostEstimate struct {
	AnalysisInput float64
	AuditInput    float64
	TotalInput    float64
	Planning      float64
	AllowanceLow  float64
	AllowanceHigh float64
	auditEnabled  bool
	auditModel    string
}

func estimateScanCost(sourceTokens int, cfg *config.Config) scanCostEstimate {
	analysis := cfg.Phases.Analysis.ModelCfg
	audit := cfg.Phases.Audit.ModelCfg
	estimate := scanCostEstimate{
		AnalysisInput: analysis.EstimateInputCost(sourceTokens),
		auditEnabled:  !cfg.SkipAudit,
		auditModel:    audit.Name,
	}
	// Illustrative input+output scenario, not a quota reservation or worst-case
	// bound. Audit is one repository-sized pass; actual batches depend on findings.
	input := int(math.Ceil(float64(sourceTokens) * 1.25))
	output := int(math.Ceil(float64(input) / 16))
	estimate.Planning = analysis.EstimateCost(input, output)
	if estimate.auditEnabled {
		estimate.AuditInput = audit.EstimateInputCost(sourceTokens)
		estimate.Planning += audit.EstimateCost(input, output)
	}
	estimate.TotalInput = estimate.AnalysisInput + estimate.AuditInput
	estimate.AllowanceLow = estimate.Planning * 2
	estimate.AllowanceHigh = estimate.Planning * 3
	return estimate
}

// checkBudget retains the existing source-input preflight gate. The planning
// allowance is informational; it is neither reserved spend nor a billed ceiling.
func (e scanCostEstimate) checkBudget(maxCost float64) error {
	if maxCost > 0 && e.TotalInput > maxCost {
		return fmt.Errorf("estimated cost $%.4f exceeds --max-cost $%.2f; aborting (use --dry-run to preview)", e.TotalInput, maxCost)
	}
	return nil
}

func (e scanCostEstimate) logAttrs() []any {
	return []any{
		"estimated_analysis_cost", fmt.Sprintf("$%.4f", e.AnalysisInput),
		"estimated_audit_cost", fmt.Sprintf("$%.4f", e.AuditInput),
		"estimated_total_input_cost", fmt.Sprintf("$%.4f", e.TotalInput),
		"estimated_planning_cost", fmt.Sprintf("$%.4f", e.Planning),
	}
}

func (e scanCostEstimate) writeSummary(w io.Writer) {
	fmt.Fprintf(w, "  Estimated analysis input cost: $%.4f\n", e.AnalysisInput)
	if e.auditEnabled {
		fmt.Fprintf(w, "  Estimated audit input cost:    $%.4f (model: %s)\n", e.AuditInput, e.auditModel)
	}
	fmt.Fprintf(w, "  Estimated total input cost:    $%.4f\n", e.TotalInput)
	fmt.Fprintf(w, "  Rough input + output cost:    $%.4f\n", e.Planning)
	fmt.Fprintf(w, "  Planning allowance (2–3x):    $%.2f–$%.2f (not a ceiling)\n", e.AllowanceLow, e.AllowanceHigh)
	fmt.Fprintln(w, "  Assumptions: 25% input overhead and output equal to 1/16 of padded input, for analysis plus one audit pass when enabled.")
	fmt.Fprintln(w, "  Excludes separate feature detection, context compression, retries and repeated audit batches.")
}
