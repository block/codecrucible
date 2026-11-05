package cli

import (
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"sort"
	"strings"

	"github.com/block/codecrucible/internal/chunk"
	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/llm"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
	plan          *scanCostPlan
}

func estimateScanCost(sourceTokens int, cfg *config.Config) scanCostEstimate {
	analysis := cfg.Phases.Analysis.ModelCfg
	audit := cfg.Phases.Audit.ModelCfg
	estimate := scanCostEstimate{
		auditEnabled: !cfg.SkipAudit,
		auditModel:   audit.Name,
	}
	// Illustrative input+output scenario, not a quota reservation or worst-case
	// bound. Audit is one repository-sized pass; actual batches depend on findings.
	input := int(math.Ceil(float64(sourceTokens) * 1.25))
	output := int(math.Ceil(float64(input) / 16))
	// An audit replay reuses saved findings and sends no analysis requests.
	if cfg.AuditFrom == "" {
		estimate.AnalysisInput = analysis.EstimateInputCost(sourceTokens)
		estimate.Planning = analysis.EstimateCost(input, output)
	}
	if estimate.auditEnabled {
		estimate.AuditInput = audit.EstimateInputCost(sourceTokens)
		estimate.Planning += audit.EstimateCost(input, output)
	}
	estimate.TotalInput = estimate.AnalysisInput + estimate.AuditInput
	estimate.AllowanceLow = estimate.Planning * 2
	estimate.AllowanceHigh = estimate.Planning * 3
	return estimate
}

// checkBudget rejects a planned scenario that already exceeds the requested
// budget. Unknown work means passing this gate is not a billed-spend ceiling.
func (e scanCostEstimate) checkBudget(maxCost float64) error {
	if maxCost > 0 && e.plan != nil && len(e.plan.Unpriced) > 0 {
		return fmt.Errorf("cannot enforce --max-cost: missing pricing for %s; add input and output pricing or unset max-cost (--max-cost 0)", strings.Join(e.plan.Unpriced, ", "))
	}
	cost := e.TotalInput
	if maxCost > 0 && cost > maxCost {
		return fmt.Errorf("estimated input cost $%.4f exceeds --max-cost $%.2f; input + maximum output upper bound for this scenario: $%.4f; aborting (use --dry-run to preview)", cost, maxCost, e.Planning)
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
	fmt.Fprintf(w, "  Input + maximum output upper bound (scenario):    $%.4f\n", e.Planning)
	fmt.Fprintf(w, "  Planning allowance (2–3x):    $%.2f–$%.2f (not a ceiling)\n", e.AllowanceLow, e.AllowanceHigh)
	if e.plan != nil {
		fmt.Fprintf(w, "  Planned analysis chunks: %d (source budget: %d tokens)\n", e.plan.Chunks, e.plan.SourceBudget)
		fmt.Fprintf(w, "  Audit scenario: %d batches; one finding per source file, batch size %d; up to %d retrieval tokens per batch within model capacity.\n", e.plan.AuditBatches, e.plan.BatchSize, auditRetrievalBudget)
		fmt.Fprintln(w, "  Assumptions: all analysis prompt sections; 20% context safety margin; configured maximum output per request. Each source file appears in one audit batch; each batch is capped with prompt and retrieval by model input capacity. Actual findings and batches are unknown; this is not a spending ceiling.")
		fmt.Fprintln(w, "  Excludes feature detection, supplementary context and compression, adaptive tokenizer correction, finding payloads/CWE-specific audit sections, retries, and additional audit iterations. These may change the executed chunk plan and cost.")
		for _, model := range e.plan.Unpriced {
			fmt.Fprintf(w, "  Warning: missing pricing for %s; estimate is incomplete, not free.\n", model)
		}
		return
	}
	fmt.Fprintln(w, "  Assumptions: 25% input overhead and output equal to 1/16 of padded input, for analysis plus one audit pass when enabled.")
	fmt.Fprintln(w, "  Excludes separate feature detection, context compression, retries and repeated audit batches.")
}

// scanCostPlan records a provider-free scenario, not a prediction of findings.
type scanCostPlan struct {
	Chunks, SourceBudget, AuditBatches, BatchSize int
	Unpriced                                      []string
}

func planScanCost(flat ingest.FlattenResult, cfg *config.Config, loader *llm.PromptLoader, repoName string, counter *chunk.TokenCounter, opts *chunk.ChunkOptions) (scanCostEstimate, error) {
	analysis, audit := cfg.Phases.Analysis.ModelCfg, cfg.Phases.Audit.ModelCfg
	e := scanCostEstimate{auditEnabled: !cfg.SkipAudit, auditModel: audit.Name, plan: &scanCostPlan{BatchSize: cfg.AuditBatchSize}}
	schema := llm.SecurityAnalysisSchema()
	msgs, err := loader.AssembleMessages(llm.PromptParams{RepoName: repoName, Schema: string(*schema), ChunkTotal: 1, CustomRequirements: cfg.CustomRequirements})
	if err != nil {
		return e, fmt.Errorf("planning analysis prompt: %w", err)
	}
	overhead := 0
	for _, msg := range msgs {
		overhead += counter.Count(msg.Content)
	}
	if llm.OutputModeForConfig(analysis) == llm.OutputModeToolUse {
		overhead += counter.Count(string(*schema))
	}
	budget := int(float64(analysis.ContextLimit)*0.8) - overhead - analysis.MaxOutputTokens
	if flat.Tokens > budget {
		paths := make([]string, 0, len(flat.FileMap))
		for path := range flat.FileMap {
			paths = append(paths, path)
		}
		sort.Strings(paths)
		overhead += min(counter.Count(strings.Join(paths, "\n")), analysis.ContextLimit/10)
		budget = int(float64(analysis.ContextLimit)*0.8) - overhead - analysis.MaxOutputTokens
	}
	// Match runAnalysisPhases' fallback when prompts leave no source capacity.
	if budget <= 0 {
		budget = analysis.ContextLimit / 2
	}
	e.plan.SourceBudget = budget
	if cfg.AuditFrom == "" {
		chunks, chunkErr := chunk.NewChunker(counter, slog.Default()).Chunk(flat, budget, opts)
		if chunkErr != nil {
			return e, fmt.Errorf("planning chunks: %w", chunkErr)
		}
		e.plan.Chunks = len(chunks)
		for _, part := range chunks {
			input := overhead + counter.Count(part.XML)
			e.AnalysisInput += analysis.EstimateInputCost(input)
			e.Planning += analysis.EstimateCost(input, analysis.MaxOutputTokens)
		}
		if analysis.InputPricePerM <= 0 || analysis.OutputPricePerM <= 0 {
			e.plan.Unpriced = append(e.plan.Unpriced, "analysis ("+analysis.Name+")")
		}
	}
	if !cfg.SkipAudit {
		// Findings do not exist yet. Make the batch assumption visible rather than
		// hiding repeated source and retrieval behind a single repository pass.
		batches := 1
		if cfg.AuditBatchSize > 0 {
			batches = (len(flat.FileMap) + cfg.AuditBatchSize - 1) / cfg.AuditBatchSize
		}
		e.plan.AuditBatches = batches
		auditSchema := llm.AuditSchema()
		ap, loadErr := loader.LoadAuditPrompt()
		if loadErr != nil {
			return e, fmt.Errorf("planning audit prompt: %w", loadErr)
		}
		if ap.Contract == "v2" {
			auditSchema = llm.AuditSchemaV2()
		}
		auditMsgs, auditErr := loader.AssembleAuditMessages(llm.AuditParams{RepoName: repoName, FindingsJSON: "[]", Schema: string(*auditSchema), ProductionOnly: !cfg.IncludeTests})
		if auditErr != nil {
			return e, fmt.Errorf("planning audit prompt: %w", auditErr)
		}
		auditCounter := chunk.NewTokenCounter(audit.Encoding, slog.Default())
		base := 0
		for _, msg := range auditMsgs {
			base += auditCounter.Count(msg.Content)
		}
		if llm.OutputModeForConfig(audit) == llm.OutputModeToolUse {
			base += auditCounter.Count(string(*auditSchema))
		}
		capacity := max(0, audit.ContextLimit-audit.MaxOutputTokens)
		// The scenario assigns each file to exactly one deterministic batch.
		// Only prompt and retrieval allowances repeat across batches.
		paths := make([]string, 0, len(flat.FileMap))
		for path := range flat.FileMap {
			paths = append(paths, path)
		}
		sort.Strings(paths)
		batchSize := cfg.AuditBatchSize
		if batchSize <= 0 {
			batchSize = max(1, len(paths))
		}
		for offset := 0; offset < len(paths); offset += batchSize {
			var files []ingest.SourceFile
			for _, path := range paths[offset:min(len(paths), offset+batchSize)] {
				content := flat.FileMap[path]
				files = append(files, ingest.SourceFile{Path: path, Content: content, LineCount: strings.Count(content, "\n") + 1})
			}
			sourceXML := ingest.Flatten(files, ingest.FlattenConfig{}).XML
			source := min(auditCounter.Count(sourceXML), max(0, capacity-base))
			retrieval := min(auditRetrievalBudget, max(0, capacity-base-source))
			input := min(capacity, base+source+retrieval)
			e.AuditInput += audit.EstimateInputCost(input)
			e.Planning += audit.EstimateCost(input, audit.MaxOutputTokens)
		}
		if audit.InputPricePerM <= 0 || audit.OutputPricePerM <= 0 {
			e.plan.Unpriced = append(e.plan.Unpriced, "audit ("+audit.Name+")")
		}
	}
	e.TotalInput = e.AnalysisInput + e.AuditInput
	e.AllowanceLow, e.AllowanceHigh = e.Planning*2, e.Planning*3
	return e, nil
}

// explicitMaxCost distinguishes a user limit from the historical default.
// MAX_COST is the environment name used by config.BindEnvVars.
func explicitMaxCost(cmd *cobra.Command, settings *viper.Viper, limit float64) bool {
	flag := cmd.Flags().Lookup("max-cost")
	return (flag != nil && flag.Changed) || settings.InConfig("max-cost") || os.Getenv("MAX_COST") != "" || limit != config.DefaultMaxCost
}

func (e scanCostEstimate) checkConfiguredBudget(limit float64, explicit bool) error {
	if !explicit && e.plan != nil && len(e.plan.Unpriced) > 0 {
		slog.Warn("default $25 cap is not being enforced for unpriced models", "models", strings.Join(e.plan.Unpriced, ", "), "action", "add model pricing or set an explicit max-cost")
		// Keep enforcing the known priced portion under the implicit cap.
		priced := e
		priced.plan = nil
		return priced.checkBudget(limit)
	}
	return e.checkBudget(limit)
}
