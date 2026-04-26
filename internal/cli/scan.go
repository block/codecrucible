package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/block/codecrucible/internal/chunk"
	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/llm"
	"github.com/block/codecrucible/internal/sarif"
	"github.com/spf13/cobra"
)

func newScanCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan [repo-path]",
		Short: "Scan a repository for security vulnerabilities",
		Long: `Scan analyzes one or more repository paths using an LLM-based security analysis
pipeline and produces SARIF output suitable for GitHub Code Scanning integration.`,
		Args: cobra.MaximumNArgs(1),
		RunE: runScan,
	}

	// Repository targeting
	cmd.Flags().StringSlice("paths", nil, "paths within the repository to analyze (can be specified multiple times)")
	cmd.Flags().StringSlice("include", nil, "glob patterns for files to include")
	cmd.Flags().StringSlice("exclude", nil, "glob patterns for files to exclude")

	// Per-phase LLM selection: three symmetric families, defined once.
	// Analysis-phase flags carry no prefix (they're the ones you reach
	// for first). Unset --audit-* / --feature-detection-* inherit from
	// the analysis values.
	for _, p := range phaseFlagSets {
		cmd.Flags().String(p.prefix+"model", "", p.what+" model"+p.inherit)
		cmd.Flags().String(p.prefix+"provider", "", p.what+" provider: anthropic, openai, google, ollama, openai-compat, databricks"+p.inherit)
		cmd.Flags().String(p.prefix+"api-key", "", p.what+" API key (optional for ollama/openai-compat)"+p.inherit)
		cmd.Flags().String(p.prefix+"base-url", "", p.what+" base URL override"+p.inherit)
		cmd.Flags().String(p.prefix+"model-params", "", p.what+" model request params as JSON (merged into request body)"+p.inherit)
		// Hide per-phase flags from default --help to reduce noise.
		// They still work; use --help-all or the README for full docs.
		if p.prefix != "" {
			for leaf := range phaseLeaves {
				_ = cmd.Flags().MarkHidden(p.prefix + leaf)
			}
		}
		// Short-form alias: distinct hidden flags binding to the same
		// viper key in bindScanFlags. Cobra has command aliases but not
		// flag aliases, so this is the idiom.
		if p.alias != "" {
			for leaf := range phaseLeaves {
				cmd.Flags().String(p.alias+leaf, "", "")
				_ = cmd.Flags().MarkHidden(p.alias + leaf)
			}
		}
	}

	// Analysis behaviour
	cmd.Flags().Float64("fail-on-severity", 0, "exit non-zero if any finding meets or exceeds this severity (0-10)")
	cmd.Flags().Float64("max-cost", 25, "maximum cost budget in dollars (0 = unlimited)")
	cmd.Flags().Bool("dry-run", false, "show what would be analyzed without making LLM calls")
	cmd.Flags().String("custom-requirements", "", "additional analysis requirements to include in the prompt")
	cmd.Flags().StringSlice("context-source", nil, "supplementary context as key=value pairs: name=X,type=<path|repo|url|inline>,location=Y,priority=N,compress=true (repeatable)")
	cmd.Flags().Int("context-budget-pct", 15, "percentage of context window reserved for supplementary context (max 40)")
	cmd.Flags().String("prompts-dir", "", "prompt set directory containing YAML templates (default: prompts/default)")
	cmd.Flags().StringSlice("custom-headers", nil, "additional HTTP headers for LLM requests, format 'Name: Value' (repeatable)")

	// Content options
	cmd.Flags().Bool("include-tests", false, "include test files in the analysis")
	cmd.Flags().Bool("include-docs", false, "include documentation files in the analysis")
	cmd.Flags().Bool("compress", false, "compress whitespace in source files to save tokens")
	cmd.Flags().Int("max-file-size", 102400, "exclude files larger than this size in bytes (0 = no limit)")

	// Model limits
	cmd.Flags().Int("context-limit", 0, "override the model's context window size in tokens (0 = use model registry default)")
	cmd.Flags().Int("max-output-tokens", 0, "override the model's max output tokens (0 = use model registry default)")
	cmd.Flags().Int("request-timeout", 0, "per-request HTTP timeout in seconds (0 = default 600s)")

	// Phase gates
	cmd.Flags().Bool("skip-feature-detection", false, "skip the feature detection pre-pass (faster for small repos)")
	cmd.Flags().Bool("skip-audit", false, "skip the CWE-specific audit phase (faster but less accurate)")
	cmd.Flags().Float64("audit-confidence-threshold", 0.3, "reject findings below this confidence score (0.0-1.0)")
	cmd.Flags().Int("audit-batch-size", 25, "split audit into batches of N findings (0 = single call). Default keeps each call under typical server connection-age limits (~10-12min)")
	cmd.Flags().Int("concurrency", 3, "max number of chunks to analyze in parallel")

	// Output
	cmd.Flags().StringP("output", "o", "", "write output to file (default: stdout)")
	cmd.Flags().String("phase-output-dir", "", "write per-phase artifacts to this directory (default: sidecars next to --output)")

	// Bind scan flags to viper
	cmd.PreRun = func(cmd *cobra.Command, args []string) {
		bindScanFlags(cmd)
	}

	return cmd
}

// phaseFlagSets keeps the three per-phase flag families symmetric. Add a
// knob once, get it on all three. The analysis phase has an empty prefix:
// --model, --provider, --api-key, --model-params are its flags. The other
// two get their name as prefix.
//
// viperKey maps the CLI form to the config.Phases.<phase>.<leaf> path so a
// config-file phases: block, a PHASES_AUDIT_MODEL env var, and an
// --audit-model flag all land in the same place.
//
// The analysis phase is odd: its model/provider also bind to the legacy
// flat cfg.Model/cfg.Provider keys so existing config files and env vars
// (CODECRUCIBLE_PROVIDER, etc.) keep working. ResolvePhases reads the
// flat keys when seeding the analysis PhaseConfig, so either path ends up
// in the same slot.
var phaseFlagSets = []struct {
	prefix   string // CLI flag prefix
	alias    string // short prefix; flags registered hidden, bound to the same viper key
	viperKey string // phases.<this>.<leaf>
	what     string // help text subject
	inherit  string // help text suffix
}{
	{"", "", "analysis", "analysis-phase", " (inherited by other phases unless overridden)"},
	{"feature-detection-", "fd-", "feature-detection", "feature-detection-phase", " (default: inherit from analysis; alias: --fd-*)"},
	{"audit-", "", "audit", "audit-phase", " (default: inherit from analysis)"},
	{"context-compress-", "cc-", "context-compress", "context-compression-phase", " (default: inherit from analysis; alias: --cc-*)"},
}

// phaseLeaves are the per-phase knobs. CLI name → PhaseConfig mapstructure
// leaf. model-params gets the -json suffix because the CLI form is a JSON
// string while the config-file form is a native YAML map — same split as
// the legacy global model-params / model-params-json pair.
var phaseLeaves = map[string]string{
	"model":        "model",
	"provider":     "provider",
	"api-key":      "api-key",
	"base-url":     "base-url",
	"model-params": "model-params-json",
}

func bindScanFlags(cmd *cobra.Command) {
	// Flat flags map to same-named viper keys.
	flags := []string{
		"paths", "fail-on-severity", "max-cost", "dry-run",
		"include-tests", "include-docs", "compress", "custom-requirements",
		"output", "phase-output-dir", "prompts-dir", "include", "exclude", "custom-headers",
		"skip-feature-detection", "concurrency", "max-file-size",
		"context-limit", "max-output-tokens", "request-timeout",
		"skip-audit", "audit-confidence-threshold", "audit-batch-size",
		"context-budget-pct",
	}
	for _, f := range flags {
		_ = v.BindPFlag(f, cmd.Flags().Lookup(f))
	}
	// context-source flag populates the raw-string slice; config.Load parses
	// each into a ContextSource and appends to any declared in the config file.
	_ = v.BindPFlag("context-sources-raw", cmd.Flags().Lookup("context-source"))

	// Per-phase families: one loop, three phases, four knobs each.
	// BindPFlag stores key → *pflag.Flag in a map; a second bind to the
	// same key overwrites the first. So bind the alias only when the
	// user actually set it — otherwise the long form stays wired.
	// bindScanFlags runs from PreRun, after argv parsing, so .Changed
	// is accurate here.
	for _, p := range phaseFlagSets {
		for cli, leaf := range phaseLeaves {
			key := "phases." + p.viperKey + "." + leaf
			_ = v.BindPFlag(key, cmd.Flags().Lookup(p.prefix+cli))
			if p.alias != "" {
				if af := cmd.Flags().Lookup(p.alias + cli); af != nil && af.Changed {
					_ = v.BindPFlag(key, af)
				}
			}
		}
	}

	// Legacy flat-key aliases for the analysis phase so existing
	// config files (model:, provider:) and env vars keep working.
	// ResolvePhases reads these into Phases.Analysis.
	_ = v.BindPFlag("model", cmd.Flags().Lookup("model"))
	_ = v.BindPFlag("provider", cmd.Flags().Lookup("provider"))
	_ = v.BindPFlag("model-params-json", cmd.Flags().Lookup("model-params"))
	_ = v.BindPFlag("base-url", cmd.Flags().Lookup("base-url"))
	// Same for the legacy per-phase model-only flags.
	_ = v.BindPFlag("feature-detection-model", cmd.Flags().Lookup("feature-detection-model"))
	_ = v.BindPFlag("audit-model", cmd.Flags().Lookup("audit-model"))
}

// exitCodeFindings is the exit code when findings exceed --fail-on-severity.
const exitCodeFindings = 2

func runScan(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(v)
	if err != nil {
		return err
	}
	if err := config.ResolvePhases(cfg); err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Determine repo root.
	repoRoot := "."
	if len(args) > 0 {
		repoRoot = args[0]
	}
	repoRoot, err = filepath.Abs(repoRoot)
	if err != nil {
		return fmt.Errorf("resolving repo path: %w", err)
	}

	slog.Info("scan starting",
		"repo", repoRoot,
		"paths", cfg.Paths,
		"model", cfg.Model,
		"dry_run", cfg.DryRun,
	)

	// Phase configs are fully resolved by this point — registry lookup,
	// per-phase overrides, provider detection, key cascade all done.
	// Alias the analysis phase's model config to keep downstream token
	// math and call sites reading the familiar name.
	analysis := &cfg.Phases.Analysis
	modelCfg := analysis.ModelCfg

	// --- Stage 1: Ingest ---
	files, err := ingestFiles(repoRoot, cfg)
	if err != nil {
		return err
	}

	// --- Stage 2: Filter ---
	filtered, stats := ingest.FilterFiles(files, ingest.FilterConfig{
		IncludeTests: cfg.IncludeTests,
		IncludeDocs:  cfg.IncludeDocs,
		Include:      cfg.Include,
		Exclude:      cfg.Exclude,
		MaxFileSize:  cfg.MaxFileSize,
	})

	slog.Info("ingestion complete",
		"files_found", stats.Total,
		"files_kept", stats.Kept,
	)

	// --- Stage 3: Build FileMap (defer full XML generation) ---
	flattenCfg := ingest.FlattenConfig{Compress: cfg.Compress}
	flatResult := ingest.FlattenFileMapOnly(filtered)

	// --- Stage 3.5: Build import graph and export summaries ---
	importGraph := ingest.ResolveImports(filtered)
	exportSummaries := buildExportSummaries(filtered)

	slog.Info("import graph built",
		"files_with_imports", len(importGraph),
		"files_with_summaries", len(exportSummaries),
	)

	// --- Stage 4: Count tokens and chunk ---
	counter := chunk.NewTokenCounter(modelCfg.Encoding, slog.Default())
	// Streaming count: iterate FileMap one file at a time so peak memory is
	// max(single file XML) rather than the full concatenated document.
	totalTokens := streamingTokenCount(flatResult.FileMap, counter, flattenCfg)
	flatResult.Tokens = totalTokens

	// Only build the full XML when the repo likely fits in a single chunk.
	// The chunker returns this verbatim for single-chunk, but for multi-chunk
	// it rebuilds per-file XML from FileMap anyway — so building ~2x N of
	// XML upfront would be pure waste.
	if totalTokens <= modelCfg.ContextLimit {
		flatResult.BuildFullXML(filtered, flattenCfg)
	}

	// Estimate cost.
	analysisCost := float64(totalTokens) * modelCfg.InputPricePerM / 1_000_000

	// Estimate audit phase cost (assumes all repo tokens as context in the worst case).
	var auditCostEstimate float64
	if !cfg.SkipAudit {
		auditCostEstimate = float64(totalTokens) * cfg.Phases.Audit.ModelCfg.InputPricePerM / 1_000_000
	}

	estimatedCost := analysisCost + auditCostEstimate

	slog.Info("analysis scope",
		"files", len(filtered),
		"tokens", totalTokens,
		"model", modelCfg.Name,
		"context_limit", modelCfg.ContextLimit,
		"estimated_analysis_cost", fmt.Sprintf("$%.4f", analysisCost),
		"estimated_audit_cost", fmt.Sprintf("$%.4f", auditCostEstimate),
		"estimated_total_input_cost", fmt.Sprintf("$%.4f", estimatedCost),
	)

	// Handle empty repo.
	if len(filtered) == 0 {
		slog.Info("no source files after filtering, producing empty SARIF")
		return outputEmptySARIF(cfg)
	}

	if cfg.DryRun {
		fmt.Printf("Dry run — analysis scope:\n")
		fmt.Printf("  Files: %d (of %d total)\n", stats.Kept, stats.Total)
		fmt.Printf("  Tokens: %d\n", totalTokens)
		fmt.Printf("  Model: %s (context limit: %d)\n", modelCfg.Name, modelCfg.ContextLimit)
		fmt.Printf("  Estimated analysis input cost: $%.4f\n", analysisCost)
		if !cfg.SkipAudit {
			fmt.Printf("  Estimated audit input cost:    $%.4f (model: %s)\n", auditCostEstimate, cfg.Phases.Audit.ModelCfg.Name)
		}
		fmt.Printf("  Estimated total input cost:    $%.4f\n", estimatedCost)
		if totalTokens > modelCfg.ContextLimit {
			chunks := (totalTokens / modelCfg.ContextLimit) + 1
			fmt.Printf("  Will require ~%d chunks\n", chunks)
		}
		return nil
	}

	// Check max cost.
	if cfg.MaxCost > 0 && estimatedCost > cfg.MaxCost {
		return fmt.Errorf("estimated cost $%.4f exceeds --max-cost $%.2f; aborting (use --dry-run to preview)", estimatedCost, cfg.MaxCost)
	}

	// --- Stage 5: Prepare LLM ---
	client, endpoint, err := buildPhaseClient(*analysis, cfg)
	if err != nil {
		return err
	}

	slog.Info("LLM provider configured", "provider", analysis.Provider, "model", modelCfg.Name)

	// Load prompt templates.
	promptLoader, err := resolvePromptLoader(cfg.PromptsDir)
	if err != nil {
		return fmt.Errorf("loading prompts: %w", err)
	}

	schema := llm.SecurityAnalysisSchema()
	outputMode := llm.OutputModeForModel(modelCfg.Name)
	repoName := filepath.Base(repoRoot)
	artifacts := newPhaseArtifactWriter(cfg)
	if artifacts.Enabled() {
		slog.Info("phase artifacts enabled",
			"feature_detection", artifacts.Path("feature-detection"),
			"analysis", artifacts.Path("analysis"),
			"audit", artifacts.Path("audit"),
		)
	}

	// --- Stage 5.25: Load & pack supplementary context ---
	analysisCtx, auditCtx, err := loadSupplementaryContext(cmd.Context(), cfg, counter, promptLoader, modelCfg.ContextLimit)
	if err != nil {
		return err
	}

	// --- Stage 5.5: Estimate whether we need chunking ---
	// Measure prompt overhead assuming all sections (worst-case) to decide if
	// feature detection is worth the extra LLM round-trip.
	worstCaseMsgs, err := promptLoader.AssembleMessages(llm.PromptParams{
		RepoName:             repoName,
		XML:                  "",
		Schema:               string(*schema),
		ChunkTotal:           1,
		CustomRequirements:   cfg.CustomRequirements,
		EnabledFeatures:      nil, // nil = all sections included
		SupplementaryContext: analysisCtx.Rendered,
	})
	if err != nil {
		return fmt.Errorf("measuring prompt overhead: %w", err)
	}
	worstCaseOverhead := 0
	for _, msg := range worstCaseMsgs {
		worstCaseOverhead += counter.Count(msg.Content)
	}
	if outputMode == llm.OutputModeToolUse && schema != nil {
		worstCaseOverhead += counter.Count(string(*schema))
	}

	// If the repo fits in a single chunk even with all sections, skip feature
	// detection entirely — it's a full LLM round-trip for no benefit.
	const tokenizerSafetyMargin = 0.20
	outputReserve := modelCfg.MaxOutputTokens
	worstCaseEffective := int(float64(modelCfg.ContextLimit) * (1 - tokenizerSafetyMargin))
	worstCaseBudget := worstCaseEffective - worstCaseOverhead - outputReserve

	var detectedFeatures []string
	var tokenCorrection float64
	if !cfg.SkipFeatureDetection && totalTokens > worstCaseBudget {
		// Multi-chunk scenario: feature detection trims sections and saves tokens.
		fd := &cfg.Phases.FeatureDetection
		fdClient, fdEndpoint, fdErr := buildPhaseClient(*fd, cfg)
		if fdErr != nil {
			slog.Warn("failed to build feature-detection client; falling back to analysis client",
				"error", fdErr, "provider", fd.Provider)
			fdClient, fdEndpoint = client, endpoint
			fd = analysis
		} else if fd.ModelCfg.Name != modelCfg.Name || fd.Provider != analysis.Provider {
			slog.Info("feature detection uses separate configuration",
				"provider", fd.Provider, "model", fd.ModelCfg.Name)
		}
		fdOutputMode := llm.OutputModeForModel(fd.ModelCfg.Name)
		var fdCorrection float64
		detectedFeatures, fdCorrection, err = runFeatureDetection(cmd.Context(), filtered, repoName, fdClient, fdEndpoint, fd.ModelCfg, promptLoader, fdOutputMode, fd.ModelParams, counter)
		if err != nil {
			if wErr := artifacts.WriteFeatureDetection(featureDetectionArtifact{
				Phase:    "feature-detection",
				Status:   "failed",
				Repo:     repoName,
				Provider: fd.Provider,
				Model:    fd.ModelCfg.Name,
				Error:    err.Error(),
				Fallback: "all_sections",
			}); wErr != nil {
				return fmt.Errorf("writing feature-detection artifact: %w", wErr)
			}
			slog.Warn("feature detection failed, using all sections", "error", err)
		} else {
			if wErr := artifacts.WriteFeatureDetection(featureDetectionArtifact{
				Phase:            "feature-detection",
				Status:           "completed",
				Repo:             repoName,
				Provider:         fd.Provider,
				Model:            fd.ModelCfg.Name,
				DetectedFeatures: detectedFeatures,
				TokenCorrection:  fdCorrection,
			}); wErr != nil {
				return fmt.Errorf("writing feature-detection artifact: %w", wErr)
			}
			slog.Info("feature detection complete", "features", detectedFeatures)
		}
		// Calibration is only valid when feature detection hit the same model
		// as chunk analysis — a different model means a different tokenizer.
		if fd.ModelCfg.Name == modelCfg.Name {
			tokenCorrection = fdCorrection
		}
	} else if cfg.SkipFeatureDetection {
		if wErr := artifacts.WriteFeatureDetection(featureDetectionArtifact{
			Phase:  "feature-detection",
			Status: "skipped",
			Repo:   repoName,
			Reason: "--skip-feature-detection",
		}); wErr != nil {
			return fmt.Errorf("writing feature-detection artifact: %w", wErr)
		}
		slog.Info("feature detection skipped (--skip-feature-detection)")
	} else {
		if wErr := artifacts.WriteFeatureDetection(featureDetectionArtifact{
			Phase:  "feature-detection",
			Status: "skipped",
			Repo:   repoName,
			Reason: "repo fits in single chunk",
		}); wErr != nil {
			return fmt.Errorf("writing feature-detection artifact: %w", wErr)
		}
		slog.Info("feature detection skipped (repo fits in single chunk)")
	}

	// Release SourceFile slice — FileMap retains the content strings via
	// shared Go string backing bytes; the slice of structs is no longer needed.
	filtered = nil

	// Measure actual prompt token overhead with the resolved features.
	// If features are nil (same as worst-case), reuse the already-computed value
	// to avoid a redundant BPE encoding pass.
	promptOverhead := worstCaseOverhead
	if detectedFeatures != nil {
		measureMsgs, mErr := promptLoader.AssembleMessages(llm.PromptParams{
			RepoName:             repoName,
			XML:                  "",
			Schema:               string(*schema),
			ChunkTotal:           1,
			CustomRequirements:   cfg.CustomRequirements,
			EnabledFeatures:      detectedFeatures,
			SupplementaryContext: analysisCtx.Rendered,
		})
		if mErr != nil {
			return fmt.Errorf("measuring prompt overhead: %w", mErr)
		}
		promptOverhead = 0
		for _, msg := range measureMsgs {
			promptOverhead += counter.Count(msg.Content)
		}
		toolOverhead := 0
		if outputMode == llm.OutputModeToolUse && schema != nil {
			toolOverhead = counter.Count(string(*schema))
		}
		promptOverhead += toolOverhead
	}

	// For multi-chunk scenarios, the prompt includes a manifest of all other
	// file paths (injected by AssembleMessages when ChunkTotal > 1). Account
	// for this in the overhead so the chunk budget isn't over-allocated.
	// Cap the manifest to 10% of the context limit so it doesn't crowd out
	// the actual file content in large repos.
	manifestBudget := modelCfg.ContextLimit / 10
	if totalTokens > worstCaseBudget {
		allPaths := make([]string, 0, len(flatResult.FileMap))
		for p := range flatResult.FileMap {
			allPaths = append(allPaths, p)
		}
		manifestTokens := counter.Count(strings.Join(allPaths, "\n"))
		if manifestTokens > manifestBudget {
			manifestTokens = manifestBudget
		}
		promptOverhead += manifestTokens
	}

	slog.Info("prompt overhead measured",
		"total_overhead", promptOverhead,
	)

	// Chunk if needed.
	// Reserve budget for output tokens, measured prompt overhead, and a safety
	// margin for tokenizer variance. The anthropic-tokenizer-go library uses
	// Claude 2-era BPE vocabulary which undercounts ~17% vs Claude 4's actual
	// tokenizer. Also accounts for API-side overhead (tool definitions, message
	// framing, internal prompt formatting).
	effectiveLimit := int(float64(modelCfg.ContextLimit) * (1 - tokenizerSafetyMargin))
	chunkBudget := effectiveLimit - promptOverhead - outputReserve
	// When supplementary context is configured, a too-small chunk budget
	// means the user has starved the scan target. Fail loudly rather than
	// producing tiny chunks with poor coverage.
	const minChunkBudget = 5000
	if analysisCtx.Tokens > 0 && chunkBudget < minChunkBudget {
		return fmt.Errorf("supplementary context (%d tokens) leaves only %d tokens for source code; reduce --context-budget-pct or enable compress:true on large sources",
			analysisCtx.Tokens, chunkBudget)
	}
	if chunkBudget <= 0 {
		chunkBudget = modelCfg.ContextLimit / 2
	}

	// Apply the measured correction from feature detection. Only shrink —
	// if the heuristic overcounted (correction < 1), we're already safe.
	// Clamp to 2× to guard against noisy measurements where framing overhead
	// dominates a small feature-detection payload.
	if tokenCorrection > 1.0 {
		clamp := tokenCorrection
		if clamp > 2.0 {
			clamp = 2.0
		}
		adjusted := int(float64(chunkBudget) / clamp)
		slog.Info("shrinking chunk budget to match measured tokenizer density",
			"before", chunkBudget,
			"after", adjusted,
			"correction_factor", fmt.Sprintf("%.3f", tokenCorrection),
		)
		chunkBudget = adjusted
	}

	chunker := chunk.NewChunker(counter, slog.Default())
	chunkOpts := &chunk.ChunkOptions{
		ImportGraph:     importGraph,
		ExportSummaries: exportSummaries,
	}
	chunks, err := chunker.Chunk(flatResult, chunkBudget, chunkOpts)
	if err != nil {
		return fmt.Errorf("chunking: %w", err)
	}

	slog.Info("chunking complete",
		"chunks", len(chunks),
		"chunk_budget", chunkBudget,
		"effective_limit", effectiveLimit,
	)

	// Release the full XML string — the chunker has either returned it
	// verbatim (single-chunk) or built per-file XML from FileMap
	// (multi-chunk). Holding it further wastes ~2x source-size bytes.
	flatResult.XML = ""

	// --- Stage 5.75: Analyze chunks in parallel ---
	maxConcurrency := cfg.Concurrency
	if maxConcurrency <= 0 {
		maxConcurrency = 3
	}

	type chunkResult struct {
		index int
		doc   sarif.SARIFDocument
		usage llm.TokenUsage
		cost  float64
		err   error
	}

	results := make([]chunkResult, len(chunks))
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrency)

	for i, c := range chunks {
		wg.Add(1)
		go func(idx int, ch chunk.Chunk) {
			defer wg.Done()
			sem <- struct{}{}        // acquire
			defer func() { <-sem }() // release

			doc, usage, cost, aErr := analyzeChunk(
				cmd.Context(), ch, repoName, client, endpoint,
				modelCfg, promptLoader, schema, outputMode,
				cfg.CustomRequirements, analysisCtx.Rendered, detectedFeatures, flatResult.FileMap, analysis.ModelParams,
			)
			results[idx] = chunkResult{index: idx, doc: doc, usage: usage, cost: cost, err: aErr}
		}(i, c)
	}
	wg.Wait()

	// Collect results in order.
	var sarifDocs []sarif.SARIFDocument
	var totalUsage llm.TokenUsage
	var totalCost float64
	var overflowPaths []string
	for i, r := range results {
		if errors.Is(r.err, llm.ErrContextLengthExceeded) {
			overflowPaths = append(overflowPaths, chunks[i].Paths...)
			continue
		}
		sarifDocs = append(sarifDocs, r.doc)
		totalUsage.PromptTokens += r.usage.PromptTokens
		totalUsage.CompletionTokens += r.usage.CompletionTokens
		totalCost += r.cost
	}

	// Recovery pass: any chunk that hit the server-side context limit gets
	// re-chunked at 60% budget and retried once. Overflow 400s fail fast
	// (no generation), so the wasted cost is just one cheap round-trip.
	// One round is enough when calibration is working — if 60% still
	// overflows, the heuristic is off by >40% and we'd rather fail loudly.
	if len(overflowPaths) > 0 {
		retryBudget := chunkBudget * 6 / 10
		slog.Warn("re-chunking files from overflowed chunks at reduced budget",
			"files", len(overflowPaths),
			"original_budget", chunkBudget,
			"retry_budget", retryBudget,
		)

		retryMap := make(ingest.FileMap, len(overflowPaths))
		for _, p := range overflowPaths {
			if content, ok := flatResult.FileMap[p]; ok {
				retryMap[p] = content
			}
		}
		retryChunks, rErr := chunker.Chunk(ingest.FlattenResult{FileMap: retryMap}, retryBudget, chunkOpts)
		if rErr != nil {
			slog.Error("overflow recovery re-chunking failed; files skipped", "error", rErr, "files", len(overflowPaths))
		} else {
			slog.Info("overflow recovery pass starting", "chunks", len(retryChunks))
			for _, rc := range retryChunks {
				doc, usage, cost, aErr := analyzeChunk(
					cmd.Context(), rc, repoName, client, endpoint,
					modelCfg, promptLoader, schema, outputMode,
					cfg.CustomRequirements, analysisCtx.Rendered, detectedFeatures, flatResult.FileMap, analysis.ModelParams,
				)
				if errors.Is(aErr, llm.ErrContextLengthExceeded) {
					slog.Error("overflow recovery chunk still exceeds context; files skipped",
						"files", len(rc.Paths),
						"estimated_tokens", rc.Tokens,
						"hint", "lower --context-limit or raise the tokenizer safety margin",
					)
					continue
				}
				sarifDocs = append(sarifDocs, doc)
				totalUsage.PromptTokens += usage.PromptTokens
				totalUsage.CompletionTokens += usage.CompletionTokens
				totalCost += cost
			}
		}
	}

	// --- Stage 6: Merge ---
	merged := sarif.Merge(sarifDocs)

	// --- Stage 6.5: Post-process (dedup + deprioritize non-source) ---
	merged = sarif.PostProcess(merged)

	slog.Info("initial analysis complete",
		"total_findings", len(merged.Runs[0].Results),
		"total_rules", len(merged.Runs[0].Tool.Driver.Rules),
		"prompt_tokens", totalUsage.PromptTokens,
		"completion_tokens", totalUsage.CompletionTokens,
		"total_cost", fmt.Sprintf("$%.4f", totalCost),
	)
	if err := artifacts.WriteSARIF("analysis", merged); err != nil {
		return fmt.Errorf("writing analysis artifact: %w", err)
	}

	// --- Stage 6.75: Audit phase (CWE-specific scrutiny) ---
	if !cfg.SkipAudit && len(merged.Runs[0].Results) > 0 {
		audit := &cfg.Phases.Audit
		auditClient, auditEndpoint, auditErr := buildPhaseClient(*audit, cfg)
		if auditErr != nil {
			slog.Warn("failed to build audit client; falling back to analysis client",
				"error", auditErr, "provider", audit.Provider)
			auditClient, auditEndpoint = client, endpoint
			audit = analysis
		} else if audit.ModelCfg.Name != modelCfg.Name || audit.Provider != analysis.Provider {
			slog.Info("audit phase uses separate configuration",
				"provider", audit.Provider, "model", audit.ModelCfg.Name)
		}
		auditOutputMode := llm.OutputModeForModel(audit.ModelCfg.Name)

		auditedDoc, auditUsage, auditCost := runAuditPhase(
			cmd.Context(), merged, repoName,
			auditClient, auditEndpoint, audit.ModelCfg, promptLoader,
			auditOutputMode, flatResult.FileMap, cfg.AuditConfidenceThreshold, audit.ModelParams, auditCtx.Rendered,
			cfg.AuditBatchSize, !cfg.IncludeTests, counter,
		)
		if auditedDoc != nil {
			merged = *auditedDoc
			totalUsage.PromptTokens += auditUsage.PromptTokens
			totalUsage.CompletionTokens += auditUsage.CompletionTokens
			totalCost += auditCost
			if err := artifacts.WriteSARIF("audit", merged); err != nil {
				return fmt.Errorf("writing audit artifact: %w", err)
			}
		}
	} else if cfg.SkipAudit {
		slog.Info("audit phase skipped (--skip-audit)")
	} else {
		slog.Info("audit phase skipped (no findings to audit)")
	}

	slog.Info("analysis complete",
		"total_findings", len(merged.Runs[0].Results),
		"total_rules", len(merged.Runs[0].Tool.Driver.Rules),
		"prompt_tokens", totalUsage.PromptTokens,
		"completion_tokens", totalUsage.CompletionTokens,
		"total_cost", fmt.Sprintf("$%.4f", totalCost),
	)

	// --- Stage 7: Output ---
	output, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling SARIF: %w", err)
	}

	if cfg.Output != "" {
		if err := os.WriteFile(cfg.Output, output, 0600); err != nil {
			return fmt.Errorf("writing output file: %w", err)
		}
		slog.Info("SARIF written", "path", cfg.Output)
	} else {
		fmt.Println(string(output))
	}

	// Check --fail-on-severity threshold.
	if cfg.FailOnSeverity > 0 {
		ruleSeverity := make(map[string]float64, len(merged.Runs[0].Tool.Driver.Rules))
		for _, rule := range merged.Runs[0].Tool.Driver.Rules {
			if sevStr, ok := rule.Properties["security-severity"].(string); ok {
				var sev float64
				if _, err := fmt.Sscanf(sevStr, "%f", &sev); err == nil {
					ruleSeverity[rule.ID] = sev
				}
			}
		}
		var maxSev float64
		for _, result := range merged.Runs[0].Results {
			if sev, ok := ruleSeverity[result.RuleID]; ok && sev > maxSev {
				maxSev = sev
			}
		}
		if maxSev >= cfg.FailOnSeverity {
			slog.Info("findings exceed severity threshold",
				"threshold", cfg.FailOnSeverity,
				"max_severity", maxSev,
			)
			exitFunc(exitCodeFindings)
			return nil
		}
	}

	return nil
}
