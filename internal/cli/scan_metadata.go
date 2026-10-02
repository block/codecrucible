package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/decision"
	"github.com/block/codecrucible/internal/llm"
	"github.com/block/codecrucible/internal/sarif"
)

func fingerprint(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// newScanMetadata accepts resolved configuration only. Explicit projection
// prevents future credential/config fields from silently entering reports.
func newScanMetadata(cfg *config.Config) *sarif.ScanMetadata {
	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 3
	}
	contextPct := cfg.ContextBudgetPct
	if contextPct <= 0 {
		contextPct = 15
	}
	prompts := cfg.PromptsDir
	if prompts == "" {
		prompts = "prompts/default"
	}
	m := &sarif.ScanMetadata{
		SchemaVersion: 1,
		Recipe: sarif.ScanRecipe{
			ToolVersion: version, ToolCommit: commit,
			Phases:         map[string]sarif.PhaseRecipe{},
			Prompts:        sarif.PromptIdentity{Name: filepath.Base(filepath.Clean(prompts))},
			ContextSources: []sarif.ContextIdentity{},
			Controls: sarif.ScanControls{
				Paths: append([]string{}, cfg.Paths...), Include: append([]string{}, cfg.Include...), Exclude: append([]string{}, cfg.Exclude...),
				IncludeTests: cfg.IncludeTests, IncludeDocs: cfg.IncludeDocs, MaxFileSize: cfg.MaxFileSize,
				Compress: cfg.Compress, Concurrency: concurrency, MaxCost: cfg.MaxCost, FailOnSeverity: cfg.FailOnSeverity,
				SkipFeatureDetection: cfg.SkipFeatureDetection, SkipAudit: cfg.SkipAudit,
				AuditConfidenceThreshold: cfg.AuditConfidenceThreshold, AuditBatchSize: cfg.AuditBatchSize, AuditConcurrency: max(1, cfg.AuditConcurrency),
				ContextBudgetPct: contextPct,
			},
		},
		Execution: sarif.ScanExecution{
			Phases: map[string]sarif.PhaseExecution{}, DetectedFeatures: []string{},
			ContextSources: []sarif.ContextExecution{}, ContextPacking: map[string]sarif.ContextPacking{},
		},
	}
	for name, phase := range map[string]config.PhaseConfig{
		"analysis": cfg.Phases.Analysis, "feature-detection": cfg.Phases.FeatureDetection,
		"audit": cfg.Phases.Audit, "context-compress": cfg.Phases.ContextCompress,
	} {
		m.Recipe.Phases[name] = phaseRecipe(phase, cfg)
		m.Execution.Phases[name] = sarif.PhaseExecution{Status: "pending"}
	}
	if cfg.SkipAudit {
		setPhaseStatus(m, "audit", "skipped", "disabled")
	}
	if cfg.SkipFeatureDetection {
		setPhaseStatus(m, "feature-detection", "skipped", "disabled")
	}
	setPhaseStatus(m, "context-compress", "skipped", "no eligible sources")
	if cfg.CustomRequirements != "" {
		m.Recipe.CustomRequirementsFingerprint = fingerprint([]byte(cfg.CustomRequirements))
	}
	for i, source := range cfg.ContextSources {
		name := source.Name
		if name == "" {
			name = fmt.Sprintf("context-%d", i+1)
		}
		m.Recipe.ContextSources = append(m.Recipe.ContextSources, sarif.ContextIdentity{
			Name: name, Type: strings.ToLower(source.Type), Priority: source.Priority, Compress: source.Compress,
			Phases: append([]string{}, source.Phases...), Include: append([]string{}, source.Include...), Exclude: append([]string{}, source.Exclude...),
		})
		m.Execution.ContextSources = append(m.Execution.ContextSources, sarif.ContextExecution{SourceIndex: i, Status: "not_loaded", Compression: "not_requested"})
	}
	if cfg.Decisions.AnyEnabled() || cfg.Decisions.DependencyGrouping {
		d := cfg.Decisions
		m.Recipe.Decisions = &sarif.DecisionRecipe{DependencyGrouping: d.DependencyGrouping, StageCallLimits: decisionStageLimits(d), Modes: d.Modes(), Model: d.Model, Endpoint: safeURL(d.URL), Policy: decision.PolicyVersion, Timeout: d.Timeout, MaxCalls: d.MaxCalls, Retries: d.Retries, InputPrice: d.InputPrice}
	}
	return m
}

func phaseRecipe(pc config.PhaseConfig, cfg *config.Config) sarif.PhaseRecipe {
	model := pc.ModelCfg
	timeout := pc.RequestTimeout
	if timeout <= 0 {
		timeout = 600
	}
	baseURL := pc.BaseURL
	endpoint := ""
	if pc.Provider == "databricks" {
		if baseURL == "" {
			baseURL = cfg.DatabricksHost + "/serving-endpoints"
		}
		endpoint = pc.Endpoint
		if endpoint == "" {
			endpoint = model.Endpoint
		}
		endpoint = strings.TrimSuffix(endpoint, "/invocations")
	} else if baseURL == "" {
		baseURL = providerPresets[pc.Provider].baseURL
	}
	transport := "http"
	if pc.Provider == "anthropic" && pc.APIKey == "" {
		transport = "claude-cli"
		baseURL = ""
	}
	mode := "none"
	switch llm.OutputModeForConfig(model) {
	case llm.OutputModeJSONSchema:
		mode = "json_schema"
	case llm.OutputModeToolUse:
		mode = "tool_use"
	}
	return sarif.PhaseRecipe{
		Provider: pc.Provider, Model: model.Name, BaseURL: safeURL(baseURL), Endpoint: safeURL(endpoint), Transport: transport,
		ModelParams: safeParameters(pc.ModelParams), ContextLimit: model.ContextLimit, MaxOutputTokens: model.MaxOutputTokens,
		Temperature: model.Temperature, OmitTemperature: model.OmitTemperature, UseMaxCompletionTokens: model.UseMaxCompletionTokens,
		OutputMode: mode, RequestTimeoutSeconds: timeout, Tokenizer: model.Encoding,
		Pricing: sarif.ModelPricing{
			InputPerMillion: model.InputPricePerM, OutputPerMillion: model.OutputPricePerM,
			LongContextThreshold: model.LongContextThreshold, LongContextInputPerMillion: model.LongContextInputPricePerM,
			LongContextOutputPerMillion: model.LongContextOutputPricePerM,
		},
	}
}

func safeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	u.User, u.RawQuery, u.Fragment, u.RawFragment, u.ForceQuery = nil, "", "", "", false
	return u.String()
}

// Values with arbitrary text are represented by a digest, not copied. Numeric
// tuning values and a small set of enumerations are safe to show directly.
func safeParameters(params map[string]any) map[string]any {
	out := map[string]any{}
	for key, value := range params {
		k := strings.ToLower(strings.NewReplacer("_", "", "-", "", ".", "").Replace(key))
		if strings.Contains(k, "apikey") || strings.Contains(k, "secret") || strings.Contains(k, "password") ||
			strings.Contains(k, "credential") || strings.Contains(k, "authorization") || strings.Contains(k, "header") ||
			strings.HasSuffix(k, "token") || strings.Contains(k, "bearer") {
			continue
		}
		if nested, ok := value.(map[string]any); ok {
			out[key] = safeParameters(nested)
			continue
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			out[key] = map[string]any{"omitted": true}
			continue
		}
		// Marshal/unmarshal normalizes the numeric types produced by YAML,
		// Viper and programmatic callers without assuming a concrete Go type.
		var scalar any
		_ = json.Unmarshal(encoded, &scalar)
		safe := false
		switch key {
		case "temperature", "top_p", "top_k", "seed", "max_tokens", "max_completion_tokens", "max_output_tokens", "budget_tokens", "frequency_penalty", "presence_penalty", "n":
			_, safe = scalar.(float64)
		case "stream", "parallel_tool_calls":
			_, safe = scalar.(bool)
		case "reasoning_effort", "effort":
			s, ok := scalar.(string)
			safe = ok && (s == "none" || s == "minimal" || s == "low" || s == "medium" || s == "high" || s == "xhigh" || s == "max")
		case "type":
			s, ok := scalar.(string)
			safe = ok && (s == "enabled" || s == "disabled" || s == "adaptive" || s == "json_object" || s == "json_schema")
		}
		if safe {
			out[key] = scalar
		} else {
			out[key] = map[string]any{"omitted": true, "fingerprint": fingerprint(encoded)}
		}
	}
	return out
}

func setPhaseStatus(m *sarif.ScanMetadata, phase, status, reason string) {
	state := m.Execution.Phases[phase]
	state.Status, state.Reason = status, reason
	m.Execution.Phases[phase] = state
}

func recordActualPhase(m *sarif.ScanMetadata, phase string, pc config.PhaseConfig, cfg *config.Config, fallback bool) {
	actual := phaseRecipe(pc, cfg)
	state := m.Execution.Phases[phase]
	state.Actual = &actual
	if actual.Transport == "claude-cli" {
		state.RequestPolicy = "Claude CLI manages sampling and output limits; configured modelParams are not forwarded"
		state.Actual.ModelParams = map[string]any{}
		state.Actual.MaxOutputTokens = 0
		state.Actual.Temperature = 0
		state.Actual.OmitTemperature = true
		state.Actual.OutputMode = "json_schema"
	}
	if fallback {
		state.Fallback = "analysis client"
	}
	m.Execution.Phases[phase] = state
}

// prepareSARIF is the output boundary shared by final and intermediate files.
// Deep-copy metadata: audit changes must not retroactively alter analysis.
func prepareSARIF(doc sarif.SARIFDocument, metadata *sarif.ScanMetadata, stage string) (sarif.SARIFDocument, error) {
	doc = sarif.ReviewPresentation(doc)
	if metadata == nil {
		return doc, nil
	}
	recipe, err := json.Marshal(metadata.Recipe)
	if err != nil {
		return doc, fmt.Errorf("encoding scan recipe: %w", err)
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		return doc, fmt.Errorf("encoding scan metadata: %w", err)
	}
	var snapshot sarif.ScanMetadata
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return doc, err
	}
	snapshot.RecipeFingerprint = fingerprint(recipe)
	snapshot.Execution.ArtifactStage = stage
	for i := range doc.Runs {
		doc.Runs[i].Properties = &sarif.RunProperties{CodeCrucible: &snapshot}
		doc.Runs[i].Tool.Driver.Version = snapshot.Recipe.ToolVersion
	}
	return doc, nil
}

func recordChunkOutcome(m *sarif.ScanMetadata, doc sarif.SARIFDocument, err error) {
	if err != nil || scanExecutionError(doc) != nil || len(doc.Runs) == 0 {
		m.Execution.Chunks.Failed++
	} else {
		m.Execution.Chunks.Completed++
	}
}

func recordDecisionPhase(m *sarif.ScanMetadata, phase string, d config.Decisions) {
	state := m.Execution.Phases[phase]
	state.Status = "completed"
	state.Actual = &sarif.PhaseRecipe{Provider: "typesafe", Model: d.Model, BaseURL: safeURL(d.URL), Transport: "http", OutputMode: "typed_decisions", RequestTimeoutSeconds: d.Timeout, ContextLimit: 64000, Tokenizer: "conservative_utf8_bytes", Pricing: sarif.ModelPricing{InputPerMillion: d.InputPrice}}
	state.RequestPolicy = "Bounded typed Jev decisions; source coverage and evidence checks required; uncertain findings use the generative auditor"
	m.Execution.Phases[phase] = state
}
