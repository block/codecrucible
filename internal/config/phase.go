package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
)

// PhaseConfig carries everything one pipeline phase needs to construct its
// own LLM client and ChatRequest, independent of the other phases.
//
// The zero value inherits: any field left at its zero value on the
// feature-detection or audit phase is filled from the analysis phase by
// ResolvePhases. For ModelParams, "zero" means len == 0 — a phase that
// genuinely needs to clear inherited params can set {"_":""} or similar,
// but in practice nobody wants that.
//
// ModelCfg is an output: ResolvePhases populates it from the registry with
// ContextLimit / MaxOutputTokens overrides applied. Callers read ModelCfg
// for pricing, tokenizer encoding, and request limits; they do not set it.
type PhaseConfig struct {
	// Provider selects the HTTP client flavour: anthropic, openai, google,
	// databricks. Empty inherits (analysis phase: auto-detects from env).
	Provider string `mapstructure:"provider"`

	// Model is the model name sent in the request body. Drives registry
	// lookup for ModelCfg.
	Model string `mapstructure:"model"`

	// APIKey authenticates this phase's client. Per-phase so you can hit
	// Anthropic for analysis and Google for audit without either key
	// leaking into the wrong Authorization header.
	APIKey string `mapstructure:"api-key"`

	// BaseURL overrides the hardcoded per-provider default. Use for proxies,
	// Azure OpenAI, Vertex-vs-AI-Studio, local mock servers. Empty = default.
	BaseURL string `mapstructure:"base-url"`

	// Endpoint is the Databricks serving-endpoint path segment. Ignored by
	// other providers.
	Endpoint string `mapstructure:"endpoint"`

	// ModelParams is merged into the top level of the request body (see
	// llm.marshalWithModelParams). Per-phase so e.g. the audit phase can
	// drop thinking-mode params that only the analysis phase needs.
	ModelParams map[string]any `mapstructure:"model-params"`

	// ModelParamsJSON is the CLI/env string form — parsed and merged into
	// ModelParams by ResolvePhases. Config-file users set ModelParams as a
	// YAML map directly and leave this empty.
	ModelParamsJSON string `mapstructure:"model-params-json"`

	// RequestTimeout is the per-request HTTP timeout in seconds. Covers the
	// full body read, so for streaming responses it bounds total generation
	// time. 0 = inherit (analysis: client default 600s).
	RequestTimeout int `mapstructure:"request-timeout"`

	// Headers are extra HTTP headers in "Name: Value" form, parsed by the
	// CLI layer.
	Headers []string `mapstructure:"headers"`

	// ContextLimit overrides the registry's context window for chunk-budget
	// math. Only the analysis phase's value affects chunking, but we carry
	// it per-phase so a fresh registry lookup for an audit model doesn't
	// silently drop the override (the prior code had that bug).
	ContextLimit int `mapstructure:"context-limit"`

	// MaxOutputTokens overrides the registry's max output. Becomes
	// ChatRequest.MaxTokens.
	MaxOutputTokens int `mapstructure:"max-output-tokens"`

	// ModelCfg is the resolved registry entry with overrides applied.
	// Populated by ResolvePhases; never set directly.
	ModelCfg ModelConfig `mapstructure:"-"`
}

// Phases groups the three pipeline phase configs. Lives on Config under
// mapstructure:"phases" so config-file users write:
//
//	phases:
//	  analysis:
//	    model: claude-opus-4-6
//	  audit:
//	    provider: google
//	    model: gemini-3-pro
//	    api-key: ${GOOGLE_API_KEY}
//
// Env var form (see BindEnvVars replacer): PHASES_AUDIT_PROVIDER,
// PHASES_AUDIT_MODEL, PHASES_AUDIT_API_KEY, PHASES_AUDIT_MODEL_PARAMS_JSON.
type Phases struct {
	Analysis         PhaseConfig `mapstructure:"analysis"`
	FeatureDetection PhaseConfig `mapstructure:"feature-detection"`
	Audit            PhaseConfig `mapstructure:"audit"`
	ContextCompress  PhaseConfig `mapstructure:"context-compress"`
}

// ResolvePhases fills Config.Phases from legacy globals and applies the
// inheritance cascade. Call once after Load.
//
// Cascade, in order:
//  1. Analysis phase is seeded from legacy flat fields (cfg.Model,
//     cfg.Provider, cfg.ModelParams, ...). Anything already set on
//     cfg.Phases.Analysis (config file, per-phase env) wins.
//  2. FeatureDetection and Audit inherit any zero-valued field from the
//     resolved Analysis phase. Legacy per-phase flags (cfg.AuditModel,
//     cfg.FeatureDetectionModel) act as overrides.
//  3. Each phase's ModelCfg is looked up from the registry and patched
//     with that phase's ContextLimit / MaxOutputTokens overrides. This
//     fixes the prior bug where --context-limit only patched the main
//     model and a separate --audit-model got fresh registry values.
//  4. Provider auto-detect runs per-phase: registry hint, then which key
//     is set on this phase, then ambient Databricks env. --provider (the
//     legacy global) acts as a default, not a per-phase override — so
//     setting phases.audit.provider beats --provider for the audit phase
//     but --provider still applies to phases that don't set their own.
func ResolvePhases(cfg *Config) error {
	// ── 1. Analysis: legacy globals as the base layer ──────────────────
	base := PhaseConfig{
		Provider:        cfg.Provider,
		Model:           cfg.Model,
		BaseURL:         cfg.BaseURL,
		ModelParams:     cfg.ModelParams,
		RequestTimeout:  cfg.RequestTimeout,
		Headers:         cfg.CustomHeaders,
		ContextLimit:    cfg.ContextLimit,
		MaxOutputTokens: cfg.MaxOutputTokens,
		Endpoint:        cfg.DatabricksEndpoint,
		// APIKey: left empty — picked per-provider in step 4.
	}
	overlay(&base, &cfg.Phases.Analysis)
	if err := parsePhaseParams(&base, "analysis"); err != nil {
		return err
	}
	cfg.Phases.Analysis = base

	// ── 2. Secondary phases: inherit from analysis, then overlay ───────
	secondaries := []struct {
		name        string
		legacyModel string // --audit-model / --feature-detection-model
		dst         *PhaseConfig
	}{
		{"feature-detection", cfg.FeatureDetectionModel, &cfg.Phases.FeatureDetection},
		{"audit", cfg.AuditModel, &cfg.Phases.Audit},
		{"context-compress", "", &cfg.Phases.ContextCompress},
	}
	for _, s := range secondaries {
		pc := base // value copy — inherit everything
		// ModelParams is a map: the value copy aliases the same backing
		// store. Break the alias so a phase that sets its own params
		// doesn't mutate analysis's, and so downstream mergeMaps has a
		// distinct target.
		pc.ModelParams = cloneParams(base.ModelParams)

		// Legacy per-phase model flag is an override only when set —
		// otherwise the inherited analysis model stands.
		if s.legacyModel != "" {
			pc.Model = s.legacyModel
		}

		overlay(&pc, s.dst)
		if err := parsePhaseParams(&pc, s.name); err != nil {
			return err
		}
		*s.dst = pc
	}

	// ── 3. Resolve registry + apply overrides, per phase ───────────────
	for name, pc := range allPhases(cfg) {
		pc.ModelCfg = lookupOrDefault(pc.Model, name)
		if pc.ContextLimit > 0 {
			slog.Info("overriding model context limit",
				"phase", name, "registry", pc.ModelCfg.ContextLimit, "override", pc.ContextLimit)
			pc.ModelCfg.ContextLimit = pc.ContextLimit
		}
		if pc.MaxOutputTokens > 0 {
			slog.Info("overriding model max output tokens",
				"phase", name, "registry", pc.ModelCfg.MaxOutputTokens, "override", pc.MaxOutputTokens)
			pc.ModelCfg.MaxOutputTokens = pc.MaxOutputTokens
		}
	}

	// ── 4. Provider + API key resolution, per phase ────────────────────
	for name, pc := range allPhases(cfg) {
		if pc.Provider == "" {
			pc.Provider = detectProvider(pc, cfg)
		}
		if pc.APIKey == "" {
			pc.APIKey = ambientKey(pc.Provider, cfg)
		}
		slog.Debug("phase resolved",
			"phase", name, "provider", pc.Provider, "model", pc.ModelCfg.Name,
			"has_api_key", pc.APIKey != "", "base_url", pc.BaseURL)
	}

	return nil
}

// overlay copies every non-zero field from src onto dst. This is how a
// phase-specific config (from config file or PHASES_* env) beats the
// inherited/legacy value. Field-by-field because reflect would be overkill
// for a dozen fields and hides what "non-zero" means for each type.
func overlay(dst, src *PhaseConfig) {
	if src.Provider != "" {
		dst.Provider = src.Provider
	}
	if src.Model != "" {
		dst.Model = src.Model
	}
	if src.APIKey != "" {
		dst.APIKey = src.APIKey
	}
	if src.BaseURL != "" {
		dst.BaseURL = src.BaseURL
	}
	if src.Endpoint != "" {
		dst.Endpoint = src.Endpoint
	}
	if len(src.ModelParams) > 0 {
		// Replace, don't merge — a phase that sets its own params gets
		// exactly those params. Inheritance already gave dst the analysis
		// params as a starting point; overlaying means "I want these
		// instead." Merge-on-overlay would make it impossible to drop an
		// inherited key.
		dst.ModelParams = cloneParams(src.ModelParams)
	}
	if src.ModelParamsJSON != "" {
		dst.ModelParamsJSON = src.ModelParamsJSON
	}
	if src.RequestTimeout > 0 {
		dst.RequestTimeout = src.RequestTimeout
	}
	if len(src.Headers) > 0 {
		dst.Headers = src.Headers
	}
	if src.ContextLimit > 0 {
		dst.ContextLimit = src.ContextLimit
	}
	if src.MaxOutputTokens > 0 {
		dst.MaxOutputTokens = src.MaxOutputTokens
	}
}

// parsePhaseParams decodes the JSON-string form of model params and merges
// it into the map form. The string form wins on conflict — it's the
// CLI/env override path.
func parsePhaseParams(pc *PhaseConfig, phase string) error {
	if pc.ModelParams == nil {
		pc.ModelParams = map[string]any{}
	}
	s := strings.TrimSpace(pc.ModelParamsJSON)
	if s == "" {
		return nil
	}
	var override map[string]any
	if err := json.Unmarshal([]byte(s), &override); err != nil {
		return fmt.Errorf("parsing %s model-params-json: %w", phase, err)
	}
	mergeMaps(pc.ModelParams, override)
	return nil
}

// detectProvider picks a provider when the phase didn't set one explicitly.
// Precedence: registry hint for this phase's model, then Databricks ambient
// env (because Databricks proxies all providers — if it's configured, route
// through it), then whichever direct-provider key is set on cfg, then
// databricks as the historic default.
func detectProvider(pc *PhaseConfig, cfg *Config) string {
	if pc.ModelCfg.Provider != "" {
		// Registry knows — but Databricks proxies everything, so if both
		// Databricks env and a direct key are set, prefer Databricks.
		// This preserves the prior resolveProvider behaviour.
		if cfg.DatabricksHost != "" && cfg.DatabricksToken != "" {
			return "databricks"
		}
		return pc.ModelCfg.Provider
	}
	if cfg.DatabricksHost != "" && cfg.DatabricksToken != "" {
		return "databricks"
	}
	if cfg.AnthropicAPIKey != "" {
		return "anthropic"
	}
	if cfg.OpenAIAPIKey != "" {
		return "openai"
	}
	if cfg.GoogleAPIKey != "" {
		return "google"
	}
	// No credentials detected — fall back to anthropic (Claude CLI can
	// authenticate without an API key) rather than databricks which
	// requires host+token env vars.
	return "anthropic"
}

// ambientKey returns the global provider-specific key from cfg when the
// phase didn't set its own. Databricks auth is host+token, not a single
// key, so it's handled in the client builder instead.
func ambientKey(provider string, cfg *Config) string {
	switch provider {
	case "anthropic":
		return cfg.AnthropicAPIKey
	case "openai":
		return cfg.OpenAIAPIKey
	case "google":
		return cfg.GoogleAPIKey
	}
	return ""
}

func lookupOrDefault(name, phase string) ModelConfig {
	if name == "" {
		return DefaultModel()
	}
	if m, ok := LookupModel(name); ok {
		// Preserve the user-supplied name: the registry may have matched by
		// substring (databricks-claude-opus → claude-opus-4), and the API
		// wants the name the user typed.
		m.Name = name
		return m
	}
	slog.Warn("model not in registry, using defaults", "phase", phase, "model", name)
	return UnknownModelDefaults(name)
}

func cloneParams(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		// Deep-copy nested maps to prevent aliasing between phases.
		if nested, ok := v.(map[string]any); ok {
			out[k] = cloneParams(nested)
		} else {
			out[k] = v
		}
	}
	return out
}

// allPhases iterates every phase by name and pointer, for the resolve
// passes that treat them uniformly.
func allPhases(cfg *Config) func(yield func(string, *PhaseConfig) bool) {
	return func(yield func(string, *PhaseConfig) bool) {
		if !yield("analysis", &cfg.Phases.Analysis) {
			return
		}
		if !yield("feature-detection", &cfg.Phases.FeatureDetection) {
			return
		}
		if !yield("audit", &cfg.Phases.Audit) {
			return
		}
		yield("context-compress", &cfg.Phases.ContextCompress)
	}
}
