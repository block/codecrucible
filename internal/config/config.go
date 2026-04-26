package config

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/viper"
)

// Config holds the application configuration loaded from Viper.
type Config struct {
	// Global options
	Verbose bool `mapstructure:"verbose"`

	// Scan options
	Paths                 []string       `mapstructure:"paths"`
	Model                 string         `mapstructure:"model"`
	FailOnSeverity        float64        `mapstructure:"fail-on-severity"`
	MaxCost               float64        `mapstructure:"max-cost"`
	DryRun                bool           `mapstructure:"dry-run"`
	IncludeTests          bool           `mapstructure:"include-tests"`
	IncludeDocs           bool           `mapstructure:"include-docs"`
	Compress              bool           `mapstructure:"compress"`
	CustomRequirements    string         `mapstructure:"custom-requirements"`
	SkipFeatureDetection  bool           `mapstructure:"skip-feature-detection"`
	FeatureDetectionModel string         `mapstructure:"feature-detection-model"`
	Concurrency           int            `mapstructure:"concurrency"`
	Output                string         `mapstructure:"output"`
	PhaseOutputDir        string         `mapstructure:"phase-output-dir"`
	PromptsDir            string         `mapstructure:"prompts-dir"`
	Include               []string       `mapstructure:"include"`
	Exclude               []string       `mapstructure:"exclude"`
	CustomHeaders         []string       `mapstructure:"custom-headers"`
	BaseURL               string         `mapstructure:"base-url"`
	ModelParams           map[string]any `mapstructure:"model-params"`
	ModelParamsJSON       string         `mapstructure:"model-params-json"`
	MaxFileSize           int            `mapstructure:"max-file-size"`
	ContextLimit          int            `mapstructure:"context-limit"`
	MaxOutputTokens       int            `mapstructure:"max-output-tokens"`
	RequestTimeout        int            `mapstructure:"request-timeout"` // seconds; 0 = client default

	// Audit phase
	SkipAudit                bool    `mapstructure:"skip-audit"`
	AuditModel               string  `mapstructure:"audit-model"`
	AuditConfidenceThreshold float64 `mapstructure:"audit-confidence-threshold"`
	AuditBatchSize           int     `mapstructure:"audit-batch-size"`

	// Supplementary context: reference material injected into analysis and
	// audit prompts. See internal/supctx.
	ContextSources    []ContextSource `mapstructure:"context-sources"`
	ContextBudgetPct  int             `mapstructure:"context-budget-pct"`  // % of context window reserved for sources (default 15, max 40)
	ContextSourcesRaw []string        `mapstructure:"context-sources-raw"` // CLI form: "name=X,type=Y,location=Z,priority=N"

	// Provider selection
	Provider string `mapstructure:"provider"` // "databricks", "anthropic", "openai", "google" (auto-detected if empty)

	// Databricks options (from env vars)
	DatabricksHost     string `mapstructure:"databricks-host"`
	DatabricksToken    string `mapstructure:"databricks-token"`
	DatabricksEndpoint string `mapstructure:"databricks-endpoint"`

	// Anthropic options (from env vars)
	AnthropicAPIKey string `mapstructure:"anthropic-api-key"`

	// OpenAI options (from env vars)
	OpenAIAPIKey string `mapstructure:"openai-api-key"`

	// Google options (from env vars)
	GoogleAPIKey string `mapstructure:"google-api-key"`

	// Phases carries per-phase (provider, model, api_key, model_params,
	// ...) tuples. The flat fields above act as defaults for the analysis
	// phase; feature-detection and audit inherit from analysis. See
	// ResolvePhases. Populated by config file (phases.audit.provider: ...)
	// or env (PHASES_AUDIT_PROVIDER=...).
	Phases Phases `mapstructure:"phases"`

	// Models extends (or overrides) the built-in model registry. Each entry
	// is passed to RegisterModel at Load time, keyed by Name — so user
	// entries sharing a built-in name replace the built-in wholesale. Lets
	// operators add a new provider endpoint or retune pricing / context
	// limits without recompiling. See RegisterUserModels.
	Models []ModelConfig `mapstructure:"models"`
}

// Load reads configuration from the given Viper instance.
// Priority chain: flags > env > config file > defaults.
// The caller is responsible for setting up flag bindings and calling
// viper.ReadInConfig() before calling Load.
func Load(v *viper.Viper) (*Config, error) {
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	if cfg.ModelParams == nil {
		cfg.ModelParams = map[string]any{}
	}
	if strings.TrimSpace(cfg.ModelParamsJSON) != "" {
		var override map[string]any
		if err := json.Unmarshal([]byte(cfg.ModelParamsJSON), &override); err != nil {
			return nil, fmt.Errorf("parsing model-params-json: %w", err)
		}
		if override == nil {
			override = map[string]any{}
		}
		mergeMaps(cfg.ModelParams, override)
	}

	// Parse CLI-form context sources and append to any from the config file.
	for _, raw := range cfg.ContextSourcesRaw {
		cs, err := parseContextSourceKV(raw)
		if err != nil {
			return nil, fmt.Errorf("parsing --context-source %q: %w", raw, err)
		}
		cfg.ContextSources = append(cfg.ContextSources, cs)
	}

	// Merge user-declared models into the global registry. Entries sharing a
	// name with a built-in replace it; new names extend. Running this on
	// every Load is a no-op when cfg.Models is empty, and idempotent (same
	// entry twice) when it isn't.
	if err := RegisterUserModels(cfg.Models); err != nil {
		return nil, fmt.Errorf("registering models from config: %w", err)
	}

	return &cfg, nil
}

// SetDefaults configures the default values for all config keys.
func SetDefaults(v *viper.Viper) {
	v.SetDefault("verbose", false)
	v.SetDefault("model", "")
	v.SetDefault("fail-on-severity", float64(0))
	v.SetDefault("max-cost", float64(25)) //Set to $25 as a default
	v.SetDefault("dry-run", false)
	v.SetDefault("include-tests", false)
	v.SetDefault("include-docs", false)
	v.SetDefault("compress", false)
	v.SetDefault("custom-requirements", "")
	v.SetDefault("skip-feature-detection", false)
	v.SetDefault("feature-detection-model", "")
	v.SetDefault("concurrency", 3)
	v.SetDefault("output", "")
	v.SetDefault("phase-output-dir", "")
	v.SetDefault("prompts-dir", "")
	v.SetDefault("custom-headers", []string{})
	v.SetDefault("model-params", map[string]any{})
	v.SetDefault("model-params-json", "")
	v.SetDefault("provider", "")
	v.SetDefault("base-url", "")
	v.SetDefault("max-file-size", 102400) // 100KB
	v.SetDefault("context-limit", 0)      // 0 = use model registry default
	v.SetDefault("max-output-tokens", 0)  // 0 = use model registry default
	v.SetDefault("request-timeout", 0)    // 0 = use client default (600s)
	v.SetDefault("skip-audit", false)
	v.SetDefault("audit-model", "")
	v.SetDefault("audit-confidence-threshold", 0.3)
	v.SetDefault("audit-batch-size", 25)
	v.SetDefault("context-budget-pct", 15)
	v.SetDefault("context-sources-raw", []string{})
}

// BindEnvVars binds environment variables to Viper keys.
func BindEnvVars(v *viper.Viper) {
	// "-" → "_" lets flat keys like context-limit map to CONTEXT_LIMIT.
	// "." → "_" lets nested keys like phases.audit.provider map to
	// PHASES_AUDIT_PROVIDER. No existing key contains a dot, so this is
	// additive.
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	v.AutomaticEnv()

	// Explicit bindings for Databricks env vars
	_ = v.BindEnv("databricks-host", "DATABRICKS_HOST")
	_ = v.BindEnv("databricks-token", "DATABRICKS_TOKEN")
	_ = v.BindEnv("databricks-endpoint", "DATABRICKS_ENDPOINT")

	// Direct-provider key bindings — these populate the legacy flat fields
	// which ResolvePhases then cascades to any phase that didn't set its own.
	_ = v.BindEnv("anthropic-api-key", "ANTHROPIC_API_KEY")
	_ = v.BindEnv("openai-api-key", "OPENAI_API_KEY")
	_ = v.BindEnv("google-api-key", "GOOGLE_API_KEY", "GEMINI_API_KEY")
	_ = v.BindEnv("provider", "CODECRUCIBLE_PROVIDER")
	_ = v.BindEnv("model-params-json", "CODECRUCIBLE_MODEL_PARAMS")

	// Per-phase nested keys: AutomaticEnv only picks up env vars for keys
	// viper already knows about. Unmarshal into a nested struct doesn't
	// pre-register the leaves, so bind the env-shaped ones explicitly.
	// Config-file users don't need this — only the env path does.
	for _, phase := range []string{"analysis", "feature-detection", "audit", "context-compress"} {
		for _, leaf := range []string{
			"provider", "model", "api-key", "base-url", "endpoint",
			"model-params-json", "request-timeout",
			"context-limit", "max-output-tokens",
		} {
			_ = v.BindEnv("phases." + phase + "." + leaf)
		}
	}
}

func mergeMaps(dst, src map[string]any) {
	for k, v := range src {
		existing, ok := dst[k]
		if !ok {
			dst[k] = v
			continue
		}

		existingMap, existingIsMap := existing.(map[string]any)
		srcMap, srcIsMap := v.(map[string]any)
		if existingIsMap && srcIsMap {
			mergeMaps(existingMap, srcMap)
			dst[k] = existingMap
			continue
		}

		dst[k] = v
	}
}

// SetupViper initializes a Viper instance with defaults, env bindings,
// and optional config file. This does NOT bind CLI flags — that is
// done in the CLI layer.
// Returns an error if a config file exists but cannot be parsed.
func SetupViper(configFile string) (*viper.Viper, error) {
	v := viper.New()
	SetDefaults(v)
	BindEnvVars(v)

	if configFile != "" {
		v.SetConfigFile(configFile)
	} else {
		v.SetConfigName(".codecrucible")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("$HOME")
	}

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
	}

	return v, nil
}

// ContextSource mirrors supctx.Source for config unmarshal. Defined here so
// the config package stays free of internal dependencies.
type ContextSource struct {
	Name     string   `mapstructure:"name"`
	Type     string   `mapstructure:"type"`     // "path" | "repo" | "url" | "inline"
	Location string   `mapstructure:"location"` // path, git URL, HTTP URL, or literal text
	Priority int      `mapstructure:"priority"`
	Compress bool     `mapstructure:"compress"`
	Phases   []string `mapstructure:"phases"` // empty = all phases
	Include  []string `mapstructure:"include"`
	Exclude  []string `mapstructure:"exclude"`
}

// parseContextSourceKV parses the CLI form "name=X,type=Y,location=Z,priority=N".
// Only scalar fields are supported on the CLI — use the config file for
// include/exclude globs and phase lists.
func parseContextSourceKV(raw string) (ContextSource, error) {
	var cs ContextSource
	for _, pair := range strings.Split(raw, ",") {
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			return cs, fmt.Errorf("expected key=value, got %q", pair)
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch k {
		case "name":
			cs.Name = v
		case "type":
			cs.Type = v
		case "location":
			cs.Location = v
		case "priority":
			p, err := strconv.Atoi(v)
			if err != nil {
				return cs, fmt.Errorf("priority must be an integer: %w", err)
			}
			cs.Priority = p
		case "compress":
			b, err := strconv.ParseBool(v)
			if err != nil {
				return cs, fmt.Errorf("compress must be a boolean: %w", err)
			}
			cs.Compress = b
		default:
			return cs, fmt.Errorf("unknown key %q", k)
		}
	}
	if cs.Type == "" || cs.Location == "" {
		return cs, fmt.Errorf("type and location are required")
	}
	return cs, nil
}
