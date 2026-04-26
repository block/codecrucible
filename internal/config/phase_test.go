package config

import (
	"reflect"
	"testing"
)

func TestResolvePhases_InheritFromLegacy(t *testing.T) {
	// Nothing per-phase set: all three phases should end up identical,
	// seeded from the legacy flat fields.
	cfg := &Config{
		Model:           "claude-opus-4-6",
		Provider:        "anthropic",
		AnthropicAPIKey: "sk-ant-legacy",
		ModelParams:     map[string]any{"temperature": 0.0},
		RequestTimeout:  1800,
		ContextLimit:    500000,
		MaxOutputTokens: 128000,
	}
	if err := ResolvePhases(cfg); err != nil {
		t.Fatalf("ResolvePhases: %v", err)
	}

	for name, pc := range allPhases(cfg) {
		if pc.Provider != "anthropic" {
			t.Errorf("%s.Provider = %q, want anthropic", name, pc.Provider)
		}
		if pc.APIKey != "sk-ant-legacy" {
			t.Errorf("%s.APIKey = %q, want sk-ant-legacy", name, pc.APIKey)
		}
		if pc.RequestTimeout != 1800 {
			t.Errorf("%s.RequestTimeout = %d, want 1800", name, pc.RequestTimeout)
		}
		if pc.ModelCfg.ContextLimit != 500000 {
			t.Errorf("%s.ModelCfg.ContextLimit = %d, want 500000 (override applied)", name, pc.ModelCfg.ContextLimit)
		}
		if pc.ModelCfg.MaxOutputTokens != 128000 {
			t.Errorf("%s.ModelCfg.MaxOutputTokens = %d, want 128000 (override applied)", name, pc.ModelCfg.MaxOutputTokens)
		}
	}
}

func TestResolvePhases_PerPhaseOverride(t *testing.T) {
	// Audit phase sets its own provider + key + model; analysis and
	// feature-detection stay on the legacy values. This is the headline
	// use case: audit on a different provider entirely.
	cfg := &Config{
		Model:           "claude-opus-4-6",
		AnthropicAPIKey: "sk-ant-analysis",
		Phases: Phases{
			Audit: PhaseConfig{
				Provider: "google",
				Model:    "gemini-3-pro",
				APIKey:   "goog-audit",
			},
		},
	}
	if err := ResolvePhases(cfg); err != nil {
		t.Fatalf("ResolvePhases: %v", err)
	}

	if cfg.Phases.Analysis.Provider != "anthropic" {
		t.Errorf("analysis.Provider = %q, want anthropic (from registry)", cfg.Phases.Analysis.Provider)
	}
	if cfg.Phases.Analysis.APIKey != "sk-ant-analysis" {
		t.Errorf("analysis.APIKey = %q, want sk-ant-analysis", cfg.Phases.Analysis.APIKey)
	}

	if cfg.Phases.Audit.Provider != "google" {
		t.Errorf("audit.Provider = %q, want google", cfg.Phases.Audit.Provider)
	}
	if cfg.Phases.Audit.APIKey != "goog-audit" {
		t.Errorf("audit.APIKey = %q, want goog-audit (per-phase, not inherited)", cfg.Phases.Audit.APIKey)
	}
	if cfg.Phases.Audit.ModelCfg.Name != "gemini-3-pro" {
		t.Errorf("audit.ModelCfg.Name = %q, want gemini-3-pro", cfg.Phases.Audit.ModelCfg.Name)
	}
	// ContextLimit should come from the gemini registry entry, not
	// inherited from claude.
	if cfg.Phases.Audit.ModelCfg.ContextLimit != 1048576 {
		t.Errorf("audit.ModelCfg.ContextLimit = %d, want 1048576 (gemini registry)", cfg.Phases.Audit.ModelCfg.ContextLimit)
	}

	// Feature-detection inherits everything from analysis.
	if cfg.Phases.FeatureDetection.Provider != "anthropic" {
		t.Errorf("fd.Provider = %q, want anthropic (inherited)", cfg.Phases.FeatureDetection.Provider)
	}
}

func TestResolvePhases_LegacyAuditModelStillWorks(t *testing.T) {
	// --audit-model (the legacy flag) should still override the model for
	// the audit phase without touching provider/key.
	cfg := &Config{
		Model:           "claude-opus-4-6",
		AnthropicAPIKey: "sk-ant",
		AuditModel:      "claude-sonnet-4-6",
	}
	if err := ResolvePhases(cfg); err != nil {
		t.Fatalf("ResolvePhases: %v", err)
	}

	if cfg.Phases.Audit.ModelCfg.Name != "claude-sonnet-4-6" {
		t.Errorf("audit model = %q, want claude-sonnet-4-6", cfg.Phases.Audit.ModelCfg.Name)
	}
	if cfg.Phases.Audit.Provider != "anthropic" {
		t.Errorf("audit provider = %q, want anthropic (inherited)", cfg.Phases.Audit.Provider)
	}
	if cfg.Phases.Audit.APIKey != "sk-ant" {
		t.Errorf("audit key = %q, want sk-ant (inherited)", cfg.Phases.Audit.APIKey)
	}
}

func TestResolvePhases_ModelParamsNotAliased(t *testing.T) {
	// Mutating the audit phase's ModelParams after resolve must not
	// mutate the analysis phase's — the inheritance must have broken
	// the map alias.
	cfg := &Config{
		Model:           "claude-opus-4-6",
		AnthropicAPIKey: "k",
		ModelParams:     map[string]any{"max_tokens": 1000},
	}
	if err := ResolvePhases(cfg); err != nil {
		t.Fatalf("ResolvePhases: %v", err)
	}

	cfg.Phases.Audit.ModelParams["max_tokens"] = 9999

	if cfg.Phases.Analysis.ModelParams["max_tokens"] != 1000 {
		t.Errorf("analysis.ModelParams mutated by audit write: %v", cfg.Phases.Analysis.ModelParams)
	}
	if cfg.Phases.FeatureDetection.ModelParams["max_tokens"] != 1000 {
		t.Errorf("fd.ModelParams mutated by audit write: %v", cfg.Phases.FeatureDetection.ModelParams)
	}
}

func TestResolvePhases_PerPhaseModelParamsReplace(t *testing.T) {
	// A phase that sets its own model-params gets exactly those params,
	// not a merge with the inherited ones. The whole point of per-phase
	// params is being able to DROP an inherited key (e.g. thinking-mode
	// params that only analysis needs).
	cfg := &Config{
		Model:           "claude-opus-4-6",
		AnthropicAPIKey: "k",
		ModelParams:     map[string]any{"thinking": map[string]any{"type": "enabled"}, "max_tokens": 32000},
		Phases: Phases{
			Audit: PhaseConfig{
				ModelParams: map[string]any{"max_tokens": 8000},
			},
		},
	}
	if err := ResolvePhases(cfg); err != nil {
		t.Fatalf("ResolvePhases: %v", err)
	}

	want := map[string]any{"max_tokens": 8000}
	if !reflect.DeepEqual(cfg.Phases.Audit.ModelParams, want) {
		t.Errorf("audit.ModelParams = %v, want %v (replace, not merge — thinking key should be gone)",
			cfg.Phases.Audit.ModelParams, want)
	}
	// Analysis keeps its own.
	if _, ok := cfg.Phases.Analysis.ModelParams["thinking"]; !ok {
		t.Error("analysis.ModelParams lost thinking key")
	}
}

func TestResolvePhases_ModelParamsJSON(t *testing.T) {
	cfg := &Config{
		Model:           "claude-opus-4-6",
		AnthropicAPIKey: "k",
		Phases: Phases{
			Audit: PhaseConfig{
				ModelParamsJSON: `{"max_tokens": 4096, "tool_choice": {"type": "auto"}}`,
			},
		},
	}
	if err := ResolvePhases(cfg); err != nil {
		t.Fatalf("ResolvePhases: %v", err)
	}

	if cfg.Phases.Audit.ModelParams["max_tokens"] != float64(4096) {
		t.Errorf("audit max_tokens = %v, want 4096", cfg.Phases.Audit.ModelParams["max_tokens"])
	}
	tc, _ := cfg.Phases.Audit.ModelParams["tool_choice"].(map[string]any)
	if tc["type"] != "auto" {
		t.Errorf("audit tool_choice = %v, want {type:auto}", cfg.Phases.Audit.ModelParams["tool_choice"])
	}
}

func TestResolvePhases_ModelParamsJSON_Invalid(t *testing.T) {
	cfg := &Config{
		Phases: Phases{
			Audit: PhaseConfig{ModelParamsJSON: `{not json`},
		},
	}
	err := ResolvePhases(cfg)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestResolvePhases_GoogleAmbientKey(t *testing.T) {
	// No per-phase key, no Anthropic key, but GOOGLE_API_KEY is set and
	// the model is gemini → provider should auto-detect to google and
	// the key should cascade.
	cfg := &Config{
		Model:        "gemini-3-flash",
		GoogleAPIKey: "goog-ambient",
	}
	if err := ResolvePhases(cfg); err != nil {
		t.Fatalf("ResolvePhases: %v", err)
	}

	if cfg.Phases.Analysis.Provider != "google" {
		t.Errorf("provider = %q, want google (from registry)", cfg.Phases.Analysis.Provider)
	}
	if cfg.Phases.Analysis.APIKey != "goog-ambient" {
		t.Errorf("key = %q, want goog-ambient", cfg.Phases.Analysis.APIKey)
	}
}

func TestResolvePhases_ContextLimitFix(t *testing.T) {
	// Prior bug: --context-limit only patched the main modelCfg; a
	// separate --audit-model got fresh registry values without the
	// override. Now the override inherits per-phase unless the phase
	// sets its own.
	cfg := &Config{
		Model:           "claude-opus-4-6",
		AnthropicAPIKey: "k",
		ContextLimit:    777777,
		AuditModel:      "claude-sonnet-4-6", // different model, same override
	}
	if err := ResolvePhases(cfg); err != nil {
		t.Fatalf("ResolvePhases: %v", err)
	}

	if cfg.Phases.Analysis.ModelCfg.ContextLimit != 777777 {
		t.Errorf("analysis context = %d, want 777777", cfg.Phases.Analysis.ModelCfg.ContextLimit)
	}
	if cfg.Phases.Audit.ModelCfg.ContextLimit != 777777 {
		t.Errorf("audit context = %d, want 777777 (override inherited despite different model)", cfg.Phases.Audit.ModelCfg.ContextLimit)
	}
}

func TestResolvePhases_DatabricksProxiesAll(t *testing.T) {
	// When Databricks env is set, it wins over the registry's provider
	// hint — Databricks proxies all models. This is the prior behaviour
	// of resolveProvider and must be preserved.
	cfg := &Config{
		Model:           "claude-opus-4-6", // registry says anthropic
		DatabricksHost:  "https://dbx.example.com",
		DatabricksToken: "dbx-tok",
	}
	if err := ResolvePhases(cfg); err != nil {
		t.Fatalf("ResolvePhases: %v", err)
	}

	if cfg.Phases.Analysis.Provider != "databricks" {
		t.Errorf("provider = %q, want databricks (proxies anthropic)", cfg.Phases.Analysis.Provider)
	}
}

func TestDetectProvider(t *testing.T) {
	tests := []struct {
		name string
		pc   PhaseConfig
		cfg  Config
		want string
	}{
		{
			name: "registry hint wins when no databricks env",
			pc:   PhaseConfig{ModelCfg: ModelConfig{Provider: "anthropic"}},
			cfg:  Config{},
			want: "anthropic",
		},
		{
			name: "databricks env overrides registry hint",
			pc:   PhaseConfig{ModelCfg: ModelConfig{Provider: "anthropic"}},
			cfg:  Config{DatabricksHost: "https://dbx", DatabricksToken: "tok"},
			want: "databricks",
		},
		{
			name: "databricks env without registry hint",
			pc:   PhaseConfig{},
			cfg:  Config{DatabricksHost: "https://dbx", DatabricksToken: "tok"},
			want: "databricks",
		},
		{
			name: "databricks host alone is not enough",
			pc:   PhaseConfig{},
			cfg:  Config{DatabricksHost: "https://dbx", AnthropicAPIKey: "sk-ant"},
			want: "anthropic",
		},
		{
			name: "anthropic key",
			pc:   PhaseConfig{},
			cfg:  Config{AnthropicAPIKey: "sk-ant"},
			want: "anthropic",
		},
		{
			name: "openai key",
			pc:   PhaseConfig{},
			cfg:  Config{OpenAIAPIKey: "sk-oai"},
			want: "openai",
		},
		{
			name: "google key",
			pc:   PhaseConfig{},
			cfg:  Config{GoogleAPIKey: "goog"},
			want: "google",
		},
		{
			name: "anthropic beats openai when both set",
			pc:   PhaseConfig{},
			cfg:  Config{AnthropicAPIKey: "sk-ant", OpenAIAPIKey: "sk-oai"},
			want: "anthropic",
		},
		{
			name: "fallback to anthropic when nothing set",
			pc:   PhaseConfig{},
			cfg:  Config{},
			want: "anthropic",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detectProvider(&tt.pc, &tt.cfg); got != tt.want {
				t.Errorf("detectProvider() = %q, want %q", got, tt.want)
			}
		})
	}
}
