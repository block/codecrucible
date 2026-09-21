package config

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestCerebrasEnvironmentAndPhases(t *testing.T) {
	t.Setenv("CEREBRAS_API_KEY", "cerebras-test")
	v := viper.New()
	SetDefaults(v)
	BindEnvVars(v)
	v.Set("provider", "cerebras")
	v.Set("model", "custom-glm")
	cfg, err := Load(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := ResolvePhases(cfg); err != nil {
		t.Fatal(err)
	}
	for name, pc := range allPhases(cfg) {
		if pc.Provider != "cerebras" || pc.APIKey != "cerebras-test" || pc.ModelCfg.Name != "custom-glm" {
			t.Errorf("incorrect phase %s", name)
		}
	}
	if detectProvider(&PhaseConfig{}, &Config{CerebrasAPIKey: "test"}) != "cerebras" {
		t.Fatal("ambient detection failed")
	}
}

func TestCerebrasRequiresModel(t *testing.T) {
	err := ResolvePhases(&Config{Provider: "cerebras"})
	if err == nil || !strings.Contains(err.Error(), "requires an explicit model") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProviderChangeClearsInheritedSettings(t *testing.T) {
	for _, explicitProvider := range []string{"", "anthropic"} {
		cfg := &Config{Model: "claude-sonnet-5", Provider: explicitProvider, CerebrasAPIKey: "cerebras-test",
			Phases: Phases{Analysis: PhaseConfig{APIKey: "analysis-key", BaseURL: "https://analysis.invalid", Headers: []string{"x-api-key: analysis"}, ModelParams: map[string]any{"thinking": true}, ModelParamsJSON: `{"temperature":1}`},
				Audit: PhaseConfig{Provider: "cerebras", Model: "custom-glm"}}}
		if err := ResolvePhases(cfg); err != nil {
			t.Fatal(err)
		}
		audit := cfg.Phases.Audit
		if audit.APIKey != "cerebras-test" || audit.BaseURL != "" || len(audit.Headers) > 0 || len(audit.ModelParams) > 0 {
			t.Fatal("provider settings leaked into audit")
		}
		fd := cfg.Phases.FeatureDetection
		if fd.APIKey != "analysis-key" || fd.BaseURL != "https://analysis.invalid" || len(fd.ModelParams) == 0 {
			t.Fatal("same-provider inheritance lost")
		}
	}
}

func TestProviderChangePreservesExplicitSettings(t *testing.T) {
	cfg := &Config{Provider: "anthropic", Model: "claude-sonnet-5", Phases: Phases{Audit: PhaseConfig{Provider: "cerebras", Model: "custom-glm", APIKey: "override", BaseURL: "https://override.invalid", ModelParams: map[string]any{"temperature": 0.5}}}}
	if err := ResolvePhases(cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Phases.Audit.APIKey != "override" || cfg.Phases.Audit.BaseURL != "https://override.invalid" || cfg.Phases.Audit.ModelParams["temperature"] != 0.5 {
		t.Fatal("explicit overrides lost")
	}
}

func TestKimiAliasesResolveWireModelAcrossPhases(t *testing.T) {
	for _, alias := range []string{"kimi", "Kimi", "kimi-k2", "KIMI-K2.6", " kimi k2.6 ", "kimi-k2.6"} {
		t.Run(alias, func(t *testing.T) {
			cfg := &Config{Provider: "cerebras", Model: alias}
			if err := ResolvePhases(cfg); err != nil {
				t.Fatal(err)
			}
			for phase, pc := range allPhases(cfg) {
				if pc.ModelCfg.Name != "kimi-k2.6" {
					t.Errorf("%s sends %q", phase, pc.ModelCfg.Name)
				}
			}
		})
	}
	for _, name := range []string{"kimi-k3", "my-kimi-proxy", "kimi-k2.7", "databricks-claude-sonnet-5"} {
		if got := lookupOrDefault(name, "analysis").Name; got != name {
			t.Errorf("rewrote %q as %q", name, got)
		}
	}
}

func TestKimiAliasPreservesExactUserModel(t *testing.T) {
	saved := DefaultModelRegistry()
	t.Cleanup(func() { modelsMu.Lock(); defaultModels = saved; modelsMu.Unlock() })
	RegisterModel(ModelConfig{Name: "kimi", Provider: "openai-compat", ContextLimit: 64000})
	got := lookupOrDefault("kimi", "analysis")
	if got.Name != "kimi" || got.Provider != "openai-compat" || got.ContextLimit != 64000 {
		t.Fatalf("lost user override: %+v", got)
	}
}
