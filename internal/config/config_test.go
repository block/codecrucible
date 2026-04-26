package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

func TestSetDefaults(t *testing.T) {
	v := viper.New()
	SetDefaults(v)

	tests := []struct {
		key      string
		expected any
	}{
		{"verbose", false},
		{"dry-run", false},
		{"include-tests", false},
		{"include-docs", false},
		{"compress", false},
		{"fail-on-severity", float64(0)},
		{"max-cost", float64(25)},
	}

	for _, tt := range tests {
		got := v.Get(tt.key)
		if got != tt.expected {
			t.Errorf("default for %q: got %v (%T), want %v (%T)", tt.key, got, got, tt.expected, tt.expected)
		}
	}

	if got := v.GetStringSlice("custom-headers"); len(got) != 0 {
		t.Errorf("default for %q: got %v, want empty slice", "custom-headers", got)
	}
	if got := v.GetString("model-params-json"); got != "" {
		t.Errorf("default for %q: got %q, want empty", "model-params-json", got)
	}
	if got := v.GetString("phase-output-dir"); got != "" {
		t.Errorf("default for %q: got %q, want empty", "phase-output-dir", got)
	}
}

func TestLoad_FromDefaults(t *testing.T) {
	v := viper.New()
	SetDefaults(v)

	cfg, err := Load(v)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Verbose {
		t.Error("Verbose should default to false")
	}
	if cfg.DryRun {
		t.Error("DryRun should default to false")
	}
}

func TestBindEnvVars_DatabricksHost(t *testing.T) {
	v := viper.New()
	SetDefaults(v)
	BindEnvVars(v)

	t.Setenv("DATABRICKS_HOST", "https://test.databricks.com")

	cfg, err := Load(v)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.DatabricksHost != "https://test.databricks.com" {
		t.Errorf("DatabricksHost: got %q, want %q", cfg.DatabricksHost, "https://test.databricks.com")
	}
}

func TestBindEnvVars_DatabricksToken(t *testing.T) {
	v := viper.New()
	SetDefaults(v)
	BindEnvVars(v)

	t.Setenv("DATABRICKS_TOKEN", "test-token-123")

	cfg, err := Load(v)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.DatabricksToken != "test-token-123" {
		t.Errorf("DatabricksToken: got %q, want %q", cfg.DatabricksToken, "test-token-123")
	}
}

func TestBindEnvVars_DatabricksEndpoint(t *testing.T) {
	v := viper.New()
	SetDefaults(v)
	BindEnvVars(v)

	t.Setenv("DATABRICKS_ENDPOINT", "my-endpoint/invocations")

	cfg, err := Load(v)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.DatabricksEndpoint != "my-endpoint/invocations" {
		t.Errorf("DatabricksEndpoint: got %q, want %q", cfg.DatabricksEndpoint, "my-endpoint/invocations")
	}
}

func TestBindEnvVars_ModelParamsJSON(t *testing.T) {
	v := viper.New()
	SetDefaults(v)
	BindEnvVars(v)

	t.Setenv("CODECRUCIBLE_MODEL_PARAMS", `{"thinking":{"type":"enabled","budget_tokens":2048}}`)

	cfg, err := Load(v)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	thinkingRaw, ok := cfg.ModelParams["thinking"]
	if !ok {
		t.Fatalf("expected thinking in model params, got %+v", cfg.ModelParams)
	}
	thinking, ok := thinkingRaw.(map[string]any)
	if !ok {
		t.Fatalf("expected thinking object, got %T", thinkingRaw)
	}
	if thinking["type"] != "enabled" {
		t.Errorf("thinking.type: got %v, want enabled", thinking["type"])
	}
}

func TestLoad_ModelParamsJSON_MergesWithConfigObject(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfgBody := `model-params:
  thinking:
    type: enabled
    budget_tokens: 1024
  extra:
    keep: true
`
	if err := os.WriteFile(cfgPath, []byte(cfgBody), 0644); err != nil {
		t.Fatalf("writing config file: %v", err)
	}

	v, err := SetupViper(cfgPath)
	if err != nil {
		t.Fatalf("SetupViper failed: %v", err)
	}

	v.Set("model-params-json", `{"thinking":{"budget_tokens":4096,"mode":"adaptive"}}`)

	cfg, err := Load(v)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	thinkingRaw := cfg.ModelParams["thinking"]
	thinking, ok := thinkingRaw.(map[string]any)
	if !ok {
		t.Fatalf("expected thinking object, got %T", thinkingRaw)
	}
	if thinking["type"] != "enabled" {
		t.Errorf("thinking.type: got %v, want enabled", thinking["type"])
	}
	if thinking["budget_tokens"] != float64(4096) {
		t.Errorf("thinking.budget_tokens: got %v, want 4096", thinking["budget_tokens"])
	}
	if thinking["mode"] != "adaptive" {
		t.Errorf("thinking.mode: got %v, want adaptive", thinking["mode"])
	}

	extraRaw := cfg.ModelParams["extra"]
	extra, ok := extraRaw.(map[string]any)
	if !ok {
		t.Fatalf("expected extra object, got %T", extraRaw)
	}
	if extra["keep"] != true {
		t.Errorf("extra.keep: got %v, want true", extra["keep"])
	}
}

func TestPriorityChain_FlagOverridesEnvOverridesFile(t *testing.T) {
	// Create a temp config file with concurrency=10.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("concurrency: 10\nverbose: true\n"), 0644); err != nil {
		t.Fatalf("writing config file: %v", err)
	}

	// Step 1: Config file provides concurrency=10.
	v := viper.New()
	SetDefaults(v)
	BindEnvVars(v)
	v.SetConfigFile(cfgPath)
	if err := v.ReadInConfig(); err != nil {
		t.Fatalf("ReadInConfig: %v", err)
	}

	cfg, err := Load(v)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Concurrency != 10 {
		t.Errorf("Step 1 (file): Concurrency got %d, want %d", cfg.Concurrency, 10)
	}

	// Step 2: Env var overrides config file.
	t.Setenv("CONCURRENCY", "5")
	cfg, err = Load(v)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Concurrency != 5 {
		t.Errorf("Step 2 (env): Concurrency got %d, want %d", cfg.Concurrency, 5)
	}

	// Step 3: Flag (via Set) overrides env.
	v.Set("concurrency", 7)
	cfg, err = Load(v)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Concurrency != 7 {
		t.Errorf("Step 3 (flag): Concurrency got %d, want %d", cfg.Concurrency, 7)
	}
}

func TestSetupViper_NoConfigFile(t *testing.T) {
	// SetupViper should not error when no config file exists.
	v, err := SetupViper("")
	if err != nil {
		t.Fatalf("SetupViper failed: %v", err)
	}
	if v == nil {
		t.Fatal("expected non-nil viper instance")
	}

	// Defaults should be set.
	if v.GetBool("verbose") != false {
		t.Error("default verbose should be false")
	}
}

func TestSetupViper_WithConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test-config.yaml")
	if err := os.WriteFile(cfgPath, []byte("verbose: true\nmodel: test-model\n"), 0644); err != nil {
		t.Fatalf("writing config file: %v", err)
	}

	v, err := SetupViper(cfgPath)
	if err != nil {
		t.Fatalf("SetupViper failed: %v", err)
	}

	if !v.GetBool("verbose") {
		t.Error("expected verbose=true from config file")
	}
	if v.GetString("model") != "test-model" {
		t.Errorf("model: got %q, want %q", v.GetString("model"), "test-model")
	}
}

func TestPriorityChain_ConfigFileOverridesDefaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("dry-run: true\n"), 0644); err != nil {
		t.Fatalf("writing config file: %v", err)
	}

	v, err := SetupViper(cfgPath)
	if err != nil {
		t.Fatalf("SetupViper failed: %v", err)
	}

	cfg, err := Load(v)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if !cfg.DryRun {
		t.Error("expected DryRun=true from config file (overriding default false)")
	}
}

func TestSetupViper_MalformedConfigFileReturnsError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad-config.yaml")
	// Write invalid YAML to trigger a parse error.
	if err := os.WriteFile(cfgPath, []byte(":\n  bad: [yaml\n  unclosed"), 0644); err != nil {
		t.Fatalf("writing config file: %v", err)
	}

	_, err := SetupViper(cfgPath)
	if err == nil {
		t.Fatal("expected error for malformed config file, got nil")
	}
}

func TestParseContextSourceKV(t *testing.T) {
	cs, err := parseContextSourceKV("name=spec,type=path,location=/tmp/api.yaml,priority=100,compress=true")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cs.Name != "spec" || cs.Type != "path" || cs.Location != "/tmp/api.yaml" || cs.Priority != 100 || !cs.Compress {
		t.Errorf("parsed struct wrong: %+v", cs)
	}

	if _, err := parseContextSourceKV("name=x,type=path"); err == nil {
		t.Error("expected error for missing location")
	}
	if _, err := parseContextSourceKV("name=x,location=y"); err == nil {
		t.Error("expected error for missing type")
	}
	if _, err := parseContextSourceKV("name=x,type=path,location=y,priority=abc"); err == nil {
		t.Error("expected error for non-integer priority")
	}
	if _, err := parseContextSourceKV("name=x,type=path,location=y,unknown=z"); err == nil {
		t.Error("expected error for unknown key")
	}
}

func TestLoad_RegistersModelsFromConfigFile(t *testing.T) {
	// Isolate the global registry from other tests.
	saved := make([]ModelConfig, len(defaultModels))
	copy(saved, defaultModels)
	defer func() { defaultModels = saved }()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfgBody := `
models:
  # Extend: a local Ollama model.
  - name: llama-4-405b
    provider: ollama
    input_price_per_million: 0.0
    output_price_per_million: 0.0
    context_limit: 131072
    max_output_tokens: 8192
    tokenizer_encoding: cl100k_base
    supports_structured_output: false

  # Override: retune a built-in.
  - name: claude-sonnet-4-6
    provider: anthropic
    endpoint: claude-sonnet-4-6/invocations
    input_price_per_million: 2.0
    output_price_per_million: 10.0
    context_limit: 200000
    max_output_tokens: 16384
    tokenizer_encoding: claude
    supports_structured_output: true
`
	if err := os.WriteFile(cfgPath, []byte(cfgBody), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	v, err := SetupViper(cfgPath)
	if err != nil {
		t.Fatalf("SetupViper: %v", err)
	}
	cfg, err := Load(v)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(cfg.Models) != 2 {
		t.Fatalf("cfg.Models: got %d entries, want 2", len(cfg.Models))
	}

	// Extension round-trip: the new model is in the registry, and empty
	// Endpoint was defaulted from Name.
	llama, ok := LookupModel("llama-4-405b")
	if !ok {
		t.Fatal("llama-4-405b not found in registry after Load")
	}
	if llama.Endpoint != "llama-4-405b/invocations" {
		t.Errorf("llama Endpoint: got %q, want default", llama.Endpoint)
	}
	if llama.Provider != "ollama" {
		t.Errorf("llama Provider: got %q, want ollama", llama.Provider)
	}

	// Override round-trip: built-in pricing was replaced.
	sonnet, _ := LookupModel("claude-sonnet-4-6")
	if sonnet.InputPricePerM != 2.0 {
		t.Errorf("claude-sonnet-4-6 override InputPricePerM: got %v, want 2.0", sonnet.InputPricePerM)
	}
	if sonnet.OutputPricePerM != 10.0 {
		t.Errorf("claude-sonnet-4-6 override OutputPricePerM: got %v, want 10.0", sonnet.OutputPricePerM)
	}
}

func TestLoad_EmptyModelNameErrors(t *testing.T) {
	saved := make([]ModelConfig, len(defaultModels))
	copy(saved, defaultModels)
	defer func() { defaultModels = saved }()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfgBody := `
models:
  - provider: openai-compat
    context_limit: 128000
`
	if err := os.WriteFile(cfgPath, []byte(cfgBody), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	v, err := SetupViper(cfgPath)
	if err != nil {
		t.Fatalf("SetupViper: %v", err)
	}
	if _, err := Load(v); err == nil {
		t.Fatal("expected Load to error for models entry without name")
	}
}

func TestLoad_ContextSourcesRaw(t *testing.T) {
	v := viper.New()
	SetDefaults(v)
	v.Set("context-sources-raw", []string{
		"name=a,type=inline,location=hello",
		"name=b,type=path,location=/tmp,priority=50",
	})
	cfg, err := Load(v)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if len(cfg.ContextSources) != 2 {
		t.Fatalf("expected 2 sources, got %d", len(cfg.ContextSources))
	}
	if cfg.ContextSources[0].Name != "a" || cfg.ContextSources[1].Priority != 50 {
		t.Errorf("sources parsed wrong: %+v", cfg.ContextSources)
	}
}
