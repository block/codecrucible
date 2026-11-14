package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func providerFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "provider.yaml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

const localProvider = `schema_version: 1
name: local-test
protocol: openai-chat
base_url: http://localhost:8080/gateway
auth:
  type: bearer
  api_key_env: LOCAL_TEST_API_KEY
request:
  path: /chat/completions
  max_tokens_field: max_completion_tokens
discovery:
  format: openai-models
  path: /models
models:
  - name: claude-sonnet-5
    request_model: deployment-42
    aliases: [review-model]
    context_limit: 64000
    max_output_tokens: 4096
    supports_structured_output: true
    input_price_per_million: 0.5
`

func TestProviderPatchPreservesUnspecifiedFieldsAndExplicitZeros(t *testing.T) {
	first := providerFile(t, `schema_version: 1
name: anthropic
models:
  - name: claude-sonnet-5
    input_price_per_million: 0
    omit_temperature: false
`)
	second := providerFile(t, `schema_version: 1
name: anthropic
models:
  - name: claude-sonnet-5
    output_price_per_million: 1.25
`)
	r, err := LoadRegistry([]string{first, second}, nil)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := r.LookupModel("anthropic", "claude-sonnet-5")
	if !ok || m.InputPricePerM != 0 || m.OutputPricePerM != 1.25 || m.OmitTemperature || m.ContextLimit != 1000000 || !m.NativeStructuredOutput {
		t.Fatalf("incorrect merged model: %+v", m)
	}
	original, _ := LookupModel("claude-sonnet-5")
	if original.InputPricePerM == 0 || !original.OmitTemperature {
		t.Fatalf("patch mutated bundled catalog: %+v", original)
	}
}

func TestProviderScopedModelsAndRequestIDs(t *testing.T) {
	r, err := LoadRegistry([]string{providerFile(t, localProvider)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ResolveModel("", "claude-sonnet-5"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("expected ambiguity, got %v", err)
	}
	local, err := r.ResolveModel("local-test", "REVIEW_MODEL")
	if err != nil {
		t.Fatal(err)
	}
	if local.Name != "deployment-42" || local.ContextLimit != 64000 || local.InputPricePerM != 0.5 {
		t.Fatalf("lost provider metadata: %+v", local)
	}
	native, _ := r.ResolveModel("anthropic", "claude-sonnet-5")
	if native.ContextLimit != 1000000 || native.Name != "claude-sonnet-5" {
		t.Fatalf("native metadata changed: %+v", native)
	}
	unknown, _ := r.ResolveModel("openai", "claude-sonnet-5")
	if unknown.SupportsStructuredOutput || unknown.InputPricePerM != 0 {
		t.Fatalf("borrowed another provider's capabilities: %+v", unknown)
	}
	proxy, _ := r.ResolveModel("databricks", "databricks-gpt-5.5")
	if proxy.ContextLimit != 1050000 || proxy.Name != "databricks-gpt-5.5" {
		t.Fatalf("lost legacy Databricks lookup: %+v", proxy)
	}
}

func TestConfigLoadsHaveIndependentRegistriesAndRelativePaths(t *testing.T) {
	path := providerFile(t, localProvider)
	cfgPath := filepath.Join(filepath.Dir(path), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("provider-files: [provider.yaml]\nprovider: local-test\nmodel: review-model\n"), 0600); err != nil {
		t.Fatal(err)
	}
	v, err := SetupViper(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(v)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("LOCAL_TEST_API_KEY", "custom-key")
	if err := ResolvePhases(cfg); err != nil {
		t.Fatal(err)
	}
	for name, pc := range allPhases(cfg) {
		if pc.Provider != "local-test" || pc.APIKey != "custom-key" || pc.ModelCfg.Name != "deployment-42" || pc.ModelCfg.MaxOutputTokens != 4096 {
			t.Fatalf("%s resolved incorrectly: %+v", name, pc)
		}
	}
	fresh, err := Load(viper.New())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fresh.Registry.Provider("local-test"); ok {
		t.Fatal("provider leaked between loads")
	}
	legacy := viper.New()
	legacy.Set("models", []ModelConfig{{Name: "unique-load-only", ExactMatch: true, Provider: "ollama", ContextLimit: 4000}})
	one, err := Load(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := one.Registry.LookupModel("ollama", "unique-load-only"); !ok {
		t.Fatal("legacy config was not applied")
	}
	if _, ok := fresh.Registry.LookupModel("ollama", "unique-load-only"); ok {
		t.Fatal("legacy model leaked between loads")
	}
}

func TestProviderCredentialOverrideAndPhaseIsolation(t *testing.T) {
	r, err := LoadRegistry([]string{providerFile(t, localProvider), providerFile(t, `schema_version: 1
name: anthropic
auth:
  api_key_env: OTHER_ANTHROPIC_KEY
`)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("OTHER_ANTHROPIC_KEY", "other-key")
	t.Setenv("LOCAL_TEST_API_KEY", "local-key")
	cfg := &Config{Registry: r, Provider: "anthropic", Model: "claude-opus-4-8", AnthropicAPIKey: "legacy-key", Phases: Phases{
		Analysis: PhaseConfig{BaseURL: "https://analysis.invalid", Headers: []string{"X-Analysis: secret"}, ModelParams: map[string]any{"thinking": true}},
		Audit:    PhaseConfig{Provider: "local-test", Model: "review-model"},
	}}
	if err := ResolvePhases(cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Phases.Analysis.APIKey != "other-key" {
		t.Fatal("overridden credential source used the legacy key")
	}
	audit := cfg.Phases.Audit
	if audit.APIKey != "local-key" || audit.BaseURL != "" || len(audit.Headers) != 0 || len(audit.ModelParams) != 0 {
		t.Fatalf("analysis settings leaked into provider: %+v", audit)
	}
}

func TestRegistryAccessorsReturnIndependentCopies(t *testing.T) {
	r := BuiltinRegistry()
	m, _ := r.LookupModel("cerebras", "kimi-k2.6")
	m.Aliases[0] = "changed"
	models := r.Models()
	for i := range models {
		models[i].Name = "changed"
	}
	p, _ := r.Provider("anthropic")
	p.Headers["anthropic-version"] = "changed"
	p.Models[0].Name = "changed"
	ps := r.Providers()
	ps[0].Name = "changed"
	again, _ := r.Provider("anthropic")
	kimi, _ := r.ResolveModel("cerebras", "kimi")
	if again.Headers["anthropic-version"] != "2023-06-01" || again.Models[0].Name == "changed" || kimi.Name != "kimi-k2.6" {
		t.Fatal("accessor mutated registry")
	}
}

func TestProviderValidationRejectsInvalidCatalogs(t *testing.T) {
	cases := map[string]string{
		"unknown field":          "schema_version: 1\nname: cerebras\nprotcol: openai-chat\n",
		"unknown null field":     "schema_version: 1\nname: cerebras\nprotcol: null\n",
		"unknown model field":    "schema_version: 1\nname: cerebras\nmodels: [{name: kimi-k2.6, context_limt: 1000}]\n",
		"unknown nested field":   "schema_version: 1\nname: cerebras\nauth: {api_key_en: WRONG}\n",
		"schema version":         "schema_version: 2\nname: cerebras\n",
		"protocol":               "schema_version: 1\nname: cerebras\nprotocol: imaginary\n",
		"auth":                   "schema_version: 1\nname: cerebras\nauth: {type: imaginary}\n",
		"bad variable":           "schema_version: 1\nname: cerebras\nauth: {api_key_env: '${SECRET}'}\n",
		"output field":           "schema_version: 1\nname: cerebras\nrequest: {max_tokens_field: output_tokens}\n",
		"path":                   "schema_version: 1\nname: cerebras\nrequest: {path: 'https://example.com'}\n",
		"discovery":              "schema_version: 1\nname: cerebras\ndiscovery: {format: invented}\n",
		"url":                    "schema_version: 1\nname: cerebras\nbase_url: 'https://key:secret@example.com'\n",
		"limits":                 "schema_version: 1\nname: cerebras\nmodels: [{name: kimi-k2.6, context_limit: 0}]\n",
		"output exceeds context": "schema_version: 1\nname: cerebras\nmodels: [{name: kimi-k2.6, max_output_tokens: 99999999}]\n",
		"negative price":         "schema_version: 1\nname: cerebras\nmodels: [{name: kimi-k2.6, input_price_per_million: -1}]\n",
		"nan price":              "schema_version: 1\nname: cerebras\nmodels: [{name: kimi-k2.6, input_price_per_million: .nan}]\n",
		"duplicate model":        "schema_version: 1\nname: cerebras\nmodels: [{name: kimi-k2.6}, {name: KIMI-K2.6}]\n",
		"duplicate alias":        "schema_version: 1\nname: cerebras\nmodels: [{name: another-model, aliases: [kimi]}]\n",
		"empty alias":            "schema_version: 1\nname: cerebras\nmodels: [{name: another-model, aliases: ['']}]\n",
		"wrong owner":            "schema_version: 1\nname: cerebras\nmodels: [{name: another-model, provider: openai}]\n",
		"empty name":             "schema_version: 1\nname: cerebras\nmodels: [{context_limit: 4000}]\n",
		"literal auth header":    "schema_version: 1\nname: cerebras\nheaders: {Authorization: secret}\n",
		"multiple documents":     "schema_version: 1\nname: cerebras\n---\nschema_version: 1\nname: openai\n",
		"duplicate field":        "schema_version: 1\nname: cerebras\nname: openai\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := providerFile(t, body)
			_, err := LoadRegistry([]string{path}, nil)
			if err == nil {
				t.Fatal("accepted invalid catalog")
			}
			if !strings.Contains(err.Error(), path) {
				t.Fatalf("error must identify source: %v", err)
			}
		})
	}
}

func TestProviderCanClearAliases(t *testing.T) {
	r, err := LoadRegistry([]string{providerFile(t, "schema_version: 1\nname: cerebras\nmodels: [{name: kimi-k2.6, aliases: []}]\n")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := r.LookupModel("cerebras", "kimi-k2.6")
	if len(m.Aliases) != 0 {
		t.Fatal("empty aliases did not replace list")
	}
}

func TestProviderDefaultModelUsesRequestID(t *testing.T) {
	body := strings.Replace(localProvider, "protocol: openai-chat", "protocol: openai-chat\ndefault_model: claude-sonnet-5\nrequire_model: true", 1)
	r, err := LoadRegistry([]string{providerFile(t, body)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Registry: r, Provider: "local-test"}
	if err := ResolvePhases(cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Phases.Analysis.ModelCfg.Name != "deployment-42" {
		t.Fatal("default model did not use configured request ID")
	}
}

func TestProviderAutoDetectionPriorities(t *testing.T) {
	body := strings.Replace(localProvider, "protocol: openai-chat", "protocol: openai-chat\nauto_detect_priority: 5", 1)
	r, err := LoadRegistry([]string{providerFile(t, body)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("LOCAL_TEST_API_KEY", "local-key")
	cfg := &Config{Registry: r, AnthropicAPIKey: "anthropic-key"}
	if got := r.AutoDetect(cfg); got != "local-test" {
		t.Fatalf("priority not respected: %s", got)
	}
	p, _ := r.Provider("local-test")
	p.Auth.Type = "none"
	if len(p.AuthHeaders("should-not-send")) != 0 {
		t.Fatal("no-auth provider attached credentials")
	}
}

func TestLegacyDefaultModelCanChangeProvider(t *testing.T) {
	r, err := LoadRegistry(nil, []ModelConfig{{Name: "claude-sonnet-5", Provider: "openai-compat", ContextLimit: 64000}})
	if err != nil {
		t.Fatal(err)
	}
	m, err := r.ResolveModel("", "")
	if err != nil || m.Name != "claude-sonnet-5" || m.Provider != "openai-compat" || m.ContextLimit != 64000 {
		t.Fatalf("lost legacy default override: %+v %v", m, err)
	}
}

func TestCatalogHeaderNamesDoNotUseModelMergeRules(t *testing.T) {
	path := providerFile(t, "schema_version: 1\nname: openai\nheaders: {models: v1}\n")
	r, err := LoadRegistry([]string{path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := r.Provider("openai")
	if p.Headers["models"] != "v1" {
		t.Fatal("lost static header")
	}
}
