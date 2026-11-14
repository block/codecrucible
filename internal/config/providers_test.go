package config

import (
	"testing"
	"testing/fstest"
)

func TestYAMLProviderResolvesCredentialsWithoutGoRegistration(t *testing.T) {
	files := fstest.MapFS{"providers/example.yaml": {Data: []byte(`name: example
protocol: openai-chat
base_url: https://example.com
auth:
  type: bearer
  api_key_env: CODECRUCIBLE_TEST_PROVIDER_KEY
request:
  path: /v1/chat/completions
discovery:
  format: openai-models
  path: /v1/models
`)}}
	providers, err := loadProviders(files)
	if err != nil {
		t.Fatal(err)
	}
	saved := builtinProviders
	builtinProviders = append(append([]ProviderConfig{}, saved...), providers...)
	t.Cleanup(func() { builtinProviders = saved })
	t.Setenv("CODECRUCIBLE_TEST_PROVIDER_KEY", "example-key")
	cfg := &Config{Provider: "example", Model: "custom-model"}
	if err := ResolvePhases(cfg); err != nil {
		t.Fatal(err)
	}
	for name, phase := range allPhases(cfg) {
		if phase.Provider != "example" || phase.APIKey != "example-key" {
			t.Fatalf("%s did not resolve YAML provider", name)
		}
	}
}

func TestProviderCatalogRejectsTypos(t *testing.T) {
	files := fstest.MapFS{"providers/invalid.yaml": {Data: []byte("name: example\nprotcol: openai-chat\n")}}
	if _, err := loadProviders(files); err == nil {
		t.Fatal("misspelled provider field must not be silently ignored")
	}
}
