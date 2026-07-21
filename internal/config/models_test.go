package config

import (
	"math"
	"strings"
	"testing"
)

func TestDefaultModelRegistry_ContainsExpectedModels(t *testing.T) {
	registry := DefaultModelRegistry()

	expected := []struct {
		name         string
		contextLimit int
	}{
		{"claude-sonnet-5", 1000000},
		{"claude-opus-4-8", 1000000},
		{"claude-fable-5", 1000000},
		{"claude-haiku-4-5", 200000},
		{"goose-claude-4-6-opus", 200000},
		{"goose-claude-4-7-opus", 1000000},
		{"gpt-5.6", 1050000},
		{"gpt-5.6-sol", 1050000},
		{"gpt-5.6-terra", 1050000},
		{"gpt-5.6-luna", 1050000},
		{"gpt-5.5", 1050000},
		{"gpt-5.5-cyber-preview", 272000},
		{"gpt-5.5-cyber", 272000},
		{"gpt-5.4", 1050000},
		{"gpt-5.4-mini", 400000},
		{"gpt-5.4-nano", 400000},
		{"gemini-3.1-pro-preview", 1048576},
		{"gemini-3.5-flash", 1048576},
		{"gemini-3.1-flash-lite", 1048576},
	}

	if len(registry) != len(expected) {
		t.Fatalf("registry length: got %d, want %d", len(registry), len(expected))
	}

	for i, exp := range expected {
		if registry[i].Name != exp.name {
			t.Errorf("registry[%d].Name: got %q, want %q", i, registry[i].Name, exp.name)
		}
		if registry[i].ContextLimit != exp.contextLimit {
			t.Errorf("registry[%d].ContextLimit: got %d, want %d", i, registry[i].ContextLimit, exp.contextLimit)
		}
	}
}

func TestDefaultModelRegistry_ReturnsCopy(t *testing.T) {
	r1 := DefaultModelRegistry()
	r1[0].Name = "mutated"

	r2 := DefaultModelRegistry()
	if r2[0].Name == "mutated" {
		t.Error("DefaultModelRegistry should return a copy, but mutation leaked")
	}
}

func TestLookupModel_ExactName(t *testing.T) {
	tests := []struct {
		query        string
		wantName     string
		wantEndpoint string
		wantFound    bool
	}{
		{"claude-sonnet-5", "claude-sonnet-5", "claude-sonnet-5/invocations", true},
		{"claude-opus-4-8", "claude-opus-4-8", "claude-opus-4-8/invocations", true},
		{"gpt-5.6", "gpt-5.6", "gpt-5.6/invocations", true},
		{"gpt-5.6-sol", "gpt-5.6-sol", "gpt-5.6-sol/invocations", true},
		{"gpt-5.6-terra", "gpt-5.6-terra", "gpt-5.6-terra/invocations", true},
		{"gpt-5.6-luna", "gpt-5.6-luna", "gpt-5.6-luna/invocations", true},
		{"gpt-5.5", "gpt-5.5", "gpt-5.5/invocations", true},
		{"gpt-5.5-cyber-preview", "gpt-5.5-cyber-preview", "gpt-5.5-cyber-preview/invocations", true},
		{"gpt-5.5-cyber", "gpt-5.5-cyber", "gpt-5.5-cyber/invocations", true},
		{"gemini-3.1-pro-preview", "gemini-3.1-pro-preview", "gemini-3.1-pro-preview/invocations", true},
		{"nonexistent-model", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			m, found := LookupModel(tt.query)
			if found != tt.wantFound {
				t.Fatalf("found: got %v, want %v", found, tt.wantFound)
			}
			if !found {
				return
			}
			if m.Name != tt.wantName {
				t.Errorf("Name: got %q, want %q", m.Name, tt.wantName)
			}
			if m.Endpoint != tt.wantEndpoint {
				t.Errorf("Endpoint: got %q, want %q", m.Endpoint, tt.wantEndpoint)
			}
		})
	}
}

func TestLookupModel_CaseInsensitive(t *testing.T) {
	tests := []struct {
		query    string
		wantName string
	}{
		{"Claude-Sonnet-5", "claude-sonnet-5"},
		{"CLAUDE-SONNET-5", "claude-sonnet-5"},
		{"GPT-5.6", "gpt-5.6"},
		{"GPT-5.6-TERRA", "gpt-5.6-terra"},
		{"GPT-5.5", "gpt-5.5"},
		{"GPT-5.5-CYBER-PREVIEW", "gpt-5.5-cyber-preview"},
		{"Gemini-3.1-Pro-Preview", "gemini-3.1-pro-preview"},
	}

	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			m, found := LookupModel(tt.query)
			if !found {
				t.Fatalf("expected to find model for query %q", tt.query)
			}
			if m.Name != tt.wantName {
				t.Errorf("Name: got %q, want %q", m.Name, tt.wantName)
			}
		})
	}
}

func TestLookupModel_PartialMatch(t *testing.T) {
	tests := []struct {
		query    string
		wantName string
	}{
		{"sonnet", "claude-sonnet-5"},
		// Use a direct-Claude fragment so workspace-specific goose aliases do
		// not win the generic longest-match rule.
		{"claude-opus", "claude-opus-4-8"},
		// Multiple gpt entries: longest-match picks the cyber preview alias.
		// Exact GPT queries still hit the exact-match fast path.
		{"gpt", "gpt-5.5-cyber-preview"},
		// The preview Pro ID is the longest Gemini entry.
		{"gemini", "gemini-3.1-pro-preview"},
	}

	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			m, found := LookupModel(tt.query)
			if !found {
				t.Fatalf("expected to find model for query %q", tt.query)
			}
			if m.Name != tt.wantName {
				t.Errorf("Name: got %q, want %q", m.Name, tt.wantName)
			}
		})
	}
}

func TestLookupModelByEndpoint(t *testing.T) {
	tests := []struct {
		endpoint  string
		wantName  string
		wantFound bool
	}{
		{"claude-sonnet-5/invocations", "claude-sonnet-5", true},
		{"claude-opus-4-8/invocations", "claude-opus-4-8", true},
		{"gpt-5.6/invocations", "gpt-5.6", true},
		{"gpt-5.6-sol/invocations", "gpt-5.6-sol", true},
		{"gpt-5.5/invocations", "gpt-5.5", true},
		{"gpt-5.5-cyber-preview/invocations", "gpt-5.5-cyber-preview", true},
		{"gemini-3.1-pro-preview/invocations", "gemini-3.1-pro-preview", true},
		{"nonexistent/invocations", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.endpoint, func(t *testing.T) {
			m, found := LookupModelByEndpoint(tt.endpoint)
			if found != tt.wantFound {
				t.Fatalf("found: got %v, want %v", found, tt.wantFound)
			}
			if !found {
				return
			}
			if m.Name != tt.wantName {
				t.Errorf("Name: got %q, want %q", m.Name, tt.wantName)
			}
		})
	}
}

func TestLookupModel_GPT55Capabilities(t *testing.T) {
	m, found := LookupModel("gpt-5.5")
	if !found {
		t.Fatal("gpt-5.5 not found")
	}

	if m.Provider != "openai" {
		t.Errorf("Provider: got %q, want openai", m.Provider)
	}
	if m.InputPricePerM != 5.0 {
		t.Errorf("InputPricePerM: got %f, want 5.0", m.InputPricePerM)
	}
	if m.OutputPricePerM != 30.0 {
		t.Errorf("OutputPricePerM: got %f, want 30.0", m.OutputPricePerM)
	}
	if m.ContextLimit != 1050000 {
		t.Errorf("ContextLimit: got %d, want 1050000", m.ContextLimit)
	}
	if m.MaxOutputTokens != 128000 {
		t.Errorf("MaxOutputTokens: got %d, want 128000", m.MaxOutputTokens)
	}
	if m.Temperature != 1.0 {
		t.Errorf("Temperature: got %f, want 1.0", m.Temperature)
	}
	if m.Encoding != "o200k_base" {
		t.Errorf("Encoding: got %q, want o200k_base", m.Encoding)
	}
	if !m.SupportsStructuredOutput {
		t.Error("SupportsStructuredOutput: got false, want true")
	}
	if !m.UseMaxCompletionTokens {
		t.Error("UseMaxCompletionTokens: got false, want true")
	}
	if m.LongContextThreshold != 272000 {
		t.Errorf("LongContextThreshold: got %d, want 272000", m.LongContextThreshold)
	}
}

func TestLookupModel_GPT56FamilyCapabilities(t *testing.T) {
	tests := []struct {
		name                       string
		inputPricePerM             float64
		outputPricePerM            float64
		longContextInputPricePerM  float64
		longContextOutputPricePerM float64
	}{
		{"gpt-5.6", 5.0, 30.0, 10.0, 45.0},
		{"gpt-5.6-sol", 5.0, 30.0, 10.0, 45.0},
		{"gpt-5.6-terra", 2.5, 15.0, 5.0, 22.5},
		{"gpt-5.6-luna", 1.0, 6.0, 2.0, 9.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, found := LookupModel(tt.name)
			if !found {
				t.Fatalf("%s not found", tt.name)
			}

			if m.Provider != "openai" {
				t.Errorf("Provider: got %q, want openai", m.Provider)
			}
			if m.InputPricePerM != tt.inputPricePerM || m.OutputPricePerM != tt.outputPricePerM {
				t.Errorf("base pricing: got input=%f output=%f, want input=%f output=%f",
					m.InputPricePerM, m.OutputPricePerM, tt.inputPricePerM, tt.outputPricePerM)
			}
			if m.LongContextInputPricePerM != tt.longContextInputPricePerM || m.LongContextOutputPricePerM != tt.longContextOutputPricePerM {
				t.Errorf("long-context pricing: got input=%f output=%f, want input=%f output=%f",
					m.LongContextInputPricePerM, m.LongContextOutputPricePerM,
					tt.longContextInputPricePerM, tt.longContextOutputPricePerM)
			}
			if m.ContextLimit != 1050000 {
				t.Errorf("ContextLimit: got %d, want 1050000", m.ContextLimit)
			}
			if m.MaxOutputTokens != 128000 {
				t.Errorf("MaxOutputTokens: got %d, want 128000", m.MaxOutputTokens)
			}
			if m.LongContextThreshold != 272000 {
				t.Errorf("LongContextThreshold: got %d, want 272000", m.LongContextThreshold)
			}
			if !m.UseMaxCompletionTokens {
				t.Error("UseMaxCompletionTokens: got false, want true")
			}
			if !m.OmitTemperature {
				t.Error("OmitTemperature: got false, want true")
			}
			if !m.SupportsStructuredOutput {
				t.Error("SupportsStructuredOutput: got false, want true")
			}
			if m.ExecutionWarning == "" {
				t.Error("ExecutionWarning: got empty, want safeguard warning")
			}
		})
	}
}

func TestLookupModel_GPT55CyberAliasesUseProvisionalConfig(t *testing.T) {
	base, found := LookupModel("gpt-5.5")
	if !found {
		t.Fatal("gpt-5.5 not found")
	}

	for _, name := range []string{"gpt-5.5-cyber-preview", "gpt-5.5-cyber"} {
		t.Run(name, func(t *testing.T) {
			m, found := LookupModel(name)
			if !found {
				t.Fatalf("%s not found", name)
			}

			if m.Provider != "openai" {
				t.Errorf("Provider: got %q, want openai", m.Provider)
			}
			if m.ContextLimit != 272000 {
				t.Errorf("ContextLimit: got %d, want 272000", m.ContextLimit)
			}
			if m.MaxOutputTokens != base.MaxOutputTokens {
				t.Errorf("MaxOutputTokens: got %d, want GPT-5.5 value %d", m.MaxOutputTokens, base.MaxOutputTokens)
			}
			if m.InputPricePerM != base.InputPricePerM || m.OutputPricePerM != base.OutputPricePerM {
				t.Errorf("pricing: got input=%f output=%f, want GPT-5.5 input=%f output=%f",
					m.InputPricePerM, m.OutputPricePerM, base.InputPricePerM, base.OutputPricePerM)
			}
			if m.ExecutionWarning == "" {
				t.Error("ExecutionWarning: got empty, want provisional-config warning")
			}
			if m.LongContextThreshold != 0 {
				t.Errorf("LongContextThreshold: got %d, want 0 for a 272K context alias", m.LongContextThreshold)
			}
		})
	}
}

func TestLookupModel_FableCarriesExecutionWarning(t *testing.T) {
	m, found := LookupModel("claude-fable-5")
	if !found {
		t.Fatal("claude-fable-5 not found")
	}
	if m.ExecutionWarning == "" {
		t.Error("ExecutionWarning: got empty, want security-policy warning")
	}
	for _, want := range []string{"security-policy", "data retention", "provider rejection"} {
		if !strings.Contains(m.ExecutionWarning, want) {
			t.Errorf("ExecutionWarning %q missing %q", m.ExecutionWarning, want)
		}
	}
}

func TestDefaultModel_IsClaudeSonnet5(t *testing.T) {
	m := DefaultModel()
	if m.Name != "claude-sonnet-5" {
		t.Errorf("Name: got %q, want %q", m.Name, "claude-sonnet-5")
	}
	if m.Endpoint != "claude-sonnet-5/invocations" {
		t.Errorf("Endpoint: got %q, want %q", m.Endpoint, "claude-sonnet-5/invocations")
	}
}

func TestUnknownModelDefaults(t *testing.T) {
	m := UnknownModelDefaults("my-custom-model")

	if m.Name != "my-custom-model" {
		t.Errorf("Name: got %q, want %q", m.Name, "my-custom-model")
	}
	if m.Endpoint != "my-custom-model/invocations" {
		t.Errorf("Endpoint: got %q, want %q", m.Endpoint, "my-custom-model/invocations")
	}
	if m.ContextLimit != 128000 {
		t.Errorf("ContextLimit: got %d, want %d", m.ContextLimit, 128000)
	}
	if m.MaxOutputTokens != 8192 {
		t.Errorf("MaxOutputTokens: got %d, want %d", m.MaxOutputTokens, 8192)
	}
	if m.Temperature != 0.0 {
		t.Errorf("Temperature: got %f, want %f", m.Temperature, 0.0)
	}
	if m.Encoding != "cl100k_base" {
		t.Errorf("Encoding: got %q, want %q", m.Encoding, "cl100k_base")
	}
	if m.SupportsStructuredOutput {
		t.Error("SupportsStructuredOutput: got true, want false")
	}
}

func TestRegisterModel_AddsNew(t *testing.T) {
	// Save and restore the registry to avoid polluting other tests.
	saved := make([]ModelConfig, len(defaultModels))
	copy(saved, defaultModels)
	defer func() { defaultModels = saved }()

	RegisterModel(ModelConfig{
		Name:            "my-custom-model",
		ContextLimit:    256000,
		MaxOutputTokens: 16384,
	})

	m, found := LookupModel("my-custom-model")
	if !found {
		t.Fatal("registered model not found")
	}
	if m.ContextLimit != 256000 {
		t.Errorf("ContextLimit: got %d, want %d", m.ContextLimit, 256000)
	}
}

func TestRegisterModel_ReplacesExisting(t *testing.T) {
	saved := make([]ModelConfig, len(defaultModels))
	copy(saved, defaultModels)
	defer func() { defaultModels = saved }()

	original, _ := LookupModel("claude-sonnet-5")
	if original.MaxOutputTokens != 128000 {
		t.Fatalf("precondition: expected 128000, got %d", original.MaxOutputTokens)
	}

	RegisterModel(ModelConfig{
		Name:            "claude-sonnet-5",
		ContextLimit:    200000,
		MaxOutputTokens: 32768,
	})

	updated, found := LookupModel("claude-sonnet-5")
	if !found {
		t.Fatal("replaced model not found")
	}
	if updated.MaxOutputTokens != 32768 {
		t.Errorf("MaxOutputTokens: got %d, want %d", updated.MaxOutputTokens, 32768)
	}

	// Registry size should not have grown.
	if len(defaultModels) != len(saved) {
		t.Errorf("registry grew from %d to %d after replace", len(saved), len(defaultModels))
	}
}

func TestRegisterUserModels_AddsAndOverrides(t *testing.T) {
	saved := make([]ModelConfig, len(defaultModels))
	copy(saved, defaultModels)
	defer func() { defaultModels = saved }()

	err := RegisterUserModels([]ModelConfig{
		// New entry — extends the registry.
		{
			Name:            "acme-llama-70b",
			Provider:        "openai-compat",
			InputPricePerM:  0.5,
			OutputPricePerM: 1.5,
			ContextLimit:    131072,
			MaxOutputTokens: 8192,
			Encoding:        "cl100k_base",
		},
		// Override of a built-in — same Name, different pricing.
		{
			Name:            "claude-sonnet-5",
			Provider:        "anthropic",
			InputPricePerM:  1.5,
			OutputPricePerM: 7.5,
			ContextLimit:    200000,
			MaxOutputTokens: 16384,
			Encoding:        "claude",
		},
	})
	if err != nil {
		t.Fatalf("RegisterUserModels: %v", err)
	}

	added, ok := LookupModel("acme-llama-70b")
	if !ok {
		t.Fatal("user-defined model not registered")
	}
	if added.Endpoint != "acme-llama-70b/invocations" {
		t.Errorf("empty Endpoint should default to <name>/invocations, got %q", added.Endpoint)
	}
	if added.Provider != "openai-compat" {
		t.Errorf("Provider: got %q, want %q", added.Provider, "openai-compat")
	}

	overridden, _ := LookupModel("claude-sonnet-5")
	if overridden.InputPricePerM != 1.5 {
		t.Errorf("user override did not take effect: InputPricePerM got %v, want 1.5", overridden.InputPricePerM)
	}

	// Size grew by exactly one (the new one). The override replaced in place.
	if len(defaultModels) != len(saved)+1 {
		t.Errorf("registry grew by %d, want 1", len(defaultModels)-len(saved))
	}
}

func TestRegisterUserModels_PreservesExplicitEndpoint(t *testing.T) {
	saved := make([]ModelConfig, len(defaultModels))
	copy(saved, defaultModels)
	defer func() { defaultModels = saved }()

	err := RegisterUserModels([]ModelConfig{{
		Name:     "azure-gpt-5",
		Provider: "openai-compat",
		Endpoint: "deployments/my-azure-deploy/chat/completions",
	}})
	if err != nil {
		t.Fatalf("RegisterUserModels: %v", err)
	}

	m, _ := LookupModel("azure-gpt-5")
	if m.Endpoint != "deployments/my-azure-deploy/chat/completions" {
		t.Errorf("Endpoint: got %q, want the explicit value", m.Endpoint)
	}
}

func TestRegisterUserModels_RejectsEmptyName(t *testing.T) {
	saved := make([]ModelConfig, len(defaultModels))
	copy(saved, defaultModels)
	defer func() { defaultModels = saved }()

	err := RegisterUserModels([]ModelConfig{
		{Name: "ok-model", ContextLimit: 100000},
		{Name: " ", ContextLimit: 100000}, // whitespace-only name
	})
	if err == nil {
		t.Fatal("expected error for empty name, got nil")
	}
}

func TestDefaultModelRegistry_FieldValues(t *testing.T) {
	tests := []struct {
		name        string
		maxOutput   int
		encoding    string
		structured  bool
		temperature float64
		omitTemp    bool
	}{
		{"claude-sonnet-5", 128000, "claude", true, 0.0, true},
		{"claude-opus-4-8", 128000, "claude", true, 0.0, true},
		{"claude-fable-5", 128000, "claude", true, 0.0, true},
		{"claude-haiku-4-5", 64000, "claude", true, 0.0, false},
		{"gpt-5.6", 128000, "o200k_base", true, 0.0, true},
		{"gpt-5.6-sol", 128000, "o200k_base", true, 0.0, true},
		{"gpt-5.6-terra", 128000, "o200k_base", true, 0.0, true},
		{"gpt-5.6-luna", 128000, "o200k_base", true, 0.0, true},
		{"gpt-5.5", 128000, "o200k_base", true, 1.0, false},
		{"gpt-5.5-cyber-preview", 128000, "o200k_base", true, 1.0, false},
		{"gpt-5.5-cyber", 128000, "o200k_base", true, 1.0, false},
		{"gemini-3.1-pro-preview", 65536, "cl100k_base", true, 0.0, false},
		{"gemini-3.5-flash", 65536, "cl100k_base", true, 0.0, false},
		{"gemini-3.1-flash-lite", 65536, "cl100k_base", true, 0.0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, found := LookupModel(tt.name)
			if !found {
				t.Fatalf("model %q not found", tt.name)
			}
			if m.MaxOutputTokens != tt.maxOutput {
				t.Errorf("MaxOutputTokens: got %d, want %d", m.MaxOutputTokens, tt.maxOutput)
			}
			if m.Encoding != tt.encoding {
				t.Errorf("Encoding: got %q, want %q", m.Encoding, tt.encoding)
			}
			if m.SupportsStructuredOutput != tt.structured {
				t.Errorf("SupportsStructuredOutput: got %v, want %v", m.SupportsStructuredOutput, tt.structured)
			}
			if m.Temperature != tt.temperature {
				t.Errorf("Temperature: got %f, want %f", m.Temperature, tt.temperature)
			}
			if m.OmitTemperature != tt.omitTemp {
				t.Errorf("OmitTemperature: got %v, want %v", m.OmitTemperature, tt.omitTemp)
			}
		})
	}
}

func TestModelConfig_EstimateCost_LongContextPricing(t *testing.T) {
	tests := []struct {
		name         string
		model        string
		inputTokens  int
		outputTokens int
		want         float64
	}{
		{name: "gpt threshold uses base rate", model: "gpt-5.5", inputTokens: 272000, outputTokens: 1000, want: 1.39},
		{name: "gpt over threshold uses long rate", model: "gpt-5.5", inputTokens: 272001, outputTokens: 1000, want: 2.76501},
		{name: "gpt-5.6-luna over threshold uses long rate", model: "gpt-5.6-luna", inputTokens: 272001, outputTokens: 1000, want: 0.553002},
		{name: "gemini over threshold uses long rate", model: "gemini-3.1-pro-preview", inputTokens: 200001, outputTokens: 1000, want: 0.818004},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, found := LookupModel(tt.model)
			if !found {
				t.Fatalf("model %q not found", tt.model)
			}
			if got := m.EstimateCost(tt.inputTokens, tt.outputTokens); math.Abs(got-tt.want) > 1e-9 {
				t.Errorf("EstimateCost(%d, %d) = %f, want %f", tt.inputTokens, tt.outputTokens, got, tt.want)
			}
		})
	}
}
