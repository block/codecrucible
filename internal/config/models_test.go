package config

import "testing"

func TestDefaultModelRegistry_ContainsExpectedModels(t *testing.T) {
	registry := DefaultModelRegistry()

	expected := []struct {
		name         string
		contextLimit int
	}{
		{"claude-sonnet-4-6", 200000},
		{"claude-opus-4-6", 200000},
		{"claude-opus-4-7", 1000000},
		{"gpt-5.2", 400000},
		{"gpt-5.4", 1000000},
		{"gpt-5.4-mini", 400000},
		{"gpt-5.4-nano", 400000},
		{"gemini-3-pro", 1048576},
		{"gemini-3-flash", 1048576},
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
		{"claude-sonnet-4-6", "claude-sonnet-4-6", "claude-sonnet-4-6/invocations", true},
		{"claude-opus-4-6", "claude-opus-4-6", "claude-opus-4-6/invocations", true},
		{"gpt-5.2", "gpt-5.2", "gpt-5.2/invocations", true},
		{"gemini-3-pro", "gemini-3-pro", "gemini-3-pro/invocations", true},
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
		{"Claude-Sonnet-4-6", "claude-sonnet-4-6"},
		{"CLAUDE-SONNET-4-6", "claude-sonnet-4-6"},
		{"GPT-5.2", "gpt-5.2"},
		{"Gemini-3-Pro", "gemini-3-pro"},
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
		{"sonnet", "claude-sonnet-4-6"},
		// Two opus entries: longest-match prefers the first declared since
		// names are the same length; claude-opus-4-6 comes first in the registry.
		{"opus", "claude-opus-4-6"},
		// Multiple gpt entries: longest-match picks gpt-5.4-mini (first of the
		// 12-char entries in declaration order). Exact queries (gpt-5.2, gpt-5.4)
		// still hit the exact-match fast path.
		{"gpt", "gpt-5.4-mini"},
		// Two gemini entries: longest-match picks flash (14 chars vs 12).
		// Exact queries (gemini-3-pro) still hit the exact-match fast path.
		{"gemini", "gemini-3-flash"},
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
		{"claude-sonnet-4-6/invocations", "claude-sonnet-4-6", true},
		{"claude-opus-4-6/invocations", "claude-opus-4-6", true},
		{"gpt-5.2/invocations", "gpt-5.2", true},
		{"gemini-3-pro/invocations", "gemini-3-pro", true},
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

func TestDefaultModel_IsClaudeSonnet46(t *testing.T) {
	m := DefaultModel()
	if m.Name != "claude-sonnet-4-6" {
		t.Errorf("Name: got %q, want %q", m.Name, "claude-sonnet-4-6")
	}
	if m.Endpoint != "claude-sonnet-4-6/invocations" {
		t.Errorf("Endpoint: got %q, want %q", m.Endpoint, "claude-sonnet-4-6/invocations")
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

	original, _ := LookupModel("claude-sonnet-4-6")
	if original.MaxOutputTokens != 16384 {
		t.Fatalf("precondition: expected 16384, got %d", original.MaxOutputTokens)
	}

	RegisterModel(ModelConfig{
		Name:            "claude-sonnet-4-6",
		ContextLimit:    200000,
		MaxOutputTokens: 32768,
	})

	updated, found := LookupModel("claude-sonnet-4-6")
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

func TestDefaultModelRegistry_FieldValues(t *testing.T) {
	tests := []struct {
		name       string
		maxOutput  int
		encoding   string
		structured bool
	}{
		{"claude-sonnet-4-6", 16384, "claude", true},
		{"claude-opus-4-6", 32768, "claude", true},
		{"gpt-5.2", 16384, "o200k_base", true},
		{"gemini-3-pro", 65536, "cl100k_base", true},
		{"gemini-3-flash", 65536, "cl100k_base", true},
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
			if m.Temperature != 0.0 {
				t.Errorf("Temperature: got %f, want 0.0", m.Temperature)
			}
		})
	}
}
