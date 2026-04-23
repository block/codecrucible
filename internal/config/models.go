package config

import (
	"strings"
	"sync"
)

// ModelConfig describes a model's capabilities, pricing, and endpoint.
type ModelConfig struct {
	Name                     string  `yaml:"name"`
	Provider                 string  `yaml:"provider"` // "databricks", "anthropic", "openai", "google"
	Endpoint                 string  `yaml:"endpoint"`
	InputPricePerM           float64 `yaml:"input_price_per_million"`
	OutputPricePerM          float64 `yaml:"output_price_per_million"`
	ContextLimit             int     `yaml:"context_limit"`
	MaxOutputTokens          int     `yaml:"max_output_tokens"`
	Temperature              float64 `yaml:"temperature"`
	Encoding                 string  `yaml:"tokenizer_encoding"`
	SupportsStructuredOutput bool    `yaml:"supports_structured_output"`
}

// modelsMu protects defaultModels for concurrent access.
var modelsMu sync.RWMutex

// defaultModels is the built-in model registry.
var defaultModels = []ModelConfig{
	{
		Name:                     "claude-sonnet-4-6",
		Provider:                 "anthropic",
		Endpoint:                 "claude-sonnet-4-6/invocations",
		InputPricePerM:           3.0,
		OutputPricePerM:          15.0,
		ContextLimit:             200000,
		MaxOutputTokens:          16384,
		Temperature:              0.0,
		Encoding:                 "claude",
		SupportsStructuredOutput: true,
	},
	{
		Name:                     "claude-opus-4-6",
		Provider:                 "anthropic",
		Endpoint:                 "claude-opus-4-6/invocations",
		InputPricePerM:           5.0,
		OutputPricePerM:          25.0,
		ContextLimit:             200000,
		MaxOutputTokens:          32768,
		Temperature:              0.0,
		Encoding:                 "claude",
		SupportsStructuredOutput: true,
	},
	{
		Name:                     "claude-opus-4-7",
		Provider:                 "anthropic",
		Endpoint:                 "claude-opus-4-7/invocations",
		InputPricePerM:           5.0,
		OutputPricePerM:          25.0,
		ContextLimit:             1000000,
		MaxOutputTokens:          128000,
		Temperature:              0.0,
		Encoding:                 "claude",
		SupportsStructuredOutput: true,
	},
	{
		Name:                     "gpt-5.2",
		Provider:                 "openai",
		Endpoint:                 "gpt-5.2/invocations",
		InputPricePerM:           1.75,
		OutputPricePerM:          14.0,
		ContextLimit:             400000,
		MaxOutputTokens:          16384,
		Temperature:              0.0,
		Encoding:                 "o200k_base",
		SupportsStructuredOutput: true,
	},
	{
		Name:                     "gpt-5.4",
		Provider:                 "openai",
		Endpoint:                 "gpt-5.4/invocations",
		InputPricePerM:           2.50,
		OutputPricePerM:          15.0,
		ContextLimit:             1000000,
		MaxOutputTokens:          128000,
		Temperature:              0.0,
		Encoding:                 "o200k_base",
		SupportsStructuredOutput: true,
	},
	{
		Name:                     "gpt-5.4-mini",
		Provider:                 "openai",
		Endpoint:                 "gpt-5.4-mini/invocations",
		InputPricePerM:           0.75,
		OutputPricePerM:          4.50,
		ContextLimit:             400000,
		MaxOutputTokens:          128000,
		Temperature:              0.0,
		Encoding:                 "o200k_base",
		SupportsStructuredOutput: true,
	},
	{
		Name:                     "gpt-5.4-nano",
		Provider:                 "openai",
		Endpoint:                 "gpt-5.4-nano/invocations",
		InputPricePerM:           0.20,
		OutputPricePerM:          1.25,
		ContextLimit:             400000,
		MaxOutputTokens:          128000,
		Temperature:              0.0,
		Encoding:                 "o200k_base",
		SupportsStructuredOutput: true,
	},
	{
		Name:            "gemini-3-pro",
		Provider:        "google",
		Endpoint:        "gemini-3-pro/invocations",
		InputPricePerM:  2.0,
		OutputPricePerM: 12.0,
		ContextLimit:    1048576,
		MaxOutputTokens: 65536,
		Temperature:     0.0,
		Encoding:        "cl100k_base",
		// Google's OpenAI-compat endpoint accepts response_format json_schema.
		SupportsStructuredOutput: true,
	},
	{
		Name:                     "gemini-3-flash",
		Provider:                 "google",
		Endpoint:                 "gemini-3-flash/invocations",
		InputPricePerM:           0.15,
		OutputPricePerM:          0.60,
		ContextLimit:             1048576,
		MaxOutputTokens:          65536,
		Temperature:              0.0,
		Encoding:                 "cl100k_base",
		SupportsStructuredOutput: true,
	},
}

// RegisterModel adds or replaces a model in the registry. If a model with the
// same name already exists (case-insensitive), it is replaced. This allows
// callers to extend the built-in registry at startup without forking the code.
func RegisterModel(m ModelConfig) {
	modelsMu.Lock()
	defer modelsMu.Unlock()
	lower := strings.ToLower(m.Name)
	for i, existing := range defaultModels {
		if strings.ToLower(existing.Name) == lower {
			defaultModels[i] = m
			return
		}
	}
	defaultModels = append(defaultModels, m)
}

// DefaultModelRegistry returns a copy of the built-in model configs.
func DefaultModelRegistry() []ModelConfig {
	modelsMu.RLock()
	defer modelsMu.RUnlock()
	out := make([]ModelConfig, len(defaultModels))
	copy(out, defaultModels)
	return out
}

// LookupModel finds a model by name using case-insensitive partial matching.
// It matches if either the query contains a known model name, or a known model
// name contains the query. This handles Databricks-prefixed names like
// "databricks-claude-opus-4-5" matching "claude-opus-4".
func LookupModel(name string) (ModelConfig, bool) {
	modelsMu.RLock()
	defer modelsMu.RUnlock()
	lower := strings.ToLower(name)
	// Exact match first.
	for _, m := range defaultModels {
		if strings.ToLower(m.Name) == lower {
			return m, true
		}
	}
	// Partial match: query contains model name, or model name contains query.
	// Try longest match first to avoid "claude-opus-4" matching before a more specific entry.
	var best ModelConfig
	bestLen := 0
	found := false
	for _, m := range defaultModels {
		mLower := strings.ToLower(m.Name)
		if strings.Contains(lower, mLower) || strings.Contains(mLower, lower) {
			if len(m.Name) > bestLen {
				best = m
				bestLen = len(m.Name)
				found = true
			}
		}
	}
	return best, found
}

// LookupModelByEndpoint finds a model by its exact endpoint.
func LookupModelByEndpoint(endpoint string) (ModelConfig, bool) {
	modelsMu.RLock()
	defer modelsMu.RUnlock()
	for _, m := range defaultModels {
		if m.Endpoint == endpoint {
			return m, true
		}
	}
	return ModelConfig{}, false
}

// DefaultModel returns the default model (claude-sonnet-4).
func DefaultModel() ModelConfig {
	modelsMu.RLock()
	defer modelsMu.RUnlock()
	return defaultModels[0]
}

// UnknownModelDefaults returns conservative defaults for a model not in the
// registry. Uses 128K context and 8192 output tokens — reasonable for most
// frontier models released since 2024. Structured output is disabled since
// we can't know if the model supports it.
func UnknownModelDefaults(name string) ModelConfig {
	return ModelConfig{
		Name:                     name,
		Endpoint:                 name + "/invocations",
		ContextLimit:             128000,
		MaxOutputTokens:          8192,
		Temperature:              0.0,
		Encoding:                 "cl100k_base",
		SupportsStructuredOutput: false,
	}
}
