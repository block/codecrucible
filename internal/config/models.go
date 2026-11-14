package config

import (
	"fmt"
	"strings"
	"sync"
)

// ModelConfig describes a model's capabilities, pricing, and endpoint.
//
// Both tags support embedded provider YAML and legacy Viper models: entries.
type ModelConfig struct {
	Name                       string  `yaml:"name"                                  mapstructure:"name"`
	ExactMatch                 bool    `yaml:"exact_match"                           mapstructure:"exact_match"` // Exclude this profile from aliases and partial-name matching.
	Provider                   string  `yaml:"provider"                              mapstructure:"provider"`    // "databricks", "anthropic", "openai", "google"
	Endpoint                   string  `yaml:"endpoint"                              mapstructure:"endpoint"`
	ExecutionWarning           string  `yaml:"execution_warning"                     mapstructure:"execution_warning"`
	InputPricePerM             float64 `yaml:"input_price_per_million"               mapstructure:"input_price_per_million"`
	OutputPricePerM            float64 `yaml:"output_price_per_million"              mapstructure:"output_price_per_million"`
	LongContextThreshold       int     `yaml:"long_context_threshold"                mapstructure:"long_context_threshold"`
	LongContextInputPricePerM  float64 `yaml:"long_context_input_price_per_million"  mapstructure:"long_context_input_price_per_million"`
	LongContextOutputPricePerM float64 `yaml:"long_context_output_price_per_million" mapstructure:"long_context_output_price_per_million"`
	ContextLimit               int     `yaml:"context_limit"                         mapstructure:"context_limit"`
	MaxOutputTokens            int     `yaml:"max_output_tokens"                     mapstructure:"max_output_tokens"`
	Temperature                float64 `yaml:"temperature"                           mapstructure:"temperature"`
	OmitTemperature            bool    `yaml:"omit_temperature"                      mapstructure:"omit_temperature"`
	UseMaxCompletionTokens     bool    `yaml:"use_max_completion_tokens"             mapstructure:"use_max_completion_tokens"`
	Encoding                   string  `yaml:"tokenizer_encoding"                    mapstructure:"tokenizer_encoding"`
	SupportsStructuredOutput   bool    `yaml:"supports_structured_output"            mapstructure:"supports_structured_output"`
	NativeStructuredOutput     bool    `yaml:"native_structured_output"              mapstructure:"native_structured_output"`
}

// modelsMu protects defaultModels for concurrent access.
var modelsMu sync.RWMutex

// defaultModels preserves the existing model registry behavior; the bundled
// entries are loaded from the embedded provider YAML catalog.
var defaultModels = builtinModels()

// EstimateInputCost returns the input-token charge for one request. Providers
// with long-context tiers apply the higher rate to the whole request once the
// prompt crosses the documented threshold.
func (m ModelConfig) EstimateInputCost(inputTokens int) float64 {
	inputPrice, _ := m.pricesForInputTokens(inputTokens)
	return float64(inputTokens) * inputPrice / 1_000_000
}

// EstimateCost returns the input and output token charge for one request.
func (m ModelConfig) EstimateCost(inputTokens, outputTokens int) float64 {
	inputPrice, outputPrice := m.pricesForInputTokens(inputTokens)
	return float64(inputTokens)*inputPrice/1_000_000 +
		float64(outputTokens)*outputPrice/1_000_000
}

func (m ModelConfig) pricesForInputTokens(inputTokens int) (float64, float64) {
	if m.LongContextThreshold > 0 && inputTokens > m.LongContextThreshold {
		inputPrice := m.LongContextInputPricePerM
		if inputPrice == 0 {
			inputPrice = m.InputPricePerM
		}
		outputPrice := m.LongContextOutputPricePerM
		if outputPrice == 0 {
			outputPrice = m.OutputPricePerM
		}
		return inputPrice, outputPrice
	}
	return m.InputPricePerM, m.OutputPricePerM
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

// RegisterUserModels registers user-defined model configs into the registry.
// Each entry must have a non-empty Name. Entries with a name that matches a
// built-in are replaced (case-insensitive), so this is also how users override
// built-in pricing / context limits without forking. Empty Endpoint defaults
// to "<name>/invocations" to match the built-in convention (Databricks serving
// path; other providers ignore it).
func RegisterUserModels(models []ModelConfig) error {
	for i, m := range models {
		if strings.TrimSpace(m.Name) == "" {
			return fmt.Errorf("models[%d]: name is required", i)
		}
		if m.Endpoint == "" {
			m.Endpoint = m.Name + "/invocations"
		}
		RegisterModel(m)
	}
	return nil
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
// Unless a profile requires an exact match, it matches if either the query
// contains a known model name, or a known model name contains the query.
// This handles Databricks-prefixed names like
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
	// Known Kimi shorthand is routed to the deployed API model. Keep exact
	// user registry entries above authoritative, including a custom "kimi".
	if isKimiAlias(name) {
		for _, m := range defaultModels {
			if strings.EqualFold(m.Name, "kimi-k2.6") && !m.ExactMatch {
				return m, true
			}
		}
	}
	// Partial match: query contains model name, or model name contains query.
	// Try longest match first to avoid "claude-opus-4" matching before a more specific entry.
	var best ModelConfig
	bestLen := 0
	found := false
	for _, m := range defaultModels {
		if m.ExactMatch {
			continue
		}
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

// DefaultModel returns the default model.
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

// isKimiAlias tolerates case and common separators but deliberately does not
// map unknown versions or arbitrary names containing "kimi" to this deployment.
func isKimiAlias(name string) bool {
	normalized := strings.ToLower(strings.TrimSpace(name))
	normalized = strings.NewReplacer("-", "", "_", "", ".", "", " ", "").Replace(normalized)
	switch normalized {
	case "kimi", "kimik2", "kimik26":
		return true
	default:
		return false
	}
}
