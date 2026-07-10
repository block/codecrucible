package config

import (
	"fmt"
	"strings"
	"sync"
)

// ModelConfig describes a model's capabilities, pricing, and endpoint.
//
// Both yaml and mapstructure tags are set so the same struct literal in
// defaultModels can also be populated by Viper from a user's config file
// (Viper uses mapstructure for Unmarshal).
type ModelConfig struct {
	Name                       string  `yaml:"name"                                  mapstructure:"name"`
	Provider                   string  `yaml:"provider"                              mapstructure:"provider"` // "databricks", "anthropic", "openai", "google"
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

// defaultModels is the built-in model registry.
var defaultModels = []ModelConfig{
	{
		// Sonnet 5 enables adaptive thinking by default. Anthropic documents
		// temperature changes as incompatible with thinking, so omit it.
		Name:                     "claude-sonnet-5",
		Provider:                 "anthropic",
		Endpoint:                 "claude-sonnet-5/invocations",
		InputPricePerM:           2.0,  // Introductory price through 2026-08-31.
		OutputPricePerM:          10.0, // Introductory price through 2026-08-31.
		ContextLimit:             1000000,
		MaxOutputTokens:          128000,
		Temperature:              0.0,
		OmitTemperature:          true,
		Encoding:                 "claude",
		SupportsStructuredOutput: true,
		NativeStructuredOutput:   true,
	},
	{
		Name:                     "claude-opus-4-8",
		Provider:                 "anthropic",
		Endpoint:                 "claude-opus-4-8/invocations",
		InputPricePerM:           5.0,
		OutputPricePerM:          25.0,
		ContextLimit:             1000000,
		MaxOutputTokens:          128000,
		Temperature:              0.0,
		Encoding:                 "claude",
		SupportsStructuredOutput: true,
		NativeStructuredOutput:   true,
	},
	{
		// Fable 5 always uses adaptive thinking and cannot disable it.
		Name:                     "claude-fable-5",
		Provider:                 "anthropic",
		Endpoint:                 "claude-fable-5/invocations",
		ExecutionWarning:         "claude-fable-5 may trigger security-policy errors during security analysis and invalidate scan results",
		InputPricePerM:           10.0,
		OutputPricePerM:          50.0,
		ContextLimit:             1000000,
		MaxOutputTokens:          128000,
		Temperature:              0.0,
		OmitTemperature:          true,
		Encoding:                 "claude",
		SupportsStructuredOutput: true,
		NativeStructuredOutput:   true,
	},
	{
		Name:                     "claude-haiku-4-5",
		Provider:                 "anthropic",
		Endpoint:                 "claude-haiku-4-5/invocations",
		InputPricePerM:           1.0,
		OutputPricePerM:          5.0,
		ContextLimit:             200000,
		MaxOutputTokens:          64000,
		Temperature:              0.0,
		Encoding:                 "claude",
		SupportsStructuredOutput: true,
		NativeStructuredOutput:   true,
	},
	{
		// Block-internal Databricks serving endpoint. Keep workspace serving
		// aliases explicit: public provider model IDs do not establish which
		// internal deployment name a workspace exposes.
		Name:                     "goose-claude-4-6-opus",
		Provider:                 "databricks",
		Endpoint:                 "goose-claude-4-6-opus/invocations",
		InputPricePerM:           5.0,
		OutputPricePerM:          25.0,
		ContextLimit:             200000,
		MaxOutputTokens:          32768,
		Temperature:              0.0,
		Encoding:                 "claude",
		SupportsStructuredOutput: true,
	},
	{
		// Block-internal Databricks serving endpoint. Keep workspace serving
		// aliases explicit: public provider model IDs do not establish which
		// internal deployment name a workspace exposes.
		Name:                     "goose-claude-4-7-opus",
		Provider:                 "databricks",
		Endpoint:                 "goose-claude-4-7-opus/invocations",
		InputPricePerM:           5.0,
		OutputPricePerM:          25.0,
		ContextLimit:             1000000,
		MaxOutputTokens:          128000,
		Temperature:              0.0,
		Encoding:                 "claude",
		SupportsStructuredOutput: true,
	},
	{
		// GPT-5.6 is the documented alias for gpt-5.6-sol. Keep both names in
		// the registry so users can select the stable alias or the exact tier.
		// OpenAI documents real-time cyber/biology safeguards for this family;
		// in a security scan those can interrupt generation and invalidate the
		// resulting findings. Omit an explicit temperature for this family and
		// let the API apply its default.
		Name:                       "gpt-5.6",
		Provider:                   "openai",
		Endpoint:                   "gpt-5.6/invocations",
		ExecutionWarning:           "gpt-5.6 models may trigger real-time cyber safeguards during security analysis, which can block or pause generation and invalidate scan results",
		InputPricePerM:             5.00,
		OutputPricePerM:            30.0,
		LongContextThreshold:       272000,
		LongContextInputPricePerM:  10.0,
		LongContextOutputPricePerM: 45.0,
		ContextLimit:               1050000,
		MaxOutputTokens:            128000,
		Temperature:                0.0,
		OmitTemperature:            true,
		UseMaxCompletionTokens:     true,
		Encoding:                   "o200k_base",
		SupportsStructuredOutput:   true,
	},
	{
		Name:                       "gpt-5.6-sol",
		Provider:                   "openai",
		Endpoint:                   "gpt-5.6-sol/invocations",
		ExecutionWarning:           "gpt-5.6 models may trigger real-time cyber safeguards during security analysis, which can block or pause generation and invalidate scan results",
		InputPricePerM:             5.00,
		OutputPricePerM:            30.0,
		LongContextThreshold:       272000,
		LongContextInputPricePerM:  10.0,
		LongContextOutputPricePerM: 45.0,
		ContextLimit:               1050000,
		MaxOutputTokens:            128000,
		Temperature:                0.0,
		OmitTemperature:            true,
		UseMaxCompletionTokens:     true,
		Encoding:                   "o200k_base",
		SupportsStructuredOutput:   true,
	},
	{
		Name:                       "gpt-5.6-terra",
		Provider:                   "openai",
		Endpoint:                   "gpt-5.6-terra/invocations",
		ExecutionWarning:           "gpt-5.6 models may trigger real-time cyber safeguards during security analysis, which can block or pause generation and invalidate scan results",
		InputPricePerM:             2.50,
		OutputPricePerM:            15.0,
		LongContextThreshold:       272000,
		LongContextInputPricePerM:  5.0,
		LongContextOutputPricePerM: 22.5,
		ContextLimit:               1050000,
		MaxOutputTokens:            128000,
		Temperature:                0.0,
		OmitTemperature:            true,
		UseMaxCompletionTokens:     true,
		Encoding:                   "o200k_base",
		SupportsStructuredOutput:   true,
	},
	{
		Name:                       "gpt-5.6-luna",
		Provider:                   "openai",
		Endpoint:                   "gpt-5.6-luna/invocations",
		ExecutionWarning:           "gpt-5.6 models may trigger real-time cyber safeguards during security analysis, which can block or pause generation and invalidate scan results",
		InputPricePerM:             1.00,
		OutputPricePerM:            6.0,
		LongContextThreshold:       272000,
		LongContextInputPricePerM:  2.0,
		LongContextOutputPricePerM: 9.0,
		ContextLimit:               1050000,
		MaxOutputTokens:            128000,
		Temperature:                0.0,
		OmitTemperature:            true,
		UseMaxCompletionTokens:     true,
		Encoding:                   "o200k_base",
		SupportsStructuredOutput:   true,
	},
	{
		Name:                       "gpt-5.5",
		Provider:                   "openai",
		Endpoint:                   "gpt-5.5/invocations",
		InputPricePerM:             5.00,
		OutputPricePerM:            30.0,
		LongContextThreshold:       272000,
		LongContextInputPricePerM:  10.0,
		LongContextOutputPricePerM: 45.0,
		ContextLimit:               1050000,
		MaxOutputTokens:            128000,
		Temperature:                1.0,
		UseMaxCompletionTokens:     true,
		Encoding:                   "o200k_base",
		SupportsStructuredOutput:   true,
	},
	{
		// Private/preview cyber alias. Public provider docs do not publish
		// limits or pricing for this slug yet, so keep GPT-5.5 request
		// semantics and base prices while flagging the registry data as
		// provisional. Its observed 272K window cannot reach GPT-5.5's
		// long-context tier under the default registry limit.
		Name:                     "gpt-5.5-cyber-preview",
		Provider:                 "openai",
		Endpoint:                 "gpt-5.5-cyber-preview/invocations",
		ExecutionWarning:         "gpt-5.5-cyber-preview registry parameters and pricing are provisional; cost estimates currently use gpt-5.5 rates",
		InputPricePerM:           5.00,
		OutputPricePerM:          30.0,
		ContextLimit:             272000,
		MaxOutputTokens:          128000,
		Temperature:              1.0,
		UseMaxCompletionTokens:   true,
		Encoding:                 "o200k_base",
		SupportsStructuredOutput: true,
	},
	{
		// Private cyber alias with the same provisional treatment as preview.
		Name:                     "gpt-5.5-cyber",
		Provider:                 "openai",
		Endpoint:                 "gpt-5.5-cyber/invocations",
		ExecutionWarning:         "gpt-5.5-cyber registry parameters and pricing are provisional; cost estimates currently use gpt-5.5 rates",
		InputPricePerM:           5.00,
		OutputPricePerM:          30.0,
		ContextLimit:             272000,
		MaxOutputTokens:          128000,
		Temperature:              1.0,
		UseMaxCompletionTokens:   true,
		Encoding:                 "o200k_base",
		SupportsStructuredOutput: true,
	},
	{
		Name:                       "gpt-5.4",
		Provider:                   "openai",
		Endpoint:                   "gpt-5.4/invocations",
		InputPricePerM:             2.50,
		OutputPricePerM:            15.0,
		LongContextThreshold:       272000,
		LongContextInputPricePerM:  5.0,
		LongContextOutputPricePerM: 22.5,
		ContextLimit:               1050000,
		MaxOutputTokens:            128000,
		Temperature:                0.0,
		UseMaxCompletionTokens:     true,
		Encoding:                   "o200k_base",
		SupportsStructuredOutput:   true,
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
		UseMaxCompletionTokens:   true,
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
		UseMaxCompletionTokens:   true,
		Encoding:                 "o200k_base",
		SupportsStructuredOutput: true,
	},
	{
		Name:                       "gemini-3.1-pro-preview",
		Provider:                   "google",
		Endpoint:                   "gemini-3.1-pro-preview/invocations",
		InputPricePerM:             2.0,
		OutputPricePerM:            12.0,
		LongContextThreshold:       200000,
		LongContextInputPricePerM:  4.0,
		LongContextOutputPricePerM: 18.0,
		ContextLimit:               1048576,
		MaxOutputTokens:            65536,
		Temperature:                0.0,
		Encoding:                   "cl100k_base",
		// Google's OpenAI-compat endpoint accepts response_format json_schema.
		SupportsStructuredOutput: true,
	},
	{
		Name:                     "gemini-3.5-flash",
		Provider:                 "google",
		Endpoint:                 "gemini-3.5-flash/invocations",
		InputPricePerM:           1.50,
		OutputPricePerM:          9.00,
		ContextLimit:             1048576,
		MaxOutputTokens:          65536,
		Temperature:              0.0,
		Encoding:                 "cl100k_base",
		SupportsStructuredOutput: true,
	},
	{
		Name:                     "gemini-3.1-flash-lite",
		Provider:                 "google",
		Endpoint:                 "gemini-3.1-flash-lite/invocations",
		InputPricePerM:           0.25,
		OutputPricePerM:          1.50,
		ContextLimit:             1048576,
		MaxOutputTokens:          65536,
		Temperature:              0.0,
		Encoding:                 "cl100k_base",
		SupportsStructuredOutput: true,
	},
}

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
