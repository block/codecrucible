package config

import (
	"fmt"
	"strings"
	"sync"
)

// ModelConfig describes a model's capabilities, pricing, and endpoint.
//
// YAML catalogs and legacy Viper models: entries share this schema.
type ModelConfig struct {
	Aliases                    []string `yaml:"aliases,omitempty" mapstructure:"aliases"`
	RequestModel               string   `yaml:"request_model,omitempty" mapstructure:"request_model"`
	Name                       string   `yaml:"name"                                  mapstructure:"name"`
	ExactMatch                 bool     `yaml:"exact_match"                           mapstructure:"exact_match"` // Exclude this profile from aliases and partial-name matching.
	Provider                   string   `yaml:"provider"                              mapstructure:"provider"`    // "databricks", "anthropic", "openai", "google"
	Endpoint                   string   `yaml:"endpoint"                              mapstructure:"endpoint"`
	ExecutionWarning           string   `yaml:"execution_warning"                     mapstructure:"execution_warning"`
	InputPricePerM             float64  `yaml:"input_price_per_million"               mapstructure:"input_price_per_million"`
	OutputPricePerM            float64  `yaml:"output_price_per_million"              mapstructure:"output_price_per_million"`
	LongContextThreshold       int      `yaml:"long_context_threshold"                mapstructure:"long_context_threshold"`
	LongContextInputPricePerM  float64  `yaml:"long_context_input_price_per_million"  mapstructure:"long_context_input_price_per_million"`
	LongContextOutputPricePerM float64  `yaml:"long_context_output_price_per_million" mapstructure:"long_context_output_price_per_million"`
	ContextLimit               int      `yaml:"context_limit"                         mapstructure:"context_limit"`
	MaxOutputTokens            int      `yaml:"max_output_tokens"                     mapstructure:"max_output_tokens"`
	Temperature                float64  `yaml:"temperature"                           mapstructure:"temperature"`
	OmitTemperature            bool     `yaml:"omit_temperature"                      mapstructure:"omit_temperature"`
	UseMaxCompletionTokens     bool     `yaml:"use_max_completion_tokens"             mapstructure:"use_max_completion_tokens"`
	Encoding                   string   `yaml:"tokenizer_encoding"                    mapstructure:"tokenizer_encoding"`
	SupportsStructuredOutput   bool     `yaml:"supports_structured_output"            mapstructure:"supports_structured_output"`
	NativeStructuredOutput     bool     `yaml:"native_structured_output"              mapstructure:"native_structured_output"`
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

// The bundled snapshot is immutable. User configuration never mutates it.
var bundledRegistry = sync.OnceValue(func() *Registry { return BuiltinRegistry() })

// DefaultModelRegistry returns a copy of the bundled model catalog.
func DefaultModelRegistry() []ModelConfig         { return bundledRegistry().Models() }
func LookupModel(name string) (ModelConfig, bool) { return bundledRegistry().LookupModel("", name) }
func LookupModelByEndpoint(endpoint string) (ModelConfig, bool) {
	for _, m := range bundledRegistry().models {
		if m.Endpoint == endpoint {
			return cloneModel(m), true
		}
	}
	return ModelConfig{}, false
}
func DefaultModel() ModelConfig { return bundledRegistry().DefaultModel("") }

func (r *Registry) DefaultModel(provider string) ModelConfig {
	if p, ok := r.Provider(provider); ok && p.DefaultModel != "" {
		if m, ok := r.LookupModel(p.Name, p.DefaultModel); ok {
			return m
		}
	}
	for _, p := range r.providers {
		if p.DefaultModel != "" {
			if m, ok := r.LookupModel(p.Name, p.DefaultModel); ok {
				return m
			}
			// Legacy whole-entry overrides can move the historic default to
			// another provider while retaining its default model name.
			if m, ok := r.LookupModel("", p.DefaultModel); ok {
				return m
			}
		}
	}
	return UnknownModelDefaults("")
}

// LookupModel scopes capabilities and pricing to a provider. Databricks can
// proxy models from any catalog, retaining the historic deployment-name lookup.
func (r *Registry) LookupModel(provider, name string) (ModelConfig, bool) {
	matches := r.matchModels(provider, name)
	if len(matches) != 1 {
		return ModelConfig{}, false
	}
	return cloneModel(matches[0]), true
}

func normalizeAlias(name string) string {
	return strings.NewReplacer("-", "", "_", "", ".", "", " ", "").Replace(strings.ToLower(strings.TrimSpace(name)))
}
func matchesAlias(m ModelConfig, name string) bool {
	if m.ExactMatch {
		return false
	}
	for _, alias := range m.Aliases {
		if normalizeAlias(alias) == normalizeAlias(name) {
			return true
		}
	}
	return false
}

func (r *Registry) matchModels(provider, name string) []ModelConfig {
	provider = strings.ToLower(strings.TrimSpace(provider))
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return nil
	}
	var exact, aliases, partial []ModelConfig
	best := 0
	for _, m := range r.models {
		if provider != "" && m.Provider != "" && m.Provider != provider {
			continue
		}
		if strings.EqualFold(m.Name, lower) {
			exact = append(exact, m)
			continue
		}
		if matchesAlias(m, name) {
			aliases = append(aliases, m)
			continue
		}
		ml := strings.ToLower(m.Name)
		if !m.ExactMatch && (strings.Contains(lower, ml) || strings.Contains(ml, lower)) {
			if len(ml) > best {
				best = len(ml)
				partial = nil
			}
			if len(ml) == best {
				partial = append(partial, m)
			}
		}
	}
	if len(exact) > 0 {
		return exact
	}
	if len(aliases) > 0 {
		return aliases
	}
	if len(partial) > 0 {
		return partial
	}
	if provider == "databricks" {
		return r.matchModels("", name)
	}
	return nil
}

// ResolveModel preserves user-supplied deployment IDs for legacy partial
// matches. Declared aliases and request_model explicitly select a wire model ID.
func (r *Registry) ResolveModel(provider, name string) (ModelConfig, error) {
	if strings.TrimSpace(name) == "" {
		m := r.DefaultModel(provider)
		if m.RequestModel != "" {
			m.Name = m.RequestModel
		}
		return m, nil
	}
	matches := r.matchModels(provider, name)
	if len(matches) > 1 {
		return ModelConfig{}, fmt.Errorf("model %q is ambiguous; select a provider explicitly", name)
	}
	if len(matches) == 0 {
		return UnknownModelDefaults(name), nil
	}
	m := cloneModel(matches[0])
	if m.RequestModel != "" {
		m.Name = m.RequestModel
	} else if !matchesAlias(m, name) {
		m.Name = name
	}
	return m, nil
}

func (r *Registry) validateAliases() error {
	canonical := map[string][]string{}
	aliases := map[string]string{}
	for _, m := range r.models {
		key := m.Provider + "/" + normalizeAlias(m.Name)
		canonical[key] = append(canonical[key], m.Name)
	}
	for _, m := range r.models {
		if m.ExactMatch {
			continue
		}
		for _, alias := range m.Aliases {
			if normalizeAlias(alias) == "" {
				return fmt.Errorf("model %q: alias cannot be empty", m.Name)
			}
			key := m.Provider + "/" + normalizeAlias(alias)
			for _, name := range canonical[key] {
				if name != m.Name {
					return fmt.Errorf("provider %q: alias %q conflicts with model %q", m.Provider, alias, name)
				}
			}
			if old, ok := aliases[key]; ok && old != m.Name {
				return fmt.Errorf("provider %q: alias %q conflicts with model %q", m.Provider, alias, old)
			}
			aliases[key] = m.Name
		}
	}
	return nil
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
