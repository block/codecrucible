package config

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"os"

	"go.yaml.in/yaml/v3"
)

// ProviderConfig registers a service using one of the existing API protocols.
// YAML defines connection settings; Go still implements each wire format.
type ProviderConfig struct {
	Name     string `yaml:"name"`
	Protocol string `yaml:"protocol"`
	BaseURL  string `yaml:"base_url"`
	Auth     struct {
		Type      string `yaml:"type"`
		APIKeyEnv string `yaml:"api_key_env"`
	} `yaml:"auth"`
	Request struct {
		Path           string `yaml:"path"`
		MaxTokensField string `yaml:"max_tokens_field"`
	} `yaml:"request"`
	Discovery struct {
		Format string `yaml:"format"`
		Path   string `yaml:"path"`
	} `yaml:"discovery"`
	Headers map[string]string `yaml:"headers"`
	Models  []ModelConfig     `yaml:"models"`
}

//go:embed providers/*.yaml
var providerFiles embed.FS

var builtinProviders = func() []ProviderConfig {
	providers, err := loadProviders(providerFiles)
	if err != nil {
		panic(err)
	}
	return providers
}()

func loadProviders(files fs.FS) ([]ProviderConfig, error) {
	paths, err := fs.Glob(files, "providers/*.yaml")
	if err != nil {
		return nil, err
	}
	var providers []ProviderConfig
	seen := map[string]bool{}
	for _, path := range paths {
		data, err := fs.ReadFile(files, path)
		if err != nil {
			return nil, err
		}
		var p ProviderConfig
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		decoder.KnownFields(true)
		if err := decoder.Decode(&p); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if p.Name == "" || seen[p.Name] {
			return nil, fmt.Errorf("%s: missing or duplicate provider name %q", path, p.Name)
		}
		switch p.Protocol {
		case "openai-chat", "anthropic-messages", "databricks":
		default:
			return nil, fmt.Errorf("%s: unsupported protocol %q", path, p.Protocol)
		}
		if p.Request.Path == "" {
			return nil, fmt.Errorf("%s: request.path is required", path)
		}
		switch p.Auth.Type {
		case "none", "bearer", "api-key", "optional-bearer":
		default:
			return nil, fmt.Errorf("%s: unsupported auth type %q", path, p.Auth.Type)
		}
		switch p.Request.MaxTokensField {
		case "", "max_tokens", "max_completion_tokens":
		default:
			return nil, fmt.Errorf("%s: unsupported max_tokens_field %q", path, p.Request.MaxTokensField)
		}
		switch p.Discovery.Format {
		case "openai-models", "anthropic-models", "ollama-tags", "databricks", "none":
		default:
			return nil, fmt.Errorf("%s: unsupported discovery format %q", path, p.Discovery.Format)
		}
		for _, m := range p.Models {
			if m.Name == "" {
				return nil, fmt.Errorf("%s: model name is required", path)
			}
		}
		seen[p.Name] = true
		providers = append(providers, p)
	}
	return providers, nil
}

func LookupProvider(name string) (ProviderConfig, bool) {
	for _, p := range builtinProviders {
		if p.Name == name {
			return p, true
		}
	}
	return ProviderConfig{}, false
}

func ProviderNames() []string {
	names := make([]string, 0, len(builtinProviders))
	for _, p := range builtinProviders {
		names = append(names, p.Name)
	}
	return names
}

func builtinModels() []ModelConfig {
	var models []ModelConfig
	for _, p := range builtinProviders {
		for _, m := range p.Models {
			m.Provider = p.Name
			models = append(models, m)
		}
	}
	return models
}

// ProviderKey retains the existing configuration fields and their environment
// aliases. Additional YAML providers resolve the variable named in their file.
func (cfg *Config) ProviderKey(provider string) string {
	p, ok := LookupProvider(provider)
	if !ok {
		return ""
	}
	switch p.Auth.APIKeyEnv {
	case "ANTHROPIC_API_KEY":
		return cfg.AnthropicAPIKey
	case "OPENAI_API_KEY":
		return cfg.OpenAIAPIKey
	case "GOOGLE_API_KEY":
		return cfg.GoogleAPIKey
	case "CEREBRAS_API_KEY":
		return cfg.CerebrasAPIKey
	case "DATABRICKS_TOKEN":
		return cfg.DatabricksToken
	}
	return os.Getenv(p.Auth.APIKeyEnv)
}
