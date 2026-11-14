package config

import (
	"bytes"
	"embed"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// ProviderConfig describes a service using a supported API protocol. Credentials
// are resolved at runtime; provider files contain environment variable names only.
type ProviderConfig struct {
	SchemaVersion      int               `yaml:"schema_version"`
	Name               string            `yaml:"name"`
	Protocol           string            `yaml:"protocol"`
	BaseURL            string            `yaml:"base_url"`
	DefaultModel       string            `yaml:"default_model,omitempty"`
	AutoDetectPriority int               `yaml:"auto_detect_priority,omitempty"`
	RequireModel       bool              `yaml:"require_model,omitempty"`
	WarnUnpriced       bool              `yaml:"warn_unpriced,omitempty"`
	Fallback           string            `yaml:"fallback,omitempty"`
	Auth               ProviderAuth      `yaml:"auth"`
	Request            ProviderRequest   `yaml:"request"`
	Discovery          ProviderDiscovery `yaml:"discovery"`
	Headers            map[string]string `yaml:"headers,omitempty"`
	Models             []ModelConfig     `yaml:"models,omitempty"`
}

type ProviderAuth struct {
	Type      string `yaml:"type"`
	APIKeyEnv string `yaml:"api_key_env,omitempty"`
}

type ProviderRequest struct {
	Path           string `yaml:"path"`
	MaxTokensField string `yaml:"max_tokens_field,omitempty"`
}

type ProviderDiscovery struct {
	Format string `yaml:"format"`
	Path   string `yaml:"path"`
}

//go:embed providers/*.yaml
var providerFiles embed.FS

// Registry is an immutable snapshot of built-in catalogs plus local overrides.
// Each configuration load owns a separate snapshot; accessors return copies.
type Registry struct {
	providers []ProviderConfig
	models    []ModelConfig
}

// BuiltinRegistry loads the embedded definitions. Invalid bundled YAML is a
// programming error, caught by registry tests and validate-providers.
func BuiltinRegistry() *Registry {
	r, err := LoadRegistry(nil, nil)
	if err != nil {
		panic("invalid built-in provider catalog: " + err.Error())
	}
	return r
}

// LoadRegistry loads external provider files in order, then applies legacy
// models: entries as whole-entry replacements. External provider/model entries
// patch named built-ins field by field, including explicit false and zero values.
func LoadRegistry(files []string, legacy []ModelConfig) (*Registry, error) {
	r := &Registry{}
	definitions := map[string]map[string]any{}
	entries, err := providerFiles.ReadDir("providers")
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		data, err := providerFiles.ReadFile("providers/" + entry.Name())
		if err != nil {
			return nil, err
		}
		if err := r.loadDefinition(data, "embedded "+entry.Name(), definitions); err != nil {
			return nil, err
		}
	}

	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("provider file %s: %w", path, err)
		}
		if err := r.loadDefinition(data, path, definitions); err != nil {
			return nil, err
		}
	}
	for i, m := range legacy {
		m.Provider = strings.ToLower(strings.TrimSpace(m.Provider))
		if strings.TrimSpace(m.Name) == "" {
			return nil, fmt.Errorf("models[%d]: name is required", i)
		}
		if m.Provider != "" {
			if _, ok := r.Provider(m.Provider); !ok {
				return nil, fmt.Errorf("models[%d]: unsupported provider %q", i, m.Provider)
			}
		}
		if m.Endpoint == "" {
			m.Endpoint = m.Name + "/invocations"
		}
		// Legacy entries historically replaced by name, including the provider hint.
		next := r.models[:0]
		for _, old := range r.models {
			if !strings.EqualFold(old.Name, m.Name) {
				next = append(next, old)
			}
		}
		r.models = append(next, cloneModel(m))
	}
	if err := r.validateAliases(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Registry) loadDefinition(data []byte, source string, defs map[string]map[string]any) error {
	var patch map[string]any
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&patch); err != nil {
		return fmt.Errorf("%s: %w", source, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("%s: expected exactly one YAML document", source)
	}
	// Decode the patch independently to reject unknown fields even when null.
	var typed ProviderConfig
	strict := yaml.NewDecoder(bytes.NewReader(data))
	strict.KnownFields(true)
	if err := strict.Decode(&typed); err != nil {
		return fmt.Errorf("%s: %w", source, err)
	}
	if typed.SchemaVersion != 1 {
		return fmt.Errorf("%s: schema_version must be 1", source)
	}
	if !providerName.MatchString(typed.Name) {
		return fmt.Errorf("%s: name must use lowercase letters, digits, and hyphens", source)
	}
	for _, m := range typed.Models {
		if m.Provider != "" && m.Provider != typed.Name {
			return fmt.Errorf("%s: model %q belongs to provider %q", source, m.Name, m.Provider)
		}
	}
	merged, err := mergeDefinition(defs[typed.Name], patch)
	if err != nil {
		return fmt.Errorf("%s: %w", source, err)
	}
	encoded, err := yaml.Marshal(merged)
	if err != nil {
		return fmt.Errorf("%s: %w", source, err)
	}
	var p ProviderConfig
	strict = yaml.NewDecoder(bytes.NewReader(encoded))
	strict.KnownFields(true)
	if err := strict.Decode(&p); err != nil {
		return fmt.Errorf("%s: %w", source, err)
	}
	if err := validateProvider(p); err != nil {
		return fmt.Errorf("%s: %w", source, err)
	}
	defs[p.Name] = merged
	replaced := false
	for i, old := range r.providers {
		if old.Name == p.Name {
			r.providers[i] = p
			replaced = true
			break
		}
	}
	if !replaced {
		r.providers = append(r.providers, p)
	}
	next := r.models[:0]
	for _, m := range r.models {
		if m.Provider != p.Name {
			next = append(next, m)
		}
	}
	r.models = next
	for _, m := range p.Models {
		m.Provider = p.Name
		if m.Endpoint == "" {
			m.Endpoint = m.Name + "/invocations"
		}
		r.models = append(r.models, m)
	}
	if err := r.validateAliases(); err != nil {
		return fmt.Errorf("%s: %w", source, err)
	}
	return nil
}

// mergeDefinition merges mappings and patches the model sequence by name. Other
// sequences (notably aliases) replace, so [] explicitly clears an inherited list.
func mergeDefinition(base, patch map[string]any) (map[string]any, error) {
	return mergeCatalogMap(base, patch, true)
}

func mergeCatalogMap(base, patch map[string]any, providerRoot bool) (map[string]any, error) {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range patch {
		if providerRoot && k == "models" {
			items, ok := v.([]any)
			if !ok {
				return nil, fmt.Errorf("models must be a sequence")
			}
			existing, _ := out[k].([]any)
			models := append([]any{}, existing...)
			seen := map[string]bool{}
			for _, item := range items {
				m, ok := item.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("model must be a mapping")
				}
				name, _ := m["name"].(string)
				key := strings.ToLower(name)
				if strings.TrimSpace(name) == "" || seen[key] {
					return nil, fmt.Errorf("missing or duplicate model name %q", name)
				}
				seen[key] = true
				index := -1
				for i, old := range models {
					om, _ := old.(map[string]any)
					on, _ := om["name"].(string)
					if strings.EqualFold(on, name) {
						index = i
						break
					}
				}
				if index >= 0 {
					combined, err := mergeCatalogMap(models[index].(map[string]any), m, false)
					if err != nil {
						return nil, err
					}
					models[index] = combined
				} else {
					// Unknown models retain conservative limits until operators supply them.
					defaults := UnknownModelDefaults(name)
					dm := map[string]any{"name": defaults.Name, "endpoint": defaults.Endpoint, "context_limit": defaults.ContextLimit, "max_output_tokens": defaults.MaxOutputTokens, "tokenizer_encoding": defaults.Encoding}
					combined, err := mergeCatalogMap(dm, m, false)
					if err != nil {
						return nil, err
					}
					models = append(models, combined)
				}
			}
			out[k] = models
			continue
		}
		if vm, ok := v.(map[string]any); ok {
			bm, _ := out[k].(map[string]any)
			merged, err := mergeCatalogMap(bm, vm, false)
			if err != nil {
				return nil, err
			}
			out[k] = merged
		} else {
			out[k] = v
		}
	}
	return out, nil
}

var providerName = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func validateProvider(p ProviderConfig) error {
	switch p.Protocol {
	case "openai-chat", "anthropic-messages", "databricks":
	default:
		return fmt.Errorf("unsupported protocol %q", p.Protocol)
	}
	switch p.Auth.Type {
	case "bearer", "optional-bearer", "api-key", "none":
	default:
		return fmt.Errorf("unsupported auth type %q", p.Auth.Type)
	}
	if p.Auth.APIKeyEnv != "" && !envName.MatchString(p.Auth.APIKeyEnv) {
		return fmt.Errorf("invalid api_key_env %q", p.Auth.APIKeyEnv)
	}
	if p.BaseURL != "" {
		u, err := url.Parse(p.BaseURL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("base_url must be an HTTP(S) URL without credentials, query, or fragment")
		}
	}
	if err := validatePath(p.Request.Path, p.Protocol == "databricks"); err != nil {
		return fmt.Errorf("request.path: %w", err)
	}
	if p.Request.MaxTokensField != "" && p.Request.MaxTokensField != "max_tokens" && p.Request.MaxTokensField != "max_completion_tokens" {
		return fmt.Errorf("unsupported max_tokens_field %q", p.Request.MaxTokensField)
	}
	if p.Protocol != "openai-chat" && p.Request.MaxTokensField == "max_completion_tokens" {
		return fmt.Errorf("max_completion_tokens requires openai-chat")
	}
	switch p.Discovery.Format {
	case "openai-models", "anthropic-models", "ollama-tags", "databricks", "none":
	default:
		return fmt.Errorf("unsupported discovery format %q", p.Discovery.Format)
	}
	if p.Discovery.Format != "none" {
		if err := validatePath(p.Discovery.Path, false); err != nil {
			return fmt.Errorf("discovery.path: %w", err)
		}
	}
	if p.Fallback != "" && (p.Fallback != "claude-cli" || p.Protocol != "anthropic-messages") {
		return fmt.Errorf("fallback must be claude-cli with anthropic-messages")
	}
	if p.AutoDetectPriority < 0 {
		return fmt.Errorf("auto_detect_priority cannot be negative")
	}
	for k, v := range p.Headers {
		if !validHeader(k, v) {
			return fmt.Errorf("invalid header %q", k)
		}
		lower := strings.ToLower(k)
		if lower == "authorization" || lower == "x-api-key" || lower == "api-key" || lower == "cookie" {
			return fmt.Errorf("use auth.api_key_env for credentials instead of header %q", k)
		}
	}
	for _, m := range p.Models {
		if strings.TrimSpace(m.Name) == "" || strings.TrimSpace(m.Name) != m.Name {
			return fmt.Errorf("model name must be nonempty without surrounding whitespace")
		}
		for _, value := range []float64{m.InputPricePerM, m.OutputPricePerM, m.LongContextInputPricePerM, m.LongContextOutputPricePerM, m.Temperature} {
			if math.IsNaN(value) || math.IsInf(value, 0) {
				return fmt.Errorf("model %q: numeric values must be finite", m.Name)
			}
		}
		if m.ContextLimit <= 0 || m.MaxOutputTokens <= 0 || m.MaxOutputTokens > m.ContextLimit {
			return fmt.Errorf("model %q: require positive limits with max_output_tokens <= context_limit", m.Name)
		}
		if m.InputPricePerM < 0 || m.OutputPricePerM < 0 || m.LongContextInputPricePerM < 0 || m.LongContextOutputPricePerM < 0 || m.LongContextThreshold < 0 {
			return fmt.Errorf("model %q: pricing and thresholds cannot be negative", m.Name)
		}
	}
	if p.DefaultModel != "" {
		found := false
		for _, m := range p.Models {
			if strings.EqualFold(m.Name, p.DefaultModel) {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("default_model %q is not in this provider's models", p.DefaultModel)
		}
	}
	return nil
}

func validatePath(path string, endpoint bool) error {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "?#\\\r\n") {
		return fmt.Errorf("must be a path beginning with a single /")
	}
	check := path
	if endpoint {
		check = strings.ReplaceAll(check, "{endpoint}", "model")
	}
	if strings.ContainsAny(check, "{}") {
		return fmt.Errorf("unsupported path placeholder")
	}
	for _, part := range strings.Split(check, "/") {
		if part == ".." || part == "." {
			return fmt.Errorf("path traversal is not supported")
		}
	}
	return nil
}

func validHeader(k, v string) bool {
	if k == "" || strings.ContainsAny(v, "\r\n") {
		return false
	}
	for _, c := range k {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
			return false
		}
	}
	return true
}

func cloneModel(m ModelConfig) ModelConfig { m.Aliases = append([]string(nil), m.Aliases...); return m }
func cloneProvider(p ProviderConfig) ProviderConfig {
	p.Models = append([]ModelConfig(nil), p.Models...)
	for i := range p.Models {
		p.Models[i] = cloneModel(p.Models[i])
	}
	h := map[string]string{}
	for k, v := range p.Headers {
		h[k] = v
	}
	p.Headers = h
	return p
}

func (r *Registry) Provider(name string) (ProviderConfig, bool) {
	for _, p := range r.providers {
		if p.Name == strings.ToLower(strings.TrimSpace(name)) {
			out := cloneProvider(p)
			out.Models = nil
			for _, m := range r.models {
				if m.Provider == p.Name {
					out.Models = append(out.Models, cloneModel(m))
				}
			}
			return out, true
		}
	}
	return ProviderConfig{}, false
}
func (r *Registry) Providers() []ProviderConfig {
	out := make([]ProviderConfig, len(r.providers))
	for i, p := range r.providers {
		out[i] = cloneProvider(p)
		out[i].Models = nil
		for _, m := range r.models {
			if m.Provider == p.Name {
				out[i].Models = append(out[i].Models, cloneModel(m))
			}
		}
	}
	return out
}
func (r *Registry) Models() []ModelConfig {
	out := make([]ModelConfig, len(r.models))
	for i, m := range r.models {
		out[i] = cloneModel(m)
	}
	return out
}

// ConfigRegistry supports programmatic callers that construct Config directly.
func (cfg *Config) ConfigRegistry() *Registry {
	if cfg.Registry != nil {
		return cfg.Registry
	}
	return bundledRegistry()
}

// ProviderKey preserves the legacy configuration fields and environment aliases,
// then resolves arbitrary provider-defined credential variable names.
func (cfg *Config) ProviderKey(p ProviderConfig) string {
	// Only use a legacy field when the catalog still names its legacy variable.
	// An overridden credential source must not reuse another environment's key.
	legacy := map[string]struct{ env, key string }{
		"anthropic":  {"ANTHROPIC_API_KEY", cfg.AnthropicAPIKey},
		"openai":     {"OPENAI_API_KEY", cfg.OpenAIAPIKey},
		"google":     {"GOOGLE_API_KEY", cfg.GoogleAPIKey},
		"cerebras":   {"CEREBRAS_API_KEY", cfg.CerebrasAPIKey},
		"databricks": {"DATABRICKS_TOKEN", cfg.DatabricksToken},
	}
	if value, ok := legacy[p.Name]; ok && p.Auth.APIKeyEnv == value.env && value.key != "" {
		return value.key
	}
	return os.Getenv(p.Auth.APIKeyEnv)
}
func (p ProviderConfig) AuthHeaders(key string) http.Header {
	h := http.Header{}
	for k, v := range p.Headers {
		h.Set(k, v)
	}
	if key != "" {
		switch p.Auth.Type {
		case "bearer", "optional-bearer":
			h.Set("Authorization", "Bearer "+key)
		case "api-key":
			h.Set("x-api-key", key)
		}
	}
	return h
}
func (p ProviderConfig) RequiresKey() bool {
	return p.Auth.Type == "bearer" || p.Auth.Type == "api-key"
}

func (r *Registry) AutoDetect(cfg *Config) string {
	providers := r.Providers()
	sort.SliceStable(providers, func(i, j int) bool { return providers[i].AutoDetectPriority < providers[j].AutoDetectPriority })
	for _, p := range providers {
		if p.AutoDetectPriority > 0 && p.Auth.Type != "none" && cfg.ProviderKey(p) != "" {
			return p.Name
		}
	}
	return ""
}

// providerPaths resolves config-file paths relative to the configuration file.
func providerPaths(paths []string, configFile string) []string {
	out := append([]string(nil), paths...)
	for i, p := range out {
		if configFile != "" && !filepath.IsAbs(p) {
			out[i] = filepath.Join(filepath.Dir(configFile), p)
		}
	}
	return out
}
