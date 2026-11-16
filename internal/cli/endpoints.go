package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/block/codecrucible/internal/config"
	"github.com/spf13/cobra"
)

func newListEndpointsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list-models",
		Aliases: []string{"list-endpoints"},
		Short:   "List available models/endpoints for a provider",
		Long: fmt.Sprintf(`Queries a model provider for its available models and prints a table.

Provider is chosen by --provider if set. Otherwise, Databricks is used when
DATABRICKS_HOST + DATABRICKS_TOKEN are set; failing that, the first of
ANTHROPIC_API_KEY / OPENAI_API_KEY / GOOGLE_API_KEY / CEREBRAS_API_KEY present is used.

Supported providers: %s.`, strings.Join(config.ProviderNames(), ", ")),
		RunE: runListEndpoints,
	}
	cmd.Flags().String("provider", "", "provider to query (from the embedded YAML catalog)")
	cmd.Flags().String("base-url", "", "override provider base URL (useful for OpenAI-compat endpoints)")
	return cmd
}

// modelEntry is the unified row format rendered by listEndpointsTable.
type modelEntry struct {
	Name  string // identifier a user would pass to --model / DATABRICKS_ENDPOINT
	State string // READY / ACTIVE / "-" (not all providers expose a state)
	Model string // underlying model name; often equal to Name for direct providers
	Usage string // hint for how to target this entry on subsequent scans
}

// ===== Command dispatcher ============================================

func runListEndpoints(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(v)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	name, err := resolveListProvider(cmd, cfg)
	if err != nil {
		return err
	}
	p, ok := config.LookupProvider(name)
	if !ok {
		return fmt.Errorf("unsupported provider %q (see list-models --help)", name)
	}
	entries, err := listProvider(cmd.Context(), cfg, p, cmdStringFlag(cmd, "base-url"))
	if err != nil {
		return err
	}

	if len(entries) == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "No models returned for provider %q.\n", name)
		return nil
	}
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ENDPOINT\tSTATE\tMODEL\tUSAGE")
	for _, e := range entries {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", e.Name, emptyDash(e.State), emptyDash(e.Model), emptyDash(e.Usage))
	}
	return w.Flush()
}

// resolveListProvider picks a provider: explicit flag > databricks (if creds
// present, preserving existing behavior) > first provider with an API key.
func resolveListProvider(cmd *cobra.Command, cfg *config.Config) (string, error) {
	if p := strings.TrimSpace(cmdStringFlag(cmd, "provider")); p != "" {
		return strings.ToLower(p), nil
	}
	if p := strings.TrimSpace(cfg.Provider); p != "" {
		return strings.ToLower(p), nil
	}
	// If either Databricks env var is set, route to the Databricks lister so
	// its specific "DATABRICKS_HOST/TOKEN is not set" error surfaces rather
	// than the generic no-provider message.
	if cfg.DatabricksHost != "" || cfg.DatabricksToken != "" {
		return "databricks", nil
	}
	if cfg.AnthropicAPIKey != "" {
		return "anthropic", nil
	}
	if cfg.OpenAIAPIKey != "" {
		return "openai", nil
	}
	if cfg.GoogleAPIKey != "" {
		return "google", nil
	}
	if cfg.CerebrasAPIKey != "" {
		return "cerebras", nil
	}
	return "", fmt.Errorf("no provider specified and no credentials detected; pass --provider or set one of ANTHROPIC_API_KEY / OPENAI_API_KEY / GOOGLE_API_KEY / CEREBRAS_API_KEY / (DATABRICKS_HOST + DATABRICKS_TOKEN)")
}

func cmdStringFlag(cmd *cobra.Command, name string) string {
	if cmd == nil || cmd.Flags() == nil {
		return ""
	}
	s, _ := cmd.Flags().GetString(name)
	return s
}

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func listProvider(ctx context.Context, cfg *config.Config, p config.ProviderConfig, baseURL string) ([]modelEntry, error) {
	if p.Discovery.Format == "none" {
		return nil, fmt.Errorf("provider=%s does not support model discovery", p.Name)
	}
	base := firstNonEmpty(baseURL, cfg.BaseURL, p.BaseURL)
	if p.Protocol == "databricks" && base == "" {
		base = cfg.DatabricksHost
		if base == "" {
			return nil, fmt.Errorf("DATABRICKS_HOST is not set")
		}
	}
	key := cfg.ProviderKey(p.Name)
	if (p.Auth.Type == "bearer" || p.Auth.Type == "api-key") && key == "" {
		return nil, fmt.Errorf("%s is not set (provider=%s)", p.Auth.APIKeyEnv, p.Name)
	}
	if base == "" {
		return nil, fmt.Errorf("provider=%s requires --base-url (no default URL)", p.Name)
	}
	headers := http.Header{}
	for name, value := range p.Headers {
		headers.Set(name, value)
	}
	if key != "" {
		switch p.Auth.Type {
		case "bearer", "optional-bearer":
			headers.Set("Authorization", "Bearer "+key)
		case "api-key":
			headers.Set("x-api-key", key)
		}
	}
	body, err := httpGetJSON(ctx, strings.TrimRight(base, "/")+p.Discovery.Path, headers)
	if err != nil {
		return nil, fmt.Errorf("querying %s: %w", p.Name, err)
	}
	entries := []modelEntry{}
	add := func(name, state, model string) {
		entries = append(entries, modelEntry{Name: name, State: state, Model: model, Usage: "--provider " + p.Name + " --model " + name})
	}
	switch p.Discovery.Format {
	case "openai-models", "anthropic-models":
		var list struct {
			Data []struct {
				ID          string `json:"id"`
				DisplayName string `json:"display_name"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &list); err != nil {
			return nil, fmt.Errorf("parsing %s models: %w", p.Name, err)
		}
		for _, m := range list.Data {
			add(m.ID, "available", firstNonEmpty(m.DisplayName, m.ID))
		}
	case "ollama-tags":
		var list struct {
			Models []struct {
				Name  string `json:"name"`
				Model string `json:"model"`
			} `json:"models"`
		}
		if err := json.Unmarshal(body, &list); err != nil {
			return nil, fmt.Errorf("parsing Ollama tags: %w", err)
		}
		for _, m := range list.Models {
			name := firstNonEmpty(m.Name, m.Model)
			add(name, "local", name)
		}
	case "databricks":
		var list databricksEndpointList
		if err := json.Unmarshal(body, &list); err != nil {
			return nil, fmt.Errorf("parsing Databricks endpoints: %w", err)
		}
		for _, ep := range list.Endpoints {
			add(ep.Name, ep.State.Ready, describeModel(ep))
			entries[len(entries)-1].Usage = usageHint(ep.Name)
		}
	}
	return entries, nil
}

// databricksEndpointList is the response from the Databricks serving-endpoints API.
type databricksEndpointList struct {
	Endpoints []databricksEndpoint `json:"endpoints"`
}

type databricksEndpoint struct {
	Name    string                `json:"name"`
	State   databricksState       `json:"state"`
	Config  databricksEndpointCfg `json:"config"`
	Creator string                `json:"creator"`
}

type databricksState struct {
	Ready        string `json:"ready"`
	ConfigUpdate string `json:"config_update"`
}

type databricksEndpointCfg struct {
	ServedEntities []databricksServedEntity `json:"served_entities"`
	ServedModels   []databricksServedModel  `json:"served_models"`
}

type databricksServedEntity struct {
	Name            string                     `json:"name"`
	ExternalModel   *databricksExternalModel   `json:"external_model"`
	FoundationModel *databricksFoundationModel `json:"foundation_model"`
}

type databricksExternalModel struct {
	Name     string `json:"name"`
	Provider string `json:"provider"`
}

type databricksFoundationModel struct {
	Name string `json:"name"`
}

type databricksServedModel struct {
	Name      string `json:"name"`
	ModelName string `json:"model_name"`
}

// describeModel extracts a human-readable model name from the endpoint config.
func describeModel(ep databricksEndpoint) string {
	for _, e := range ep.Config.ServedEntities {
		if e.ExternalModel != nil {
			return e.ExternalModel.Provider + "/" + e.ExternalModel.Name
		}
		if e.FoundationModel != nil {
			return e.FoundationModel.Name
		}
		if e.Name != "" {
			return e.Name
		}
	}
	for _, m := range ep.Config.ServedModels {
		if m.ModelName != "" {
			return m.ModelName
		}
	}
	return "-"
}

// usageHint shows how to use this endpoint with codecrucible (Databricks flavor).
func usageHint(name string) string {
	if _, ok := config.LookupModel(name); ok {
		return "auto-detected"
	}
	return "DATABRICKS_ENDPOINT=" + name
}

// httpGetJSON performs an authenticated GET and returns the raw body,
// raising a formatted error on any non-2xx response.
func httpGetJSON(ctx context.Context, url string, headers http.Header) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	for k, vs := range headers {
		for _, val := range vs {
			req.Header.Add(k, val)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, truncateStr(string(body), 300))
	}
	return body, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// truncateStr shortens a string (avoids collision with scan.go's truncate via llm package).
func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
