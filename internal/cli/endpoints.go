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
		Long: `Queries a model provider for its available models and prints a table.

Provider is chosen by --provider if set. Otherwise, Databricks is used when
DATABRICKS_HOST + DATABRICKS_TOKEN are set; failing that, the first of
ANTHROPIC_API_KEY / OPENAI_API_KEY / GOOGLE_API_KEY present is used.

Supported providers: databricks, anthropic, openai, google, ollama.`,
		RunE: runListEndpoints,
	}
	cmd.Flags().String("provider", "", "provider to query (databricks, anthropic, openai, google, ollama)")
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

	provider, err := resolveListProvider(cmd, cfg)
	if err != nil {
		return err
	}

	var entries []modelEntry
	switch provider {
	case "databricks":
		entries, err = listDatabricks(cmd.Context(), cfg)
	case "anthropic":
		entries, err = listAnthropic(cmd.Context(), cfg, cmdStringFlag(cmd, "base-url"))
	case "openai":
		entries, err = listOpenAI(cmd.Context(), cfg, cmdStringFlag(cmd, "base-url"))
	case "google":
		entries, err = listGoogle(cmd.Context(), cfg, cmdStringFlag(cmd, "base-url"))
	case "ollama":
		entries, err = listOllama(cmd.Context(), cmdStringFlag(cmd, "base-url"))
	default:
		return fmt.Errorf("unsupported provider %q (supported: databricks, anthropic, openai, google, ollama)", provider)
	}
	if err != nil {
		return err
	}

	if len(entries) == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "No models returned for provider %q.\n", provider)
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
	return "", fmt.Errorf("no provider specified and no credentials detected; pass --provider or set one of ANTHROPIC_API_KEY / OPENAI_API_KEY / GOOGLE_API_KEY / (DATABRICKS_HOST + DATABRICKS_TOKEN)")
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

// ===== Databricks ===================================================

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

func listDatabricks(ctx context.Context, cfg *config.Config) ([]modelEntry, error) {
	if cfg.DatabricksHost == "" {
		return nil, fmt.Errorf("DATABRICKS_HOST is not set")
	}
	if cfg.DatabricksToken == "" {
		return nil, fmt.Errorf("DATABRICKS_TOKEN is not set")
	}

	host := strings.TrimRight(cfg.DatabricksHost, "/")
	url := host + "/api/2.0/serving-endpoints"

	body, err := httpGetJSON(ctx, url, http.Header{
		"Authorization": []string{"Bearer " + cfg.DatabricksToken},
	})
	if err != nil {
		return nil, fmt.Errorf("querying Databricks: %w", err)
	}

	var result databricksEndpointList
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	entries := make([]modelEntry, 0, len(result.Endpoints))
	for _, ep := range result.Endpoints {
		entries = append(entries, modelEntry{
			Name:  ep.Name,
			State: ep.State.Ready,
			Model: describeModel(ep),
			Usage: usageHint(ep.Name),
		})
	}
	return entries, nil
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

// ===== Anthropic ====================================================

// anthropicModelList is the response from GET /v1/models.
type anthropicModelList struct {
	Data []struct {
		ID          string `json:"id"`
		DisplayName string `json:"display_name"`
		Type        string `json:"type"`
	} `json:"data"`
}

func listAnthropic(ctx context.Context, cfg *config.Config, baseURL string) ([]modelEntry, error) {
	if cfg.AnthropicAPIKey == "" {
		return nil, fmt.Errorf("ANTHROPIC_API_KEY is not set")
	}
	base := firstNonEmpty(baseURL, cfg.BaseURL, "https://api.anthropic.com")
	url := strings.TrimRight(base, "/") + "/v1/models"

	body, err := httpGetJSON(ctx, url, http.Header{
		"x-api-key":         []string{cfg.AnthropicAPIKey},
		"anthropic-version": []string{"2023-06-01"},
	})
	if err != nil {
		return nil, fmt.Errorf("querying Anthropic: %w", err)
	}

	var list anthropicModelList
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	entries := make([]modelEntry, 0, len(list.Data))
	for _, m := range list.Data {
		entries = append(entries, modelEntry{
			Name:  m.ID,
			State: "available",
			Model: firstNonEmpty(m.DisplayName, m.ID),
			Usage: "--provider anthropic --model " + m.ID,
		})
	}
	return entries, nil
}

// ===== OpenAI =======================================================

// openaiModelList is the response from GET /v1/models.
type openaiModelList struct {
	Data []struct {
		ID      string `json:"id"`
		OwnedBy string `json:"owned_by"`
	} `json:"data"`
}

func listOpenAI(ctx context.Context, cfg *config.Config, baseURL string) ([]modelEntry, error) {
	if cfg.OpenAIAPIKey == "" {
		return nil, fmt.Errorf("OPENAI_API_KEY is not set")
	}
	base := firstNonEmpty(baseURL, cfg.BaseURL, "https://api.openai.com")
	url := strings.TrimRight(base, "/") + "/v1/models"

	body, err := httpGetJSON(ctx, url, http.Header{
		"Authorization": []string{"Bearer " + cfg.OpenAIAPIKey},
	})
	if err != nil {
		return nil, fmt.Errorf("querying OpenAI: %w", err)
	}

	var list openaiModelList
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	entries := make([]modelEntry, 0, len(list.Data))
	for _, m := range list.Data {
		entries = append(entries, modelEntry{
			Name:  m.ID,
			State: "available",
			Model: firstNonEmpty(m.OwnedBy, m.ID),
			Usage: "--provider openai --model " + m.ID,
		})
	}
	return entries, nil
}

// ===== Google (OpenAI-compat layer) =================================

func listGoogle(ctx context.Context, cfg *config.Config, baseURL string) ([]modelEntry, error) {
	if cfg.GoogleAPIKey == "" {
		return nil, fmt.Errorf("GOOGLE_API_KEY is not set")
	}
	// Google's OpenAI-compat layer mirrors OpenAI's /models endpoint, mounted
	// under /v1beta/openai/.
	base := firstNonEmpty(baseURL, cfg.BaseURL, "https://generativelanguage.googleapis.com/v1beta/openai")
	url := strings.TrimRight(base, "/") + "/models"

	body, err := httpGetJSON(ctx, url, http.Header{
		"Authorization": []string{"Bearer " + cfg.GoogleAPIKey},
	})
	if err != nil {
		return nil, fmt.Errorf("querying Google: %w", err)
	}

	var list openaiModelList
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	entries := make([]modelEntry, 0, len(list.Data))
	for _, m := range list.Data {
		entries = append(entries, modelEntry{
			Name:  m.ID,
			State: "available",
			Model: firstNonEmpty(m.OwnedBy, m.ID),
			Usage: "--provider google --model " + m.ID,
		})
	}
	return entries, nil
}

// ===== Ollama =======================================================

// ollamaTags is the response from GET /api/tags on an Ollama server.
type ollamaTags struct {
	Models []struct {
		Name  string `json:"name"`
		Model string `json:"model"`
	} `json:"models"`
}

func listOllama(ctx context.Context, baseURL string) ([]modelEntry, error) {
	base := firstNonEmpty(baseURL, "http://localhost:11434")
	url := strings.TrimRight(base, "/") + "/api/tags"

	body, err := httpGetJSON(ctx, url, nil)
	if err != nil {
		return nil, fmt.Errorf("querying Ollama: %w", err)
	}

	var tags ollamaTags
	if err := json.Unmarshal(body, &tags); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	entries := make([]modelEntry, 0, len(tags.Models))
	for _, m := range tags.Models {
		name := firstNonEmpty(m.Name, m.Model)
		entries = append(entries, modelEntry{
			Name:  name,
			State: "local",
			Model: name,
			Usage: "--provider ollama --model " + name,
		})
	}
	return entries, nil
}

// ===== Shared helpers ===============================================

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
