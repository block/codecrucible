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
	cmd := &cobra.Command{Use: "list-models", Aliases: []string{"list-endpoints"}, Short: "List provider-reported models or the configured catalog", RunE: runListEndpoints}
	cmd.Flags().String("provider", "", "provider to query (see list-providers)")
	cmd.Flags().String("base-url", "", "override provider base URL")
	cmd.Flags().Bool("registered", false, "list configured model capabilities without querying a provider")
	return cmd
}

type modelEntry struct{ Name, State, Model, Usage string }

func runListEndpoints(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(v)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	registered, _ := cmd.Flags().GetBool("registered")
	var entries []modelEntry
	if registered {
		return listRegisteredModels(cmd, cfg)
	}
	name, err := resolveListProvider(cmd, cfg)
	if err != nil {
		return err
	}
	p, ok := cfg.Registry.Provider(name)
	if !ok {
		return fmt.Errorf("unsupported provider %q (see list-providers)", name)
	}
	entries, err = listProvider(cmd.Context(), cfg, p, cmdStringFlag(cmd, "base-url"))
	if err != nil {
		return err
	}

	if len(entries) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No models returned.")
		return nil
	}
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ENDPOINT\tSTATE\tMODEL\tUSAGE")
	for _, e := range entries {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", e.Name, emptyDash(e.State), emptyDash(e.Model), e.Usage)
	}
	return w.Flush()
}

// Discovery and scanning share provider definitions and credential resolution.
func resolveListProvider(cmd *cobra.Command, cfg *config.Config) (string, error) {
	if p := firstNonEmpty(cmdStringFlag(cmd, "provider"), cfg.Provider); p != "" {
		return strings.ToLower(strings.TrimSpace(p)), nil
	}
	if cfg.DatabricksHost != "" || cfg.DatabricksToken != "" {
		return "databricks", nil
	}
	if p := cfg.ConfigRegistry().AutoDetect(cfg); p != "" {
		return p, nil
	}
	return "", fmt.Errorf("no provider specified and no credentials detected; pass --provider (see list-providers)")
}

func cmdStringFlag(cmd *cobra.Command, name string) string {
	value, _ := cmd.Flags().GetString(name)
	return value
}
func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func listProvider(ctx context.Context, cfg *config.Config, p config.ProviderConfig, baseURL string) ([]modelEntry, error) {
	if p.Discovery.Format == "none" {
		return nil, fmt.Errorf("provider=%s does not support discovery; use list-models --registered", p.Name)
	}
	base := firstNonEmpty(baseURL, cfg.BaseURL, p.BaseURL)
	if p.Protocol == "databricks" && base == "" {
		base = cfg.DatabricksHost
		if base == "" {
			return nil, fmt.Errorf("DATABRICKS_HOST is not set")
		}
	}
	key := cfg.ProviderKey(p)
	if p.RequiresKey() && key == "" {
		return nil, fmt.Errorf("%s is not set (provider=%s)", p.Auth.APIKeyEnv, p.Name)
	}
	if base == "" {
		return nil, fmt.Errorf("provider=%s requires --base-url (no default URL)", p.Name)
	}
	body, err := httpGetJSON(ctx, strings.TrimRight(base, "/")+p.Discovery.Path, p.AuthHeaders(key))
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
			if _, ok := cfg.ConfigRegistry().LookupModel(p.Name, ep.Name); ok {
				entries[len(entries)-1].Usage = "auto-detected"
			} else {
				entries[len(entries)-1].Usage = "DATABRICKS_ENDPOINT=" + ep.Name
			}
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
