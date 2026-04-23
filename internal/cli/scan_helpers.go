package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/textproto"
	"os"
	"strings"
	"time"

	"github.com/block/codecrucible/internal/chunk"
	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/llm"
	"github.com/block/codecrucible/internal/sarif"
	"github.com/block/codecrucible/internal/supctx"
)

// providerPreset describes how to build a client for a given provider.
// The preset controls defaults; any value set explicitly on PhaseConfig wins.
type providerPreset struct {
	baseURL      string // default base URL (empty = must be provided)
	keyEnv       string // env var name for the error message (empty = auth not required)
	authRequired bool   // whether an API key is mandatory
	// wireProvider is the provider string passed to the LLM HTTP client,
	// which controls URL path and request body format. Providers that use
	// OpenAI-compatible APIs set this to "openai".
	wireProvider string
}

// providerPresets maps --provider values to their defaults. Databricks is
// handled separately because it uses host+token env vars rather than a
// single API key.
var providerPresets = map[string]providerPreset{
	"anthropic": {
		baseURL:      "https://api.anthropic.com",
		keyEnv:       "ANTHROPIC_API_KEY",
		authRequired: true,
		wireProvider: "anthropic",
	},
	"openai": {
		baseURL:      "https://api.openai.com",
		keyEnv:       "OPENAI_API_KEY",
		authRequired: true,
		wireProvider: "openai",
	},
	"google": {
		baseURL:      "https://generativelanguage.googleapis.com/v1beta/openai",
		keyEnv:       "GOOGLE_API_KEY",
		authRequired: true,
		wireProvider: "google",
	},
	"ollama": {
		baseURL:      "http://localhost:11434",
		authRequired: false,
		wireProvider: "openai",
	},
	"openai-compat": {
		authRequired: false,
		wireProvider: "openai",
	},
}

// buildPhaseClient constructs an LLM client from a resolved PhaseConfig.
// Everything that varies per-phase (provider, key, timeout, headers,
// base URL, model params) comes from pc. Only Databricks host/token stay
// on cfg — Databricks is an all-provider proxy so per-phase Databricks
// credentials don't really make sense; if you want a different workspace
// per phase, set pc.BaseURL.
//
// Returns (client, endpoint, err). endpoint is empty for direct providers
// where the model name goes in the request body; for Databricks it is the
// serving-endpoint path segment.
func buildPhaseClient(pc config.PhaseConfig, cfg *config.Config) (llm.Client, string, error) {
	headers, err := parseCustomHeaders(pc.Headers)
	if err != nil {
		return nil, "", err
	}

	// 0 → 0s → llm.NewClient falls through to its own default (600s).
	timeout := time.Duration(pc.RequestTimeout) * time.Second

	// Anthropic has a no-key fallback: the locally-installed claude CLI
	// can proxy requests using the user's desktop session. Only Anthropic
	// offers this, so it stays a special case rather than table-driven.
	if pc.Provider == "anthropic" && pc.APIKey == "" {
		if len(pc.ModelParams) > 0 {
			slog.Warn("model params are ignored with Claude CLI auth; set an API key to send model params to the Anthropic API")
		}
		client, err := llm.NewClaudeCLIClient(llm.ClientConfig{
			Provider: "anthropic",
			Headers:  headers,
			Timeout:  timeout,
			Logger:   slog.Default(),
		})
		if err != nil {
			return nil, "", fmt.Errorf("no API key and Claude CLI auth unavailable (provider=anthropic): %w", err)
		}
		slog.Info("using Claude CLI authentication for Anthropic requests")
		return client, "", nil
	}

	// Known providers — use preset defaults, allow overrides.
	if preset, ok := providerPresets[pc.Provider]; ok {
		if preset.authRequired && pc.APIKey == "" {
			return nil, "", fmt.Errorf("no API key for provider=%s (set %s, or phases.<phase>.api-key)", pc.Provider, preset.keyEnv)
		}
		baseURL := pc.BaseURL
		if baseURL == "" {
			if preset.baseURL == "" {
				return nil, "", fmt.Errorf("provider=%s requires --base-url (no default URL)", pc.Provider)
			}
			baseURL = preset.baseURL
		}
		client := llm.NewClient(llm.ClientConfig{
			BaseURL:    baseURL,
			Token:      pc.APIKey, // empty string is fine for no-auth providers
			Provider:   preset.wireProvider,
			Headers:    headers,
			MaxRetries: 3,
			Timeout:    timeout,
			Logger:     slog.Default(),
		})
		return client, "", nil
	}

	// Databricks (and any unrecognised provider string, as before).
	if cfg.DatabricksHost == "" {
		return nil, "", fmt.Errorf("DATABRICKS_HOST is not set (provider=%s)", pc.Provider)
	}
	if cfg.DatabricksToken == "" {
		return nil, "", fmt.Errorf("DATABRICKS_TOKEN is not set (provider=%s)", pc.Provider)
	}
	baseURL := pc.BaseURL
	if baseURL == "" {
		baseURL = cfg.DatabricksHost + "/serving-endpoints"
	}
	client := llm.NewClient(llm.ClientConfig{
		BaseURL:    baseURL,
		Token:      cfg.DatabricksToken,
		Provider:   "databricks",
		Headers:    headers,
		MaxRetries: 3,
		Timeout:    timeout,
		Logger:     slog.Default(),
	})
	endpoint := pc.Endpoint
	if endpoint == "" {
		endpoint = pc.ModelCfg.Endpoint
	}
	// The LLM client's buildURL appends "/invocations", so strip it if
	// present to avoid double-appending (the registry stores
	// "model/invocations").
	return client, strings.TrimSuffix(endpoint, "/invocations"), nil
}

// parseCustomHeaders parses header entries in "Name: Value" format.
func parseCustomHeaders(raw []string) (http.Header, error) {
	headers := make(http.Header)
	for _, entry := range raw {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}

		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid custom header %q: expected format 'Name: Value'", entry)
		}

		name := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		if name == "" {
			return nil, fmt.Errorf("invalid custom header %q: header name is empty", entry)
		}
		if value == "" {
			return nil, fmt.Errorf("invalid custom header %q: header value is empty", entry)
		}

		headers.Add(name, value)
	}

	return headers, nil
}

// resolveModel looks up the model in the registry or returns defaults.
func resolveModel(name string) config.ModelConfig {
	if name == "" {
		return config.DefaultModel()
	}
	if m, ok := config.LookupModel(name); ok {
		return m
	}
	slog.Warn("model not in registry, using defaults", "model", name)
	return config.UnknownModelDefaults(name)
}

// resolvePromptLoader creates a PromptLoader from --prompts-dir or the default location.
func resolvePromptLoader(promptsDir string) (*llm.PromptLoader, error) {
	if promptsDir != "" {
		return llm.NewPromptLoader(os.DirFS(promptsDir)), nil
	}
	// Default: look for prompts/default/ directory relative to CWD.
	if info, err := os.Stat("prompts/default"); err == nil && info.IsDir() {
		return llm.NewPromptLoader(os.DirFS("prompts/default")), nil
	}
	return nil, fmt.Errorf("prompts directory not found; use --prompts-dir to specify a prompt set (e.g. prompts/default)")
}

// capManifest truncates a list of file paths to fit within a character budget.
// When truncated, appends a note indicating how many paths were omitted.
func capManifest(paths []string, charBudget int) []string {
	if charBudget <= 0 {
		return nil
	}
	total := 0
	for i, p := range paths {
		total += len(p) + 1 // +1 for newline
		if total > charBudget {
			omitted := len(paths) - i
			return append(paths[:i], fmt.Sprintf("... and %d more files", omitted))
		}
	}
	return paths
}

// outputEmptySARIF produces a valid SARIF document with zero findings.
func outputEmptySARIF(cfg *config.Config) error {
	doc := sarif.Build(sarif.AnalysisResult{}, nil, sarif.BuilderConfig{
		ToolVersion: version,
	})
	doc.Runs[0].Invocations = []sarif.SARIFInvocation{{
		ExecutionSuccessful: true,
		ToolExecutionNotifications: []sarif.SARIFNotification{{
			Level:   "note",
			Message: sarif.SARIFMessage{Text: "no source files found after filtering"},
		}},
	}}

	output, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling SARIF: %w", err)
	}

	if cfg.Output != "" {
		return os.WriteFile(cfg.Output, output, 0644)
	}
	fmt.Println(string(output))
	return nil
}

// maxContextBudgetPct is the hard ceiling on how much of the context window
// supplementary sources may claim. Above this the actual scan target starves.
const maxContextBudgetPct = 40

// loadSupplementaryContext fetches, optionally compresses, and packs the
// configured context sources into per-phase rendered blocks. Returned
// PackResults carry the token count so the caller can fold it into
// promptOverhead — that's what keeps chunk-budget math honest.
func loadSupplementaryContext(
	ctx context.Context,
	cfg *config.Config,
	counter *chunk.TokenCounter,
	promptLoader *llm.PromptLoader,
	contextLimit int,
) (analysisCtx, auditCtx supctx.PackResult, err error) {
	if len(cfg.ContextSources) == 0 {
		return
	}

	pct := cfg.ContextBudgetPct
	if pct <= 0 {
		pct = 15
	}
	if pct > maxContextBudgetPct {
		return analysisCtx, auditCtx,
			fmt.Errorf("--context-budget-pct %d exceeds maximum %d; supplementary context would starve the scan target", pct, maxContextBudgetPct)
	}
	budget := contextLimit * pct / 100

	slog.Info("loading supplementary context",
		"sources", len(cfg.ContextSources), "budget_tokens", budget, "budget_pct", pct)

	srcs := make([]supctx.Source, len(cfg.ContextSources))
	for i, cs := range cfg.ContextSources {
		srcs[i] = supctx.Source{
			Name:     cs.Name,
			Type:     cs.Type,
			Location: cs.Location,
			Priority: cs.Priority,
			Compress: cs.Compress,
			Phases:   cs.Phases,
			Include:  cs.Include,
			Exclude:  cs.Exclude,
		}
	}

	loaded := supctx.LoadAll(ctx, srcs, counter)
	if len(loaded) == 0 {
		slog.Warn("no supplementary context loaded (all sources empty or failed)")
		return
	}

	// Run the optional compression pre-pass when any source opted in.
	if anyCompress(loaded) {
		cc := &cfg.Phases.ContextCompress
		ccClient, _, ccErr := buildPhaseClient(*cc, cfg)
		if ccErr != nil {
			slog.Warn("context-compress client build failed; skipping compression", "error", ccErr)
		} else {
			cp, cpErr := promptLoader.LoadContextCompressPrompt()
			if cpErr != nil {
				slog.Warn("failed to load context compress prompt; skipping compression", "error", cpErr)
			} else {
				compressor := supctx.Compressor{
					Client:  ccClient,
					Prompt:  *cp,
					Counter: counter,
					Model:   cc.ModelCfg.Name,
				}
				loaded = compressor.Compress(ctx, loaded, budget)
			}
		}
	}

	analysisCtx = supctx.Pack(supctx.FilterPhase(loaded, "analysis"), budget, counter)
	auditCtx = supctx.Pack(supctx.FilterPhase(loaded, "audit"), budget, counter)

	logPack("analysis", analysisCtx)
	logPack("audit", auditCtx)

	return analysisCtx, auditCtx, nil
}

// streamingTokenCount estimates the total token count of the flattened XML by
// iterating FileMap entries one at a time. Each per-file XML string is built,
// counted, and discarded, so peak memory is max(single file XML) rather than
// sum(all file XML). The result closely matches counter.Count(fullXML) because
// the heuristic token counter is linear and additive.
func streamingTokenCount(fm ingest.FileMap, counter *chunk.TokenCounter, cfg ingest.FlattenConfig) int {
	paths := make([]string, 0, len(fm))
	for p := range fm {
		paths = append(paths, p)
	}

	// Envelope: header + directory structure + <files></files> wrapper.
	envelope := ingest.EnvelopeXML(paths, cfg)
	total := counter.Count(envelope)

	// Per-file: build XML one at a time, count, discard.
	for _, p := range paths {
		fileXML := chunk.BuildFileXML(p, fm[p])
		total += counter.Count(fileXML)
	}

	return total
}

func anyCompress(loaded []supctx.Loaded) bool {
	for _, l := range loaded {
		if l.Compress {
			return true
		}
	}
	return false
}

func logPack(phase string, r supctx.PackResult) {
	if r.Tokens == 0 {
		return
	}
	slog.Info("supplementary context packed", "phase", phase, "tokens", r.Tokens,
		"dropped", r.Dropped, "truncated", r.Truncated)
	for _, d := range r.Dropped {
		slog.Warn("context source dropped (over budget)", "phase", phase, "source", d)
	}
	if r.Truncated != "" {
		slog.Warn("context source truncated", "phase", phase, "source", r.Truncated)
	}
}
