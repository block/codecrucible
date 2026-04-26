package llm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Message represents a single chat message.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatRequest holds the parameters for a chat completion call.
type ChatRequest struct {
	// Label is a caller-supplied tag for log correlation (e.g. "chunk 3/9",
	// "feature-detection"). Carried into every log line inside the retry
	// loop so concurrent requests can be distinguished.
	Label          string           `json:"-"`
	Endpoint       string           `json:"-"`           // Model serving endpoint name.
	Model          string           `json:"-"`           // Model name (used by Anthropic/OpenAI direct APIs).
	Messages       []Message        `json:"messages"`    // System + user messages.
	Temperature    float64          `json:"temperature"` // Sampling temperature.
	MaxTokens      int              `json:"max_tokens"`  // Max output tokens.
	ResponseSchema *json.RawMessage `json:"-"`           // JSON Schema for response_format enforcement.
	OutputMode     OutputMode       `json:"-"`           // How to enforce structured output.
	ModelParams    map[string]any   `json:"-"`           // Provider-specific request body params (merged at top level).
}

// ChatResponse holds the result of a chat completion call.
type ChatResponse struct {
	Content      string     `json:"content"`       // Raw response content.
	Usage        TokenUsage `json:"usage"`         // Input/output token counts.
	FinishReason string     `json:"finish_reason"` // "stop", "length", "content_filter", etc.
	Model        string     `json:"model"`         // Model that generated the response.

	// Streaming-only timing. Zero for non-streaming responses.
	// TimeToFirstToken is headers-received → first content_block_delta:
	// that's server-side prompt processing + thinking (the model does all
	// its thinking before the first visible output token).
	// GenerationTime is first delta → message_stop: the pure output phase.
	// CompletionTokens / GenerationTime is the real emit rate, free of
	// prompt-processing and thinking overhead.
	TimeToFirstToken time.Duration `json:"-"`
	GenerationTime   time.Duration `json:"-"`
}

// TokenUsage tracks input and output token consumption.
type TokenUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	// Anthropic prompt-caching fields. Creation is billed at ~1.25× input
	// rate; reads at ~0.1×. Zero for providers that don't report them.
	CacheCreationTokens int `json:"cache_creation_tokens,omitempty"`
	CacheReadTokens     int `json:"cache_read_tokens,omitempty"`
	// Characters (not tokens — Anthropic doesn't break the count down) in
	// thinking blocks. Shows how much of CompletionTokens was reasoning vs
	// the output you actually see. Streaming only.
	ThinkingChars int `json:"thinking_chars,omitempty"`
}

// OutputMode specifies how to enforce structured output.
type OutputMode int

const (
	// OutputModeNone sends no structured output enforcement.
	OutputModeNone OutputMode = iota
	// OutputModeJSONSchema uses response_format with JSON Schema (OpenAI/GPT endpoints).
	OutputModeJSONSchema
	// OutputModeToolUse uses tool_use for structured output (Claude endpoints).
	OutputModeToolUse
)

// ErrContextLengthExceeded is returned when the model reports context length exceeded.
// Callers should re-chunk and retry rather than retrying the same request.
var ErrContextLengthExceeded = fmt.Errorf("llm: context length exceeded")

// errNonRetryable wraps an error to indicate it should not be retried.
type errNonRetryable struct {
	err error
}

func (e *errNonRetryable) Error() string { return e.err.Error() }
func (e *errNonRetryable) Unwrap() error { return e.err }

// errToolChoiceIncompatible indicates the endpoint rejected forced tool_choice
// for the selected model. Callers may retry without forcing tool choice.
type errToolChoiceIncompatible struct {
	err error
}

func (e *errToolChoiceIncompatible) Error() string { return e.err.Error() }
func (e *errToolChoiceIncompatible) Unwrap() error { return e.err }

// errTemperatureIncompatible indicates the endpoint rejected the requested
// temperature value (e.g. adaptive-thinking models that require temperature=1).
// Callers may retry with temperature omitted so the API picks its own default.
type errTemperatureIncompatible struct {
	err error
}

func (e *errTemperatureIncompatible) Error() string { return e.err.Error() }
func (e *errTemperatureIncompatible) Unwrap() error { return e.err }

// errMaxTokensParamIncompatible indicates the endpoint rejected `max_tokens`
// and requires `max_completion_tokens` instead (OpenAI GPT-5 family and
// reasoning-series models). Callers may retry using the new field name.
type errMaxTokensParamIncompatible struct {
	err error
}

func (e *errMaxTokensParamIncompatible) Error() string { return e.err.Error() }
func (e *errMaxTokensParamIncompatible) Unwrap() error { return e.err }

// securityAnalysisToolDescription is sent alongside the JSON schema. Models
// that can't be forced to use a tool (tool_choice:auto only) read this at the
// exact moment they're populating fields — it's the cheapest place to prevent
// per-field drift like "none found" where [] belongs.
const securityAnalysisToolDescription = "Submit the security analysis results. " +
	"You MUST call this tool — do not respond with plain text. " +
	"security_issues and public_api_routes MUST be arrays: use [] when empty, never a string. " +
	"Every issue requires file_path, numeric start_line/end_line, and a severity between 0 and 10."

// Client abstracts LLM interaction for testability.
type Client interface {
	// ChatCompletion sends a structured chat request and returns typed output.
	ChatCompletion(ctx context.Context, req ChatRequest) (*ChatResponse, error)
}

// ClientConfig holds configuration for the HTTP LLM client.
type ClientConfig struct {
	BaseURL    string        // Base URL for the API (e.g., "https://host.databricks.com/serving-endpoints").
	Token      string        // Bearer token for authentication.
	Provider   string        // "databricks", "anthropic", "openai" — controls URL construction and request format.
	Headers    http.Header   // Additional headers to include in every request.
	MaxRetries int           // Maximum number of retries for transient errors (default: 3).
	Timeout    time.Duration // Per-request timeout (default: 600s).
	Logger     *slog.Logger  // Structured logger.
}

// httpClient implements Client using HTTP against an OpenAI-compatible API.
type httpClient struct {
	baseURL      string
	token        string
	provider     string
	maxRetries   int
	timeout      time.Duration
	logger       *slog.Logger
	extraHeaders http.Header
	client       *http.Client
	backoffFunc  func(ctx context.Context, attempt int, retryAfter time.Duration) // override for testing

	// Learned constraints: set once when the API rejects a request feature,
	// then applied to all subsequent requests to avoid wasted round-trips.
	noForcedToolChoice     atomic.Bool
	dropTemperature        atomic.Bool
	useMaxCompletionTokens atomic.Bool
}

// NewClient creates a new LLM HTTP client.
func NewClient(cfg ClientConfig) Client {
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 3
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 600 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return &httpClient{
		baseURL:      strings.TrimRight(cfg.BaseURL, "/"),
		token:        cfg.Token,
		provider:     cfg.Provider,
		maxRetries:   cfg.MaxRetries,
		timeout:      cfg.Timeout,
		logger:       cfg.Logger,
		extraHeaders: cfg.Headers.Clone(),
		client:       &http.Client{Timeout: cfg.Timeout, Transport: transport},
	}
}

// ChatCompletion sends a chat completion request with retry logic for transient errors.
func (c *httpClient) ChatCompletion(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	url := c.buildURL(req.Endpoint)

	var lastErr error
	disableForcedToolChoice := c.noForcedToolChoice.Load()
	dropTemperature := c.dropTemperature.Load()
	useMaxCompletionTokens := c.useMaxCompletionTokens.Load()

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			c.logger.Info("retrying LLM request",
				"label", req.Label,
				"attempt", attempt,
				"max_retries", c.maxRetries,
			)
		}

		body, err := c.buildRequestBody(req, !disableForcedToolChoice, dropTemperature, useMaxCompletionTokens)
		if err != nil {
			return nil, fmt.Errorf("llm: building request body: %w", err)
		}

		resp, err := c.doRequest(ctx, url, req.Label, body)
		if err != nil {
			// Context cancellation is not retryable.
			if ctx.Err() != nil {
				return nil, fmt.Errorf("llm: context cancelled: %w", ctx.Err())
			}
			lastErr = err
			c.logger.Warn("LLM request failed",
				"label", req.Label,
				"attempt", attempt,
				"error", err,
			)
			if attempt < c.maxRetries {
				c.backoff(ctx, attempt, 0)
			}
			continue
		}

		chatResp, retryAfter, err := c.handleResponse(resp)
		if err != nil {
			// Some endpoints reject forced tool_choice for specific models.
			// Retry once without forcing tool use while still providing tools.
			var toolChoiceErr *errToolChoiceIncompatible
			if errors.As(err, &toolChoiceErr) && req.OutputMode == OutputModeToolUse && !disableForcedToolChoice {
				disableForcedToolChoice = true
				c.noForcedToolChoice.Store(true)
				lastErr = err
				c.logger.Warn("endpoint rejected forced tool_choice; retrying without force",
					"label", req.Label,
					"provider", c.provider,
					"model", req.Model,
				)
				continue
			}

			// Same adaptive pattern for temperature constraints: drop the field
			// and let the API use its model-specific default.
			var tempErr *errTemperatureIncompatible
			if errors.As(err, &tempErr) && !dropTemperature {
				dropTemperature = true
				c.dropTemperature.Store(true)
				lastErr = err
				c.logger.Warn("endpoint rejected temperature; retrying without it",
					"label", req.Label,
					"provider", c.provider,
					"model", req.Model,
				)
				continue
			}

			// OpenAI GPT-5 family and reasoning models require
			// `max_completion_tokens` in place of `max_tokens`.
			var maxTokErr *errMaxTokensParamIncompatible
			if errors.As(err, &maxTokErr) && !useMaxCompletionTokens {
				useMaxCompletionTokens = true
				c.useMaxCompletionTokens.Store(true)
				lastErr = err
				c.logger.Warn("endpoint rejected max_tokens; retrying with max_completion_tokens",
					"label", req.Label,
					"provider", c.provider,
					"model", req.Model,
				)
				continue
			}

			// Context length exceeded is not retryable — signal re-chunking.
			if errors.Is(err, ErrContextLengthExceeded) {
				return nil, err
			}

			// Non-retryable errors (4xx client errors) should fail immediately.
			var nonRetryable *errNonRetryable
			if errors.As(err, &nonRetryable) {
				return nil, nonRetryable.err
			}

			lastErr = err
			statusCode := 0
			if resp != nil {
				statusCode = resp.StatusCode
			}
			c.logger.Warn("LLM response error",
				"label", req.Label,
				"attempt", attempt,
				"status", statusCode,
				"error", err,
			)

			if attempt < c.maxRetries {
				c.backoff(ctx, attempt, retryAfter)
			}
			continue
		}

		return chatResp, nil
	}

	return nil, fmt.Errorf("llm: exhausted %d retries: %w", c.maxRetries, lastErr)
}

func (c *httpClient) buildURL(endpoint string) string {
	switch c.provider {
	case "anthropic":
		return c.baseURL + "/v1/messages"
	case "openai":
		return c.baseURL + "/v1/chat/completions"
	case "google":
		// Google's OpenAI-compat layer: request body, response body, and
		// Bearer auth all ride the existing non-Anthropic paths. The only
		// divergence is the URL — /chat/completions directly under the
		// compat base, no /v1/ segment.
		return c.baseURL + "/chat/completions"
	default: // "databricks" or empty
		if endpoint == "" {
			return c.baseURL + "/chat/completions"
		}
		return c.baseURL + "/" + endpoint + "/invocations"
	}
}

// apiRequest is the OpenAI-compatible request body.
type apiRequest struct {
	Model               string           `json:"model,omitempty"`
	Messages            []Message        `json:"messages"`
	Temperature         *float64         `json:"temperature,omitempty"`
	MaxTokens           int              `json:"max_tokens,omitempty"`
	MaxCompletionTokens int              `json:"max_completion_tokens,omitempty"`
	ResponseFormat      *responseFormat  `json:"response_format,omitempty"`
	Tools               []toolDefinition `json:"tools,omitempty"`
	ToolChoice          any              `json:"tool_choice,omitempty"`
}

type responseFormat struct {
	Type       string           `json:"type"`
	JSONSchema *json.RawMessage `json:"json_schema,omitempty"`
}

// toolDefinition supports both OpenAI function-calling format and
// Anthropic/Databricks tool_use format. Only one of Function or
// the Anthropic fields (Name, Description, InputSchema) should be set.
type toolDefinition struct {
	// OpenAI format
	Type     string        `json:"type"`
	Function *toolFunction `json:"function,omitempty"`
	// Anthropic/Databricks format
	Name        string           `json:"name,omitempty"`
	Description string           `json:"description,omitempty"`
	InputSchema *json.RawMessage `json:"input_schema,omitempty"`
}

type toolFunction struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Parameters  *json.RawMessage `json:"parameters"`
}

func (c *httpClient) buildRequestBody(req ChatRequest, forceToolChoice, dropTemperature, useMaxCompletionTokens bool) ([]byte, error) {
	if c.provider == "anthropic" {
		return c.buildAnthropicRequestBody(req, forceToolChoice, dropTemperature)
	}

	apiReq := apiRequest{
		Model:    req.Model,
		Messages: req.Messages,
	}
	if !dropTemperature {
		t := req.Temperature
		apiReq.Temperature = &t
	}
	if useMaxCompletionTokens {
		apiReq.MaxCompletionTokens = req.MaxTokens
	} else {
		apiReq.MaxTokens = req.MaxTokens
	}

	switch req.OutputMode {
	case OutputModeJSONSchema:
		if req.ResponseSchema != nil {
			apiReq.ResponseFormat = &responseFormat{
				Type:       "json_schema",
				JSONSchema: req.ResponseSchema,
			}
		}
	case OutputModeToolUse:
		if req.ResponseSchema != nil {
			// Extract the inner "schema" object from the response_format envelope
			// (which has {"name": ..., "strict": ..., "schema": {...}}) to get
			// the raw JSON Schema with a top-level "type" field.
			inputSchema := extractInnerSchema(req.ResponseSchema)
			apiReq.Tools = []toolDefinition{
				{
					// OpenAI function-calling format (required by Databricks proxy).
					Type: "function",
					Function: &toolFunction{
						Name:        "security_analysis",
						Description: securityAnalysisToolDescription,
						Parameters:  inputSchema,
					},
				},
			}
			// Force the model to use the tool when supported.
			if forceToolChoice {
				apiReq.ToolChoice = map[string]any{"type": "function", "function": map[string]string{"name": "security_analysis"}}
			}
		}
	}

	return marshalWithModelParams(apiReq, requestParamsWithout(req.ModelParams, dropTemperature, "temperature"))
}

// extractInnerSchema extracts the inner "schema" object from the response_format
// envelope used by OpenAI's JSON Schema mode. The envelope has the shape:
//
//	{"name": "...", "strict": true, "schema": { "type": "object", ... }}
//
// For Anthropic tool_use, we need just the inner schema (the part with "type": "object").
// If extraction fails, returns the original raw message as-is.
func extractInnerSchema(raw *json.RawMessage) *json.RawMessage {
	if raw == nil {
		return nil
	}
	var envelope struct {
		Schema json.RawMessage `json:"schema"`
	}
	if err := json.Unmarshal(*raw, &envelope); err != nil || len(envelope.Schema) == 0 {
		return raw
	}
	return &envelope.Schema
}

func (c *httpClient) doRequest(ctx context.Context, url, label string, body []byte) (*http.Response, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	switch c.provider {
	case "anthropic":
		httpReq.Header.Set("x-api-key", c.token)
		httpReq.Header.Set("anthropic-version", "2023-06-01")
	default:
		if c.token != "" {
			httpReq.Header.Set("Authorization", "Bearer "+c.token)
		}
	}

	for name, values := range c.extraHeaders {
		if len(values) == 0 {
			continue
		}
		httpReq.Header.Set(name, values[0])
		for _, value := range values[1:] {
			httpReq.Header.Add(name, value)
		}
	}

	start := time.Now()
	resp, err := c.client.Do(httpReq)
	elapsed := time.Since(start)
	if err != nil {
		c.logger.Debug("HTTP request failed", "label", label, "url", url, "elapsed", elapsed, "error", err)
		return nil, err
	}
	// "headers received", not "completed" — for streaming responses the body
	// is still draining after this returns. elapsed here is time-to-first-byte;
	// the caller's ttft/gen_time/elapsed give the full picture.
	c.logger.Info("HTTP response headers received", "label", label, "status", resp.StatusCode, "ttfb", elapsed)
	return resp, nil
}

// apiResponse is the OpenAI-compatible response body.
type apiResponse struct {
	Choices []apiChoice `json:"choices"`
	Usage   struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
	Model string    `json:"model"`
	Error *apiError `json:"error,omitempty"`
}

type apiChoice struct {
	Message      apiMessage `json:"message"`
	FinishReason string     `json:"finish_reason"`
}

type apiMessage struct {
	Content   flexString    `json:"content"`
	ToolCalls []apiToolCall `json:"tool_calls,omitempty"`
}

// flexString unmarshals both a plain JSON string and an array of content
// parts (as returned by Gemini via the Databricks proxy).  The array
// format looks like: [{"type":"text","text":"..."}].  In that case, all
// "text" fields are concatenated.
type flexString string

func (f *flexString) UnmarshalJSON(data []byte) error {
	// Fast path: plain string (OpenAI / Claude).
	if len(data) > 0 && data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*f = flexString(s)
		return nil
	}

	// Slow path: array of content parts (Gemini).
	if len(data) > 0 && data[0] == '[' {
		var parts []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if err := json.Unmarshal(data, &parts); err != nil {
			return err
		}
		var b strings.Builder
		for _, p := range parts {
			if p.Text != "" {
				b.WriteString(p.Text)
			}
		}
		*f = flexString(b.String())
		return nil
	}

	// null → empty string
	if string(data) == "null" {
		*f = ""
		return nil
	}

	return fmt.Errorf("flexString: unexpected JSON token %q", data[0])
}

type apiToolCall struct {
	Function struct {
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type apiError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code"`
}

// handleResponse processes the HTTP response, returning the chat response, retry-after duration,
// and any error. A non-nil error with retryAfter > 0 indicates a retryable error.
func (c *httpClient) handleResponse(resp *http.Response) (*ChatResponse, time.Duration, error) {
	defer resp.Body.Close()

	// Streaming responses (Anthropic only for now). Dispatch on Content-Type so
	// a model_params override of stream:false falls through to the blocking
	// path below without any further plumbing. Only successful responses
	// stream; 4xx/5xx still return a JSON error body.
	if resp.StatusCode == http.StatusOK &&
		strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		return c.readAnthropicStream(resp.Body)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("reading response body: %w", err)
	}

	// Parse Retry-After header for rate-limited responses.
	retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))

	// Retryable: 429 (rate limit) and 5xx (server errors).
	if resp.StatusCode == http.StatusTooManyRequests || (resp.StatusCode >= 500 && resp.StatusCode < 600) {
		return nil, retryAfter, fmt.Errorf("llm: retryable error (status %d): %s", resp.StatusCode, truncate(string(respBody), 200))
	}

	// Non-retryable client errors (400, 401, 403, 404, etc.).
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if isToolChoiceIncompatibleError(string(respBody)) {
			return nil, 0, &errToolChoiceIncompatible{err: fmt.Errorf("llm: request failed (status %d): %s", resp.StatusCode, truncate(string(respBody), 200))}
		}
		if isTemperatureIncompatibleError(string(respBody)) {
			return nil, 0, &errTemperatureIncompatible{err: fmt.Errorf("llm: request failed (status %d): %s", resp.StatusCode, truncate(string(respBody), 200))}
		}
		if isMaxTokensParamIncompatibleError(string(respBody)) {
			return nil, 0, &errMaxTokensParamIncompatible{err: fmt.Errorf("llm: request failed (status %d): %s", resp.StatusCode, truncate(string(respBody), 200))}
		}

		// Check for context_length_exceeded in OpenAI error response.
		var apiResp apiResponse
		if json.Unmarshal(respBody, &apiResp) == nil && apiResp.Error != nil {
			if strings.Contains(apiResp.Error.Code, "context_length_exceeded") ||
				strings.Contains(apiResp.Error.Message, "context_length_exceeded") ||
				strings.Contains(apiResp.Error.Message, "maximum context length") {
				return nil, 0, ErrContextLengthExceeded
			}
		}
		// Check for Anthropic error format.
		var anthErr struct {
			Error *anthropicError `json:"error"`
		}
		if json.Unmarshal(respBody, &anthErr) == nil && anthErr.Error != nil {
			if strings.Contains(anthErr.Error.Message, "too long") || strings.Contains(anthErr.Error.Message, "too many tokens") {
				return nil, 0, ErrContextLengthExceeded
			}
		}
		return nil, 0, &errNonRetryable{err: fmt.Errorf("llm: request failed (status %d): %s", resp.StatusCode, truncate(string(respBody), 200))}
	}

	// Anthropic response parsing.
	if c.provider == "anthropic" {
		return c.parseAnthropicResponse(respBody)
	}

	// Parse successful OpenAI-compatible response.
	// Parse errors on a 200 are non-retryable — the server won't return a
	// different format on retry.
	var apiResp apiResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, 0, &errNonRetryable{err: fmt.Errorf("llm: parsing response: %w", err)}
	}

	if len(apiResp.Choices) == 0 {
		return nil, 0, &errNonRetryable{err: fmt.Errorf("llm: empty choices in response")}
	}

	choice := apiResp.Choices[0]
	content := string(choice.Message.Content)

	// If tool_use mode, extract content from tool call arguments.
	if content == "" && len(choice.Message.ToolCalls) > 0 {
		content = choice.Message.ToolCalls[0].Function.Arguments
	}

	return &ChatResponse{
		Content:      content,
		Usage:        TokenUsage{PromptTokens: apiResp.Usage.PromptTokens, CompletionTokens: apiResp.Usage.CompletionTokens},
		FinishReason: choice.FinishReason,
		Model:        apiResp.Model,
	}, 0, nil
}

// anthropicRequest is the Anthropic Messages API request body.
type anthropicRequest struct {
	Model       string          `json:"model"`
	Messages    []Message       `json:"messages"`
	System      string          `json:"system,omitempty"`
	MaxTokens   int             `json:"max_tokens"`
	Temperature *float64        `json:"temperature,omitempty"`
	Tools       []anthropicTool `json:"tools,omitempty"`
	ToolChoice  any             `json:"tool_choice,omitempty"`
	Stream      bool            `json:"stream,omitempty"`
}

type anthropicTool struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	InputSchema *json.RawMessage `json:"input_schema"`
}

// anthropicResponse is the Anthropic Messages API response body.
type anthropicResponse struct {
	ID         string           `json:"id"`
	Content    []anthropicBlock `json:"content"`
	Model      string           `json:"model"`
	StopReason string           `json:"stop_reason"`
	Usage      anthropicUsage   `json:"usage"`
	Error      *anthropicError  `json:"error,omitempty"`
}

type anthropicBlock struct {
	Type  string          `json:"type"`
	Text  string          `json:"text,omitempty"`
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
}

type anthropicUsage struct {
	InputTokens              int `json:"input_tokens"`
	OutputTokens             int `json:"output_tokens"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens"`
}

type anthropicError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

func (c *httpClient) buildAnthropicRequestBody(req ChatRequest, forceToolChoice, dropTemperature bool) ([]byte, error) {
	// Extract system message - Anthropic requires it as a separate field.
	var system string
	var messages []Message
	for _, m := range req.Messages {
		if m.Role == "system" {
			system = m.Content
		} else {
			messages = append(messages, m)
		}
	}

	apiReq := anthropicRequest{
		Model:     req.Model,
		Messages:  messages,
		System:    system,
		MaxTokens: req.MaxTokens,
		// Stream even though we don't need incremental output: SSE keepalive
		// frames hold the TCP connection open through long generations. Without
		// this, slow models trip the server-side idle timeout (~10–15min) and
		// the edge sends RST before the full response is ready.
		Stream: true,
	}
	if !dropTemperature {
		t := req.Temperature
		apiReq.Temperature = &t
	}

	if req.OutputMode == OutputModeToolUse && req.ResponseSchema != nil {
		inputSchema := extractInnerSchema(req.ResponseSchema)
		apiReq.Tools = []anthropicTool{
			{
				Name:        "security_analysis",
				Description: securityAnalysisToolDescription,
				InputSchema: inputSchema,
			},
		}
		if forceToolChoice {
			// {"type":"any"} forces tool use without naming a specific tool.
			// With only one tool defined, it's functionally equivalent to
			// {"type":"tool","name":"..."}.
			//
			// Thinking-enabled models reject any forced form of tool_choice
			// (any, tool, or named) with
			// "Thinking may not be enabled when tool_choice forces tool use".
			// In that case the request loop (see processAnthropicResponse →
			// isToolChoiceIncompatibleError) disables forceToolChoice and
			// retries, which drops this field entirely — Anthropic's default
			// with tools defined is tool_choice=auto, which is accepted
			// alongside thinking.
			apiReq.ToolChoice = map[string]string{"type": "any"}
		}
	}

	return marshalWithModelParams(apiReq, requestParamsWithout(req.ModelParams, dropTemperature, "temperature"))
}

func marshalWithModelParams(base any, modelParams map[string]any) ([]byte, error) {
	raw, err := json.Marshal(base)
	if err != nil {
		return nil, err
	}
	if len(modelParams) == 0 {
		return raw, nil
	}

	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	mergeRequestParams(payload, modelParams)
	return json.Marshal(payload)
}

func requestParamsWithout(modelParams map[string]any, drop bool, keys ...string) map[string]any {
	if !drop || len(modelParams) == 0 || len(keys) == 0 {
		return modelParams
	}

	dropKeys := make(map[string]bool, len(keys))
	needsCopy := false
	for _, key := range keys {
		dropKeys[key] = true
		if _, ok := modelParams[key]; ok {
			needsCopy = true
		}
	}
	if !needsCopy {
		return modelParams
	}

	out := make(map[string]any, len(modelParams))
	for key, value := range modelParams {
		if !dropKeys[key] {
			out[key] = value
		}
	}
	return out
}

// atomicRequestKeys are request-body keys whose value the user's model-params
// must fully replace, not deep-merge. Merging these produces payloads the API
// rejects (e.g. Anthropic tool_choice {"type":"auto","name":"x"} is invalid).
var atomicRequestKeys = map[string]bool{
	"tool_choice":     true,
	"response_format": true,
}

func mergeRequestParams(dst, src map[string]any) {
	for k, v := range src {
		if atomicRequestKeys[k] {
			dst[k] = v
			continue
		}

		existing, ok := dst[k]
		if !ok {
			dst[k] = v
			continue
		}

		existingMap, existingIsMap := existing.(map[string]any)
		srcMap, srcIsMap := v.(map[string]any)
		if existingIsMap && srcIsMap {
			mergeRequestParams(existingMap, srcMap)
			dst[k] = existingMap
			continue
		}

		dst[k] = v
	}
}

func (c *httpClient) parseAnthropicResponse(body []byte) (*ChatResponse, time.Duration, error) {
	var resp anthropicResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, 0, fmt.Errorf("llm: parsing Anthropic response: %w", err)
	}
	return mapAnthropicResponse(&resp), 0, nil
}

func mapAnthropicResponse(resp *anthropicResponse) *ChatResponse {
	// Extract content. Prefer tool_use blocks: when the request defined tools,
	// the tool_use input is the authoritative structured output. Thinking-enabled
	// models (and models run with tool_choice=auto) commonly emit a leading text
	// block alongside the tool_use — that text is explanatory prose, not the
	// answer. Picking text first would make the parser try to JSON-decode
	// "Looking at this code..." and fail.
	var content string
	for _, block := range resp.Content {
		if block.Type == "tool_use" {
			content = string(block.Input)
			break
		}
	}
	// Fall back to text blocks when no tool_use was emitted (e.g. non-tool mode,
	// or the model declined to call the tool under auto).
	if content == "" {
		for _, block := range resp.Content {
			if block.Type == "text" {
				content = block.Text
				break
			}
		}
	}

	// Map Anthropic stop_reason to OpenAI finish_reason.
	finishReason := resp.StopReason
	switch finishReason {
	case "end_turn":
		finishReason = "stop"
	case "max_tokens":
		finishReason = "length"
	case "tool_use":
		finishReason = "stop"
	}

	return &ChatResponse{
		Content: content,
		Usage: TokenUsage{
			PromptTokens:        resp.Usage.InputTokens,
			CompletionTokens:    resp.Usage.OutputTokens,
			CacheCreationTokens: resp.Usage.CacheCreationInputTokens,
			CacheReadTokens:     resp.Usage.CacheReadInputTokens,
		},
		FinishReason: finishReason,
		Model:        resp.Model,
	}
}

// readAnthropicStream consumes an SSE response from /v1/messages and
// reconstructs the same anthropicResponse the non-streaming path would have
// received, so callers see no difference.
//
// Anthropic's stream is a sequence of typed events. The ones we act on:
//
//	message_start       carries model name and usage.input_tokens
//	content_block_start opens a text / tool_use / thinking block
//	content_block_delta appends text_delta.text or input_json_delta.partial_json
//	content_block_stop  finalises the current block (commit tool_use input JSON)
//	message_delta       carries stop_reason and usage.output_tokens
//	message_stop        end of stream
//	ping                keepalive — ignore (these are why we stream at all)
//	error               mid-stream failure — propagate as retryable
//
// thinking blocks are dropped: mapAnthropicResponse only reads text and
// tool_use, so there's no point accumulating them.
func (c *httpClient) readAnthropicStream(body io.Reader) (*ChatResponse, time.Duration, error) {
	streamStart := time.Now()
	var firstDeltaAt time.Time // zero until the first content_block_delta
	var thinkingChars int

	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var resp anthropicResponse
	var cur *anthropicBlock       // nil between content_block_start/stop
	var toolInput strings.Builder // accumulates input_json_delta fragments
	var ev struct {               // reused per data: line; Decode zeroes it
		Type         string            `json:"type"`
		Message      anthropicResponse `json:"message"`       // message_start
		Index        int               `json:"index"`         // content_block_*
		ContentBlock anthropicBlock    `json:"content_block"` // content_block_start
		Delta        struct {
			Type        string `json:"type"`
			Text        string `json:"text"`         // text_delta
			PartialJSON string `json:"partial_json"` // input_json_delta
			Thinking    string `json:"thinking"`     // thinking_delta
			StopReason  string `json:"stop_reason"`  // message_delta.delta
		} `json:"delta"`
		Usage anthropicUsage `json:"usage"` // message_delta (top-level, not in delta)
		Error anthropicError `json:"error"`
	}

	flush := func() {
		if cur == nil {
			return
		}
		if cur.Type == "tool_use" {
			// partial_json fragments concatenate to a complete JSON document.
			// Leave validation to the caller that actually parses it.
			cur.Input = json.RawMessage(toolInput.String())
		}
		resp.Content = append(resp.Content, *cur)
		cur = nil
		toolInput.Reset()
	}

	for sc.Scan() {
		line := sc.Bytes()
		// SSE framing: "event:" lines name the event, "data:" lines carry the
		// payload. The payload's own "type" field duplicates the event name,
		// so we key off that and ignore the event: line entirely.
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		payload := bytes.TrimSpace(line[len("data:"):])
		if len(payload) == 0 {
			continue
		}

		if err := json.Unmarshal(payload, &ev); err != nil {
			return nil, 0, fmt.Errorf("llm: parsing stream event: %w", err)
		}

		switch ev.Type {
		case "message_start":
			resp.ID = ev.Message.ID
			resp.Model = ev.Message.Model
			resp.Usage.InputTokens = ev.Message.Usage.InputTokens
			resp.Usage.CacheCreationInputTokens = ev.Message.Usage.CacheCreationInputTokens
			resp.Usage.CacheReadInputTokens = ev.Message.Usage.CacheReadInputTokens

		case "content_block_start":
			flush()
			if ev.ContentBlock.Type == "thinking" {
				break // don't track; next start/stop will flush nil harmlessly
			}
			b := ev.ContentBlock
			cur = &b

		case "content_block_delta":
			if firstDeltaAt.IsZero() {
				firstDeltaAt = time.Now()
			}
			if ev.Delta.Type == "thinking_delta" {
				thinkingChars += len(ev.Delta.Thinking)
				break // block itself isn't tracked, but count the volume
			}
			if cur == nil {
				break // delta for a block we chose not to track
			}
			switch ev.Delta.Type {
			case "text_delta":
				cur.Text += ev.Delta.Text
			case "input_json_delta":
				toolInput.WriteString(ev.Delta.PartialJSON)
			}

		case "content_block_stop":
			flush()

		case "message_delta":
			resp.StopReason = ev.Delta.StopReason
			resp.Usage.OutputTokens = ev.Usage.OutputTokens

		case "message_stop":
			flush()
			out := mapAnthropicResponse(&resp)
			out.Usage.ThinkingChars = thinkingChars
			if !firstDeltaAt.IsZero() {
				out.TimeToFirstToken = firstDeltaAt.Sub(streamStart)
				out.GenerationTime = time.Since(firstDeltaAt)
			}
			return out, 0, nil

		case "error":
			// overloaded_error mid-stream is the common case; plain error
			// keeps it retryable via the ChatCompletion loop.
			return nil, 0, fmt.Errorf("llm: stream error (%s): %s", ev.Error.Type, ev.Error.Message)
		}
	}

	if err := sc.Err(); err != nil {
		return nil, 0, fmt.Errorf("llm: reading stream: %w", err)
	}
	// Scanner hit EOF without message_stop — the connection was cut. Surface
	// what we have so the retry log is informative, but don't return a partial
	// result: tool_use input is likely truncated mid-JSON.
	return nil, 0, fmt.Errorf("llm: stream ended without message_stop (got %d blocks, stop_reason=%q)", len(resp.Content), resp.StopReason)
}

func isToolChoiceIncompatibleError(body string) bool {
	lower := strings.ToLower(body)
	if !strings.Contains(lower, "tool_choice") {
		return false
	}
	if strings.Contains(lower, "not compatible with this model") {
		return true
	}
	// Anthropic rejects thinking combined with tool_choice forcing tool use
	// (type=any, type=tool, or a named tool). The retry path disables forced
	// tool_choice and re-issues the request with tool_choice=auto, which is
	// accepted alongside thinking.
	if strings.Contains(lower, "thinking") && strings.Contains(lower, "forces tool use") {
		return true
	}
	return strings.Contains(lower, "does not support") && strings.Contains(lower, "tool")
}

func isTemperatureIncompatibleError(body string) bool {
	lower := strings.ToLower(body)
	if !strings.Contains(lower, "temperature") {
		return false
	}
	return strings.Contains(lower, "may only be set") ||
		strings.Contains(lower, "must be") ||
		strings.Contains(lower, "unsupported value") ||
		strings.Contains(lower, "does not support") ||
		strings.Contains(lower, "not supported") ||
		strings.Contains(lower, "deprecated")
}

// isMaxTokensParamIncompatibleError detects OpenAI GPT-5 / reasoning-model
// errors that require `max_completion_tokens` in place of `max_tokens`.
// Example message: "Unsupported parameter: 'max_tokens' is not supported
// with this model. Use 'max_completion_tokens' instead."
func isMaxTokensParamIncompatibleError(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "max_tokens") &&
		strings.Contains(lower, "max_completion_tokens")
}

// backoff sleeps for an exponentially increasing duration with jitter.
// If retryAfter > 0, it respects the server-specified delay instead.
func (c *httpClient) backoff(ctx context.Context, attempt int, retryAfter time.Duration) {
	if c.backoffFunc != nil {
		c.backoffFunc(ctx, attempt, retryAfter)
		return
	}

	var delay time.Duration
	if retryAfter > 0 {
		delay = retryAfter
	} else {
		// Exponential backoff: 1s, 2s, 4s, 8s, capped at 30s.
		base := time.Duration(math.Pow(2, float64(attempt))) * time.Second
		if base > 30*time.Second {
			base = 30 * time.Second
		}
		// Add jitter: 0-25% of the base delay.
		jitter := time.Duration(rand.Float64() * 0.25 * float64(base))
		delay = base + jitter
	}

	c.logger.Debug("backing off before retry",
		"delay", delay,
		"attempt", attempt,
	)

	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}

// parseRetryAfter parses the Retry-After HTTP header value.
// Supports both seconds-based values (e.g., "5") and HTTP-date values.
func parseRetryAfter(header string) time.Duration {
	if header == "" {
		return 0
	}
	// Try parsing as integer seconds.
	if secs, err := strconv.Atoi(header); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	// Try parsing as HTTP-date.
	if t, err := http.ParseTime(header); err == nil {
		delay := time.Until(t)
		if delay > 0 {
			return delay
		}
	}
	return 0
}

// truncate shortens a string to the given maximum length.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
