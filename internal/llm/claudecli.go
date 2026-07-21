package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/textproto"
	"os/exec"
	"strings"
	"time"
)

var lookPathClaude = exec.LookPath

// NewClaudeCLIClient creates an LLM client backed by the local Claude Code CLI.
// This allows Anthropic models to run using the user's Claude login instead of
// requiring a separate ANTHROPIC_API_KEY.
func NewClaudeCLIClient(cfg ClientConfig) (Client, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 600 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	betas, err := extractClaudeCLIBetas(cfg.Headers)
	if err != nil {
		return nil, err
	}

	claudePath, err := lookPathClaude("claude")
	if err != nil {
		return nil, fmt.Errorf("claude command not found in PATH: %w", err)
	}

	return &claudeCLIClient{
		claudePath: claudePath,
		timeout:    cfg.Timeout,
		logger:     cfg.Logger,
		betas:      betas,
	}, nil
}

type claudeCLIClient struct {
	claudePath string
	timeout    time.Duration
	logger     *slog.Logger
	betas      []string
}

type claudeCLIResult struct {
	Type             string          `json:"type"`
	Subtype          string          `json:"subtype"`
	IsError          bool            `json:"is_error"`
	Result           string          `json:"result"`
	StructuredOutput json.RawMessage `json:"structured_output"`
	StopReason       string          `json:"stop_reason"`
	Usage            struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	ModelUsage map[string]json.RawMessage `json:"modelUsage"`
}

func (c *claudeCLIClient) ChatCompletion(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	systemPrompt, userPrompt := splitClaudeCLIMessages(req.Messages)

	args := []string{
		"-p",
		"--output-format", "json",
		"--tools", "",
		"--permission-mode", "bypassPermissions",
	}
	if req.Model != "" {
		args = append(args, "--model", req.Model)
	}
	if systemPrompt != "" {
		args = append(args, "--system-prompt", systemPrompt)
	}
	if req.ResponseSchema != nil {
		args = append(args, "--json-schema", string(*req.ResponseSchema))
	}
	if len(c.betas) > 0 {
		args = append(args, "--betas")
		args = append(args, c.betas...)
	}

	stdout, stderr, err := c.run(ctx, args, userPrompt)
	if err != nil {
		combined := strings.TrimSpace(strings.Join([]string{stdout, stderr}, "\n"))
		if isClaudeCLIContextLengthError(combined) {
			return nil, ErrContextLengthExceeded
		}
		if combined == "" {
			combined = err.Error()
		}
		return nil, fmt.Errorf("llm: claude CLI request failed: %s", combined)
	}

	var result claudeCLIResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return nil, fmt.Errorf("llm: parsing claude CLI response: %w", err)
	}
	if result.IsError {
		msg := strings.TrimSpace(result.Result)
		if msg == "" {
			msg = "unknown Claude CLI error"
		}
		if isClaudeCLIContextLengthError(msg) {
			return nil, ErrContextLengthExceeded
		}
		return nil, fmt.Errorf("llm: claude CLI error: %s", msg)
	}

	content := result.Result
	if len(result.StructuredOutput) > 0 && string(result.StructuredOutput) != "null" {
		content = string(result.StructuredOutput)
	}

	return &ChatResponse{
		Content:      content,
		Usage:        TokenUsage{PromptTokens: result.Usage.InputTokens, CompletionTokens: result.Usage.OutputTokens},
		FinishReason: mapClaudeCLIStopReason(result.StopReason),
		Model:        firstClaudeCLIModel(result.ModelUsage, req.Model),
	}, nil
}

func (c *claudeCLIClient) run(ctx context.Context, args []string, input string) (stdout string, stderr string, err error) {
	if _, hasDeadline := ctx.Deadline(); !hasDeadline && c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, c.claudePath, args...)
	cmd.Stdin = strings.NewReader(input)

	var outBuf bytes.Buffer
	var errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err = cmd.Run()
	return outBuf.String(), errBuf.String(), err
}

func extractClaudeCLIBetas(headers http.Header) ([]string, error) {
	if len(headers) == 0 {
		return nil, nil
	}

	var betas []string
	for name, values := range headers {
		canonical := textproto.CanonicalMIMEHeaderKey(name)
		switch canonical {
		case "Anthropic-Beta":
			for _, value := range values {
				trimmed := strings.TrimSpace(value)
				if trimmed != "" {
					betas = append(betas, trimmed)
				}
			}
		default:
			if len(values) > 0 {
				return nil, fmt.Errorf("claude CLI auth only supports Anthropic-Beta custom headers; unsupported header %q", canonical)
			}
		}
	}

	return betas, nil
}

func splitClaudeCLIMessages(messages []Message) (systemPrompt string, userPrompt string) {
	var systemParts []string
	var promptParts []string
	for _, msg := range messages {
		content := strings.TrimSpace(msg.Content)
		if content == "" {
			continue
		}
		if strings.EqualFold(msg.Role, "system") {
			systemParts = append(systemParts, content)
			continue
		}
		role := strings.TrimSpace(msg.Role)
		if len(promptParts) == 0 && strings.EqualFold(role, "user") {
			promptParts = append(promptParts, content)
			continue
		}
		if role == "" {
			role = "user"
		}
		promptParts = append(promptParts, fmt.Sprintf("%s:\n%s", strings.ToUpper(role[:1])+strings.ToLower(role[1:]), content))
	}
	return strings.Join(systemParts, "\n\n"), strings.Join(promptParts, "\n\n")
}

func mapClaudeCLIStopReason(stopReason string) string {
	switch stopReason {
	case "max_tokens":
		return "length"
	default:
		return stopReason
	}
}

func firstClaudeCLIModel(modelUsage map[string]json.RawMessage, fallback string) string {
	for model := range modelUsage {
		return model
	}
	return fallback
}

func isClaudeCLIContextLengthError(msg string) bool {
	lower := strings.ToLower(msg)
	return strings.Contains(lower, "context length") ||
		strings.Contains(lower, "too many tokens") ||
		strings.Contains(lower, "prompt is too long") ||
		strings.Contains(lower, "input is too long")
}
