package llm

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/block/codecrucible/internal/usage"
)

// A missing or invalid count is different from an explicitly reported zero.
func decodeReportedUsage(body []byte, provider string) (TokenUsage, string, string) {
	var envelope struct {
		Model string                     `json:"model"`
		Usage map[string]json.RawMessage `json:"usage"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		return TokenUsage{}, "unknown", ""
	}
	if envelope.Usage == nil {
		return TokenUsage{}, "unknown", envelope.Model
	}
	invalid := false
	read := func(name string) (int, bool) {
		raw, ok := envelope.Usage[name]
		var n int
		if !ok || string(raw) == "null" || json.Unmarshal(raw, &n) != nil || n < 0 {
			if ok {
				invalid = true
			}
			return 0, false
		}
		return n, true
	}
	var t TokenUsage
	var input, output bool
	if provider == "anthropic" {
		t.PromptTokens, input = read("input_tokens")
		t.CompletionTokens, output = read("output_tokens")
		t.CacheCreationTokens, _ = read("cache_creation_input_tokens")
		t.CacheReadTokens, _ = read("cache_read_input_tokens")
	} else {
		t.PromptTokens, input = read("prompt_tokens")
		t.CompletionTokens, output = read("completion_tokens")
		var completion struct {
			Reasoning int `json:"reasoning_tokens"`
		}
		var prompt struct {
			Cached int `json:"cached_tokens"`
		}
		if raw, ok := envelope.Usage["completion_tokens_details"]; ok && json.Unmarshal(raw, &completion) != nil {
			invalid = true
		}
		if raw, ok := envelope.Usage["prompt_tokens_details"]; ok && json.Unmarshal(raw, &prompt) != nil {
			invalid = true
		}
		if completion.Reasoning < 0 || prompt.Cached < 0 || completion.Reasoning > t.CompletionTokens || prompt.Cached > t.PromptTokens {
			invalid = true
		}
		t.ReasoningTokens = max(0, completion.Reasoning)
		t.CachedPromptTokens = max(0, prompt.Cached)
	}
	status := "partial"
	if input && output && !invalid {
		status = "reported"
	}
	if !input && !output && t.CacheCreationTokens == 0 && t.CacheReadTokens == 0 {
		status = "unknown"
	}
	return t, status, envelope.Model
}

func hasMessageUsageField(body []byte, field string) bool {
	var event struct {
		Message json.RawMessage `json:"message"`
	}
	return json.Unmarshal(body, &event) == nil && hasUsageField(event.Message, field)
}

func hasUsageField(body []byte, field string) bool {
	var event struct {
		Usage map[string]json.RawMessage `json:"usage"`
	}
	if json.Unmarshal(body, &event) != nil {
		return false
	}
	raw, ok := event.Usage[field]
	var count int
	return ok && string(raw) != "null" && json.Unmarshal(raw, &count) == nil && count >= 0
}

func attemptResult(ctx context.Context, resp *ChatResponse, status int, err error) usage.Result {
	r := usage.Result{Status: "completed", HTTPStatus: status}
	if resp != nil {
		r.Tokens, r.UsageStatus, r.Model = resp.Usage, resp.UsageStatus, resp.Model
	}
	if err == nil {
		return r
	}
	r.Status, r.Reason = "error", "response_error"
	var tool *errToolChoiceIncompatible
	var temp *errTemperatureIncompatible
	var limit *errMaxTokensParamIncompatible
	switch {
	case ctx.Err() != nil:
		r.Status, r.Reason = "cancelled", "context_cancelled"
	case errors.Is(err, ErrContextLengthExceeded):
		r.Reason = "context_length_exceeded"
	case errors.As(err, &tool):
		r.Reason = "tool_choice_incompatible"
	case errors.As(err, &temp):
		r.Reason = "temperature_incompatible"
	case errors.As(err, &limit):
		r.Reason = "max_tokens_incompatible"
	case status == 429:
		r.Reason = "rate_limited"
	case status >= 500:
		r.Reason = "server_error"
	case status == 0:
		r.Reason = "transport_error"
	}
	return r
}
