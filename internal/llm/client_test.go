package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// successResponse builds a valid OpenAI-compatible JSON response body.
func successResponse(content, model, finishReason string, promptTok, completionTok int) string {
	return fmt.Sprintf(`{
		"choices": [{"message": {"content": %q}, "finish_reason": %q}],
		"usage": {"prompt_tokens": %d, "completion_tokens": %d},
		"model": %q
	}`, content, finishReason, promptTok, completionTok, model)
}

func TestChatCompletion_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, successResponse("hello world", "gpt-4", "stop", 10, 5))
	}))
	defer srv.Close()

	c := NewClient(ClientConfig{
		BaseURL:    srv.URL,
		Token:      "test-token",
		MaxRetries: 3,
		Timeout:    5 * time.Second,
	})

	resp, err := c.ChatCompletion(context.Background(), ChatRequest{
		Messages:    []Message{{Role: "user", Content: "hi"}},
		Temperature: 0.5,
		MaxTokens:   100,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Content != "hello world" {
		t.Errorf("Content = %q, want %q", resp.Content, "hello world")
	}
	if resp.Model != "gpt-4" {
		t.Errorf("Model = %q, want %q", resp.Model, "gpt-4")
	}
	if resp.FinishReason != "stop" {
		t.Errorf("FinishReason = %q, want %q", resp.FinishReason, "stop")
	}
	if resp.Usage.PromptTokens != 10 {
		t.Errorf("PromptTokens = %d, want 10", resp.Usage.PromptTokens)
	}
	if resp.Usage.CompletionTokens != 5 {
		t.Errorf("CompletionTokens = %d, want 5", resp.Usage.CompletionTokens)
	}
}

func TestChatCompletion_BearerTokenAuth(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, successResponse("ok", "gpt-4", "stop", 1, 1))
	}))
	defer srv.Close()

	c := NewClient(ClientConfig{
		BaseURL: srv.URL,
		Token:   "my-secret-token",
		Timeout: 5 * time.Second,
	})

	_, err := c.ChatCompletion(context.Background(), ChatRequest{
		Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "Bearer my-secret-token"
	if gotAuth != want {
		t.Errorf("Authorization = %q, want %q", gotAuth, want)
	}
}

func TestChatCompletion_AnthropicCustomHeaders(t *testing.T) {
	var gotBeta []string
	var gotVersion string
	var gotFeature string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBeta = r.Header.Values("Anthropic-Beta")
		gotVersion = r.Header.Get("Anthropic-Version")
		gotFeature = r.Header.Get("X-Feature-Flag")

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"id":"msg_1",
			"content":[{"type":"text","text":"ok"}],
			"model":"claude-opus-4-6",
			"stop_reason":"end_turn",
			"usage":{"input_tokens":10,"output_tokens":5}
		}`)
	}))
	defer srv.Close()

	c := NewClient(ClientConfig{
		BaseURL:  srv.URL,
		Provider: "anthropic",
		Token:    "anthropic-key",
		Headers: http.Header{
			"Anthropic-Beta":    []string{"context-1m-2025-08-07", "other-beta"},
			"Anthropic-Version": []string{"2099-01-01"},
			"X-Feature-Flag":    []string{"enabled"},
		},
		Timeout: 5 * time.Second,
	})

	resp, err := c.ChatCompletion(context.Background(), ChatRequest{
		Model:       "claude-opus-4-6",
		Messages:    []Message{{Role: "user", Content: "hi"}},
		Temperature: 0,
		MaxTokens:   64,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Content != "ok" {
		t.Fatalf("Content = %q, want %q", resp.Content, "ok")
	}

	if len(gotBeta) != 2 {
		t.Fatalf("Anthropic-Beta values = %v, want 2 values", gotBeta)
	}
	if gotBeta[0] != "context-1m-2025-08-07" || gotBeta[1] != "other-beta" {
		t.Fatalf("Anthropic-Beta values = %v, want [context-1m-2025-08-07 other-beta]", gotBeta)
	}
	if gotVersion != "2099-01-01" {
		t.Fatalf("Anthropic-Version = %q, want %q", gotVersion, "2099-01-01")
	}
	if gotFeature != "enabled" {
		t.Fatalf("X-Feature-Flag = %q, want %q", gotFeature, "enabled")
	}
}

func TestChatCompletion_AnthropicStream(t *testing.T) {
	var gotStream bool

	sse := func(w http.ResponseWriter, event, data string) {
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
		w.(http.Flusher).Flush()
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		gotStream, _ = body["stream"].(bool)

		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.WriteHeader(http.StatusOK)

		sse(w, "message_start", `{"type":"message_start","message":{"id":"msg_1","model":"claude-opus-4-6","stop_reason":null,"usage":{"input_tokens":42,"output_tokens":0}}}`)
		sse(w, "ping", `{"type":"ping"}`)
		// Thinking block: must be skipped, not treated as content.
		sse(w, "content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}`)
		sse(w, "content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"hmm"}}`)
		sse(w, "content_block_stop", `{"type":"content_block_stop","index":0}`)
		// Text block split across deltas.
		sse(w, "content_block_start", `{"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}`)
		sse(w, "content_block_delta", `{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"hel"}}`)
		sse(w, "ping", `{"type":"ping"}`)
		sse(w, "content_block_delta", `{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"lo"}}`)
		sse(w, "content_block_stop", `{"type":"content_block_stop","index":1}`)
		sse(w, "message_delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}`)
		sse(w, "message_stop", `{"type":"message_stop"}`)
	}))
	defer srv.Close()

	c := NewClient(ClientConfig{
		BaseURL:  srv.URL,
		Provider: "anthropic",
		Token:    "k",
		Timeout:  5 * time.Second,
	})

	resp, err := c.ChatCompletion(context.Background(), ChatRequest{
		Model:     "claude-opus-4-6",
		Messages:  []Message{{Role: "user", Content: "hi"}},
		MaxTokens: 64,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !gotStream {
		t.Fatal("request body did not include stream:true")
	}
	if resp.Content != "hello" {
		t.Fatalf("Content = %q, want %q", resp.Content, "hello")
	}
	if resp.FinishReason != "stop" {
		t.Fatalf("FinishReason = %q, want %q (end_turn should map to stop)", resp.FinishReason, "stop")
	}
	if resp.Usage.PromptTokens != 42 || resp.Usage.CompletionTokens != 7 {
		t.Fatalf("Usage = %+v, want {42 7}", resp.Usage)
	}
}

func TestChatCompletion_AnthropicStream_ToolUse(t *testing.T) {
	sse := func(w http.ResponseWriter, event, data string) {
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
		w.(http.Flusher).Flush()
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		sse(w, "message_start", `{"type":"message_start","message":{"id":"msg_1","model":"m","usage":{"input_tokens":10,"output_tokens":0}}}`)
		// tool_use input arrives as partial_json fragments that must concatenate
		// to valid JSON. Split mid-token to prove we don't parse incrementally.
		sse(w, "content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"tu_1","name":"security_analysis","input":{}}}`)
		sse(w, "content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"find"}}`)
		sse(w, "content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"ings\":["}}`)
		sse(w, "content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"1,2]}"}}`)
		sse(w, "content_block_stop", `{"type":"content_block_stop","index":0}`)
		sse(w, "message_delta", `{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":3}}`)
		sse(w, "message_stop", `{"type":"message_stop"}`)
	}))
	defer srv.Close()

	c := NewClient(ClientConfig{BaseURL: srv.URL, Provider: "anthropic", Token: "k", Timeout: 5 * time.Second})
	schema := json.RawMessage(`{"type":"object"}`)
	resp, err := c.ChatCompletion(context.Background(), ChatRequest{
		Model:          "m",
		Messages:       []Message{{Role: "user", Content: "go"}},
		MaxTokens:      64,
		OutputMode:     OutputModeToolUse,
		ResponseSchema: &schema,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Content != `{"findings":[1,2]}` {
		t.Fatalf("Content = %q, want reassembled tool input", resp.Content)
	}
	if resp.FinishReason != "stop" {
		t.Fatalf("FinishReason = %q, want %q (tool_use should map to stop)", resp.FinishReason, "stop")
	}
}

func TestChatCompletion_AnthropicStream_Truncated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"model\":\"m\",\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\n")
		fmt.Fprint(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n")
		// hang up mid-stream — no message_stop
	}))
	defer srv.Close()

	c := NewClient(ClientConfig{BaseURL: srv.URL, Provider: "anthropic", Token: "k", Timeout: 5 * time.Second, MaxRetries: 0})
	_, err := c.ChatCompletion(context.Background(), ChatRequest{
		Model:     "m",
		Messages:  []Message{{Role: "user", Content: "x"}},
		MaxTokens: 64,
	})
	if err == nil {
		t.Fatal("expected error on truncated stream, got nil")
	}
	if !strings.Contains(err.Error(), "message_stop") {
		t.Fatalf("error = %q, want mention of message_stop", err)
	}
}

func TestChatCompletion_FinishReasonLength(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, successResponse("partial", "gpt-4", "length", 100, 50))
	}))
	defer srv.Close()

	c := NewClient(ClientConfig{BaseURL: srv.URL, Token: "t", Timeout: 5 * time.Second})

	resp, err := c.ChatCompletion(context.Background(), ChatRequest{
		Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.FinishReason != "length" {
		t.Errorf("FinishReason = %q, want %q", resp.FinishReason, "length")
	}
}

func TestChatCompletion_TokenUsageTracked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, successResponse("ok", "gpt-4", "stop", 250, 75))
	}))
	defer srv.Close()

	c := NewClient(ClientConfig{BaseURL: srv.URL, Token: "t", Timeout: 5 * time.Second})

	resp, err := c.ChatCompletion(context.Background(), ChatRequest{
		Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Usage.PromptTokens != 250 {
		t.Errorf("PromptTokens = %d, want 250", resp.Usage.PromptTokens)
	}
	if resp.Usage.CompletionTokens != 75 {
		t.Errorf("CompletionTokens = %d, want 75", resp.Usage.CompletionTokens)
	}
}

func TestChatCompletion_Retry429(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n <= 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, `{"error": "rate limited"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, successResponse("ok", "gpt-4", "stop", 1, 1))
	}))
	defer srv.Close()

	// Use a custom client with very short backoff by replacing the httpClient's backoff.
	// Since we can't easily replace backoff, we rely on the real implementation but with
	// a short enough test that the exponential backoff (1s, 2s) completes.
	// Instead, we'll directly access the httpClient and override its backoff timing
	// by creating a wrapper. The simplest approach: just verify it eventually succeeds.
	c := NewClient(ClientConfig{
		BaseURL:    srv.URL,
		Token:      "t",
		MaxRetries: 3,
		Timeout:    30 * time.Second,
	})

	// Override the internal client to have a very short timeout so backoff doesn't block.
	hc := c.(*httpClient)
	hc.backoffFunc = func(_ context.Context, _ int, _ time.Duration) {} // no-op backoff for test speed

	resp, err := hc.ChatCompletion(context.Background(), ChatRequest{
		Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Content != "ok" {
		t.Errorf("Content = %q, want %q", resp.Content, "ok")
	}
	if int(attempts.Load()) != 3 {
		t.Errorf("attempts = %d, want 3", attempts.Load())
	}
}

func TestChatCompletion_Retry5xx(t *testing.T) {
	statusCodes := []int{500, 502, 503}
	for _, code := range statusCodes {
		t.Run(fmt.Sprintf("status_%d", code), func(t *testing.T) {
			var attempts atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := attempts.Add(1)
				if n == 1 {
					w.WriteHeader(code)
					fmt.Fprint(w, `{"error": "server error"}`)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, successResponse("recovered", "gpt-4", "stop", 1, 1))
			}))
			defer srv.Close()

			c := NewClient(ClientConfig{
				BaseURL:    srv.URL,
				Token:      "t",
				MaxRetries: 3,
				Timeout:    30 * time.Second,
			})
			hc := c.(*httpClient)
			hc.backoffFunc = func(_ context.Context, _ int, _ time.Duration) {}

			resp, err := hc.ChatCompletion(context.Background(), ChatRequest{
				Messages: []Message{{Role: "user", Content: "hi"}},
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Content != "recovered" {
				t.Errorf("Content = %q, want %q", resp.Content, "recovered")
			}
		})
	}
}

func TestChatCompletion_RetryAfterHeader(t *testing.T) {
	var attempts atomic.Int32
	var observedDelay time.Duration

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "3")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, `{"error": "rate limited"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, successResponse("ok", "gpt-4", "stop", 1, 1))
	}))
	defer srv.Close()

	c := NewClient(ClientConfig{
		BaseURL:    srv.URL,
		Token:      "t",
		MaxRetries: 3,
		Timeout:    30 * time.Second,
	})
	hc := c.(*httpClient)
	hc.backoffFunc = func(_ context.Context, _ int, retryAfter time.Duration) {
		observedDelay = retryAfter
	}

	resp, err := hc.ChatCompletion(context.Background(), ChatRequest{
		Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Content != "ok" {
		t.Errorf("Content = %q, want %q", resp.Content, "ok")
	}
	if observedDelay != 3*time.Second {
		t.Errorf("retry-after delay = %v, want 3s", observedDelay)
	}
}

func TestChatCompletion_MaxRetriesExhausted(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error": "always failing"}`)
	}))
	defer srv.Close()

	c := NewClient(ClientConfig{
		BaseURL:    srv.URL,
		Token:      "t",
		MaxRetries: 3,
		Timeout:    30 * time.Second,
	})
	hc := c.(*httpClient)
	hc.backoffFunc = func(_ context.Context, _ int, _ time.Duration) {}

	_, err := hc.ChatCompletion(context.Background(), ChatRequest{
		Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if err == nil {
		t.Fatal("expected error after max retries, got nil")
	}
	if !strings.Contains(err.Error(), "exhausted 3 retries") {
		t.Errorf("error = %q, want it to contain 'exhausted 3 retries'", err.Error())
	}
	// 1 initial + 3 retries = 4 total attempts
	if int(attempts.Load()) != 4 {
		t.Errorf("attempts = %d, want 4", attempts.Load())
	}
}

func TestChatCompletion_ContextLengthExceeded(t *testing.T) {
	tests := []struct {
		name     string
		respBody string
	}{
		{
			name:     "code_field",
			respBody: `{"error": {"message": "some error", "type": "invalid_request_error", "code": "context_length_exceeded"}}`,
		},
		{
			name:     "message_field",
			respBody: `{"error": {"message": "context_length_exceeded: too many tokens", "type": "invalid_request_error", "code": ""}}`,
		},
		{
			name:     "maximum_context_length",
			respBody: `{"error": {"message": "This model's maximum context length is 8192 tokens", "type": "invalid_request_error", "code": ""}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, tt.respBody)
			}))
			defer srv.Close()

			c := NewClient(ClientConfig{
				BaseURL:    srv.URL,
				Token:      "t",
				MaxRetries: 3,
				Timeout:    5 * time.Second,
			})

			_, err := c.ChatCompletion(context.Background(), ChatRequest{
				Messages: []Message{{Role: "user", Content: "hi"}},
			})
			if err != ErrContextLengthExceeded {
				t.Errorf("err = %v, want ErrContextLengthExceeded", err)
			}
		})
	}
}

func TestChatCompletion_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, successResponse("late", "gpt-4", "stop", 1, 1))
	}))
	defer srv.Close()

	c := NewClient(ClientConfig{
		BaseURL:    srv.URL,
		Token:      "t",
		MaxRetries: 1,
		Timeout:    200 * time.Millisecond,
	})
	hc := c.(*httpClient)
	hc.maxRetries = 0 // no retries — just fail on first timeout

	_, err := hc.ChatCompletion(context.Background(), ChatRequest{
		Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

func TestChatCompletion_ContextCancellation(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error": "fail"}`)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())

	c := NewClient(ClientConfig{
		BaseURL:    srv.URL,
		Token:      "t",
		MaxRetries: 10,
		Timeout:    30 * time.Second,
	})
	hc := c.(*httpClient)
	hc.backoffFunc = func(ctx context.Context, _ int, _ time.Duration) {
		// Cancel context during backoff to simulate cancellation stopping retry loop
		cancel()
		// Wait for context to be done
		<-ctx.Done()
	}

	_, err := hc.ChatCompletion(ctx, ChatRequest{
		Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if err == nil {
		t.Fatal("expected error from cancelled context, got nil")
	}
	if !strings.Contains(err.Error(), "context") {
		t.Errorf("error = %q, want it to mention 'context'", err.Error())
	}
}

func TestChatCompletion_ResponseFormatJSONSchema(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, successResponse("ok", "gpt-4", "stop", 1, 1))
	}))
	defer srv.Close()

	schema := json.RawMessage(`{"type":"object","properties":{"name":{"type":"string"}}}`)
	c := NewClient(ClientConfig{BaseURL: srv.URL, Token: "t", Timeout: 5 * time.Second})

	_, err := c.ChatCompletion(context.Background(), ChatRequest{
		Messages:       []Message{{Role: "user", Content: "hi"}},
		OutputMode:     OutputModeJSONSchema,
		ResponseSchema: &schema,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var reqBody map[string]json.RawMessage
	if err := json.Unmarshal(receivedBody, &reqBody); err != nil {
		t.Fatalf("failed to parse request body: %v", err)
	}

	rfRaw, ok := reqBody["response_format"]
	if !ok {
		t.Fatal("request body missing 'response_format' field")
	}

	var rf map[string]interface{}
	if err := json.Unmarshal(rfRaw, &rf); err != nil {
		t.Fatalf("failed to parse response_format: %v", err)
	}
	if rf["type"] != "json_schema" {
		t.Errorf("response_format.type = %v, want 'json_schema'", rf["type"])
	}
	if rf["json_schema"] == nil {
		t.Error("response_format.json_schema is nil, want schema")
	}
}

func TestChatCompletion_ModelParamsMergedIntoRequest(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, successResponse("ok", "gpt-4", "stop", 1, 1))
	}))
	defer srv.Close()

	c := NewClient(ClientConfig{BaseURL: srv.URL, Token: "t", Timeout: 5 * time.Second})

	_, err := c.ChatCompletion(context.Background(), ChatRequest{
		Messages: []Message{{Role: "user", Content: "hi"}},
		ModelParams: map[string]any{
			"thinking": map[string]any{"type": "enabled", "budget_tokens": 2048},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var reqBody map[string]any
	if err := json.Unmarshal(receivedBody, &reqBody); err != nil {
		t.Fatalf("failed to parse request body: %v", err)
	}
	thinkingRaw, ok := reqBody["thinking"]
	if !ok {
		t.Fatalf("request missing thinking model param: %v", reqBody)
	}
	thinking, ok := thinkingRaw.(map[string]any)
	if !ok {
		t.Fatalf("thinking param is %T, want object", thinkingRaw)
	}
	if thinking["type"] != "enabled" {
		t.Errorf("thinking.type = %v, want enabled", thinking["type"])
	}
}

func TestChatCompletion_RetriesOpenAIWithoutTemperature(t *testing.T) {
	var attempts atomic.Int32
	var retriedBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":{"message":"Unsupported value: 'temperature' does not support 0 with this model. Only the default (1) value is supported.","type":"invalid_request_error","param":"temperature"}}`)
			return
		}

		retriedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, successResponse("ok", "gpt-5.5", "stop", 1, 1))
	}))
	defer srv.Close()

	modelParams := map[string]any{"temperature": 0.0}
	c := NewClient(ClientConfig{
		BaseURL:  srv.URL,
		Provider: "openai",
		Token:    "t",
		Timeout:  5 * time.Second,
	})

	resp, err := c.ChatCompletion(context.Background(), ChatRequest{
		Model:       "gpt-5.5",
		Messages:    []Message{{Role: "user", Content: "hi"}},
		Temperature: 0.0,
		MaxTokens:   100,
		ModelParams: modelParams,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Content != "ok" {
		t.Fatalf("Content = %q, want ok", resp.Content)
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("attempts = %d, want 2", got)
	}

	var reqBody map[string]any
	if err := json.Unmarshal(retriedBody, &reqBody); err != nil {
		t.Fatalf("failed to parse retried request body: %v", err)
	}
	if _, ok := reqBody["temperature"]; ok {
		t.Fatalf("retried request still contains temperature: %v", reqBody["temperature"])
	}
	if _, ok := modelParams["temperature"]; !ok {
		t.Fatal("request retry mutated caller-owned model params")
	}
}

func TestChatCompletion_ModelParamsDeepMerge(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, successResponse("ok", "gpt-4", "stop", 1, 1))
	}))
	defer srv.Close()

	schema := json.RawMessage(`{"name":"security_analysis","strict":true,"schema":{"type":"object","properties":{"result":{"type":"string"}}}}`)
	c := NewClient(ClientConfig{BaseURL: srv.URL, Token: "t", Timeout: 5 * time.Second})

	_, err := c.ChatCompletion(context.Background(), ChatRequest{
		Messages:       []Message{{Role: "user", Content: "hi"}},
		OutputMode:     OutputModeToolUse,
		ResponseSchema: &schema,
		ModelParams: map[string]any{
			"tool_choice": map[string]any{"type": "auto"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var reqBody map[string]any
	if err := json.Unmarshal(receivedBody, &reqBody); err != nil {
		t.Fatalf("failed to parse request body: %v", err)
	}
	tcRaw, ok := reqBody["tool_choice"]
	if !ok {
		t.Fatalf("request missing tool_choice: %v", reqBody)
	}
	toolChoice, ok := tcRaw.(map[string]any)
	if !ok {
		t.Fatalf("tool_choice is %T, want object", tcRaw)
	}
	if toolChoice["type"] != "auto" {
		t.Errorf("tool_choice.type = %v, want auto", toolChoice["type"])
	}
	// tool_choice is an atomic key: model-params must fully replace the base
	// value, not deep-merge into it (merged values are rejected by the API).
	if _, hasFn := toolChoice["function"]; hasFn {
		t.Errorf("tool_choice.function should not survive replacement: %v", toolChoice)
	}
	if _, hasName := toolChoice["name"]; hasName {
		t.Errorf("tool_choice.name should not survive replacement: %v", toolChoice)
	}
}

func TestChatCompletion_ToolUseForClaude(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		// Respond with tool_call content
		fmt.Fprint(w, `{
			"choices": [{"message": {"content": "", "tool_calls": [{"function": {"arguments": "{\"result\":\"ok\"}"}}]}, "finish_reason": "stop"}],
			"usage": {"prompt_tokens": 1, "completion_tokens": 1},
			"model": "claude-3"
		}`)
	}))
	defer srv.Close()

	schema := json.RawMessage(`{"type":"object","properties":{"result":{"type":"string"}}}`)
	c := NewClient(ClientConfig{BaseURL: srv.URL, Token: "t", Timeout: 5 * time.Second})

	resp, err := c.ChatCompletion(context.Background(), ChatRequest{
		Messages:       []Message{{Role: "user", Content: "hi"}},
		OutputMode:     OutputModeToolUse,
		ResponseSchema: &schema,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify tool_calls arguments were extracted as content
	if resp.Content != `{"result":"ok"}` {
		t.Errorf("Content = %q, want %q", resp.Content, `{"result":"ok"}`)
	}

	var reqBody map[string]json.RawMessage
	if err := json.Unmarshal(receivedBody, &reqBody); err != nil {
		t.Fatalf("failed to parse request body: %v", err)
	}

	toolsRaw, ok := reqBody["tools"]
	if !ok {
		t.Fatal("request body missing 'tools' field")
	}

	var tools []map[string]interface{}
	if err := json.Unmarshal(toolsRaw, &tools); err != nil {
		t.Fatalf("failed to parse tools: %v", err)
	}
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}
	if tools[0]["type"] != "function" {
		t.Errorf("tool type = %v, want 'function'", tools[0]["type"])
	}
	fn, hasFn := tools[0]["function"].(map[string]interface{})
	if !hasFn {
		t.Fatal("tool missing 'function' field (OpenAI format)")
	}
	if fn["name"] != "security_analysis" {
		t.Errorf("function name = %v, want 'security_analysis'", fn["name"])
	}
	if _, hasParams := fn["parameters"]; !hasParams {
		t.Error("function missing 'parameters' field")
	}

	// Verify tool_choice is set
	if _, hasTC := reqBody["tool_choice"]; !hasTC {
		t.Error("request body missing 'tool_choice' field")
	}

	// Verify no response_format is set
	if _, hasRF := reqBody["response_format"]; hasRF {
		t.Error("request body should not have 'response_format' for tool_use mode")
	}
}

func TestChatCompletion_ToolUseFallbackWhenToolChoiceRejected(t *testing.T) {
	var attempts int32
	var requestBodies [][]byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requestBodies = append(requestBodies, append([]byte(nil), body...))

		n := atomic.AddInt32(&attempts, 1)
		if n == 1 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":{"message":"tool_choice forces tool use is not compatible with this model."}}`)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
                        "choices": [{"message": {"content": "", "tool_calls": [{"function": {"arguments": "{\"result\":\"ok\"}"}}]}, "finish_reason": "stop"}],
                        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
                        "model": "claude-sonnet-4-6"
                }`)
	}))
	defer srv.Close()

	schema := json.RawMessage(`{"type":"object","properties":{"result":{"type":"string"}}}`)
	c := NewClient(ClientConfig{BaseURL: srv.URL, Token: "t", Timeout: 5 * time.Second})

	resp, err := c.ChatCompletion(context.Background(), ChatRequest{
		Messages:       []Message{{Role: "user", Content: "hi"}},
		OutputMode:     OutputModeToolUse,
		ResponseSchema: &schema,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Content != `{"result":"ok"}` {
		t.Errorf("Content = %q, want %q", resp.Content, `{"result":"ok"}`)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
	if len(requestBodies) != 2 {
		t.Fatalf("expected 2 request bodies, got %d", len(requestBodies))
	}

	var first map[string]json.RawMessage
	if err := json.Unmarshal(requestBodies[0], &first); err != nil {
		t.Fatalf("failed to parse first request body: %v", err)
	}
	if _, hasToolChoice := first["tool_choice"]; !hasToolChoice {
		t.Fatal("first request missing tool_choice")
	}

	var second map[string]json.RawMessage
	if err := json.Unmarshal(requestBodies[1], &second); err != nil {
		t.Fatalf("failed to parse second request body: %v", err)
	}
	if _, hasToolChoice := second["tool_choice"]; hasToolChoice {
		t.Fatal("second request should not include tool_choice fallback")
	}
	if _, hasTools := second["tools"]; !hasTools {
		t.Fatal("second request should keep tools in fallback")
	}
}

func TestChatCompletion_UnstructuredFallback(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, successResponse("unstructured output", "gemini-pro", "stop", 1, 1))
	}))
	defer srv.Close()

	schema := json.RawMessage(`{"type":"object"}`)
	c := NewClient(ClientConfig{BaseURL: srv.URL, Token: "t", Timeout: 5 * time.Second})

	resp, err := c.ChatCompletion(context.Background(), ChatRequest{
		Messages:       []Message{{Role: "user", Content: "hi"}},
		OutputMode:     OutputModeNone,
		ResponseSchema: &schema,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Content != "unstructured output" {
		t.Errorf("Content = %q, want %q", resp.Content, "unstructured output")
	}

	var reqBody map[string]json.RawMessage
	if err := json.Unmarshal(receivedBody, &reqBody); err != nil {
		t.Fatalf("failed to parse request body: %v", err)
	}

	if _, hasRF := reqBody["response_format"]; hasRF {
		t.Error("request body should not have 'response_format' for OutputModeNone")
	}
	if _, hasTools := reqBody["tools"]; hasTools {
		t.Error("request body should not have 'tools' for OutputModeNone")
	}
}

func TestChatCompletion_EndpointURL(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		wantPath string
	}{
		{"empty_endpoint", "", "/chat/completions"},
		{"named_endpoint", "my-model", "/my-model/invocations"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotPath string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, successResponse("ok", "gpt-4", "stop", 1, 1))
			}))
			defer srv.Close()

			c := NewClient(ClientConfig{BaseURL: srv.URL, Token: "t", Timeout: 5 * time.Second})

			_, err := c.ChatCompletion(context.Background(), ChatRequest{
				Endpoint: tt.endpoint,
				Messages: []Message{{Role: "user", Content: "hi"}},
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotPath != tt.wantPath {
				t.Errorf("path = %q, want %q", gotPath, tt.wantPath)
			}
		})
	}
}

func TestParseRetryAfter(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   time.Duration
	}{
		{"empty", "", 0},
		{"seconds", "5", 5 * time.Second},
		{"zero", "0", 0},
		{"negative", "-1", 0},
		{"non_numeric", "abc", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseRetryAfter(tt.header)
			if got != tt.want {
				t.Errorf("parseRetryAfter(%q) = %v, want %v", tt.header, got, tt.want)
			}
		})
	}
}

// --- schema.go tests ---

func TestOutputModeForModel(t *testing.T) {
	tests := []struct {
		name      string
		modelName string
		want      OutputMode
	}{
		{"gpt4", "gpt-4", OutputModeJSONSchema},
		{"gpt4_turbo", "gpt-4-turbo", OutputModeJSONSchema},
		{"gpt35", "gpt-3.5-turbo", OutputModeJSONSchema},
		{"GPT_uppercase", "GPT-4", OutputModeJSONSchema},
		{"o1_model", "o1-preview", OutputModeJSONSchema},
		{"o3_model", "o3-mini", OutputModeJSONSchema},
		{"claude3", "claude-3-sonnet", OutputModeToolUse},
		{"claude_uppercase", "Claude-3-Opus", OutputModeToolUse},
		{"anthropic", "anthropic.claude-v2", OutputModeToolUse},
		{"gemini_pro", "gemini-pro", OutputModeJSONSchema},
		{"gemini_15", "gemini-1.5-pro", OutputModeJSONSchema},
		{"unknown_model", "llama-3-70b", OutputModeNone},
		{"empty_string", "", OutputModeNone},
		{"mixtral", "mixtral-8x7b", OutputModeNone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := OutputModeForModel(tt.modelName)
			if got != tt.want {
				t.Errorf("OutputModeForModel(%q) = %v, want %v", tt.modelName, got, tt.want)
			}
		})
	}
}

func TestSecurityAnalysisSchema_ValidJSON(t *testing.T) {
	schema := SecurityAnalysisSchema()
	if schema == nil {
		t.Fatal("SecurityAnalysisSchema() returned nil")
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(*schema, &parsed); err != nil {
		t.Fatalf("SecurityAnalysisSchema() returned invalid JSON: %v", err)
	}

	if parsed["name"] != "security_analysis" {
		t.Errorf("schema name = %v, want 'security_analysis'", parsed["name"])
	}
	if parsed["strict"] != true {
		t.Errorf("schema strict = %v, want true", parsed["strict"])
	}

	schemaObj, ok := parsed["schema"].(map[string]interface{})
	if !ok {
		t.Fatal("schema.schema is not an object")
	}
	if schemaObj["type"] != "object" {
		t.Errorf("schema.schema.type = %v, want 'object'", schemaObj["type"])
	}

	required, ok := schemaObj["required"].([]interface{})
	if !ok {
		t.Fatal("schema.schema.required is not an array")
	}
	requiredFields := make(map[string]bool)
	for _, f := range required {
		requiredFields[f.(string)] = true
	}

	expectedFields := []string{"repo_name", "description", "public_api_routes", "security_issues", "security_risk", "risk_justification"}
	for _, f := range expectedFields {
		if !requiredFields[f] {
			t.Errorf("missing required field: %s", f)
		}
	}
}

func TestExtractInnerSchema(t *testing.T) {
	// Envelope format (used by response_format JSON Schema mode).
	envelope := json.RawMessage(`{"name":"test","strict":true,"schema":{"type":"object","properties":{"x":{"type":"string"}}}}`)
	inner := extractInnerSchema(&envelope)
	var parsed map[string]interface{}
	if err := json.Unmarshal(*inner, &parsed); err != nil {
		t.Fatalf("failed to parse inner schema: %v", err)
	}
	if parsed["type"] != "object" {
		t.Errorf("inner schema type = %v, want 'object'", parsed["type"])
	}

	// Already a raw schema (no envelope).
	raw := json.RawMessage(`{"type":"object","properties":{}}`)
	result := extractInnerSchema(&raw)
	var parsed2 map[string]interface{}
	if err := json.Unmarshal(*result, &parsed2); err != nil {
		t.Fatalf("failed to parse raw schema: %v", err)
	}
	if parsed2["type"] != "object" {
		t.Errorf("raw schema type = %v, want 'object'", parsed2["type"])
	}

	// Nil input.
	if extractInnerSchema(nil) != nil {
		t.Error("expected nil for nil input")
	}
}

func TestFlexString_PlainString(t *testing.T) {
	body := `{"choices":[{"message":{"content":"hello"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1},"model":"gpt-4"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	c := NewClient(ClientConfig{BaseURL: srv.URL, Token: "t", Timeout: 5 * time.Second})
	resp, err := c.ChatCompletion(context.Background(), ChatRequest{
		Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Content != "hello" {
		t.Errorf("Content = %q, want %q", resp.Content, "hello")
	}
}

func TestFlexString_ArrayOfParts(t *testing.T) {
	// Gemini-style: content is an array of parts.
	body := `{"choices":[{"message":{"content":[{"type":"text","text":"hello from gemini"}]},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1},"model":"gemini-3-pro"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	c := NewClient(ClientConfig{BaseURL: srv.URL, Token: "t", Timeout: 5 * time.Second})
	resp, err := c.ChatCompletion(context.Background(), ChatRequest{
		Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Content != "hello from gemini" {
		t.Errorf("Content = %q, want %q", resp.Content, "hello from gemini")
	}
}

func TestFlexString_NullContent(t *testing.T) {
	body := `{"choices":[{"message":{"content":null,"tool_calls":[{"function":{"arguments":"{\"ok\":true}"}}]},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1},"model":"gpt-4"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	c := NewClient(ClientConfig{BaseURL: srv.URL, Token: "t", Timeout: 5 * time.Second})
	resp, err := c.ChatCompletion(context.Background(), ChatRequest{
		Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Content != `{"ok":true}` {
		t.Errorf("Content = %q, want tool_calls fallback", resp.Content)
	}
}

func TestChatCompletion_ParseErrorNotRetried(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `not valid json at all`)
	}))
	defer srv.Close()

	c := NewClient(ClientConfig{
		BaseURL:    srv.URL,
		Token:      "t",
		MaxRetries: 3,
		Timeout:    5 * time.Second,
	})
	hc := c.(*httpClient)
	hc.backoffFunc = func(_ context.Context, _ int, _ time.Duration) {}

	_, err := hc.ChatCompletion(context.Background(), ChatRequest{
		Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "parsing response") {
		t.Errorf("error = %q, want it to contain 'parsing response'", err.Error())
	}
	// Should NOT retry — only 1 attempt.
	if int(attempts.Load()) != 1 {
		t.Errorf("attempts = %d, want 1 (no retries for parse errors)", attempts.Load())
	}
}

func TestErrorTypes_ErrorAndUnwrap(t *testing.T) {
	base := errors.New("underlying cause")
	tests := []struct {
		name string
		err  error
	}{
		{"errNonRetryable", &errNonRetryable{err: base}},
		{"errToolChoiceIncompatible", &errToolChoiceIncompatible{err: base}},
		{"errTemperatureIncompatible", &errTemperatureIncompatible{err: base}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != "underlying cause" {
				t.Errorf("Error() = %q, want %q", got, "underlying cause")
			}
			if !errors.Is(tt.err, base) {
				t.Errorf("errors.Is() = false, want true (Unwrap should return wrapped error)")
			}
			if unwrapped := errors.Unwrap(tt.err); unwrapped != base {
				t.Errorf("Unwrap() = %v, want %v", unwrapped, base)
			}
		})
	}
}
