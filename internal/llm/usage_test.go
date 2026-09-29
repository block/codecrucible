package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/block/codecrucible/internal/usage"
)

func TestUsageRecordsHTTPRetriesAndMissingUsage(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 {
			w.WriteHeader(429)
			fmt.Fprint(w, `{"error":{"message":"secret response body"}}`)
			return
		}
		fmt.Fprint(w, `{"model":"actual-model","choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":100,"completion_tokens":10,"completion_tokens_details":{"reasoning_tokens":4}}}`)
	}))
	defer srv.Close()
	c := NewClient(ClientConfig{BaseURL: srv.URL, Provider: "openai"}).(*httpClient)
	c.backoffFunc = func(context.Context, int, time.Duration) {}
	l := usage.New()
	ctx := usage.WithPhase(usage.WithLedger(context.Background(), l), usage.Phase{Name: "analysis", Provider: "openai", Pricing: usage.Pricing{InputPerMillion: 2, OutputPerMillion: 10}})
	if _, err := c.ChatCompletion(ctx, ChatRequest{Model: "requested", Label: "chunk 1"}); err != nil {
		t.Fatal(err)
	}
	r := l.Snapshot("completed")
	if len(r.Requests) != 2 {
		t.Fatalf("got %d attempts, want 2", len(r.Requests))
	}
	if r.Requests[0].UsageStatus != "unknown" || r.Requests[0].Reason != "rate_limited" || r.Requests[1].UsageStatus != "reported" {
		t.Fatalf("bad request states: %+v", r.Requests)
	}
	if r.Total.Complete || r.Total.Tokens.PromptTokens != 100 || r.Total.Tokens.ReasoningTokens != 4 {
		t.Fatalf("wrong totals: %+v", r.Total)
	}
	if r.Requests[1].ReportedModel != "actual-model" {
		t.Fatal("actual model missing")
	}
}

func TestUsageRecordsInterruptedStreamBeforeRetry(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintln(w, `data: {"type":"message_start","message":{"model":"claude-test","usage":{"input_tokens":100,"output_tokens":1,"cache_read_input_tokens":40}}}`)
		if n == 1 {
			fmt.Fprintln(w, `data: {"type":"error","error":{"type":"overloaded_error","message":"private response text"}}`)
			return
		}
		fmt.Fprintln(w, `data: {"type":"message_delta","usage":{"output_tokens":3},"delta":{}}`)
		fmt.Fprintln(w, `data: {"type":"message_delta","usage":{"input_tokens":120,"cache_read_input_tokens":60,"output_tokens":10},"delta":{"stop_reason":"end_turn"}}`)
		fmt.Fprintln(w, `data: {"type":"message_stop"}`)
	}))
	defer srv.Close()
	c := NewClient(ClientConfig{BaseURL: srv.URL, Provider: "anthropic"}).(*httpClient)
	c.backoffFunc = func(context.Context, int, time.Duration) {}
	l := usage.New()
	_, err := c.ChatCompletion(usage.WithLedger(context.Background(), l), ChatRequest{Model: "claude-test"})
	if err != nil {
		t.Fatal(err)
	}
	r := l.Snapshot("completed")
	if r.Total.Attempts != 2 || r.Total.Tokens.PromptTokens != 220 || r.Total.Tokens.CompletionTokens != 11 || r.Total.Tokens.CacheReadTokens != 100 {
		t.Fatalf("stream usage lost or counted twice: %+v", r)
	}
	if r.Requests[0].UsageStatus != "partial" || r.Requests[1].UsageStatus != "reported" || r.Total.Complete {
		t.Fatalf("incomplete stream not identified: %+v", r)
	}
	data, _ := json.Marshal(r)
	if strings.Contains(string(data), "private response text") {
		t.Fatal("response body leaked into usage artifact")
	}
}

func TestReportedUsageDistinguishesZeroMissingAndInvalid(t *testing.T) {
	for _, tt := range []struct{ body, status string }{
		{`{"model":"m"}`, "unknown"},
		{`{"model":"m","usage":{"prompt_tokens":0,"completion_tokens":0}}`, "reported"},
		{`{"model":"m","usage":{"prompt_tokens":12}}`, "partial"},
		{`{"model":"m","usage":{"prompt_tokens":12,"completion_tokens":null}}`, "partial"},
		{`{"model":"m","usage":{"prompt_tokens":12,"completion_tokens":-1}}`, "partial"},
		{`{"model":"m","usage":{"prompt_tokens":12,"completion_tokens":1,"prompt_tokens_details":{"cached_tokens":-1}}}`, "partial"},
	} {
		_, status, model := decodeReportedUsage([]byte(tt.body), "openai")
		if status != tt.status || model != "m" {
			t.Errorf("%s: got %q/%q", tt.body, status, model)
		}
	}
}

func TestUsageRecordsFailedClaudeCLIInvocation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude")
	script := `#!/bin/sh
cat >/dev/null
echo '{"is_error":true,"result":"private failure","usage":{"input_tokens":50,"output_tokens":4,"cache_read_input_tokens":10},"modelUsage":{"claude-test":{}}}'
exit 1
`
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	c, err := NewClaudeCLIClient(ClientConfig{})
	if err != nil {
		t.Fatal(err)
	}
	l := usage.New()
	if _, err = c.ChatCompletion(usage.WithLedger(context.Background(), l), ChatRequest{Model: "claude-test"}); err == nil {
		t.Fatal("expected CLI failure")
	}
	r := l.Snapshot("failed")
	if r.Total.Attempts != 1 || r.Total.Tokens.PromptTokens != 50 || r.Total.Tokens.CacheReadTokens != 10 || r.Requests[0].Transport != "claude_cli" || r.Requests[0].ReportedModel != "claude-test" {
		t.Fatalf("CLI usage lost: %+v", r)
	}
}

func TestCancelledCallDoesNotRecordUnsentAttempts(t *testing.T) {
	l := usage.New()
	ctx, cancel := context.WithCancel(usage.WithLedger(context.Background(), l))
	cancel()
	_, err := NewClient(ClientConfig{BaseURL: "http://unused", Provider: "openai"}).ChatCompletion(ctx, ChatRequest{})
	if err == nil || l.Snapshot("failed").Total.Attempts != 0 {
		t.Fatal("cancelled call was sent or counted")
	}
}

func TestUsageRetainsTokensWhenResponseHasNoChoices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"model":"m","choices":[],"usage":{"prompt_tokens":20,"completion_tokens":5}}`)
	}))
	defer srv.Close()
	l := usage.New()
	c := NewClient(ClientConfig{BaseURL: srv.URL, Provider: "openai"})
	if _, err := c.ChatCompletion(usage.WithLedger(context.Background(), l), ChatRequest{Model: "m"}); err == nil {
		t.Fatal("expected invalid response error")
	}
	r := l.Snapshot("failed")
	if r.Total.Attempts != 1 || r.Total.Tokens.PromptTokens != 20 || r.Total.Tokens.CompletionTokens != 5 {
		t.Fatalf("failed response usage lost: %+v", r)
	}
}
