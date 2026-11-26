package llm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTransientHTTPRetryBudget(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		status, failures, wantCalls int
		retryAfter                  string
		cancel                      bool
	}{
		{name: "queue recovers after old budget", status: 429, failures: 8, wantCalls: 9},
		{name: "queue stays full", status: 429, failures: 100, wantCalls: 9},
		{name: "service unavailable", status: 503, failures: 8, wantCalls: 9},
		{name: "request timeout", status: 408, failures: 8, wantCalls: 9},
		{name: "server delay", status: 429, failures: 8, wantCalls: 9, retryAfter: "45"},
		{name: "permanent error", status: 401, failures: 100, wantCalls: 1},
		{name: "cancel during backoff", status: 429, failures: 100, wantCalls: 1, cancel: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if calls <= tc.failures {
					w.Header().Set("Retry-After", tc.retryAfter)
					w.WriteHeader(tc.status)
					fmt.Fprint(w, `{"code":"queue_exceeded","message":"high traffic"}`)
					return
				}
				fmt.Fprint(w, successResponse("recovered", "test", "stop", 1, 1))
			}))
			defer server.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			client := NewClient(ClientConfig{BaseURL: server.URL, MaxRetries: 3}).(*httpClient)
			var delays []time.Duration
			client.backoffFunc = func(_ context.Context, _ int, delay time.Duration) {
				delays = append(delays, delay)
				if tc.cancel {
					cancel()
				}
			}
			resp, err := client.ChatCompletion(ctx, ChatRequest{})
			if calls != tc.wantCalls {
				t.Fatalf("calls=%d want %d; err=%v", calls, tc.wantCalls, err)
			}
			switch {
			case tc.cancel:
				if !errors.Is(err, context.Canceled) || errors.Is(err, ErrTransientExhausted) {
					t.Fatal(err)
				}
			case tc.status == 401:
				if err == nil || errors.Is(err, ErrTransientExhausted) || len(delays) != 0 {
					t.Fatalf("err=%v delays=%v", err, delays)
				}
			case tc.failures == 100:
				if !errors.Is(err, ErrTransientExhausted) {
					t.Fatal(err)
				}
			default:
				if err != nil || resp.Content != "recovered" {
					t.Fatalf("response=%v err=%v", resp, err)
				}
			}
			if tc.wantCalls != 9 {
				return
			}
			if len(delays) != 8 {
				t.Fatalf("delays=%v", delays)
			}
			var total time.Duration
			for _, delay := range delays {
				if tc.retryAfter != "" && delay != 45*time.Second {
					t.Fatalf("Retry-After overridden: %v", delays)
				}
				total += delay
			}
			if tc.retryAfter == "" && (total < 121*time.Second || total > 151250*time.Millisecond) {
				t.Fatalf("backoff total=%v, want 121s plus at most 25%% jitter", total)
			}
		})
	}
}
