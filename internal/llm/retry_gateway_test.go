package llm

import (
	"context"
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

func TestGatewayRetryClassification(t *testing.T) {
	for _, tc := range []struct {
		name, contentType, body     string
		status, failures, wantCalls int
		wantError                   bool
	}{
		{"html forbidden recovers", "text/html", "<!DOCTYPE html>\n<html>Gateway unavailable</html>", 403, 1, 2, false},
		{"sniff html forbidden", "text/plain", " \n<!DOCTYPE HTML><html>Blocked</html>", 403, 1, 2, false},
		{"html forbidden exhausts", "text/html", "<html>Blocked</html>", 403, 10, 4, true},
		{"json forbidden permanent", "application/json", `{"error":{"message":"permission denied"}}`, 403, 1, 1, true},
		{"mislabeled json permanent", "text/html", `{"error":{"message":"permission denied"}}`, 403, 1, 1, true},
		{"plain forbidden permanent", "text/plain", "permission denied", 403, 1, 1, true},
		{"unauthorized permanent", "text/html", "<html>Unauthorized</html>", 401, 1, 1, true},
		{"timeout recovers", "text/plain", "request timeout", 408, 1, 2, false},
		{"rate limit recovers", "application/json", `{"error":"rate limited"}`, 429, 1, 2, false},
		{"internal server error recovers", "application/json", `{"error":"internal error"}`, 500, 1, 2, false},
		{"bad gateway recovers", "text/html", "<html>Bad Gateway</html>", 502, 1, 2, false},
		{"service unavailable recovers", "application/json", `{"error":"temporarily unavailable"}`, 503, 1, 2, false},
		{"gateway timeout recovers", "text/plain", "gateway timeout", 504, 1, 2, false},
		{"service unavailable exhausts", "text/plain", "service unavailable", 503, 10, 4, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if int(calls.Add(1)) <= tc.failures {
					w.Header().Set("Content-Type", tc.contentType)
					w.Header().Set("Server", "cloudflare")
					w.Header().Set("Retry-After", "3")
					w.WriteHeader(tc.status)
					fmt.Fprint(w, tc.body)
					return
				}
				fmt.Fprint(w, successResponse("recovered", "test", "stop", 10, 5))
			}))
			defer server.Close()
			client := NewClient(ClientConfig{BaseURL: server.URL, MaxRetries: 3}).(*httpClient)
			var delays []time.Duration
			client.backoffFunc = func(_ context.Context, _ int, delay time.Duration) { delays = append(delays, delay) }
			resp, err := client.ChatCompletion(context.Background(), ChatRequest{Label: "audit 20/22"})
			if (err != nil) != tc.wantError || int(calls.Load()) != tc.wantCalls {
				t.Fatalf("calls=%d error=%v; want calls=%d error=%v", calls.Load(), err, tc.wantCalls, tc.wantError)
			}
			if !tc.wantError && resp.Content != "recovered" {
				t.Fatal(resp)
			}
			if len(delays) != tc.wantCalls-1 {
				t.Fatal("incorrect backoff count", delays)
			}
			for _, delay := range delays {
				if delay != 3*time.Second {
					t.Fatal("Retry-After not respected", delay)
				}
			}
			if tc.failures == 10 && !strings.Contains(err.Error(), "exhausted 3 retries") {
				t.Fatal(err)
			}
		})
	}
}

func TestGatewayRetryCancellation(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(403)
		fmt.Fprint(w, "<html>Gateway blocked</html>")
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := NewClient(ClientConfig{BaseURL: server.URL}).(*httpClient)
	client.backoffFunc = func(context.Context, int, time.Duration) { cancel() }
	_, err := client.ChatCompletion(ctx, ChatRequest{})
	if !errors.Is(err, context.Canceled) || calls.Load() != 1 {
		t.Fatalf("calls=%d error=%v", calls.Load(), err)
	}
}

type retryRoundTripper func(*http.Request) (*http.Response, error)

func (f retryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type interruptedResponseBody struct{}

func (interruptedResponseBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (interruptedResponseBody) Close() error             { return nil }

func TestRetryTransportAndInterruptedBody(t *testing.T) {
	for _, failure := range []string{"connection lost", "request timeout", "body interrupted"} {
		t.Run(failure, func(t *testing.T) {
			calls := 0
			client := NewClient(ClientConfig{BaseURL: "https://provider.invalid"}).(*httpClient)
			client.backoffFunc = func(context.Context, int, time.Duration) {}
			client.client.Transport = retryRoundTripper(func(*http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					switch failure {
					case "connection lost":
						return nil, io.EOF
					case "request timeout":
						return nil, context.DeadlineExceeded
					default:
						return &http.Response{StatusCode: 200, Header: make(http.Header), Body: interruptedResponseBody{}}, nil
					}
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(successResponse("recovered", "test", "stop", 1, 1)))}, nil
			})
			response, err := client.ChatCompletion(context.Background(), ChatRequest{})
			if err != nil || calls != 2 || response.Content != "recovered" {
				t.Fatalf("calls=%d response=%v error=%v", calls, response, err)
			}
		})
	}
}
