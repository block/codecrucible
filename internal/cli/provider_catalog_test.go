package cli

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/llm"
)

// Verify that the YAML migration preserves each service's wire contract.
// Existing tests already cover Cerebras scans and Databricks routing.
func TestYAMLProviderClientAndDiscovery(t *testing.T) {
	for _, tc := range []struct{ name, chatPath, discoveryPath, authHeader string }{
		{"openai", "/v1/chat/completions", "/v1/models", "Authorization"},
		{"google", "/chat/completions", "/models", "Authorization"},
		{"anthropic", "/v1/messages", "/v1/models", "x-api-key"},
		{"ollama", "/v1/chat/completions", "/api/tags", ""},
		{"openai-compat", "/v1/chat/completions", "/v1/models", "Authorization"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := config.LookupProvider(tc.name)
			if !ok {
				t.Fatal("missing provider")
			}
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				authHeader := tc.authHeader
				if tc.name == "openai-compat" && r.Method == http.MethodGet {
					authHeader = ""
				}
				if authHeader == "" {
					if r.Header.Get("Authorization") != "" || r.Header.Get("x-api-key") != "" {
						t.Error("unexpected auth")
					}
				} else {
					want := "test-key"
					if authHeader == "Authorization" {
						want = "Bearer " + want
					}
					if r.Header.Get(authHeader) != want {
						t.Error("wrong authentication header")
					}
				}
				if tc.name == "anthropic" && r.Header.Get("anthropic-version") != "2023-06-01" {
					t.Error("missing Anthropic version")
				}
				if r.Method == http.MethodPost {
					if r.URL.Path != tc.chatPath {
						t.Errorf("chat path=%s, want %s", r.URL.Path, tc.chatPath)
					}
					if tc.name == "anthropic" {
						fmt.Fprint(w, `{"content":[{"type":"text","text":"{}"}],"stop_reason":"end_turn"}`)
					} else {
						fmt.Fprint(w, `{"choices":[{"message":{"content":"{}"},"finish_reason":"stop"}]}`)
					}
				} else {
					if r.URL.Path != tc.discoveryPath {
						t.Errorf("discovery path=%s, want %s", r.URL.Path, tc.discoveryPath)
					}
					if tc.name == "ollama" {
						fmt.Fprint(w, `{"models":[{"name":"fixture"}]}`)
					} else {
						fmt.Fprint(w, `{"data":[{"id":"fixture"}]}`)
					}
				}
			}))
			defer server.Close()
			cfg := &config.Config{AnthropicAPIKey: "test-key", OpenAIAPIKey: "test-key", GoogleAPIKey: "test-key"}
			client, _, err := buildPhaseClient(config.PhaseConfig{Provider: tc.name, APIKey: "test-key", BaseURL: server.URL}, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.ChatCompletion(context.Background(), llm.ChatRequest{Model: "fixture", MaxTokens: 100}); err != nil {
				t.Fatal(err)
			}
			entries, err := listProvider(context.Background(), cfg, p, server.URL)
			if err != nil || len(entries) != 1 || entries[0].Name != "fixture" || calls != 2 {
				t.Fatalf("entries=%v calls=%d err=%v", entries, calls, err)
			}
		})
	}
}
