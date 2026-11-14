package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/sarif"
)

func writeProviderFixture(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func executeProviderCommand(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := NewRootCommand()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

func TestYAMLOnlyProviderDiscoveryAndScan(t *testing.T) {
	getCalls, postCalls := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer yaml-test-key" || r.Header.Get("X-Provider-Version") != "2026-11" {
			t.Error("provider authentication or headers not applied")
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /gateway/models":
			getCalls++
			fmt.Fprint(w, `{"data":[{"id":"deployment-42"}]}`)
		case "POST /gateway/chat/completions":
			postCalls++
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body["model"] != "deployment-42" || body["max_completion_tokens"] != float64(2048) {
				t.Errorf("incorrect request: %+v", body)
			}
			if _, ok := body["max_tokens"]; ok {
				t.Error("wrong output token field")
			}
			if _, ok := body["temperature"]; ok {
				t.Error("model omit_temperature ignored")
			}
			if _, ok := body["response_format"]; !ok {
				t.Error("model capabilities ignored")
			}
			content := `{"repo_name":"fixture","description":"fixture","public_api_routes":[],"security_issues":[],"security_risk":0,"risk_justification":"No issues"}`
			_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": content}, "finish_reason": "stop"}}, "usage": map[string]int{"prompt_tokens": 100, "completion_tokens": 20}})
		default:
			http.Error(w, "unexpected path", 404)
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	t.Setenv("YAML_ONLY_TEST_KEY", "yaml-test-key")
	dir := t.TempDir()
	provider := writeProviderFixture(t, dir, "provider.yaml", fmt.Sprintf(`schema_version: 1
name: yaml-only
protocol: openai-chat
base_url: %s/gateway
auth:
  type: bearer
  api_key_env: YAML_ONLY_TEST_KEY
headers:
  X-Provider-Version: "2026-11"
request:
  path: /chat/completions
  max_tokens_field: max_completion_tokens
discovery:
  format: openai-models
  path: /models
models:
  - name: review-v1
    request_model: deployment-42
    aliases: [reviewer]
    context_limit: 64000
    max_output_tokens: 4096
    omit_temperature: true
    supports_structured_output: true
    input_price_per_million: 1
    output_price_per_million: 2
`, server.URL))
	patch := writeProviderFixture(t, dir, "patch.yaml", "schema_version: 1\nname: yaml-only\nmodels: [{name: review-v1, max_output_tokens: 2048}]\n")
	cfg := writeProviderFixture(t, dir, "config.yaml", "provider: yaml-only\nmodel: reviewer\nprovider-files: [missing-on-purpose.yaml]\n")
	cwd, _ := os.Getwd()
	relative, err := filepath.Rel(cwd, provider)
	if err != nil {
		t.Fatal(err)
	}
	// Flags override the config list and remain relative to the working directory.
	baseArgs := []string{"--config", cfg, "--provider-file", relative, "--provider-file", patch}
	run := func(args ...string) string {
		t.Helper()
		out, err := executeProviderCommand(t, append(append([]string{}, baseArgs...), args...)...)
		if err != nil {
			t.Fatalf("command %v: %v\n%s", args, err, out)
		}
		return out
	}
	if out := run("validate-providers"); !strings.Contains(out, "Valid: 8 providers") {
		t.Fatal(out)
	}
	if out := run("list-providers"); !strings.Contains(out, "yaml-only") || !strings.Contains(out, "YAML_ONLY_TEST_KEY") {
		t.Fatal(out)
	}
	if out := run("list-models", "--registered"); !strings.Contains(out, "deployment-42") || !strings.Contains(out, "2048") {
		t.Fatal(out)
	}
	if getCalls != 0 || postCalls != 0 {
		t.Fatal("offline commands contacted API")
	}
	if out := run("list-models"); !strings.Contains(out, "--provider yaml-only --model deployment-42") {
		t.Fatal(out)
	}
	repo := createTestRepo(t)
	output := filepath.Join(t.TempDir(), "results.sarif")
	run("scan", repo, "--prompts-dir", filepath.Join(repo, "prompts", "default"), "--skip-audit", "--skip-feature-detection", "--output", output)
	if getCalls != 1 || postCalls != 1 {
		t.Fatalf("expected discovery and scan: GET=%d POST=%d", getCalls, postCalls)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("yaml-test-key")) {
		t.Fatal("credential leaked to output")
	}
	var doc sarif.SARIFDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	recipe := doc.Runs[0].Properties.CodeCrucible.Recipe.Phases["analysis"]
	if recipe.Provider != "yaml-only" || recipe.Model != "deployment-42" || recipe.Protocol != "openai-chat" || recipe.RequestPath != "/chat/completions" || recipe.MaxOutputTokens != 2048 || !recipe.UseMaxCompletionTokens || recipe.ProviderFingerprint == "" {
		t.Fatalf("metadata differs from actual request: %+v", recipe)
	}
}

func TestCatalogDiscoveryFormats(t *testing.T) {
	for _, tc := range []struct{ name, path, header, value, body, model string }{
		{"openai", "/v1/models", "Authorization", "Bearer test-key", `{"data":[{"id":"example"}]}`, "example"},
		{"anthropic", "/v1/models", "x-api-key", "test-key", `{"data":[{"id":"example","display_name":"Example"}]}`, "example"},
		{"google", "/models", "Authorization", "Bearer test-key", `{"data":[{"id":"example"}]}`, "example"},
		{"ollama", "/api/tags", "", "", `{"models":[{"name":"example:latest"}]}`, "example:latest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tc.path {
					t.Errorf("path=%s", r.URL.Path)
				}
				if tc.header != "" && r.Header.Get(tc.header) != tc.value {
					t.Error("wrong auth")
				}
				if tc.name == "anthropic" && r.Header.Get("anthropic-version") != "2023-06-01" {
					t.Error("missing version header")
				}
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			p, _ := config.BuiltinRegistry().Provider(tc.name)
			cfg := &config.Config{AnthropicAPIKey: "test-key", OpenAIAPIKey: "test-key", GoogleAPIKey: "test-key"}
			rows, err := listProvider(context.Background(), cfg, p, server.URL)
			if err != nil || len(rows) != 1 || rows[0].Name != tc.model {
				t.Fatalf("rows=%+v err=%v", rows, err)
			}
		})
	}
}

func TestValidateProvidersFailsBeforeNetwork(t *testing.T) {
	dir := t.TempDir()
	cfg := writeProviderFixture(t, dir, "config.yaml", "# isolated\n")
	path := writeProviderFixture(t, dir, "broken.yaml", "schema_version: 1\nname: openai\nprotocol: unsupported\n")
	out, err := executeProviderCommand(t, "--config", cfg, "--provider-file", path, "validate-providers")
	if err == nil || !strings.Contains(err.Error(), "unsupported protocol") {
		t.Fatalf("err=%v output=%s", err, out)
	}
}
