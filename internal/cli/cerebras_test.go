package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/llm"
)

func TestCerebrasClientContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("incorrect URL or authentication")
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body["model"] != "custom-glm" || body["max_completion_tokens"] != float64(65536) {
			t.Errorf("incorrect model or output limit: %v", body)
		}
		if _, exists := body["max_tokens"]; exists {
			t.Error("legacy max_tokens must not be sent")
		}
		format, ok := body["response_format"].(map[string]any)
		if !ok || format["type"] != "json_schema" {
			t.Error("missing schema enforcement")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"choices":[{"message":{"content":"{}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":20,"total_tokens":120}}`)
	}))
	defer server.Close()
	client, _, err := buildPhaseClient(config.PhaseConfig{Provider: "cerebras", APIKey: "test-key", BaseURL: server.URL + "/"}, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	model := config.ModelConfig{Name: "custom-glm", SupportsStructuredOutput: true}
	for _, schema := range []*json.RawMessage{llm.SecurityAnalysisSchema(), llm.FeatureDetectionSchema(), llm.AuditSchema()} {
		resp, err := client.ChatCompletion(context.Background(), llm.ChatRequest{Model: model.Name, MaxTokens: 65536, ResponseSchema: schema, OutputMode: llm.OutputModeForConfig(model)})
		if err != nil {
			t.Fatal(err)
		}
		if resp.Usage.PromptTokens != 100 || resp.Usage.CompletionTokens != 20 {
			t.Fatal("usage lost")
		}
	}

	for _, params := range []map[string]any{
		{"max_tokens": 65536},
		{"max_tokens": 8192, "max_completion_tokens": 65536},
	} {
		_, err := client.ChatCompletion(context.Background(), llm.ChatRequest{
			Model: model.Name, MaxTokens: 65536,
			ResponseSchema: llm.SecurityAnalysisSchema(), OutputMode: llm.OutputModeForConfig(model),
			ModelParams: params,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := params["max_tokens"]; !ok {
			t.Fatal("request mutated caller params")
		}
	}
}

func TestCerebrasListModels(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" || r.Header.Get("Authorization") != "Bearer test-key" {
			t.Error("incorrect model listing request")
		}
		fmt.Fprint(w, `{"data":[{"id":"custom-glm","owned_by":"Cerebras"}]}`)
	}))
	defer server.Close()
	rows, err := listCerebras(context.Background(), &config.Config{CerebrasAPIKey: "test-key"}, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Usage != "--provider cerebras --model custom-glm" {
		t.Fatalf("incorrect rows: %v", rows)
	}
	if _, err := listCerebras(context.Background(), &config.Config{}, server.URL); err == nil {
		t.Fatal("missing credentials accepted")
	}
	if _, _, err := buildPhaseClient(config.PhaseConfig{Provider: "cerebras"}, &config.Config{}); err == nil {
		t.Fatal("missing credentials accepted")
	}
}

func TestCerebrasScanProducesSARIF(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Error("wrong path")
		}
		content := `{"repo_name":"fixture","description":"fixture","public_api_routes":[],"security_issues":[],"security_risk":0,"risk_justification":"No issues"}`
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": content}, "finish_reason": "stop"}}, "usage": map[string]int{"prompt_tokens": 100, "completion_tokens": 20}})
	}))
	defer server.Close()
	dir := createTestRepo(t)
	output := filepath.Join(t.TempDir(), "result.sarif")
	oldV := v
	t.Cleanup(func() { v = oldV })
	v = viper.New()
	config.SetDefaults(v)
	v.Set("provider", "cerebras")
	v.Set("model", "custom-glm")
	v.Set("cerebras-api-key", "test-key")
	v.Set("base-url", server.URL)
	v.Set("prompts-dir", filepath.Join(dir, "prompts", "default"))
	v.Set("skip-audit", true)
	v.Set("skip-feature-detection", true)
	v.Set("output", output)
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	if err := runScan(cmd, []string{dir}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["version"] != "2.1.0" {
		t.Fatal("invalid SARIF version")
	}
	runs := doc["runs"].([]any)
	if len(runs) != 1 {
		t.Fatal("missing run")
	}
	inv := runs[0].(map[string]any)["invocations"].([]any)[0].(map[string]any)
	if inv["executionSuccessful"] != true {
		t.Fatal("scan did not succeed")
	}
}
