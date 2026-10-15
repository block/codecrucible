package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/llm"
	"github.com/block/codecrucible/internal/sarif"
)

type stubClient struct {
	resp *llm.ChatResponse
	err  error
}

func (s stubClient) ChatCompletion(context.Context, llm.ChatRequest) (*llm.ChatResponse, error) {
	return s.resp, s.err
}

func TestModelUsageTalliesByPhaseAndModel(t *testing.T) {
	usage := newModelUsage()
	priced := config.ModelConfig{InputPricePerM: 2, OutputPricePerM: 8}
	served := &llm.ChatResponse{
		Model: "served-b",
		Usage: llm.TokenUsage{PromptTokens: 1000, CompletionTokens: 500, ReasoningTokens: 100},
		Sent:  &llm.SentRequest{TemperatureOmitted: true, MaxTokensParam: "max_completion_tokens"},
	}
	analysis := usage.wrap("analysis", stubClient{resp: served}, priced)
	req := llm.ChatRequest{Model: "kimi", ModelParams: map[string]any{"model": "deployment-id"}}
	for range 2 {
		if _, err := analysis.ChatCompletion(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}
	other := *served
	other.Model, other.Sent = "served-a", &llm.SentRequest{MaxTokensParam: "max_tokens"}
	_, _ = usage.wrap("analysis", stubClient{resp: &other}, priced).ChatCompletion(context.Background(), req)
	// A fallback to the analysis client is tallied under the phase using it.
	failing := usage.wrap("analysis", stubClient{err: errors.New("unavailable")}, priced)
	audit := usage.wrap("audit", failing, priced)
	if _, err := audit.ChatCompletion(context.Background(), llm.ChatRequest{Endpoint: "serving"}); err == nil {
		t.Fatal("recording must return the client's error")
	}

	m := newScanMetadata(&config.Config{})
	usage.apply(m)
	want := []sarif.ModelExecution{{
		Model: "deployment-id", ResponseModels: []string{"served-a", "served-b"},
		Calls: 3, PromptTokens: 3000, CompletionTokens: 1500, ReasoningTokens: 300,
		EstimatedCost: 3 * priced.EstimateCost(1000, 500), TemperatureOmitted: 2, MaxCompletionTokens: 2,
	}}
	if got := m.Execution.Phases["analysis"].Models; !reflect.DeepEqual(got, want) {
		t.Fatalf("analysis models = %+v, want %+v", got, want)
	}
	wantAudit := []sarif.ModelExecution{{Model: "serving", ResponseModels: []string{}, Calls: 1, Failures: 1}}
	if got := m.Execution.Phases["audit"].Models; !reflect.DeepEqual(got, wantAudit) {
		t.Fatalf("audit models = %+v, want %+v", got, wantAudit)
	}
	// Failed calls served nothing; an ID the provider did not report falls
	// back to the ID sent.
	if got := m.Execution.Models; !reflect.DeepEqual(got, []string{"served-a", "served-b"}) {
		t.Fatalf("run models = %v", got)
	}
	_, _ = usage.wrap("audit", stubClient{resp: &llm.ChatResponse{}}, priced).ChatCompletion(context.Background(), llm.ChatRequest{Model: "unreported"})
	usage.apply(m)
	if got := m.Execution.Models; !reflect.DeepEqual(got, []string{"served-a", "served-b", "unreported"}) {
		t.Fatalf("run models = %v", got)
	}
	var nilUsage *modelUsage
	if client := (stubClient{}); nilUsage.wrap("analysis", client, priced) != client {
		t.Fatal("nil usage must not wrap")
	}
	nilUsage.apply(m)
}

func TestScanMetadataRecordsModelsSent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var wire map[string]any
		_ = json.Unmarshal(body, &wire)
		if wire["model"] != "deployment-id" {
			http.Error(w, "unexpected model", http.StatusNotFound)
			return
		}
		if _, ok := wire["temperature"]; ok {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":{"message":"Unsupported value: 'temperature' does not support 0 with this model.","param":"temperature"}}`)
			return
		}
		content := `{"security_issues":[{"issue":"Reflected XSS","file_path":"src/main.go","start_line":1,"technical_details":"Evidence.","severity":8,"cwe_id":"CWE-79"}]}`
		if strings.Contains(string(body), "audited_findings") {
			content = `{"audited_findings":[{"original_issue":"Reflected XSS","file_path":"src/main.go","start_line":1,"verdict":"confirmed","confidence":0.9,"justification":"Validated chain"}]}`
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model":   "served-model",
			"usage":   map[string]any{"prompt_tokens": 100, "completion_tokens": 10},
			"choices": []any{map[string]any{"message": map[string]any{"content": content}, "finish_reason": "stop"}},
		})
	}))
	defer server.Close()
	dir := createTestRepo(t)
	out := filepath.Join(t.TempDir(), "scan.sarif")
	old := v
	t.Cleanup(func() { v = old })
	v = viper.New()
	config.SetDefaults(v)
	v.Set("provider", "openai")
	v.Set("model", "gpt-5.5")
	v.Set("model-params", map[string]any{"model": "deployment-id"})
	v.Set("openai-api-key", "credential-sentinel")
	v.Set("base-url", server.URL)
	v.Set("prompts-dir", "../../prompts/default")
	v.Set("skip-feature-detection", true)
	v.Set("output", out)
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	if err := runScan(cmd, []string{dir}); err != nil {
		t.Fatal(err)
	}

	read := func(path string) *sarif.ScanMetadata {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc sarif.SARIFDocument
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		return doc.Runs[0].Properties.CodeCrucible
	}
	registered, _ := config.LookupModel("gpt-5.5")
	sent := sarif.ModelExecution{
		Model: "deployment-id", ResponseModels: []string{"served-model"}, Calls: 1, PromptTokens: 100, CompletionTokens: 10,
		EstimatedCost: registered.EstimateCost(100, 10), TemperatureOmitted: 1, MaxCompletionTokens: 1,
	}
	analysis := read(strings.TrimSuffix(out, ".sarif") + ".analysis.sarif")
	if got := analysis.Execution.Phases["analysis"].Models; !reflect.DeepEqual(got, []sarif.ModelExecution{sent}) {
		t.Fatalf("analysis artifact models = %+v", got)
	}
	if got := analysis.Execution.Phases["audit"].Models; got != nil {
		t.Fatalf("audit models recorded before the audit ran: %+v", got)
	}
	final := read(out)
	for _, phase := range []string{"analysis", "audit"} {
		if got := final.Execution.Phases[phase].Models; !reflect.DeepEqual(got, []sarif.ModelExecution{sent}) {
			t.Fatalf("%s models = %+v", phase, got)
		}
	}
	if got := final.Execution.Models; !reflect.DeepEqual(got, []string{"served-model"}) {
		t.Fatalf("run models = %v", got)
	}
}
