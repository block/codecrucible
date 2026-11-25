package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/sarif"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func TestScanInputBudgetRetainsPartialResults(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		content := `{"security_issues":[{"issue":"XSS","file_path":"src/main.go","start_line":1,"severity":8,"cwe_id":"CWE-79"}]}`
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": content}, "finish_reason": "stop"}}, "usage": map[string]int{"prompt_tokens": 10, "completion_tokens": 5}})
	}))
	defer server.Close()
	old := v
	t.Cleanup(func() { v = old })
	v = viper.New()
	config.SetDefaults(v)
	output := filepath.Join(t.TempDir(), "scan.sarif")
	for key, value := range map[string]any{"provider": "openai", "model": "unpriced-test-model", "context-limit": 32000, "max-output-tokens": 1000, "openai-api-key": "test", "base-url": server.URL, "prompts-dir": "../../prompts/default", "skip-feature-detection": true, "max-cost": 0, "max-input-tokens": 10, "output": output} {
		v.Set(key, value)
	}
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	err := runScan(cmd, []string{createTestRepo(t)})
	if err == nil || !strings.Contains(err.Error(), "input token budget exhausted") {
		t.Fatalf("error=%v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("budget allowed %d provider calls", calls.Load())
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var doc sarif.SARIFDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	m := doc.Runs[0].Properties.CodeCrucible
	if len(doc.Runs[0].Results) != 1 || doc.Runs[0].Invocations[0].ExecutionSuccessful || m.Execution.InputTokens != 10 || !m.Execution.InputTokenBudgetExhausted {
		t.Fatalf("partial output lost: %+v", m.Execution)
	}
	if m.Recipe.Controls.MaxInputTokens != 10 {
		t.Fatal("budget missing from recipe")
	}
}

func TestNegativeTokenBudgetRejected(t *testing.T) {
	settings := viper.New()
	config.SetDefaults(settings)
	settings.Set("max-input-tokens", -1)
	if _, err := config.Load(settings); err == nil {
		t.Fatal(fmt.Sprint("negative budget accepted"))
	}
}
