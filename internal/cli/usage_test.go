package cli

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/block/codecrucible/internal/sarif"
	"github.com/block/codecrucible/internal/usage"
)

// Exercise real clients through the CLI: optional pre-passes, paid malformed
// output, repair calls, context-limit recovery, and a wholly failed audit.
func TestScanUsageIncludesEveryPhaseAndSurvivesAuditFailure(t *testing.T) {
	oldV := v
	t.Cleanup(func() { v = oldV })
	var mu sync.Mutex
	calls := map[string]int{}
	overflowed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Model    string `json:"model"`
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		calls[req.Model]++
		failContext := req.Model == "usage-analysis" && !overflowed
		if failContext {
			overflowed = true
		}
		mu.Unlock()
		if failContext {
			w.WriteHeader(400)
			fmt.Fprint(w, `{"error":{"code":"context_length_exceeded"}}`)
			return
		}
		content := "not JSON"
		switch req.Model {
		case "usage-compress":
			content = "Authentication requires a trusted identity."
		case "usage-fd":
			content = `{"detected_features":["authentication"]}`
		case "usage-analysis":
			if len(req.Messages) > 0 && strings.HasPrefix(req.Messages[0].Content, "The following output failed to parse") {
				content = `{"security_issues":[{"issue":"Missing authorization","file_path":"src/main.go","start_line":3,"end_line":3,"severity":8,"cwe_id":"CWE-862","technical_details":"A caller can access a resource without an ownership check."}],"public_api_routes":[]}`
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"model": req.Model, "choices": []any{map[string]any{"message": map[string]any{"content": content}, "finish_reason": "stop"}}, "usage": map[string]int{"prompt_tokens": 10, "completion_tokens": 2}})
	}))
	defer srv.Close()
	dir := createTestRepo(t)
	for i := 0; i < 8; i++ {
		content := "package main\n" + strings.Repeat("func handler() { println(\"example security input\") }\n", 200)
		if err := os.WriteFile(filepath.Join(dir, "src", fmt.Sprintf("source%d.go", i)), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	docPath := filepath.Join(t.TempDir(), "context.txt")
	if err := os.WriteFile(docPath, []byte(strings.Repeat("Authentication and authorization constraints. ", 2000)), 0600); err != nil {
		t.Fatal(err)
	}
	prompts, err := filepath.Abs("../../prompts/default")
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "usage.yaml")
	cfg := fmt.Sprintf("provider: openai\nmodel: usage-analysis\nbase-url: %s\nopenai-api-key: test-key\ncontext-limit: 16000\nmax-output-tokens: 128\ncontext-budget-pct: 5\nphases:\n  feature-detection:\n    model: usage-fd\n  context-compress:\n    model: usage-compress\n  audit:\n    model: usage-audit\ncontext-sources:\n  - name: design\n    type: path\n    location: %s\n    compress: true\nmodels:\n", srv.URL, docPath)
	for _, model := range []string{"usage-analysis", "usage-fd", "usage-compress", "usage-audit"} {
		cfg += fmt.Sprintf("  - name: %s\n    input_price_per_million: 2\n    output_price_per_million: 10\n    context_limit: 16000\n    max_output_tokens: 128\n", model)
	}
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"OPENAI_API_KEY", "DATABRICKS_HOST", "DATABRICKS_TOKEN"} {
		t.Setenv(key, "")
	}
	out := filepath.Join(t.TempDir(), "scan.sarif")
	cmd := NewRootCommand()
	cmd.SetArgs([]string{"--config", cfgPath, "scan", dir, "--prompts-dir", prompts, "--output", out, "--max-cost", "0", "--concurrency", "2"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("incomplete audit should continue: %v", err)
	}
	data, err := os.ReadFile(strings.TrimSuffix(out, ".sarif") + ".usage.json")
	if err != nil {
		t.Fatal(err)
	}
	var report usage.Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "completed" || report.SchemaVersion != 1 || report.RunID == "" || report.Total.Complete {
		t.Fatalf("bad report: %+v", report)
	}
	// The standalone SARIF must preserve every measured attempt, including failed
	// calls and repairs, without allocating batch tokens to individual findings.
	var analysisAttempts int
	for _, stage := range []string{"analysis", "audit", "final"} {
		path := strings.TrimSuffix(out, ".sarif") + "." + stage + ".sarif"
		if stage == "final" {
			path = out
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc sarif.SARIFDocument
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		got := doc.Runs[0].Properties.CodeCrucible.Execution.Usage
		if got == nil || got.RunID != report.RunID {
			t.Fatal("missing run usage", stage)
		}
		if stage == "analysis" {
			analysisAttempts = got.Total.Attempts
			if got.Phases["audit"].Attempts != 0 || got.Status != "in_progress" {
				t.Fatal("analysis snapshot contains future usage")
			}
		} else if !reflect.DeepEqual(got.Total, report.Total) || !reflect.DeepEqual(got.Requests, report.Requests) {
			t.Fatal("SARIF usage differs from sidecar", stage)
		}
	}
	if analysisAttempts >= report.Total.Attempts {
		t.Fatal("audit attempts missing")
	}

	total := 0
	mu.Lock()
	for model, count := range calls {
		total += count
		if count == 0 {
			t.Errorf("no requests for %s", model)
		}
	}
	mu.Unlock()
	if report.Total.Attempts != total || report.Total.UnknownUsageAttempts != 1 || report.Total.Tokens.PromptTokens != (total-1)*10 || math.Abs(report.Total.KnownCostUSD-float64(total-1)*0.00004) > 1e-10 {
		t.Fatalf("requests do not reconcile: calls=%v report=%+v", calls, report.Total)
	}
	for _, phase := range []string{"analysis", "audit", "feature-detection", "context-compress"} {
		if report.Phases[phase].Attempts == 0 {
			t.Errorf("missing phase %s", phase)
		}
	}
	repair, recovery := false, false
	for _, r := range report.Requests {
		repair = repair || strings.HasSuffix(r.Purpose, " repair")
		recovery = recovery || r.FallbackReason == "context_length_recovery"
	}
	if !repair || !recovery {
		t.Fatalf("missing repair/recovery: repair=%v recovery=%v", repair, recovery)
	}
	if strings.Contains(string(data), "test-key") || strings.Contains(string(data), "trusted identity") {
		t.Fatal("credential or content in usage artifact")
	}
	if info, err := os.Stat(strings.TrimSuffix(out, ".sarif") + ".usage.json"); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("usage artifact permissions: %v %v", info, err)
	}
}
