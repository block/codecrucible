package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/sarif"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// A chunk whose answer stops at the output limit is split once. Recovery
// replaces its failure in the final coverage, and both the failed attempt and
// the recovery requests are counted. A half that still exhausts the limit
// stays an execution failure rather than being resent or split again.
func TestAnalysisOutputExhaustionRecovery(t *testing.T) {
	for _, tc := range []struct {
		name      string
		truncated string // the answer that stopped at the limit
		recovers  bool
	}{
		{"recovered", "", true},
		// A cut-off answer that happens to parse is still incomplete.
		{"parseable truncation recovered", `{"security_issues":[]}`, true},
		{"exhausted", "", false},
	} {
		recovers := tc.recovers
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var requests []int // files sent in each request
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					Messages []struct{ Content string }
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				files := 0
				for _, m := range req.Messages {
					files += strings.Count(m.Content, "<file path=")
				}
				mu.Lock()
				requests = append(requests, files)
				initial := len(requests) == 1
				mu.Unlock()
				choice := map[string]any{"message": map[string]any{"content": `{"security_issues":[]}`}, "finish_reason": "stop"}
				if initial || !recovers {
					choice = map[string]any{"message": map[string]any{"content": tc.truncated}, "finish_reason": "length"}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{choice},
					"usage": map[string]int{"prompt_tokens": 100, "completion_tokens": 50}})
			}))
			defer server.Close()

			out := filepath.Join(t.TempDir(), "scan.sarif")
			old := v
			t.Cleanup(func() { v = old })
			v = viper.New()
			config.SetDefaults(v)
			v.Set("provider", "openai")
			v.Set("model", "gpt-5.5")
			v.Set("openai-api-key", "test-key")
			v.Set("base-url", server.URL)
			v.Set("prompts-dir", "../../prompts/default")
			v.Set("skip-feature-detection", true)
			v.Set("output", out)
			cmd := &cobra.Command{}
			cmd.SetContext(context.Background())
			err := runScan(cmd, []string{createTestRepo(t)})
			if (err != nil) == recovers {
				t.Fatalf("scan error = %v", err)
			}

			if len(requests) != 3 || requests[1]+requests[2] != requests[0] || requests[1] == 0 || requests[2] == 0 {
				t.Fatalf("files per request = %v, want one attempt then one per half", requests)
			}
			data, rErr := os.ReadFile(out)
			if rErr != nil {
				t.Fatal(rErr)
			}
			var doc sarif.SARIFDocument
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			m := doc.Runs[0].Properties.CodeCrucible
			chunks := m.Execution.Chunks
			if chunks.Initial != 1 || chunks.OutputExhausted != 1 || chunks.Recovery != 2 {
				t.Fatalf("chunks = %+v", chunks)
			}
			if models := m.Execution.Phases["analysis"].Models; len(models) != 1 || models[0].Calls != 3 || models[0].CompletionTokens != 150 {
				t.Fatalf("analysis usage = %+v, want all three paid attempts", models)
			}
			coverage := m.Execution.SourceCoverage
			if recovers {
				if chunks.Completed != 2 || chunks.Failed != 0 || len(coverage.Unanalyzed) != 0 || scanExecutionError(doc) != nil {
					t.Fatalf("recovery did not supersede the failure: chunks=%+v coverage=%+v", chunks, coverage)
				}
				return
			}
			if chunks.Completed != 0 || chunks.Failed != 2 || len(coverage.Unanalyzed) != requests[0] || m.Execution.Phases["analysis"].Status != "failed" {
				t.Fatalf("exhausted recovery must stay failed: chunks=%+v coverage=%+v", chunks, coverage)
			}
			if !strings.Contains(err.Error(), "finish_reason=length") {
				t.Fatalf("scan error = %v", err)
			}
		})
	}
}
