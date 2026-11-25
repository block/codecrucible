package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/llm"
	"github.com/block/codecrucible/internal/sarif"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Enforce the provider's context limit on EVERY request, including recovery.
// An API which accepts everything after the first rejection cannot expose a
// bad retry budget. This models a real 517,967 / 256,000 total-size diagnosis.
func TestReportedContextRecoveryWorkflow(t *testing.T) {
	for _, mode := range []string{"reported", "unknown", "persistent"} {
		t.Run(mode, func(t *testing.T) {
			var mu sync.Mutex
			baseline, calls, rejected, acceptedFiles := 0, 0, 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request struct {
					Messages            []llm.Message `json:"messages"`
					MaxTokens           int           `json:"max_tokens"`
					MaxCompletionTokens int           `json:"max_completion_tokens"`
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
					w.WriteHeader(500)
					return
				}
				var parts []string
				for _, message := range request.Messages {
					parts = append(parts, message.Content)
				}
				content := strings.Join(parts, "\n")
				reserve := max(request.MaxTokens, request.MaxCompletionTokens)
				mu.Lock()
				defer mu.Unlock()
				calls++
				if baseline == 0 {
					baseline = len(content)
				}
				current := reserve + int(math.Round(float64(517967-reserve)*float64(len(content))/float64(baseline)))
				if current > 256000 || mode == "persistent" {
					rejected++
					message := fmt.Sprintf("Current length is %d while limit is 256000", current)
					if mode == "unknown" {
						message = "request exceeds deployment limit"
					}
					w.WriteHeader(400)
					json.NewEncoder(w).Encode(map[string]string{"code": "context_length_exceeded", "message": message})
					return
				}
				acceptedFiles += strings.Count(content, "<file path=")
				fmt.Fprint(w, `{"choices":[{"message":{"content":"{\"security_issues\":[]}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":5}}`)
			}))
			defer server.Close()
			repo := t.TempDir()
			for i := range 24 {
				value := strings.Repeat(fmt.Sprintf("entry%02d_alpha_beta_gamma_delta_", i), 700)[:20000]
				content := fmt.Sprintf("package fixture\nfunc Value%02d() string { return %q }\n", i, value)
				if err := os.WriteFile(filepath.Join(repo, fmt.Sprintf("file%02d.go", i)), []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			old := v
			t.Cleanup(func() { v = old })
			v = viper.New()
			config.SetDefaults(v)
			output := filepath.Join(t.TempDir(), "scan.sarif")
			for key, value := range map[string]any{
				"provider": "openai", "model": "gpt-5.5", "openai-api-key": "test",
				"base-url": server.URL, "prompts-dir": "../../prompts/default",
				"skip-feature-detection": true, "skip-audit": true,
				"context-limit": 250000, "max-output-tokens": 40960,
				"max-cost": 0, "concurrency": 1, "fail-on-incomplete": true, "output": output,
			} {
				v.Set(key, value)
			}
			cmd := &cobra.Command{}
			cmd.SetContext(context.Background())
			scanErr := runScan(cmd, []string{repo})
			data, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			var doc sarif.SARIFDocument
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			execution := doc.Runs[0].Properties.CodeCrucible.Execution
			mu.Lock()
			defer mu.Unlock()
			if execution.Chunks.Initial != 1 || calls != 1+execution.Chunks.Recovery {
				t.Fatalf("must run one bounded recovery round: calls=%d chunks=%+v", calls, execution.Chunks)
			}
			if mode == "reported" {
				if scanErr != nil || rejected != 1 || acceptedFiles != 24 || execution.SourceCoverage.Analyzed != 24 || len(execution.SourceCoverage.Unanalyzed) != 0 {
					t.Fatalf("err=%v rejected=%d accepted=%d coverage=%+v", scanErr, rejected, acceptedFiles, execution.SourceCoverage)
				}
			} else if scanErr == nil || rejected < 2 || len(execution.SourceCoverage.Unanalyzed) == 0 {
				t.Fatalf("failed recovery must remain incomplete: err=%v rejected=%d coverage=%+v", scanErr, rejected, execution.SourceCoverage)
			}
		})
	}
}
