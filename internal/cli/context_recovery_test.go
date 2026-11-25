package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/sarif"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func TestTopLevelContextErrorRecoversOnlyFailedAnalysis(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"code":"context_length_exceeded","message":"Current length is 260000 while limit is 250000"}`)
			return
		}
		fmt.Fprint(w, `{"choices":[{"message":{"content":"{\"security_issues\":[]}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5}}`)
	}))
	defer server.Close()
	old := v
	t.Cleanup(func() { v = old })
	v = viper.New()
	config.SetDefaults(v)
	for key, value := range map[string]any{
		"provider": "openai", "model": "gpt-5.5", "openai-api-key": "test",
		"base-url": server.URL, "prompts-dir": "../../prompts/default",
		"skip-feature-detection": true, "skip-audit": true,
	} {
		v.Set(key, value)
	}
	output := filepath.Join(t.TempDir(), "scan.sarif")
	v.Set("output", output)
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	if err := runScan(cmd, []string{createTestRepo(t)}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var doc sarif.SARIFDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	execution := doc.Runs[0].Properties.CodeCrucible.Execution
	if calls.Load() != 2 || execution.Chunks.Overflowed != 1 || execution.Chunks.Recovery != 1 || len(execution.SourceCoverage.Unanalyzed) != 0 {
		t.Fatalf("calls=%d chunks=%+v coverage=%+v", calls.Load(), execution.Chunks, execution.SourceCoverage)
	}
}
