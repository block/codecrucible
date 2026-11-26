package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/block/codecrucible/internal/chunk"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/llm"
	"github.com/block/codecrucible/internal/sourceindex"
)

func TestAnalysisTransientRecovery(t *testing.T) {
	for _, tc := range []struct {
		name       string
		firstErr   error
		persistent bool
		wantCalls  int
	}{
		{"recovers unsplit", llm.ErrTransientExhausted, false, 2},
		{"persistent failure", llm.ErrTransientExhausted, true, 2},
		{"permanent failure", errors.New("unauthorized"), true, 1},
		{"cancellation", context.Canceled, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := resolvedMetadataConfig(t)
			cfg.SkipFeatureDetection = true
			metadata := newScanMetadata(cfg)
			setPhaseStatus(metadata, "audit", "skipped", "test")
			loader, err := resolvePromptLoader("../../prompts/default")
			if err != nil {
				t.Fatal(err)
			}
			schema, _ := contractSchemas("")
			files := ingest.FileMap{"a.go": "package a\nfunc A() {}", "b.go": "package a\nfunc B() {}"}
			xml := chunk.BuildFileXML("a.go", files["a.go"]) + chunk.BuildFileXML("b.go", files["b.go"])
			counter := chunk.NewTokenCounter(cfg.Phases.Analysis.ModelCfg.Encoding, slog.Default())
			calls := 0
			client := auditClientFunc(func(_ context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
				calls++
				content := ""
				for _, m := range req.Messages {
					content += m.Content
				}
				if strings.Count(content, "<file path=") != 2 || !strings.Contains(content, chunk.BuildFileXML("a.go", files["a.go"])) || !strings.Contains(content, chunk.BuildFileXML("b.go", files["b.go"])) {
					t.Errorf("attempt %d did not retain both source files", calls)
				}
				if calls == 1 || tc.persistent {
					return nil, fmt.Errorf("wrapped client error: %w", tc.firstErr)
				}
				return &llm.ChatResponse{Content: `{"security_issues":[]}`, FinishReason: "stop", Usage: llm.TokenUsage{PromptTokens: 10, CompletionTokens: 5}}, nil
			})
			out, err := runAnalysisPhases(context.Background(), analysisInputs{
				cfg: cfg, analysis: &cfg.Phases.Analysis, client: client, promptLoader: loader,
				schema: schema, outputMode: llm.OutputModeForConfig(cfg.Phases.Analysis.ModelCfg),
				repoName: "fixture", counter: counter, metadata: metadata, source: sourceindex.New(files),
				flatResult: &ingest.FlattenResult{FileMap: files, XML: xml}, totalTokens: counter.Count(xml),
			})
			if err != nil {
				t.Fatal(err)
			}
			chunks, coverage := metadata.Execution.Chunks, metadata.Execution.SourceCoverage
			if calls != tc.wantCalls || chunks.Initial != 1 || chunks.Recovery != tc.wantCalls-1 {
				t.Fatalf("calls=%d chunks=%+v", calls, chunks)
			}
			completeErr := scanCompletenessError(out.doc, metadata)
			if tc.persistent {
				if chunks.Failed != 1 || chunks.Completed != 0 || len(coverage.Unanalyzed) != 2 || !errors.Is(completeErr, ErrIncompleteScan) {
					t.Fatalf("failure hidden: chunks=%+v coverage=%+v err=%v", chunks, coverage, completeErr)
				}
			} else if chunks.Failed != 0 || chunks.Completed != 1 || coverage.Analyzed != 2 || len(coverage.Unanalyzed) != 0 || completeErr != nil || out.usage.PromptTokens != 10 {
				t.Fatalf("recovery incomplete: chunks=%+v coverage=%+v usage=%+v err=%v", chunks, coverage, out.usage, completeErr)
			}
		})
	}
}
