package cli

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/block/codecrucible/internal/chunk"
	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/llm"
	"github.com/block/codecrucible/internal/sarif"
	"github.com/block/codecrucible/internal/sourceindex"
)

func TestSourceCoverageTracksRetriesAndOmissions(t *testing.T) {
	ix := sourceindex.New(map[string]string{"shared": "s", "good": "g", "retry": "r", "too-large": "x"})
	c := newSourceCoverage(ix)
	c.plan([]chunk.Chunk{{Paths: []string{"shared", "good"}}, {Paths: []string{"shared", "retry"}}})
	doc := sarif.Build(sarif.AnalysisResult{}, nil, sarif.BuilderConfig{})
	c.complete([]string{"shared", "good"}, doc, nil)
	c.complete([]string{"shared", "retry"}, doc, errors.New("overflow"))
	c.plan([]chunk.Chunk{{Paths: []string{"retry"}}})
	c.complete([]string{"retry"}, doc, nil)
	r := c.report()
	if r.Admitted != 4 || r.Planned != 3 || r.Analyzed != 3 || r.RepeatedFiles != 2 || !reflect.DeepEqual(r.Unplanned, []string{"too-large"}) || !reflect.DeepEqual(r.Unanalyzed, []string{"too-large"}) {
		t.Fatalf("wrong coverage: %+v", r)
	}
}

func TestBothAuditContractsReuseSourceIndex(t *testing.T) {
	files := ingest.FileMap{"app.go": "package app\nimport \"example/guard\"\nfunc Handle(value string) { guard.Check(value) }\n", "guard/check.go": "package guard\nfunc Check(value string) { validate(value) }\n"}
	index := sourceindex.New(files)
	doc := sarif.Build(sarif.AnalysisResult{SecurityIssues: []sarif.SecurityIssue{{Issue: "Claim", FilePath: "app.go", StartLine: 3, EndLine: 3, TechnicalDetails: "check input", Severity: 8}}}, sarif.FileMap(files), sarif.BuilderConfig{})
	for _, tc := range []struct {
		name   string
		loader *llm.PromptLoader
	}{{"legacy", llm.NewPromptLoader(os.DirFS("../../prompts/default"))}, {"v2", v2PromptLoader()}} {
		t.Run(tc.name, func(t *testing.T) {
			var prompt string
			client := auditClientFunc(func(_ context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
				for _, m := range req.Messages {
					prompt += m.Content
				}
				return nil, errors.New("fixture stops after prompt capture")
			})
			metadata := &sarif.ScanMetadata{Execution: sarif.ScanExecution{Phases: map[string]sarif.PhaseExecution{}}}
			// A rebuilt index from this smaller FileMap would lose the guard.
			_, _, _, _ = runAuditPhase(context.Background(), doc, "fixture", client, "", config.ModelConfig{Name: "test"}, tc.loader, llm.OutputModeNone, ingest.FileMap{"app.go": files["app.go"]}, .3, nil, "", 0, true, chunk.NewTokenCounter("", nil), metadata, index)
			if !strings.Contains(prompt, "validate(value)") {
				t.Fatalf("%s lost the shared index's guard", tc.name)
			}
			if len(metadata.Execution.SourceBundles) == 0 || metadata.Execution.SourceBundles[0].Fingerprint == "" {
				t.Fatal("audit source bundle not recorded")
			}
		})
	}
}

func TestBundleIdentityIncludesCrossFileContext(t *testing.T) {
	c := chunk.Chunk{XML: "<code />", Paths: []string{"a"}, Manifest: []string{"a", "b"}, Total: 2}
	m := &sarif.ScanMetadata{}
	recordAnalysisBundles(m, []chunk.Chunk{c}, 10000, false)
	c.RelatedSummaries = []string{"b: Check()"}
	recordAnalysisBundles(m, []chunk.Chunk{c}, 10000, false)
	if m.Execution.SourceBundles[0].Fingerprint == m.Execution.SourceBundles[1].Fingerprint {
		t.Fatal("different supplied context has same bundle identity")
	}
}
