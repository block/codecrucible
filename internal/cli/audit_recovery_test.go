package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/block/codecrucible/internal/chunk"
	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/llm"
	"github.com/block/codecrucible/internal/sarif"
)

type auditClientFunc func(context.Context, llm.ChatRequest) (*llm.ChatResponse, error)

func (f auditClientFunc) ChatCompletion(ctx context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
	return f(ctx, req)
}

func auditFixture() sarif.SARIFDocument {
	return sarif.Build(sarif.AnalysisResult{SecurityIssues: []sarif.SecurityIssue{
		{Issue: "First", FilePath: "a.go", StartLine: 1, TechnicalDetails: "Original first", Summary: "Initial first summary", Severity: 8},
		{Issue: "Second", FilePath: "b.go", StartLine: 1, TechnicalDetails: "Original second", Severity: 8},
	}}, nil, sarif.BuilderConfig{})
}

func auditReply(issue, path string) *llm.ChatResponse {
	data, _ := json.Marshal(AuditResult{AuditedFindings: []AuditedFinding{{
		OriginalIssue: issue, FilePath: path, StartLine: 1, Verdict: "confirmed", Confidence: .9,
		RefinedTechnicalDetails: "Audited " + issue, Summary: "Reviewed " + issue, Remediation: "Validate the input",
		CodePath: []sarif.CodePathStep{{FilePath: path, StartLine: 1, EndLine: 1, Message: "Unsafe operation"}},
	}}})
	return &llm.ChatResponse{Content: string(data), Usage: llm.TokenUsage{PromptTokens: 10, CompletionTokens: 5}}
}

func runFixtureAudit(ctx context.Context, doc sarif.SARIFDocument, client llm.Client) (*sarif.SARIFDocument, llm.TokenUsage, float64, error) {
	return runAuditPhase(ctx, doc, "fixture", client, "", config.ModelConfig{Name: "test", InputPricePerM: 1, OutputPricePerM: 2},
		llm.NewPromptLoader(os.DirFS("../../prompts/default")), llm.OutputModeNone,
		ingest.FileMap{"a.go": "sink()", "b.go": "sink()"}, .3, nil, "", 1, true, chunk.NewTokenCounter("", nil), nil)
}

func TestAuditPartialFailureRetainsFindingsAndCompletedWork(t *testing.T) {
	doc := auditFixture()
	before, _ := json.Marshal(doc)
	calls := 0
	client := auditClientFunc(func(_ context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
		calls++
		if req.Label == "audit 2/2" {
			return nil, errors.New("provider permission denied")
		}
		return auditReply("First", "a.go"), nil
	})
	got, usage, cost, err := runFixtureAudit(context.Background(), doc, client)
	if err == nil || !strings.Contains(err.Error(), "1 of 2 batches") || calls != 2 || got == nil {
		t.Fatalf("calls=%d doc=%v error=%v", calls, got, err)
	}
	if usage.PromptTokens != 10 || usage.CompletionTokens != 5 || cost != .00002 {
		t.Fatalf("usage=%+v cost=%v", usage, cost)
	}
	results := got.Runs[0].Results
	if len(results) != 2 || results[0].Properties.AuditStatus != "confirmed" || results[1].Properties.AuditStatus != "not_audited" ||
		!strings.Contains(results[0].Message.Text, "Audited First") || results[1].Message.Text != "Original second" || len(results[0].CodeFlows) != 1 {
		t.Fatal("lost partial results", results)
	}
	after, _ := json.Marshal(doc)
	if string(before) != string(after) {
		t.Fatal("audit mutated analysis snapshot")
	}
	gotDoc := markAuditIncomplete(*got, err.Error())
	if err := scanExecutionError(gotDoc); err != nil {
		t.Fatal("warning failed scan", err)
	}
	inv := gotDoc.Runs[0].Invocations[0]
	if !inv.ExecutionSuccessful || inv.ToolExecutionNotifications[0].Level != "warning" {
		t.Fatal(inv)
	}
	failed := markInvocationFailed(doc, "analysis failed")
	if scanExecutionError(markAuditIncomplete(failed, "audit incomplete")) == nil {
		t.Fatal("audit warning hid analysis failure")
	}
}

func TestAuditResponseRecoveryAndExhaustion(t *testing.T) {
	for _, tc := range []struct {
		name, bad string
		finish    string
		recover   bool
	}{
		{"malformed recovers", `{"audited_findings":`, "", true},
		{"missing verdict recovers", `{"audited_findings":[]}`, "", true},
		{"missing verdict exhausted", `{}`, "", false},
		{"truncated exhausted", `{"audited_findings":[]}`, "length", false},
		{"unknown verdict exhausted", `{"audited_findings":[{"original_issue":"First","file_path":"a.go","start_line":1,"verdict":"maybe"}]}`, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := auditFixture()
			doc.Runs[0].Results = doc.Runs[0].Results[:1]
			calls := 0
			client := auditClientFunc(func(context.Context, llm.ChatRequest) (*llm.ChatResponse, error) {
				calls++
				if calls == 2 && tc.recover {
					return auditReply("First", "a.go"), nil
				}
				return &llm.ChatResponse{Content: tc.bad, FinishReason: tc.finish, Usage: llm.TokenUsage{PromptTokens: 10, CompletionTokens: 5}}, nil
			})
			got, usage, cost, err := runFixtureAudit(context.Background(), doc, client)
			if calls != 2 || (err == nil) != tc.recover || got == nil {
				t.Fatalf("calls=%d doc=%v error=%v", calls, got, err)
			}
			if usage.PromptTokens != 20 || usage.CompletionTokens != 10 || cost != .00004 {
				t.Fatalf("retry usage=%+v cost=%v", usage, cost)
			}
			if !tc.recover && got.Runs[0].Results[0].Properties.AuditStatus != "not_audited" {
				t.Fatal("failure not marked")
			}
		})
	}
}

func TestAuditTotalTransportFailureAndCancellation(t *testing.T) {
	for _, cancelScan := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelScan), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			client := auditClientFunc(func(context.Context, llm.ChatRequest) (*llm.ChatResponse, error) {
				calls++
				if cancelScan {
					cancel()
					return nil, context.Canceled
				}
				return nil, errors.New("HTTP retries exhausted")
			})
			got, _, _, err := runFixtureAudit(ctx, auditFixture(), client)
			wantCalls := 2
			if cancelScan {
				wantCalls = 1
			}
			if calls != wantCalls || err == nil || got == nil || len(got.Runs[0].Results) != 2 {
				t.Fatalf("calls=%d doc=%v err=%v", calls, got, err)
			}
			if cancelScan && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			for _, result := range got.Runs[0].Results {
				if result.Properties.AuditStatus != "not_audited" {
					t.Fatal(result)
				}
			}
		})
	}
}

func TestAuditRejectsDuplicateOrForeignVerdicts(t *testing.T) {
	expected := map[auditFindingKey]bool{{"a.go", 1, "First"}: true}
	valid := AuditedFinding{OriginalIssue: "First", FilePath: "a.go", StartLine: 1, Verdict: "confirmed", Confidence: .9}
	foreign := valid
	foreign.FilePath = "b.go"
	for _, verdicts := range [][]AuditedFinding{{valid, valid}, {foreign}} {
		if validateAuditCoverage(AuditResult{AuditedFindings: verdicts}, expected) == nil {
			t.Fatal("invalid verdict coverage accepted")
		}
	}
}

func TestAuditIncludesCodePathFilesAndReplacesPath(t *testing.T) {
	files := sarif.FileMap{"a.go": "sink()", "b.go": "request()"}
	path := []sarif.CodePathStep{{FilePath: "b.go", StartLine: 1, EndLine: 1, Message: "Input"}, {FilePath: "a.go", StartLine: 1, EndLine: 1, Message: "Sink"}}
	doc := sarif.Build(sarif.AnalysisResult{SecurityIssues: []sarif.SecurityIssue{{Issue: "First", FilePath: "a.go", StartLine: 1, CodePath: path}}}, files, sarif.BuilderConfig{})
	client := auditClientFunc(func(_ context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
		var prompt string
		for _, m := range req.Messages {
			prompt += m.Content
		}
		if !strings.Contains(prompt, `<file path="b.go">`) || !strings.Contains(prompt, "request()") {
			t.Fatal("audit omitted cross-file path evidence")
		}
		return auditReply("First", "a.go"), nil
	})
	got, _, _, err := runAuditPhase(context.Background(), doc, "fixture", client, "", config.ModelConfig{Name: "test"},
		llm.NewPromptLoader(os.DirFS("../../prompts/default")), llm.OutputModeNone,
		ingest.FileMap(files), .3, nil, "", 1, true, chunk.NewTokenCounter("", nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	steps := got.Runs[0].Results[0].CodeFlows[0].ThreadFlows[0].Locations
	if len(steps) != 1 || steps[0].Location.PhysicalLocation.ArtifactLocation.URI != "a.go" {
		t.Fatal("audit failed to replace analysis path", steps)
	}
	uncertain := applyAuditVerdicts(doc, AuditResult{AuditedFindings: []AuditedFinding{{OriginalIssue: "First", FilePath: "a.go", StartLine: 1, Verdict: "unverified", CodePath: path}}}, ingest.FileMap(files), .3)
	if len(uncertain.Runs[0].Results[0].CodeFlows) != 0 {
		t.Fatal("unverified finding retains asserted code flow")
	}
}
