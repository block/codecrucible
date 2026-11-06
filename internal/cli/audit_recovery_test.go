package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/block/codecrucible/internal/auditcore"
	"github.com/block/codecrucible/internal/chunk"
	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/llm"
	"github.com/block/codecrucible/internal/provenance"
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
		ingest.FileMap{"a.go": "sink()", "b.go": "sink()"}, .3, nil, "", 1, true, chunk.NewTokenCounter("", nil), nil, nil)
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
	expected := []auditClaim{{FindingID: "first", FilePath: "a.go", StartLine: 1, Issue: "First"}}
	valid := AuditedFinding{OriginalIssue: "First", FilePath: "a.go", StartLine: 1, Verdict: "confirmed", Confidence: .9}
	foreign := valid
	foreign.FilePath = "b.go"
	for _, verdicts := range [][]AuditedFinding{{valid, valid}, {foreign}} {
		if accepted, err := acceptLegacyVerdicts(expected, verdicts); err == nil || len(accepted) != 0 {
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
		ingest.FileMap(files), .3, nil, "", 1, true, chunk.NewTokenCounter("", nil), nil, nil)
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

func TestLegacyRetryDeduplicatesAdditions(t *testing.T) {
	var records bytes.Buffer
	ledger := provenance.New("retry", &records)
	calls := 0
	got, _, _, err := runLegacyAuditBatch(context.Background(), []auditClaim{{FindingID: "a"}, {FindingID: "b"}}, "test", config.ModelConfig{}, func(_ []auditClaim, _ string) (*llm.ChatResponse, error) {
		calls++
		id := "a"
		if calls == 2 {
			id = "b"
		}
		data, _ := json.Marshal(AuditResult{AuditedFindings: []AuditedFinding{{FindingID: id, Verdict: "confirmed", Confidence: .9}}, NewFindings: []NewFinding{{Issue: "Unsafe query", FilePath: "a.go", StartLine: 3, CWEID: "CWE-89", Confidence: .9}}})
		producer, e := ledger.BeginRequest("audit", fmt.Sprint(calls), auditcore.Producer{})
		if e != nil {
			return nil, e
		}
		if e = ledger.CompleteRequest(producer, provenance.Exchange{Content: string(data)}); e != nil {
			return nil, e
		}
		return &llm.ChatResponse{Content: string(data), ProducerID: producer.ResponseID}, nil
	})
	journal := &auditJournal{ledger: ledger}
	if e := journal.discardAdditions(got.DiscardedAdditions); e != nil {
		t.Fatal(e)
	}
	if len(got.DiscardedAdditions) != 1 || !strings.Contains(records.String(), `"reason":"duplicate audit addition"`) {
		t.Fatal("duplicate discard missing", records.String())
	}
	if err != nil || calls != 2 || len(got.AuditedFindings) != 2 || len(got.NewFindings) != 1 {
		t.Fatalf("calls=%d additions=%d verdicts=%d err=%v", calls, len(got.NewFindings), len(got.AuditedFindings), err)
	}
}

func TestLegacyAdditionIdentityPreservesDistinctCauses(t *testing.T) {
	base := NewFinding{Issue: "Unsafe query", FilePath: "a.go", StartLine: 3, CWEID: "CWE-89", CodePath: []sarif.CodePathStep{{FilePath: "source.go", StartLine: 1}, {FilePath: "a.go", StartLine: 3}}}
	for _, tc := range []struct {
		name string
		edit func(*NewFinding)
		want int
	}{
		{"CWE", func(f *NewFinding) { f.CWEID = "CWE-943" }, 1},
		{"missing", func(f *NewFinding) { f.CodePath = nil }, 1},
		{"middle", func(f *NewFinding) {
			f.CodePath = []sarif.CodePathStep{base.CodePath[0], {FilePath: "middle.go", StartLine: 2}, base.CodePath[1]}
		}, 1},
		{"source", func(f *NewFinding) {
			f.CodePath = []sarif.CodePathStep{{FilePath: "other.go", StartLine: 1}, base.CodePath[1]}
		}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			other := base
			tc.edit(&other)
			got, _ := deduplicateLegacyAdditions([]NewFinding{base, other})
			if len(got) != tc.want {
				t.Fatalf("got %d want %d", len(got), tc.want)
			}
		})
	}
}

func TestAuditRetryKeepsMaximumConfidenceAddition(t *testing.T) {
	for _, confidences := range [][]float64{{.2, .9}, {.9, .2}} {
		t.Run(fmt.Sprint(confidences), func(t *testing.T) {
			var records bytes.Buffer
			ledger := provenance.New("max-confidence", &records)
			doc := auditFixture()
			if err := ledger.Observe("analysis", &doc); err != nil {
				t.Fatal(err)
			}
			calls := 0
			client := auditClientFunc(func(_ context.Context, _ llm.ChatRequest) (*llm.ChatResponse, error) {
				issue, path := "First", "a.go"
				if calls == 1 {
					issue, path = "Second", "b.go"
				}
				data, _ := json.Marshal(AuditResult{AuditedFindings: []AuditedFinding{{OriginalIssue: issue, FilePath: path, StartLine: 1, Verdict: "confirmed", Confidence: .9}}, NewFindings: []NewFinding{{Issue: "Unsafe query", FilePath: "c.go", StartLine: 1, Severity: 8, Confidence: confidences[calls]}}})
				if confidences[calls] < .9 {
					var response AuditResult
					if err := json.Unmarshal(data, &response); err != nil {
						t.Fatal(err)
					}
					response.NewFindings[0].CodePath = []sarif.CodePathStep{{FilePath: "c.go", StartLine: 1, EndLine: 1, Message: "Unsafe query"}}
					data, _ = json.Marshal(response)
				}
				calls++
				return &llm.ChatResponse{Content: string(data)}, nil
			})
			got, _, _, err := runAuditPhase(context.Background(), doc, "fixture", traceClient(client, ledger, "audit"), "", config.ModelConfig{Name: "test"}, llm.NewPromptLoader(os.DirFS("../../prompts/default")), llm.OutputModeNone, ingest.FileMap{"a.go": "sink()", "b.go": "sink()", "c.go": "sink()"}, .3, nil, "", 20, true, chunk.NewTokenCounter("", nil), nil, nil)
			if err != nil || got == nil {
				t.Fatal(err)
			}
			if !strings.Contains(records.String(), `"reason":"duplicate audit addition"`) {
				t.Fatal("missing wired discard", records.String())
			}
			count := 0
			for _, result := range got.Runs[0].Results {
				if result.Properties.AuditStatus == "new" {
					count++
					if (result.Properties.AuditConfidence == nil || *result.Properties.AuditConfidence != .9) || len(result.Suppressions) != 0 || len(result.CodeFlows) == 0 {
						t.Fatalf("lost high confidence addition: %+v", result)
					}
				}
			}
			if calls != 2 || count != 1 {
				t.Fatalf("calls=%d new=%d", calls, count)
			}
		})
	}
}

func TestAuditBatchesKeepMaximumConfidenceAddition(t *testing.T) {
	for _, confidences := range [][]float64{{.2, .9}, {.9, .2}} {
		t.Run(fmt.Sprint(confidences), func(t *testing.T) {
			var records bytes.Buffer
			ledger := provenance.New("max-confidence", &records)
			doc := auditFixture()
			if err := ledger.Observe("analysis", &doc); err != nil {
				t.Fatal(err)
			}
			calls := 0
			client := auditClientFunc(func(_ context.Context, _ llm.ChatRequest) (*llm.ChatResponse, error) {
				issue, path := "First", "a.go"
				if calls == 1 {
					issue, path = "Second", "b.go"
				}
				data, _ := json.Marshal(AuditResult{AuditedFindings: []AuditedFinding{{OriginalIssue: issue, FilePath: path, StartLine: 1, Verdict: "confirmed", Confidence: .9}}, NewFindings: []NewFinding{{Issue: "Unsafe query", FilePath: "c.go", StartLine: 1, Severity: 8, Confidence: confidences[calls]}}})
				if confidences[calls] < .9 {
					var response AuditResult
					if err := json.Unmarshal(data, &response); err != nil {
						t.Fatal(err)
					}
					response.NewFindings[0].CodePath = []sarif.CodePathStep{{FilePath: "c.go", StartLine: 1, EndLine: 1, Message: "Unsafe query"}}
					data, _ = json.Marshal(response)
				}
				calls++
				return &llm.ChatResponse{Content: string(data)}, nil
			})
			got, _, _, err := runAuditPhase(context.Background(), doc, "fixture", traceClient(client, ledger, "audit"), "", config.ModelConfig{Name: "test"}, llm.NewPromptLoader(os.DirFS("../../prompts/default")), llm.OutputModeNone, ingest.FileMap{"a.go": "sink()", "b.go": "sink()", "c.go": "sink()"}, .3, nil, "", 1, true, chunk.NewTokenCounter("", nil), nil, nil)
			if err != nil || got == nil {
				t.Fatal(err)
			}
			if !strings.Contains(records.String(), `"reason":"duplicate audit addition"`) {
				t.Fatal("missing wired discard", records.String())
			}
			count := 0
			for _, result := range got.Runs[0].Results {
				if result.Properties.AuditStatus == "new" {
					count++
					if (result.Properties.AuditConfidence == nil || *result.Properties.AuditConfidence != .9) || len(result.Suppressions) != 0 || len(result.CodeFlows) == 0 {
						t.Fatalf("lost high confidence addition: %+v", result)
					}
				}
			}
			if calls != 2 || count != 1 {
				t.Fatalf("calls=%d new=%d", calls, count)
			}
		})
	}
}

func TestAuditAdditionDuplicatesAnalysisWithoutRevivingIt(t *testing.T) {
	var records bytes.Buffer
	ledger := provenance.New("original-duplicate", &records)
	doc := auditFixture()
	if err := ledger.Observe("analysis", &doc); err != nil {
		t.Fatal(err)
	}
	calls := 0
	client := auditClientFunc(func(_ context.Context, _ llm.ChatRequest) (*llm.ChatResponse, error) {
		issue, path := "First", "a.go"
		if calls > 0 {
			issue, path = "Second", "b.go"
		}
		verdict := AuditedFinding{OriginalIssue: issue, FilePath: path, StartLine: 1, Verdict: "confirmed", Confidence: .9}
		if calls == 0 {
			verdict.Verdict = "rejected"
			verdict.BlockingCode = "sink()"
		}
		calls++
		data, _ := json.Marshal(AuditResult{AuditedFindings: []AuditedFinding{verdict}, NewFindings: []NewFinding{{Issue: " first ", FilePath: "a.go", StartLine: 1, Severity: 8, Confidence: .9, CodePath: []sarif.CodePathStep{{FilePath: "c.go", StartLine: 1, Message: "source"}, {FilePath: "a.go", StartLine: 1, Message: "sink"}}}}})
		return &llm.ChatResponse{Content: string(data)}, nil
	})
	got, _, _, err := runAuditPhase(context.Background(), doc, "fixture", traceClient(client, ledger, "audit"), "", config.ModelConfig{Name: "test"}, llm.NewPromptLoader(os.DirFS("../../prompts/default")), llm.OutputModeNone, ingest.FileMap{"a.go": "sink()", "b.go": "sink()", "c.go": "source()"}, .3, nil, "", 1, true, chunk.NewTokenCounter("", nil), nil, nil)
	if err != nil || got == nil {
		t.Fatal(err)
	}
	if len(got.Runs[0].Results) != 2 {
		t.Fatalf("duplicate survived: %+v", got.Runs[0].Results)
	}
	first := got.Runs[0].Results[0]
	if first.Properties.AuditStatus != "rejected" || len(first.Suppressions) == 0 || len(first.CodeFlows) == 0 {
		t.Fatalf("lost rejection or evidence: %+v", first)
	}
	if !strings.Contains(records.String(), `"reason":"duplicate of analysis finding"`) {
		t.Fatal("missing analysis discard", records.String())
	}
	if len(doc.Runs[0].Results[0].CodeFlows) != 0 {
		t.Fatal("mutated original snapshot")
	}
}
