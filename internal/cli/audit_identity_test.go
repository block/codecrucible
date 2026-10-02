package cli

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/block/codecrucible/internal/chunk"
	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/llm"
	"github.com/block/codecrucible/internal/sarif"
)

func requestedClaims(t *testing.T, req llm.ChatRequest) []AuditedFinding {
	t.Helper()
	for _, message := range req.Messages {
		if i := strings.Index(message.Content, `{"claims_to_verify":`); i >= 0 {
			var envelope struct {
				Claims []struct {
					ID    string `json:"finding_id"`
					Issue string `json:"issue"`
					Path  string `json:"file_path"`
					Line  int    `json:"start_line"`
				} `json:"claims_to_verify"`
			}
			if err := json.NewDecoder(strings.NewReader(message.Content[i:])).Decode(&envelope); err != nil {
				t.Fatal(err)
			}
			var out []AuditedFinding
			for _, f := range envelope.Claims {
				if f.ID == "" {
					t.Fatal("audit input lacks immutable finding ID")
				}
				out = append(out, AuditedFinding{FindingID: f.ID, OriginalIssue: f.Issue, FilePath: f.Path, StartLine: f.Line, Verdict: "confirmed", Confidence: .9})
			}
			return out
		}
	}
	t.Fatal("audit claims absent from prompt")
	return nil
}
func verdictResponse(findings ...AuditedFinding) *llm.ChatResponse {
	data, _ := json.Marshal(AuditResult{AuditedFindings: findings})
	return &llm.ChatResponse{Content: string(data), Usage: llm.TokenUsage{PromptTokens: 10, CompletionTokens: 5}}
}
func runIdentityAudit(t *testing.T, client llm.Client) (*sarif.SARIFDocument, llm.TokenUsage, error) {
	t.Helper()
	got, usage, _, err := runAuditPhase(context.Background(), auditFixture(), "fixture", client, "", config.ModelConfig{Name: "test"},
		llm.NewPromptLoader(os.DirFS("../../prompts/default")), llm.OutputModeNone,
		ingest.FileMap{"a.go": "first()\nsecond()\n", "b.go": "first()\nsecond()\n"}, .3, nil, "", 2, 1, true, chunk.NewTokenCounter("", nil), nil)
	return got, usage, err
}
func TestAuditIdentitySurvivesLocationRefinement(t *testing.T) {
	calls := 0
	var ids []string
	got, _, err := runIdentityAudit(t, auditClientFunc(func(_ context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
		calls++
		findings := requestedClaims(t, req)
		for i := range findings {
			ids = append(ids, findings[i].FindingID)
			findings[i].StartLine = 2
			findings[i].EndLine = 2
			findings[i].OriginalIssue = "Model reformulated title"
		}
		return verdictResponse(findings...), nil
	}))
	if err != nil || calls != 1 {
		t.Fatalf("calls=%d error=%v", calls, err)
	}
	for i, f := range got.Runs[0].Results {
		if f.Properties.FindingID != ids[i] || f.Properties.AuditStatus != "confirmed" || f.Locations[0].PhysicalLocation.Region.StartLine != 2 {
			t.Fatalf("identity/refinement lost: %+v", f)
		}
	}
}
func TestAuditRetriesOnlyUnresolvedIDs(t *testing.T) {
	for _, kind := range []string{"missing", "duplicate", "invalid", "foreign", "exhausted", "transport"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			pendingID := ""
			got, usage, err := runIdentityAudit(t, auditClientFunc(func(_ context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
				calls++
				findings := requestedClaims(t, req)
				if calls == 1 {
					pendingID = findings[1].FindingID
					switch kind {
					case "duplicate":
						return verdictResponse(findings[0], findings[1], findings[1]), nil
					case "invalid":
						findings[1].Verdict = "maybe"
						return verdictResponse(findings...), nil
					case "foreign":
						findings[1].FindingID = "unknown"
						return verdictResponse(findings...), nil
					default:
						return verdictResponse(findings[0]), nil
					}
				}
				if len(findings) != 1 || findings[0].FindingID != pendingID {
					t.Fatalf("retried resolved findings: %+v", findings)
				}
				if kind == "exhausted" {
					return verdictResponse(), nil
				}
				if kind == "transport" {
					return nil, context.DeadlineExceeded
				}
				return verdictResponse(findings...), nil
			}))
			incomplete := kind == "exhausted" || kind == "transport"
			if (err != nil) != incomplete || calls != 2 || got == nil || len(got.Runs[0].Results) != 2 {
				t.Fatalf("calls=%d err=%v doc=%+v", calls, err, got)
			}
			wantTokens := 20
			if kind == "transport" {
				wantTokens = 10
			}
			if usage.PromptTokens != wantTokens {
				t.Fatalf("usage=%+v", usage)
			}
			if got.Runs[0].Results[0].Properties.AuditStatus != "confirmed" {
				t.Fatal("discarded valid first verdict")
			}
			wantStatus := "confirmed"
			if incomplete {
				wantStatus = "not_audited"
			}
			if got.Runs[0].Results[1].Properties.AuditStatus != wantStatus {
				t.Fatalf("lost unresolved input: %+v", got.Runs[0].Results[1])
			}
		})
	}
}

// Adapt pre-ID fixtures explicitly; production never matches verdicts by location.
func applyFixtureAuditVerdicts(doc sarif.SARIFDocument, audit AuditResult, files ingest.FileMap, threshold float64) sarif.SARIFDocument {
	doc = sarif.WithFindingIDs(doc)
	titles := map[string]string{}
	for _, rule := range doc.Runs[0].Tool.Driver.Rules {
		titles[rule.ID] = rule.ShortDescription.Text
	}
	for i := range audit.AuditedFindings {
		f := &audit.AuditedFindings[i]
		for _, result := range doc.Runs[0].Results {
			if len(result.Locations) == 0 {
				continue
			}
			p := result.Locations[0].PhysicalLocation
			if p.Region != nil && p.ArtifactLocation.URI == f.FilePath && p.Region.StartLine == f.StartLine && titles[result.RuleID] == f.OriginalIssue {
				f.FindingID = result.Properties.FindingID
			}
		}
	}
	return applyAuditVerdicts(doc, audit, files, threshold)
}

func TestAuditMalformedVerdictDoesNotDiscardValidWork(t *testing.T) {
	for _, kind := range []string{"confidence_missing", "confidence_null", "confidence_type", "location_type", "duplicate_malformed"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			got, _, err := runIdentityAudit(t, auditClientFunc(func(_ context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
				calls++
				findings := requestedClaims(t, req)
				if calls == 2 {
					if len(findings) != 1 || findings[0].OriginalIssue != "Second" {
						t.Fatal("retried validated first verdict")
					}
					return verdictResponse(), nil
				}
				data, _ := json.Marshal(findings)
				var rows []map[string]any
				if err := json.Unmarshal(data, &rows); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "confidence_missing":
					delete(rows[1], "confidence")
				case "confidence_null":
					rows[1]["confidence"] = nil
				case "confidence_type":
					rows[1]["confidence"] = "certain"
				case "location_type":
					rows[1]["start_line"] = "one"
				case "duplicate_malformed":
					duplicate := map[string]any{"finding_id": findings[1].FindingID, "confidence": "invalid"}
					rows = append(rows, duplicate)
				}
				content, _ := json.Marshal(map[string]any{"audited_findings": rows})
				return &llm.ChatResponse{Content: string(content)}, nil
			}))
			if err == nil || calls != 2 || got == nil || len(got.Runs[0].Results) != 2 {
				t.Fatalf("invalid verdict caused loss: calls=%d err=%v doc=%+v", calls, err, got)
			}
			results := got.Runs[0].Results
			if results[0].Properties.AuditStatus != "confirmed" || results[1].Properties.AuditStatus != "not_audited" {
				t.Fatal("failed to preserve per-finding outcomes")
			}
		})
	}
}

func TestAuditInvalidLocationRefinementRetainsOriginal(t *testing.T) {
	got, _, err := runIdentityAudit(t, auditClientFunc(func(_ context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
		findings := requestedClaims(t, req)
		findings[0].FilePath = "missing.go"
		findings[1].StartLine = 999
		return verdictResponse(findings...), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	for i, f := range got.Runs[0].Results {
		original := auditFixture().Runs[0].Results[i].Locations[0].PhysicalLocation
		actual := f.Locations[0].PhysicalLocation
		if actual.ArtifactLocation.URI != original.ArtifactLocation.URI || actual.Region.StartLine != original.Region.StartLine || f.Properties.AuditStatus != "confirmed" {
			t.Fatal("invalid refinement changed the finding")
		}
	}
}
