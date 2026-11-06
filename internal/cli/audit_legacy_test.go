package cli

import (
	"context"
	"encoding/json"
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
)

func legacyResponse(findings ...AuditedFinding) *llm.ChatResponse {
	data, _ := json.Marshal(AuditResult{AuditedFindings: findings})
	return &llm.ChatResponse{Content: string(data), Usage: llm.TokenUsage{PromptTokens: 10, CompletionTokens: 5}}
}

func runLegacyFixture(doc sarif.SARIFDocument, client llm.Client) (*sarif.SARIFDocument, llm.TokenUsage, float64, error) {
	return runAuditPhase(context.Background(), doc, "fixture", client, "", config.ModelConfig{Name: "test", InputPricePerM: 1, OutputPricePerM: 2},
		llm.NewPromptLoader(os.DirFS("../../prompts/default")), llm.OutputModeNone,
		ingest.FileMap{"a.go": "input()\nsink()", "b.go": "input()\nsink()"}, .3, nil, "", 2, true, chunk.NewTokenCounter("", nil), nil, nil)
}

func TestLegacyAuditMatchesStableIDsWithRefinedEvidence(t *testing.T) {
	doc := sarif.AssignFindingIDs(auditFixture())
	before, _ := json.Marshal(doc)
	ids := auditFindingIDs(doc.Runs[0].Results)
	calls := 0
	client := auditClientFunc(func(_ context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
		calls++
		if got := claimIDs(t, req); !reflect.DeepEqual(got, ids) {
			t.Fatalf("claim IDs = %v, want %v", got, ids)
		}
		if !strings.Contains(req.Messages[1].Content, "1| input()\n2| sink()") || !strings.Contains(req.Messages[0].Content, "copying its finding_id exactly") {
			t.Fatal("request lost numbered source or stable-ID instructions")
		}
		// Reverse order while preserving the immutable original claim fields.
		original := auditClaims(doc)
		return legacyResponse(
			AuditedFinding{FindingID: ids[1], OriginalIssue: original[1].Issue, FilePath: original[1].FilePath, StartLine: original[1].StartLine, RefinedTechnicalDetails: "Refined second evidence", Verdict: "unverified", Confidence: .2},
			AuditedFinding{FindingID: ids[0], OriginalIssue: original[0].Issue, FilePath: original[0].FilePath, StartLine: original[0].StartLine, RefinedTechnicalDetails: "Refined first evidence", Verdict: "confirmed", Confidence: .9},
		), nil
	})
	got, _, _, err := runLegacyFixture(doc, client)
	if err != nil || calls != 1 {
		t.Fatalf("calls=%d error=%v", calls, err)
	}
	results := got.Runs[0].Results
	if len(results) != 2 || results[0].Properties.AuditStatus != "confirmed" || results[1].Properties.AuditStatus != "unverified" {
		t.Fatalf("verdicts applied to wrong findings: %+v", results)
	}
	if !reflect.DeepEqual(auditFindingIDs(results), ids) || !reflect.DeepEqual(results[0].Locations, doc.Runs[0].Results[0].Locations) {
		t.Fatal("audit changed original finding identity or location")
	}
	after, _ := json.Marshal(doc)
	if string(before) != string(after) {
		t.Fatal("audit mutated the input document")
	}
}

func TestLegacyAuditRetainsValidVerdictsWhileRetryingOnlyMissingClaims(t *testing.T) {
	for _, outcome := range []string{"recovers", "invalid", "transport"} {
		t.Run(outcome, func(t *testing.T) {
			doc := sarif.AssignFindingIDs(auditFixture())
			ids := auditFindingIDs(doc.Runs[0].Results)
			calls := 0
			client := auditClientFunc(func(_ context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
				calls++
				if calls == 1 {
					return legacyResponse(AuditedFinding{FindingID: ids[0], Verdict: "confirmed", Confidence: .9},
						AuditedFinding{FindingID: ids[1], Verdict: "invalid"}), nil
				}
				if got := claimIDs(t, req); !reflect.DeepEqual(got, ids[1:]) {
					t.Fatalf("retried already assessed claims: %v", got)
				}
				if outcome == "transport" {
					return nil, errors.New("temporary service failure after client retries")
				}
				if outcome == "invalid" {
					return legacyResponse(), nil
				}
				return legacyResponse(AuditedFinding{FindingID: ids[1], Verdict: "confirmed", Confidence: .9}), nil
			})
			got, usage, cost, err := runLegacyFixture(doc, client)
			if calls != 2 || (err == nil) != (outcome == "recovers") {
				t.Fatalf("calls=%d error=%v", calls, err)
			}
			results := got.Runs[0].Results
			if len(results) != 2 || results[0].Properties.AuditStatus != "confirmed" || !reflect.DeepEqual(auditFindingIDs(results), ids) {
				t.Fatal("valid verdict or original finding lost", results)
			}
			wantSecond, paidResponses := "not_audited", 2
			if outcome == "recovers" {
				wantSecond = "confirmed"
			}
			if outcome == "transport" {
				paidResponses = 1
			}
			if results[1].Properties.AuditStatus != wantSecond || usage.PromptTokens != 10*paidResponses || cost != .00002*float64(paidResponses) {
				t.Fatalf("status=%s usage=%+v cost=%v", results[1].Properties.AuditStatus, usage, cost)
			}
		})
	}
}

func TestLegacyVerdictIdentityIsUnambiguous(t *testing.T) {
	claims := []auditClaim{{FindingID: "one", FilePath: "a.go", StartLine: 1, Issue: "Same"}, {FindingID: "two", FilePath: "a.go", StartLine: 1, Issue: "Same"}}
	for _, answers := range [][]AuditedFinding{
		{{OriginalIssue: "Same", FilePath: "a.go", StartLine: 1, Verdict: "confirmed"}},
		{{FindingID: "foreign", OriginalIssue: "Same", FilePath: "a.go", StartLine: 1, Verdict: "confirmed"}},
		{{FindingID: "one", Verdict: "confirmed"}, {FindingID: "one", Verdict: "rejected"}},
	} {
		if got, err := acceptLegacyVerdicts(claims, answers); err == nil || len(got) != 0 {
			t.Fatalf("ambiguous verdicts accepted: %+v, %v", got, err)
		}
	}
	got, err := acceptLegacyVerdicts(claims, []AuditedFinding{{FindingID: "two", Verdict: "confirmed"}, {FindingID: "one", Verdict: "unverified"}})
	if err != nil || len(got) != 2 {
		t.Fatalf("stable IDs did not disambiguate shared locations: %+v, %v", got, err)
	}
}

func TestAuditFallbackIDsCannotCollideWithSavedIDs(t *testing.T) {
	results := []sarif.SARIFResult{
		{},
		{Properties: &sarif.FindingProperties{FindingID: "result-1"}},
		{Properties: &sarif.FindingProperties{FindingID: "result-1"}},
		{Properties: &sarif.FindingProperties{FindingID: "result-3"}},
	}
	got := auditFindingIDs(results)
	seen := map[string]bool{}
	for _, id := range got {
		if id == "" || seen[id] {
			t.Fatalf("non-unique audit identities: %v", got)
		}
		seen[id] = true
	}
	if got[1] != "result-1" || got[3] != "result-3" {
		t.Fatal("fallback displaced saved identities", got)
	}
}

func TestLegacyRejectsCrossWiredClaimIdentity(t *testing.T) {
	claims := []auditClaim{{FindingID: "a", Issue: "SQL injection", FilePath: "query.go", StartLine: 4}, {FindingID: "b", Issue: "XSS", FilePath: "view.go", StartLine: 8}}
	got, err := acceptLegacyVerdicts(claims, []AuditedFinding{{FindingID: "a", OriginalIssue: "XSS", FilePath: "view.go", StartLine: 8, Verdict: "confirmed"}, {FindingID: "b", OriginalIssue: "XSS", FilePath: "view.go", StartLine: 8, Verdict: "confirmed"}})
	if err == nil || len(got) != 1 || got[0].FindingID != "b" {
		t.Fatalf("cross-wired identity accepted: %+v %v", got, err)
	}
}

func TestAdditionStructuredIdentityAcrossOriginals(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		original := NewFinding{Issue: "Analysis title", FilePath: "a.go", StartLine: 7, CWEID: "CWE-89"}
		source := func(file string) []sarif.CodePathStep {
			return []sarif.CodePathStep{{FilePath: file, StartLine: 1, Message: "source"}, {FilePath: "a.go", StartLine: 7, Message: "sink"}}
		}
		additions := []NewFinding{
			{Issue: "Different prose", FilePath: "a.go", StartLine: 7, CWEID: "cwe-89", CodePath: source("one.go")},
			{Issue: "Different prose", FilePath: "a.go", StartLine: 7, CWEID: "CWE-89", CodePath: source("two.go")},
		}
		if reverse {
			additions[0], additions[1] = additions[1], additions[0]
		}
		kept, discarded := deduplicateLegacyAdditions(additions, &original)
		if len(kept) != 2 || len(discarded) != 0 || len(original.CodePath) != 0 {
			t.Fatalf("ambiguous sources merged: %v %v", kept, discarded)
		}
		original.CodePath = source("one.go")
		kept, discarded = deduplicateLegacyAdditions(additions, &original)
		if len(kept) != 1 || len(discarded) != 1 || discarded[0].DiscardReason != "duplicate of analysis finding" || kept[0].CodePath[0].FilePath != "two.go" {
			t.Fatalf("structured identity lost: %v %v", kept, discarded)
		}
	}
}

func TestPathlessCWEDoesNotMergeDifferentIssues(t *testing.T) {
	anchor := []sarif.CodePathStep{{FilePath: "source.go", StartLine: 1}, {FilePath: "db.go", StartLine: 40}}
	finding := func(issue string, path []sarif.CodePathStep) NewFinding {
		return NewFinding{Issue: issue, FilePath: "db.go", StartLine: 40, CWEID: "CWE-89", CodePath: path}
	}
	for _, firstPath := range [][]sarif.CodePathStep{nil, anchor} {
		a, b := finding("via name", firstPath), finding("via id", nil)
		for _, input := range [][]NewFinding{{a, b}, {b, a}} {
			kept, discarded := deduplicateLegacyAdditions(input)
			if len(kept) != 2 || len(discarded) != 0 {
				t.Fatalf("pathless CWE overmerge: %v %v", kept, discarded)
			}
		}
	}
	for _, path := range [][]sarif.CodePathStep{nil, anchor} {
		original := finding("via name", nil)
		kept, discarded := deduplicateLegacyAdditions([]NewFinding{finding("via id", path)}, &original)
		if len(kept) != 1 || len(discarded) != 0 || len(original.CodePath) != 0 {
			t.Fatal("addition borrowed its own anchor", kept, discarded)
		}
	}
	x, y, z := finding("X", nil), finding("X", nil), finding("Y", nil)
	y.CWEID = "CWE-79"
	z.CWEID = "CWE-79"
	for _, input := range [][]NewFinding{{x, y, z}, {x, z, y}, {y, x, z}, {y, z, x}, {z, x, y}, {z, y, x}} {
		kept, _ := deduplicateLegacyAdditions(input)
		if len(kept) != 2 {
			t.Fatal("order-dependent pathless merge", input, kept)
		}
	}
}
