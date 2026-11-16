package cli

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/block/codecrucible/internal/auditctx"
	"github.com/block/codecrucible/internal/chunk"
	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/llm"
	"github.com/block/codecrucible/internal/sarif"
	"github.com/block/codecrucible/internal/sourceindex"
)

// legacyAuditPrompt runs the default-set audit over one finding at
// handler.ts:2 and returns everything the model was sent. source, when set,
// is the scan's shared index.
func legacyAuditPrompt(t *testing.T, files ingest.FileMap, source *sourceindex.Index, limit int) string {
	t.Helper()
	text, _ := legacyAuditTokens(t, files, source, limit)
	return text
}

// legacyAuditTokens also returns the request's size as the audit measures it.
func legacyAuditTokens(t *testing.T, files ingest.FileMap, source *sourceindex.Index, limit int) (string, int) {
	t.Helper()
	counter := chunk.NewTokenCounter("", nil)
	tokens := 0
	doc := sarif.Build(sarif.AnalysisResult{SecurityIssues: []sarif.SecurityIssue{{Issue: "Unsafe query", FilePath: "handler.ts", StartLine: 2, Severity: 8}}}, nil, sarif.BuilderConfig{})
	var text strings.Builder
	client := auditClientFunc(func(_ context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
		for _, m := range req.Messages {
			text.WriteString(m.Content)
			tokens += counter.Count(m.Content)
		}
		data, _ := json.Marshal(AuditResult{AuditedFindings: []AuditedFinding{{OriginalIssue: "Unsafe query", FilePath: "handler.ts", StartLine: 2, Verdict: "confirmed", Confidence: .9}}})
		return &llm.ChatResponse{Content: string(data)}, nil
	})
	got, _, _, err := runAuditPhase(context.Background(), doc, "fixture", client, "", config.ModelConfig{Name: "test", ContextLimit: limit}, llm.NewPromptLoader(os.DirFS("../../prompts/default")), llm.OutputModeNone, files, .3, nil, "", 1, true, counter, nil, source)
	if err != nil || got == nil || got.Runs[0].Results[0].Properties.AuditStatus != "confirmed" {
		t.Fatalf("audit failed: %v", err)
	}
	if strings.Count(text.String(), "export function profileHandler") != 1 {
		t.Fatalf("claim's own file lost or duplicated: %s", text.String())
	}
	return text.String(), tokens
}

func TestLegacyAuditFitsRetrievalToContextLimit(t *testing.T) {
	files := ingest.FileMap{
		"handler.ts": "export function profileHandler(req,res) {\n return res.json(loadProfile(req.body));\n}\n",
		"router.ts":  "router.get('/profile', profileHandler);\n",
		"profile.ts": "export function loadProfile(body) {\n const PROFILE_LOADER = body.id;\n" + strings.Repeat(" // long context padding for audit budget\n", 55) + " return PROFILE_LOADER;\n}\n",
	}
	route := "router.get('/profile', profileHandler)"
	if text := legacyAuditPrompt(t, files, nil, 0); !strings.Contains(text, route) || !strings.Contains(text, "PROFILE_LOADER") || strings.Contains(text, "Audit context omitted:") {
		t.Fatalf("unlimited audit lost evidence: %s", text)
	}
	_, base := legacyAuditTokens(t, files, nil, 1)
	// Room for the route registration but not the padded definition.
	limit := base + auditContextReserve + 120
	text, tokens := legacyAuditTokens(t, files, nil, limit)
	if !strings.Contains(text, route) || strings.Contains(text, "PROFILE_LOADER") || !strings.Contains(text, auditctx.BudgetNote) || tokens > limit {
		t.Fatalf("evidence not trimmed in priority order (tokens=%d limit=%d): %s", tokens, limit, text)
	}
	// No room at all: only the note, still within the limit.
	limit = base + auditContextReserve
	text, tokens = legacyAuditTokens(t, files, nil, limit)
	if strings.Contains(text, route) || !strings.Contains(text, "Audit context omitted:") || tokens > limit {
		t.Fatalf("zero retrieval budget not enforced (tokens=%d limit=%d): %s", tokens, limit, text)
	}
}

func TestFitAuditContextRetriesBeforeDropping(t *testing.T) {
	// cost models wrappers that retrieval underestimates by a fixed overhead.
	fake := func(overhead int) (func(int) string, func(string) int, *[]int) {
		var asked []int
		retrieve := func(b int) string { asked = append(asked, b); return strings.Repeat("x", b) }
		cost := func(s string) int { return len(s) + overhead }
		return retrieve, cost, &asked
	}
	for _, tc := range []struct {
		name      string
		overhead  int
		want      string
		wantAsked []int
	}{
		{"fits", auditContextSlack, strings.Repeat("x", 1000), []int{1000}},
		{"retried", auditContextSlack + 100, strings.Repeat("x", 1000-auditContextSlack-100), []int{1000, 1000 - auditContextSlack - 100}},
		{"dropped", 2000, auditBudgetNote, []int{1000, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			retrieve, cost, asked := fake(tc.overhead)
			if got := fitAuditContext(1000, retrieve, cost); got != tc.want {
				t.Fatalf("got %d bytes, want %d", len(got), len(tc.want))
			}
			if len(*asked) != len(tc.wantAsked) || (*asked)[len(*asked)-1] != tc.wantAsked[len(tc.wantAsked)-1] {
				t.Fatalf("retrieval budgets %v, want %v", *asked, tc.wantAsked)
			}
		})
	}
}
