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
	"github.com/block/codecrucible/internal/sourceindex"
)

func TestLegacyAuditRetrievesMountedGuardWithinBudget(t *testing.T) {
	files := ingest.FileMap{
		"handler.ts":  "export function profileHandler(req,res) {\n return res.json(req.body);\n}\n",
		"router.ts":   "router.get('/admin', requireAdmin, adminHandler);\nrouter.get('/profile', bindOwner, profileHandler);\n",
		"identity.ts": "export function bindOwner(req,res,next) {\n req.body.owner = req.auth.id;\n" + strings.Repeat(" // long context padding for audit budget\n", 55) + " next();\n}\n",
		"guards.ts":   "export function requireAdmin(req,res,next) {\n if (!req.admin) throw new Error('ADMIN_ONLY');\n next();\n}\n",
	}
	doc := sarif.Build(sarif.AnalysisResult{SecurityIssues: []sarif.SecurityIssue{{Issue: "Unsafe query", FilePath: "handler.ts", StartLine: 2, Severity: 8}}}, nil, sarif.BuilderConfig{})
	counter := chunk.NewTokenCounter("", nil)
	run := func(limit int) (string, int) {
		t.Helper()
		text, tokens := "", 0
		client := auditClientFunc(func(_ context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
			for _, m := range req.Messages {
				text += m.Content
				tokens += counter.Count(m.Content)
			}
			data, _ := json.Marshal(AuditResult{AuditedFindings: []AuditedFinding{{OriginalIssue: "Unsafe query", FilePath: "handler.ts", StartLine: 2, Verdict: "confirmed", Confidence: .9}}})
			return &llm.ChatResponse{Content: string(data)}, nil
		})
		got, _, _, err := runAuditPhase(context.Background(), doc, "fixture", client, "", config.ModelConfig{Name: "test", ContextLimit: limit}, llm.NewPromptLoader(os.DirFS("../../prompts/default")), llm.OutputModeNone, files, .3, nil, "", 1, true, counter, nil, nil)
		if err != nil || got == nil || got.Runs[0].Results[0].Properties.AuditStatus != "confirmed" {
			t.Fatalf("audit failed: %v", err)
		}
		if strings.Contains(text, "ADMIN_ONLY") {
			t.Fatal("unrelated guard retrieved")
		}
		if strings.Count(text, "export function profileHandler") != 1 {
			t.Fatal("own file lost or duplicated")
		}
		return text, tokens
	}
	text, _ := run(0)
	if !strings.Contains(text, "req.body.owner = req.auth.id") {
		t.Fatal("mounted guard missing", text)
	}
	// Reserve space for prompt/source and an omission note, but no retrieved code.
	_, base := run(1)
	text, tokens := run(base + 512)
	if !strings.Contains(text, "Audit context omitted:") || tokens > base+512 {
		t.Fatalf("budget not enforced: tokens=%d limit=%d", tokens, base+512)
	}
}

func TestLegacyAuditRetrievalUsesSharedSourceIndex(t *testing.T) {
	// The scan builds one index and hands it to every phase. The audit's
	// retrieval must read that snapshot, not the file map it was also given.
	scanned := ingest.FileMap{
		"handler.ts":  "export function profileHandler(req,res) {\n return res.json(req.body);\n}\n",
		"router.ts":   "router.get('/profile', bindOwner, profileHandler);\n",
		"identity.ts": "export function bindOwner(req,res,next) {\n req.body.owner = req.auth.id;\n next();\n}\n",
	}
	text := legacyAuditPrompt(t, ingest.FileMap{"handler.ts": scanned["handler.ts"]}, sourceindex.New(scanned), 0)
	for _, want := range []string{"router.get('/profile', bindOwner, profileHandler)", "req.body.owner = req.auth.id"} {
		if !strings.Contains(text, want) {
			t.Fatalf("shared index evidence missing %q: %s", want, text)
		}
	}
	// With no shared index the audit builds one from the file map it has.
	if text := legacyAuditPrompt(t, ingest.FileMap{"handler.ts": scanned["handler.ts"]}, nil, 0); strings.Contains(text, "bindOwner") {
		t.Fatalf("retrieved source that is not in the snapshot: %s", text)
	}
}

func TestLegacyAuditReportsMissingCallerContext(t *testing.T) {
	files := ingest.FileMap{
		"handler.ts": "export function profileHandler(req,res) {\n return res.json(req.body);\n}\n",
		"router.ts":  "import { externalGuard } from 'external-library';\nrouter.get('/profile', externalGuard, bindOwner, profileHandler);\n",
		"one.ts":     "export function bindOwner() { return 'FIRST'; }\n",
		"two.ts":     "export function bindOwner() { return 'SECOND'; }\n",
	}
	text := legacyAuditPrompt(t, files, nil, 0)
	for _, want := range []string{"Audit context omitted: ambiguous caller reference bindOwner in router.ts", "Audit context omitted: unresolved or external caller reference externalGuard in router.ts"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q: %s", want, text)
		}
	}
	if strings.Contains(text, "FIRST") || strings.Contains(text, "SECOND") {
		t.Fatal("ambiguous definition guessed")
	}
}

func TestLegacyAuditTrimsRetrievedEvidenceInPriorityOrder(t *testing.T) {
	files := ingest.FileMap{
		"handler.ts":  "export function profileHandler(req,res) {\n return res.json(req.body);\n}\n",
		"router.ts":   "router.get('/profile', bindOwner, profileHandler);\n",
		"identity.ts": "export function bindOwner(req,res,next) {\n req.body.owner = req.auth.id;\n" + strings.Repeat(" // long context padding for audit budget\n", 55) + " next();\n}\n",
	}
	_, base := legacyAuditTokens(t, files, nil, 1)
	// Room for the route registration but not for the middleware definition.
	text, _ := legacyAuditTokens(t, files, nil, base+auditContextReserve+120)
	if !strings.Contains(text, "router.get('/profile', bindOwner, profileHandler)") {
		t.Fatalf("highest-priority evidence dropped: %s", text)
	}
	if strings.Contains(text, "req.body.owner = req.auth.id") || !strings.Contains(text, "Audit context omitted: token budget exhausted") {
		t.Fatalf("lower-priority evidence was not trimmed with a note: %s", text)
	}
}
