package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/block/codecrucible/internal/chunk"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/llm"
	"github.com/block/codecrucible/internal/sarif"
)

func scopeFixture() []ingest.SourceFile {
	return []ingest.SourceFile{
		{Path: "db/dump.sql", Content: "-- MySQL dump 10.13 Distrib 5.6.45\n" + strings.Repeat("INSERT INTO data VALUES (123456789);\n", 2000)},
		{Path: "db/migration.sql", Content: strings.Repeat("ALTER TABLE users ADD COLUMN last_seen TIMESTAMP;\n", 500)},
		{Path: "app.py", Content: "print('hello')\n"},
	}
}

func nominateDump(cs []scopeCandidate) string {
	ns := []scopeNomination{}
	for _, c := range cs {
		if strings.HasPrefix(c.Head, "-- MySQL dump") {
			ns = append(ns, scopeNomination{ID: c.ID, Category: "database_dump", Reason: "Generated database dump; retain executable application source", Evidence: "-- MySQL dump 10.13"})
		}
	}
	b, _ := json.Marshal(scopeResponse{Nominations: ns})
	return string(b)
}

func TestScopePlannerValidation(t *testing.T) {
	files := scopeFixture()
	cs := scopeCandidates(files, nil, chunk.NewTokenCounter("", slog.Default()))
	if len(cs) != 2 {
		t.Fatalf("candidates=%d", len(cs))
	}
	for _, mode := range []string{"valid", "invented", "glob", "unsupported", "missing-evidence", "migration", "malformed", "missing-array", "truncated", "extra-field"} {
		t.Run(mode, func(t *testing.T) {
			raw := nominateDump(cs)
			var resp scopeResponse
			_ = json.Unmarshal([]byte(raw), &resp)
			n := &resp.Nominations[0]
			switch mode {
			case "invented":
				n.ID = "F999999"
			case "glob":
				n.ID = "**/*.sql"
			case "unsupported":
				n.Category = "large_file"
			case "missing-evidence":
				n.Evidence = "totally absent evidence"
			case "migration":
				for _, c := range cs {
					if c.Path == "db/migration.sql" {
						n.ID = c.ID
						n.Evidence = "ALTER TABLE users"
					}
				}
			}
			b, _ := json.Marshal(resp)
			raw = string(b)
			switch mode {
			case "malformed":
				raw = "not json"
			case "missing-array":
				raw = "{}"
			case "truncated":
				raw = raw[:len(raw)-1]
			case "extra-field":
				raw = `{"nominations":[],"exclude":["**"]}`
			}
			plan := &sarif.ScopePlan{}
			kept, err := applyScopeNominations(files, cs, raw, plan)
			if mode == "valid" {
				if err != nil || len(kept) != 2 || len(plan.Exclusions) != 1 || plan.EstimatedTokensSaved <= 0 {
					t.Fatalf("kept=%d plan=%+v err=%v", len(kept), plan, err)
				}
			} else if len(kept) != len(files) || len(plan.Exclusions) != 0 {
				t.Fatalf("invalid nomination changed scope: %+v", plan)
			}
		})
	}
	protected := scopeCandidates(files, []string{"db/**"}, chunk.NewTokenCounter("", slog.Default()))
	if len(protected) != 0 {
		t.Fatal("explicit includes were nominated")
	}
}

func TestScopePlannerRequestBounded(t *testing.T) {
	var files []ingest.SourceFile
	for i := 0; i < 100; i++ {
		files = append(files, ingest.SourceFile{Path: fmt.Sprintf("file%03d.sql", i), Content: strings.Repeat("大きい file content\n", 100000)})
	}
	cs := scopeCandidates(files, nil, chunk.NewTokenCounter("", slog.Default()))
	cfg := resolvedMetadataConfig(t)
	phase := cfg.Phases.FeatureDetection
	phase.ModelCfg.ContextLimit = 20000
	phase.ModelCfg.MaxOutputTokens = 4096
	phase.ModelParams = map[string]any{"max_tokens": 999999, "model": "test-model"}
	req, sent := scopeRequest(cs, phase, "")
	if len(sent) == 0 || len(sent) > 32 || len(req.Messages[1].Content) > scopeMaxInputBytes {
		t.Fatal("unbounded or empty inventory")
	}
	var payload []scopeCandidate
	if json.Unmarshal([]byte(req.Messages[1].Content), &payload) != nil {
		t.Fatal("invalid samples")
	}
	for _, c := range payload {
		if len(c.Head) > 1536 || len(c.Tail) > 512 {
			t.Fatal("unbounded sample")
		}
	}
	counter := chunk.NewTokenCounter(phase.ModelCfg.Encoding, slog.Default())
	tokens := counter.Count(scopeSystemPrompt) + counter.Count(string(scopeSchema)) + counter.Count(req.Messages[1].Content) + 128
	if tokens+req.MaxTokens+1024 > 16000 {
		t.Fatalf("request does not fit with reservations: %d", tokens)
	}
	if _, ok := req.ModelParams["max_tokens"]; ok {
		t.Fatal("output override bypasses cap")
	}
	if req.ModelParams["model"] != "test-model" {
		t.Fatal("lost deployment override")
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(scopeSchema, &envelope) != nil || envelope["schema"] == nil {
		t.Fatal("invalid structured output envelope")
	}
}

func TestScopePlannerWorkflow(t *testing.T) {
	for _, mode := range []string{"accepted", "fallback", "truncated", "include", "dry-run", "disabled", "all-excluded", "token-budget", "empty-answer"} {
		t.Run(mode, func(t *testing.T) {
			repo := t.TempDir()
			files := scopeFixture()
			if mode == "all-excluded" {
				files = files[:1]
			}
			for _, f := range files {
				p := filepath.Join(repo, f.Path)
				if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(f.Content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			plannerCalls, analysisCalls := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				var req struct {
					Messages []llm.Message `json:"messages"`
				}
				if json.Unmarshal(body, &req) != nil {
					t.Error("bad request")
					return
				}
				response := `{"findings":[],"summary":"No findings"}`
				finish := "stop"
				if len(req.Messages) > 0 && strings.Contains(req.Messages[0].Content, "You nominate low-value") {
					plannerCalls++
					if mode == "fallback" {
						http.Error(w, "unsupported", 400)
						return
					}
					var cs []scopeCandidate
					if err := json.Unmarshal([]byte(req.Messages[1].Content), &cs); err != nil {
						t.Error(err)
					}
					response = nominateDump(cs)
					if mode == "truncated" {
						finish = "length"
					}
					if mode == "empty-answer" {
						response = `{"nominations":[]}`
					}
				} else {
					analysisCalls++
					if mode == "accepted" && bytes.Contains(body, []byte("INSERT INTO data")) {
						t.Error("excluded dump reached analysis")
					}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": response}, "finish_reason": finish}}, "usage": map[string]int{"prompt_tokens": 100, "completion_tokens": 20}})
			}))
			defer server.Close()
			args := []string{"--scope-planning", "--fail-on-incomplete", "--skip-audit"}
			if mode == "include" {
				args = append(args, "--include", "db/dump.sql")
			}
			if mode == "dry-run" {
				args = append(args, "--dry-run")
			}
			if mode == "disabled" {
				args = append(args, "--scope-planning=false")
			}
			if mode == "token-budget" {
				args = append(args, "--max-input-tokens", "100")
			}
			dir, err := runReplayScan(t, repo, server.URL, args...)
			if mode == "token-budget" {
				if !errors.Is(err, ErrIncompleteScan) {
					t.Fatalf("expected strict budget failure: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if mode == "dry-run" {
				if plannerCalls+analysisCalls != 0 {
					t.Fatal("dry run made model calls")
				}
				return
			}
			doc := readSARIF(t, filepath.Join(dir, "final.sarif"))
			m := doc.Runs[0].Properties.CodeCrucible
			if mode == "disabled" {
				if plannerCalls != 0 || m.Execution.ScopePlan != nil {
					t.Fatal("disabled planner ran")
				}
				return
			}
			plan := m.Execution.ScopePlan
			if plan == nil {
				t.Fatal("missing receipt")
			}
			wantExcluded := 0
			if mode == "accepted" || mode == "all-excluded" || mode == "token-budget" {
				wantExcluded = 1
			}
			if len(plan.Exclusions) != wantExcluded || plan.FilesAfter != len(files)-wantExcluded {
				t.Fatalf("bad scope receipt: %+v", plan)
			}
			if m.Execution.SourceCoverage.Admitted != len(files)-wantExcluded {
				t.Fatalf("excluded files counted in coverage: %+v", m.Execution.SourceCoverage)
			}
			if mode == "all-excluded" && (analysisCalls != 0 || m.Execution.SourceCoverage.Analyzed != 0 || plan.Status != "completed") {
				t.Fatal("empty scope misrepresented")
			}
			if mode == "token-budget" && analysisCalls != 0 {
				t.Fatal("planner input usage did not stop analysis")
			}
			receipt, err := os.ReadFile(filepath.Join(dir, "scope-planning.json"))
			if err != nil {
				t.Fatal(err)
			}
			var saved sarif.ScopePlan
			if json.Unmarshal(receipt, &saved) != nil || saved.FilesAfter != plan.FilesAfter {
				t.Fatal("sidecar receipt differs")
			}
			if mode != "fallback" && plannerCalls > 0 && (plan.PromptTokens != 100 || m.Execution.InputTokens < 100) {
				t.Fatal("planner usage lost")
			}
		})
	}
}

func TestScopePlannerDuplicatesAndFixtures(t *testing.T) {
	generated := "// Code generated by example. DO NOT EDIT.\n" + strings.Repeat("const answer = 123456789;\n", 2000)
	snapshot := `{"records":[` + strings.Repeat(`"fixture value",`, 2000) + `"last"]}`
	files := []ingest.SourceFile{{Path: "a/original.js", Content: generated}, {Path: "b/copy.js", Content: generated}, {Path: "fixtures/snapshot.json", Content: snapshot}, {Path: "config.json", Content: snapshot}}
	cs := scopeCandidates(files, nil, chunk.NewTokenCounter("", slog.Default()))
	var ns []scopeNomination
	for _, c := range cs {
		n := scopeNomination{ID: c.ID, Reason: "Static generated artifact; preserve original application source"}
		if strings.HasSuffix(c.Path, ".js") {
			n.Category = "generated_duplicate"
			n.Evidence = "Code generated"
			n.SourceID = c.DuplicateOf
		} else {
			n.Category = "fixture_snapshot"
			n.Evidence = "fixture value"
		}
		ns = append(ns, n)
	}
	raw, _ := json.Marshal(scopeResponse{Nominations: ns})
	plan := &sarif.ScopePlan{}
	kept, err := applyScopeNominations(files, cs, string(raw), plan)
	if err != nil || len(kept) != 2 || plan.Rejected != 2 {
		t.Fatalf("kept=%v plan=%+v err=%v", kept, plan, err)
	}
	paths := map[string]bool{}
	for _, f := range kept {
		paths[f.Path] = true
	}
	if !paths["a/original.js"] || !paths["config.json"] {
		t.Fatal("lost retained original or application config")
	}
}

func TestScopePlannerBudgetAndReplay(t *testing.T) {
	for _, mode := range []string{"preflight", "replay", "cost-refusal"} {
		t.Run(mode, func(t *testing.T) {
			cfg := resolvedMetadataConfig(t)
			cfg.ScopePlanning = true
			cfg.MaxCost = 0
			cfg.PhaseOutputDir = t.TempDir()
			files := scopeFixture()
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				var req struct {
					Messages []llm.Message `json:"messages"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				var cs []scopeCandidate
				_ = json.Unmarshal([]byte(req.Messages[1].Content), &cs)
				_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": nominateDump(cs)}, "finish_reason": "stop"}}, "usage": map[string]int{"prompt_tokens": 100, "completion_tokens": 20}})
			}))
			defer server.Close()
			cfg.Phases.FeatureDetection.BaseURL = server.URL
			if mode == "replay" {
				cfg.AuditFrom = "saved.sarif"
			}
			if mode == "cost-refusal" {
				cfg.MaxCost = 0.000001
			}
			metadata := newScanMetadata(cfg)
			usage := newModelUsage()
			artifacts := newPhaseArtifactWriter(cfg)
			kept, spent, cost, err := planScope(context.Background(), cfg, files, usage, metadata, artifacts)
			if err != nil {
				t.Fatal(err)
			}
			if mode != "preflight" {
				if calls != 0 || len(kept) != len(files) {
					t.Fatal("skipped planner changed scope or made calls")
				}
				return
			}
			if len(kept) != 2 || spent.PromptTokens != 100 || cost <= 0 || calls != 1 {
				t.Fatalf("planner did not run: %d %+v %f", len(kept), spent, cost)
			}
			if err := (scanCostEstimate{}).withPriorCost(cost).checkConfiguredBudget(cost/2, true); err == nil {
				t.Fatal("preflight ignored planner spend")
			}
			if _, err := os.Stat(filepath.Join(cfg.PhaseOutputDir, "scope-planning.json")); err != nil {
				t.Fatal("receipt lost before budget rejection")
			}
		})
	}
}

func TestScopePlannerEmptyScopeCostFailure(t *testing.T) {
	cfg := resolvedMetadataConfig(t)
	cfg.ScopePlanning = true
	cfg.MaxCost = 0.01
	cfg.Output = filepath.Join(t.TempDir(), "final.sarif")
	metadata := newScanMetadata(cfg)
	metadata.Execution.ScopePlan = &sarif.ScopePlan{Status: "completed", EstimatedCost: 0.02, FilesBefore: 1, FilesAfter: 0}
	if err := outputEmptySARIFWithMetadata(cfg, time.Now(), metadata, newModelUsage()); err == nil {
		t.Fatal("overspend with empty scope reported success")
	}
	doc := readSARIF(t, cfg.Output)
	if doc.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Fatal("overspend not persisted")
	}
}
