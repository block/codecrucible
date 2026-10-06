package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/decision"
	"github.com/block/codecrucible/internal/ingest"
)

func fileTriageServer(t *testing.T, scores map[string]float64, failPath string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var req struct {
			State struct {
				File struct {
					Path string `json:"path"`
				} `json:"file"`
			} `json:"state"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		if req.State.File.Path == failPath {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		score := scores[req.State.File.Path]
		low := score / 2
		input := 50
		_ = json.NewEncoder(w).Encode(decision.Response{Model: "jev-test", Answers: map[string]decision.Answer{
			"surface": {Type: "noul", Noul: &score},
			"vuln":    {Type: "noul", Noul: &low},
		}, Usage: decision.TokenUsage{Input: &input}})
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func triageConfig(url, mode string) config.Decisions {
	return config.Decisions{FileTriage: mode, FileTriageThreshold: 0.2, URL: url, APIKey: "k", Model: "jev-test", Timeout: 5, MaxCalls: 1, Retries: 0}
}

func TestFileTriageDropsOnlyLowScoringFilesInActiveMode(t *testing.T) {
	files := []ingest.SourceFile{
		{Path: "internal/route/repo.go", Content: "package route\n"},
		{Path: "web/src/locales/strings.json", Content: "{}\n"},
		{Path: "internal/types/webhook.go", Content: "package types\n"},
		{Path: "internal/flaky.go", Content: "package flaky\n"},
		{Path: "internal/big.go", Content: strings.Repeat("// padding line for a very large file\n", 2000)},
	}
	srv, calls := fileTriageServer(t, map[string]float64{"internal/route/repo.go": 0.97, "web/src/locales/strings.json": 0.05, "internal/types/webhook.go": 0.19, "internal/big.go": 0.01}, "internal/flaky.go")
	kept, records, err := applyFileTriage(context.Background(), triageConfig(srv.URL, "active"), files)
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, f := range kept {
		got = append(got, f.Path)
	}
	// The failed call and the truncated file are kept regardless of score.
	if strings.Join(got, ",") != "internal/route/repo.go,internal/flaky.go,internal/big.go" {
		t.Fatalf("kept %v", got)
	}
	if int(calls.Load()) != len(files) {
		t.Fatalf("expected one call per file despite MaxCalls=1 shared budget, got %d", calls.Load())
	}
	summary := records[len(records)-1]
	if summary.Outcomes["files_dropped"] != 2 || summary.Outcomes["files_unavailable"] != 1 || summary.Outcomes["files_truncated"] != 1 || summary.Complete {
		t.Fatalf("summary %+v", summary)
	}
	actions := map[string]string{}
	for _, r := range records[:len(records)-1] {
		actions[r.Subject] = r.Action
	}
	if actions["internal/flaky.go"] != "keep_unavailable" || actions["internal/big.go"] != "keep_truncated" || actions["internal/types/webhook.go"] != "drop" {
		t.Fatalf("actions %v", actions)
	}
}

func TestFileTriageShadowKeepsEveryFile(t *testing.T) {
	files := []ingest.SourceFile{{Path: "a.go", Content: "package a\n"}, {Path: "b.json", Content: "{}\n"}}
	srv, _ := fileTriageServer(t, map[string]float64{"a.go": 0.9, "b.json": 0.01}, "")
	kept, records, err := applyFileTriage(context.Background(), triageConfig(srv.URL, "shadow"), files)
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 2 {
		t.Fatalf("shadow mode dropped files: %v", kept)
	}
	if got := records[len(records)-1].Outcomes["proposed_files_dropped"]; got != 1 {
		t.Fatalf("proposed drops %d", got)
	}
}

func TestFileTriageOffMakesNoRequests(t *testing.T) {
	srv, calls := fileTriageServer(t, nil, "")
	files := []ingest.SourceFile{{Path: "a.go", Content: "package a\n"}}
	kept, records, err := applyFileTriage(context.Background(), triageConfig(srv.URL, "off"), files)
	if err != nil || len(kept) != 1 || records != nil || calls.Load() != 0 {
		t.Fatalf("off mode: kept=%d records=%v calls=%d err=%v", len(kept), records, calls.Load(), err)
	}
}

func TestFileTriageTextFitsDecisionLimit(t *testing.T) {
	content := strings.Repeat("x := \"quoted\\tvalue\" // comment\n", 3000)
	text, truncated := fileTriageText("a.go", content)
	if !truncated || len(text) == 0 || !strings.HasSuffix(text, "\n") {
		t.Fatalf("expected line-aligned truncation, got truncated=%v len=%d", truncated, len(text))
	}
	encoded, _ := json.Marshal(map[string]any{"file": map[string]any{"path": "a.go", "text": text, "truncated": true}})
	question, _ := json.Marshal(fileTriageQuestions["surface"])
	if len(encoded)+len(question)+256 > 32000 {
		t.Fatalf("state and question exceed decision limit: %d", len(encoded)+len(question)+256)
	}
}
