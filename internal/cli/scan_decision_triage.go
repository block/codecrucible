package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/decision"
	"github.com/block/codecrucible/internal/ingest"
)

// fileTriageConcurrency stays well below TypeSafe's request-rate limit.
const fileTriageConcurrency = 16

// fileTriageTextBudget keeps state plus question under the client's
// conservative 32,000-byte limit after JSON escaping.
const fileTriageTextBudget = 26000

// fileTriageQuestions were validated offline against annotated corpora; a file
// is kept when either probability reaches the threshold.
var fileTriageQuestions = map[string]decision.Question{
	"surface": decision.Noul("Does the code in `file.text` directly handle security-relevant behaviour: untrusted request input, authentication, authorization or ownership checks, sessions or tokens, secrets or cryptography, database queries, file-system or outbound network access, HTML/template output, deserialization, or security configuration?"),
	"vuln":    decision.Noul("Does `file.text` contain code with a plausible exploitable security weakness (for example injection, missing authorization, unsafe file access, weak crypto, secret exposure, unsafe redirect, XSS)?"),
}

type fileTriageResult struct {
	records []decision.Record
	kept    []ingest.SourceFile
}

// triageFiles asks Jev whether each admitted file is security-relevant. Active
// mode removes files scored below the threshold on both questions; shadow mode
// records the proposal and keeps every file. Failed calls and truncated files
// are always kept.
func triageFiles(ctx context.Context, cfg config.Decisions, files []ingest.SourceFile) (fileTriageResult, error) {
	mode := cfg.FileTriage
	client, err := decision.New(decision.Options{URL: cfg.URL, APIKey: cfg.APIKey, Model: cfg.Model, Timeout: time.Duration(cfg.Timeout) * time.Second, MaxCalls: len(files), Retries: cfg.Retries, InputPrice: cfg.InputPrice})
	if err != nil {
		return fileTriageResult{}, err
	}
	type verdict struct {
		record    decision.Record
		keep      bool
		truncated bool
		failed    bool
	}
	verdicts := make([]verdict, len(files))
	work := make(chan int)
	var wg sync.WaitGroup
	for range min(fileTriageConcurrency, len(files)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range work {
				f := files[i]
				text, truncated := fileTriageText(f.Path, f.Content)
				recorder := &decision.Recorder{Client: client}
				state := map[string]any{"file": map[string]any{"path": f.Path, "text": text, "truncated": truncated}}
				response, callErr := recorder.Evaluate(ctx, "file-triage", mode, f.Path, state, fileTriageQuestions, nil, !truncated)
				score := max(noulValue(response.Answers["surface"]), noulValue(response.Answers["vuln"]))
				failed := callErr != nil || response.Answers["surface"].Noul == nil || response.Answers["vuln"].Noul == nil
				keep := failed || truncated || score >= cfg.FileTriageThreshold
				switch {
				case failed:
					recorder.Action("keep_unavailable")
				case truncated:
					recorder.Action("keep_truncated")
				case keep:
					recorder.Action("keep")
				default:
					recorder.Action("drop")
				}
				verdicts[i] = verdict{record: recorder.Records[0], keep: keep, truncated: truncated, failed: failed}
			}
		}()
	}
	for i := range files {
		if ctx.Err() != nil {
			break
		}
		work <- i
	}
	close(work)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return fileTriageResult{}, err
	}

	result := fileTriageResult{}
	var failed, truncated, dropped, keptBytes, droppedBytes int
	for i, v := range verdicts {
		result.records = append(result.records, v.record)
		if v.failed {
			failed++
		}
		if v.truncated {
			truncated++
		}
		if v.keep || mode != "active" {
			result.kept = append(result.kept, files[i])
		}
		if v.keep {
			keptBytes += len(files[i].Content)
		} else {
			dropped++
			droppedBytes += len(files[i].Content)
		}
	}
	prefix := ""
	if mode == "shadow" {
		prefix = "proposed_"
	}
	summary := decision.Record{Stage: "file-triage", Mode: mode, Subject: "repository", Policy: decision.PolicyVersion, Status: "completed", Action: "summary", Complete: failed == 0, Outcomes: map[string]int{
		"files_evaluated":        len(files),
		"files_unavailable":      failed,
		"files_truncated":        truncated,
		prefix + "files_kept":    len(files) - dropped,
		prefix + "files_dropped": dropped,
		prefix + "bytes_kept":    keptBytes,
		prefix + "bytes_dropped": droppedBytes,
		"threshold_basis_points": int(cfg.FileTriageThreshold * 10000),
	}}
	result.records = append(result.records, summary)
	slog.Info("Jev file triage complete", "mode", mode, "files", len(files), "dropped", dropped, "bytes_dropped", droppedBytes, "unavailable", failed, "truncated", truncated)
	return result, nil
}

func noulValue(a decision.Answer) float64 {
	if a.Noul == nil {
		return 0
	}
	return *a.Noul
}

// fileTriageText cuts large files at a line boundary so the request fits.
func fileTriageText(path, content string) (string, bool) {
	fits := func(text string) bool {
		encoded, _ := json.Marshal(map[string]any{"file": map[string]any{"path": path, "text": text, "truncated": true}})
		return len(encoded) <= fileTriageTextBudget
	}
	if fits(content) {
		return content, false
	}
	limit := len(content)
	for limit > 0 {
		limit = limit * 3 / 4
		cut := content[:limit]
		if i := strings.LastIndexByte(cut, '\n'); i > 0 {
			cut = cut[:i+1]
		}
		if fits(cut) {
			return cut, true
		}
	}
	return "", true
}

// applyFileTriage runs the stage when enabled and returns the files to analyze.
func applyFileTriage(ctx context.Context, cfg config.Decisions, files []ingest.SourceFile) ([]ingest.SourceFile, []decision.Record, error) {
	if mode := cfg.FileTriage; mode != "active" && mode != "shadow" {
		return files, nil, nil
	}
	if len(files) == 0 {
		return files, nil, nil
	}
	result, err := triageFiles(ctx, cfg, files)
	if err != nil {
		return nil, nil, fmt.Errorf("Jev file triage: %w", err)
	}
	return result.kept, result.records, nil
}
