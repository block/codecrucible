package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func invocationTimes(t *testing.T, path string) (time.Time, time.Time) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Invocations []struct {
				Start string `json:"startTimeUtc"`
				End   string `json:"endTimeUtc"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Invocations) != 1 {
		t.Fatalf("expected one invocation in %s", path)
	}
	inv := doc.Runs[0].Invocations[0]
	parse := func(s string) time.Time {
		t.Helper()
		v, err := time.Parse(time.RFC3339Nano, s)
		if err != nil || !strings.HasSuffix(s, "Z") {
			t.Fatalf("invalid UTC timestamp %q in %s: %v", s, path, err)
		}
		return v
	}
	start, end := parse(inv.Start), parse(inv.End)
	if end.Before(start) {
		t.Fatalf("negative duration in %s: %s to %s", path, start, end)
	}
	return start, end
}

func TestScanInvocationTiming(t *testing.T) {
	for _, mode := range []string{"empty", "skip-audit", "audited", "failed-analysis", "incomplete-audit", "replay"} {
		t.Run(mode, func(t *testing.T) {
			repo := t.TempDir()
			if mode != "empty" {
				if err := os.WriteFile(filepath.Join(repo, "app.go"), []byte(replaySource), 0600); err != nil {
					t.Fatal(err)
				}
			}
			state := &replayServer{}
			handler := state.handler(t)
			var mu sync.Mutex
			var requests []time.Time
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				requests = append(requests, time.Now())
				mu.Unlock()
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				r.Body = io.NopCloser(bytes.NewReader(body))
				if mode == "failed-analysis" || mode == "incomplete-audit" && bytes.Contains(body, []byte("claims_to_verify")) {
					http.Error(w, "unsupported audit request", http.StatusBadRequest)
					return
				}
				handler(w, r)
			}))
			defer server.Close()

			var extra []string
			if mode == "skip-audit" {
				extra = append(extra, "--skip-audit")
			}
			if mode == "replay" {
				first, err := runReplayScan(t, repo, server.URL)
				if err != nil {
					t.Fatal(err)
				}
				extra = append(extra, "--audit-from", filepath.Join(first, "analysis.sarif"))
				mu.Lock()
				requests = nil
				mu.Unlock()
			}
			before := time.Now()
			artifacts, err := runReplayScan(t, repo, server.URL, extra...)
			after := time.Now()
			if (err != nil) != (mode == "failed-analysis") {
				t.Fatalf("unexpected scan error: %v", err)
			}
			start, end := invocationTimes(t, filepath.Join(artifacts, "final.sarif"))
			if start.Before(before) || end.After(after) {
				t.Fatalf("invocation [%s, %s] outside command [%s, %s]", start, end, before, after)
			}
			mu.Lock()
			defer mu.Unlock()
			for _, request := range requests {
				if request.Before(start) || request.After(end) {
					t.Fatalf("request at %s outside invocation [%s, %s]", request, start, end)
				}
			}
			if mode == "incomplete-audit" {
				inv := readSARIF(t, filepath.Join(artifacts, "final.sarif")).Runs[0].Invocations[0]
				if !inv.ExecutionSuccessful || len(inv.ToolExecutionNotifications) == 0 {
					t.Fatalf("incomplete-audit status lost: %+v", inv)
				}
			}
			if mode == "failed-analysis" && readSARIF(t, filepath.Join(artifacts, "final.sarif")).Runs[0].Invocations[0].ExecutionSuccessful {
				t.Fatal("failed analysis was marked successful")
			}
			for _, phase := range []string{"analysis", "audit"} {
				path := filepath.Join(artifacts, phase+".sarif")
				if _, err := os.Stat(path); os.IsNotExist(err) {
					continue
				}
				phaseStart, phaseEnd := invocationTimes(t, path)
				if !phaseStart.Equal(start) || phaseEnd.After(end) {
					t.Fatalf("%s interval [%s, %s] outside scan [%s, %s]", phase, phaseStart, phaseEnd, start, end)
				}
			}
		})
	}
}
