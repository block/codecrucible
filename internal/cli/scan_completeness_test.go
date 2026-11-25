package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestStrictCoverageScan(t *testing.T) {
	for _, mode := range []string{"complete", "skip-audit", "failed-analysis", "incomplete-audit", "replay", "unverified", "oversized", "excluded"} {
		t.Run(mode, func(t *testing.T) {
			repo := t.TempDir()
			content := replaySource
			if mode == "oversized" {
				content = strings.Repeat("var example = 123456789\n", 20000)
			}
			if err := os.WriteFile(filepath.Join(repo, "app.go"), []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			state := &replayServer{}
			handler := state.handler(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewReader(body))
				if mode == "failed-analysis" || mode == "incomplete-audit" && bytes.Contains(body, []byte("claims_to_verify")) {
					http.Error(w, "unsupported request", http.StatusBadRequest)
					return
				}
				if mode == "unverified" {
					recorder := httptest.NewRecorder()
					handler(recorder, r)
					w.Write(bytes.ReplaceAll(recorder.Body.Bytes(), []byte(`confirmed`), []byte(`unverified`)))
				} else {
					handler(w, r)
				}
			}))
			defer server.Close()
			extra := []string{"--fail-on-incomplete"}
			if mode == "oversized" {
				extra = append(extra, "--context-limit", "10000", "--max-file-size", "1000000")
			}
			if mode == "excluded" {
				extra = append(extra, "--exclude", "app.go")
			}
			if mode == "skip-audit" {
				extra = append(extra, "--skip-audit")
			}
			if mode == "replay" {
				first, err := runReplayScan(t, repo, server.URL)
				if err != nil {
					t.Fatal(err)
				}
				extra = append(extra, "--audit-from", filepath.Join(first, "analysis.sarif"))
			}
			artifacts, err := runReplayScan(t, repo, server.URL, extra...)
			incomplete := mode == "failed-analysis" || mode == "incomplete-audit" || mode == "oversized"
			if errors.Is(err, ErrIncompleteScan) != incomplete || !incomplete && err != nil {
				t.Fatalf("err=%v", err)
			}
			doc := readSARIF(t, filepath.Join(artifacts, "final.sarif"))
			if !doc.Runs[0].Properties.CodeCrucible.Recipe.Controls.FailOnIncomplete {
				t.Fatal("missing recorded strict policy")
			}
			cmd := &cobra.Command{Use: "test", RunE: func(*cobra.Command, []string) error { return err }}
			code := executeCommand(cmd, &bytes.Buffer{})
			want := 0
			if incomplete {
				want = 4
			}
			if code != want {
				t.Fatalf("exit=%d want=%d", code, want)
			}
		})
	}
}

func TestIncompleteExitSurvivesWrapping(t *testing.T) {
	cmd := &cobra.Command{Use: "test", RunE: func(*cobra.Command, []string) error { return fmt.Errorf("scan: %w", ErrIncompleteScan) }}
	if code := executeCommand(cmd, &bytes.Buffer{}); code != 4 {
		t.Fatalf("exit=%d", code)
	}
}
