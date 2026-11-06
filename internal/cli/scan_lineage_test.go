package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/provenance"
	"github.com/block/codecrucible/internal/sarif"
)

func TestScanLineageReconcilesFinalAndReplay(t *testing.T) {
	server := &replayServer{}
	srv := httptest.NewServer(server.handler(t))
	defer srv.Close()
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "app.go"), []byte(replaySource), 0600); err != nil {
		t.Fatal(err)
	}
	first, err := runReplayScan(t, repo, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	second, err := runReplayScan(t, repo, srv.URL, "--audit-from", filepath.Join(first, "analysis.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{first, second} {
		f, err := os.Open(filepath.Join(dir, "lineage.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		stat, _ := f.Stat()
		if stat.Mode().Perm() != 0600 {
			t.Fatal("lineage permissions", stat.Mode())
		}
		dec := json.NewDecoder(f)
		nodes := map[string]provenance.Event{}
		observations, terminal := 0, 0
		complete := false
		for dec.More() {
			var e provenance.Event
			if err := dec.Decode(&e); err != nil {
				t.Fatal(err)
			}
			if _, ok := nodes[e.ID]; ok {
				t.Fatal("duplicate lineage event")
			}
			for _, input := range e.Inputs {
				if _, ok := nodes[input]; !ok {
					t.Fatal("unresolved input", input)
				}
			}
			nodes[e.ID] = e
			if e.Type == "observation" {
				observations++
			}
			if e.Type == "retained" || e.Type == "suppressed" || e.Type == "filtered" {
				terminal++
			}
			if e.Operation == "run-complete" {
				complete = true
			}
		}
		doc := readSARIF(t, filepath.Join(dir, "final.sarif"))
		for _, r := range doc.Runs[0].Results {
			p := r.Properties.Provenance
			if p == nil {
				t.Fatal("missing provenance")
			}
			e, ok := nodes[p.RevisionID]
			if !ok || e.FindingID != r.Properties.FindingID {
				t.Fatal("final cannot reconcile to ledger")
			}
		}
		if observations != 2 || terminal != 2 || !complete {
			t.Fatalf("observations=%d terminal=%d complete=%v", observations, terminal, complete)
		}
	}
}

func TestAuditAddedCandidatesHaveStableLedgerIdentities(t *testing.T) {
	doc := sarif.Build(sarif.AnalysisResult{}, nil, sarif.BuilderConfig{})
	doc = applyAuditVerdicts(doc, AuditResult{NewFindings: []NewFinding{
		{Issue: "unsafe query", FilePath: "a.go", StartLine: 1, Confidence: .9},
		{Issue: "possible unsafe query", FilePath: "b.go", StartLine: 1, Confidence: .1},
	}}, ingest.FileMap{}, .5)
	var out bytes.Buffer
	l := provenance.New("run", &out)
	if err := checkpointAudit(l, &doc); err != nil {
		t.Fatal(err)
	}
	size := out.Len()
	if err := checkpointAudit(l, &doc); err != nil || out.Len() != size {
		t.Fatal("checkpoint replay changed identities", err)
	}
	if err := l.Finish(doc); err != nil {
		t.Fatal(err)
	}
	nodes := map[string]provenance.Event{}
	counts := map[string]int{}
	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	for dec.More() {
		var e provenance.Event
		if err := dec.Decode(&e); err != nil {
			t.Fatal(err)
		}
		nodes[e.ID] = e
		counts[e.Type]++
	}
	for _, r := range doc.Runs[0].Results {
		if r.Properties.FindingID == "" || nodes[r.Properties.Provenance.RevisionID].FindingID != r.Properties.FindingID {
			t.Fatal("new audit finding cannot reconcile to ledger")
		}
	}
	if counts["observation"] != 2 || counts["retained"] != 1 || counts["suppressed"] != 1 {
		t.Fatal(counts)
	}
}

type failedLineageWriter struct{ short bool }

func (w failedLineageWriter) Write(p []byte) (int, error) {
	if w.short {
		return len(p) - 1, nil
	}
	return 0, fmt.Errorf("injected ledger failure")
}
func TestScanWritesSARIFDespiteLineageFailure(t *testing.T) {
	for _, short := range []bool{false, true} {
		t.Run(fmt.Sprint(short), func(t *testing.T) {
			old := lineageWriter
			defer func() { lineageWriter = old }()
			lineageWriter = func(io.Writer) io.Writer { return failedLineageWriter{short} }
			server := &replayServer{}
			srv := httptest.NewServer(server.handler(t))
			defer srv.Close()
			repo := t.TempDir()
			if err := os.WriteFile(filepath.Join(repo, "app.go"), []byte(replaySource), 0600); err != nil {
				t.Fatal(err)
			}
			oldExit := exitFunc
			defer func() { exitFunc = oldExit }()
			code := 0
			exitFunc = func(c int) { code = c }
			threshold := "10"
			want := 0
			if short {
				threshold = "1"
				want = exitCodeFindings
			}
			dir, err := runReplayScan(t, repo, srv.URL, "--fail-on-severity", threshold)
			if code != want {
				t.Fatalf("exit=%d want=%d", code, want)
			}
			if err != nil {
				t.Fatal(err)
			}
			doc := readSARIF(t, filepath.Join(dir, "final.sarif"))
			if !doc.Runs[0].Properties.CodeCrucible.Execution.LineageIncomplete {
				t.Fatal("missing lineage diagnostic")
			}
			if len(doc.Runs[0].Results) == 0 {
				t.Fatal("lost results")
			}
		})
	}
}
