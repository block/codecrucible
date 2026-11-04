package provenance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"testing"

	"github.com/block/codecrucible/internal/sarif"
)

func TestLineageRetainsOriginalAndReplaysIdempotently(t *testing.T) {
	var out bytes.Buffer
	l := New("run", &out)
	d := sarif.Build(sarif.AnalysisResult{SecurityIssues: []sarif.SecurityIssue{{Issue: "unsafe query", FilePath: "a.go", StartLine: 1, CWEID: "CWE-89", TechnicalDetails: "original evidence", Severity: 7}}}, sarif.FileMap{"a.go": "query(input)"}, sarif.BuilderConfig{})
	if err := l.Observe("chunk-1", &d); err != nil {
		t.Fatal(err)
	}
	size := out.Len()
	if err := l.Observe("chunk-1", &d); err != nil || out.Len() != size {
		t.Fatal("replay duplicated observation", err)
	}
	d = sarif.AssignFindingIDs(d)
	if err := l.Checkpoint("analysis", &d); err != nil {
		t.Fatal(err)
	}
	original := d.Runs[0].Results[0].Properties.Provenance.RevisionID
	d.Runs[0].Results[0].Properties.TechnicalDetails = "revised evidence"
	if err := l.Checkpoint("audit", &d); err != nil {
		t.Fatal(err)
	}
	if d.Runs[0].Results[0].Properties.Provenance.RevisionID == original {
		t.Fatal("revision overwritten")
	}
	if err := l.Finish(d); err != nil {
		t.Fatal(err)
	}
	var records []Event
	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	for dec.More() {
		var e Event
		if err := dec.Decode(&e); err != nil {
			t.Fatal(err)
		}
		if e.Type != "operation" {
			records = append(records, e)
		}
	}
	if records[0].Result.Properties.TechnicalDetails != "original evidence" {
		t.Fatal("original mutated")
	}
	if records[2].Inputs[0] != original {
		t.Fatal("revision parent missing")
	}
	if records[len(records)-1].Type != "retained" {
		t.Fatal("no disposition")
	}
}
func TestOperationConflictAndWriterFailure(t *testing.T) {
	l := New("run", &bytes.Buffer{})
	d := sarif.Build(sarif.AnalysisResult{SecurityIssues: []sarif.SecurityIssue{{Issue: "a", TechnicalDetails: "one"}}}, nil, sarif.BuilderConfig{})
	if err := l.Observe("request", &d); err != nil {
		t.Fatal(err)
	}
	d.Runs[0].Results[0].Message.Text = "different response"
	if err := l.Observe("request", &d); err == nil {
		t.Fatal("accepted conflicting replay")
	}
}

func TestMergeAndFilterHaveCompleteLineage(t *testing.T) {
	var out bytes.Buffer
	l := New("scan", &out)
	mk := func(file string, sev float64) sarif.SARIFDocument {
		return sarif.Build(sarif.AnalysisResult{SecurityIssues: []sarif.SecurityIssue{{Issue: "same", FilePath: file, StartLine: 1, CWEID: "CWE-89", Severity: sev, TechnicalDetails: "same evidence"}}}, nil, sarif.BuilderConfig{})
	}
	a, b, c := mk("a.go", 7), mk("a.go", 7), mk("package.json", 2)
	for i, d := range []*sarif.SARIFDocument{&a, &b, &c} {
		if err := l.Observe(string(rune('a'+i)), d); err != nil {
			t.Fatal(err)
		}
	}
	merged := sarif.Merge([]sarif.SARIFDocument{a, b, c})
	if len(merged.Runs[0].Results) != 2 || len(merged.Runs[0].Results[0].Properties.Provenance.ObservationIDs) != 2 {
		t.Fatal("merge lost parents")
	}
	if err := l.Checkpoint("merge", &merged); err != nil {
		t.Fatal(err)
	}
	merged = sarif.AssignFindingIDs(sarif.PostProcess(merged))
	if err := l.Checkpoint("analysis", &merged); err != nil {
		t.Fatal(err)
	}
	if err := l.Finish(merged); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	counts := map[string]int{}
	seen := map[string]bool{}
	for dec.More() {
		var e Event
		if err := dec.Decode(&e); err != nil {
			t.Fatal(err)
		}
		for _, id := range e.Inputs {
			if !seen[id] {
				t.Fatalf("dangling or forward edge %s", id)
			}
		}
		seen[e.ID] = true
		counts[e.Type]++
	}
	if counts["observation"] != 3 || counts["retained"] != 2 || counts["filtered"] != 1 || counts["merged_from"] != 1 {
		t.Fatal(counts)
	}
}

type brokenWriter struct{}

func (brokenWriter) Write(p []byte) (int, error) { return 0, io.ErrClosedPipe }
func TestLedgerPropagatesWriteFailure(t *testing.T) {
	l := New("run", brokenWriter{})
	if err := l.Metadata("start", nil); err == nil {
		t.Fatal("ignored write failure")
	}
	if err := l.Metadata("complete", nil); err == nil {
		t.Fatal("cleared write failure")
	}
}

func TestConcurrentObservationIdentityDoesNotDependOnCompletionOrder(t *testing.T) {
	var out bytes.Buffer
	l := New("run", &out)
	const count = 24
	docs := make([]sarif.SARIFDocument, count)
	var wg sync.WaitGroup
	for i := range docs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			docs[i] = sarif.Build(sarif.AnalysisResult{SecurityIssues: []sarif.SecurityIssue{{Issue: "unsafe query", FilePath: fmt.Sprintf("%d.go", i)}}}, nil, sarif.BuilderConfig{})
			if err := l.Observe(fmt.Sprintf("chunk/%d", i), &docs[i]); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	// Reproduce the same operations in a deterministic reverse order.
	other := New("run", nil)
	for i := count - 1; i >= 0; i-- {
		want := docs[i].Runs[0].Results[0].Properties.Provenance.RevisionID
		if err := other.Observe(fmt.Sprintf("chunk/%d", i), &docs[i]); err != nil {
			t.Fatal(err)
		}
		if docs[i].Runs[0].Results[0].Properties.Provenance.RevisionID != want {
			t.Fatal("completion order changed identity")
		}
	}
	if lines := bytes.Count(out.Bytes(), []byte{'\n'}); lines != count*2 {
		t.Fatalf("concurrent writes lost observations: %d", lines)
	}
}

func TestCheckpointRejectsUnknownParent(t *testing.T) {
	l := New("run", nil)
	d := sarif.Build(sarif.AnalysisResult{SecurityIssues: []sarif.SecurityIssue{{Issue: "a"}}}, nil, sarif.BuilderConfig{})
	d.Runs[0].Results[0].Properties.Provenance = &sarif.FindingProvenance{RunID: "run", RevisionID: "missing"}
	if err := l.Checkpoint("audit", &d); err == nil {
		t.Fatal("allowed dangling graph reference")
	}
}
