package provenance

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/block/codecrucible/internal/auditcore"
	"github.com/block/codecrucible/internal/sarif"
)

func TestProducerPrecedesResponseAndReplay(t *testing.T) {
	var out bytes.Buffer
	l := New("run", &out)
	p, err := l.BeginRequest("analysis", "chunk", auditcore.Producer{RequestedModel: "model", PromptFingerprint: "prompt", SchemaFingerprint: "schema"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), p.AttemptID) || strings.Contains(out.String(), `"type":"model_response"`) {
		t.Fatal("attempt was not persisted before response")
	}
	if err = l.CompleteRequest(p, Exchange{Content: "malformed"}); err != nil {
		t.Fatal(err)
	}
	producer, err := l.Transform(p.ResponseID, "local-json-repair", "{}")
	if err != nil {
		t.Fatal(err)
	}
	doc := sarif.Build(sarif.AnalysisResult{SecurityIssues: []sarif.SecurityIssue{{Issue: "a"}}}, nil, sarif.BuilderConfig{})
	doc.ProducerID = producer
	if err = l.Observe("chunk", &doc); err != nil {
		t.Fatal(err)
	}
	size := out.Len()
	if err = l.Observe("other label", &doc); err != nil || size != out.Len() {
		t.Fatal("response replay created observations", err)
	}
	report, err := Validate(bytes.NewReader(out.Bytes()), nil)
	if err != nil || report.Complete || len(report.Unresolved) != 1 {
		t.Fatal(report, err)
	}
}
func TestValidatorRejectsCorruptionAndReadsV1(t *testing.T) {
	event := Event{Version: 1, RunID: "old", Operation: "legacy/observation", Type: "observation"}
	event.ID = "EV-" + digest([]string{event.RunID, event.Operation})
	b, _ := json.Marshal(event)
	v, err := Validate(bytes.NewReader(b), nil)
	if err != nil || v.Observations != 1 || v.Complete {
		t.Fatal(v, err)
	}
	event.Inputs = []string{"not-there"}
	b, _ = json.Marshal(event)
	if _, err := Validate(bytes.NewReader(b), nil); err == nil {
		t.Fatal("accepted dangling reference")
	}
	event.Inputs = nil
	event.Version = 99
	b, _ = json.Marshal(event)
	if _, err := Validate(bytes.NewReader(b), nil); err == nil {
		t.Fatal("accepted unknown version")
	}
}
func TestFinishKeepsObservationVisibleWhenOneChildSurvives(t *testing.T) {
	var out bytes.Buffer
	l := New("run", &out)
	doc := sarif.AssignFindingIDs(sarif.Build(sarif.AnalysisResult{SecurityIssues: []sarif.SecurityIssue{{Issue: "parent"}}}, nil, sarif.BuilderConfig{}))
	if err := l.Observe("parent", &doc); err != nil {
		t.Fatal(err)
	}
	parent := *doc.Runs[0].Results[0].Properties.Provenance
	child := sarif.AssignFindingIDs(sarif.Build(sarif.AnalysisResult{SecurityIssues: []sarif.SecurityIssue{{Issue: "child", CWEID: "CWE-89"}}}, nil, sarif.BuilderConfig{}))
	if err := l.Child("child", "", parent, &child); err != nil {
		t.Fatal(err)
	}
	doc.Runs[0].Results[0].Suppressions = []sarif.SARIFSuppression{{Kind: "external"}}
	doc.Runs[0].Results = append(doc.Runs[0].Results, child.Runs[0].Results[0])
	if err := l.Checkpoint("audit", &doc); err != nil {
		t.Fatal(err)
	}
	if err := l.Finish(doc); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(&out)
	last := Event{}
	for dec.More() {
		if err := dec.Decode(&last); err != nil {
			t.Fatal(err)
		}
	}
	if last.Type != "retained" {
		t.Fatal("visible child marked suppressed", last)
	}
}

func TestRunCompleteWithIncompleteLineageIsPartial(t *testing.T) {
	for _, tc := range []struct {
		name     string
		metadata *sarif.ScanMetadata
		partial  bool
	}{
		{name: "legacy completion"},
		{name: "explicit complete", metadata: &sarif.ScanMetadata{}},
		{name: "dropped disposition", metadata: &sarif.ScanMetadata{Execution: sarif.ScanExecution{LineageIncomplete: true}}, partial: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			l := New("run", &out)
			doc := sarif.AssignFindingIDs(sarif.Build(sarif.AnalysisResult{SecurityIssues: []sarif.SecurityIssue{{Issue: "undisposed", FilePath: "app.go", StartLine: 1}}}, nil, sarif.BuilderConfig{}))
			if err := l.Observe("analysis", &doc); err != nil {
				t.Fatal(err)
			}
			if err := l.Checkpoint("final", &doc); err != nil {
				t.Fatal(err)
			}
			if err := l.Metadata("run-complete", tc.metadata); err != nil {
				t.Fatal(err)
			}
			report, err := Validate(bytes.NewReader(out.Bytes()), &doc)
			if !tc.partial {
				if err == nil || !strings.Contains(err.Error(), "undisposed observations") {
					t.Fatalf("complete ledger lost strict disposition check: %+v %v", report, err)
				}
				return
			}
			if err != nil || report.Complete || len(report.Unresolved) != 1 {
				t.Fatalf("expected partial ledger: %+v %v", report, err)
			}
			// A partial flag must not excuse a final finding that cannot reconcile.
			doc.Runs[0].Results[0].Properties.Provenance.RevisionID = "missing"
			if _, err := Validate(bytes.NewReader(out.Bytes()), &doc); err == nil {
				t.Fatal("partial flag bypassed reconciliation")
			}
		})
	}
}

func TestTruncatedFinalRecordPreservesPrefixAndStrictReconciliation(t *testing.T) {
	var out bytes.Buffer
	l := New("run", &out)
	doc := sarif.AssignFindingIDs(sarif.Build(sarif.AnalysisResult{SecurityIssues: []sarif.SecurityIssue{{Issue: "undisposed", FilePath: "app.go", StartLine: 1}}}, nil, sarif.BuilderConfig{}))
	if err := l.Observe("analysis", &doc); err != nil {
		t.Fatal(err)
	}
	if err := l.Checkpoint("audit", &doc); err != nil {
		t.Fatal(err)
	}
	prefix := append([]byte{}, out.Bytes()...)
	for _, ending := range []string{`{"version":2,"operation":"retained`, "{\"version\":2,\n", "{\"version\":2,\"operation\":\"retained\n", "not-json\n"} {
		torn := append(append([]byte{}, prefix...), []byte(ending)...)
		report, err := Validate(bytes.NewReader(torn), &doc)
		if err != nil || report.Complete || len(report.Unresolved) != 1 || len(report.Reasons) != 1 || report.Reasons[0] != "truncated final record" {
			t.Fatalf("prefix lost: %+v %v", report, err)
		}
		broken := doc
		broken.Runs = append([]sarif.SARIFRun{}, doc.Runs...)
		broken.Runs[0].Results = append([]sarif.SARIFResult{}, doc.Runs[0].Results...)
		props := *broken.Runs[0].Results[0].Properties
		prov := *props.Provenance
		prov.RevisionID = "missing"
		props.Provenance = &prov
		broken.Runs[0].Results[0].Properties = &props
		if _, err := Validate(bytes.NewReader(torn), &broken); err == nil {
			t.Fatal("truncated ledger bypassed reconciliation")
		}
	}
	// A truncated object followed by a valid record must never be accepted.
	middle := append(append([]byte{}, prefix...), []byte("{\"version\":2,\n")...)
	middle = append(middle, bytes.Split(prefix, []byte("\n"))[0]...)
	if _, err := Validate(bytes.NewReader(middle), nil); err == nil {
		t.Fatal("accepted corruption in middle")
	}
	if _, err := Validate(strings.NewReader(string(prefix)+"not-json\n"+string(prefix)), nil); err == nil {
		t.Fatal("accepted malformed record before later content")
	}
}
