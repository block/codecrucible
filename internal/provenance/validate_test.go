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
