package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/block/codecrucible/internal/chunk"
	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/llm"
	"github.com/block/codecrucible/internal/provenance"
	"github.com/block/codecrucible/internal/sarif"
)

func TestAuditAdditionPolicyPreservesCandidateLineage(t *testing.T) {
	for _, tc := range []struct {
		set     string
		allowed bool
	}{{"default", true}, {"reasoning", false}} {
		t.Run(tc.set, func(t *testing.T) {
			var buf bytes.Buffer
			ledger := provenance.New("addition-policy", &buf)
			doc := sarif.AssignFindingIDs(auditFixture())
			if err := ledger.Observe("input", &doc); err != nil {
				t.Fatal(err)
			}
			if err := ledger.Checkpoint("analysis", &doc); err != nil {
				t.Fatal(err)
			}
			client := auditClientFunc(func(_ context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
				if limited := strings.Contains(string(*req.ResponseSchema), `"maxItems": 0`); limited == tc.allowed {
					t.Fatalf("schema limit=%v, allowed=%v", limited, tc.allowed)
				}
				var verdicts []AuditedFinding
				for _, id := range claimIDs(t, req) {
					verdicts = append(verdicts, AuditedFinding{FindingID: id, Verdict: "confirmed", Confidence: .9})
				}
				// Deliberately violate the disabled-additions schema, as an endpoint
				// without native structured-output enforcement can do.
				b, _ := json.Marshal(AuditResult{AuditedFindings: verdicts, NewFindings: []NewFinding{{Issue: "Different cause", FilePath: "a.go", StartLine: 1, EndLine: 1, CWEID: "CWE-20", Severity: 5, TechnicalDetails: "candidate evidence", Confidence: .9}}})
				return &llm.ChatResponse{Content: string(b), FinishReason: "stop"}, nil
			})
			got, _, _, err := runAuditPhase(context.Background(), doc, "fixture", traceClient(client, ledger, "audit"), "", config.ModelConfig{Name: "test"},
				llm.NewPromptLoader(os.DirFS("../../prompts/"+tc.set)), llm.OutputModeNone, ingest.FileMap{"a.go": "input()\nsink()", "b.go": "input()\nsink()"}, .3, nil, "", 2, true, chunk.NewTokenCounter("", nil), nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			want := len(doc.Runs[0].Results)
			if tc.allowed {
				want++
			}
			if len(got.Runs[0].Results) != want {
				t.Fatalf("results=%d, want %d", len(got.Runs[0].Results), want)
			}
			if err := ledger.Finish(*got); err != nil {
				t.Fatal(err)
			}
			if err := ledger.Metadata("run-complete", &sarif.ScanMetadata{}); err != nil {
				t.Fatal(err)
			}
			v, err := provenance.Validate(bytes.NewReader(buf.Bytes()), got)
			if err != nil || !v.Complete || v.Observations != 3 {
				t.Fatalf("validation=%+v error=%v", v, err)
			}
			discarded, filtered := 0, 0
			for _, line := range bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte{'\n'}) {
				var e provenance.Event
				if err := json.Unmarshal(line, &e); err != nil {
					t.Fatal(err)
				}
				if e.Type == "discarded" && e.Reason == "audit_discovery_disabled" {
					discarded++
				}
				if e.Type == "filtered" {
					filtered++
				}
			}
			if tc.allowed && (discarded != 0 || filtered != 0) {
				t.Fatal("default discarded a candidate")
			}
			if !tc.allowed && (discarded != 1 || filtered != 1) {
				t.Fatalf("discarded=%d filtered=%d", discarded, filtered)
			}
		})
	}
}
