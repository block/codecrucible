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

// additionsAllowedLoader returns a legacy prompt set that leaves the audit free
// to add findings. The default set does not, so tests of how additions are
// deduplicated and recorded must use a set that keeps them.
func additionsAllowedLoader(t *testing.T) *llm.PromptLoader {
	t.Helper()
	loader := llm.NewPromptLoader(os.DirFS("../../prompts/exploit-proof"))
	prompt, err := loader.LoadAuditPrompt()
	if err != nil || !prompt.AllowsNewFindings() || prompt.Contract != "" {
		t.Fatalf("exploit-proof is no longer a legacy set that allows additions: %v", err)
	}
	return loader
}

func TestAuditAdditionPolicyPreservesCandidateLineage(t *testing.T) {
	for _, tc := range []struct {
		set     string
		allowed bool
	}{{"exploit-proof", true}, {"default", false}} {
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
				t.Fatal("a set that allows additions discarded a candidate")
			}
			if !tc.allowed && (discarded != 1 || filtered != 1) {
				t.Fatalf("discarded=%d filtered=%d", discarded, filtered)
			}
		})
	}
}

// TestDefaultAuditCannotAddFindings runs the real default prompt set against a
// model that ignores the schema and returns additions anyway. The default
// audit may only judge the claims it was given; a set that opts in keeps
// additions, and the other legacy-set behavior is unchanged.
func TestDefaultAuditCannotAddFindings(t *testing.T) {
	for _, tc := range []struct {
		name        string
		loader      *llm.PromptLoader
		allowed     bool
		wantResults int
		wantDropped int
	}{
		{"default", llm.NewPromptLoader(os.DirFS("../../prompts/default")), false, 2, 3},
		{"opted in", additionsAllowedLoader(t), true, 4, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mustAuditPrompt(t, tc.loader).AllowsNewFindings(); got != tc.allowed {
				t.Fatalf("AllowsNewFindings = %v, want %v", got, tc.allowed)
			}
			calls := 0
			client := auditClientFunc(func(_ context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
				calls++
				if limited := strings.Contains(string(*req.ResponseSchema), `"maxItems": 0`); limited == tc.allowed {
					t.Fatalf("schema limit=%v with additions allowed=%v", limited, tc.allowed)
				}
				extra := NewFinding{Issue: "Extra", FilePath: "a.go", StartLine: 1, Severity: 8, Confidence: .9}
				// Two copies of one addition and a different one, so the counter
				// reflects what the model returned, not what survived dedup.
				data, _ := json.Marshal(AuditResult{
					AuditedFindings: []AuditedFinding{{OriginalIssue: "First", FilePath: "a.go", StartLine: 1, Verdict: "confirmed", Confidence: .9}, {OriginalIssue: "Second", FilePath: "b.go", StartLine: 1, Verdict: "confirmed", Confidence: .9}},
					NewFindings:     []NewFinding{extra, extra, {Issue: "Another", FilePath: "b.go", StartLine: 1, Severity: 5, Confidence: .9}},
				})
				return &llm.ChatResponse{Content: string(data)}, nil
			})
			metadata := &sarif.ScanMetadata{}
			got, _, _, err := runAuditPhase(context.Background(), auditFixture(), "fixture", client, "", config.ModelConfig{Name: "test"}, tc.loader, llm.OutputModeNone,
				ingest.FileMap{"a.go": "sink()", "b.go": "sink()"}, .3, nil, "", 20, true, chunk.NewTokenCounter("", nil), metadata, nil)
			if err != nil || got == nil {
				t.Fatal(err)
			}
			added := 0
			for _, r := range got.Runs[0].Results {
				if r.Properties.AuditStatus == "new" {
					added++
				}
			}
			wantAdded := tc.wantResults - 2
			if calls != 1 || len(got.Runs[0].Results) != tc.wantResults || added != wantAdded || metadata.Execution.AuditAdditionsDropped != tc.wantDropped {
				t.Fatalf("calls=%d results=%d added=%d dropped=%d", calls, len(got.Runs[0].Results), added, metadata.Execution.AuditAdditionsDropped)
			}
			encoded, _ := json.Marshal(metadata.Execution)
			if has := strings.Contains(string(encoded), `"auditAdditionsDropped":3`); has != (tc.wantDropped == 3) {
				t.Fatalf("auditAdditionsDropped serialization: %s", encoded)
			}
			if tc.allowed && strings.Contains(string(encoded), "auditAdditionsDropped") {
				t.Fatal("zero counter must be omitted")
			}
		})
	}
}

func mustAuditPrompt(t *testing.T, loader *llm.PromptLoader) *llm.AuditPrompt {
	t.Helper()
	prompt, err := loader.LoadAuditPrompt()
	if err != nil {
		t.Fatal(err)
	}
	return prompt
}
