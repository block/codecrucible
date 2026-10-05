package cli

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/decision"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/sarif"
)

func classificationFixture() (*scanDecisions, sarif.SARIFDocument) {
	files := map[string]string{"query.go": "package app\nfunc query(input string) {\n sql := \"SELECT * FROM records WHERE id = \" + input\n db.Query(sql)\n}\n"}
	doc := sarif.WithFindingIDs(sarif.Build(sarif.AnalysisResult{SecurityIssues: []sarif.SecurityIssue{{Issue: "SQL injection", FilePath: "query.go", StartLine: 4, EndLine: 4, TechnicalDetails: "An SQL query concatenates untrusted input into the command.", Severity: 8, CWEID: "CWE-79"}}}, sarif.FileMap(files), sarif.BuilderConfig{}))
	d := &scanDecisions{cfg: config.Decisions{CWEMapping: "active", MaxCalls: 128}, files: files, graph: map[string][]string{}, recorder: &decision.Recorder{}}
	return d, doc
}

func TestCWEMappingModesAndFallbacks(t *testing.T) {
	for _, tc := range []struct {
		name, mode, choice    string
		low, failure, missing bool
		want                  string
		changed               bool
	}{
		{name: "mapped", mode: "active", choice: "CWE-89", want: "mapped", changed: true},
		{name: "shadow", mode: "shadow", choice: "CWE-89"},
		{name: "off", mode: "off"},
		{name: "low certainty", mode: "active", choice: "CWE-89", low: true, want: "insufficient_evidence"},
		{name: "unknown candidate", mode: "active", choice: "CWE-999999", want: "insufficient_evidence"},
		{name: "no candidate fits", mode: "active", choice: "none_of_these", want: "outside_candidates"},
		{name: "uncertain", mode: "active", choice: "insufficient_evidence", want: "insufficient_evidence"},
		{name: "provider failure", mode: "active", failure: true, want: "unavailable"},
		{name: "missing source", mode: "active", missing: true, want: "insufficient_evidence"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, doc := classificationFixture()
			d.cfg.CWEMapping = tc.mode
			if tc.missing {
				d.files = nil
			}
			before, _ := json.Marshal(doc)
			calls := 0
			d.recorder.Client = evaluateFunc(func(_ context.Context, r decision.Request) (decision.Response, error) {
				calls++
				if tc.failure {
					return decision.Response{}, errors.New("unavailable")
				}
				if _, ok := r.Questions["primary_cwe"].Criteria.(map[string]string)["CWE-89"]; !ok {
					t.Fatal("retrieval missed SQL injection")
				}
				out := answersFor(r, map[string]string{"primary_cwe": tc.choice})
				if tc.low {
					a := out.Answers["primary_cwe"]
					a.Probabilities[tc.choice] = .6
					out.Answers["primary_cwe"] = a
				}
				return out, nil
			})
			out, err := d.mapCWEs(context.Background(), doc)
			if err != nil {
				t.Fatal(err)
			}
			if tc.mode == "shadow" || tc.mode == "off" {
				if !reflect.DeepEqual(out, doc) {
					t.Fatal("observational mode changed output")
				}
			} else {
				p := out.Runs[0].Results[0].Properties
				if p.DecisionCWE.Status != tc.want || p.DecisionCWE.Applied != tc.changed {
					t.Fatalf("assessment %+v", p.DecisionCWE)
				}
				if p.FindingID != doc.Runs[0].Results[0].Properties.FindingID || len(out.Runs[0].Results) != 1 {
					t.Fatal("finding lost or identity changed")
				}
				if tc.changed && len(p.CWEChanges) != 1 {
					t.Fatal("missing original classification")
				}
			}
			if (tc.mode == "off" || tc.missing) && calls != 0 {
				t.Fatal("unnecessary model call")
			}
			after, _ := json.Marshal(doc)
			if string(before) != string(after) {
				t.Fatal("mutated original")
			}
		})
	}
}

func TestCWEMappingReviewRequiredIsOnlyProposed(t *testing.T) {
	d, doc := classificationFixture()
	// The existing mappable Class entry is always included even if retrieval is poor.
	doc = sarif.ApplyCWEAssignments(doc, map[string]sarif.CWEAssignment{doc.Runs[0].Results[0].Properties.FindingID: {ID: "CWE-862", Source: "fixture"}})
	d.recorder.Client = evaluateFunc(func(_ context.Context, r decision.Request) (decision.Response, error) {
		return answersFor(r, map[string]string{"primary_cwe": "CWE-862"}), nil
	})
	out, err := d.mapCWEs(context.Background(), doc)
	if err != nil || out.Runs[0].Results[0].Properties.DecisionCWE.Status != "review_required" || out.Runs[0].Results[0].Properties.DecisionCWE.Applied {
		t.Fatal("review-required mapping applied")
	}
}

func TestAuditAppliesCWERefinement(t *testing.T) {
	_, doc := classificationFixture()
	id := doc.Runs[0].Results[0].Properties.FindingID
	out := applyAuditVerdicts(doc, AuditResult{AuditedFindings: []AuditedFinding{{FindingID: id, Verdict: "refined", ClaimCoverage: "complete", Confidence: .9, RefinedCWEID: "CWE-89", RefinedTechnicalDetails: "SQL injection"}}}, ingest.FileMap{}, .3)
	if sarif.CWEForRule(out.Runs[0].Tool.Driver.Rules[0]) != "CWE-89" || out.Runs[0].Results[0].Properties.CWEChanges[0].Source != "generative_audit" {
		t.Fatal("ignored refined CWE")
	}
}
