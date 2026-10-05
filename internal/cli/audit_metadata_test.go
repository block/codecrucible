package cli

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/sarif"
)

func TestAuditMetadataSurvivesPresentation(t *testing.T) {
	for _, verdict := range []string{"confirmed", "refined", "unverified", "rejected", "missing"} {
		t.Run(verdict, func(t *testing.T) {
			doc := sarif.WithFindingIDs(sarif.Build(sarif.AnalysisResult{SecurityIssues: []sarif.SecurityIssue{{Issue: "Unsafe query", TechnicalDetails: "Input reaches the query.", Summary: "An attacker controls the query.", Severity: 8}}}, nil, sarif.BuilderConfig{}))
			id := doc.Runs[0].Results[0].Properties.FindingID
			gates := []sarif.AuditGate{{ID: "reachability", Status: "unknown", Reason: "Caller unavailable"}}
			af := AuditedFinding{FindingID: id, Verdict: verdict, Confidence: .7, ClaimCoverage: "complete", Justification: "GATE 1: caller unavailable", AuditGates: gates, RefinedTechnicalDetails: "Input reaches a SQL query."}
			audit := AuditResult{}
			if verdict != "missing" {
				audit.AuditedFindings = []AuditedFinding{af}
			}
			before, _ := json.Marshal(doc)
			got := sarif.ReviewPresentation(applyAuditVerdicts(doc, audit, ingest.FileMap{}, .3))
			after, _ := json.Marshal(doc)
			if string(before) != string(after) {
				t.Fatal("original snapshot mutated")
			}
			r := got.Runs[0].Results[0]
			p := r.Properties
			if p.FindingID != id || r.Message.Text != "Unsafe query" {
				t.Fatal("identity or clean title lost")
			}
			rule := got.Runs[0].Tool.Driver.Rules[0]
			if strings.Contains(rule.Help.Text+rule.Help.Markdown+rule.FullDescription.Text, "GATE 1") {
				t.Fatal("audit deliberation leaked into description")
			}
			if verdict == "missing" {
				if p.AuditStatus != "not_audited" || p.AuditConfidence != nil || !reflect.DeepEqual(p.AuditReasons, []string{"missing_verdict"}) {
					t.Fatalf("missing audit misrepresented: %+v", p)
				}
				return
			}
			if p.AuditJustification != af.Justification || !reflect.DeepEqual(p.AuditGates, gates) || p.AuditConfidence == nil || *p.AuditConfidence != .7 {
				t.Fatalf("audit metadata lost: %+v", p)
			}
			var revision AuditedFinding
			if err := json.Unmarshal(p.AuditRevision, &revision); err != nil || !reflect.DeepEqual(revision.AuditGates, gates) {
				t.Fatal("original audit revision lost", err)
			}
			if verdict == "rejected" && (p.AuditStatus != "unverified" || !reflect.DeepEqual(p.AuditReasons, []string{"ungrounded_rejection"}) || revision.Verdict != "rejected") {
				t.Fatal("effective verdict and proposed rejection conflated")
			}
		})
	}
}
