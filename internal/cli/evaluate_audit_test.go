package cli

import (
	"github.com/block/codecrucible/internal/sarif"
	"math"
	"testing"
)

func TestScoreAuditReportsLossAndUncertainty(t *testing.T) {
	doc := sarif.SARIFDocument{Runs: []sarif.SARIFRun{{Results: []sarif.SARIFResult{
		{Properties: &sarif.FindingProperties{FindingID: "a", AuditStatus: "confirmed", SemanticDuplicates: []string{"b"}}},
		{Properties: &sarif.FindingProperties{FindingID: "b", AuditStatus: "rejected"}, Suppressions: []sarif.SARIFSuppression{{Kind: "external"}}},
	}}}}
	labels := auditEvalLabels{Cases: []auditEvalCase{{FindingID: "a", Weakness: "invalid", Impact: "unsupported"}, {FindingID: "b", Weakness: "valid"}, {FindingID: "missing", Weakness: "valid"}}, Pairs: []auditEvalPair{{Left: "b", Right: "a", Duplicate: true}}}
	got, err := scoreAudit(doc, labels)
	if err != nil {
		t.Fatal(err)
	}
	if got.Missing != 1 || got.InvalidConfirmed.Count != 1 || got.PositiveSuppressed.Count != 1 || got.UnsupportedImpactConfirmed.Count != 1 || got.DuplicatePrecision.Count != 1 {
		t.Fatal(got)
	}
	if got.DuplicatePrecision.Low >= .99 || math.IsNaN(got.DuplicatePrecision.Low) {
		t.Fatal("one pair was treated as conclusive", got)
	}
}

func TestScoreAuditCountsEveryActiveVerdict(t *testing.T) {
	for _, status := range []string{"confirmed", "refined", "escalated", "unverified", "not_audited", "new", "rejected", ""} {
		t.Run(status, func(t *testing.T) {
			doc := sarif.SARIFDocument{Runs: []sarif.SARIFRun{{Results: []sarif.SARIFResult{{Properties: &sarif.FindingProperties{FindingID: "junk", AuditStatus: status}}}}}}
			got, err := scoreAudit(doc, auditEvalLabels{Cases: []auditEvalCase{{FindingID: "junk", Weakness: "invalid", Impact: "unsupported"}}})
			if err != nil || got.InvalidConfirmed.Count != 1 || got.UnsupportedImpactConfirmed.Count != 1 {
				t.Fatalf("active junk omitted: %+v %v", got, err)
			}
		})
	}
}

func TestScoreAuditSeparatesRecallMissFromSuppression(t *testing.T) {
	doc := sarif.SARIFDocument{Runs: []sarif.SARIFRun{{Results: []sarif.SARIFResult{
		{Properties: &sarif.FindingProperties{FindingID: "kept", AuditStatus: "unverified"}},
		{Properties: &sarif.FindingProperties{FindingID: "suppressed", AuditStatus: "rejected"}, Suppressions: []sarif.SARIFSuppression{{Kind: "external"}}},
	}}}}
	got, err := scoreAudit(doc, auditEvalLabels{Cases: []auditEvalCase{{FindingID: "kept", Weakness: "valid"}, {FindingID: "suppressed", Weakness: "valid"}, {FindingID: "absent", Weakness: "valid"}}})
	if err != nil || got.RecallMisses != 1 || got.PositiveSuppressed.Count != 1 || got.Recall.Count != 1 || got.Recall.Total != 3 || got.Recall.Rate != 1.0/3 {
		t.Fatalf("incorrect recall accounting: %+v %v", got, err)
	}
}
