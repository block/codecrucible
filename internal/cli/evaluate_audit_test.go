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
	if got.Missing != 1 || got.InvalidConfirmed.Count != 1 || got.PositiveSuppressed.Count != 2 || got.UnsupportedImpactConfirmed.Count != 1 || got.DuplicatePrecision.Count != 1 {
		t.Fatal(got)
	}
	if got.DuplicatePrecision.Low >= .99 || math.IsNaN(got.DuplicatePrecision.Low) {
		t.Fatal("one pair was treated as conclusive", got)
	}
}
