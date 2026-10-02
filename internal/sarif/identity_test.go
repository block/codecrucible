package sarif

import (
	"encoding/json"
	"testing"
)

func TestFindingIDsRemainUniqueAndImmutableAcrossRefinements(t *testing.T) {
	doc := Build(AnalysisResult{SecurityIssues: []SecurityIssue{{Issue: "First", FilePath: "a.go", StartLine: 1}, {Issue: "Second", FilePath: "a.go", StartLine: 1}}}, nil, BuilderConfig{})
	before, _ := json.Marshal(doc)
	identified := WithFindingIDs(doc)
	first := identified.Runs[0].Results[0].Properties.FindingID
	second := identified.Runs[0].Results[1].Properties.FindingID
	if first == "" || second == "" || first == second {
		t.Fatal("IDs absent or collided")
	}
	after, _ := json.Marshal(doc)
	if string(after) != string(before) {
		t.Fatal("mutated analysis snapshot")
	}
	identified.Runs[0].Results[0].Message.Text = "Refined evidence"
	identified.Runs[0].Results[0].Locations = nil
	next := WithFindingIDs(identified)
	if next.Runs[0].Results[0].Properties.FindingID != first {
		t.Fatal("refinement changed identity")
	}
	next.Runs[0].Results[1].Properties.FindingID = first
	unique := WithFindingIDs(next)
	if unique.Runs[0].Results[0].Properties.FindingID != first || unique.Runs[0].Results[1].Properties.FindingID == first {
		t.Fatal("failed to resolve duplicate identity")
	}
}
