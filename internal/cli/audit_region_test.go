package cli

import (
	"encoding/json"
	"github.com/block/codecrucible/internal/sarif"
	"testing"
)

func TestAuditClaimPreservesClampedRegionAcrossReplay(t *testing.T) {
	doc := sarif.Build(sarif.AnalysisResult{SecurityIssues: []sarif.SecurityIssue{{Issue: "unsafe", FilePath: "a.go", StartLine: 2, EndLine: 99}}}, nil, sarif.BuilderConfig{})
	doc = sarif.ValidateSourceLocations(doc, sarif.FileMap{"a.go": "one\ntwo\nthree\n"})
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var replay sarif.SARIFDocument
	if err = json.Unmarshal(data, &replay); err != nil {
		t.Fatal(err)
	}
	claims := auditClaims(replay)
	if len(claims) != 1 || claims[0].StartLine != 2 || claims[0].EndLine != 3 {
		t.Fatalf("lost focused region: %+v", claims)
	}
}
