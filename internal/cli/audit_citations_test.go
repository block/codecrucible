package cli

import (
	"strings"
	"testing"

	"github.com/block/codecrucible/internal/auditctx"
	"github.com/block/codecrucible/internal/chunk"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/sarif"
	"github.com/block/codecrucible/internal/sourceindex"
)

func TestCitedContextRetainsAdmittedEvidenceOnly(t *testing.T) {
	source := sourceindex.New(map[string]string{"routes/a.go": "one\ntwo\nthree", "other.go": "private"})
	text, _ := citedAuditContext(auditctx.NewRetriever(source), source, []auditClaim{{UnverifiedExploitSketch: "routes/a.go:2–3; absent.go:1; ../other.go:1"}}, map[string]bool{}, chunk.NewTokenCounter("", nil))
	if !strings.Contains(text, "2| two") || strings.Contains(text, "private") || strings.Contains(text, "absent.go") {
		t.Fatal(text)
	}
}

func TestRepeatedCitationsDoNotClaimMissingContext(t *testing.T) {
	source := sourceindex.New(map[string]string{"a.go": "one\ntwo\nthree\nfour\nfive\n"})
	text, _ := citedAuditContext(auditctx.NewRetriever(source), source, []auditClaim{{UnverifiedExploitSketch: "a.go:2 a.go:2 a.go:3"}}, nil, chunk.NewTokenCounter("", nil))
	if strings.Contains(text, "incomplete") || !strings.Contains(text, "3| three") {
		t.Fatal(text)
	}
}

func TestCitationsStillReportBudgetOmissions(t *testing.T) {
	source := sourceindex.New(map[string]string{"a.go": strings.Repeat("token ", 30000)})
	text, _ := citedAuditContext(auditctx.NewRetriever(source), source, []auditClaim{{UnverifiedExploitSketch: "a.go:1 a.go:1"}}, nil, chunk.NewTokenCounter("", nil))
	if !strings.Contains(text, "incomplete") {
		t.Fatal("missing budget warning")
	}
}

func TestIndexChunkAndValidationAgreeOnFinalNewline(t *testing.T) {
	for _, text := range []string{"one\ntwo", "one\ntwo\n"} {
		n := len(sourceindex.New(map[string]string{"a.go": text}).Lines("a.go"))
		chunks, err := chunk.NewChunker(chunk.NewTokenCounter("", nil), nil).Chunk(ingest.FlattenResult{FileMap: ingest.FileMap{"a.go": text}}, 10000, nil)
		if err != nil || len(chunks) != 1 || n != 2 {
			t.Fatalf("lines=%d chunks=%v err=%v", n, chunks, err)
		}
		if strings.Contains(chunks[0].XML, "3|") {
			t.Fatal("chunk emitted phantom line")
		}
		for _, line := range []int{n, n + 1} {
			doc := sarif.Build(sarif.AnalysisResult{SecurityIssues: []sarif.SecurityIssue{{Issue: "claim", FilePath: "a.go", StartLine: line}}}, nil, sarif.BuilderConfig{})
			doc = sarif.ValidateSourceLocations(doc, sarif.FileMap{"a.go": text})
			if (doc.Runs[0].Results[0].Locations[0].PhysicalLocation.Region != nil) != (line == n) {
				t.Fatal("validator/index disagreement")
			}
		}
	}
}

func TestChainedCitationsKeepPartialBudgetCoverage(t *testing.T) {
	source := sourceindex.New(map[string]string{"a.go": strings.Repeat(strings.Repeat("evidence ", 16)+"\n", 400)})
	text, kept := citedAuditContext(auditctx.NewRetriever(source), source, []auditClaim{{UnverifiedExploitSketch: "a.go:1-80 a.go:79-159 a.go:158-238 a.go:237-317"}}, nil, chunk.NewTokenCounter("", nil))
	if kept < 3 || !strings.Contains(text, "158|") || !strings.Contains(text, "incomplete") {
		t.Fatalf("kept %d ranges: %s", kept, text)
	}
}

func TestCitationsKeepClaimOrderUnderBudget(t *testing.T) {
	content := strings.Repeat(strings.Repeat("evidence ", 40)+"\n", 100)
	source := sourceindex.New(map[string]string{"a.go": content, "z.go": content})
	text, kept := citedAuditContext(auditctx.NewRetriever(source), source, []auditClaim{{UnverifiedExploitSketch: "z.go:1-80 a.go:1-80"}}, nil, chunk.NewTokenCounter("", nil))
	if kept != 1 || !strings.Contains(text, `path="z.go"`) || strings.Contains(text, `path="a.go"`) {
		t.Fatalf("citation priority changed: kept=%d %s", kept, text)
	}
}
