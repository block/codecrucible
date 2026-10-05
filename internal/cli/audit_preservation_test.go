package cli

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/block/codecrucible/internal/chunk"
	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/decision"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/llm"
	"github.com/block/codecrucible/internal/sarif"
)

func TestSelectedAuditEvidenceReachesAuditorWithoutReplacingAnchor(t *testing.T) {
	files := ingest.FileMap{"client.js": "const preview = document.getElementById('preview');\nif (preview) preview.innerHTML = location.hash;", "page.html": "<div id='preview'></div><script src='client.js'></script>"}
	doc := sarif.WithFindingIDs(sarif.Build(sarif.AnalysisResult{SecurityIssues: []sarif.SecurityIssue{{Issue: "DOM injection", FilePath: "client.js", StartLine: 2, Severity: 8}}}, sarif.FileMap(files), sarif.BuilderConfig{}))
	e, _ := decision.SourceEvidence("page.html", files["page.html"], 1, 1)
	id := doc.Runs[0].Results[0].Properties.FindingID
	client := auditClientFunc(func(_ context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
		var prompt string
		for _, m := range req.Messages {
			prompt += m.Content
		}
		if !strings.Contains(prompt, `<file path="client.js">`) || !strings.Contains(prompt, "optional_source_evidence") || !strings.Contains(prompt, "page.html") {
			t.Fatal("mandatory or selected evidence missing")
		}
		return verdictResponse(requestedClaims(t, req)...), nil
	})
	out, _, _, err := runAuditPhase(context.Background(), doc, "fixture", client, "", config.ModelConfig{Name: "test"}, llm.NewPromptLoader(os.DirFS("../../prompts/default")), llm.OutputModeNone, files, .3, nil, "", 1, 1, true, chunk.NewTokenCounter("", nil), nil, map[string][]decision.Evidence{id: {e}})
	if err != nil || len(out.Runs[0].Results) != 1 {
		t.Fatalf("audit lost finding: %v", err)
	}
}

func TestAuditMissingTemplateAndPartialClaimsSurvive(t *testing.T) {
	files := ingest.FileMap{"client.js": "const el = document.getElementById('preview');\nif (el) el.innerHTML = location.hash;\n"}
	doc := sarif.WithFindingIDs(sarif.Build(sarif.AnalysisResult{SecurityIssues: []sarif.SecurityIssue{{Issue: "Unsafe DOM update and another unresolved effect", FilePath: "client.js", StartLine: 2, TechnicalDetails: "URL text reaches innerHTML. A second effect remains unresolved.", Severity: 8}}}, sarif.FileMap(files), sarif.BuilderConfig{}))
	for _, reason := range []string{"missing_context", "conditional_execution", "fabricated_quote", "partial", "low_confidence"} {
		t.Run(reason, func(t *testing.T) {
			af := AuditedFinding{FindingID: doc.Runs[0].Results[0].Properties.FindingID, Verdict: "rejected", Confidence: .9, ClaimCoverage: "complete", RefinedTechnicalDetails: "Only the first effect", FilePath: "client.js", StartLine: 1, BlockingCode: "if (el)", BlockingEvidence: &AuditBlockingEvidence{Path: "client.js", Start: 2, End: 2, Quote: "if (el) el.innerHTML = location.hash;", BlocksAllPaths: true, Reason: reason}}
			if reason == "fabricated_quote" {
				af.BlockingEvidence.Reason = "executable_protection"
				af.BlockingEvidence.Quote = "return;"
			}
			if reason == "partial" {
				af.Verdict = "refined"
				af.ClaimCoverage = "partial"
				af.UnresolvedClaims = []string{"second effect"}
			}
			if reason == "low_confidence" {
				af.Verdict = "confirmed"
				af.Confidence = .1
			}
			out := applyAuditVerdicts(doc, AuditResult{AuditedFindings: []AuditedFinding{af}}, files, .5)
			if len(out.Runs[0].Results) != 1 {
				t.Fatal("dropped uncertain finding")
			}
			got := out.Runs[0].Results[0]
			if got.Properties.AuditStatus != "unverified" || !strings.Contains(got.Message.Text, "second effect") || !reflect.DeepEqual(got.Locations, doc.Runs[0].Results[0].Locations) {
				t.Fatal("erased original claim or location")
			}
			if got.Properties.AuditOriginal == nil || len(got.Properties.AuditRevision) == 0 {
				t.Fatal("missing original/proposed audit provenance")
			}
		})
	}
}

func TestExactBlockingEvidenceRequired(t *testing.T) {
	files := ingest.FileMap{"guard.go": "if !owner(user, record) { return forbidden }"}
	af := AuditedFinding{ClaimCoverage: "complete", BlockingEvidence: &AuditBlockingEvidence{Path: "guard.go", Start: 1, End: 1, Quote: files["guard.go"], BlocksAllPaths: true, Reason: "executable_protection"}}
	if !groundedAuditRejection(af, files) {
		t.Fatal("rejected exact bounded evidence")
	}
	af.UnresolvedClaims = []string{"another path"}
	if groundedAuditRejection(af, files) {
		t.Fatal("accepted unresolved subclaim")
	}
}

func TestAuditArchiveRetainsOriginalRuleAndClaim(t *testing.T) {
	files := ingest.FileMap{"query.go": "query(input)"}
	doc := sarif.WithFindingIDs(sarif.Build(sarif.AnalysisResult{SecurityIssues: []sarif.SecurityIssue{{Issue: "Query", FilePath: "query.go", StartLine: 1, Severity: 4, TechnicalDetails: "Original complete claim"}}}, sarif.FileMap(files), sarif.BuilderConfig{}))
	before := doc.Runs[0].Tool.Driver.Rules[0].Properties["security-severity"]
	af := AuditedFinding{FindingID: doc.Runs[0].Results[0].Properties.FindingID, Verdict: "refined", ClaimCoverage: "complete", Confidence: .9, RefinedSeverity: 8, RefinedTechnicalDetails: "Corrected claim"}
	out := applyAuditVerdicts(doc, AuditResult{AuditedFindings: []AuditedFinding{af}}, files, .3)
	original := out.Runs[0].Results[0].Properties.AuditOriginal
	if original.Rule.Properties["security-severity"] != before || original.Result.Message.Text != "Original complete claim" {
		t.Fatal("rewrite mutated original archive")
	}
}
