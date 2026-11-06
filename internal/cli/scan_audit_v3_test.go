package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/block/codecrucible/internal/auditcore"
	"github.com/block/codecrucible/internal/chunk"
	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/llm"
	"github.com/block/codecrucible/internal/provenance"
	"github.com/block/codecrucible/internal/sarif"
)

func v3Loader() *llm.PromptLoader {
	return llm.NewPromptLoader(fstest.MapFS{"audit.yaml": {Data: []byte(strings.Replace(testAuditV2YAML, "contract: v2", "contract: v3", 1))}, "audit_families.yaml": {Data: []byte(testAuditFamiliesYAML)}})
}
func requestClaimsV3(t *testing.T, req llm.ChatRequest) []auditcore.Claim {
	t.Helper()
	text := req.Messages[len(req.Messages)-1].Content
	at := strings.Index(text, `{"claims_to_verify":`)
	if at < 0 {
		t.Fatal("claims missing")
	}
	var payload struct {
		Claims []auditcore.Claim `json:"claims_to_verify"`
	}
	if err := json.NewDecoder(strings.NewReader(text[at:])).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	return payload.Claims
}
func assessmentV3(c auditcore.Claim, quote, call string, status string) auditcore.Assessment {
	e := auditcore.Evidence{File: c.File, Start: c.Start, End: c.Start, Quote: quote}
	a := auditcore.Assessment{FindingID: c.FindingID, RevisionID: c.RevisionID, Digest: c.Digest, RefinedSeverity: c.Severity, SeverityBasis: "supported scope"}
	for _, m := range c.Material {
		a.CoveredMaterial = append(a.CoveredMaterial, auditcore.Coverage{MaterialID: m.ID, Quote: m.Text})
	}
	for _, q := range auditcore.Questions {
		a.Assertions = append(a.Assertions, auditcore.Assertion{GuardState: "does_not_block", Kind: q, Status: "established", Statement: q, Reason: "source supports this condition", Subject: "value", Consumer: call, Guard: call, ConsumerInput: "value", GuardInput: "value", Evidence: []auditcore.Evidence{e}, ConsumerEvidence: []auditcore.Evidence{e}, GuardEvidence: []auditcore.Evidence{e}})
	}
	if status == "rejected" {
		a.Assertions[3].Status = "refuted"
		a.Assertions[3].GuardState = "blocks"
	}
	return a
}
func replyV3(a ...auditcore.Assessment) *llm.ChatResponse {
	b, _ := json.Marshal(map[string]any{"assessments": a})
	return &llm.ChatResponse{Content: string(b), Usage: llm.TokenUsage{PromptTokens: 12, CompletionTokens: 9}}
}
func v3Fixture(t *testing.T, issues []sarif.SecurityIssue) (sarif.SARIFDocument, ingest.FileMap, *provenance.Ledger, *bytes.Buffer) {
	t.Helper()
	files := ingest.FileMap{"a.go": "package a\nfunc one(value string){sink(value)}\nfunc two(value string){safe(value)}\n"}
	doc := sarif.AssignFindingIDs(sarif.Build(sarif.AnalysisResult{SecurityIssues: issues}, sarif.FileMap(files), sarif.BuilderConfig{}))
	buf := &bytes.Buffer{}
	l := provenance.New("v3", buf)
	if err := l.Observe("fixture", &doc); err != nil {
		t.Fatal(err)
	}
	if err := l.Checkpoint("analysis", &doc); err != nil {
		t.Fatal(err)
	}
	return doc, files, l, buf
}
func runV3(t *testing.T, doc sarif.SARIFDocument, files ingest.FileMap, l *provenance.Ledger, client llm.Client, mode string) (*sarif.SARIFDocument, error) {
	t.Helper()
	got, _, _, err := runAuditPhase(context.Background(), doc, "fixture", traceClient(client, l, "audit"), "", config.ModelConfig{Name: "test", ContextLimit: 100000, MaxOutputTokens: 4096}, v3Loader(), llm.OutputModeJSONSchema, files, .3, nil, "", 0, true, chunk.NewTokenCounter("", nil), nil, nil, auditRunOptions{semanticDedup: mode})
	return got, err
}
func finishV3(t *testing.T, l *provenance.Ledger, buf *bytes.Buffer, doc *sarif.SARIFDocument) provenance.Validation {
	t.Helper()
	if err := l.Finish(*doc); err != nil {
		t.Fatal(err)
	}
	if err := l.Metadata("run-complete", nil); err != nil {
		t.Fatal(err)
	}
	v, err := provenance.Validate(bytes.NewReader(buf.Bytes()), doc)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func TestAuditV3RetriesOnlySwappedClaimAndReconciles(t *testing.T) {
	doc, files, l, buf := v3Fixture(t, []sarif.SecurityIssue{{Issue: "unsafe", FilePath: "a.go", StartLine: 2, EndLine: 2, TechnicalDetails: "one", CWEID: "CWE-89", Severity: 8}, {Issue: "guarded", FilePath: "a.go", StartLine: 3, EndLine: 3, TechnicalDetails: "two", CWEID: "CWE-89", Severity: 7}})
	calls := 0
	client := auditClientFunc(func(_ context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
		calls++
		claims := requestClaimsV3(t, req)
		if calls == 1 {
			a := assessmentV3(claims[0], "sink(value)", "sink", "confirmed")
			b := assessmentV3(claims[1], "safe(value)", "safe", "rejected")
			b.Digest = a.Digest
			return replyV3(a, b), nil
		}
		if len(claims) != 1 || claims[0].Start != 3 {
			t.Fatalf("valid peer was retried: %+v", claims)
		}
		return replyV3(assessmentV3(claims[0], "safe(value)", "safe", "rejected")), nil
	})
	got, err := runV3(t, doc, files, l, client, "off")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || got.Runs[0].Results[0].Properties.AuditStatus != "confirmed" || got.Runs[0].Results[1].Properties.AuditStatus != "rejected" {
		t.Fatalf("calls=%d results=%+v", calls, got.Runs[0].Results)
	}
	v := finishV3(t, l, buf, got)
	if v.Observations != 2 || v.Decisions != 6 || !v.Complete {
		t.Fatal(v)
	}
}
func TestAuditV3SplitPreservesValidSiblingAndRemainder(t *testing.T) {
	doc, files, l, buf := v3Fixture(t, []sarif.SecurityIssue{{Issue: "grouped", FilePath: "a.go", StartLine: 2, EndLine: 2, TechnicalDetails: "unsafe one; safe two", CWEID: "CWE-89", Severity: 8}})
	client := auditClientFunc(func(_ context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
		c := requestClaimsV3(t, req)[0]
		if c.Title == "grouped" {
			a := assessmentV3(c, "sink(value)", "sink", "rejected")
			for _, part := range []struct {
				title, detail, quote string
				line                 int
			}{{"first", "unsafe one", "sink(value)", 2}, {"second", "safe two", "safe(value)", 3}} {
				a.Children = append(a.Children, auditcore.Child{Title: part.title, Detail: part.detail, File: "a.go", Start: part.line, End: part.line, Covers: []auditcore.Coverage{{MaterialID: "detail", Quote: part.detail}}, Evidence: []auditcore.Evidence{{File: "a.go", Start: part.line, End: part.line, Quote: part.quote}}})
			}
			return replyV3(a), nil
		}
		if c.Start == 2 {
			return replyV3(assessmentV3(c, "sink(value)", "sink", "confirmed")), nil
		}
		return replyV3(assessmentV3(c, "safe(value)", "safe", "rejected")), nil
	})
	got, err := runV3(t, doc, files, l, client, "off")
	if err != nil {
		t.Fatal(err)
	}
	rs := got.Runs[0].Results
	if len(rs) != 3 || len(rs[0].Suppressions) == 0 || rs[0].Properties.AuditStatus != "rejected" || rs[1].Properties.AuditStatus != "confirmed" || len(rs[1].Suppressions) != 0 || rs[2].Properties.AuditStatus != "rejected" {
		t.Fatalf("split lost a claim: %+v", rs)
	}
	if rs[1].Properties.ParentFindingID != rs[0].Properties.FindingID || rs[1].Properties.FindingID == rs[2].Properties.FindingID {
		t.Fatal("invalid child identities")
	}
	v := finishV3(t, l, buf, got)
	if v.Observations != 1 || len(v.Unresolved) != 0 {
		t.Fatal(v)
	}
}
func TestAuditV3DuplicateReportsNeverSuppress(t *testing.T) {
	issues := []sarif.SecurityIssue{}
	for _, title := range []string{"unsafe query", "same query"} {
		issues = append(issues, sarif.SecurityIssue{Issue: title, FilePath: "a.go", StartLine: 2, EndLine: 2, TechnicalDetails: title, CWEID: "CWE-89", Severity: 8})
	}
	doc, files, l, buf := v3Fixture(t, issues)
	client := auditClientFunc(func(_ context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
		if strings.Contains(req.Label, "duplicates") {
			var payload struct{ Left, Right auditcore.Claim }
			if err := json.NewDecoder(strings.NewReader(req.Messages[1].Content)).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			e := auditcore.Evidence{File: "a.go", Start: 2, End: 2, Quote: "sink(value)"}
			b, _ := json.Marshal(auditcore.PairJudgment{LeftID: payload.Left.FindingID, RightID: payload.Right.FindingID, LeftDigest: payload.Left.Digest, RightDigest: payload.Right.Digest, Judgment: "same_cause_same_fix", Reason: "same source operation", CauseEvidence: []auditcore.Evidence{e}, FixEvidence: []auditcore.Evidence{e}})
			return &llm.ChatResponse{Content: string(b)}, nil
		}
		var out []auditcore.Assessment
		for _, c := range requestClaimsV3(t, req) {
			out = append(out, assessmentV3(c, "sink(value)", "sink", "confirmed"))
		}
		return replyV3(out...), nil
	})
	got, err := runV3(t, doc, files, l, client, "report")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range got.Runs[0].Results {
		if len(r.Suppressions) > 0 || len(r.Properties.SemanticDuplicates) != 1 {
			t.Fatal("duplicate was hidden", r.Properties)
		}
	}
	finishV3(t, l, buf, got)
}
func TestAuditV3TransportFailureRetainsFindings(t *testing.T) {
	doc, files, l, _ := v3Fixture(t, []sarif.SecurityIssue{{Issue: "unsafe", FilePath: "a.go", StartLine: 2, TechnicalDetails: "one"}})
	got, err := runV3(t, doc, files, l, auditClientFunc(func(context.Context, llm.ChatRequest) (*llm.ChatResponse, error) {
		return nil, fmt.Errorf("503 unavailable")
	}), "off")
	if err == nil || len(got.Runs[0].Results) != 1 || len(got.Runs[0].Results[0].Suppressions) != 0 || got.Runs[0].Results[0].Properties.AuditStatus != "not_audited" {
		t.Fatal(got, err)
	}
}

func TestV3RefinementPreservesSeverityAndCanonicalCWE(t *testing.T) {
	for _, cwe := range []string{"invalid", "cwe-79: XSS"} {
		sev := 8.0
		result := sarif.SARIFResult{Properties: &sarif.FindingProperties{Severity: &sev, CWE: "CWE-89"}}
		applyOutcomeV3(&result, assessedV3{outcome: auditcore.Outcome{Status: "confirmed"}, raw: auditcore.Assessment{SeverityBasis: "basis", RefinedSeverity: 0, RefinedCWE: cwe}})
		want := "CWE-89"
		if cwe != "invalid" {
			want = "CWE-79"
		}
		if *result.Properties.Severity != 8 || result.Properties.CWE != want {
			t.Fatalf("invalid refinement applied: %+v", result.Properties)
		}
	}
}

func TestAuditV3InvalidChildCannotReviveRejectedParent(t *testing.T) {
	doc, files, l, buf := v3Fixture(t, []sarif.SecurityIssue{{Issue: "parent", FilePath: "a.go", StartLine: 2, EndLine: 2, TechnicalDetails: "one", CWEID: "CWE-89", Severity: 8}})
	client := auditClientFunc(func(_ context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
		c := requestClaimsV3(t, req)[0]
		a := assessmentV3(c, "sink(value)", "sink", "rejected")
		a.Children = []auditcore.Child{{Title: "unsupported child"}}
		return replyV3(a), nil
	})
	got, err := runV3(t, doc, files, l, client, "off")
	if err != nil {
		t.Fatal(err)
	}
	rs := got.Runs[0].Results
	if len(rs) != 1 || rs[0].Properties.AuditStatus != "rejected" || len(rs[0].Suppressions) == 0 {
		t.Fatalf("invalid child revived parent: %+v", rs)
	}
	finishV3(t, l, buf, got)
}

func TestRejectedChildKeepsSupportedGrandchildVisible(t *testing.T) {
	for _, valid := range []bool{false, true} {
		doc, files, l, buf := v3Fixture(t, []sarif.SecurityIssue{{Issue: "grouped", FilePath: "a.go", StartLine: 2, EndLine: 2, TechnicalDetails: "unsafe one", CWEID: "CWE-89", Severity: 8}})
		client := auditClientFunc(func(_ context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
			c := requestClaimsV3(t, req)[0]
			a := assessmentV3(c, "sink(value)", "sink", "confirmed")
			proposal := auditcore.Child{Title: "child", Detail: "unsafe one", File: "a.go", Start: 2, End: 2, Covers: []auditcore.Coverage{{MaterialID: "detail", Quote: "unsafe one"}}, Evidence: []auditcore.Evidence{{File: "a.go", Start: 2, End: 2, Quote: "sink(value)"}}}
			if c.Title == "child" {
				a = assessmentV3(c, "sink(value)", "sink", "rejected")
				proposal.Title = "grandchild"
				if !valid {
					proposal.Detail = ""
				}
			}
			a.Children = []auditcore.Child{proposal}
			return replyV3(a), nil
		})
		got, err := runV3(t, doc, files, l, client, "off")
		if err != nil {
			t.Fatal(err)
		}
		rs := got.Runs[0].Results
		if len(rs) != 2 {
			t.Fatal(rs)
		}
		if valid && (rs[1].Properties.AuditStatus != "unverified" || len(rs[1].Suppressions) != 0) {
			t.Fatal("supported residual hidden", rs[1])
		}
		if !valid && (rs[1].Properties.AuditStatus != "rejected" || len(rs[1].Suppressions) == 0) {
			t.Fatal("invalid residual revived child", rs[1])
		}
		finishV3(t, l, buf, got)
	}
}
