package cli

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/block/codecrucible/internal/chunk"
	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/llm"
	"github.com/block/codecrucible/internal/sarif"
)

const testAuditV2YAML = `contract: v2
system_message: Audit the claims.
user_prompt_template: |
  {findings_json}
  {cwe_analysis_prompts}
  {code_context}
json_formatting_rules: "Schema: {schema}"
`

const testAuditFamiliesYAML = `families:
  injection:
    title: Injection
    cwes: [CWE-89]
    establish: Input reaches the query.
    refute: A parameterized query.
  general:
    title: General
    cwes: []
    establish: The claim holds.
    refute: A guard.
fallback: general
`

func v2PromptLoader() *llm.PromptLoader {
	return llm.NewPromptLoader(fstest.MapFS{
		"audit.yaml":          &fstest.MapFile{Data: []byte(testAuditV2YAML)},
		"audit_families.yaml": &fstest.MapFile{Data: []byte(testAuditFamiliesYAML)},
	})
}

func established(reason string) sarif.AuditAnswer {
	return sarif.AuditAnswer{Status: "established", Reason: reason}
}

func TestAuditVerdictV2Policy(t *testing.T) {
	ans := func(ac, pb, um string) map[string]sarif.AuditAnswer {
		return map[string]sarif.AuditAnswer{"attacker_control": {Status: ac}, "privilege_boundary": {Status: pb}, "unmitigated": {Status: um}}
	}
	for _, tc := range []struct {
		answers map[string]sarif.AuditAnswer
		status  string
		reasons []string
	}{
		{ans("established", "established", "established"), "confirmed", nil},
		{ans("established", "refuted", "established"), "rejected", []string{"refuted:privilege_boundary"}},
		{ans("unknown", "established", "refuted"), "rejected", []string{"refuted:unmitigated"}},
		{ans("established", "unknown", "established"), "unverified", []string{"unknown:privilege_boundary"}},
		{ans("", "established", "established"), "unverified", []string{"unknown:attacker_control"}},
	} {
		status, reasons := auditVerdictV2(tc.answers)
		if status != tc.status || !reflect.DeepEqual(reasons, tc.reasons) {
			t.Errorf("auditVerdictV2(%v) = %q %v; want %q %v", tc.answers, status, reasons, tc.status, tc.reasons)
		}
	}
}

func TestEvidenceVerifierChecksQuotesAgainstSource(t *testing.T) {
	files := ingest.FileMap{"app/db.go": "package db\n\nfunc Find(id string) {\n\trows := db.Query(\"SELECT * FROM t WHERE id = ?\", id)\n\t_ = rows\n}\n"}
	ev := &evidenceVerifier{files: files, lines: map[string][]string{}}
	for _, tc := range []struct {
		name string
		e    sarif.AuditEvidence
		ok   bool
	}{
		{"exact", sarif.AuditEvidence{File: "app/db.go", Line: 4, Quote: `rows := db.Query("SELECT * FROM t WHERE id = ?", id)`}, true},
		{"whitespace", sarif.AuditEvidence{File: "app/db.go", Line: 4, Quote: "rows   :=  db.Query("}, true},
		{"within two lines", sarif.AuditEvidence{File: "app/db.go", Line: 6, Quote: "db.Query("}, true},
		{"line prefix copied", sarif.AuditEvidence{File: "app/db.go", Line: 3, Quote: "3| func Find(id string) {"}, true},
		{"repaired path", sarif.AuditEvidence{File: "db.go", Line: 3, Quote: "func Find"}, true},
		{"too far", sarif.AuditEvidence{File: "app/db.go", Line: 1, Quote: "db.Query("}, false},
		{"fabricated", sarif.AuditEvidence{File: "app/db.go", Line: 4, Quote: "if !isAdmin(user) { return }"}, false},
		{"too short", sarif.AuditEvidence{File: "app/db.go", Line: 6, Quote: "}"}, false},
		{"unknown file", sarif.AuditEvidence{File: "other.go", Line: 1, Quote: "package db"}, false},
		{"line out of range", sarif.AuditEvidence{File: "app/db.go", Line: 99, Quote: "package db"}, false},
	} {
		got := ev.verify([]sarif.AuditEvidence{tc.e})
		if (len(got) == 1) != tc.ok {
			t.Errorf("%s: verify = %v; want ok=%v", tc.name, got, tc.ok)
		}
		if len(got) == 1 && got[0].File != "app/db.go" {
			t.Errorf("%s: path not resolved: %+v", tc.name, got[0])
		}
	}

	refuted := sarif.AuditAnswer{Status: "refuted", Reason: "guarded"}
	if a, reason := ev.answer(refuted); a.Status != "unknown" || reason != "ungrounded_refutation" {
		t.Errorf("refutation without evidence = %+v %q", a, reason)
	}
	refuted.Evidence = []sarif.AuditEvidence{{File: "app/db.go", Line: 4, Quote: "if !isAdmin(user)"}}
	if a, reason := ev.answer(refuted); a.Status != "unknown" || reason != "unverified_evidence" || len(a.Evidence) != 0 {
		t.Errorf("refutation with fabricated evidence = %+v %q", a, reason)
	}
	if a, reason := ev.answer(established("searched handlers; no guard")); a.Status != "established" || reason != "" {
		t.Errorf("established without evidence = %+v %q", a, reason)
	}

	if e := ev.exposure(sarif.DeploymentExposure{Status: "not_deployed"}); e != nil {
		t.Errorf("not_deployed without evidence recorded: %+v", e)
	}
	if e := ev.exposure(sarif.DeploymentExposure{Status: "config_enabled", Detail: "feature.flag"}); e == nil || e.Status != "config_enabled" {
		t.Errorf("config_enabled exposure = %+v", e)
	}
}

func TestNumberedSource(t *testing.T) {
	if got := numberedSource("a\nb\n"); got != "1| a\n2| b\n" {
		t.Errorf("numberedSource = %q", got)
	}
	if got := numberedSource("a\nb"); got != "1| a\n2| b\n" {
		t.Errorf("numberedSource without trailing newline = %q", got)
	}
}

// v2Fixture has four findings with stable IDs: a SQL injection, an admin
// endpoint, a path traversal, and a second report of the injection.
func v2Fixture() (sarif.SARIFDocument, ingest.FileMap, []string) {
	files := ingest.FileMap{
		"app/db.go":    "package app\n\nfunc Find(id string) {\n\tdb.Query(\"SELECT * FROM t WHERE id = \" + id)\n}\n",
		"app/admin.go": "package app\n\n// @RequiresRole(\"admin\")\nfunc Purge() {\n\tdeleteAll()\n}\n",
		"app/file.go":  "package app\n\nfunc Read(name string) {\n\tos.ReadFile(name)\n}\n",
	}
	doc := sarif.AssignFindingIDs(sarif.Build(sarif.AnalysisResult{SecurityIssues: []sarif.SecurityIssue{
		{Issue: "SQL injection", FilePath: "app/db.go", StartLine: 4, TechnicalDetails: "id is concatenated", Severity: 8, CWEID: "CWE-89"},
		{Issue: "Missing authorization", FilePath: "app/admin.go", StartLine: 4, TechnicalDetails: "anyone can purge", Severity: 7, CWEID: "CWE-862"},
		{Issue: "Path traversal", FilePath: "app/file.go", StartLine: 4, TechnicalDetails: "name reaches ReadFile", Severity: 6, CWEID: "CWE-22"},
		{Issue: "Query built from input", FilePath: "app/db.go", StartLine: 4, TechnicalDetails: "same concatenation", Severity: 8, CWEID: "CWE-89"},
	}}, sarif.FileMap(files), sarif.BuilderConfig{}))
	var ids []string
	for _, r := range doc.Runs[0].Results {
		ids = append(ids, r.Properties.FindingID)
	}
	return doc, files, ids
}

// claimIDs decodes the finding IDs of the claims in an audit request.
func claimIDs(t *testing.T, req llm.ChatRequest) []string {
	t.Helper()
	content := req.Messages[len(req.Messages)-1].Content
	i := strings.Index(content, `{"claims_to_verify":[`)
	if i < 0 {
		t.Fatal("request has no claims")
	}
	var body struct {
		Claims []auditClaimV2 `json:"claims_to_verify"`
	}
	if err := json.NewDecoder(strings.NewReader(content[i:])).Decode(&body); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, c := range body.Claims {
		ids = append(ids, c.FindingID)
	}
	return ids
}

func v2Reply(t *testing.T, resp auditResponseV2) *llm.ChatResponse {
	t.Helper()
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	return &llm.ChatResponse{Content: string(data), Usage: llm.TokenUsage{PromptTokens: 10, CompletionTokens: 5}}
}

func runV2Audit(doc sarif.SARIFDocument, files ingest.FileMap, client llm.Client, metadata *sarif.ScanMetadata) (*sarif.SARIFDocument, error) {
	got, _, _, err := runAuditPhase(context.Background(), doc, "fixture", client, "", config.ModelConfig{Name: "test"},
		v2PromptLoader(), llm.OutputModeNone, files, .3, nil, "", 0, true, chunk.NewTokenCounter("", nil), metadata)
	return got, err
}

func TestAuditV2ComputesVerdictsAndRetriesMissingClaims(t *testing.T) {
	doc, files, ids := v2Fixture()
	var requests [][]string
	client := auditClientFunc(func(_ context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
		requests = append(requests, claimIDs(t, req))
		if len(requests) == 1 {
			content := req.Messages[len(req.Messages)-1].Content
			if !strings.Contains(content, "4| \tdb.Query(") || !strings.Contains(content, "security_audit_v2") || !strings.Contains(content, "### Injection") {
				t.Errorf("request lacks numbered source, v2 schema, or family card:\n%s", content)
			}
			return v2Reply(t, auditResponseV2{Assessments: []auditAssessmentV2{
				{FindingID: ids[0], AttackerControl: sarif.AuditAnswer{Status: "established", Evidence: []sarif.AuditEvidence{{File: "app/db.go", Line: 4, Quote: `"SELECT * FROM t WHERE id = " + id`}}},
					PrivilegeBoundary: established("unauthenticated"), Unmitigated: established("no escaping"), RefinedSeverity: 9, Summary: "Concatenated SQL."},
				{FindingID: ids[1], AttackerControl: established("request reaches Purge"),
					PrivilegeBoundary: sarif.AuditAnswer{Status: "refuted", Reason: "admin-only by design",
						Evidence: []sarif.AuditEvidence{{File: "app/admin.go", Line: 3, Quote: `@RequiresRole("admin")`}}},
					Unmitigated: established("no other check")},
				{FindingID: ids[2], AttackerControl: established("name is a query parameter"), PrivilegeBoundary: established("public"),
					Unmitigated:        sarif.AuditAnswer{Status: "refuted", Reason: "sanitized", Evidence: []sarif.AuditEvidence{{File: "app/file.go", Line: 4, Quote: "filepath.Base(name)"}}},
					DeploymentExposure: sarif.DeploymentExposure{Status: "not_deployed", Detail: "looks like a dev tool"},
					Crux:               "whether name is sanitized upstream"},
				{FindingID: "no-such-id", AttackerControl: established("x"), PrivilegeBoundary: established("x"), Unmitigated: established("x")},
			}, Leads: []string{"  check the export endpoint  "}}), nil
		}
		return v2Reply(t, auditResponseV2{Assessments: []auditAssessmentV2{
			{FindingID: ids[3], AttackerControl: established("same input"), PrivilegeBoundary: established("public"),
				Unmitigated: established("none"), DuplicateOf: ids[0]},
		}}), nil
	})
	metadata := &sarif.ScanMetadata{Execution: sarif.ScanExecution{Phases: map[string]sarif.PhaseExecution{}}}
	got, err := runV2Audit(doc, files, client, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) != 2 || len(requests[0]) != 4 || !reflect.DeepEqual(requests[1], []string{ids[3]}) {
		t.Fatalf("requests = %v; want all claims, then only the omitted one", requests)
	}

	results := got.Runs[0].Results
	p := results[0].Properties
	if p.AuditStatus != "refined" || *p.Severity != 9 || p.Summary != "Concatenated SQL." || len(results[0].Suppressions) != 0 ||
		len(p.AuditAnswers["attacker_control"].Evidence) != 1 || results[0].Level != "error" {
		t.Errorf("confirmed finding = %+v", p)
	}
	p = results[1].Properties
	if p.AuditStatus != "rejected" || len(results[1].Suppressions) != 1 ||
		!strings.Contains(results[1].Suppressions[0].Justification, `app/admin.go:3: @RequiresRole("admin")`) ||
		!reflect.DeepEqual(p.AuditReasons, []string{"refuted:privilege_boundary"}) {
		t.Errorf("admin-by-design finding = %+v %+v", p, results[1].Suppressions)
	}
	p = results[2].Properties
	if p.AuditStatus != "unverified" || len(results[2].Suppressions) != 0 || p.AuditCrux != "whether name is sanitized upstream" ||
		!reflect.DeepEqual(p.AuditReasons, []string{"unknown:unmitigated", "unverified_evidence:unmitigated"}) ||
		p.DeploymentExposure == nil || p.DeploymentExposure.Status != "unknown" {
		t.Errorf("fabricated refutation = %+v exposure=%+v", p, p.DeploymentExposure)
	}
	p = results[3].Properties
	if p.AuditStatus != "duplicate" || p.DuplicateOf != ids[0] || len(results[3].Suppressions) != 1 {
		t.Errorf("duplicate finding = %+v", p)
	}
	if !reflect.DeepEqual(metadata.Execution.AuditLeads, []string{"check the export endpoint"}) {
		t.Errorf("leads = %v", metadata.Execution.AuditLeads)
	}
	if doc.Runs[0].Results[1].Suppressions != nil || doc.Runs[0].Results[0].Properties.AuditAnswers != nil {
		t.Error("audit mutated the analysis document")
	}
}

func TestAuditV2AcceptsPartialCoverage(t *testing.T) {
	doc, files, ids := v2Fixture()
	calls := 0
	client := auditClientFunc(func(_ context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
		calls++
		var out []auditAssessmentV2
		for _, id := range claimIDs(t, req) {
			if id != ids[2] {
				out = append(out, auditAssessmentV2{FindingID: id, AttackerControl: established("x"), PrivilegeBoundary: sarif.AuditAnswer{Status: "unknown"}, Unmitigated: established("x")})
			}
		}
		return v2Reply(t, auditResponseV2{Assessments: out}), nil
	})
	metadata := &sarif.ScanMetadata{Execution: sarif.ScanExecution{Phases: map[string]sarif.PhaseExecution{}}}
	got, err := runV2Audit(doc, files, client, metadata)
	if err == nil || !strings.Contains(err.Error(), "1 of 4 findings have no assessment") || calls != 2 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
	for i, r := range got.Runs[0].Results {
		want := "unverified"
		if i == 2 {
			want = "not_audited"
		}
		if r.Properties.AuditStatus != want {
			t.Errorf("result %d status = %q; want %q", i, r.Properties.AuditStatus, want)
		}
	}
	if metadata.Execution.Phases["audit"].Status != "incomplete" {
		t.Errorf("phase status = %+v", metadata.Execution.Phases["audit"])
	}
}

func TestAuditV2DuplicateNeverHidesTheStrongerFinding(t *testing.T) {
	doc, files, ids := v2Fixture()
	unknown := sarif.AuditAnswer{Status: "unknown"}
	assessments := map[string]auditAssessmentV2{
		ids[0]: {FindingID: ids[0], AttackerControl: unknown, PrivilegeBoundary: unknown, Unmitigated: unknown},
		ids[3]: {FindingID: ids[3], AttackerControl: established("x"), PrivilegeBoundary: established("x"), Unmitigated: established("x"), DuplicateOf: ids[0]},
	}
	batchOf := map[string]int{ids[0]: 0, ids[3]: 0}
	results := applyAuditAssessments(doc, assessments, batchOf, files).Runs[0].Results
	if results[3].Properties.AuditStatus != "confirmed" || results[3].Properties.DuplicateOf != "" {
		t.Errorf("confirmed finding hidden behind an unverified one: %+v", results[3].Properties)
	}

	batchOf[ids[3]] = 1
	assessments[ids[0]] = auditAssessmentV2{FindingID: ids[0], AttackerControl: established("x"), PrivilegeBoundary: established("x"), Unmitigated: established("x")}
	results = applyAuditAssessments(doc, assessments, batchOf, files).Runs[0].Results
	if results[3].Properties.AuditStatus != "confirmed" {
		t.Errorf("duplicate across batches honored: %+v", results[3].Properties)
	}
}
