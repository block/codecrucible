package cli

import (
	"slices"
	"testing"

	"github.com/block/codecrucible/internal/decision"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/sarif"
)

func TestDeploymentExposureIsRecordedWithoutChangingVerdicts(t *testing.T) {
	files := ingest.FileMap{
		"debug.go": "//go:build debug\n\npackage main\n\nfunc dump() { leak() }\n",
		"admin.go": "package main\n\nfunc admin() {\n\tif cfg.EnableAdmin {\n\t\trun()\n\t}\n}\n",
	}
	doc := sarif.WithFindingIDs(sarif.Build(sarif.AnalysisResult{SecurityIssues: []sarif.SecurityIssue{
		{Issue: "Debug leak", FilePath: "debug.go", StartLine: 5, Severity: 7},
		{Issue: "Admin command", FilePath: "admin.go", StartLine: 5, Severity: 9},
		{Issue: "Unproven exclusion", FilePath: "admin.go", StartLine: 3, Severity: 5},
		{Issue: "Deploy-file citation", FilePath: "admin.go", StartLine: 4, Severity: 6},
		{Issue: "No exposure field", FilePath: "debug.go", StartLine: 1, Severity: 4},
		{Issue: "Not audited", FilePath: "debug.go", StartLine: 3, Severity: 3},
	}}, sarif.FileMap(files), sarif.BuilderConfig{}))
	ids := make([]string, 6)
	for i, r := range doc.Runs[0].Results {
		ids[i] = r.Properties.FindingID
	}
	deployStep := decision.TraceStep{Kind: "config_setting", Evidence: decision.Evidence{Path: "Dockerfile", Start: 3, End: 4, Text: "ENV ENABLE_ADMIN=0\nRUN go build -tags release"}}
	traces := map[string]decision.DeploymentTrace{
		ids[1]: {EntryPoint: true, ConfigKeys: []string{"EnableAdmin"}, Gaps: []string{"config_key_not_set_in_repo:EnableAdmin"}},
		ids[3]: {Steps: []decision.TraceStep{deployStep}},
		ids[5]: {Gaps: []string{"no_callers_found"}},
	}
	audit := AuditResult{AuditedFindings: []AuditedFinding{
		{FindingID: ids[0], Verdict: "confirmed", DeploymentExposure: &AuditExposure{Status: "not_deployed", EnablingKey: "debug", Evidence: &AuditCitation{Path: "debug.go", Start: 1, End: 1, Quote: "//go:build debug"}}},
		{FindingID: ids[1], Verdict: "confirmed", DeploymentExposure: &AuditExposure{Status: "config_dependent", EnablingKey: " EnableAdmin ", Evidence: &AuditCitation{Path: "admin.go", Start: 4, End: 4, Quote: "if cfg.EnableAdmin {"}}},
		{FindingID: ids[2], Verdict: "unverified", DeploymentExposure: &AuditExposure{Status: "not_deployed", Evidence: &AuditCitation{Path: "admin.go", Start: 3, End: 3, Quote: "func admin() { // test only"}}},
		{FindingID: ids[3], Verdict: "confirmed", DeploymentExposure: &AuditExposure{Status: "not_deployed", Evidence: &AuditCitation{Path: "Dockerfile", Start: 4, End: 4, Quote: "RUN go build -tags release"}}},
		{FindingID: ids[4], Verdict: "confirmed"},
	}}
	out := applyDeploymentExposure(doc, audit, files, traces)
	if len(out.Runs[0].Results) != 6 {
		t.Fatalf("exposure removed findings: %d", len(out.Runs[0].Results))
	}
	got := func(i int) *sarif.DeploymentExposure { return out.Runs[0].Results[i].Properties.DeploymentExposure }
	reasons := func(i int) []string { return out.Runs[0].Results[i].Properties.AuditReasons }
	if e := got(0); e.Status != "not_deployed" || !e.Grounded || e.EnablingKey != "debug" {
		t.Errorf("grounded build constraint: %+v", e)
	}
	if e := got(1); e.Status != "config_dependent" || e.EnablingKey != "EnableAdmin" || !e.Grounded || e.Trace == nil || !e.Trace.EntryPointFound || e.Trace.Gaps[0] != "config_key_not_set_in_repo:EnableAdmin" {
		t.Errorf("config-dependent exposure: %+v", e)
	}
	if e := got(2); e.Status != "unknown" || e.Grounded || !slices.Contains(reasons(2), "ungrounded_not_deployed") {
		t.Errorf("ungrounded not_deployed: %+v %v", e, reasons(2))
	}
	if e := got(3); e.Status != "not_deployed" || !e.Grounded {
		t.Errorf("deployment file citation from the trace: %+v", e)
	}
	if e := got(4); e.Status != "unknown" || !slices.Contains(reasons(4), "missing_deployment_exposure") {
		t.Errorf("missing exposure: %+v %v", e, reasons(4))
	}
	if e := got(5); e.Status != "not_assessed" || e.Trace == nil {
		t.Errorf("unaudited finding trace: %+v", e)
	}
	if doc.Runs[0].Results[0].Properties.DeploymentExposure != nil {
		t.Error("input document mutated")
	}
}
