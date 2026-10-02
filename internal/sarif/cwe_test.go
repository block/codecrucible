package sarif

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCWEAssignmentsSplitSharedRulesAndPreserveIdentity(t *testing.T) {
	doc := WithFindingIDs(Build(AnalysisResult{SecurityIssues: []SecurityIssue{
		{Issue: "Injection", FilePath: "a.go", StartLine: 2, CWEID: "CWE-79", Severity: 8, TechnicalDetails: "SQL command"},
		{Issue: "Injection", FilePath: "b.go", StartLine: 3, CWEID: "CWE-79", Severity: 8, TechnicalDetails: "HTML output"},
	}}, nil, BuilderConfig{}))
	before, _ := json.Marshal(doc)
	id := doc.Runs[0].Results[0].Properties.FindingID
	out := ApplyCWEAssignments(doc, map[string]CWEAssignment{id: {ID: "CWE-89: SQL Injection", Source: "generative_audit"}})
	if len(out.Runs[0].Results) != 2 || len(out.Runs[0].Tool.Driver.Rules) != 2 {
		t.Fatal("changed finding count or shared the remapped rule")
	}
	rules := map[string]SARIFRule{}
	for _, r := range out.Runs[0].Tool.Driver.Rules {
		rules[r.ID] = r
	}
	a, b := out.Runs[0].Results[0], out.Runs[0].Results[1]
	if CWEForRule(rules[a.RuleID]) != "CWE-89" || CWEForRule(rules[b.RuleID]) != "CWE-79" || a.Properties.FindingID != id {
		t.Fatal("assignment leaked or identity changed")
	}
	if !strings.Contains(rules[a.RuleID].Help.Text, "CWE-89") || a.Properties.CWEChanges[0].Original != "CWE-79" {
		t.Fatal("missing display/provenance")
	}
	found := false
	for _, taxonomy := range out.Runs[0].Taxonomies {
		for _, taxon := range taxonomy.Taxa {
			found = found || taxon.ID == "CWE-89"
		}
	}
	if !found {
		t.Fatal("missing taxonomy target")
	}
	after, _ := json.Marshal(doc)
	if string(before) != string(after) {
		t.Fatal("mutated input artifact")
	}
	for _, invalid := range []string{"CWE-999999", "CWE-284", "CWE-1", "CWE-89\nCWE-79"} {
		unchanged := ApplyCWEAssignments(doc, map[string]CWEAssignment{id: {ID: invalid, Source: "generative_audit"}})
		if unchanged.Runs[0].Results[0].RuleID != doc.Runs[0].Results[0].RuleID {
			t.Fatalf("accepted %s", invalid)
		}
	}
}
