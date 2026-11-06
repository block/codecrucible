package sarif

import "testing"

// helper to build a minimal SARIF document for testing.
func testDoc(rules []SARIFRule, results []SARIFResult, taxa []SARIFTaxon) SARIFDocument {
	var taxonomies []SARIFTaxonomy
	if len(taxa) > 0 {
		taxonomies = []SARIFTaxonomy{{
			Name:             "CWE",
			Organization:     "MITRE",
			ShortDescription: SARIFMessage{Text: "Common Weakness Enumeration"},
			Taxa:             taxa,
		}}
	}
	return SARIFDocument{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []SARIFRun{{
			Tool: SARIFTool{Driver: SARIFDriver{
				Name:    "codecrucible",
				Version: "dev",
				Rules:   rules,
			}},
			Results:    results,
			Taxonomies: taxonomies,
		}},
	}
}

func makeRule(id string, severity string, cweID string) SARIFRule {
	rule := SARIFRule{
		ID:               id,
		ShortDescription: SARIFMessage{Text: id},
		Properties: map[string]any{
			"security-severity": severity,
			"tags":              []string{"security", "external/cwe/" + cweID},
		},
	}
	if cweID != "" {
		upper := "CWE-" + cweID[len("cwe-"):]
		rule.Relationships = []SARIFRelationship{{
			Target: SARIFRelationshipTarget{
				ID:            upper,
				ToolComponent: SARIFToolComponentRef{Name: "CWE"},
			},
			Kinds: []string{"superset"},
		}}
	}
	return rule
}

func makeResult(ruleID, fileURI string, startLine int, level string) SARIFResult {
	return SARIFResult{
		RuleID:  ruleID,
		Level:   level,
		Message: SARIFMessage{Text: "test finding"},
		Locations: []SARIFLocation{{
			PhysicalLocation: SARIFPhysicalLocation{
				ArtifactLocation: SARIFArtifactLocation{URI: fileURI},
				Region:           &SARIFRegion{StartLine: startLine},
			},
		}},
	}
}

func TestDedup_SameFileSameLineSameCWE_KeepsHighestSeverity(t *testing.T) {
	ruleA := makeRule("rule-low", "3.0", "cwe-89")
	ruleB := makeRule("rule-high", "9.0", "cwe-89")
	ruleA.ShortDescription.Text = "Same claim"
	ruleB.ShortDescription.Text = "Same claim"

	results := []SARIFResult{
		makeResult("rule-low", "src/app.go", 10, "note"),
		makeResult("rule-high", "src/app.go", 10, "error"),
	}

	low, high := 3.0, 9.0
	results[0].Properties = &FindingProperties{Severity: &low}
	results[1].Properties = &FindingProperties{Severity: &high}
	doc := testDoc([]SARIFRule{ruleA, ruleB}, results, []SARIFTaxon{
		{ID: "CWE-89", ShortDescription: SARIFMessage{Text: "SQL Injection"}},
	})

	got := PostProcess(doc)
	run := got.Runs[0]

	if len(run.Results) != 1 {
		t.Fatalf("expected 1 result after dedup, got %d", len(run.Results))
	}
	if run.Results[0].Level != "error" {
		t.Errorf("expected highest severity result, got rule %s", run.Results[0].RuleID)
	}
}

func TestDedup_SameFileSameLineDifferentCWE_KeepsBoth(t *testing.T) {
	ruleA := makeRule("rule-sqli", "7.0", "cwe-89")
	ruleB := makeRule("rule-xss", "5.0", "cwe-79")

	results := []SARIFResult{
		makeResult("rule-sqli", "src/app.go", 10, "error"),
		makeResult("rule-xss", "src/app.go", 10, "warning"),
	}

	doc := testDoc([]SARIFRule{ruleA, ruleB}, results, []SARIFTaxon{
		{ID: "CWE-89", ShortDescription: SARIFMessage{Text: "SQL Injection"}},
		{ID: "CWE-79", ShortDescription: SARIFMessage{Text: "XSS"}},
	})

	got := PostProcess(doc)
	run := got.Runs[0]

	if len(run.Results) != 2 {
		t.Fatalf("expected 2 results (different CWEs), got %d", len(run.Results))
	}
}

func TestDeprioritize_NonSourceFile_LowSeverityRemoved(t *testing.T) {
	rule := makeRule("rule-secret", "3.0", "cwe-798")
	results := []SARIFResult{
		makeResult("rule-secret", "package.json", 5, "warning"),
	}

	doc := testDoc([]SARIFRule{rule}, results, []SARIFTaxon{
		{ID: "CWE-798", ShortDescription: SARIFMessage{Text: "Hardcoded Credentials"}},
	})

	got := PostProcess(doc)
	run := got.Runs[0]

	if len(run.Results) != 0 {
		t.Fatalf("expected 0 results (low-severity non-source removed), got %d", len(run.Results))
	}
}

func TestDeprioritize_NonSourceFile_ErrorLevelKept(t *testing.T) {
	rule := makeRule("rule-secret", "8.0", "cwe-798")
	results := []SARIFResult{
		makeResult("rule-secret", "package.json", 5, "error"),
	}

	doc := testDoc([]SARIFRule{rule}, results, []SARIFTaxon{
		{ID: "CWE-798", ShortDescription: SARIFMessage{Text: "Hardcoded Credentials"}},
	})

	got := PostProcess(doc)
	run := got.Runs[0]

	if len(run.Results) != 1 {
		t.Fatalf("expected 1 result (error-level non-source kept), got %d", len(run.Results))
	}
	if run.Results[0].Level != "error" {
		t.Errorf("expected level 'error' preserved, got %q", run.Results[0].Level)
	}
}

func TestDeprioritize_SourceFileKeepsLevel(t *testing.T) {
	rule := makeRule("rule-sqli", "9.0", "cwe-89")
	results := []SARIFResult{
		makeResult("rule-sqli", "routes/login.ts", 42, "error"),
	}

	doc := testDoc([]SARIFRule{rule}, results, []SARIFTaxon{
		{ID: "CWE-89", ShortDescription: SARIFMessage{Text: "SQL Injection"}},
	})

	got := PostProcess(doc)
	run := got.Runs[0]

	if len(run.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(run.Results))
	}
	if run.Results[0].Level != "error" {
		t.Errorf("expected level 'error' for source file, got %q", run.Results[0].Level)
	}
}

func TestOrphanedRuleCleanup(t *testing.T) {
	ruleA := makeRule("rule-used", "7.0", "cwe-89")
	ruleB := makeRule("rule-orphan", "5.0", "cwe-79")

	results := []SARIFResult{
		makeResult("rule-used", "src/app.go", 10, "error"),
	}

	doc := testDoc([]SARIFRule{ruleA, ruleB}, results, []SARIFTaxon{
		{ID: "CWE-89", ShortDescription: SARIFMessage{Text: "SQL Injection"}},
		{ID: "CWE-79", ShortDescription: SARIFMessage{Text: "XSS"}},
	})

	got := PostProcess(doc)
	run := got.Runs[0]

	if len(run.Tool.Driver.Rules) != 1 {
		t.Fatalf("expected 1 rule after orphan cleanup, got %d", len(run.Tool.Driver.Rules))
	}
	if run.Tool.Driver.Rules[0].ID != "rule-used" {
		t.Errorf("expected rule-used to survive, got %s", run.Tool.Driver.Rules[0].ID)
	}

	// CWE-79 taxon should also be removed.
	if len(run.Taxonomies) != 1 {
		t.Fatalf("expected 1 taxonomy, got %d", len(run.Taxonomies))
	}
	if len(run.Taxonomies[0].Taxa) != 1 {
		t.Fatalf("expected 1 taxon after cleanup, got %d", len(run.Taxonomies[0].Taxa))
	}
	if run.Taxonomies[0].Taxa[0].ID != "CWE-89" {
		t.Errorf("expected CWE-89 taxon to survive, got %s", run.Taxonomies[0].Taxa[0].ID)
	}
}

func TestCweForRule(t *testing.T) {
	tests := []struct {
		name string
		rule SARIFRule
		want string
	}{
		{
			name: "from relationship",
			rule: SARIFRule{
				Relationships: []SARIFRelationship{{
					Target: SARIFRelationshipTarget{ID: "CWE-89"},
				}},
			},
			want: "CWE-89",
		},
		{
			name: "relationship without CWE prefix falls through",
			rule: SARIFRule{
				Relationships: []SARIFRelationship{{
					Target: SARIFRelationshipTarget{ID: "OWASP-A01"},
				}},
			},
			want: "",
		},
		{
			name: "from tag when no relationship",
			rule: SARIFRule{
				Properties: map[string]any{
					"tags": []string{"security", "external/cwe/cwe-79"},
				},
			},
			want: "CWE-79",
		},
		{
			name: "tags wrong type ignored",
			rule: SARIFRule{
				Properties: map[string]any{"tags": "not-a-slice"},
			},
			want: "",
		},
		{
			name: "no tags no relationships",
			rule: SARIFRule{},
			want: "",
		},
		{
			name: "tags present but no cwe tag",
			rule: SARIFRule{
				Properties: map[string]any{
					"tags": []string{"security", "performance"},
				},
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CWEForRule(tt.rule); got != tt.want {
				t.Errorf("CWEForRule() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDedupMergesProseDifferencesAtSameAnchor(t *testing.T) {
	rule := makeRule("query", "8", "cwe-89")
	a := makeResult("query", "a.go", 1, "error")
	b := a
	b.Message.Text = "Different attacker and data flow"
	doc := testDoc([]SARIFRule{rule}, []SARIFResult{a, b}, nil)
	if got := PostProcess(doc); len(got.Runs[0].Results) != 1 {
		t.Fatal("prose-only duplicates retained")
	}
	if got := Merge([]SARIFDocument{testDoc([]SARIFRule{rule}, []SARIFResult{a}, nil), testDoc([]SARIFRule{rule}, []SARIFResult{b}, nil)}); len(got.Runs[0].Results) != 1 {
		t.Fatal("merge retained prose-only duplicates")
	}
}

func TestDedupPreservesStructuralAnchors(t *testing.T) {
	rule := makeRule("query", "8", "cwe-89")
	a := makeResult("query", "a.go", 1, "error")
	a.Properties = &FindingProperties{ReportedLocations: makeResult("query", "other.go", 2, "error").Locations}
	b := a
	b.Properties = &FindingProperties{ReportedLocations: makeResult("query", "source.go", 7, "error").Locations}
	for _, got := range []SARIFDocument{PostProcess(testDoc([]SARIFRule{rule}, []SARIFResult{a, b}, nil)), Merge([]SARIFDocument{testDoc([]SARIFRule{rule}, []SARIFResult{a}, nil), testDoc([]SARIFRule{rule}, []SARIFResult{b}, nil)})} {
		if len(got.Runs[0].Results) != 2 {
			t.Fatal("distinct anchors merged")
		}
	}
}

func TestDedupFlowEndpointsAndMissingEvidence(t *testing.T) {
	flow := func(lines ...int) []SARIFCodeFlow {
		var locs []SARIFThreadFlowLocation
		for _, line := range lines {
			locs = append(locs, SARIFThreadFlowLocation{Location: makeResult("query", "a.go", line, "error").Locations[0]})
		}
		return []SARIFCodeFlow{{ThreadFlows: []SARIFThreadFlow{{Locations: locs}}}}
	}
	for _, tc := range []struct {
		name        string
		left, right []SARIFCodeFlow
		want        int
	}{
		{"missing", nil, flow(2, 10), 1},
		{"middle step", flow(2, 10), flow(2, 6, 10), 1},
		{"different source", flow(2, 10), flow(3, 10), 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := makeRule("query", "8", "cwe-89")
			a, b := makeResult("query", "a.go", 10, "error"), makeResult("query", "a.go", 10, "error")
			a.CodeFlows, b.CodeFlows = tc.left, tc.right
			got := PostProcess(Merge([]SARIFDocument{testDoc([]SARIFRule{rule}, []SARIFResult{a}, nil), testDoc([]SARIFRule{rule}, []SARIFResult{b}, nil)}))
			if len(got.Runs[0].Results) != tc.want {
				t.Fatalf("got %d want %d", len(got.Runs[0].Results), tc.want)
			}
		})
	}
}

func TestDedupPreservesFlowWhenAnchorlessSeverityWins(t *testing.T) {
	rule := makeRule("query", "8", "cwe-89")
	a, b := makeResult("query", "a.go", 10, "error"), makeResult("query", "a.go", 10, "error")
	low, high := 5.0, 9.0
	a.Properties = &FindingProperties{Severity: &low}
	b.Properties = &FindingProperties{Severity: &high}
	a.CodeFlows = []SARIFCodeFlow{{ThreadFlows: []SARIFThreadFlow{{Locations: []SARIFThreadFlowLocation{{Location: a.Locations[0]}}}}}}
	for _, results := range [][]SARIFResult{{a, b}, {b, a}} {
		got := PostProcess(testDoc([]SARIFRule{rule}, results, nil)).Runs[0].Results
		if len(got) != 1 || len(got[0].CodeFlows) != 1 || ResultSeverity(got[0], rule) != 9 {
			t.Fatal("severity or source path lost", got)
		}
	}
}
