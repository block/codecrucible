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

	results := []SARIFResult{
		makeResult("rule-low", "src/app.go", 10, "note"),
		makeResult("rule-high", "src/app.go", 10, "error"),
	}

	doc := testDoc([]SARIFRule{ruleA, ruleB}, results, []SARIFTaxon{
		{ID: "CWE-89", ShortDescription: SARIFMessage{Text: "SQL Injection"}},
	})

	got := PostProcess(doc)
	run := got.Runs[0]

	if len(run.Results) != 1 {
		t.Fatalf("expected 1 result after dedup, got %d", len(run.Results))
	}
	if run.Results[0].RuleID != "rule-high" {
		t.Errorf("expected highest severity rule kept (rule-high), got %s", run.Results[0].RuleID)
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
