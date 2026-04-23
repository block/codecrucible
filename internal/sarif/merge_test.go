package sarif

import (
	"encoding/json"
	"testing"
)

func makeDoc(rules []SARIFRule, results []SARIFResult, invocations []SARIFInvocation) SARIFDocument {
	if rules == nil {
		rules = []SARIFRule{}
	}
	if results == nil {
		results = []SARIFResult{}
	}
	if invocations == nil {
		invocations = []SARIFInvocation{{ExecutionSuccessful: true}}
	}
	return SARIFDocument{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []SARIFRun{{
			Tool: SARIFTool{Driver: SARIFDriver{
				Name:    "codecrucible",
				Version: "1.0",
				Rules:   rules,
			}},
			Results:     results,
			Invocations: invocations,
		}},
	}
}

func TestMerge_Empty(t *testing.T) {
	doc := Merge(nil)
	if len(doc.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(doc.Runs))
	}
	if len(doc.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(doc.Runs[0].Results))
	}
	if len(doc.Runs[0].Tool.Driver.Rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(doc.Runs[0].Tool.Driver.Rules))
	}
}

func TestMerge_SingleDocument(t *testing.T) {
	doc := makeDoc(
		[]SARIFRule{{ID: "codecrucible.xss", ShortDescription: SARIFMessage{Text: "XSS"}}},
		[]SARIFResult{{RuleID: "codecrucible.xss", Level: "error", Message: SARIFMessage{Text: "found xss"}}},
		nil,
	)
	merged := Merge([]SARIFDocument{doc})

	if len(merged.Runs[0].Tool.Driver.Rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(merged.Runs[0].Tool.Driver.Rules))
	}
	if len(merged.Runs[0].Results) != 1 {
		t.Errorf("expected 1 result, got %d", len(merged.Runs[0].Results))
	}
}

func TestMerge_NoOverlappingRules(t *testing.T) {
	doc1 := makeDoc(
		[]SARIFRule{{ID: "codecrucible.xss", ShortDescription: SARIFMessage{Text: "XSS"}}},
		[]SARIFResult{{
			RuleID: "codecrucible.xss", Level: "error",
			Message:   SARIFMessage{Text: "xss"},
			Locations: []SARIFLocation{{PhysicalLocation: SARIFPhysicalLocation{ArtifactLocation: SARIFArtifactLocation{URI: "a.go"}, Region: &SARIFRegion{StartLine: 1}}}},
		}},
		nil,
	)
	doc2 := makeDoc(
		[]SARIFRule{{ID: "codecrucible.sqli", ShortDescription: SARIFMessage{Text: "SQLi"}}},
		[]SARIFResult{{
			RuleID: "codecrucible.sqli", Level: "warning",
			Message:   SARIFMessage{Text: "sqli"},
			Locations: []SARIFLocation{{PhysicalLocation: SARIFPhysicalLocation{ArtifactLocation: SARIFArtifactLocation{URI: "b.go"}, Region: &SARIFRegion{StartLine: 5}}}},
		}},
		nil,
	)

	merged := Merge([]SARIFDocument{doc1, doc2})
	if len(merged.Runs[0].Tool.Driver.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(merged.Runs[0].Tool.Driver.Rules))
	}
	if len(merged.Runs[0].Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(merged.Runs[0].Results))
	}
}

func TestMerge_OverlappingRulesDedup(t *testing.T) {
	doc1 := makeDoc(
		[]SARIFRule{{ID: "codecrucible.sql-injection", ShortDescription: SARIFMessage{Text: "SQL Injection"}}},
		[]SARIFResult{{
			RuleID: "codecrucible.sql-injection", Level: "error",
			Message:   SARIFMessage{Text: "injection in a"},
			Locations: []SARIFLocation{{PhysicalLocation: SARIFPhysicalLocation{ArtifactLocation: SARIFArtifactLocation{URI: "a.go"}, Region: &SARIFRegion{StartLine: 10}}}},
		}},
		nil,
	)
	// Same rule but slightly different slug (trailing period).
	doc2 := makeDoc(
		[]SARIFRule{{ID: "codecrucible.sql-injection-", ShortDescription: SARIFMessage{Text: "SQL Injection."}}},
		[]SARIFResult{{
			RuleID: "codecrucible.sql-injection-", Level: "error",
			Message:   SARIFMessage{Text: "injection in b"},
			Locations: []SARIFLocation{{PhysicalLocation: SARIFPhysicalLocation{ArtifactLocation: SARIFArtifactLocation{URI: "b.go"}, Region: &SARIFRegion{StartLine: 20}}}},
		}},
		nil,
	)

	merged := Merge([]SARIFDocument{doc1, doc2})
	if len(merged.Runs[0].Tool.Driver.Rules) != 1 {
		t.Errorf("expected 1 deduplicated rule, got %d", len(merged.Runs[0].Tool.Driver.Rules))
	}
	if len(merged.Runs[0].Results) != 2 {
		t.Errorf("expected 2 results (different locations), got %d", len(merged.Runs[0].Results))
	}
}

func TestMerge_ResultDedup(t *testing.T) {
	result := SARIFResult{
		RuleID: "codecrucible.xss", Level: "error",
		Message:   SARIFMessage{Text: "found xss"},
		Locations: []SARIFLocation{{PhysicalLocation: SARIFPhysicalLocation{ArtifactLocation: SARIFArtifactLocation{URI: "handler.go"}, Region: &SARIFRegion{StartLine: 42}}}},
	}
	doc1 := makeDoc(
		[]SARIFRule{{ID: "codecrucible.xss", ShortDescription: SARIFMessage{Text: "XSS"}}},
		[]SARIFResult{result},
		nil,
	)
	doc2 := makeDoc(
		[]SARIFRule{{ID: "codecrucible.xss", ShortDescription: SARIFMessage{Text: "XSS"}}},
		[]SARIFResult{result},
		nil,
	)

	merged := Merge([]SARIFDocument{doc1, doc2})
	if len(merged.Runs[0].Results) != 1 {
		t.Errorf("expected 1 deduplicated result, got %d", len(merged.Runs[0].Results))
	}
}

func TestMerge_EmptyChunk(t *testing.T) {
	doc1 := makeDoc(
		[]SARIFRule{{ID: "codecrucible.xss", ShortDescription: SARIFMessage{Text: "XSS"}}},
		[]SARIFResult{{RuleID: "codecrucible.xss", Level: "error", Message: SARIFMessage{Text: "xss"}}},
		nil,
	)
	doc2 := makeDoc(nil, nil, nil) // empty chunk

	merged := Merge([]SARIFDocument{doc1, doc2})
	if len(merged.Runs[0].Tool.Driver.Rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(merged.Runs[0].Tool.Driver.Rules))
	}
	if len(merged.Runs[0].Results) != 1 {
		t.Errorf("expected 1 result, got %d", len(merged.Runs[0].Results))
	}
}

func TestMerge_PartialFailureNotifications(t *testing.T) {
	doc1 := makeDoc(nil, nil, []SARIFInvocation{{
		ExecutionSuccessful:        true,
		ToolExecutionNotifications: nil,
	}})
	doc2 := makeDoc(nil, nil, []SARIFInvocation{{
		ExecutionSuccessful: false,
		ToolExecutionNotifications: []SARIFNotification{{
			Level:   "error",
			Message: SARIFMessage{Text: "chunk 2 failed after retries"},
		}},
	}})

	merged := Merge([]SARIFDocument{doc1, doc2})
	inv := merged.Runs[0].Invocations[0]
	if inv.ExecutionSuccessful {
		t.Error("expected ExecutionSuccessful=false when any chunk failed")
	}
	if len(inv.ToolExecutionNotifications) != 1 {
		t.Fatalf("expected 1 notification, got %d", len(inv.ToolExecutionNotifications))
	}
	if inv.ToolExecutionNotifications[0].Message.Text != "chunk 2 failed after retries" {
		t.Errorf("unexpected notification: %s", inv.ToolExecutionNotifications[0].Message.Text)
	}
}

func TestMerge_RuleNormalization(t *testing.T) {
	tests := []struct {
		name string
		ids  []string
		want int // expected number of merged rules
	}{
		{
			name: "trailing punctuation",
			ids:  []string{"codecrucible.sql-injection", "codecrucible.sql-injection-"},
			want: 1,
		},
		{
			name: "different rules stay separate",
			ids:  []string{"codecrucible.xss", "codecrucible.sqli"},
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var docs []SARIFDocument
			for i, id := range tt.ids {
				docs = append(docs, makeDoc(
					[]SARIFRule{{ID: id, ShortDescription: SARIFMessage{Text: id}}},
					[]SARIFResult{{
						RuleID: id, Level: "warning",
						Message:   SARIFMessage{Text: "test"},
						Locations: []SARIFLocation{{PhysicalLocation: SARIFPhysicalLocation{ArtifactLocation: SARIFArtifactLocation{URI: "file.go"}, Region: &SARIFRegion{StartLine: i + 1}}}},
					}},
					nil,
				))
			}
			merged := Merge(docs)
			if got := len(merged.Runs[0].Tool.Driver.Rules); got != tt.want {
				t.Errorf("rules: got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestMerge_ProducesValidJSON(t *testing.T) {
	doc1 := makeDoc(
		[]SARIFRule{{ID: "codecrucible.test", ShortDescription: SARIFMessage{Text: "Test"}, Properties: map[string]any{"security-severity": "5.0"}}},
		[]SARIFResult{{RuleID: "codecrucible.test", Level: "warning", Message: SARIFMessage{Text: "details"}}},
		nil,
	)
	merged := Merge([]SARIFDocument{doc1})

	b, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal merged SARIF: %v", err)
	}

	var check SARIFDocument
	if err := json.Unmarshal(b, &check); err != nil {
		t.Fatalf("failed to unmarshal merged SARIF: %v", err)
	}
	if check.Version != sarifVersion {
		t.Errorf("version: got %q, want %q", check.Version, sarifVersion)
	}
}

func TestMerge_InvocationAllSuccessful(t *testing.T) {
	doc1 := makeDoc(nil, nil, []SARIFInvocation{{ExecutionSuccessful: true}})
	doc2 := makeDoc(nil, nil, []SARIFInvocation{{ExecutionSuccessful: true}})

	merged := Merge([]SARIFDocument{doc1, doc2})
	if !merged.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Error("expected ExecutionSuccessful=true when all chunks succeed")
	}
}

func TestNormalizeRuleID(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"codecrucible.sql-injection", "codecrucible.sql-injection"},
		{"codecrucible.sql-injection-", "codecrucible.sql-injection"},
		{"codecrucible.xss", "codecrucible.xss"},
		{"codecrucible.some-issue-with-trailing-period-", "codecrucible.some-issue-with-trailing-period"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeRuleID(tt.input)
			if got != tt.want {
				t.Errorf("normalizeRuleID(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
