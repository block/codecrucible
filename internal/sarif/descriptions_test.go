package sarif

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestDescriptionsSharedRuleAndFallback(t *testing.T) {
	doc := Build(AnalysisResult{SecurityIssues: []SecurityIssue{
		{Issue: "SQL injection", FilePath: "z.go", StartLine: 2, TechnicalDetails: "[UNVERIFIED]\n\nCheck `sink()`", CWEID: "CWE-89", Severity: 9},
		{Issue: "SQL injection", FilePath: "a.go", StartLine: 10, TechnicalDetails: "   ", CWEID: "CWE-89", Severity: 9},
		{Issue: "SQL injection", FilePath: "a.go", StartLine: 2, TechnicalDetails: "earlier evidence", CWEID: "CWE-89", Severity: 9},
	}}, nil, BuilderConfig{})
	rule := doc.Runs[0].Tool.Driver.Rules[0]
	if rule.FullDescription.Text != "SQL injection (CWE-89)" {
		t.Fatal(rule.FullDescription)
	}
	for _, help := range []string{rule.Help.Text, rule.Help.Markdown} {
		if !strings.Contains(help, "[UNVERIFIED]\n\nCheck `sink()`") {
			t.Fatal("lost caveat or evidence", help)
		}
		if !(strings.Index(help, "a.go:2") < strings.Index(help, "a.go:10") && strings.Index(help, "a.go:10") < strings.Index(help, "z.go:2")) {
			t.Fatal("non-deterministic location order", help)
		}
	}
	if doc.Runs[0].Results[1].Message.Text != "SQL injection" {
		t.Fatal("missing message fallback")
	}
	if strings.Contains(doc.Runs[0].Results[0].Message.Text, "earlier evidence") {
		t.Fatal("cross-location evidence leaked into result")
	}
	before, _ := json.Marshal(doc)
	again, _ := json.Marshal(RefreshDescriptions(doc))
	if string(before) != string(again) {
		t.Fatal("refresh is not idempotent")
	}
}

func TestDescriptionsRefreshDropsStaleEvidence(t *testing.T) {
	doc := Build(AnalysisResult{SecurityIssues: []SecurityIssue{
		{Issue: "Shared rule", FilePath: "a.go", TechnicalDetails: "removed evidence"},
		{Issue: "Shared rule", FilePath: "b.go", TechnicalDetails: "old evidence"},
	}}, nil, BuilderConfig{})
	changed := doc
	changed.Runs = append([]SARIFRun{}, doc.Runs...)
	changed.Runs[0].Results = []SARIFResult{doc.Runs[0].Results[1]}
	changed.Runs[0].Results[0].Message.Text = "refined evidence [Audit confidence: 90%]"
	changed = RefreshDescriptions(changed)
	help := changed.Runs[0].Tool.Driver.Rules[0].Help.Text
	if strings.Contains(help, "removed evidence") || strings.Contains(help, "old evidence") || !strings.Contains(help, "refined evidence") {
		t.Fatal(help)
	}
	if !strings.Contains(doc.Runs[0].Tool.Driver.Rules[0].Help.Text, "old evidence") {
		t.Fatal("refresh mutated previous snapshot")
	}
}

func TestDescriptionLimitAndEmptyArrays(t *testing.T) {
	doc := Build(AnalysisResult{SecurityIssues: []SecurityIssue{{Issue: strings.Repeat("界", 1100)}}}, nil, BuilderConfig{})
	text := doc.Runs[0].Tool.Driver.Rules[0].FullDescription.Text
	if !utf8.ValidString(text) || utf8.RuneCountInString(text) != 1024 {
		t.Fatal("invalid Unicode truncation")
	}
	data, err := json.Marshal(RefreshDescriptions(Build(AnalysisResult{}, nil, BuilderConfig{})))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"rules":[]`) || !strings.Contains(string(data), `"results":[]`) {
		t.Fatal(string(data))
	}
}
