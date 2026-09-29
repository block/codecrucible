package sarif

import (
	"encoding/json"
	"reflect"
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
		for _, evidence := range []string{"a.go", "z.go", "UNVERIFIED", "sink()", "earlier evidence"} {
			if strings.Contains(help, evidence) {
				t.Fatal("finding evidence leaked into shared rule help", help)
			}
		}
	}
	if rule.Help.Text == "" {
		t.Fatal("missing rule guidance")
	}
	if doc.Runs[0].Results[0].Message.Text != "[UNVERIFIED]\n\nCheck `sink()`" {
		t.Fatal("lost caveat or evidence")
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

func TestDescriptionsStayStableWhenFindingsChange(t *testing.T) {
	doc := Build(AnalysisResult{SecurityIssues: []SecurityIssue{
		{Issue: "Shared rule", FilePath: "a.go", TechnicalDetails: "removed evidence"},
		{Issue: "Shared rule", FilePath: "b.go", TechnicalDetails: "old evidence"},
	}}, nil, BuilderConfig{})
	changed := doc
	changed.Runs = append([]SARIFRun{}, doc.Runs...)
	changed.Runs[0].Results = []SARIFResult{doc.Runs[0].Results[1]}
	changed.Runs[0].Results[0].Message.Text = "refined evidence [Audit confidence: 90%]"
	changed.Runs[0].Results[0].Locations = nil
	changed = RefreshDescriptions(changed)
	if !reflect.DeepEqual(doc.Runs[0].Tool.Driver.Rules, changed.Runs[0].Tool.Driver.Rules) {
		t.Fatal("finding edits changed shared rule descriptions")
	}
	if doc.Runs[0].Results[1].Message.Text != "old evidence" {
		t.Fatal("refresh mutated previous snapshot")
	}
	changed.Runs[0].Tool.Driver.Rules[0].Help.Text = "changed help"
	if doc.Runs[0].Tool.Driver.Rules[0].Help.Text == "changed help" {
		t.Fatal("snapshots share mutable help")
	}
}

func TestDescriptionsPreserveLiteralEvidence(t *testing.T) {
	for _, evidence := range []string{
		"The input <img src=x onerror=alert(1)> is reflected without escaping.",
		`The literal filter \* misses _admin_ and &lt;script&gt;.`,
		"[UNVERIFIED]\n\n```html\n<script>alert(1)</script>\n```\n\n[Audit confidence: 30%] Check `sink()`.",
	} {
		t.Run(evidence, func(t *testing.T) {
			doc := Build(AnalysisResult{SecurityIssues: []SecurityIssue{{
				Issue: "Unsafe <template> & escaping", FilePath: "a.go", TechnicalDetails: evidence,
			}}}, nil, BuilderConfig{})
			data, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			var decoded SARIFDocument
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatal(err)
			}
			message := decoded.Runs[0].Results[0].Message
			if message.Text != evidence || message.Markdown != "" {
				t.Fatalf("literal evidence changed: %+v", message)
			}
			rule := decoded.Runs[0].Tool.Driver.Rules[0]
			if rule.Help.Markdown != "" || rule.FullDescription.Markdown != "" {
				t.Fatal("plain text promoted to Markdown")
			}
		})
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
