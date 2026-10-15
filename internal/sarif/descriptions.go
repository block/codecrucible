package sarif

import "strings"

const ruleGuidance = "Each finding carries its own writeup and its state in result " +
	"properties (findingId, verified, auditStatus, auditConfidence, severity, cwe, " +
	"technicalDetails). Validate the reported input, unsafe operation, and missing control " +
	"in context before applying a fix."

// RefreshDescriptions fills rule descriptions and empty result messages.
// Internal rules are shared by every result with the same title, so their help
// must not contain finding-specific evidence or audit verdicts; output gets
// per-finding rules from ReviewPresentation. Plain text stays plain
// text: interpreting payloads or code as Markdown can change their meaning.
// Modified slices and descriptions are owned by the returned snapshot.
func RefreshDescriptions(doc SARIFDocument) SARIFDocument {
	doc.Runs = append([]SARIFRun(nil), doc.Runs...)
	for i := range doc.Runs {
		run := &doc.Runs[i]
		run.Tool.Driver.Rules = append([]SARIFRule{}, run.Tool.Driver.Rules...)
		run.Results = append([]SARIFResult{}, run.Results...)
		titles := make(map[string]string)
		for _, rule := range run.Tool.Driver.Rules {
			title := strings.TrimSpace(rule.ShortDescription.Text)
			if title == "" {
				title = rule.ID
			}
			titles[rule.ID] = title
		}
		for j := range run.Results {
			r := &run.Results[j]
			if strings.TrimSpace(r.Message.Text) == "" {
				r.Message.Text = titles[r.RuleID]
				if r.Message.Text == "" {
					r.Message.Text = r.RuleID
				}
			}
		}
		for j := range run.Tool.Driver.Rules {
			rule := &run.Tool.Driver.Rules[j]
			summary := titles[rule.ID]
			if cwe := CWEForRule(*rule); cwe != "" {
				summary += " (" + cwe + ")"
			}
			runes := []rune(summary)
			if len(runes) > 1024 {
				summary = string(runes[:1023]) + "…"
			}
			rule.FullDescription = &SARIFMessage{Text: summary}
			rule.Help = &SARIFMessage{Text: summary + "\n\n" + ruleGuidance}
		}
	}
	return doc
}
