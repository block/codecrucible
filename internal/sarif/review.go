package sarif

import (
	"fmt"
	"html"
	"log/slog"
	"path"
	"strings"
)

// BuildCodeFlows emits only steps backed by source in this scan. A missing
// intermediate step invalidates the path: dropping it would imply a connection
// that the model did not establish. An empty path is preferable to a made-up one.
func BuildCodeFlows(steps []CodePathStep, files FileMap) []SARIFCodeFlow {
	if len(steps) == 0 || len(steps) > 100 {
		return nil
	}
	locations := make([]SARIFThreadFlowLocation, 0, len(steps))
	for i, step := range steps {
		step.FilePath, _ = ResolvePath(files, step.FilePath)
		content, ok := files[step.FilePath]
		end := step.EndLine
		if end == 0 {
			end = step.StartLine
		}
		if !ok || content == "" || path.IsAbs(step.FilePath) || path.Clean(step.FilePath) != step.FilePath ||
			strings.HasPrefix(step.FilePath, "../") || strings.ContainsAny(step.FilePath, "\\\x00\r\n") ||
			step.StartLine < 1 || end < step.StartLine || end > len(strings.Split(strings.TrimSuffix(content, "\n"), "\n")) ||
			strings.TrimSpace(step.Message) == "" {
			return nil
		}
		locations = append(locations, SARIFThreadFlowLocation{
			ExecutionOrder: i + 1,
			Location: SARIFLocation{
				Message: &SARIFMessage{Text: step.Message},
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: step.FilePath},
					Region: &SARIFRegion{StartLine: step.StartLine, EndLine: end,
						Snippet: &SARIFSnippet{Text: extractSnippet(files, step.FilePath, step.StartLine, end, slog.Default())}},
				},
			},
		})
	}
	return []SARIFCodeFlow{{ThreadFlows: []SARIFThreadFlow{{Locations: locations}}}}
}

// ReviewPresentation is the serialization boundary, after audit and filtering.
// Internal messages carry full evidence for the audit input. Exported results
// each carry their own writeup and state: the message is that finding's
// reviewer-facing summary, and result.properties holds its ID, verification
// status, confidence, severity, CWE, and full technical details. Rules stay
// generic because every finding with the same title shares one rule.
func ReviewPresentation(doc SARIFDocument) SARIFDocument {
	doc = AssignFindingIDs(RefreshDescriptions(doc))
	for i := range doc.Runs {
		run := &doc.Runs[i]
		ruleIndex := make(map[string]int, len(run.Tool.Driver.Rules))
		for j, rule := range run.Tool.Driver.Rules {
			ruleIndex[rule.ID] = j
		}
		type ruleSeverities struct {
			active, all float64
			hasActive   bool
		}
		severities := make(map[string]*ruleSeverities)
		for j := range run.Results {
			r := &run.Results[j]
			var rule SARIFRule
			if k, ok := ruleIndex[r.RuleID]; ok {
				rule = run.Tool.Driver.Rules[k]
			}
			title := rule.ShortDescription.Text
			if title == "" {
				title = r.RuleID
			}
			props := FindingProperties{}
			if r.Properties != nil {
				props = *r.Properties
			}
			if props.TechnicalDetails == "" {
				props.TechnicalDetails = r.Message.Text
			}
			if strings.TrimSpace(props.Summary) == "" {
				props.Summary = legacySummary(props.TechnicalDetails, title)
			}
			props.Summary = limitReviewText(strings.TrimSpace(props.Summary), 1000)
			if props.AuditStatus == "" {
				props.AuditStatus = "not_audited"
			}
			props.Verified = !IsSuppressed(*r) && verifiedAuditStatus(props.AuditStatus)
			severity := ResultSeverity(*r, rule)
			props.Severity = &severity
			props.CWE = ResultCWE(*r, rule)
			r.Properties = &props
			r.Level = severityLevel(severity)
			r.Message = findingMessage(title, *r)

			s := severities[r.RuleID]
			if s == nil {
				s = &ruleSeverities{}
				severities[r.RuleID] = s
			}
			s.all = max(s.all, severity)
			if !IsSuppressed(*r) {
				s.active = max(s.active, severity)
				s.hasActive = true
			}
		}
		// GitHub reads security-severity only from the rule. Report the worst
		// active finding so a suppressed sibling cannot raise or lower it.
		for j := range run.Tool.Driver.Rules {
			rule := &run.Tool.Driver.Rules[j]
			s := severities[rule.ID]
			if s == nil {
				continue
			}
			severity := s.all
			if s.hasActive {
				severity = s.active
			}
			properties := make(map[string]any, len(rule.Properties)+1)
			for k, v := range rule.Properties {
				properties[k] = v
			}
			properties["security-severity"] = fmt.Sprintf("%.1f", severity)
			rule.Properties = properties
		}
	}
	return doc
}

// verifiedAuditStatus reports whether an audit verdict affirms the finding.
func verifiedAuditStatus(status string) bool {
	switch status {
	case "confirmed", "refined", "escalated":
		return true
	}
	return false
}

// findingMessage renders one finding's writeup from its own properties only.
func findingMessage(title string, r SARIFResult) SARIFMessage {
	p := r.Properties
	text := p.Summary
	if text == "" {
		text = title
	}
	var md strings.Builder
	fmt.Fprintf(&md, "**%s** (%s)\n\n%s", escapeMarkdown(title), escapeMarkdown(reviewLocation(r)), escapeMarkdown(text))
	if p.Remediation != "" {
		fmt.Fprintf(&md, "\n\n**Remediation:** %s", escapeMarkdown(p.Remediation))
	}
	fmt.Fprintf(&md, "\n\n**Status:** %s", escapeMarkdown(reviewStatus(r)))
	if p.FindingID != "" {
		fmt.Fprintf(&md, "\n\n**Finding ID:** %s", escapeMarkdown(p.FindingID))
	}
	if p.TechnicalDetails != "" && p.TechnicalDetails != text {
		fmt.Fprintf(&md, "\n\n<details>\n<summary>Technical details</summary>\n\n<pre>%s</pre>\n</details>", html.EscapeString(p.TechnicalDetails))
	}
	return SARIFMessage{Text: text, Markdown: md.String()}
}

func reviewLocation(r SARIFResult) string {
	if len(r.Locations) == 0 {
		return "Finding"
	}
	p := r.Locations[0].PhysicalLocation
	if p.Region == nil {
		return p.ArtifactLocation.URI
	}
	return fmt.Sprintf("%s:%d", p.ArtifactLocation.URI, p.Region.StartLine)
}

func reviewStatus(r SARIFResult) string {
	p := r.Properties
	var status string
	switch {
	case IsSuppressed(r) && p.DuplicateOf != "":
		status = "Duplicate of " + p.DuplicateOf
	case IsSuppressed(r):
		status = "Rejected by audit"
	case p.AuditStatus == "not_audited":
		status = "Not audited; review manually"
	case p.AuditStatus == "unverified":
		status = "Unverified: the audit could not establish the full exploit path"
		if p.AuditCrux != "" {
			status += ". Open question: " + p.AuditCrux
		}
	case p.AuditStatus == "new":
		status = "Reported by the audit; not independently verified"
	default:
		status = "Audit " + p.AuditStatus
	}
	if p.AuditConfidence != nil && p.AuditStatus != "not_audited" {
		status += fmt.Sprintf(" (confidence %.0f%%)", *p.AuditConfidence*100)
	}
	return status
}

// Older/custom prompts may omit summary. Keep the first narrative paragraph,
// bounded in size, and exclude the verbose audit justification.
func legacySummary(details, title string) string {
	if i := strings.Index(details, "[Audit confidence:"); i >= 0 {
		details = details[:i]
	}
	for _, paragraph := range strings.Split(details, "\n\n") {
		paragraph = strings.TrimSpace(paragraph)
		if paragraph == "" || strings.HasPrefix(paragraph, "[") || strings.HasPrefix(paragraph, "GATE ") {
			continue
		}
		return limitReviewText(paragraph, 1000)
	}
	return title
}

func limitReviewText(s string, max int) string {
	runes := []rune(s)
	if len(runes) > max {
		return string(runes[:max-1]) + "…"
	}
	return s
}

func escapeMarkdown(s string) string {
	s = html.EscapeString(s)
	return strings.NewReplacer("\\", "\\\\", "`", "\\`", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]", "#", "\\#", "!", "\\!", "|", "\\|").Replace(s)
}
