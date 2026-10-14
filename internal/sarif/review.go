package sarif

import (
	"fmt"
	"html"
	"log/slog"
	"path"
	"regexp"
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
// Internal messages carry full evidence for the audit input. GitHub renders
// result messages as plain-text annotations and only rule help as Markdown, so
// each exported finding gets its own rule: the rule's description and help are
// that finding's writeup, and the message is a one-line annotation. Rules are
// keyed by finding ID, which excludes model wording, so a reworded title keeps
// the alert. result.properties holds the full state for other consumers.
func ReviewPresentation(doc SARIFDocument) SARIFDocument {
	doc = AssignFindingIDs(RefreshDescriptions(doc))
	for i := range doc.Runs {
		run := &doc.Runs[i]
		ruleIndex := make(map[string]int, len(run.Tool.Driver.Rules))
		for j, rule := range run.Tool.Driver.Rules {
			ruleIndex[rule.ID] = j
		}
		rules := make([]SARIFRule, 0, len(run.Results))
		emitted := make(map[string]bool, len(run.Results))
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
			r.Message = SARIFMessage{Text: firstSentence(props.Summary) + ". " + reviewStatus(*r) + "."}
			r.RuleID = rulePrefix + props.FindingID
			if !emitted[r.RuleID] {
				emitted[r.RuleID] = true
				rules = append(rules, findingRule(r.RuleID, title, rule, *r))
			}
		}
		run.Tool.Driver.Rules = rules
		run.Taxonomies = withCWETaxa(run.Taxonomies, run.Results)
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

// findingRule renders one finding's writeup from its own properties only. The
// finding ID is the rule ID, so the writeup omits it, and the annotation and
// code flows already show the location.
func findingRule(id, title string, base SARIFRule, r SARIFResult) SARIFRule {
	p := r.Properties
	status := reviewStatus(r)
	var text, md strings.Builder
	fmt.Fprintf(&text, "%s\n\nStatus: %s", p.Summary, status)
	fmt.Fprintf(&md, "%s\n\n**Status:** %s", markdownText(p.Summary), markdownText(status))
	if p.Remediation != "" {
		fmt.Fprintf(&text, "\n\nRemediation: %s", p.Remediation)
		fmt.Fprintf(&md, "\n\n#### Remediation\n\n%s", markdownText(p.Remediation))
	}
	if p.TechnicalDetails != "" && p.TechnicalDetails != p.Summary {
		fmt.Fprintf(&text, "\n\nTechnical details:\n%s", p.TechnicalDetails)
		md.WriteString("\n\n<details>\n<summary>Technical details</summary>\n")
		for _, paragraph := range strings.Split(p.TechnicalDetails, "\n\n") {
			if paragraph = strings.TrimSpace(paragraph); paragraph != "" {
				md.WriteString("\n" + markdownText(paragraph) + "\n")
			}
		}
		md.WriteString("\n</details>")
	}

	properties := make(map[string]any, len(base.Properties)+2)
	for k, v := range base.Properties {
		properties[k] = v
	}
	// GitHub reads security-severity and the CWE tag only from the rule.
	properties["security-severity"] = fmt.Sprintf("%.1f", *p.Severity)
	tags := []string{"security"}
	var relationships []SARIFRelationship
	if p.CWE != "" {
		tags = append(tags, "external/cwe/"+strings.ToLower(p.CWE))
		relationships = []SARIFRelationship{{
			Target: SARIFRelationshipTarget{ID: p.CWE, ToolComponent: SARIFToolComponentRef{Name: "CWE"}},
			Kinds:  []string{"superset"},
		}}
	}
	properties["tags"] = tags
	return SARIFRule{
		ID:               id,
		ShortDescription: SARIFMessage{Text: limitReviewText(title, 1024)},
		FullDescription:  &SARIFMessage{Text: limitReviewText(p.Summary, 1024)},
		Help:             &SARIFMessage{Text: text.String(), Markdown: md.String()},
		Properties:       properties,
		Relationships:    relationships,
	}
}

// withCWETaxa adds taxa for CWEs that the audit introduced, so every rule
// relationship resolves. Existing entries are kept.
func withCWETaxa(taxonomies []SARIFTaxonomy, results []SARIFResult) []SARIFTaxonomy {
	taxonomies = append([]SARIFTaxonomy(nil), taxonomies...)
	index := -1
	seen := make(map[string]bool)
	for i, t := range taxonomies {
		if t.Name == "CWE" {
			index = i
			for _, taxon := range t.Taxa {
				seen[taxon.ID] = true
			}
		}
	}
	for _, r := range results {
		cwe := r.Properties.CWE
		if cwe == "" || seen[cwe] {
			continue
		}
		seen[cwe] = true
		if index < 0 {
			index = len(taxonomies)
			taxonomies = append(taxonomies, SARIFTaxonomy{Name: "CWE", Organization: "MITRE",
				ShortDescription: SARIFMessage{Text: "Common Weakness Enumeration"}})
		}
		t := &taxonomies[index]
		t.Taxa = append(append([]SARIFTaxon(nil), t.Taxa...), SARIFTaxon{ID: cwe, ShortDescription: SARIFMessage{Text: cwe}})
	}
	if len(taxonomies) == 0 {
		return nil
	}
	return taxonomies
}

var sentenceEnd = regexp.MustCompile(`[.!?]\s+[A-Z]`)

// firstSentence keeps annotations to one line: GitHub uses the message as the
// alert title, and the full summary is the rule description beside it.
func firstSentence(s string) string {
	if loc := sentenceEnd.FindStringIndex(s); loc != nil {
		s = s[:loc[0]]
	}
	return limitReviewText(strings.TrimRight(s, ".!? "), 300)
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

// markdownText renders model prose so it displays literally, except that
// balanced backtick spans become inline code.
func markdownText(s string) string {
	parts := strings.Split(s, "`")
	if len(parts)%2 == 0 {
		return escapeMarkdown(s)
	}
	var b strings.Builder
	for i, part := range parts {
		if i%2 == 1 {
			b.WriteString("<code>" + html.EscapeString(part) + "</code>")
		} else {
			b.WriteString(escapeMarkdown(part))
		}
	}
	return b.String()
}

// escapeMarkdown backslash-escapes Markdown syntax, then HTML. The other order
// escapes the "#" in entities such as &#39;, which then render literally.
func escapeMarkdown(s string) string {
	s = strings.NewReplacer("\\", "\\\\", "`", "\\`", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]", "#", "\\#", "!", "\\!", "|", "\\|").Replace(s)
	return html.EscapeString(s)
}
