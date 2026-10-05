package sarif

import (
	"fmt"
	"html"
	"log/slog"
	"path"
	"regexp"
	"sort"
	"strconv"
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
// The internal message still carries full evidence for the audit input. Exported
// messages are short annotations; GitHub's issue panel uses rule.help. Rule IDs
// stay stable, and shared-rule help attributes each finding to its own location.
func ReviewPresentation(doc SARIFDocument) SARIFDocument {
	doc = RefreshDescriptions(doc)
	for i := range doc.Runs {
		run := &doc.Runs[i]
		byRule := make(map[string][]SARIFResult)
		titles := make(map[string]string)
		for _, rule := range run.Tool.Driver.Rules {
			titles[rule.ID] = rule.ShortDescription.Text
		}
		for j := range run.Results {
			r := &run.Results[j]
			props := FindingProperties{}
			if r.Properties != nil {
				props = *r.Properties
			}
			if props.TechnicalDetails == "" {
				props.TechnicalDetails = r.Message.Text
			}
			separateLegacyAudit(&props)
			if strings.TrimSpace(props.Summary) == "" {
				props.Summary = legacySummary(props.TechnicalDetails, titles[r.RuleID])
			}
			props.Summary = limitReviewText(strings.TrimSpace(props.Summary), 1000)
			r.Properties = &props
			annotation := titles[r.RuleID]
			if annotation == "" {
				annotation = r.RuleID
			}
			r.Message = SARIFMessage{Text: annotation}
			byRule[r.RuleID] = append(byRule[r.RuleID], *r)
		}
		for j := range run.Tool.Driver.Rules {
			rule := &run.Tool.Driver.Rules[j]
			findings := byRule[rule.ID]
			if len(findings) == 0 {
				continue
			}
			if len(findings) == 1 {
				p := findings[0].Properties
				text := p.Summary

				rule.FullDescription = &SARIFMessage{Text: limitReviewText(text, 1024)}
			}
			sort.SliceStable(findings, func(a, b int) bool { return reviewLocation(findings[a]) < reviewLocation(findings[b]) })
			var plain, markdown strings.Builder
			for n, r := range findings {
				if n > 0 {
					plain.WriteString("\n\n")
					markdown.WriteString("\n\n---\n\n")
				}
				p := r.Properties
				location := reviewLocation(r)
				fmt.Fprintf(&plain, "%s\n\n%s", location, p.Summary)
				fmt.Fprintf(&markdown, "### %s\n\n%s", escapeMarkdown(location), escapeMarkdown(p.Summary))
				if p.Remediation != "" {
					fmt.Fprintf(&plain, "\n\nRemediation: %s", p.Remediation)
					fmt.Fprintf(&markdown, "\n\n**Remediation:** %s", escapeMarkdown(p.Remediation))
				}
				// Full evidence is retained even without Markdown details support.
				plain.WriteString("\n\nFull technical details: result.properties.technicalDetails in the SARIF artifact.")
				fmt.Fprintf(&markdown, "\n\n<details>\n<summary>Technical details</summary>\n\n<pre>%s</pre>\n</details>", html.EscapeString(p.TechnicalDetails))
			}
			rule.Help = &SARIFMessage{Text: plain.String(), Markdown: markdown.String()}
		}
	}
	return doc
}

var legacyAuditConfidence = regexp.MustCompile(`(?m)^\[Audit confidence: ([0-9]+(?:\.[0-9]+)?)%\]`)

// Older saved findings embedded scanner metadata in the evidence text. Move
// only the known scanner annotations; do not interpret arbitrary source prose.
func separateLegacyAudit(p *FindingProperties) {
	for _, prefix := range []string{"[UNVERIFIED]\n\n", "[UNVERIFIED — original claim retained]\n\n"} {
		if strings.HasPrefix(p.TechnicalDetails, prefix) {
			p.TechnicalDetails = strings.TrimPrefix(p.TechnicalDetails, prefix)
			if p.AuditStatus == "" {
				p.AuditStatus = "unverified"
			}
		}
	}
	match := legacyAuditConfidence.FindStringSubmatchIndex(p.TechnicalDetails)
	if match == nil {
		return
	}
	confidence, err := strconv.ParseFloat(p.TechnicalDetails[match[2]:match[3]], 64)
	if err != nil || confidence > 100 {
		return
	}
	if p.AuditConfidence == nil {
		confidence /= 100
		p.AuditConfidence = &confidence
	}
	if p.AuditJustification == "" {
		p.AuditJustification = strings.TrimSpace(p.TechnicalDetails[match[1]:])
	}
	p.TechnicalDetails = strings.TrimSpace(p.TechnicalDetails[:match[0]])
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
