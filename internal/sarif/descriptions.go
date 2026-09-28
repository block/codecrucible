package sarif

import (
	"fmt"
	"sort"
	"strings"
)

// RefreshDescriptions derives rule help from the current results, including
// audit refinements. It owns the slices it modifies so older artifact snapshots
// cannot acquire descriptions from a later pipeline stage.
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
		byRule := make(map[string][]SARIFResult)
		for j := range run.Results {
			r := &run.Results[j]
			if strings.TrimSpace(r.Message.Text) == "" {
				r.Message.Text = titles[r.RuleID]
				if r.Message.Text == "" {
					r.Message.Text = r.RuleID
				}
			}
			byRule[r.RuleID] = append(byRule[r.RuleID], *r)
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
			results := byRule[rule.ID]
			sort.SliceStable(results, func(a, b int) bool {
				ap, al, ae := resultPosition(results[a])
				bp, bl, be := resultPosition(results[b])
				if ap != bp {
					return ap < bp
				}
				if al != bl {
					return al < bl
				}
				if ae != be {
					return ae < be
				}
				return results[a].Message.Text < results[b].Message.Text
			})
			plain := []string{summary}
			markdown := []string{"## " + escapeMarkdown(summary)}
			for _, r := range results {
				file, start, end := resultPosition(r)
				label := file
				if label == "" {
					label = "Location unavailable"
				}
				if start > 0 {
					label += fmt.Sprintf(":%d", start)
				}
				if end > start {
					label += fmt.Sprintf("-%d", end)
				}
				plain = append(plain, label+"\n\n"+r.Message.Text)
				body := r.Message.Markdown
				if body == "" {
					body = r.Message.Text
				}
				markdown = append(markdown, "### "+escapeMarkdown(label)+"\n\n"+body)
			}
			rule.Help = &SARIFMessage{Text: strings.Join(plain, "\n\n"), Markdown: strings.Join(markdown, "\n\n")}
		}
	}
	return doc
}

func resultPosition(r SARIFResult) (string, int, int) {
	if len(r.Locations) == 0 {
		return "", 0, 0
	}
	loc := r.Locations[0].PhysicalLocation
	if loc.Region == nil {
		return loc.ArtifactLocation.URI, 0, 0
	}
	return loc.ArtifactLocation.URI, loc.Region.StartLine, loc.Region.EndLine
}

func escapeMarkdown(s string) string {
	return strings.NewReplacer("\\", "\\\\", "`", "\\`", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]", "<", "&lt;", ">", "&gt;", "#", "\\#", "\n", " ", "\r", " ").Replace(s)
}
