package sarif

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"
)

const (
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
	sarifVersion = "2.1.0"
	rulePrefix   = "codecrucible."
)

// FileMap maps relative file paths to their content for snippet extraction.
type FileMap map[string]string

// BuilderConfig holds configuration for the SARIF builder.
type BuilderConfig struct {
	ToolName    string // default: "codecrucible"
	ToolVersion string // default: "dev"
	Logger      *slog.Logger
}

func (c BuilderConfig) toolName() string {
	if c.ToolName != "" {
		return c.ToolName
	}
	return "codecrucible"
}

func (c BuilderConfig) toolVersion() string {
	if c.ToolVersion != "" {
		return c.ToolVersion
	}
	return "dev"
}

func (c BuilderConfig) logger() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.Default()
}

// Build converts an AnalysisResult into a SARIF v2.1.0 document.
func Build(result AnalysisResult, fileMap FileMap, cfg BuilderConfig) SARIFDocument {
	if fileMap == nil {
		fileMap = FileMap{}
	}

	log := cfg.logger()

	// Deduplicate rules: issue text → rule ID.
	type ruleEntry struct {
		rule  SARIFRule
		index int
	}
	rulesByID := make(map[string]*ruleEntry)
	var rules []SARIFRule
	var results []SARIFResult

	// Track CWE taxa for the taxonomy section.
	cweTaxa := make(map[string]SARIFTaxon)

	for _, issue := range result.SecurityIssues {
		ruleID := slugify(issue.Issue)

		if _, exists := rulesByID[ruleID]; !exists {
			rule := SARIFRule{
				ID:               ruleID,
				ShortDescription: SARIFMessage{Text: issue.Issue},
				Properties:       map[string]any{},
			}
			rule.Properties["security-severity"] = fmt.Sprintf("%.1f", issue.Severity)

			// Always include "security" tag; add CWE tag in GitHub's expected format.
			tags := []string{"security"}
			cweTag := extractCWETag(issue.CWEID)
			if cweTag != "" {
				tags = append(tags, "external/cwe/"+cweTag)

				// Add a relationship to the CWE taxonomy.
				cweID := strings.ToUpper(cweTag) // "CWE-89"
				rule.Relationships = []SARIFRelationship{{
					Target: SARIFRelationshipTarget{
						ID:            cweID,
						ToolComponent: SARIFToolComponentRef{Name: "CWE"},
					},
					Kinds: []string{"superset"},
				}}

				// Record the taxon for the taxonomy section.
				if _, seen := cweTaxa[cweID]; !seen {
					cweTaxa[cweID] = SARIFTaxon{
						ID:               cweID,
						ShortDescription: SARIFMessage{Text: issue.CWEID},
					}
				}
			}
			rule.Properties["tags"] = tags

			rulesByID[ruleID] = &ruleEntry{rule: rule, index: len(rules)}
			rules = append(rules, rule)
		}

		r := SARIFResult{
			RuleID:  ruleID,
			Level:   severityLevel(issue.Severity),
			Message: SARIFMessage{Text: issue.TechnicalDetails},
		}

		if issue.FilePath != "" {
			loc := SARIFLocation{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: issue.FilePath},
				},
			}

			if issue.StartLine > 0 {
				region := &SARIFRegion{StartLine: issue.StartLine}
				if issue.EndLine > 0 {
					region.EndLine = issue.EndLine
				}
				snippet := extractSnippet(fileMap, issue.FilePath, issue.StartLine, issue.EndLine, log)
				if snippet != "" {
					region.Snippet = &SARIFSnippet{Text: snippet}
				}
				loc.PhysicalLocation.Region = region
			}

			r.Locations = []SARIFLocation{loc}
		}

		results = append(results, r)
	}

	// Guarantee non-nil slices for clean JSON output.
	if rules == nil {
		rules = []SARIFRule{}
	}
	if results == nil {
		results = []SARIFResult{}
	}

	run := SARIFRun{
		Tool: SARIFTool{
			Driver: SARIFDriver{
				Name:    cfg.toolName(),
				Version: cfg.toolVersion(),
				Rules:   rules,
			},
		},
		Results: results,
		Invocations: []SARIFInvocation{
			{ExecutionSuccessful: true},
		},
	}

	// Add the CWE taxonomy if any CWE references were found.
	if len(cweTaxa) > 0 {
		taxa := make([]SARIFTaxon, 0, len(cweTaxa))
		for _, t := range cweTaxa {
			taxa = append(taxa, t)
		}
		run.Taxonomies = []SARIFTaxonomy{{
			Name:             "CWE",
			Organization:     "MITRE",
			ShortDescription: SARIFMessage{Text: "Common Weakness Enumeration"},
			Taxa:             taxa,
		}}
	}

	return SARIFDocument{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs:    []SARIFRun{run},
	}
}

// severityLevel maps a numeric severity (0–10) to a SARIF level string.
func severityLevel(sev float64) string {
	switch {
	case sev <= 0:
		return "none"
	case sev < 4.0:
		return "note"
	case sev < 7.0:
		return "warning"
	default:
		return "error"
	}
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

// slugify converts an issue title to a rule ID like "codecrucible.sql-injection".
func slugify(text string) string {
	s := strings.ToLower(text)
	s = slugRe.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	return rulePrefix + s
}

var cweRe = regexp.MustCompile(`(?i)CWE-(\d+)`)

// extractCWETag pulls a tag like "cwe-89" from a string such as "CWE-89: SQL Injection".
func extractCWETag(id string) string {
	m := cweRe.FindStringSubmatch(id)
	if len(m) < 2 {
		return ""
	}
	return "cwe-" + m[1]
}

// extractSnippet returns the lines [startLine, endLine] from the file content
// stored in fileMap. Returns "" if the file is missing or lines are out of range.
func extractSnippet(fm FileMap, path string, startLine, endLine int, log *slog.Logger) string {
	content, ok := fm[path]
	if !ok {
		log.Warn("file not found in FileMap, skipping snippet", "path", path)
		return ""
	}

	lines := strings.Split(content, "\n")
	if startLine < 1 {
		startLine = 1
	}
	if endLine < startLine {
		endLine = startLine
	}
	if startLine > len(lines) {
		return ""
	}
	if endLine > len(lines) {
		endLine = len(lines)
	}

	selected := lines[startLine-1 : endLine]
	return strings.Join(selected, "\n")
}
