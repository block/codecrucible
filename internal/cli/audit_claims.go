package cli

import (
	"fmt"
	"strings"

	"github.com/block/codecrucible/internal/sarif"
)

// auditClaim is an analysis finding presented to either audit contract as a claim.
type auditClaim struct {
	FindingID               string                `json:"finding_id"`
	Issue                   string                `json:"issue"`
	FilePath                string                `json:"file_path"`
	StartLine               int                   `json:"start_line"`
	EndLine                 int                   `json:"end_line"`
	UnverifiedExploitSketch string                `json:"unverified_exploit_sketch"`
	Severity                float64               `json:"severity"`
	CWEID                   string                `json:"cwe_id"`
	CodeFlows               []sarif.SARIFCodeFlow `json:"code_flows,omitempty"`
}

// auditClaims presents each result as a claim keyed by its finding ID.
func auditClaims(doc sarif.SARIFDocument) []auditClaim {
	run := doc.Runs[0]
	rules := make(map[string]sarif.SARIFRule, len(run.Tool.Driver.Rules))
	for _, rule := range run.Tool.Driver.Rules {
		rules[rule.ID] = rule
	}
	ids := auditFindingIDs(run.Results)
	claims := make([]auditClaim, len(run.Results))
	for i, result := range run.Results {
		rule := rules[result.RuleID]
		c := auditClaim{
			FindingID:               ids[i],
			Issue:                   rule.ShortDescription.Text,
			UnverifiedExploitSketch: result.Message.Text,
			Severity:                sarif.ResultSeverity(result, rule),
			CWEID:                   sarif.ResultCWE(result, rule),
			CodeFlows:               result.CodeFlows,
		}
		if len(result.Locations) > 0 {
			loc := result.Locations[0].PhysicalLocation
			c.FilePath = loc.ArtifactLocation.URI
			if loc.Region != nil {
				c.StartLine, c.EndLine = loc.Region.StartLine, loc.Region.EndLine
			}
		}
		if result.Properties != nil && result.Properties.TechnicalDetails != "" {
			c.UnverifiedExploitSketch = result.Properties.TechnicalDetails
		}
		claims[i] = c
	}
	return claims
}

// auditFindingIDs returns a unique ID per result: its finding ID, or a
// positional one when IDs were not assigned.
func auditFindingIDs(results []sarif.SARIFResult) []string {
	ids := make([]string, len(results))
	seen := make(map[string]bool, len(results))
	reserved := make(map[string]bool, len(results))
	for _, r := range results {
		if r.Properties != nil {
			reserved[r.Properties.FindingID] = true
		}
	}
	for i, r := range results {
		id := ""
		if r.Properties != nil {
			id = r.Properties.FindingID
		}
		if id == "" || seen[id] {
			id = fmt.Sprintf("result-%d", i+1)
			for suffix := 1; reserved[id] || seen[id]; suffix++ {
				id = fmt.Sprintf("result-%d-%d", i+1, suffix)
			}
		}
		seen[id] = true
		ids[i] = id
	}
	return ids
}

// numberedSource prefixes each line with its 1-based number, the form audit
// evidence cites.
func numberedSource(content string) string {
	var out strings.Builder
	for i, line := range strings.SplitAfter(content, "\n") {
		if line == "" {
			break
		}
		fmt.Fprintf(&out, "%d| %s", i+1, line)
		if !strings.HasSuffix(line, "\n") {
			out.WriteByte('\n')
		}
	}
	return out.String()
}
