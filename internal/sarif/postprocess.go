package sarif

import (
	"log/slog"
	"path"
	"strconv"
	"strings"
)

// nonSourceExtensions lists file extensions that are not considered source code.
var nonSourceExtensions = map[string]bool{
	".json": true,
	".md":   true,
	".txt":  true,
	".yaml": true,
	".yml":  true,
	".toml": true,
	".cfg":  true,
	".ini":  true,
	".key":  true,
	".pem":  true,
	".crt":  true,
	".lock": true,
}

// nonSourceFilenames lists specific filenames that are not considered source code.
var nonSourceFilenames = map[string]bool{
	"package.json":      true,
	"package-lock.json": true,
	"go.sum":            true,
	"yarn.lock":         true,
	"Gemfile.lock":      true,
}

// PostProcess deduplicates findings, deprioritizes non-source file findings,
// and removes orphaned rules/taxa from the SARIF document.
func PostProcess(doc SARIFDocument) SARIFDocument {
	if len(doc.Runs) == 0 {
		return doc
	}

	run := doc.Runs[0]

	// Build a rule lookup: ruleID → SARIFRule.
	ruleByID := make(map[string]SARIFRule, len(run.Tool.Driver.Rules))
	for _, rule := range run.Tool.Driver.Rules {
		ruleByID[rule.ID] = rule
	}

	// --- Step 1: Deduplicate results by (file URI, startLine, CWE) ---
	run.Results = deduplicateResults(run.Results, ruleByID)

	// --- Step 2: Remove low-severity non-source file findings ---
	run.Results = deprioritizeNonSource(run.Results)

	// --- Step 3: Clean up orphaned rules and taxa ---
	run.Tool.Driver.Rules, run.Taxonomies = cleanOrphans(run.Results, ruleByID, run.Taxonomies)

	doc.Runs[0] = run
	return doc
}

// dedupKey uniquely identifies a finding for deduplication.
type dedupKey struct {
	fileURI   string
	startLine int
	cwe       string
}

// deduplicateResults keeps only the highest-severity result per (file, startLine, CWE).
func deduplicateResults(results []SARIFResult, ruleByID map[string]SARIFRule) []SARIFResult {
	bestIndex := make(map[dedupKey]int) // key → index into deduped slice
	var deduped []SARIFResult

	for _, r := range results {
		var fileURI string
		var startLine int
		if len(r.Locations) > 0 {
			fileURI = r.Locations[0].PhysicalLocation.ArtifactLocation.URI
			if r.Locations[0].PhysicalLocation.Region != nil {
				startLine = r.Locations[0].PhysicalLocation.Region.StartLine
			}
		}

		cwe := CWEForRule(ruleByID[r.RuleID])
		key := dedupKey{fileURI: fileURI, startLine: startLine, cwe: cwe}

		if idx, exists := bestIndex[key]; exists {
			existingSev := ruleSeverity(ruleByID[deduped[idx].RuleID])
			newSev := ruleSeverity(ruleByID[r.RuleID])
			if newSev > existingSev {
				deduped[idx] = r
			}
		} else {
			bestIndex[key] = len(deduped)
			deduped = append(deduped, r)
		}
	}

	removed := len(results) - len(deduped)
	if removed > 0 {
		slog.Info("postprocess: deduplicated results", "removed", removed, "remaining", len(deduped))
	}

	if deduped == nil {
		deduped = []SARIFResult{}
	}
	return deduped
}

// deprioritizeNonSource removes findings in non-source files that have
// severity "note" or "warning", keeping only "error"-level findings.
// This prevents low-value config/data findings from drowning out real
// vulnerabilities in route handlers and source code.
func deprioritizeNonSource(results []SARIFResult) []SARIFResult {
	var kept []SARIFResult
	removed := 0
	for _, r := range results {
		if len(r.Locations) == 0 {
			kept = append(kept, r)
			continue
		}
		uri := r.Locations[0].PhysicalLocation.ArtifactLocation.URI
		if isNonSourceFile(uri) && r.Level != "error" {
			removed++
			continue
		}
		kept = append(kept, r)
	}
	if removed > 0 {
		slog.Info("postprocess: removed low-severity non-source findings", "removed", removed, "remaining", len(kept))
	}
	if kept == nil {
		kept = []SARIFResult{}
	}
	return kept
}

// cleanOrphans removes rules not referenced by any result and taxa not referenced
// by any remaining rule.
func cleanOrphans(results []SARIFResult, ruleByID map[string]SARIFRule, taxonomies []SARIFTaxonomy) ([]SARIFRule, []SARIFTaxonomy) {
	// Determine which rule IDs are still referenced.
	usedRuleIDs := make(map[string]bool, len(results))
	for _, r := range results {
		usedRuleIDs[r.RuleID] = true
	}

	// Keep only referenced rules and collect their CWE references.
	var rules []SARIFRule
	usedCWEs := make(map[string]bool)
	for id := range usedRuleIDs {
		rule, ok := ruleByID[id]
		if !ok {
			continue
		}
		rules = append(rules, rule)
		for _, rel := range rule.Relationships {
			usedCWEs[rel.Target.ID] = true
		}
	}
	if rules == nil {
		rules = []SARIFRule{}
	}

	// Filter taxa in taxonomies.
	var filteredTaxonomies []SARIFTaxonomy
	for _, taxonomy := range taxonomies {
		var filteredTaxa []SARIFTaxon
		for _, taxon := range taxonomy.Taxa {
			if usedCWEs[taxon.ID] {
				filteredTaxa = append(filteredTaxa, taxon)
			}
		}
		if len(filteredTaxa) > 0 {
			taxonomyCopy := taxonomy
			taxonomyCopy.Taxa = filteredTaxa
			filteredTaxonomies = append(filteredTaxonomies, taxonomyCopy)
		}
	}

	return rules, filteredTaxonomies
}

// CWEForRule extracts the CWE identifier from a rule's relationships or tags.
// It returns a string like "CWE-89" or "" if no CWE is found.
func CWEForRule(rule SARIFRule) string {
	// Try relationships first.
	if len(rule.Relationships) > 0 {
		id := rule.Relationships[0].Target.ID
		if strings.HasPrefix(id, "CWE-") {
			return id
		}
	}

	// Fall back to tags in properties.
	if tags, ok := rule.Properties["tags"]; ok {
		if tagSlice, ok := tags.([]string); ok {
			for _, tag := range tagSlice {
				if strings.HasPrefix(tag, "external/cwe/cwe-") {
					num := strings.TrimPrefix(tag, "external/cwe/cwe-")
					return "CWE-" + num
				}
			}
		}
	}

	return ""
}

// ruleSeverity extracts the numeric security-severity from a rule's properties.
func ruleSeverity(rule SARIFRule) float64 {
	if rule.Properties == nil {
		return 0
	}
	raw, ok := rule.Properties["security-severity"]
	if !ok {
		return 0
	}
	switch v := raw.(type) {
	case string:
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0
		}
		return f
	case float64:
		return v
	default:
		return 0
	}
}

// isNonSourceFile returns true if the URI points to a non-source file.
func isNonSourceFile(uri string) bool {
	base := path.Base(uri)
	if nonSourceFilenames[base] {
		return true
	}
	ext := path.Ext(uri)
	return nonSourceExtensions[ext]
}
