package sarif

import "strings"

// Merge combines multiple SARIF documents (one per chunk) into a single document.
// It deduplicates rules by normalized ID and results by (ruleID, filePath, startLine).
// Partial failure notifications from all chunks are preserved.
func Merge(docs []SARIFDocument) SARIFDocument {
	if len(docs) == 0 {
		return SARIFDocument{
			Schema:  sarifSchema,
			Version: sarifVersion,
			Runs: []SARIFRun{{
				Tool: SARIFTool{Driver: SARIFDriver{
					Name:    "codecrucible",
					Version: "dev",
					Rules:   []SARIFRule{},
				}},
				Results:     []SARIFResult{},
				Invocations: []SARIFInvocation{{ExecutionSuccessful: true}},
			}},
		}
	}

	if len(docs) == 1 {
		return docs[0]
	}

	// Use tool metadata from the first document.
	first := docs[0].Runs[0]
	toolName := first.Tool.Driver.Name
	toolVersion := first.Tool.Driver.Version
	infoURI := first.Tool.Driver.InformationURI

	// Collect and deduplicate rules.
	ruleIndex := make(map[string]int) // normalized rule ID → index in rules slice
	var rules []SARIFRule

	// Collect and deduplicate results.
	type resultKey struct {
		ruleID    string
		filePath  string
		startLine int
	}
	seenResults := make(map[resultKey]bool)
	var results []SARIFResult

	// Collect notifications from all chunks.
	var notifications []SARIFNotification
	allSuccessful := true

	// Collect and deduplicate CWE taxa across chunks.
	taxaIndex := make(map[string]bool)
	var taxa []SARIFTaxon

	for _, doc := range docs {
		if len(doc.Runs) == 0 {
			continue
		}
		run := doc.Runs[0]

		// Merge taxonomies.
		for _, taxonomy := range run.Taxonomies {
			for _, taxon := range taxonomy.Taxa {
				if !taxaIndex[taxon.ID] {
					taxaIndex[taxon.ID] = true
					taxa = append(taxa, taxon)
				}
			}
		}

		// Merge rules.
		for _, rule := range run.Tool.Driver.Rules {
			normID := normalizeRuleID(rule.ID)
			if _, exists := ruleIndex[normID]; !exists {
				// Store with normalized ID.
				ruleCopy := rule
				ruleCopy.ID = normID
				ruleIndex[normID] = len(rules)
				rules = append(rules, ruleCopy)
			}
		}

		// Merge results.
		for _, r := range run.Results {
			normID := normalizeRuleID(r.RuleID)

			var fp string
			var sl int
			if len(r.Locations) > 0 {
				fp = r.Locations[0].PhysicalLocation.ArtifactLocation.URI
				if r.Locations[0].PhysicalLocation.Region != nil {
					sl = r.Locations[0].PhysicalLocation.Region.StartLine
				}
			}

			key := resultKey{ruleID: normID, filePath: fp, startLine: sl}
			if seenResults[key] {
				continue
			}
			seenResults[key] = true

			rCopy := r
			rCopy.RuleID = normID
			results = append(results, rCopy)
		}

		// Merge invocations.
		for _, inv := range run.Invocations {
			if !inv.ExecutionSuccessful {
				allSuccessful = false
			}
			notifications = append(notifications, inv.ToolExecutionNotifications...)
		}
	}

	if rules == nil {
		rules = []SARIFRule{}
	}
	if results == nil {
		results = []SARIFResult{}
	}

	inv := SARIFInvocation{
		ExecutionSuccessful:        allSuccessful,
		ToolExecutionNotifications: notifications,
	}

	run := SARIFRun{
		Tool: SARIFTool{Driver: SARIFDriver{
			Name:           toolName,
			Version:        toolVersion,
			InformationURI: infoURI,
			Rules:          rules,
		}},
		Results:     results,
		Invocations: []SARIFInvocation{inv},
	}

	if len(taxa) > 0 {
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

// normalizeRuleID normalizes a rule ID for deduplication:
// strips trailing punctuation, lowercases, then re-slugifies.
func normalizeRuleID(id string) string {
	// If it already has the prefix, strip it to get the raw text.
	text := strings.TrimPrefix(id, rulePrefix)
	// Convert slug back to words for normalization.
	text = strings.ReplaceAll(text, "-", " ")
	// Strip trailing punctuation.
	text = strings.TrimRight(text, "., ;:!?")
	// Re-slugify.
	return slugify(text)
}
