package sarif

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// FingerprintKey is the partialFingerprints key carrying the finding identity.
const FingerprintKey = "codecrucibleFinding/v1"

// AssignFindingIDs gives every result without one a findingId and matching
// partial fingerprint. Existing IDs are kept, so assigning before the audit
// keeps a finding's identity stable even when the audit refines its CWE.
//
// The identity deliberately excludes model prose (title, message) and line
// numbers: both drift between scans of unchanged code. It hashes the weakness
// class, the file, and the whitespace-normalized flagged source, so the same
// defect keeps its ID across rescans and unrelated edits that shift lines.
// Identical flagged source in one file is disambiguated by occurrence order.
func AssignFindingIDs(doc SARIFDocument) SARIFDocument {
	doc.Runs = append([]SARIFRun(nil), doc.Runs...)
	for i := range doc.Runs {
		run := &doc.Runs[i]
		run.Results = append([]SARIFResult(nil), run.Results...)
		rules := make(map[string]SARIFRule, len(run.Tool.Driver.Rules))
		for _, rule := range run.Tool.Driver.Rules {
			rules[rule.ID] = rule
		}
		used := make(map[string]bool, len(run.Results))
		for _, r := range run.Results {
			if r.Properties != nil && r.Properties.FindingID != "" {
				used[r.Properties.FindingID] = true
			}
		}
		for j := range run.Results {
			r := &run.Results[j]
			props := FindingProperties{}
			if r.Properties != nil {
				props = *r.Properties
			}
			if props.FindingID == "" {
				seed := identitySeed(*r, rules[r.RuleID])
				for n := 0; ; n++ {
					sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d", seed, n)))
					hash := fmt.Sprintf("%x", sum)
					id := "CC-" + strings.ToUpper(hash[:16])
					if !used[id] {
						used[id] = true
						props.FindingID = id
						r.PartialFingerprints = map[string]string{FingerprintKey: hash}
						break
					}
				}
			}
			r.Properties = &props
		}
	}
	return doc
}

func identitySeed(r SARIFResult, rule SARIFRule) string {
	class := ResultCWE(r, rule)
	if class == "" {
		class = r.RuleID
	}
	var uri, anchor string
	if len(r.Locations) > 0 {
		loc := r.Locations[0].PhysicalLocation
		uri = loc.ArtifactLocation.URI
		if reg := loc.Region; reg != nil {
			if reg.Snippet != nil && strings.TrimSpace(reg.Snippet.Text) != "" {
				anchor = strings.Join(strings.Fields(reg.Snippet.Text), " ")
			} else {
				anchor = fmt.Sprintf("line:%d", reg.StartLine)
			}
		}
	}
	return strings.Join([]string{"v1", class, uri, anchor}, "\x00")
}
