package sarif

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// WithFindingIDs assigns immutable, scan-local identities before routing or
// refinement. Existing IDs survive changes in titles, evidence and locations.
// Copy the modified containers so phase snapshots remain independent.
func WithFindingIDs(doc SARIFDocument) SARIFDocument {
	doc.Runs = append([]SARIFRun(nil), doc.Runs...)
	used := map[string]bool{}
	for _, run := range doc.Runs {
		for _, result := range run.Results {
			if result.Properties != nil {
				used[result.Properties.FindingID] = true
			}
		}
	}
	assigned := map[string]bool{}
	for i := range doc.Runs {
		run := &doc.Runs[i]
		run.Results = append([]SARIFResult(nil), run.Results...)
		for j := range run.Results {
			result := &run.Results[j]
			props := FindingProperties{}
			if result.Properties != nil {
				props = *result.Properties
			}
			if props.FindingID == "" || assigned[props.FindingID] {
				data, _ := json.Marshal([]any{result.RuleID, result.Locations, result.Message.Text, i, j})
				for nonce := 0; ; nonce++ {
					seed := fmt.Sprintf("%s:%d", data, nonce)
					id := fmt.Sprintf("%x", sha256.Sum256([]byte(seed)))
					if !used[id] {
						props.FindingID = id
						used[id] = true
						break
					}
				}
			}
			assigned[props.FindingID] = true
			result.Properties = &props
		}
	}
	return doc
}
