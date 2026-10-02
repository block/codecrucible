package cli

import (
	"encoding/json"
	"math"
)

// decodeAuditResult isolates malformed verdicts so unrelated, valid verdicts
// survive. Keep any readable ID on an invalid row: it must still make another
// row with the same ID ambiguous rather than allowing a duplicate to win.
func decodeAuditResult(content string) (AuditResult, error) {
	var envelope struct {
		Findings    []json.RawMessage `json:"audited_findings"`
		NewFindings []NewFinding      `json:"new_findings"`
		Summary     string            `json:"audit_summary"`
	}
	if err := json.Unmarshal([]byte(content), &envelope); err != nil {
		return AuditResult{}, err
	}
	result := AuditResult{NewFindings: envelope.NewFindings, AuditSummary: envelope.Summary}
	for _, raw := range envelope.Findings {
		var identity struct {
			ID string `json:"finding_id"`
		}
		_ = json.Unmarshal(raw, &identity)
		var finding AuditedFinding
		if err := json.Unmarshal(raw, &finding); err != nil {
			result.AuditedFindings = append(result.AuditedFindings, AuditedFinding{FindingID: identity.ID})
			continue
		}
		var required struct {
			Confidence *float64 `json:"confidence"`
		}
		if err := json.Unmarshal(raw, &required); err != nil || required.Confidence == nil {
			// Zero is a meaningful confidence, not a substitute for missing/null data.
			finding.Confidence = math.NaN()
		}
		result.AuditedFindings = append(result.AuditedFindings, finding)
	}
	return result, nil
}
