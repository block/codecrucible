package sarif

import (
	"encoding/json"
	"sort"
)

// combineProvenance preserves all contributing observations and revision
// parents without modifying the inputs. Original evidence lives in the ledger.
func combineProvenance(winner, other SARIFResult) SARIFResult {
	if other.Properties == nil || other.Properties.Provenance == nil {
		return winner
	}
	p := FindingProperties{}
	if winner.Properties != nil {
		p = *winner.Properties
	}
	q := FindingProvenance{}
	if p.Provenance != nil {
		q = *p.Provenance
	}
	observations := append([]string{}, q.ObservationIDs...)
	parents := append([]string{}, q.Parents...)
	if len(parents) == 0 && q.RevisionID != "" {
		parents = append(parents, q.RevisionID)
	}
	o := other.Properties.Provenance
	observations = append(observations, o.ObservationIDs...)
	if len(o.Parents) > 0 {
		parents = append(parents, o.Parents...)
	} else if o.RevisionID != "" {
		parents = append(parents, o.RevisionID)
	}
	q.RunID = o.RunID
	q.ObservationIDs = uniqueStrings(observations)
	q.Parents = uniqueStrings(parents)
	p.Provenance = &q
	winner.Properties = &p
	return winner
}
func uniqueStrings(values []string) []string {
	set := map[string]bool{}
	for _, v := range values {
		set[v] = true
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// evidenceKey prevents location/CWE collisions from discarding distinct claims.
// Severity differences may be consolidated, but different explanations, paths,
// remediation, or source evidence must survive independently.
func evidenceKey(r SARIFResult) string {
	var summary, details, remediation string
	var reported []SARIFLocation
	if r.Properties != nil {
		summary = r.Properties.Summary
		details = r.Properties.TechnicalDetails
		remediation = r.Properties.Remediation
		reported = r.Properties.ReportedLocations
	}
	b, _ := json.Marshal(struct {
		Message                       SARIFMessage
		Locations                     []SARIFLocation
		Reported                      []SARIFLocation
		Flows                         []SARIFCodeFlow
		Summary, Details, Remediation string
	}{r.Message, r.Locations, reported, r.CodeFlows, summary, details, remediation})
	return string(b)
}
