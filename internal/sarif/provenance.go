package sarif

import (
	"encoding/json"
	"sort"
	"strconv"
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

// evidenceKey identifies structural source anchors independently of model prose.
func evidenceKey(r SARIFResult) string {
	anchors := map[string]bool{}
	add := func(loc SARIFLocation) {
		line := 0
		if loc.PhysicalLocation.Region != nil {
			line = loc.PhysicalLocation.Region.StartLine
		}
		anchors[loc.PhysicalLocation.ArtifactLocation.URI+":"+strconv.Itoa(line)] = true
	}
	for _, flow := range r.CodeFlows {
		for _, thread := range flow.ThreadFlows {
			if len(thread.Locations) > 0 {
				add(thread.Locations[0].Location)
				add(thread.Locations[len(thread.Locations)-1].Location)
			}
		}
	}
	if r.Properties != nil {
		for _, loc := range r.Properties.ReportedLocations {
			add(loc)
		}
	}
	keys := make([]string, 0, len(anchors))
	for key := range anchors {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	b, _ := json.Marshal(keys)
	return string(b)
}
