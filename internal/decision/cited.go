package decision

import (
	"encoding/json"
	"sort"
)

// SelectCited supplies complete cited declarations without recursively fetching
// callers. It supports classification of the reported mechanism, not an audit
// verdict about reachability or exploitability. Non-Go sources use whole files.
func (index *EvidenceIndex) SelectCited(cited []SourceRange, budget int) EvidenceSelection {
	out := EvidenceSelection{}
	seen := map[string]bool{}
	if len(cited) == 0 {
		out.Gaps = append(out.Gaps, CoverageGap{Reason: "missing_location"})
	}
	for _, span := range cited {
		content, ok := index.files[span.Path]
		if !ok {
			out.Gaps = append(out.Gaps, CoverageGap{span, "missing_source"})
			continue
		}
		if span.End == 0 {
			span.End = span.Start
		}
		if _, ok := SourceEvidence(span.Path, content, span.Start, span.End); !ok {
			out.Gaps = append(out.Gaps, CoverageGap{span, "invalid_location"})
			continue
		}
		var selected *sourceUnit
		for _, unit := range index.sources[span.Path].units {
			if !unit.header && unit.Start <= span.Start && unit.End >= span.End {
				selected = unit
				break
			}
		}
		if selected == nil {
			out.Gaps = append(out.Gaps, CoverageGap{span, "missing_cited_scope"})
			continue
		}
		e, ok := SourceEvidence(span.Path, content, selected.Start, selected.End)
		if !ok {
			out.Gaps = append(out.Gaps, CoverageGap{span, "invalid_scope"})
			continue
		}
		if seen[e.ID] {
			continue
		}
		seen[e.ID] = true
		encoded, _ := json.Marshal(e)
		if len(encoded)+1 > budget {
			out.Gaps = append(out.Gaps, CoverageGap{span, "evidence_budget"})
			continue
		}
		budget -= len(encoded) + 1
		out.Evidence = append(out.Evidence, e)
	}
	sort.Slice(out.Evidence, func(i, j int) bool { return out.Evidence[i].ID < out.Evidence[j].ID })
	return out
}
