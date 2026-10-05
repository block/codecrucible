package decision

import (
	"encoding/json"
	"path"
	"sort"
	"strings"
)

// RelatedEvidence is deterministic candidate retrieval, not proof of program
// reachability. The auditor already receives entire cited files; this budget
// covers only additional files. Literal references also cover script/template
// attachments when a language parser is unavailable.
func (index *EvidenceIndex) RelatedEvidence(anchors []Evidence, budget int) []Evidence {
	anchorIDs, paths := map[string]bool{}, map[string]bool{}
	for _, e := range anchors {
		anchorIDs[e.ID], paths[e.Path] = true, true
	}
	spans := []SourceRange{}
	for _, e := range anchors {
		spans = append(spans, SourceRange{Path: e.Path, Start: e.Start, End: e.End})
	}
	selected := index.selectEvidence(spans, budget, paths)
	candidates := map[string]Evidence{}
	related := map[string]bool{}
	for _, e := range selected.Evidence {
		if !anchorIDs[e.ID] {
			candidates[e.ID] = e
			related[e.ID] = true
		}
	}
	for _, name := range sortedKeys(index.files) {
		if paths[name] {
			continue
		}
		content := index.files[name]
		for _, anchor := range anchors {
			// Best effort only: matching literals may occur in comments. Jev
			// receives the actual source and must judge evidence usefulness.
			if strings.Contains(content, path.Base(anchor.Path)) || strings.Contains(anchor.Text, path.Base(name)) {
				for _, unit := range index.sources[name].units {
					if !unit.header {
						if e, ok := SourceEvidence(name, content, unit.Start, unit.End); ok {
							candidates[e.ID] = e
						}
					}
				}
				break
			}
		}
	}
	ordered := make([]Evidence, 0, len(candidates))
	for _, e := range candidates {
		if !anchorIDs[e.ID] {
			ordered = append(ordered, e)
		}
	}
	sort.Slice(ordered, func(i, j int) bool {
		// Source relations take priority over filename literals, which may
		// appear in unrelated comments or documentation.
		if related[ordered[i].ID] != related[ordered[j].ID] {
			return related[ordered[i].ID]
		}
		if ordered[i].Path != ordered[j].Path {
			return ordered[i].Path < ordered[j].Path
		}
		return ordered[i].Start < ordered[j].Start
	})
	out := []Evidence{}
	budget -= 2 // JSON array delimiters; reserve a comma per candidate below.
	for _, e := range ordered {
		encoded, _ := json.Marshal(e)
		if len(encoded)+1 > budget {
			continue
		}
		out = append(out, e)
		budget -= len(encoded) + 1
		if len(out) == 24 {
			break
		}
	}
	return out
}

// RelevanceQuestion asks a single proposition about one candidate and one
// required fact. It authorizes optional context only, never a finding verdict.
func RelevanceQuestion(candidateID, fact string) Question {
	return Noul("Does candidate " + candidateID + " contain concrete source evidence for this required fact: " + fact + "? Names, comments claiming safety, and unrelated checks are not sufficient. Judge relevance only; do not decide whether the vulnerability exists.")
}
