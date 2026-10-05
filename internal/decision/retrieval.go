package decision

import (
	"encoding/json"
	"path"
	"sort"
	"strings"
)

// RelatedEvidence is deterministic candidate retrieval, not proof of program
// reachability. Anchors are never ranked away. Literal file references also
// cover script/template attachments when a language parser is unavailable.
func (index *EvidenceIndex) RelatedEvidence(anchors []Evidence, budget int) []Evidence {
	anchorIDs, paths := map[string]bool{}, map[string]bool{}
	for _, e := range anchors {
		anchorIDs[e.ID], paths[e.Path] = true, true
	}
	spans := []SourceRange{}
	for _, e := range anchors {
		spans = append(spans, SourceRange{Path: e.Path, Start: e.Start, End: e.End})
	}
	selected := index.Select(spans, budget)
	candidates := map[string]Evidence{}
	for _, e := range selected.Evidence {
		if !paths[e.Path] {
			candidates[e.ID] = e
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
		if ordered[i].Path != ordered[j].Path {
			return ordered[i].Path < ordered[j].Path
		}
		return ordered[i].Start < ordered[j].Start
	})
	out := []Evidence{}
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
