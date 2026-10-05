package cli

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"
	"unicode"

	"github.com/block/codecrucible/internal/chunk"
	"github.com/block/codecrucible/internal/decision"
)

type filePair struct {
	left, right string
	weight      int
}

func (d *scanDecisions) smartGrouping(ctx context.Context, baseline map[string][]string) (map[string][]string, error) {
	if d == nil || (!d.enabled("smart-chunking") && !d.cfg.DependencyGrouping) {
		return baseline, nil
	}
	mode := d.cfg.SmartChunking
	graph := map[string][]string{}
	for p, imports := range baseline {
		graph[p] = append([]string{}, imports...)
	}
	if d.cfg.DependencyGrouping {
		d.recorder.Skip("smart-chunking", "off", "deterministic_dependency_grouping")
		d.recorder.Action("dependency_grouping")
		dependencyPaths := make([]string, 0, len(d.graph))
		for p := range d.graph {
			dependencyPaths = append(dependencyPaths, p)
		}
		sort.Strings(dependencyPaths)
		for _, p := range dependencyPaths {
			imports := append([]string{}, d.graph[p]...)
			sort.Strings(imports)
			for _, dep := range imports {
				if !hasGroupingEdge(graph, p, dep) {
					d.recorder.Records[len(d.recorder.Records)-1].Edges = append(d.recorder.Records[len(d.recorder.Records)-1].Edges, decision.GroupingEdge{Left: p, Right: dep, Origin: "dependency", Applied: true})
					d.recorder.Outcome("dependency_edges_added", 1)
				}
				graph[p] = appendUnique(graph[p], dep)
			}
		}
	}
	d.groupingBaseline = graph
	if !d.enabled("smart-chunking") {
		return graph, nil
	}
	graph = cloneGroupingGraph(graph)
	evidenceIndex := decision.NewEvidenceIndex(d.files, d.graph)
	paths := make([]string, 0, len(d.files))
	for p := range d.files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	// An inverted identifier index bounds candidate generation. Very common
	// identifiers do not provide useful grouping evidence.
	index := map[string][]string{}
	for _, p := range paths {
		seen := map[string]bool{}
		for _, word := range strings.FieldsFunc(d.files[p], func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' }) {
			if len(word) >= 5 && !seen[word] {
				seen[word] = true
				index[word] = append(index[word], p)
			}
		}
	}
	pairs := []filePair{}
	for _, p := range paths {
		scores := map[string]int{}
		words := strings.FieldsFunc(d.files[p], func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' })
		seenWords := map[string]bool{}
		for _, word := range words {
			if seenWords[word] || len(index[word]) > 16 {
				continue
			}
			seenWords[word] = true
			for _, other := range index[word] {
				if other > p {
					scores[other]++
				}
			}
		}
		candidates := []filePair{}
		for other, score := range scores {
			if score >= 2 && !hasGroupingEdge(graph, p, other) {
				if path.Dir(p) == path.Dir(other) {
					score += 2
				}
				candidates = append(candidates, filePair{p, other, score})
			}
		}
		sort.Slice(candidates, func(i, j int) bool {
			if candidates[i].weight != candidates[j].weight {
				return candidates[i].weight > candidates[j].weight
			}
			return candidates[i].right < candidates[j].right
		})
		pairs = append(pairs, candidates[:min(len(candidates), 3)]...)
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].weight != pairs[j].weight {
			return pairs[i].weight > pairs[j].weight
		}
		if pairs[i].left != pairs[j].left {
			return pairs[i].left < pairs[j].left
		}
		return pairs[i].right < pairs[j].right
	})
	complete := len(pairs) <= 128
	pairs = pairs[:min(len(pairs), 128)]
	for start := 0; start < len(pairs); start += 6 {
		batch := pairs[start:min(start+6, len(pairs))]
		evidence := []decision.Evidence{}
		usedEvidence := map[string]bool{}
		questions := map[string]decision.Question{}
		for i, pair := range batch {
			terms := map[string]bool{}
			for word, members := range index {
				if len(members) > 16 {
					continue
				}
				left, right := false, false
				for _, member := range members {
					left = left || member == pair.left
					right = right || member == pair.right
				}
				if left && right {
					terms[word] = true
				}
			}
			left := evidenceIndex.RelevantEvidence(pair.left, terms, 1800)
			right := evidenceIndex.RelevantEvidence(pair.right, terms, 1800)
			if len(left) == 0 || len(right) == 0 {
				continue
			}
			for _, scopes := range [][]decision.Evidence{left, right} {
				for _, e := range scopes {
					if !usedEvidence[e.ID] {
						evidence = append(evidence, e)
						usedEvidence[e.ID] = true
					}
				}
			}
			questions[fmt.Sprintf("pair_%d", i)] = decision.Score("Should "+pair.left+" and "+pair.right+" share an analysis chunk based on the additional context their supplied source scopes provide? Judge only these two paths in `source_samples`. Shared boilerplate and names alone do not establish a connection. Samples are partial; do not assume omitted behavior.", []string{"No demonstrated additional context from these supplied scopes", "Related supporting context, but no directly connected operation is demonstrated", "The supplied scopes demonstrate directly connected operations whose joint context helps security analysis"})
		}
		if len(questions) == 0 {
			d.recorder.Skip("smart-chunking", mode, "no_pair_with_bounded_source_scopes")
			d.recorder.Outcome("pairs_skipped_missing_scopes", len(batch))
			continue
		}
		response, _ := d.recorder.Evaluate(ctx, "smart-chunking", mode, fmt.Sprintf("pairs_%d", start), map[string]any{"source_samples": evidence}, questions, evidence, false)
		d.recorder.Outcome("pairs_skipped_missing_scopes", len(batch)-len(questions))
		if ctx.Err() != nil {
			return baseline, ctx.Err()
		}
		d.recorder.Outcome("edges_accepted", 0)
		d.recorder.Outcome("edges_applied", 0)
		evaluated := 0
		for i, pair := range batch {
			id := fmt.Sprintf("pair_%d", i)
			q, requested := questions[id]
			if !requested {
				continue
			}
			// Pair decisions are independent: an unavailable neighbor must not
			// discard this validated answer from a partial response.
			one := decision.Request{Questions: map[string]decision.Question{id: q}}
			answer := decision.Response{Model: response.Model, Answers: map[string]decision.Answer{id: response.Answers[id]}}
			if decision.ValidateResponse(one, answer) != nil {
				d.recorder.Outcome("pairs_unavailable", 1)
				continue
			}
			evaluated++
			if decision.UsefulGrouping(response.Answers[id]) && !hasGroupingEdge(graph, pair.left, pair.right) {
				graph[pair.left] = appendUnique(graph[pair.left], pair.right)
				graph[pair.right] = appendUnique(graph[pair.right], pair.left)
				d.recorder.Records[len(d.recorder.Records)-1].Edges = append(d.recorder.Records[len(d.recorder.Records)-1].Edges, decision.GroupingEdge{Left: pair.left, Right: pair.right, Origin: "jev", Applied: mode == "active"})
				d.recorder.Outcome("edges_accepted", 1)
				if mode == "active" {
					d.recorder.Outcome("edges_applied", 1)
				}
			}
		}
		d.recorder.Outcome("pairs_evaluated", evaluated)
		if evaluated == 0 {
			d.recorder.Action("existing_chunking_for_batch")
		} else {
			d.recorder.Action("grouping_hints")
		}
	}
	if len(pairs) == 0 {
		d.recorder.Skip("smart-chunking", mode, "no_semantic_candidates")
	}
	if !complete {
		d.recorder.Skip("smart-chunking", mode, "candidate_limit_remaining_files_use_existing_grouping")
	}
	if mode == "shadow" {
		if !d.cfg.DependencyGrouping {
			return baseline, nil
		}
		return d.groupingBaseline, nil
	}
	for p := range graph {
		sort.Strings(graph[p])
	}
	return graph, nil
}

func (d *scanDecisions) hasAppliedGroupingEdges() bool {
	for _, record := range d.recorder.Records {
		for _, edge := range record.Edges {
			if edge.Applied && edge.Origin == "jev" {
				return true
			}
		}
	}
	return false
}

func (d *scanDecisions) recordGroupingPlacement(before, after []chunk.Chunk) {
	together := func(chunks []chunk.Chunk, left, right string) bool {
		for _, c := range chunks {
			l, r := false, false
			for _, path := range c.Paths {
				l = l || path == left
				r = r || path == right
			}
			if l && r {
				return true
			}
		}
		return false
	}
	for i := range d.recorder.Records {
		record := &d.recorder.Records[i]
		for j := range record.Edges {
			e := &record.Edges[j]
			if !e.Applied || e.Origin != "jev" {
				continue
			}
			e.PlacementMeasured = true
			e.Together = together(after, e.Left, e.Right)
			e.ChangedPlacement = e.Together != together(before, e.Left, e.Right)
			if record.Outcomes == nil {
				record.Outcomes = map[string]int{}
			}
			if e.Together {
				record.Outcomes["edges_together"]++
			}
			if e.ChangedPlacement {
				record.Outcomes["edges_changed_placement"]++
			}
		}
	}
}

func cloneGroupingGraph(graph map[string][]string) map[string][]string {
	out := map[string][]string{}
	for path, deps := range graph {
		out[path] = append([]string{}, deps...)
	}
	return out
}

func hasGroupingEdge(graph map[string][]string, left, right string) bool {
	for _, dep := range graph[left] {
		if dep == right {
			return true
		}
	}
	for _, dep := range graph[right] {
		if dep == left {
			return true
		}
	}
	return false
}
func appendUnique(values []string, value string) []string {
	for _, v := range values {
		if v == value {
			return values
		}
	}
	return append(values, value)
}
