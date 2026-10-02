package cli

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"
	"unicode"

	"github.com/block/codecrucible/internal/decision"
)

type filePair struct {
	left, right string
	weight      int
}

func (d *scanDecisions) smartGrouping(ctx context.Context, baseline map[string][]string) (map[string][]string, error) {
	if !d.enabled("smart-chunking") {
		return baseline, nil
	}
	mode := d.cfg.SmartChunking
	graph := map[string][]string{}
	for p, imports := range baseline {
		graph[p] = append([]string{}, imports...)
	}
	for p, imports := range d.graph {
		for _, dep := range imports {
			graph[p] = appendUnique(graph[p], dep)
		}
	}
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
		source := []rune(d.files[p])
		if len(source) > 1600 {
			source = source[:1600]
		}
		for _, word := range strings.FieldsFunc(string(source), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' }) {
			if len(word) >= 5 && !seen[word] {
				seen[word] = true
				index[word] = append(index[word], p)
			}
		}
	}
	pairs := []filePair{}
	for _, p := range paths {
		scores := map[string]int{}
		words := strings.FieldsFunc(d.files[p][:min(len(d.files[p]), 1600)], func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' })
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
			if score >= 2 {
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
		questions := map[string]decision.Question{}
		for i, pair := range batch {
			for _, p := range []string{pair.left, pair.right} {
				lines := strings.Split(strings.TrimSuffix(d.files[p], "\n"), "\n")
				end := min(len(lines), 12)
				e, _ := decision.SourceEvidence(p, d.files[p], 1, end)
				if len(e.Text) > 1200 {
					continue
				}
				evidence = append(evidence, e)
			}
			questions[fmt.Sprintf("pair_%d", i)] = decision.Choice("Should "+pair.left+" and "+pair.right+" share an analysis chunk because they implement the same behavior or have a meaningful data/dependency relationship? Shared boilerplate alone is not enough. File samples are partial.", map[string]string{"related": "A concrete shared behavior or dependency is visible", "unrelated": "No useful analysis relationship", "insufficient_evidence": "The samples do not establish a relationship"})
		}
		response, err := d.recorder.Evaluate(ctx, "smart-chunking", mode, fmt.Sprintf("pairs_%d", start), map[string]any{"source_samples": evidence}, questions, evidence, false)
		if ctx.Err() != nil {
			return baseline, ctx.Err()
		}
		if err != nil {
			d.recorder.Action("existing_chunking_for_batch")
			continue
		}
		present := map[string]bool{}
		for _, e := range evidence {
			present[e.Path] = true
		}
		for i, pair := range batch {
			if !present[pair.left] || !present[pair.right] {
				continue
			}
			if decision.Strong(response.Answers[fmt.Sprintf("pair_%d", i)], "related") {
				graph[pair.left] = appendUnique(graph[pair.left], pair.right)
				graph[pair.right] = appendUnique(graph[pair.right], pair.left)
			}
		}
		d.recorder.Action("grouping_hints")
	}
	if len(pairs) == 0 {
		d.recorder.Skip("smart-chunking", mode, "no_semantic_candidates")
	}
	if !complete {
		d.recorder.Skip("smart-chunking", mode, "candidate_limit_remaining_files_use_dependency_grouping")
	}
	if mode == "shadow" {
		return baseline, nil
	}
	for p := range graph {
		sort.Strings(graph[p])
	}
	return graph, nil
}
func appendUnique(values []string, value string) []string {
	for _, v := range values {
		if v == value {
			return values
		}
	}
	return append(values, value)
}
