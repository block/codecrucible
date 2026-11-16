package chunk

import (
	"path/filepath"
	"sort"
	"strings"
)

// fitGroups splits candidates that overflow when their full XML is rendered.
// Single-file groups have already passed the same check before packing.
func fitGroups(groups [][]*fileEntry, fits func([]*fileEntry) bool) [][]*fileEntry {
	var out [][]*fileEntry
	for _, group := range groups {
		if fits(group) {
			out = append(out, group)
			continue
		}
		var current []*fileEntry
		for _, e := range group {
			candidate := append(current, e)
			if len(current) > 0 && !fits(candidate) {
				out = append(out, current)
				current = []*fileEntry{e}
			} else {
				current = candidate
			}
		}
		if len(current) > 0 {
			out = append(out, current)
		}
	}
	return out
}

// Shared entries are excluded from ordinary groups before packing.
func renderGroup(group, shared []*fileEntry) ([]*fileEntry, []string, string) {
	full := make([]*fileEntry, 0, len(group)+len(shared))
	full = append(full, group...)
	full = append(full, shared...)
	sort.Slice(full, func(i, j int) bool { return full[i].path < full[j].path })
	paths := make([]string, len(full))
	var content strings.Builder
	for i, e := range full {
		paths[i] = e.path
		content.WriteString(e.content)
	}
	return full, paths, content.String()
}

func (c *defaultChunker) directoryGroups(entries []*fileEntry, budget int) [][]*fileEntry {
	ordered := append([]*fileEntry(nil), entries...)
	sort.Slice(ordered, func(i, j int) bool {
		di, dj := filepath.Dir(ordered[i].path), filepath.Dir(ordered[j].path)
		if di != dj {
			return di < dj
		}
		return ordered[i].path < ordered[j].path
	})
	return c.mergeGroups(c.packGreedy(ordered, budget), budget)
}

// importGroups grows priority-ordered seeds through their local imports and
// fills remaining space from the seed's directory. Every file is assigned once.
func (c *defaultChunker) importGroups(entries []*fileEntry, budget int) [][]*fileEntry {
	byPath := make(map[string]*fileEntry, len(entries))
	for _, e := range entries {
		byPath[e.path] = e
	}
	assigned := make(map[string]bool, len(entries))
	var groups [][]*fileEntry
	for _, seed := range entries {
		if assigned[seed.path] {
			continue
		}
		group := []*fileEntry{seed}
		assigned[seed.path] = true
		tokens := seed.tokens
		queue := append([]string(nil), seed.imports...)
		for len(queue) > 0 {
			p := queue[0]
			queue = queue[1:]
			e := byPath[p]
			if e == nil || assigned[p] || tokens+e.tokens > budget {
				continue
			}
			group = append(group, e)
			assigned[p] = true
			tokens += e.tokens
			queue = append(queue, e.imports...)
		}
		for _, e := range entries {
			if assigned[e.path] || filepath.Dir(e.path) != filepath.Dir(seed.path) || tokens+e.tokens > budget {
				continue
			}
			group = append(group, e)
			assigned[e.path] = true
			tokens += e.tokens
		}
		groups = append(groups, group)
	}
	return c.mergeGroups(groups, budget)
}

type packingScore struct {
	chunks, colocatedEdges, duplicatedBytes int
}

// Prefer the directory baseline on ties or tradeoffs. Graph grouping must
// improve at least one measure without worsening the others.
func (s packingScore) betterThan(baseline packingScore) bool {
	return s.chunks <= baseline.chunks && s.colocatedEdges >= baseline.colocatedEdges &&
		s.duplicatedBytes <= baseline.duplicatedBytes && s != baseline
}

func scorePacking(groups [][]*fileEntry, shared []*fileEntry) packingScore {
	score := packingScore{chunks: len(groups)}
	seenEdges := make(map[[2]string]bool)
	for _, group := range groups {
		members := make(map[string]*fileEntry, len(group)+len(shared))
		for _, e := range group {
			members[e.path] = e
		}
		for _, e := range shared {
			members[e.path] = e
		}
		for _, e := range members {
			for _, target := range e.imports {
				if target != e.path && members[target] != nil {
					seenEdges[[2]string{e.path, target}] = true
				}
			}
		}
	}
	score.colocatedEdges = len(seenEdges)
	for _, e := range shared {
		score.duplicatedBytes += len(e.content) * max(0, len(groups)-1)
	}
	return score
}
