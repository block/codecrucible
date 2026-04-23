package supctx

import (
	"fmt"
	"sort"
	"strings"
)

// PackResult is the rendered prompt block plus accounting.
type PackResult struct {
	// Rendered is the final string ready to splice into the prompt. Empty
	// when no sources applied or budget was zero.
	Rendered string

	// Tokens is the counted size of Rendered. This is what the caller adds
	// to promptOverhead so chunk-budget math stays honest.
	Tokens int

	// Dropped lists sources that didn't fit at all.
	Dropped []string

	// Truncated names the one source (if any) that was partially included.
	Truncated string
}

// Pack greedily fills the budget highest-priority-first. The last source that
// doesn't fully fit is truncated with a marker; anything after is dropped.
//
// Budget ≤ 0 returns an empty result — callers use this to cleanly disable
// context injection without special-casing.
func Pack(loaded []Loaded, budget int, counter TokenCounter) PackResult {
	var res PackResult
	if budget <= 0 || len(loaded) == 0 {
		for _, l := range loaded {
			res.Dropped = append(res.Dropped, l.Name)
		}
		return res
	}

	// Stable sort so equal-priority sources keep declaration order.
	sorted := make([]Loaded, len(loaded))
	copy(sorted, loaded)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Priority > sorted[j].Priority
	})

	var b strings.Builder
	remaining := budget

	for i, l := range sorted {
		block := wrapSource(l.Name, l.Content)
		tokens := counter.Count(block)

		if tokens <= remaining {
			b.WriteString(block)
			remaining -= tokens
			continue
		}

		// Doesn't fit whole. If there's meaningful room left, truncate;
		// otherwise drop this and everything after.
		if remaining > 50 {
			truncated := truncateToTokens(l.Content, remaining, counter)
			marker := fmt.Sprintf("\n[... ~%d tokens truncated ...]", l.Tokens-counter.Count(truncated))
			b.WriteString(wrapSource(l.Name, truncated+marker))
			res.Truncated = l.Name
			remaining = 0
		} else {
			res.Dropped = append(res.Dropped, l.Name)
		}

		// Everything after is dropped.
		for _, rest := range sorted[i+1:] {
			res.Dropped = append(res.Dropped, rest.Name)
		}
		break
	}

	res.Rendered = b.String()
	res.Tokens = counter.Count(res.Rendered)
	return res
}

// wrapSource puts a named envelope around content so the model can attribute
// what it reads to the right source.
func wrapSource(name, content string) string {
	return fmt.Sprintf("<context name=%q>\n%s\n</context>\n", name, content)
}

// truncateToTokens cuts content to roughly target tokens by binary-searching
// on byte length. The heuristic counter is monotone in length so this
// converges in log(len) iterations without repeatedly counting the full text.
func truncateToTokens(content string, target int, counter TokenCounter) string {
	if counter.Count(content) <= target {
		return content
	}
	lo, hi := 0, len(content)
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if counter.Count(content[:mid]) <= target {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	// Back off to the last newline so we don't cut mid-line.
	if i := strings.LastIndexByte(content[:lo], '\n'); i > 0 {
		lo = i
	}
	return content[:lo]
}
