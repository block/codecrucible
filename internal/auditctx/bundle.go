package auditctx

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/block/codecrucible/internal/auditcore"
	"github.com/block/codecrucible/internal/sourceindex"
)

type Omission struct {
	File   string `json:"file"`
	Start  int    `json:"start_line,omitempty"`
	End    int    `json:"end_line,omitempty"`
	Reason string `json:"reason"`
}
type Bundle struct {
	SourceFingerprint string     `json:"sourceFingerprint"`
	Fingerprint       string     `json:"fingerprint"`
	Included          []Excerpt  `json:"included"`
	Omitted           []Omission `json:"omitted,omitempty"`
	Text              string     `json:"-"`
}

// Bundle prioritizes explicit anchors and targeted requests, then the common
// source-index retrieval path. It records every skipped candidate.
func (ix *Index) Bundle(claims []Claim, explicit []Excerpt, budget int, count func(string) int) Bundle {
	b := Bundle{SourceFingerprint: ix.source.Snapshot().SourceFingerprint}
	var candidates []Excerpt
	for _, c := range claims {
		n := len(ix.source.Lines(c.File))
		if c.Start < 1 || c.Start > n {
			b.Omitted = append(b.Omitted, Omission{c.File, c.Start, c.End, "invalid_anchor"})
			continue
		}
		end := max(c.Start, c.End)
		candidates = append(candidates, Excerpt{c.File, max(1, c.Start-8), min(n, min(end+8, c.Start+120)), "primary claim"})
	}
	candidates = append(candidates, explicit...)
	// Small modules and enclosing declarations preserve the guards and imports
	// surrounding a narrow primary anchor without requiring a build.
	for _, c := range claims {
		n := len(ix.source.Lines(c.File))
		if n > 0 && n <= 300 {
			candidates = append(candidates, Excerpt{c.File, 1, n, "primary module"})
		} else if d, ok := ix.source.Enclosing(c.File, c.Start); ok && d.End-d.Line <= 240 {
			candidates = append(candidates, Excerpt{c.File, d.Line, d.End, "enclosing declaration"})
		}
	}

	lists := make([][]Excerpt, len(claims))
	for i, c := range claims {
		lists[i] = ix.Retrieve(c, nil)
	}
	for depth := 0; ; depth++ {
		added := false
		for _, list := range lists {
			if depth < len(list) {
				candidates = append(candidates, list[depth])
				added = true
			}
		}
		if !added {
			break
		}
	}
	ranges := map[string][][2]int{}
	for _, e := range candidates {
		lines := ix.source.Lines(e.File)
		reason := ""
		switch {
		case len(lines) == 0:
			reason = "outside_scope"
		case e.Start < 1 || e.Start > len(lines) || e.End < e.Start:
			reason = "invalid_anchor"
		}
		if reason != "" {
			b.Omitted = append(b.Omitted, Omission{e.File, e.Start, e.End, reason})
			continue
		}
		e.End = min(e.End, len(lines))
		if covered(ranges[e.File], e.Start, e.End) {
			continue
		}
		tentative := append(append([]Excerpt{}, b.Included...), e)
		text, _ := Render(ix, tentative, int(^uint(0)>>1), count)
		if count(text) > budget {
			b.Omitted = append(b.Omitted, Omission{e.File, e.Start, e.End, "budget_exhausted"})
			continue
		}
		ranges[e.File] = merge(append(ranges[e.File], [2]int{e.Start, e.End}))
		b.Included = append(b.Included, e)
	}
	for _, imp := range ix.source.Imports() {
		if len(ranges[imp.File]) == 0 || imp.Status == "resolved" {
			continue
		}
		reason := "unresolved_import"
		if imp.Status == "ambiguous" {
			reason = "ambiguous_symbol"
		}
		if imp.Status == "skipped" {
			reason = "outside_scope"
		}
		b.Omitted = append(b.Omitted, Omission{File: imp.File + " -> " + imp.Specifier, Reason: reason})
	}
	b.Text, _ = Render(ix, b.Included, int(^uint(0)>>1), count)
	identity, _ := json.Marshal(struct {
		Source   string
		Included []Excerpt
		Omitted  []Omission
	}{b.SourceFingerprint, b.Included, b.Omitted})
	b.Fingerprint = sourceindex.Fingerprint(string(identity))
	return b
}
func (ix *Index) Verify(b Bundle, e auditcore.Evidence) (auditcore.Evidence, bool) {
	if b.SourceFingerprint != ix.source.Snapshot().SourceFingerprint {
		return e, false
	}
	if e.End == 0 {
		e.End = e.Start
	}
	if e.Start < 1 || e.End < e.Start || e.End-e.Start > 120 || !meaningfulQuote(e.Quote) {
		return e, false
	}
	var ranges [][2]int
	for _, r := range b.Included {
		if r.File == e.File {
			ranges = append(ranges, [2]int{r.Start, r.End})
		}
	}
	if !covered(merge(ranges), e.Start, e.End) {
		return e, false
	}
	lines := ix.source.Lines(e.File)
	if e.End > len(lines) {
		return e, false
	}
	if !strings.Contains(strings.Join(lines[e.Start-1:e.End], "\n"), e.Quote) {
		return e, false
	}
	content, _ := ix.source.Content(e.File)
	e.Fingerprint = sourceindex.Fingerprint(content)
	e.Validation = "source_quote_matched"
	return e, true
}
func (b Bundle) PromptText() string {
	if len(b.Omitted) == 0 {
		return b.Text
	}
	omitted, _ := json.Marshal(b.Omitted)
	return b.Text + fmt.Sprintf("\nContext omissions (absence is not refutation): %s\n", omitted)
}

func (b Bundle) Includes(file string, start, end int) bool {
	if start < 1 {
		return false
	}
	if end < start {
		end = start
	}
	var ranges [][2]int
	for _, e := range b.Included {
		if e.File == file {
			ranges = append(ranges, [2]int{e.Start, e.End})
		}
	}
	return covered(merge(ranges), start, end)
}

func meaningfulQuote(s string) bool {
	n := 0
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			n++
		}
	}
	return n >= 3
}
