// Package auditctx retrieves the source an audit needs beyond the files a
// claim cites: callers and route registrations of the flagged function,
// templates it renders, the call that receives the flagged value and what it
// passes that value to, and definitions of the functions and types the
// flagged lines use. Retrieval is syntax-aware and deterministic, so a replayed
// audit sees the same context, and it is bounded by a token budget.
package auditctx

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/block/codecrucible/internal/sourceindex"
)

type Def = sourceindex.Def
type defID = sourceindex.DefID

// Excerpt is a line range retrieved for context, 1-based and inclusive.
type Excerpt struct {
	File       string
	Start, End int
	Reason     string
}

// Index applies audit retrieval policy to a reusable source snapshot.
type Index struct {
	source    *sourceindex.Index
	templates map[string][]string
	callers   map[defID][]hit
}

type hit struct {
	file string
	line int
}

var (
	templateHint = regexp.MustCompile(`(?i)render|templ|tmpl|view|layout|include|parsefiles|parseglob|execute`)
	templateVar  = regexp.MustCompile(`(?i)[A-Za-z_$][\w$]*(?:tmpl|template|view)[\w$]*`)
	routeHint    = regexp.MustCompile(`(?i)route|router|handle|mux|\.(get|post|put|patch|delete|use|all)\s*\(|mapping|@path|path\(|url\(|register`)
)
var templateExts = map[string]bool{
	".html": true, ".htm": true, ".ejs": true, ".pug": true, ".jade": true, ".hbs": true, ".handlebars": true,
	".tmpl": true, ".tpl": true, ".gohtml": true, ".jinja": true, ".jinja2": true, ".j2": true, ".erb": true,
	".njk": true, ".twig": true, ".mustache": true, ".vue": true, ".jsp": true, ".ftl": true, ".vm": true,
}

// NewIndex is a convenience for callers that do not already have a snapshot.
func NewIndex(files map[string]string) *Index { return NewRetriever(sourceindex.New(files)) }

// NewRetriever reuses the source facts extracted during ingestion.
func NewRetriever(source *sourceindex.Index) *Index {
	ix := &Index{source: source, templates: map[string][]string{}, callers: map[defID][]hit{}}
	for _, p := range source.Paths() {
		if ext := path.Ext(p); templateExts[ext] {
			base := path.Base(p)
			ix.templates[base] = append(ix.templates[base], p)
			stem := strings.TrimSuffix(base, ext)
			ix.templates[stem] = append(ix.templates[stem], p)
		}
	}
	return ix
}

// Limits keep retrieval to evidence that plausibly decides a claim.
const (
	maxCallerFiles = 3
	maxCallerHits  = 2
	maxCallerSpan  = 8 // files referencing a name before it counts as too common
	callerRadius   = 8
	maxCallees     = 4
	maxTypes       = 3
	maxContaining  = 2 // calls the flagged value is passed into
	maxForwarded   = 2 // definitions a receiving call passes the value to
	maxDefLines    = 60
	maxTemplate    = 400
	// maxEnclosingSpan is how far below a definition a claim can sit and
	// still count as inside it.
	maxEnclosingSpan = 150
)

// Claim is the location an audit claim cites.
type Claim struct {
	File       string
	Start, End int
}

// Retrieve returns context excerpts for a claim in priority order: callers
// of the enclosing function (route registration, the path in), templates the
// flagged code renders, then definitions of called functions and named types.
// Excerpts in skip (files already sent in full) are omitted.
func (ix *Index) Retrieve(c Claim, skip map[string]bool) []Excerpt {
	lines := ix.source.Lines(c.File)
	if c.Start < 1 || c.Start > len(lines) {
		return nil
	}
	end := min(len(lines), max(c.End, c.Start))
	enclosing, haveEnclosing := ix.source.Enclosing(c.File, c.Start)
	// A definition far above the claim is more likely a neighbor than the
	// function containing an anonymous handler.
	if haveEnclosing && c.Start-enclosing.Line > maxEnclosingSpan {
		haveEnclosing = false
	}
	// The flagged window is the enclosing function, capped around the claim.
	lo, hi := max(1, c.Start-3), min(len(lines), end+3)
	if haveEnclosing {
		lo, hi = max(enclosing.Line, c.Start-30), min(enclosing.End, max(end+30, c.Start+3))
	}
	window := lines[lo-1 : hi]

	var out []Excerpt
	coverage := map[string][][2]int{}
	add := func(e Excerpt) {
		if !skip[e.File] && !covered(coverage[e.File], e.Start, e.End) {
			out = append(out, e)
			coverage[e.File] = merge(append(coverage[e.File], [2]int{e.Start, e.End}))
		}
	}
	if haveEnclosing && !genericNames[enclosing.Name] && len(enclosing.Name) >= 4 {
		for _, e := range ix.callerExcerpts(enclosing) {
			add(e)
		}
	}
	for _, e := range ix.templateExcerpts(ix.templateLines(c.File, window), c.File) {
		add(e)
	}
	seen := map[defID]bool{}
	if haveEnclosing {
		seen[enclosing.ID()] = true
	}
	n := 0
	for _, receiver := range ix.source.ContainingCalls(c.File, c.Start, end, lo) {
		if n >= maxContaining || genericNames[receiver.Name] {
			continue
		}
		d, ok := ix.source.Resolve(c.File, receiver.Reference, false)
		if !ok {
			d, ok = ix.source.Resolve(c.File, receiver.Reference, true)
		}
		if !ok || seen[d.ID()] {
			continue
		}
		seen[d.ID()] = true
		add(defExcerpt(d, "receives the flagged expression: "+receiver.Name))
		for _, e := range ix.forwarded(d, receiver, seen) {
			add(e)
		}
		n++
	}
	n = 0
	for _, call := range ix.source.Calls(c.File, lo, hi) {
		if n >= maxCallees || call.Line < lo || call.Line > hi || keywords[call.Name] || genericNames[call.Name] {
			continue
		}
		if d, ok := ix.source.Resolve(c.File, call, false); ok && !seen[d.ID()] {
			seen[d.ID()] = true
			add(defExcerpt(d, "definition of "+call.Name))
			n++
		}
	}
	n = 0
	for _, ref := range ix.source.TypeReferences(c.File, lo, hi) {
		if n >= maxTypes {
			break
		}
		if d, ok := ix.source.Resolve(c.File, ref, true); ok && !seen[d.ID()] {
			seen[d.ID()] = true
			add(defExcerpt(d, "type "+ref.Name))
			n++
		}
	}

	return out
}

func defExcerpt(d Def, reason string) Excerpt {
	return Excerpt{File: d.File, Start: d.Line, End: min(d.End, d.Line+maxDefLines-1), Reason: reason}
}

// Follow only the extractor's explicit one-hop parameter uses. The audit
// decides how many uses to show and never treats them as proven taint flow.
func (ix *Index) forwarded(d Def, c sourceindex.BoundCall, seen map[defID]bool) []Excerpt {
	var out []Excerpt
	for _, next := range ix.source.ForwardedUses(d, c) {
		if next.Line >= d.Line+maxDefLines || genericNames[next.Name] {
			continue
		}
		f, ok := ix.source.Resolve(d.File, next.Reference, false)
		if !ok {
			f, ok = ix.source.Resolve(d.File, next.Reference, true)
		}
		if ok && !seen[f.ID()] {
			seen[f.ID()] = true
			out = append(out, defExcerpt(f, "possible use of "+d.Name+" parameter "+next.Parameter+" in "+next.Name))
		}
		if len(out) == maxForwarded {
			break
		}
	}
	return out
}

// callerExcerpts returns the lines that reference def's name in other files,
// preferring lines that look like route registration.
func (ix *Index) callerExcerpts(def Def) []Excerpt {
	hits, ok := ix.callers[def.ID()]
	if !ok {
		word := regexp.MustCompile(`(?:^|[^\w$])` + regexp.QuoteMeta(def.Name) + `(?:[^\w$]|$)`)
		for _, p := range ix.source.Paths() {
			code := ix.source.Code(p)
			content, _ := ix.source.Content(p)
			if p == def.File || code == nil || ix.source.Language(p) != ix.source.Language(def.File) || !strings.Contains(content, def.Name) {
				continue
			}
			for i, line := range code {
				if len(line) < 500 && word.MatchString(line) {
					if ix.source.IsDefinition(p, i+1, def.Name) {
						continue
					}
					hits = append(hits, hit{p, i + 1})
				}
			}
		}
		ix.callers[def.ID()] = hits
	}
	byFile := map[string][]hit{}
	var order []string
	for _, h := range hits {
		if _, ok := byFile[h.file]; !ok {
			order = append(order, h.file)
		}
		byFile[h.file] = append(byFile[h.file], h)
	}
	if len(order) == 0 || len(order) > maxCallerSpan {
		return nil
	}
	routed := func(f string) bool {
		for _, h := range byFile[f] {
			if routeHint.MatchString(ix.source.Lines(f)[h.line-1]) {
				return true
			}
		}
		return false
	}
	// Route registrations first, then callers outside tests.
	rank := func(f string) int {
		r := 0
		if !routed(f) {
			r += 2
		}
		if testPath(f) {
			r++
		}
		return r
	}
	sort.SliceStable(order, func(i, j int) bool { return rank(order[i]) < rank(order[j]) })
	var out []Excerpt
	for _, f := range order[:min(len(order), maxCallerFiles)] {
		for _, h := range byFile[f][:min(len(byFile[f]), maxCallerHits)] {
			out = append(out, Excerpt{File: f, Start: max(1, h.line-callerRadius), End: min(len(ix.source.Lines(f)), h.line+callerRadius),
				Reason: "reference to " + def.Name})
		}
	}
	return out
}

// templateLines extends window with the lines of file that mention a
// template-named variable used in window, so a template parsed at startup
// into searchTmpl is found from a handler that calls searchTmpl.Execute.
func (ix *Index) templateLines(file string, window []string) []string {
	vars := map[string]bool{}
	for _, line := range window {
		for _, v := range templateVar.FindAllString(line, -1) {
			vars[v] = true
		}
	}
	if len(vars) == 0 {
		return window
	}
	out := append([]string(nil), window...)
	for _, line := range ix.source.Lines(file) {
		for v := range vars {
			if strings.Contains(line, v) {
				out = append(out, line)
				break
			}
		}
	}
	return out
}

// templateExcerpts returns templates named by string literals on lines of
// window that look like rendering.
func (ix *Index) templateExcerpts(window []string, from string) []Excerpt {
	var out []Excerpt
	seen := map[string]bool{}
	for _, line := range window {
		if !templateHint.MatchString(line) {
			continue
		}
		for _, m := range stringLit.FindAllStringSubmatch(line, -1) {
			name := m[1]
			cands := ix.templates[path.Base(name)]
			if len(cands) > 1 {
				cands = closest(cands, name, from)
			}
			if len(cands) != 1 || seen[cands[0]] {
				continue
			}
			p := cands[0]
			seen[p] = true
			out = append(out, Excerpt{File: p, Start: 1, End: min(len(ix.source.Lines(p)), maxTemplate), Reason: "template " + name})
		}
	}
	return out
}

// closest narrows ambiguous template matches to those whose path ends with
// the literal, then to those sharing the most leading directories with from.
func closest(cands []string, name, from string) []string {
	var suffix []string
	for _, c := range cands {
		if strings.HasSuffix(c, "/"+strings.TrimPrefix(name, "./")) || c == name {
			suffix = append(suffix, c)
		}
	}
	if len(suffix) == 1 {
		return suffix
	}
	return nil
}

// Render writes excerpts as numbered <file> blocks, merging overlapping
// ranges per file, in order of each file's first excerpt. count measures a
// block's tokens; excerpts are added in priority order until budget is spent.
// The returned count includes excerpts already covered by an admitted range.
func Render(ix *Index, excerpts []Excerpt, budget int, count func(string) int) (string, int) {
	type fileRanges struct {
		path   string
		ranges [][2]int
	}
	var files []*fileRanges
	byPath := map[string]*fileRanges{}
	used := 0
	kept := 0
	for _, e := range excerpts {
		lines := ix.source.Lines(e.File)
		start, end := max(1, e.Start), min(len(lines), e.End)
		if start > end {
			continue
		}
		f := byPath[e.File]
		if f != nil && covered(f.ranges, start, end) {
			kept++
			continue
		}
		cost := count(strings.Join(lines[start-1:end], "\n")) + 10
		if used+cost > budget {
			continue
		}
		used += cost
		kept++
		if f == nil {
			f = &fileRanges{path: e.File}
			byPath[e.File] = f
			files = append(files, f)
		}
		f.ranges = append(f.ranges, [2]int{start, end})
	}
	var b strings.Builder
	for _, f := range files {
		ranges := merge(f.ranges)
		labels := make([]string, len(ranges))
		for i, r := range ranges {
			labels[i] = fmt.Sprintf("%d-%d", r[0], r[1])
		}
		fmt.Fprintf(&b, "<file path=\"%s\" lines=\"%s\">\n", f.path, strings.Join(labels, ","))
		lines := ix.source.Lines(f.path)
		for i, r := range ranges {
			if i > 0 {
				b.WriteString("...\n")
			}
			for n := r[0]; n <= r[1]; n++ {
				fmt.Fprintf(&b, "%d| %s\n", n, lines[n-1])
			}
		}
		b.WriteString("</file>\n\n")
	}
	return b.String(), kept
}

func covered(ranges [][2]int, start, end int) bool {
	for _, r := range ranges {
		if r[0] <= start && end <= r[1] {
			return true
		}
	}
	return false
}

func merge(ranges [][2]int) [][2]int {
	sorted := append([][2]int(nil), ranges...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i][0] < sorted[j][0] })
	var out [][2]int
	for _, r := range sorted {
		if n := len(out); n > 0 && r[0] <= out[n-1][1]+1 {
			out[n-1][1] = max(out[n-1][1], r[1])
			continue
		}
		out = append(out, r)
	}
	return out
}

var testFile = regexp.MustCompile(`(?i)(^|/)(tests?|__tests__|spec)/|(_test|\.test|\.spec|tests?)\.[a-z]+$|(^|/)test_[^/]*$`)

// testPath reports whether path looks like a test file.
func testPath(path string) bool {
	return testFile.MatchString(path)
}

var (
	keywords = map[string]bool{
		"if": true, "for": true, "while": true, "switch": true, "catch": true, "return": true, "function": true,
		"else": true, "do": true, "try": true, "with": true, "new": true, "typeof": true, "await": true,
	}
	// Names too common to identify one function.
	genericNames = map[string]bool{
		"main": true, "init": true, "handler": true, "handle": true, "New": true, "new": true, "get": true, "set": true,
		"run": true, "Run": true, "ServeHTTP": true, "toString": true, "constructor": true, "index": true, "render": true,
		"String": true, "Error": true, "close": true, "Close": true, "execute": true, "apply": true, "call": true,
	}
	stringLit = regexp.MustCompile("[\"'`]([\\w./-]+)[\"'`]")
)
