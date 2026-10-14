// Package auditctx retrieves the source an audit needs beyond the files a
// claim cites: callers and route registrations of the flagged function,
// templates it renders, and definitions of the functions and types the
// flagged lines use. Retrieval is lexical and deterministic, so a replayed
// audit sees the same context, and it is bounded by a token budget.
package auditctx

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Def is a function or type definition found in a scanned file.
type Def struct {
	Name string
	Type bool // a type (struct, class, interface) rather than a function
	File string
	Line int
	End  int // last line of the definition, bounded by the next definition
}

// Excerpt is a line range retrieved for context, 1-based and inclusive.
type Excerpt struct {
	File       string
	Start, End int
	Reason     string
}

// Index holds the scanned files and their definitions.
type Index struct {
	files     map[string]string
	lines     map[string][]string
	defs      map[string][]Def // by name
	byFile    map[string][]Def // in line order
	templates map[string][]string
	callers   map[string][]hit
}

type hit struct {
	file string
	line int
}

var (
	funcPatterns = []*regexp.Regexp{
		regexp.MustCompile(`^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*[\[(]`),                                                                                                            // Go
		regexp.MustCompile(`^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(`),                                                                        // JS function
		regexp.MustCompile(`^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:async\s+)?(?:function\b|\(|[A-Za-z_$][\w$]*\s*=>)`),                                // JS arrow or function expression
		regexp.MustCompile(`^\s*(?:module\.)?exports\.([A-Za-z_$][\w$]*)\s*=`),                                                                                                              // CommonJS export
		regexp.MustCompile(`^\s*module\.exports\s*=\s*(?:async\s+)?function\s*([A-Za-z_$][\w$]*)`),                                                                                          // CommonJS default export
		regexp.MustCompile(`^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(`),                                                                                                                    // Python
		regexp.MustCompile(`^\s*(?:[a-z]+\s+)*fun\s+(?:<[^>]*>\s*)?(?:[\w.]+\.)?([A-Za-z_]\w*)\s*\(`),                                                                                       // Kotlin
		regexp.MustCompile(`^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+"[^"]*"\s+)?fn\s+([A-Za-z_]\w*)`),                                                           // Rust
		regexp.MustCompile(`^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|private|protected|static|final|synchronized|abstract|override|async)\s+)+(?:[\w<>\[\],.?]+\s+)?([A-Za-z_]\w*)\s*\(`), // Java, C#, TS methods with a modifier
		regexp.MustCompile(`^\s{2,}(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*(?::\s*[^{]+)?\{\s*$`),                                                                                     // indented method
	}
	typePatterns = []*regexp.Regexp{
		regexp.MustCompile(`^\s*type\s+([A-Za-z_]\w*)\s+(?:struct|interface)\b`), // Go
		regexp.MustCompile(`^\s*(?:export\s+)?(?:default\s+)?(?:(?:public|private|protected|internal|abstract|final|sealed|data|open|static)\s+)*(?:class|interface|struct|enum|record|trait)\s+([A-Za-z_]\w*)`), // most languages
		regexp.MustCompile(`^\s*(?:export\s+)?type\s+([A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*=`), // TypeScript
	}
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
	callName     = regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*\(`)
	typeName     = regexp.MustCompile(`\b([A-Z][A-Za-z0-9_]*)\b`)
	stringLit    = regexp.MustCompile("[\"'`]([\\w./-]+)[\"'`]")
	templateHint = regexp.MustCompile(`(?i)render|templ|tmpl|view|layout|include|parsefiles|parseglob|execute`)
	templateVar  = regexp.MustCompile(`(?i)[A-Za-z_$][\w$]*(?:tmpl|template|view)[\w$]*`)
	routeHint    = regexp.MustCompile(`(?i)route|router|handle|mux|\.(get|post|put|patch|delete|use|all)\s*\(|mapping|@path|path\(|url\(|register`)
)

var templateExts = map[string]bool{
	".html": true, ".htm": true, ".ejs": true, ".pug": true, ".jade": true, ".hbs": true, ".handlebars": true,
	".tmpl": true, ".tpl": true, ".gohtml": true, ".jinja": true, ".jinja2": true, ".j2": true, ".erb": true,
	".njk": true, ".twig": true, ".mustache": true, ".vue": true, ".jsp": true, ".ftl": true, ".vm": true,
}

// NewIndex indexes the definitions in files.
func NewIndex(files map[string]string) *Index {
	ix := &Index{files: files, lines: make(map[string][]string, len(files)), defs: map[string][]Def{},
		byFile: map[string][]Def{}, templates: map[string][]string{}, callers: map[string][]hit{}}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		lines := strings.Split(files[p], "\n")
		ix.lines[p] = lines
		if ext := path.Ext(p); templateExts[ext] {
			base := path.Base(p)
			ix.templates[base] = append(ix.templates[base], p)
			ix.templates[strings.TrimSuffix(base, ext)] = append(ix.templates[strings.TrimSuffix(base, ext)], p)
			continue
		}
		var defs []Def
		for i, line := range lines {
			if d, ok := matchDef(line); ok {
				d.File, d.Line = p, i+1
				defs = append(defs, d)
			}
		}
		for i := range defs {
			end := len(lines)
			if i+1 < len(defs) {
				end = defs[i+1].Line - 1
			}
			defs[i].End = end
			ix.defs[defs[i].Name] = append(ix.defs[defs[i].Name], defs[i])
		}
		ix.byFile[p] = defs
	}
	return ix
}

func matchDef(line string) (Def, bool) {
	if len(line) > 300 {
		return Def{}, false
	}
	for _, re := range typePatterns {
		if m := re.FindStringSubmatch(line); m != nil {
			return Def{Name: m[1], Type: true}, true
		}
	}
	for _, re := range funcPatterns {
		if m := re.FindStringSubmatch(line); m != nil && !keywords[m[1]] {
			return Def{Name: m[1]}, true
		}
	}
	return Def{}, false
}

// Limits keep retrieval to evidence that plausibly decides a claim.
const (
	maxCallerFiles = 3
	maxCallerHits  = 2
	maxCallerSpan  = 8 // files referencing a name before it counts as too common
	callerRadius   = 8
	maxCallees     = 4
	maxTypes       = 3
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
	lines, ok := ix.lines[c.File]
	if !ok || c.Start < 1 {
		return nil
	}
	end := max(c.End, c.Start)
	enclosing, haveEnclosing := ix.enclosing(c.File, c.Start)
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
	add := func(e Excerpt) {
		if !skip[e.File] {
			out = append(out, e)
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
	seen := map[string]bool{}
	if haveEnclosing {
		seen[enclosing.Name] = true
	}
	n := 0
	for _, line := range window {
		for _, m := range callName.FindAllStringSubmatch(line, -1) {
			name := m[1]
			if n >= maxCallees || seen[name] || keywords[name] || genericNames[name] {
				continue
			}
			seen[name] = true
			if d, ok := ix.uniqueDef(name, false, c.File); ok {
				add(Excerpt{File: d.File, Start: d.Line, End: min(d.End, d.Line+maxDefLines-1), Reason: "definition of " + name})
				n++
			}
		}
	}
	n = 0
	for _, line := range window {
		for _, m := range typeName.FindAllStringSubmatch(line, -1) {
			name := m[1]
			if n >= maxTypes || seen[name] {
				continue
			}
			seen[name] = true
			if d, ok := ix.uniqueDef(name, true, c.File); ok {
				add(Excerpt{File: d.File, Start: d.Line, End: min(d.End, d.Line+maxDefLines-1), Reason: "type " + name})
				n++
			}
		}
	}
	return out
}

// enclosing returns the function definition containing line.
func (ix *Index) enclosing(file string, line int) (Def, bool) {
	var best Def
	found := false
	for _, d := range ix.byFile[file] {
		if d.Line > line {
			break
		}
		if !d.Type {
			best, found = d, true
		}
	}
	return best, found
}

// uniqueDef finds name's definition outside file. Names defined in more than
// two places are ambiguous and skipped.
func (ix *Index) uniqueDef(name string, typ bool, file string) (Def, bool) {
	var match []Def
	for _, d := range ix.defs[name] {
		if d.Type == typ {
			if d.File == file {
				return Def{}, false // visible already
			}
			match = append(match, d)
		}
	}
	if len(match) == 0 || len(match) > 2 {
		return Def{}, false
	}
	return match[0], true
}

// callerExcerpts returns the lines that reference def's name in other files,
// preferring lines that look like route registration.
func (ix *Index) callerExcerpts(def Def) []Excerpt {
	hits, ok := ix.callers[def.Name]
	if !ok {
		word := regexp.MustCompile(`(?:^|[^\w$])` + regexp.QuoteMeta(def.Name) + `(?:[^\w$]|$)`)
		for _, p := range sortedKeys(ix.lines) {
			if p == def.File || !strings.Contains(ix.files[p], def.Name) {
				continue
			}
			for i, line := range ix.lines[p] {
				if len(line) < 500 && word.MatchString(line) {
					if d, isDef := matchDef(line); isDef && d.Name == def.Name {
						continue
					}
					hits = append(hits, hit{p, i + 1})
				}
			}
		}
		ix.callers[def.Name] = hits
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
			if routeHint.MatchString(ix.lines[f][h.line-1]) {
				return true
			}
		}
		return false
	}
	sort.SliceStable(order, func(i, j int) bool { return routed(order[i]) && !routed(order[j]) })
	var out []Excerpt
	for _, f := range order[:min(len(order), maxCallerFiles)] {
		for _, h := range byFile[f][:min(len(byFile[f]), maxCallerHits)] {
			out = append(out, Excerpt{File: f, Start: max(1, h.line-callerRadius), End: min(len(ix.lines[f]), h.line+callerRadius),
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
	for _, line := range ix.lines[file] {
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
			out = append(out, Excerpt{File: p, Start: 1, End: min(len(ix.lines[p]), maxTemplate), Reason: "template " + name})
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

func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Render writes excerpts as numbered <file> blocks, merging overlapping
// ranges per file, in order of each file's first excerpt. count measures a
// block's tokens; excerpts are added in priority order until budget is spent.
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
		lines := ix.lines[e.File]
		start, end := max(1, e.Start), min(len(lines), e.End)
		if start > end {
			continue
		}
		f := byPath[e.File]
		if f != nil && covered(f.ranges, start, end) {
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
		lines := ix.lines[f.path]
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
