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
)

// Def is a function or type definition found in a scanned file.
type Def struct {
	Name               string
	Type               bool // a type (struct, class, interface) rather than a function
	File               string
	Line               int
	End                int // inclusive; lexical fallback stops at the next declaration
	owner              string
	params             []parameter
	bodyStart, bodyEnd int // byte offsets, exclusive end; zero if binding is unsupported
}

// Excerpt is a line range retrieved for context, 1-based and inclusive.
// An empty File carries an omission note in Reason instead of source.
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
	sources   map[string]*sourceInfo
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

// NewIndex indexes the definitions in files.
func NewIndex(files map[string]string) *Index {
	ix := &Index{files: files, lines: make(map[string][]string, len(files)), defs: map[string][]Def{},
		byFile: map[string][]Def{}, templates: map[string][]string{}, callers: map[defID][]hit{}, sources: map[string]*sourceInfo{}}
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
			// Template claims can themselves reference included templates.
			// They have no language bindings, but still participate in retrieval.
			ix.sources[p] = &sourceInfo{adapter: lexicalAdapter{}, language: language(p), code: lines}
			continue
		}
		src := adapterFor(p).parse(p, files[p])
		ix.sources[p] = src
		for _, d := range src.defs {
			ix.defs[d.Name] = append(ix.defs[d.Name], d)
		}
		ix.byFile[p] = src.defs
	}
	return ix
}

// Limits keep retrieval to evidence that plausibly decides a claim.
const (
	maxCallerFiles       = 3
	maxCallerHits        = 2
	maxCallerSpan        = 8 // files referencing a name before it counts as too common
	callerRadius         = 8
	maxCallees           = 4
	maxCallerDefinitions = 8
	maxTypes             = 3
	maxContaining        = 2 // calls the flagged value is passed into
	maxForwarded         = 2 // definitions a receiving call passes the value to
	maxDefLines          = 60
	maxTemplate          = 400
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
	if !ok || c.Start < 1 || c.Start > len(lines) || ix.sources[c.File] == nil {
		return nil
	}
	end := min(len(lines), max(c.End, c.Start))
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
	coverage := map[string][][2]int{}
	add := func(e Excerpt) {
		if e.File == "" {
			out = append(out, e)
			return
		}
		if !skip[e.File] && !covered(coverage[e.File], e.Start, e.End) {
			out = append(out, e)
			coverage[e.File] = merge(append(coverage[e.File], [2]int{e.Start, e.End}))
		}
	}
	seen := map[defID]bool{}
	if haveEnclosing {
		seen[enclosing.id()] = true
	}
	if haveEnclosing && !genericNames[enclosing.Name] && len(enclosing.Name) >= 4 {
		callers := ix.callerExcerpts(enclosing)
		for _, e := range callers {
			add(e)
		}
		for _, e := range ix.callerDefinitions(enclosing, callers, seen) {
			add(e)
		}
	}
	for _, e := range ix.templateExcerpts(ix.templateLines(c.File, window), c.File) {
		add(e)
	}
	src := ix.sources[c.File]
	n := 0
	for _, receiver := range src.containingCalls(c.Start, end, lo) {
		if n >= maxContaining || genericNames[receiver.name] {
			continue
		}
		d, ok := ix.resolve(c.File, receiver.reference, false)
		if !ok {
			d, ok = ix.resolve(c.File, receiver.reference, true)
		}
		if !ok || seen[d.id()] {
			continue
		}
		seen[d.id()] = true
		add(defExcerpt(d, "receives the flagged expression: "+receiver.name))
		for _, e := range ix.forwarded(d, receiver, seen) {
			add(e)
		}
		n++
	}
	n = 0
	for _, call := range src.calls {
		if n >= maxCallees || call.line < lo || call.line > hi || keywords[call.name] || genericNames[call.name] {
			continue
		}
		if d, ok := ix.resolve(c.File, call.reference, false); ok && !seen[d.id()] {
			seen[d.id()] = true
			add(defExcerpt(d, "definition of "+call.name))
			n++
		}
	}
	n = 0
	offset := 0
	for i, line := range src.code {
		if i+1 >= lo && i+1 <= hi {
			for _, m := range typeName.FindAllStringSubmatchIndex(line, -1) {
				ref := reference{name: line[m[4]:m[5]], offset: offset + m[0]}
				refs := []reference{ref}
				if m[2] >= 0 {
					ref.qualifier = line[m[2]:m[3]]
					// In Direction.OUTBOUND the qualifier is itself the type;
					// in models.User the qualified member is the type.
					refs = []reference{{name: ref.qualifier, offset: ref.offset}, ref}
				}
				for _, ref := range refs {
					if n >= maxTypes {
						break
					}
					if d, ok := ix.resolve(c.File, ref, true); ok && !seen[d.id()] {
						seen[d.id()] = true
						add(defExcerpt(d, "type "+ref.name))
						n++
					}
				}
			}
		}
		offset += len(line) + 1
	}
	return out
}

func defExcerpt(d Def, reason string) Excerpt {
	return Excerpt{File: d.File, Start: d.Line, End: min(d.End, d.Line+maxDefLines-1), Reason: reason}
}

// enclosing returns the function definition containing line.
func (ix *Index) enclosing(file string, line int) (Def, bool) {
	var best Def
	found := false
	for _, d := range ix.byFile[file] {
		if d.Line > line {
			break
		}
		if !d.Type && line <= d.End {
			best, found = d, true
		}
	}
	return best, found
}

// callerExcerpts returns the lines that reference def's name in other files,
// preferring lines that look like route registration.
func (ix *Index) callerExcerpts(def Def) []Excerpt {
	hits, ok := ix.callers[def.id()]
	if !ok {
		word := regexp.MustCompile(`(?:^|[^\w$])` + regexp.QuoteMeta(def.Name) + `(?:[^\w$]|$)`)
		for _, p := range sortedKeys(ix.lines) {
			src := ix.sources[p]
			if p == def.File || src == nil || src.language != ix.sources[def.File].language || !strings.Contains(ix.files[p], def.Name) {
				continue
			}
			for i, line := range src.code {
				if len(line) < 500 && word.MatchString(line) {
					if ix.isDefinition(p, i+1, def.Name) {
						continue
					}
					hits = append(hits, hit{p, i + 1})
				}
			}
		}
		ix.callers[def.id()] = hits
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
		sort.SliceStable(byFile[f], func(i, j int) bool {
			return routeHint.MatchString(ix.lines[f][byFile[f][i].line-1]) && !routeHint.MatchString(ix.lines[f][byFile[f][j].line-1])
		})
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
	var notes []string
	truncated := false
	kept := 0
	for _, e := range excerpts {
		if e.File == "" {
			notes = append(notes, e.Reason)
			continue
		}
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
			truncated = true
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
	if truncated {
		notes = append(notes, "Audit context omitted: token budget exhausted")
	}
	seenNotes := map[string]bool{}
	for _, note := range notes {
		if seenNotes[note] {
			continue
		}
		seenNotes[note] = true
		fmt.Fprintf(&b, "%s\n", note)
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

// callerDefinitions retrieves local definitions named by callers. These are
// context candidates, not proof that a guard executes or applies to a claim.
func (ix *Index) callerDefinitions(subject Def, callers []Excerpt, seen map[defID]bool) []Excerpt {
	type candidate struct {
		file string
		ref  reference
	}
	var candidates []candidate
	for _, e := range callers {
		src := ix.sources[e.File]
		if src == nil {
			continue
		}
		code := strings.Join(src.code, "\n")
		if _, ok := src.adapter.(lexicalAdapter); ok {
			code = maskSource(code, src.language == ".py")
		}
		for _, span := range callerStatementSpans(code, subject.Name) {
			line := strings.Count(code[:span[0]], "\n") + 1
			endLine := line + strings.Count(code[span[0]:span[1]], "\n")
			if endLine < e.Start || line > e.End {
				continue
			}
			for _, m := range callerNameUse.FindAllStringSubmatchIndex(code[span[0]:span[1]], -1) {
				text := code[span[0]:span[1]]
				ref := reference{name: text[m[4]:m[5]], offset: span[0] + m[0]}
				if m[2] >= 0 {
					ref.qualifier = text[m[2]:m[3]]
				}
				_, imported := callerImport(ix.files[e.File], ref.name)
				if len(ix.defs[ref.name]) > 0 || imported || ref.qualifier != "" {
					candidates = append(candidates, candidate{e.File, ref})
				}
			}
		}
	}
	var out []Excerpt
	noted := map[string]bool{}
	definitions := 0
	for _, c := range candidates {
		if keywords[c.ref.name] || genericNames[c.ref.name] || c.ref.name == subject.Name {
			continue
		}
		d, ok := ix.resolve(c.file, c.ref, false)
		importName := c.ref.name
		if c.ref.qualifier != "" {
			importName = c.ref.qualifier
		}
		if module, imported := callerImport(ix.files[c.file], importName); imported && !strings.HasPrefix(module, ".") && (!ok || !callerModuleMatches(module, d.File)) {
			ok = false
		}
		if !ok {
			// Only direct wrappers of the subject need missing-context notes.
			if ix.sources[c.file].language == ".go" && c.ref.qualifier != "" && !callerWrapsSubject(ix.sources[c.file], c.ref, subject.Name) {
				continue
			}
			reason := "unresolved or external"
			if len(ix.candidates(c.file, c.ref.name, false)) > 1 {
				reason = "ambiguous"
			}
			note := fmt.Sprintf("Audit context omitted: %s caller reference %s in %s", reason, c.ref.name, c.file)
			if !noted[note] {
				out = append(out, Excerpt{Reason: note})
				noted[note] = true
			}
			continue
		}
		if seen[d.id()] {
			continue
		}
		seen[d.id()] = true
		if definitions == maxCallerDefinitions {
			out = append(out, Excerpt{Reason: "Audit context omitted: caller definition limit reached"})
			break
		}
		definitions++
		out = append(out, defExcerpt(d, "candidate definition near caller of "+subject.Name+": "+c.ref.name))
	}
	return out
}

var callerNameUse = regexp.MustCompile(`\b(?:([A-Za-z_$][\w$]*)\s*\.\s*)?([A-Za-z_$][\w$]*)\b`)

// callerStatementSpans keeps adjacent registrations separate, including when
// one statement spans several lines. Literal and comment bytes are masked.
func callerStatementSpans(code, subject string) [][2]int {
	var out [][2]int
	start, depth := 0, 0
	flush := func(end int) {
		statement := code[start:end]
		for _, match := range callerNameUse.FindAllStringSubmatch(statement, -1) {
			if match[2] == subject && !strings.HasPrefix(strings.TrimSpace(statement), "import ") {
				out = append(out, [2]int{start, end})
				break
			}
		}
		start = end
	}
	for i, ch := range code {
		switch ch {
		case '(', '[':
			depth++
		case ')', ']':
			if depth > 0 {
				depth--
			}
		}
		if ch == ';' || (ch == '\n' && depth == 0) {
			flush(i + 1)
		}
	}
	if start < len(code) {
		flush(len(code))
	}
	return out
}

var callerDefaultImport = regexp.MustCompile(`import\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s+from\s*['"]([^'"]+)['"]`)

var callerNamedImport = regexp.MustCompile(`(?s)import\s*\{([^}]+)\}\s*from\s*['"]([^'"]+)['"]`)

// callerModuleMatches recognizes local aliases only at complete path segments.
func callerModuleMatches(module, file string) bool {
	module = strings.TrimPrefix(strings.TrimPrefix(module, "@/"), "~/")
	module = strings.TrimSuffix(module, path.Ext(module))
	file = strings.TrimSuffix(file, path.Ext(file))
	file = strings.TrimSuffix(file, "/index")
	return file == module || strings.HasSuffix(file, "/"+module)
}

// callerImport handles ES imports only; Go and Python retain adapter resolution.
func callerImport(code, name string) (string, bool) {
	for _, match := range callerDefaultImport.FindAllStringSubmatch(code, -1) {
		if match[1] == name {
			return match[2], true
		}
	}
	for _, match := range callerNamedImport.FindAllStringSubmatch(code, -1) {
		for _, item := range strings.Split(match[1], ",") {
			fields := strings.Fields(item)
			if len(fields) > 0 && fields[len(fields)-1] == name {
				return match[2], true
			}
		}
	}
	return "", false
}

func callerWrapsSubject(src *sourceInfo, ref reference, subject string) bool {
	for _, call := range src.calls {
		if call.name != ref.name || call.qualifier != ref.qualifier || call.offset != ref.offset {
			continue
		}
		for _, arg := range call.args {
			if arg.direct == subject {
				return true
			}
		}
	}
	return false
}
