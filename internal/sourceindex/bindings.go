package sourceindex

import (
	"path"
	"regexp"
	"sort"
	"strings"
)

// Binding is a name a file binds by import. Targets lists the admitted files
// the import resolves to; it is empty when the module is external or was not
// admitted, and a local namesake is then not evidence of what the name means.
type Binding struct {
	Specifier string
	Targets   []string
}

// ImportOf reports whether file binds name by import, and to what. Each
// language's import syntax stays in its adapter or import parser; callers see
// only the binding.
func (ix *Index) ImportOf(file, name string) (Binding, bool) {
	src := ix.sources[file]
	if src == nil {
		return Binding{}, false
	}
	spec, ok := src.imports[name]
	if !ok {
		return Binding{}, false
	}
	b := Binding{Specifier: spec}
	if imp, ok := ix.importsByFile[file][spec]; ok && imp.Status == "resolved" {
		b.Targets = append(b.Targets, imp.Targets...)
	} else if src.language == "javascript" {
		b.Targets = jsAliasTargets(ix.paths, spec)
	}
	return b, true
}

// identifier is the shared lexical shape of a name, optionally qualified by
// one receiver or module name. It covers the C, JavaScript, Python, Go and
// JVM families; adapters with other rules can supply their own.
var identifier = regexp.MustCompile(`\b(?:([A-Za-z_$][\w$]*)\s*\.\s*)?([A-Za-z_$][\w$]*)\b`)

// StatementsReferencing returns the byte spans of statements in file that use
// name, so adjacent registrations stay separate even when one statement spans
// several lines. Import statements are excluded: they bind a name, not use it.
// Statements end at ';' or at a newline outside brackets, which holds for the
// languages the index reads; comments and literals are masked first.
func (ix *Index) StatementsReferencing(file, name string) [][2]int {
	src := ix.sources[file]
	if src == nil {
		return nil
	}
	code := ix.MaskedSource(file)
	var out [][2]int
	start, depth := 0, 0
	flush := func(end int) {
		if !overlaps(src.importSpans, start, end) {
			for _, m := range identifier.FindAllStringSubmatch(code[start:end], -1) {
				if m[2] == name {
					out = append(out, [2]int{start, end})
					break
				}
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

// NamesIn lists the names used in a span of file, as returned by
// StatementsReferencing. Offsets and lines refer to the original source.
func (ix *Index) NamesIn(file string, span [2]int) []Reference {
	code := ix.MaskedSource(file)
	if span[0] < 0 || span[1] > len(code) || span[0] >= span[1] {
		return nil
	}
	text := code[span[0]:span[1]]
	line := strings.Count(code[:span[0]], "\n") + 1
	var out []Reference
	for _, m := range identifier.FindAllStringSubmatchIndex(text, -1) {
		ref := Reference{Name: text[m[4]:m[5]], Offset: span[0] + m[0], Line: line + strings.Count(text[:m[0]], "\n")}
		if m[2] >= 0 {
			ref.Qualifier = text[m[2]:m[3]]
		}
		out = append(out, ref)
	}
	return out
}

// KnowsArguments reports whether file's adapter records call arguments, so
// that PassesName returning false means the name is not passed rather than
// unknown.
func (ix *Index) KnowsArguments(file string) bool {
	src := ix.sources[file]
	return src != nil && src.mode == "syntax"
}

func overlaps(spans [][2]int, start, end int) bool {
	for _, s := range spans {
		if s[0] < end && s[1] > start {
			return true
		}
	}
	return false
}

// hashCommentExts lists lexically read languages whose line comments start
// with '#'. Elsewhere '#' can be code, such as a C preprocessor directive.
var hashCommentExts = map[string]bool{
	".py": true, ".rb": true, ".sh": true, ".bash": true, ".zsh": true, ".pl": true, ".pm": true,
	".r": true, ".R": true, ".php": true, ".ex": true, ".exs": true, ".jl": true, ".nim": true,
	".cr": true, ".ps1": true, ".tcl": true, ".yaml": true, ".yml": true, ".toml": true,
}

// scriptBindings records the names JavaScript and Python files bind by
// import, and where their import statements are. Go and Kotlin adapters do
// this while parsing.
func scriptBindings(file, text string) (map[string]string, [][2]int) {
	switch language(file) {
	case "javascript":
		return javascriptBindings(text)
	case ".py":
		return pythonBindings(text)
	}
	return nil, nil
}

var (
	jsImportStatement = regexp.MustCompile(`(?s)\bimport\s+(?:type\s+)?([^;'"]*?)\s*\bfrom\s*['"]([^'"]+)['"]`)
	jsRequire         = regexp.MustCompile(`(?s)\b(?:const|let|var)\s+(\{[^}]*\}|[A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)`)
	jsBareImport      = regexp.MustCompile(`\bimport\s*['"][^'"]+['"]`)
)

func javascriptBindings(text string) (map[string]string, [][2]int) {
	names := map[string]string{}
	var spans [][2]int
	for _, m := range jsImportStatement.FindAllStringSubmatchIndex(text, -1) {
		spans = append(spans, [2]int{m[0], m[1]})
		clause, spec := text[m[2]:m[3]], text[m[4]:m[5]]
		if i := strings.Index(clause, "{"); i >= 0 {
			if j := strings.Index(clause[i:], "}"); j >= 0 {
				for _, item := range strings.Split(clause[i+1:i+j], ",") {
					// a, b as c, type d
					if fields := strings.Fields(item); len(fields) > 0 {
						names[fields[len(fields)-1]] = spec
					}
				}
			}
			clause = clause[:i]
		}
		// Default and namespace bindings: X, * as X
		for _, part := range strings.Split(clause, ",") {
			if fields := strings.Fields(part); len(fields) > 0 && fields[len(fields)-1] != "*" {
				names[fields[len(fields)-1]] = spec
			}
		}
	}
	for _, m := range jsRequire.FindAllStringSubmatchIndex(text, -1) {
		spans = append(spans, [2]int{m[0], m[1]})
		target, spec := text[m[2]:m[3]], text[m[4]:m[5]]
		if strings.HasPrefix(target, "{") {
			for _, item := range strings.Split(strings.Trim(target, "{}"), ",") {
				// a, b: c
				parts := strings.Split(item, ":")
				if name := strings.TrimSpace(parts[len(parts)-1]); name != "" {
					names[name] = spec
				}
			}
			continue
		}
		names[target] = spec
	}
	for _, m := range jsBareImport.FindAllStringIndex(text, -1) {
		spans = append(spans, [2]int{m[0], m[1]})
	}
	return names, spans
}

var pyBinding = regexp.MustCompile(`(?m)^[ \t]*(?:from[ \t]+([.\w]+)[ \t]+import[ \t]+(\([^)]*\)|[^\n#]+)|import[ \t]+([^\n#]+))`)

func pythonBindings(text string) (map[string]string, [][2]int) {
	names := map[string]string{}
	var spans [][2]int
	for _, m := range pyBinding.FindAllStringSubmatchIndex(text, -1) {
		spans = append(spans, [2]int{m[0], m[1]})
		if m[2] >= 0 {
			module := text[m[2]:m[3]]
			for _, item := range strings.Split(strings.Trim(text[m[4]:m[5]], "() \t\n"), ",") {
				fields := strings.Fields(item)
				if len(fields) == 0 {
					continue
				}
				name := fields[len(fields)-1]
				// "from . import helpers" binds a sibling module, which the
				// import parser records as its own specifier.
				spec := module
				if strings.Trim(module, ".") == "" {
					spec = module + fields[0]
				}
				names[name] = spec
			}
			continue
		}
		for _, item := range strings.Split(text[m[6]:m[7]], ",") {
			fields := strings.Fields(item)
			switch {
			case len(fields) == 3 && fields[1] == "as":
				names[fields[2]] = fields[0]
			case len(fields) == 1 && !strings.Contains(fields[0], "."):
				names[fields[0]] = fields[0]
			}
		}
	}
	return names, spans
}

// jsAliasTargets matches a non-relative specifier to admitted files, with
// directory index files. After a project alias (@/ or ~/) it matches at
// complete path segments. Any other specifier names a package unless it is
// a repository-relative path: a local file that only shares the package's
// name (src/auth-lib.ts for 'auth-lib') is not evidence of what the import
// means. Partial segments never match.
func jsAliasTargets(paths []string, spec string) []string {
	if strings.HasPrefix(spec, ".") {
		return nil
	}
	module, alias := strings.CutPrefix(spec, "@/")
	if !alias {
		module, alias = strings.CutPrefix(spec, "~/")
	}
	module = strings.TrimSuffix(module, path.Ext(module))
	var out []string
	for _, p := range paths {
		if language(p) != "javascript" || vendored(p) {
			continue
		}
		file := strings.TrimSuffix(strings.TrimSuffix(p, path.Ext(p)), "/index")
		if file == module || (alias && strings.HasSuffix(file, "/"+module)) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// MaskedSource returns the file as one string with comments and literals
// blanked, preserving byte offsets, for pattern matching that must not be
// fooled by prose or strings. Syntax adapters already expose masked lines;
// lexical files are masked here so every language is treated alike. The
// result is empty for an unknown file.
func (ix *Index) MaskedSource(file string) string {
	s := ix.sources[file]
	if s == nil {
		return ""
	}
	// Computed on first use; the index is otherwise immutable and may be
	// read concurrently.
	s.maskOnce.Do(func() {
		s.masked = strings.Join(s.code, "\n")
		if _, ok := s.adapter.(lexicalAdapter); ok {
			s.masked = maskSource(s.masked, hashCommentExts[path.Ext(file)])
		}
	})
	return s.masked
}
