package auditctx

import (
	"path"
	"sort"
)

// Adapters supply syntax and name resolution only. Traversal, prioritization,
// excerpt coverage and budgets belong to the shared retrieval engine. A parsed
// call is a context hint, not proof of data flow or of a security control.
type languageAdapter interface {
	parse(file, text string) *sourceInfo
	resolve(ix *Index, file string, ref reference, typ bool) (Def, bool)
}

type sourceInfo struct {
	adapter     languageAdapter
	language    string
	code        []string // syntax adapters mask comments/literals; fallback is lexical
	defs        []Def
	calls       []call
	packageName string
	imports     map[string]string
	unbound     [][2]int // scopes in which parameter identity is not established
}

type parameter struct{ name, typ string }
type reference struct {
	name, qualifier string
	offset          int
}
type argument struct {
	name, direct string // named argument, and bare identifier (if any)
	start, end   int    // inclusive lines
}
type call struct {
	reference
	start, end int // byte offsets; exclusive end
	line       int
	args       []argument
}
type boundCall struct {
	call
	arg int // -1 when a line intersects multiple arguments
}

func adapterFor(file string) languageAdapter {
	switch path.Ext(file) {
	case ".go":
		return goAdapter{}
	case ".kt", ".kts":
		return kotlinAdapter{}
	default:
		return lexicalAdapter{}
	}
}

func language(file string) string {
	switch ext := path.Ext(file); ext {
	case ".kt", ".kts":
		return "kotlin"
	case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs":
		return "javascript"
	default:
		return ext
	}
}

func onlyDefinition(candidates []Def) (Def, bool) {
	if len(candidates) != 1 {
		return Def{}, false
	}
	return candidates[0], true
}

func (ix *Index) candidates(file, name string, typ bool) []Def {
	var out []Def
	for _, d := range ix.defs[name] {
		if d.Type == typ && ix.sources[d.File].language == ix.sources[file].language {
			out = append(out, d)
		}
	}
	return out
}

func (ix *Index) resolve(file string, ref reference, typ bool) (Def, bool) {
	return ix.sources[file].adapter.resolve(ix, file, ref, typ)
}

func (ix *Index) isDefinition(file string, line int, name string) bool {
	for _, d := range ix.byFile[file] {
		if d.Line == line && d.Name == name {
			return true
		}
	}
	return false
}

// containingCalls includes inline arguments, but prefers calls opened above
// the flagged line: those receive the expression being reported on that line.
// With only line coordinates, multiple arguments on that line cannot be bound.
func (s *sourceInfo) containingCalls(start, end, lo int) []boundCall {
	var out []boundCall
	for _, c := range s.calls {
		if c.line < lo || c.line > end || len(c.args) == 0 {
			continue
		}
		arg, hits := -1, 0
		for i, a := range c.args {
			if a.start <= end && a.end >= start {
				arg, hits = i, hits+1
			}
		}
		if hits == 0 {
			continue
		}
		if hits > 1 {
			arg = -1
		}
		out = append(out, boundCall{c, arg})
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if (a.line < start) != (b.line < start) {
			return a.line < start
		}
		return a.end-a.start < b.end-b.start
	})
	for i := range out {
		for _, inner := range out[:i] {
			if inner.line < start && inner.start > out[i].start && inner.end < out[i].end {
				// An outer call receives the inner call's result, not the
				// flagged argument. Keep its context but do not bind it.
				out[i].arg = -1
				break
			}
		}
	}
	return out
}

func (d Def) boundParameter(c boundCall) string {
	if c.arg < 0 || c.arg >= len(c.args) {
		return ""
	}
	if name := c.args[c.arg].name; name != "" {
		for _, p := range d.params {
			if p.name == name {
				return name
			}
		}
		return ""
	}
	if c.arg < len(d.params) {
		return d.params[c.arg].name
	}
	return ""
}

type defID struct {
	file, name string
	line       int
	typ        bool
}

func (d Def) id() defID { return defID{d.File, d.Name, d.Line, d.Type} }

// Follow just one hop, and only explicit identifier arguments. Expressions,
// aliases, nested declarations and unsupported signatures are not taint traced.
func (ix *Index) forwarded(d Def, c boundCall, seen map[defID]bool) []Excerpt {
	param := d.boundParameter(c)
	if param == "" || d.bodyEnd <= d.bodyStart {
		return nil
	}
	var out []Excerpt
	for _, next := range ix.sources[d.File].calls {
		if next.start < d.bodyStart || next.end > d.bodyEnd || next.line >= d.Line+maxDefLines || genericNames[next.name] {
			continue
		}
		// A nested function's parameter may shadow this one.
		nested := false
		for _, span := range ix.sources[d.File].unbound {
			if span[0] >= d.bodyStart && span[1] <= d.bodyEnd && next.start >= span[0] && next.end <= span[1] {
				nested = true
				break
			}
		}
		for _, child := range ix.byFile[d.File] {
			if child.id() != d.id() && child.bodyStart >= d.bodyStart && child.bodyEnd <= d.bodyEnd && next.start >= child.bodyStart && next.end <= child.bodyEnd {
				nested = true
				break
			}
		}
		if nested {
			continue
		}
		for _, a := range next.args {
			if a.direct != param {
				continue
			}
			f, ok := ix.resolve(d.File, next.reference, false)
			if !ok {
				f, ok = ix.resolve(d.File, next.reference, true)
			}
			if ok && !seen[f.id()] {
				seen[f.id()] = true
				out = append(out, defExcerpt(f, "possible use of "+d.Name+" parameter "+param+" in "+next.name))
			}
			break
		}
		if len(out) == maxForwarded {
			break
		}
	}
	return out
}
