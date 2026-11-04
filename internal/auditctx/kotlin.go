package auditctx

import (
	"regexp"
	"strings"
)

// kotlinAdapter is a bounded syntax reader, not a Kotlin compiler. It handles
// ordinary functions, primary constructors, objects, named arguments and import
// aliases. It does not infer overloads, extension dispatch, implicit receivers,
// wildcard imports or expression data flow. Unresolved references stay unresolved.
type kotlinAdapter struct{}

var kotlinPackage = regexp.MustCompile(`(?m)^\s*package\s+([\w.]+)`)
var kotlinImport = regexp.MustCompile(`(?m)^\s*import\s+([\w.]+)(?:\s+as\s+(\w+))?\s*;?\s*$`)

type kotlinToken struct {
	text       string
	start, end int
	line       int
}

func kotlinTokens(code string) ([]kotlinToken, map[int]int) {
	var tokens []kotlinToken
	line := 1
	for i := 0; i < len(code); {
		if code[i] <= ' ' {
			if code[i] == '\n' {
				line++
			}
			i++
			continue
		}
		start := i
		i++
		if kotlinIdentifier(code[start:i]) {
			for i < len(code) && (kotlinIdentifier(code[i:i+1]) || code[i] >= '0' && code[i] <= '9') {
				i++
			}
		}
		tokens = append(tokens, kotlinToken{code[start:i], start, i, line})
	}
	pairs := map[int]int{}
	var stack []int
	for i, t := range tokens {
		switch t.text {
		case "(", "[", "{":
			stack = append(stack, i)
		case ")", "]", "}":
			if len(stack) == 0 {
				continue
			}
			open := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if strings.Index("([{", tokens[open].text) == strings.Index(")]}", t.text) {
				pairs[open] = i
			}
		}
	}
	return tokens, pairs
}

func kotlinIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if r != '_' && !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(i > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// kotlinParts splits a balanced argument/parameter list. Angle brackets are
// supported in signatures only; generic call arguments are left unbound.
func kotlinParts(ts []kotlinToken, pairs map[int]int, open, close int, signature bool) ([][]kotlinToken, bool) {
	var parts [][]kotlinToken
	start, angle := open+1, 0
	for i := start; i < close; i++ {
		if end, ok := pairs[i]; ok {
			i = end
			continue
		}
		switch ts[i].text {
		case "<":
			if !signature {
				return nil, false
			}
			angle++
		case ">":
			if !signature || angle == 0 {
				return nil, false
			}
			angle--
		case ",":
			if angle == 0 {
				parts = append(parts, ts[start:i])
				start = i + 1
			}
		}
	}
	if angle != 0 {
		return nil, false
	}
	if start < close {
		parts = append(parts, ts[start:close])
	}
	return parts, true
}

func kotlinParameters(ts []kotlinToken, pairs map[int]int, open, close int) []parameter {
	parts, ok := kotlinParts(ts, pairs, open, close, true)
	if !ok {
		return nil
	}
	var params []parameter
	for _, part := range parts {
		var p parameter
		for i, t := range part {
			if t.text == "vararg" {
				return nil
			}
			if t.text == ":" && i > 0 && i+1 < len(part) && kotlinIdentifier(part[i-1].text) {
				p.name, p.typ = part[i-1].text, part[i+1].text
				break
			}
		}
		if p.name == "" {
			return nil
		}
		params = append(params, p)
	}
	return params
}

func (kotlinAdapter) parse(file, text string) *sourceInfo {
	code := maskSource(text, false)
	s := &sourceInfo{adapter: kotlinAdapter{}, language: language(file), code: strings.Split(code, "\n"), imports: map[string]string{}}
	if m := kotlinPackage.FindStringSubmatch(code); m != nil {
		s.packageName = m[1]
	}
	for _, m := range kotlinImport.FindAllStringSubmatch(code, -1) {
		name := m[2]
		if name == "" {
			name = m[1][strings.LastIndex(m[1], ".")+1:]
		}
		s.imports[name] = m[1]
	}
	ts, pairs := kotlinTokens(code)
	// Explicit lambdas introduce a new parameter scope. A spelling match in
	// their body cannot establish that the constructor/function parameter flows.
	for open, close := range pairs {
		if ts[open].text != "{" {
			continue
		}
		for i := open + 1; i < close; i++ {
			if end, ok := pairs[i]; ok {
				i = end
				continue
			}
			if ts[i].text == "-" && i+1 < close && ts[i+1].text == ">" {
				s.unbound = append(s.unbound, [2]int{ts[open].start, ts[close].end})
				break
			}
		}
	}
	declarations := map[int]bool{}
	for i, t := range ts {
		typ := t.text == "class" || t.text == "object" || t.text == "interface"
		if (!typ && t.text != "fun") || i+1 >= len(ts) || !kotlinIdentifier(ts[i+1].text) {
			continue
		}
		name, next := i+1, i+2
		if next < len(ts) && (ts[next].text == "." || ts[next].text == "<") {
			continue
		}
		d := Def{Name: ts[name].text, Type: typ, File: file, Line: t.line, End: ts[name].line}
		if next < len(ts) && ts[next].text == "(" {
			end, ok := pairs[next]
			if !ok {
				continue
			}
			declarations[next] = true
			d.params = kotlinParameters(ts, pairs, next, end)
			d.End, next = ts[end].line, end+1
		} else if !typ {
			continue
		}
		// Return type / supertype list, followed by a block or expression body.
		for j := next; j < len(ts); j++ {
			if ts[j].text == "{" {
				if end, ok := pairs[j]; ok {
					d.bodyStart, d.bodyEnd, d.End = ts[j].start, ts[end].end, ts[end].line
				}
				break
			}
			if ts[j].text == "=" && !typ {
				last := j
				for k := j + 1; k < len(ts); k++ {
					if ts[k].text == "}" || ts[k].text == ";" || (k > j+1 && ts[k].line > ts[last].line) {
						break
					}
					if end, ok := pairs[k]; ok {
						k = end
					}
					last = k
				}
				d.bodyStart, d.bodyEnd, d.End = ts[j].end, ts[last].end, ts[last].line
				break
			}
			if ts[j].text == "}" || ts[j].text == ";" || (ts[j].line > d.End && ts[j].text != ":") {
				break
			}
			if end, ok := pairs[j]; ok {
				j = end
			}
		}
		s.defs = append(s.defs, d)
	}
	// Attribute members to the narrowest enclosing type.
	for i := range s.defs {
		d := &s.defs[i]
		for j := 0; j < i; j++ {
			parent := s.defs[j]
			if parent.Type && parent.Line <= d.Line && parent.End >= d.End && parent.bodyEnd > 0 {
				d.owner = parent.Name
				if parent.owner != "" {
					d.owner = parent.owner + "." + d.owner
				}
			}
		}
	}
	for i, t := range ts {
		if t.text != "(" || i == 0 || declarations[i] || !kotlinIdentifier(ts[i-1].text) || keywords[ts[i-1].text] {
			continue
		}
		end, ok := pairs[i]
		if !ok {
			continue
		}
		ref := reference{name: ts[i-1].text, offset: ts[i-1].start}
		if i >= 3 && ts[i-2].text == "." {
			ref.qualifier = ts[i-3].text
			// Complex receiver expressions require type inference.
			if !kotlinIdentifier(ref.qualifier) || (i >= 4 && (ts[i-4].text == "." || ts[i-4].text == "?")) {
				continue
			}
		}
		c := call{reference: ref, start: ts[i-1].start, end: ts[end].end, line: ts[i-1].line}
		if parts, ok := kotlinParts(ts, pairs, i, end, false); ok {
			for _, part := range parts {
				if len(part) == 0 {
					c.args = nil
					break
				}
				a := argument{start: part[0].line, end: part[len(part)-1].line}
				if len(part) >= 3 && kotlinIdentifier(part[0].text) && part[1].text == "=" && part[2].text != "=" {
					a.name, part = part[0].text, part[2:]
				}
				if len(part) == 1 && kotlinIdentifier(part[0].text) {
					a.direct = part[0].text
				}
				c.args = append(c.args, a)
			}
		}
		s.calls = append(s.calls, c)
	}
	return s
}

func kotlinQualified(s *sourceInfo, d Def) string {
	name := d.Name
	if d.owner != "" {
		name = d.owner + "." + name
	}
	if s.packageName != "" {
		name = s.packageName + "." + name
	}
	return name
}

func (kotlinAdapter) resolve(ix *Index, file string, ref reference, typ bool) (Def, bool) {
	s := ix.sources[file]
	name, qualified := ref.name, ""
	ownerScope := ""
	for _, d := range s.defs {
		if d.Type && ref.offset >= d.bodyStart && ref.offset < d.bodyEnd {
			ownerScope = d.Name
			if d.owner != "" {
				ownerScope = d.owner + "." + d.Name
			}
		}
	}
	if ref.qualifier == "" {
		if imported, ok := s.imports[name]; ok {
			qualified, name = imported, imported[strings.LastIndex(imported, ".")+1:]
		}
	} else {
		owner := ref.qualifier
		for _, d := range s.defs {
			if ref.offset < d.bodyStart || ref.offset >= d.bodyEnd {
				continue
			}
			for _, p := range d.params {
				if p.name == ref.qualifier {
					owner = p.typ
				}
			}
		}
		if imported, ok := s.imports[owner]; ok {
			owner = imported
		} else if s.packageName != "" {
			owner = s.packageName + "." + owner
		}
		qualified = owner + "." + name
	}
	var matches []Def
	for _, d := range ix.candidates(file, name, typ) {
		if qualified != "" {
			if kotlinQualified(ix.sources[d.File], d) == qualified {
				matches = append(matches, d)
			}
		} else if ix.sources[d.File].packageName == s.packageName && (d.owner == "" || d.owner == ownerScope) {
			matches = append(matches, d)
		}
	}
	return onlyDefinition(matches)
}
