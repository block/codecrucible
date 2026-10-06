package decision

import "strings"

var pySyntax = &syntax{python: true, varKeywords: map[string]bool{}, containers: set("class")}

// pyLine is one logical line: an inclusive token range and its indentation.
type pyLine struct {
	s, e   int
	indent int
}

// pythonUnits scopes Python by logical lines and indentation. Decorators stay
// with their definition, and class members become units under the class.
func pythonUnits(path, content string) ([]*sourceUnit, bool) {
	lx := newLexer(content, pySyntax)
	lines, ok := lx.pythonLines()
	if !ok || len(lines) == 0 || !pyIndentation(lines, lx.toks) {
		return nil, false
	}
	py := &pyParser{p: &braceParser{toks: lx.toks, lang: pySyntax}, lines: lines}
	if end, ok := py.block(0, 0, nil); !ok || end != len(lines) {
		return nil, false
	}
	return finishUnits(path, py.p.units, lx.comments, lx.code)
}

func (lx *lexer) pythonLines() ([]pyLine, bool) {
	var lines []pyLine
	depth, first := 0, 0
	flush := func() {
		if len(lx.toks) > first {
			lines = append(lines, pyLine{first, len(lx.toks) - 1, lx.toks[first].col})
			first = len(lx.toks)
		}
	}
	for lx.i < len(lx.src) {
		c := lx.src[lx.i]
		switch {
		case c == '\n':
			lx.advance()
			if depth == 0 {
				flush()
			}
		case c == ' ' || c == '\t' || c == '\r' || c == '\f':
			lx.advance()
		case c == '\\' && lx.peek(1) == '\n':
			lx.advanceN(2)
		case c == '\\' && lx.peek(1) == '\r' && lx.peek(2) == '\n':
			lx.advanceN(3)
		case c == '#':
			lx.lineComment()
		case c == '"' || c == '\'':
			if !lx.pyString(0) {
				return nil, false
			}
		case isIdentStart(c):
			j := lx.i
			for j < len(lx.src) && isIdentChar(lx.src[j]) {
				j++
			}
			if j < len(lx.src) && (lx.src[j] == '"' || lx.src[j] == '\'') && pyStringPrefix(lx.src[lx.i:j]) {
				if !lx.pyString(j - lx.i) {
					return nil, false
				}
				continue
			}
			lx.ident()
		case c >= '0' && c <= '9':
			lx.number()
		default:
			lx.punct()
			switch lx.toks[len(lx.toks)-1].text {
			case "(", "[", "{":
				depth++
			case ")", "]", "}":
				if depth--; depth < 0 {
					return nil, false
				}
			}
		}
	}
	if depth != 0 {
		return nil, false
	}
	flush()
	return lines, true
}

// pyIndentation applies Python's indentation rules: blocks open only after a
// colon, and each dedent returns to an enclosing level.
func pyIndentation(lines []pyLine, toks []lexToken) bool {
	levels := []int{0}
	for i, line := range lines {
		top := levels[len(levels)-1]
		opened := i > 0 && toks[lines[i-1].e].text == ":" && toks[lines[i-1].e].kind == 'p'
		switch {
		case opened && line.indent > top:
			levels = append(levels, line.indent)
		case opened || line.indent > top:
			return false
		default:
			for line.indent < levels[len(levels)-1] {
				levels = levels[:len(levels)-1]
			}
			if line.indent != levels[len(levels)-1] {
				return false
			}
		}
	}
	return true
}

func pyStringPrefix(prefix string) bool {
	if len(prefix) > 2 {
		return false
	}
	for _, c := range strings.ToLower(prefix) {
		if !strings.ContainsRune("rbuft", c) {
			return false
		}
	}
	return true
}

// pyString scans a string literal whose prefix has n bytes.
func (lx *lexer) pyString(n int) bool {
	start, line, col := lx.i, lx.line, lx.i-lx.lineStart
	formatted := strings.ContainsAny(strings.ToLower(lx.src[lx.i:lx.i+n]), "ft")
	lx.advanceN(n)
	if !lx.pyStringBody(formatted) {
		return false
	}
	lx.emit('s', "", start, line, col)
	return true
}

// pyStringBody consumes a quoted string starting at its opening quote.
func (lx *lexer) pyStringBody(formatted bool) bool {
	q := lx.src[lx.i]
	closing := string(q)
	if strings.HasPrefix(lx.src[lx.i:], strings.Repeat(closing, 3)) {
		closing = strings.Repeat(closing, 3)
	}
	lx.advanceN(len(closing))
	for lx.i < len(lx.src) {
		c := lx.src[lx.i]
		switch {
		case c == '\\':
			lx.advanceN(2)
		case strings.HasPrefix(lx.src[lx.i:], closing):
			lx.advanceN(len(closing))
			return true
		case c == '\n' && len(closing) == 1:
			return false
		case formatted && c == '{' && lx.peek(1) == '{':
			lx.advanceN(2)
		case formatted && c == '{':
			lx.advance()
			if !lx.pyReplacement() {
				return false
			}
		default:
			lx.advance()
		}
	}
	return false
}

// pyReplacement skips an f-string replacement field, including nested strings.
func (lx *lexer) pyReplacement() bool {
	depth := 1
	start := lx.i
	for lx.i < len(lx.src) {
		switch c := lx.src[lx.i]; c {
		case '"', '\'':
			if !lx.pyStringBody(false) {
				return false
			}
		case '{', '(', '[':
			depth++
			lx.advance()
		case '}', ')', ']':
			depth--
			lx.advance()
			if depth == 0 {
				lx.interp = append(lx.interp, interpolatedWords(lx.src[start:lx.i-1])...)
				return true
			}
		default:
			lx.advance()
		}
	}
	return false
}

type pyParser struct {
	p     *braceParser
	lines []pyLine
}

func (py *pyParser) first(l int) lexToken { return py.p.toks[py.lines[l].s] }

// keyword returns a line's leading keyword, skipping async.
func (py *pyParser) keyword(l int) string {
	line := py.lines[l]
	if py.p.is(line.s, "async") && line.s < line.e {
		return py.p.toks[line.s+1].text
	}
	return py.p.toks[line.s].text
}

// suite returns the last line of the indented block opened by line l, or l for
// simple statements and one-line compound statements.
func (py *pyParser) suite(l int) (int, bool) {
	if !py.p.is(py.lines[l].e, ":") {
		return l, true
	}
	indent := py.lines[l].indent
	if l+1 >= len(py.lines) || py.lines[l+1].indent <= indent {
		return 0, false
	}
	end := l + 1
	for end+1 < len(py.lines) && py.lines[end+1].indent > indent {
		end++
	}
	return end, true
}

var pyClauses = set("elif", "else", "except", "finally")

// block parses sibling statements at indent and returns the first line after.
func (py *pyParser) block(l, indent int, parent *sourceUnit) (int, bool) {
	for l < len(py.lines) {
		switch ind := py.lines[l].indent; {
		case ind < indent:
			return l, true
		case ind > indent:
			return 0, false
		}
		start := l
		for l < len(py.lines) && py.p.is(py.lines[l].s, "@") && py.lines[l].indent == indent {
			l++
		}
		if l >= len(py.lines) || py.lines[l].indent != indent {
			return 0, false
		}
		kw := py.keyword(l)
		if l > start && kw != "def" && kw != "class" {
			return 0, false
		}
		head := l
		end, ok := py.suite(head)
		if !ok {
			return 0, false
		}
		l = end + 1
		if kw == "class" && end > head {
			u := py.p.addUnit(py.lines[start].s, py.lines[head].e, parent)
			u.container = true
			py.describe(u, start, head, true)
			next, ok := py.block(head+1, py.lines[head+1].indent, u)
			if !ok || next != l {
				return 0, false
			}
			continue
		}
		for kw != "def" && kw != "class" && l < len(py.lines) && py.lines[l].indent == indent && pyClauses[py.first(l).text] {
			if end, ok = py.suite(l); !ok {
				return 0, false
			}
			l = end + 1
		}
		py.describe(py.p.addUnit(py.lines[start].s, py.lines[end].e, parent), start, end, false)
	}
	return l, true
}

var pyClauseLines = set("try", "except", "else", "finally", "if", "elif", "pass")

func (py *pyParser) describe(u *sourceUnit, a, b int, container bool) {
	p := py.p
	s, e := py.lines[a].s, py.lines[b].e
	p.identsInto(u.refs, s, e)
	header := true
	for l := a; l <= b; l++ {
		ls, le := py.lines[l].s, py.lines[l].e
		if p.is(ls, "@") {
			p.attributes(u, ls, le)
		}
		if !container {
			p.controlsFrom(u, ls, le)
		}
		for i := ls; i <= le; i++ {
			t := p.toks[i]
			u.guard = u.guard || p.registersGuard(i, ls)
			if t.kind == 'i' && (t.text == "lambda" || (p.is(i+1, "(") && !controlWords[t.text])) {
				u.function = true
			}
		}
		kw := py.keyword(l)
		if kw != "import" && kw != "from" && !pyClauseLines[kw] {
			header = false
		}
	}
	head := a
	for head < b && p.is(py.lines[head].s, "@") {
		head++
	}
	switch kw := py.keyword(head); kw {
	case "def", "class":
		u.function = kw == "def"
		for i := py.lines[head].s; i < py.lines[head].e; i++ {
			if p.is(i, kw) && p.toks[i+1].kind == 'i' {
				u.names[p.toks[i+1].text] = true
				break
			}
		}
		return
	case "import", "from":
		u.header = true
		return
	case "if", "try", "with", "for", "while":
		// Conditional imports and definitions still name module-level symbols.
		u.header = header
		for l := head; l <= b; l++ {
			switch py.keyword(l) {
			case "def", "class":
				for i := py.lines[l].s; i < py.lines[l].e; i++ {
					if (p.is(i, "def") || p.is(i, "class")) && p.toks[i+1].kind == 'i' {
						u.names[p.toks[i+1].text] = true
						break
					}
				}
			default:
				py.targets(u, l)
			}
		}
		return
	}
	py.targets(u, head)
}

// targets names assignment and annotation targets: a, b = ...; x: int = ...
func (py *pyParser) targets(u *sourceUnit, l int) {
	p := py.p
	line := py.lines[l]
	end := -1
	depth := 0
	for i := line.s; i <= line.e; i++ {
		switch p.toks[i].text {
		case "(", "[", "{":
			depth++
		case ")", "]", "}":
			depth--
		case "=", ":":
			if depth == 0 && p.toks[i].kind == 'p' && end < 0 {
				end = i
			}
		}
	}
	if end < 0 || p.is(line.e, ":") && p.is(end, ":") {
		return
	}
	for i := line.s; i < end; i++ {
		t := p.toks[i]
		if t.kind == 'i' && !p.is(i-1, ".") && !p.is(i+1, ".") && !p.is(i+1, "[") && !p.is(i+1, "(") {
			u.names[t.text] = true
		}
	}
}
