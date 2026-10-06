package decision

import (
	"path/filepath"
	"sort"
	"strings"
)

func set(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}

var (
	jsSyntax = &syntax{quoteStrings: true, templates: true, regex: true, newlineEnds: true,
		containers: set("class", "interface", "enum", "namespace", "module"), varKeywords: set("const", "let", "var")}
	javaSyntax = &syntax{tripleQuotes: true, tripleEscapes: true,
		containers: set("class", "interface", "enum", "record")}
	kotlinSyntax = &syntax{nestedComments: true, tripleQuotes: true, dollarInterp: true, backtickIdents: true, newlineEnds: true,
		containers: set("class", "interface", "object"), varKeywords: set("val", "var")}
	scalaSyntax = &syntax{nestedComments: true, tripleQuotes: true, dollarInterp: true, backtickIdents: true, lifetimes: true, newlineEnds: true, scala: true,
		containers: set("class", "trait", "object", "enum"), varKeywords: set("val", "var")}
	swiftSyntax = &syntax{nestedComments: true, tripleQuotes: true, tripleEscapes: true, swiftInterp: true, backtickIdents: true, newlineEnds: true,
		containers: set("class", "struct", "enum", "protocol", "extension", "actor"), varKeywords: set("let", "var")}
	csharpSyntax = &syntax{hashDirectives: true, csharpStrings: true, tripleQuotes: true,
		containers: set("class", "struct", "interface", "enum", "record", "namespace")}
	rustSyntax = &syntax{nestedComments: true, lifetimes: true, rustStrings: true, multilineStr: true,
		containers: set("impl", "trait", "mod", "struct", "enum", "union"), varKeywords: set("let", "const", "static")}
	phpSyntax = &syntax{hashComments: true, php: true, quoteStrings: true, multilineStr: true,
		containers: set("class", "interface", "trait", "enum", "namespace"), varKeywords: set("const")}
	cSyntax   = &syntax{hashDirectives: true, cLike: true, containers: set("struct", "union", "enum", "extern")}
	cppSyntax = &syntax{hashDirectives: true, cLike: true, cppRaw: true, digitQuotes: true,
		containers: set("class", "struct", "union", "namespace", "enum", "extern")}
)

var braceLanguages = map[string]*syntax{
	".js": jsSyntax, ".jsx": jsSyntax, ".mjs": jsSyntax, ".cjs": jsSyntax,
	".ts": jsSyntax, ".tsx": jsSyntax, ".mts": jsSyntax, ".cts": jsSyntax,
	".java": javaSyntax, ".kt": kotlinSyntax, ".kts": kotlinSyntax, ".scala": scalaSyntax,
	".swift": swiftSyntax, ".cs": csharpSyntax, ".rs": rustSyntax, ".php": phpSyntax,
	".c": cSyntax, ".h": cppSyntax, ".cc": cppSyntax, ".cpp": cppSyntax, ".cxx": cppSyntax,
	".hpp": cppSyntax, ".hh": cppSyntax,
}

// Words that can precede '(' without naming a declaration.
var controlWords = set("if", "else", "for", "foreach", "while", "switch", "catch", "return", "function",
	"fun", "fn", "def", "func", "new", "typeof", "sizeof", "await", "yield", "throw", "do", "with",
	"lock", "using", "when", "match", "synchronized", "elif", "assert", "super", "this", "self",
	"and", "or", "not", "in", "is", "as", "lambda", "defer", "go", "try", "except", "raise", "del",
	"unless", "until", "guard", "case", "default", "static_assert", "decltype", "typeid", "alignof",
	"noexcept", "isset", "unset")

var funcKeywords = set("function", "fun", "fn", "def", "func")

var modifiers = set("export", "default", "public", "private", "protected", "internal", "static",
	"final", "abstract", "open", "override", "async", "suspend", "inline", "data", "sealed",
	"readonly", "declare", "partial", "virtual", "lateinit", "inner", "annotation", "operator",
	"infix", "tailrec", "external", "fileprivate", "mutating", "nonmutating", "convenience",
	"required", "dynamic", "lazy", "weak", "unowned", "implicit", "case", "pub", "unsafe",
	"extern", "const", "volatile", "constexpr", "inline", "friend", "explicit", "noinline",
	"crossinline", "reified", "value", "actual", "expect", "sync", "native", "transient",
	"strictfp", "synchronized", "new", "sealed", "global")

// Calls whose arguments configure guards for later handlers.
var middlewareCalls = set("use", "Use", "With", "UseMiddleware", "middleware", "before_action",
	"before_filter", "prepend_before_action", "addFilter", "addFilterBefore", "addFilterAfter",
	"addInterceptor", "addInterceptors", "UseAuthentication", "UseAuthorization",
	"RequireAuthorization", "authorizeRequests", "authorizeHttpRequests", "securityMatcher",
	"UseGuards", "UseInterceptors", "before_request", "before_app_request", "Depends", "Security",
	"login_required", "permission_required", "user_passes_test", "staff_member_required")

// Route registrations whose middle arguments are per-route middleware.
var routeCalls = set("get", "post", "put", "patch", "delete", "del", "all", "head", "options",
	"route", "any", "Get", "Post", "Put", "Patch", "Delete", "Any", "Handle", "HandleFunc",
	"MapGet", "MapPost", "MapPut", "MapDelete", "add_url_rule", "add_api_route")

// structuralUnits returns declaration-level units for languages without a Go
// parser. It understands strings, comments, and brackets only; anything it
// cannot tokenize or balance returns false so callers keep whole-file evidence.
func structuralUnits(path, content string) (units []*sourceUnit, ok bool) {
	defer func() {
		if recover() != nil {
			units, ok = nil, false // malformed input must never fail the scan
		}
	}()
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".py" {
		return pythonUnits(path, content)
	}
	lang, ok := braceLanguages[ext]
	if !ok {
		return nil, false
	}
	if lang.scala && scala3Braceless(content) {
		return nil, false
	}
	lx := newLexer(content, lang)
	if !lx.run() || len(lx.toks) == 0 {
		return nil, false
	}
	p := &braceParser{toks: lx.toks, lang: lang}
	if _, ok := p.members(0, false, nil); !ok {
		return nil, false
	}
	return finishUnits(path, p.units, lx.comments, lx.code)
}

// Scala 3 significant indentation cannot be scoped with bracket structure.
func scala3Braceless(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "end ") {
			return true
		}
		for _, kw := range []string{"object ", "class ", "trait ", "enum ", "given ", "extension "} {
			if strings.Contains(" "+trimmed, " "+kw) && strings.HasSuffix(trimmed, ":") {
				return true
			}
		}
	}
	return false
}

type braceParser struct {
	toks  []lexToken
	lang  *syntax
	units []*sourceUnit
}

func (p *braceParser) is(i int, text string) bool {
	return i >= 0 && i < len(p.toks) && p.toks[i].text == text && p.toks[i].kind != 's'
}

// members parses statements until the brace closing the current container
// (nested) or EOF. It returns the index of the closing brace.
func (p *braceParser) members(i int, nested bool, parent *sourceUnit) (int, bool) {
	column := -1
	for i < len(p.toks) {
		if p.is(i, "}") {
			return i, nested
		}
		if p.is(i, ";") {
			i++
			continue
		}
		end, open, ok := p.statement(i)
		if !ok {
			return 0, false
		}
		// Newline-terminated languages place sibling statements at one indent;
		// a deeper start means a continuation was misread.
		if p.lang.newlineEnds {
			if column < 0 {
				column = p.toks[i].col
			} else if p.toks[i].col != column {
				return 0, false
			}
		}
		if open < 0 {
			p.describe(p.addUnit(i, end, parent), i, end)
			i = end + 1
			continue
		}
		header := p.addUnit(i, open, parent)
		header.container = true
		p.describeContainer(header, i, open)
		close, ok := p.members(open+1, true, header)
		if !ok {
			return 0, false
		}
		i = close + 1
		if p.is(i, ";") && p.toks[i].line == p.toks[close].line {
			i++
		}
	}
	return len(p.toks), !nested
}

func (p *braceParser) addUnit(s, e int, parent *sourceUnit) *sourceUnit {
	u := &sourceUnit{SourceRange: SourceRange{Start: p.toks[s].line, End: p.toks[e].end},
		names: map[string]bool{}, refs: map[string]bool{}, controls: map[string]bool{}, parent: parent}
	u.codeStart = u.Start
	p.units = append(p.units, u)
	return u
}

var closers = map[string]string{")": "(", "]": "[", "}": "{"}

// statement returns the last token of the statement starting at s. If the
// statement opens a member container, open is the index of its '{'.
func (p *braceParser) statement(s int) (end, open int, ok bool) {
	var stack []string
	doStmt := p.is(s, "do")
	for j := s; j < len(p.toks); j++ {
		t := p.toks[j]
		if len(stack) == 0 && j > s && p.lang.newlineEnds && t.line > p.toks[j-1].end && p.endsAtNewline(s, j) {
			return j - 1, -1, true
		}
		if t.kind == 's' {
			continue
		}
		switch t.text {
		case "(", "[":
			stack = append(stack, t.text)
		case "{":
			if len(stack) == 0 && p.isContainer(s, j) >= 0 {
				close, ok := p.match(j)
				if !ok {
					return 0, 0, false
				}
				// A declarator after the body (typedef struct s {...} s_t;)
				// makes the braces part of one declaration.
				declarator := close+1 < len(p.toks) && p.toks[close+1].line == p.toks[close].end && !p.is(close+1, ";")
				if p.descend(j, close) && !declarator {
					return close, j, true
				}
			}
			stack = append(stack, "{")
		case ")", "]", "}":
			if len(stack) == 0 {
				if t.text == "}" && j > s {
					return j - 1, -1, true
				}
				return 0, 0, false
			}
			if stack[len(stack)-1] != closers[t.text] {
				return 0, 0, false
			}
			stack = stack[:len(stack)-1]
			if t.text == "}" && len(stack) == 0 {
				if j+1 >= len(p.toks) {
					return j, -1, true
				}
				if p.is(j+1, ";") {
					return j + 1, -1, true
				}
				if p.continues(t, p.toks[j+1], doStmt) {
					continue
				}
				return j, -1, true
			}
		case ";":
			if len(stack) == 0 {
				return j, -1, true
			}
		}
	}
	if len(stack) != 0 {
		return 0, 0, false
	}
	return len(p.toks) - 1, -1, true
}

func (p *braceParser) match(open int) (int, bool) {
	var stack []string
	for j := open; j < len(p.toks); j++ {
		t := p.toks[j]
		if t.kind == 's' {
			continue
		}
		switch t.text {
		case "(", "[", "{":
			stack = append(stack, t.text)
		case ")", "]", "}":
			if len(stack) == 0 || stack[len(stack)-1] != closers[t.text] {
				return 0, false
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return j, true
			}
		}
	}
	return 0, false
}

// descend reports whether a container body has members on their own lines.
// Compact one-line containers stay a single unit.
func (p *braceParser) descend(open, close int) bool {
	return close > open+1 && p.toks[open+1].line > p.toks[open].line && p.toks[close].line > p.toks[close-1].end
}

var continuationWords = set("else", "catch", "finally", "extends", "implements", "where", "as", "instanceof", "in", "of")

// continues reports whether a statement goes on after a closing brace.
func (p *braceParser) continues(close, next lexToken, doStmt bool) bool {
	if next.kind == 's' {
		return next.line == close.end
	}
	if next.line == close.end {
		return next.text != "}"
	}
	if next.kind == 'i' {
		return continuationWords[next.text] || (doStmt && next.text == "while")
	}
	switch next.text {
	case ".", "?.", ")", "]", ",", "=>", "->", ":", "?", "=", "&&", "||", "??", "+", "*", "|", "&":
		return true
	}
	return false
}

var lineEndContinues = set("extends", "implements", "new", "else", "export", "default", "async",
	"import", "from", "class", "fun", "function", "def", "val", "var", "let", "const", "private",
	"public", "protected", "internal", "static", "override", "open", "abstract", "final", "suspend",
	"inline", "data", "sealed", "readonly", "declare", "throws", "where", "is", "as", "return", "typealias", "type")

var lineStartContinues = set(".", "?.", ")", "]", ",", "=>", "->", "?", ":", "=", "==", "===", "!=",
	"!==", "&&", "||", "??", "+", "*", "/", "%", "|", "&", "^", "<", ">", "<=", ">=", "+=", "-=",
	"*=", "/=", "{")

// endsAtNewline decides automatic statement termination between j-1 and j.
func (p *braceParser) endsAtNewline(s, j int) bool {
	prev, next := p.toks[j-1], p.toks[j]
	if prev.kind == 'p' {
		switch prev.text {
		case ")", "]", "}", ";", "++", "--", "!", ">":
		case "*":
			if !p.is(s, "import") {
				return false
			}
		case "?":
			if p.lang.regex {
				return false // JavaScript ternary
			}
		default:
			return false
		}
	}
	if prev.kind == 'i' && lineEndContinues[prev.text] {
		return false
	}
	if p.annotationOnly(s, j) {
		return false
	}
	if next.kind == 'p' && lineStartContinues[next.text] {
		return false
	}
	if next.kind == 'i' && continuationWords[next.text] {
		return false
	}
	if next.kind == 'i' && (next.text == "get" || next.text == "set") && (p.is(j+1, "(") || p.is(j+1, "=") || p.is(j+1, "{")) {
		return false // Kotlin property accessor
	}
	return true
}

// annotationOnly reports whether tokens s..j-1 are only annotations/modifiers.
func (p *braceParser) annotationOnly(s, j int) bool {
	for k := s; k < j; {
		t := p.toks[k]
		switch {
		case p.is(k, "@"):
			k++
			if k >= j || p.toks[k].kind != 'i' {
				return false
			}
			k++
			for k+1 < j && p.is(k, ".") && p.toks[k+1].kind == 'i' {
				k += 2
			}
			if p.is(k, "(") {
				m, ok := p.match(k)
				if !ok || m >= j {
					return false
				}
				k = m + 1
			}
		case t.kind == 'i' && modifiers[t.text]:
			k++
		default:
			return false
		}
	}
	return true
}

// isContainer returns the keyword index if tokens s..open-1 declare a type,
// namespace, or module whose body holds independent members.
func (p *braceParser) isContainer(s, open int) int {
	depth := 0
	first := -1
	for k := s; k < open; k++ {
		t := p.toks[k]
		if t.kind == 's' {
			continue
		}
		switch t.text {
		case "(", "[":
			depth++
			continue
		case ")", "]":
			depth--
			continue
		}
		if depth != 0 || t.kind != 'i' {
			continue
		}
		if first < 0 && !modifiers[t.text] && !p.is(k-1, "@") {
			first = k
		}
		if !p.lang.containers[t.text] || p.is(k-1, ".") || p.is(k-1, "::") || p.is(k-1, "?.") || !p.plainHeader(k, open) {
			continue
		}
		next := p.toks[k+1]
		switch {
		case (t.text == "module" || t.text == "namespace") && k != first:
		case next.kind == 'i' && !p.lang.containers[next.text] && !funcKeywords[next.text] && !controlWords[next.text] &&
			next.text != "var" && next.text != "let" && next.text != "val":
			return k
		case next.kind == 's' && (t.text == "module" || t.text == "namespace" || t.text == "extern"):
			return k
		case t.text == "impl" && next.text == "<":
			return k
		}
	}
	return -1
}

// plainHeader rejects initializers and C functions returning struct types,
// whose braces hold statements rather than members.
func (p *braceParser) plainHeader(k, open int) bool {
	depth := 0
	for i := k + 1; i < open; i++ {
		switch p.toks[i].text {
		case "(":
			if p.lang.cLike {
				return false
			}
			depth++
		case "[":
			depth++
		case ")", "]":
			depth--
		case "=":
			if depth == 0 {
				return false
			}
		}
	}
	return true
}

func (p *braceParser) describeContainer(u *sourceUnit, s, open int) {
	k := p.isContainer(s, open)
	p.identsInto(u.refs, s, open-1)
	p.attributes(u, s, open)
	if p.toks[k].text == "impl" {
		// impl<T> Trait for Type: the implemented type names the block.
		name, depth := "", 0
		for i := k + 1; i < open; i++ {
			switch p.toks[i].text {
			case "<":
				depth++
			case ">":
				depth--
			}
			if p.toks[i].text == "where" {
				break
			}
			if depth == 0 && p.toks[i].kind == 'i' && p.toks[i].text != "for" && p.toks[i].text != "dyn" {
				name = p.toks[i].text
			}
		}
		if name != "" {
			u.names[name] = true
		}
		return
	}
	if p.toks[k+1].kind == 'i' {
		u.names[p.toks[k+1].text] = true
	}
}

// attributes adds decorator, annotation, and attribute identifiers to controls.
func (p *braceParser) attributes(u *sourceUnit, s, e int) {
	for k := s; k < e; k++ {
		var start int
		switch {
		case p.is(k, "@") && k+1 < e && p.toks[k+1].kind == 'i':
			start = k + 1
		case p.is(k, "[") && !p.lang.python && (k == s || p.is(k-1, "]") || p.is(k-1, "#")):
			start = k
		default:
			continue
		}
		end := start
		if p.is(start, "[") {
			end, _ = p.match(start)
		} else {
			for end+2 < len(p.toks) && p.is(end+1, ".") && p.toks[end+2].kind == 'i' {
				end += 2
			}
			if p.is(end+1, "(") {
				end, _ = p.match(end + 1)
			}
		}
		u.annotated = true
		p.identsInto(u.controls, start, min(end, len(p.toks)-1))
		if end > k {
			k = end
		}
	}
}

func (p *braceParser) describe(u *sourceUnit, s, e int) {
	p.identsInto(u.refs, s, e)
	p.attributes(u, s, e)
	p.controlsFrom(u, s, e)

	first := s
	for first <= e && (p.toks[first].kind == 'i' && modifiers[p.toks[first].text] || p.is(first, "@") || p.is(first, "#") || p.is(first, "[")) {
		switch {
		case p.is(first, "@"):
			first += 2
			for p.is(first, ".") {
				first += 2
			}
			if p.is(first, "(") {
				m, ok := p.match(first)
				if !ok {
					return
				}
				first = m + 1
			}
		case p.is(first, "#") || p.is(first, "["):
			if p.is(first, "#") {
				first++
			}
			m, ok := p.match(first)
			if !ok {
				return
			}
			first = m + 1
		default:
			first++
		}
	}
	if first > e {
		return
	}
	lead := p.toks[first]
	switch lead.text {
	case "import", "package":
		u.header = true
		return
	case "using", "use":
		if !p.is(first+1, "(") && !p.is(first+1, "var") {
			u.header = true
			return
		}
	case "namespace":
		u.header = true
		return
	case "export":
		for i := first; i <= e; i++ {
			if p.toks[i].text == "from" && i+1 <= e && p.toks[i+1].kind == 's' {
				u.header = true
				return
			}
		}
	}
	if lead.text == "extern" && p.is(first+1, "crate") {
		u.header = true
		return
	}

	// Depth-0 positions of the statement, ignoring bracketed groups.
	var top []int
	depth := 0
	for i := s; i <= e; i++ {
		t := p.toks[i]
		if t.kind != 's' {
			switch t.text {
			case "(", "[", "{":
				if depth == 0 {
					top = append(top, i)
				}
				depth++
				continue
			case ")", "]", "}":
				depth--
				continue
			}
		}
		if depth == 0 {
			top = append(top, i)
		}
	}

	for idx, i := range top {
		t := p.toks[i]
		if t.kind != 'i' {
			continue
		}
		switch {
		case funcKeywords[t.text]:
			u.function = true
			if name := p.nameBeforeParen(i, e); name != "" {
				u.names[name] = true
			} else if idx+1 < len(top) && p.toks[top[idx+1]].kind == 'i' {
				u.names[p.toks[top[idx+1]].text] = true
			}
		case p.lang.varKeywords[t.text] && i == top[0] || p.lang.varKeywords[t.text] && idx > 0 && modifiers[p.toks[top[idx-1]].text]:
			next := i + 1
			if p.is(next, "mut") {
				next++
			}
			if next <= e && p.toks[next].kind == 'i' {
				u.names[p.toks[next].text] = true
			} else if p.is(next, "{") || p.is(next, "[") || p.is(next, "(") {
				if m, ok := p.match(next); ok {
					for k := next; k <= m; k++ {
						if p.toks[k].kind == 'i' {
							u.names[p.toks[k].text] = true
						}
					}
				}
			}
		case (t.text == "type" || t.text == "typealias") && i == first && idx+1 < len(top) && p.toks[top[idx+1]].kind == 'i':
			u.names[p.toks[top[idx+1]].text] = true
		case t.text == "macro_rules" && p.is(i+1, "!") && i+2 <= e && p.toks[i+2].kind == 'i':
			u.names[p.toks[i+2].text] = true
		}
	}

	// name(...) followed by a body or declaration terminator. Annotation
	// arguments precede the name; an initializer call follows '='.
	declared := false
	for idx, i := range top {
		if p.is(i, "=") {
			break
		}
		if !p.is(i, "(") || idx == 0 || i < first {
			continue
		}
		nameAt := top[idx-1]
		if p.is(nameAt, ">") {
			nameAt = p.genericStart(nameAt, s)
		}
		if nameAt < s || p.toks[nameAt].kind != 'i' || controlWords[p.toks[nameAt].text] {
			break
		}
		before := nameAt - 1
		if before >= s && (p.is(before, ".") || p.is(before, "?.") || p.is(before, "new") || (p.is(before, "::") && !p.lang.cLike)) {
			break
		}
		close, ok := p.match(i)
		if !ok {
			break
		}
		if p.declarationBody(close, e, u.parent != nil) {
			u.names[p.toks[nameAt].text] = true
			u.function = true
			declared = true
		}
		break
	}
	// A compact or body-less type declaration, not a function returning one.
	if !declared {
		for _, i := range top {
			if p.lang.containers[p.toks[i].text] && p.toks[i].kind == 'i' && i+1 <= e && p.toks[i+1].kind == 'i' && !p.is(i-1, ".") {
				u.names[p.toks[i+1].text] = true
				break
			}
		}
	}

	// Assignment: the identifier immediately before the first depth-0 '='.
	for idx, i := range top {
		if p.is(i, "=") && idx > 0 && p.toks[top[idx-1]].kind == 'i' {
			u.names[p.toks[top[idx-1]].text] = true
			break
		}
	}

	if u.parent != nil {
		p.memberNames(u, top, e)
	}

	for idx, i := range top {
		if p.is(i, "=>") || p.is(i, "->") {
			u.function = true
		}
		if p.is(i, "(") && idx > 0 && p.toks[top[idx-1]].kind == 'i' && !controlWords[p.toks[top[idx-1]].text] {
			u.function = true // executable statement: calls, registrations
		}
	}
	for i := s; i <= e; i++ {
		u.guard = u.guard || p.registersGuard(i, s)
	}
}

// registersGuard reports a middleware registration on a router or app object,
// such as app.use(auth). Decorators on one handler are not file-wide guards.
func (p *braceParser) registersGuard(i, s int) bool {
	if p.toks[i].kind != 'i' || !middlewareCalls[p.toks[i].text] {
		return false
	}
	return p.is(i-1, ".") || p.is(i-1, "::") || p.is(i-1, "->") || (i == s && p.is(i+1, "("))
}

// memberNames names fields and properties inside type bodies.
func (p *braceParser) memberNames(u *sourceUnit, top []int, e int) {
	hasParen := false
	for _, i := range top {
		if p.is(i, "(") {
			hasParen = true
		}
		if p.is(i, "{") && !hasParen && p.lang.csharpStrings {
			if prev := i - 1; prev >= 0 && p.toks[prev].kind == 'i' {
				u.names[p.toks[prev].text] = true // C# property
			}
		}
	}
	for idx, i := range top {
		if p.is(i, ":") && idx > 1 && (p.is(top[idx-1], "?") || p.is(top[idx-1], "!")) {
			idx-- // TypeScript optional and definite members: name?: T
		}
		if p.is(i, ":") && idx > 0 && p.toks[top[idx-1]].kind == 'i' {
			before := idx - 2
			if before < 0 || p.is(top[before], ",") || modifiers[p.toks[top[before]].text] || p.lang.varKeywords[p.toks[top[before]].text] {
				u.names[p.toks[top[idx-1]].text] = true
			}
		}
	}
	if !hasParen && len(top) > 1 {
		last := len(top) - 1
		for last > 0 && (p.is(top[last], ";") || p.is(top[last], "[")) {
			last-- // char buf[256];
		}
		if last := top[last]; p.toks[last].kind == 'i' && len(u.names) == 0 {
			u.names[p.toks[last].text] = true // Java/C#/C field without initializer
		}
	}
}

func (p *braceParser) genericStart(close, s int) int {
	depth := 0
	for k := close; k >= s; k-- {
		switch p.toks[k].text {
		case ">":
			depth++
		case "<":
			depth--
			if depth == 0 {
				return k - 1
			}
		}
	}
	return -1
}

// nameBeforeParen returns the identifier immediately before the first '(' after
// a function keyword, skipping generic parameters and receivers.
func (p *braceParser) nameBeforeParen(kw, e int) string {
	depth := 0
	for k := kw + 1; k <= e; k++ {
		switch p.toks[k].text {
		case "<":
			depth++
		case ">":
			depth--
		case "(":
			if depth > 0 {
				continue
			}
			at := k - 1
			if p.is(at, ">") {
				at = p.genericStart(at, kw)
			}
			if at > kw && p.toks[at].kind == 'i' {
				return p.toks[at].text
			}
			return ""
		case "{", "=", ";":
			return ""
		}
	}
	return ""
}

// declarationBody reports whether a parameter list closing at close is followed
// by a body or, inside a type, by an abstract declaration terminator.
func (p *braceParser) declarationBody(close, e int, member bool) bool {
	for k := close + 1; k <= e; k++ {
		t := p.toks[k]
		if t.kind == 's' {
			continue
		}
		switch t.text {
		case "{", "=>":
			return true
		case "=":
			return p.lang.newlineEnds && !p.lang.regex // Kotlin/Scala/Swift expression bodies
		case ";":
			return member || p.lang.cLike
		case "(", ".", "?.", ",":
			return false
		}
	}
	return member && p.lang.newlineEnds
}

// controlsFrom records identifiers that decide whether code runs: conditions,
// middleware registrations, and per-route middleware arguments.
func (p *braceParser) controlsFrom(u *sourceUnit, s, e int) {
	for k := s; k <= e; k++ {
		t := p.toks[k]
		if t.kind != 'i' {
			continue
		}
		switch {
		case t.text == "if" || t.text == "elif" || t.text == "unless" || t.text == "guard":
			if p.is(k+1, "(") {
				if m, ok := p.match(k + 1); ok {
					p.identsInto(u.controls, k+1, m)
				}
				continue
			}
			for i := k + 1; i <= e && !p.is(i, "{"); i++ {
				p.identsInto(u.controls, i, i)
			}
		case middlewareCalls[t.text] && p.is(k+1, "("):
			if m, ok := p.match(k + 1); ok {
				p.identsInto(u.controls, k+1, m)
			}
		case routeCalls[t.text] && (p.is(k-1, ".") || p.is(k-1, "::") || p.is(k-1, "->")) && p.is(k+1, "("):
			m, ok := p.match(k + 1)
			if !ok {
				continue
			}
			args := p.splitArgs(k+1, m)
			for a := 1; a+1 < len(args); a++ {
				p.identsInto(u.controls, args[a][0], args[a][1])
			}
		}
	}
}

// identsInto adds identifiers in s..e, including string interpolations.
func (p *braceParser) identsInto(dst map[string]bool, s, e int) {
	for i := s; i <= e; i++ {
		if p.toks[i].kind == 'i' {
			dst[p.toks[i].text] = true
		}
		for _, ref := range p.toks[i].refs {
			dst[ref] = true
		}
	}
}

// splitArgs returns inclusive token ranges of top-level call arguments.
func (p *braceParser) splitArgs(open, close int) [][2]int {
	var args [][2]int
	start, depth := open+1, 0
	for k := open + 1; k < close; k++ {
		if p.toks[k].kind == 's' {
			continue
		}
		switch p.toks[k].text {
		case "(", "[", "{":
			depth++
		case ")", "]", "}":
			depth--
		case ",":
			if depth == 0 {
				args = append(args, [2]int{start, k - 1})
				start = k + 1
			}
		}
	}
	if start < close {
		args = append(args, [2]int{start, close - 1})
	}
	return args
}

// finishUnits merges statements sharing a line and attaches leading comments.
// Any structural conflict falls back to the whole file.
func finishUnits(path string, units []*sourceUnit, comments, code map[int]bool) ([]*sourceUnit, bool) {
	if len(units) == 0 {
		return nil, false
	}
	sort.SliceStable(units, func(i, j int) bool { return units[i].Start < units[j].Start })
	merged := []*sourceUnit{}
	for _, u := range units {
		u.Path = path
		if n := len(merged); n > 0 && u.Start <= merged[n-1].End {
			prev := merged[n-1]
			if prev.container || u.container || prev.parent != u.parent {
				return nil, false
			}
			if u.End > prev.End {
				prev.End = u.End
			}
			for _, m := range []struct{ dst, src map[string]bool }{{prev.names, u.names}, {prev.refs, u.refs}, {prev.controls, u.controls}} {
				for k := range m.src {
					m.dst[k] = true
				}
			}
			prev.function = prev.function || u.function
			prev.guard = prev.guard || u.guard
			prev.header = prev.header && u.header
			continue
		}
		merged = append(merged, u)
	}
	prevEnd := 0
	for _, u := range merged {
		for u.Start-1 > prevEnd && comments[u.Start-1] && !code[u.Start-1] {
			u.Start--
		}
		prevEnd = u.End
	}
	return merged, true
}
