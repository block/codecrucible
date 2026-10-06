package decision

import "strings"

// lexToken is one lexical element of a brace- or indentation-delimited source.
// Strings, comments, and interpolations are opaque: only their extent matters.
type lexToken struct {
	text      string
	kind      byte // 'i' identifier, 's' string/regex literal, 'n' number, 'p' punctuation
	line, end int  // first and last source line
	col       int
	refs      []string // identifiers interpolated into a string literal
}

// syntax describes only the lexical rules needed to keep brackets balanced.
type syntax struct {
	hashComments   bool // PHP '#' line comments
	hashDirectives bool // C, C++, C# preprocessor lines
	nestedComments bool
	quoteStrings   bool // '...' is a string rather than a character literal
	multilineStr   bool // ordinary strings may span lines
	templates      bool // JavaScript backquote templates
	regex          bool
	tripleQuotes   bool
	tripleEscapes  bool
	dollarInterp   bool // "${...}" interpolation inside strings
	swiftInterp    bool // "\(...)" interpolation inside strings
	backtickIdents bool
	lifetimes      bool // Rust/Scala 'name is not a character literal
	digitQuotes    bool // C++ 1'000 digit separators
	rustStrings    bool
	cppRaw         bool
	csharpStrings  bool
	php            bool
	newlineEnds    bool // statements may end at a newline
	scala          bool
	cLike          bool // prototypes and qualified out-of-line definitions
	python         bool
	containers     map[string]bool
	varKeywords    map[string]bool
}

type lexer struct {
	src       string
	i         int
	line      int
	lineStart int
	lang      *syntax
	toks      []lexToken
	comments  map[int]bool // lines containing a comment
	code      map[int]bool // lines containing code
	interp    []string     // interpolated identifiers of the current literal
}

func newLexer(src string, lang *syntax) *lexer {
	return &lexer{src: src, line: 1, lang: lang, comments: map[int]bool{}, code: map[int]bool{}}
}

func (lx *lexer) peek(n int) byte {
	if lx.i+n < len(lx.src) {
		return lx.src[lx.i+n]
	}
	return 0
}

func (lx *lexer) advance() {
	if lx.src[lx.i] == '\n' {
		lx.line++
		lx.lineStart = lx.i + 1
	}
	lx.i++
}

func (lx *lexer) advanceN(n int) {
	for ; n > 0 && lx.i < len(lx.src); n-- {
		lx.advance()
	}
}

func (lx *lexer) emit(kind byte, text string, start, line, col int) {
	if text == "" {
		text = lx.src[start:lx.i]
	}
	tok := lexToken{text: text, kind: kind, line: line, end: lx.line, col: col}
	if kind == 's' {
		if lx.lang.php && (strings.HasPrefix(text, `"`) || strings.HasPrefix(text, "<<<") && !strings.Contains(text[:min(len(text), 8)], "'")) {
			lx.interp = append(lx.interp, phpVariables(text)...)
		}
		tok.refs, lx.interp = lx.interp, nil
	}
	lx.toks = append(lx.toks, tok)
	for l := line; l <= lx.line; l++ {
		lx.code[l] = true
	}
}

func isIdentStart(c byte) bool {
	return c == '_' || c == '$' || c >= 0x80 || (c|0x20 >= 'a' && c|0x20 <= 'z')
}

func isIdentChar(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

func (lx *lexer) atLineStart() bool {
	return strings.TrimSpace(lx.src[lx.lineStart:lx.i]) == ""
}

// run tokenizes the whole source. false means the lexical structure is not
// understood, and callers must fall back to whole-file evidence.
func (lx *lexer) run() bool {
	if lx.lang.php {
		trimmed := strings.TrimLeft(lx.src, " \t\r\n\ufeff")
		if !strings.HasPrefix(trimmed, "<?php") {
			return false
		}
		lx.advanceN(len(lx.src) - len(trimmed) + len("<?php"))
	}
	for lx.i < len(lx.src) {
		c := lx.src[lx.i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v':
			lx.advance()
		case lx.lang.hashDirectives && c == '#' && lx.atLineStart():
			lx.directive()
		case c == '/' && lx.peek(1) == '/', lx.lang.hashComments && c == '#' && lx.peek(1) != '[':
			lx.lineComment()
		case c == '/' && lx.peek(1) == '*':
			if !lx.blockComment() {
				return false
			}
		case lx.lang.php && c == '?' && lx.peek(1) == '>':
			// A closing tag followed by markup means an HTML template.
			return strings.TrimSpace(lx.src[lx.i+2:]) == ""
		case lx.lang.php && strings.HasPrefix(lx.src[lx.i:], "<<<"):
			if !lx.heredoc() {
				return false
			}
		case lx.lang.csharpStrings && (c == '@' || c == '$') && lx.csharpStringAhead():
			if !lx.csharpString() {
				return false
			}
		case c == '"' || (c == '\'' && lx.lang.quoteStrings):
			if !lx.str() {
				return false
			}
		case c == '\'':
			if !lx.quote() {
				return false
			}
		case c == '`' && lx.lang.templates:
			if !lx.template() {
				return false
			}
		case c == '`' && lx.lang.backtickIdents:
			if !lx.backtickIdent() {
				return false
			}
		case c == '/' && lx.lang.regex && lx.regexAllowed():
			if !lx.regexLiteral() {
				return false
			}
		case isIdentStart(c):
			if !lx.ident() {
				return false
			}
		case c >= '0' && c <= '9':
			lx.number()
		default:
			lx.punct()
		}
	}
	return true
}

func (lx *lexer) directive() {
	start, line := lx.i, lx.line
	for lx.i < len(lx.src) {
		if lx.src[lx.i] == '\n' {
			prev := strings.TrimRight(lx.src[start:lx.i], "\r")
			if !strings.HasSuffix(prev, "\\") {
				break
			}
		}
		lx.advance()
	}
	for l := line; l <= lx.line; l++ {
		lx.code[l] = true
	}
}

func (lx *lexer) lineComment() {
	lx.comments[lx.line] = true
	for lx.i < len(lx.src) && lx.src[lx.i] != '\n' {
		lx.advance()
	}
}

func (lx *lexer) blockComment() bool {
	depth := 0
	for lx.i < len(lx.src) {
		lx.comments[lx.line] = true
		if lx.src[lx.i] == '/' && lx.peek(1) == '*' {
			depth++
			lx.advanceN(2)
			continue
		}
		if lx.src[lx.i] == '*' && lx.peek(1) == '/' {
			depth--
			lx.advanceN(2)
			if depth == 0 || !lx.lang.nestedComments {
				return true
			}
			continue
		}
		lx.advance()
	}
	return false
}

func (lx *lexer) heredoc() bool {
	start, line, col := lx.i, lx.line, lx.i-lx.lineStart
	lx.advanceN(3)
	for lx.i < len(lx.src) && (lx.src[lx.i] == ' ' || lx.src[lx.i] == '\'' || lx.src[lx.i] == '"') {
		lx.advance()
	}
	nameStart := lx.i
	for lx.i < len(lx.src) && isIdentChar(lx.src[lx.i]) {
		lx.advance()
	}
	name := lx.src[nameStart:lx.i]
	if name == "" {
		return false
	}
	for lx.i < len(lx.src) {
		if lx.src[lx.i] == '\n' {
			lx.advance()
			rest := strings.TrimLeft(lx.src[lx.i:], " \t")
			if strings.HasPrefix(rest, name) && (len(rest) == len(name) || !isIdentChar(rest[len(name)])) {
				lx.advanceN(len(lx.src) - len(rest) - lx.i + len(name))
				lx.emit('s', "", start, line, col)
				return true
			}
			continue
		}
		lx.advance()
	}
	return false
}

// str scans an ordinary or triple-quoted string starting at the quote.
func (lx *lexer) str() bool {
	start, line, col := lx.i, lx.line, lx.i-lx.lineStart
	q := lx.src[lx.i]
	if q == '"' && lx.lang.tripleQuotes && strings.HasPrefix(lx.src[lx.i:], `"""`) {
		if !lx.triple() {
			return false
		}
		lx.emit('s', "", start, line, col)
		return true
	}
	lx.advance()
	if !lx.stringBody(q, lx.lang.multilineStr) {
		return false
	}
	lx.emit('s', "", start, line, col)
	return true
}

// stringBody consumes up to and including the closing quote.
func (lx *lexer) stringBody(q byte, multiline bool) bool {
	for lx.i < len(lx.src) {
		c := lx.src[lx.i]
		switch {
		case c == '\\':
			if lx.lang.swiftInterp && lx.peek(1) == '(' {
				lx.advanceN(2)
				if !lx.skipNested('(', ')') {
					return false
				}
				continue
			}
			lx.advanceN(2)
		case c == q:
			lx.advance()
			return true
		case c == '\n' && !multiline:
			return false
		case q == '"' && lx.lang.dollarInterp && c == '$' && lx.peek(1) == '{':
			lx.advanceN(2)
			if !lx.skipNested('{', '}') {
				return false
			}
		default:
			lx.advance()
		}
	}
	return false
}

func (lx *lexer) triple() bool {
	n := 0
	for lx.i+n < len(lx.src) && lx.src[lx.i+n] == '"' {
		n++
	}
	if !lx.lang.csharpStrings {
		n = 3
	}
	closing := strings.Repeat(`"`, n)
	lx.advanceN(n)
	for lx.i < len(lx.src) {
		switch {
		case lx.src[lx.i] == '\\' && lx.lang.tripleEscapes:
			lx.advanceN(2)
		case strings.HasPrefix(lx.src[lx.i:], closing):
			lx.advanceN(n)
			for lx.i < len(lx.src) && lx.src[lx.i] == '"' {
				lx.advance() // Kotlin/Scala allow extra quotes before the delimiter.
			}
			return true
		case lx.lang.dollarInterp && lx.src[lx.i] == '$' && lx.peek(1) == '{':
			lx.advanceN(2)
			if !lx.skipNested('{', '}') {
				return false
			}
		default:
			lx.advance()
		}
	}
	return false
}

// skipNested skips an interpolated expression up to its matching close and
// records its identifiers for the enclosing literal.
func (lx *lexer) skipNested(open, close byte) bool {
	depth := 1
	start := lx.i
	for lx.i < len(lx.src) {
		c := lx.src[lx.i]
		switch {
		case c == '"' || (c == '\'' && lx.lang.quoteStrings):
			lx.advance()
			if !lx.stringBody(c, false) {
				return false
			}
		case c == '`' && lx.lang.templates:
			if !lx.template() {
				return false
			}
			lx.toks = lx.toks[:len(lx.toks)-1]
		case c == open:
			depth++
			lx.advance()
		case c == close:
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

// interpolatedWords returns identifiers in an interpolated expression, skipping
// nested quoted literals such as map keys.
func interpolatedWords(expr string) []string {
	var words []string
	for i := 0; i < len(expr); {
		c := expr[i]
		switch {
		case c == '"' || c == '\'':
			end := strings.IndexByte(expr[i+1:], c)
			if end < 0 {
				return words
			}
			i += end + 2
		case isIdentStart(c):
			j := i
			for j < len(expr) && isIdentChar(expr[j]) {
				j++
			}
			if word := strings.TrimLeft(expr[i:j], "$"); word != "" {
				words = append(words, word)
			}
			i = j
		case c >= '0' && c <= '9':
			for i < len(expr) && isIdentChar(expr[i]) {
				i++
			}
		default:
			i++
		}
	}
	return words
}

// phpVariables returns variables and property chains interpolated into a PHP
// double-quoted string or heredoc: "$id", "{$this->table}".
func phpVariables(text string) []string {
	var words []string
	for i := 0; i < len(text); i++ {
		if text[i] != '$' || i+1 >= len(text) || !isIdentStart(text[i+1]) || text[i+1] == '$' {
			continue
		}
		for {
			j := i + 1
			for j < len(text) && isIdentChar(text[j]) && text[j] != '$' {
				j++
			}
			words = append(words, text[i+1:j])
			if !strings.HasPrefix(text[j:], "->") || j+2 >= len(text) || !isIdentStart(text[j+2]) {
				i = j - 1
				break
			}
			i = j + 1
		}
	}
	return words
}

func (lx *lexer) template() bool {
	start, line, col := lx.i, lx.line, lx.i-lx.lineStart
	lx.advance()
	for lx.i < len(lx.src) {
		c := lx.src[lx.i]
		switch {
		case c == '\\':
			lx.advanceN(2)
		case c == '`':
			lx.advance()
			lx.emit('s', "", start, line, col)
			return true
		case c == '$' && lx.peek(1) == '{':
			lx.advanceN(2)
			if !lx.skipNested('{', '}') {
				return false
			}
		default:
			lx.advance()
		}
	}
	return false
}

func (lx *lexer) backtickIdent() bool {
	start, line, col := lx.i, lx.line, lx.i-lx.lineStart
	lx.advance()
	for lx.i < len(lx.src) && lx.src[lx.i] != '`' {
		if lx.src[lx.i] == '\n' {
			return false
		}
		lx.advance()
	}
	if lx.i >= len(lx.src) {
		return false
	}
	lx.advance()
	lx.emit('i', strings.Trim(lx.src[start:lx.i], "`"), start, line, col)
	return true
}

// quote scans a character literal, or a Rust/Scala lifetime or symbol.
func (lx *lexer) quote() bool {
	start, line, col := lx.i, lx.line, lx.i-lx.lineStart
	if lx.lang.lifetimes && isIdentStart(lx.peek(1)) {
		j := lx.i + 1
		for j < len(lx.src) && isIdentChar(lx.src[j]) {
			j++
		}
		if j >= len(lx.src) || lx.src[j] != '\'' {
			lx.advance()
			lx.emit('p', "", start, line, col)
			return true
		}
	}
	lx.advance()
	for n := 0; lx.i < len(lx.src) && n < 16; n++ {
		switch lx.src[lx.i] {
		case '\\':
			lx.advanceN(2)
		case '\'':
			lx.advance()
			lx.emit('s', "", start, line, col)
			return true
		case '\n':
			return false
		default:
			lx.advance()
		}
	}
	return false
}

func (lx *lexer) csharpStringAhead() bool {
	rest := lx.src[lx.i:]
	return strings.HasPrefix(rest, `@"`) || strings.HasPrefix(rest, `$"`) ||
		strings.HasPrefix(rest, `$@"`) || strings.HasPrefix(rest, `@$"`) || strings.HasPrefix(rest, `$$"`)
}

func (lx *lexer) csharpString() bool {
	start, line, col := lx.i, lx.line, lx.i-lx.lineStart
	verbatim, interpolated := false, false
	for lx.src[lx.i] != '"' {
		verbatim = verbatim || lx.src[lx.i] == '@'
		interpolated = interpolated || lx.src[lx.i] == '$'
		lx.advance()
	}
	if strings.HasPrefix(lx.src[lx.i:], `"""`) {
		if !lx.triple() {
			return false
		}
		lx.emit('s', "", start, line, col)
		return true
	}
	lx.advance()
	for lx.i < len(lx.src) {
		c := lx.src[lx.i]
		switch {
		case c == '"' && verbatim && lx.peek(1) == '"':
			lx.advanceN(2)
		case c == '"':
			lx.advance()
			lx.emit('s', "", start, line, col)
			return true
		case c == '\\' && !verbatim:
			lx.advanceN(2)
		case c == '\n' && !verbatim:
			return false
		case c == '{' && interpolated && lx.peek(1) == '{':
			lx.advanceN(2)
		case c == '{' && interpolated:
			lx.advance()
			if !lx.skipNested('{', '}') {
				return false
			}
		default:
			lx.advance()
		}
	}
	return false
}

var regexPrefixKeywords = map[string]bool{
	"return": true, "typeof": true, "instanceof": true, "in": true, "of": true, "new": true,
	"delete": true, "void": true, "throw": true, "case": true, "do": true, "else": true,
	"yield": true, "await": true,
}

func (lx *lexer) regexAllowed() bool {
	if len(lx.toks) == 0 {
		return true
	}
	prev := lx.toks[len(lx.toks)-1]
	switch prev.kind {
	case 'p':
		// '</' closes a JSX element; it never starts a regular expression.
		return prev.text != ")" && prev.text != "]" && prev.text != "}" && prev.text != "<"
	case 'i':
		return regexPrefixKeywords[prev.text]
	}
	return false
}

func (lx *lexer) regexLiteral() bool {
	start, line, col := lx.i, lx.line, lx.i-lx.lineStart
	lx.advance()
	inClass := false
	for lx.i < len(lx.src) {
		c := lx.src[lx.i]
		switch {
		case c == '\\':
			lx.advanceN(2)
			continue
		case c == '\n':
			return false
		case c == '[':
			inClass = true
		case c == ']':
			inClass = false
		case c == '/' && !inClass:
			lx.advance()
			for lx.i < len(lx.src) && isIdentChar(lx.src[lx.i]) {
				lx.advance()
			}
			lx.emit('s', "", start, line, col)
			return true
		}
		lx.advance()
	}
	return false
}

func (lx *lexer) ident() bool {
	start, line, col := lx.i, lx.line, lx.i-lx.lineStart
	for lx.i < len(lx.src) && isIdentChar(lx.src[lx.i]) {
		lx.advance()
	}
	text := lx.src[start:lx.i]
	next := lx.peek(0)
	switch {
	case lx.lang.rustStrings && (text == "r" || text == "br") && (next == '"' || next == '#'):
		return lx.rustRaw(start, line, col)
	case lx.lang.rustStrings && text == "b" && next == '"':
		lx.advance()
		if !lx.stringBody('"', true) {
			return false
		}
		lx.emit('s', "", start, line, col)
		return true
	case lx.lang.rustStrings && text == "b" && next == '\'':
		return lx.quote()
	case lx.lang.cppRaw && next == '"' && (text == "R" || text == "u8R" || text == "uR" || text == "UR" || text == "LR"):
		return lx.cppRawString(start, line, col)
	}
	if lx.lang.php {
		text = strings.TrimLeft(text, "$")
		if text == "" {
			lx.emit('p', "$", start, line, col)
			return true
		}
	}
	lx.emit('i', text, start, line, col)
	return true
}

func (lx *lexer) rustRaw(start, line, col int) bool {
	hashes := 0
	for lx.i < len(lx.src) && lx.src[lx.i] == '#' {
		hashes++
		lx.advance()
	}
	if lx.i >= len(lx.src) || lx.src[lx.i] != '"' {
		return false
	}
	lx.advance()
	closing := `"` + strings.Repeat("#", hashes)
	idx := strings.Index(lx.src[lx.i:], closing)
	if idx < 0 {
		return false
	}
	lx.advanceN(idx + len(closing))
	lx.emit('s', "", start, line, col)
	return true
}

func (lx *lexer) cppRawString(start, line, col int) bool {
	lx.advance()
	open := strings.IndexByte(lx.src[lx.i:], '(')
	if open < 0 || open > 16 {
		return false
	}
	closing := ")" + lx.src[lx.i:lx.i+open] + `"`
	idx := strings.Index(lx.src[lx.i+open:], closing)
	if idx < 0 {
		return false
	}
	lx.advanceN(open + idx + len(closing))
	lx.emit('s', "", start, line, col)
	return true
}

func (lx *lexer) number() {
	start, line, col := lx.i, lx.line, lx.i-lx.lineStart
	for lx.i < len(lx.src) {
		c := lx.src[lx.i]
		if isIdentChar(c) || c == '.' || (c == '\'' && lx.lang.digitQuotes && lx.peek(1) >= '0' && lx.peek(1) <= '9') {
			lx.advance()
			continue
		}
		break
	}
	lx.emit('n', "", start, line, col)
}

var multiPunct = []string{
	"===", "!==", "...", "**=", "<<=", ">>=", "??=", "||=", "&&=",
	"=>", "->", "::", "?.", "??", "&&", "||", "==", "!=", "<=", ">=", "++", "--",
	"+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "**", ":=",
}

func (lx *lexer) punct() {
	start, line, col := lx.i, lx.line, lx.i-lx.lineStart
	rest := lx.src[lx.i:]
	for _, op := range multiPunct {
		if strings.HasPrefix(rest, op) {
			lx.advanceN(len(op))
			lx.emit('p', "", start, line, col)
			return
		}
	}
	lx.advance()
	lx.emit('p', "", start, line, col)
}
