package sourceindex

import (
	"regexp"
	"strings"
)

var (
	funcPatterns = []*regexp.Regexp{
		regexp.MustCompile(`^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(`),                                                                        // JS function
		regexp.MustCompile(`^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:async\s+)?(?:function\b|\(|[A-Za-z_$][\w$]*\s*=>)`),                                // JS arrow or function expression
		regexp.MustCompile(`^\s*(?:module\.)?exports\.([A-Za-z_$][\w$]*)\s*=`),                                                                                                              // CommonJS export
		regexp.MustCompile(`^\s*module\.exports\s*=\s*(?:async\s+)?function\s*([A-Za-z_$][\w$]*)`),                                                                                          // CommonJS default export
		regexp.MustCompile(`^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(`),                                                                                                                    // Python
		regexp.MustCompile(`^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+"[^"]*"\s+)?fn\s+([A-Za-z_]\w*)`),                                                           // Rust
		regexp.MustCompile(`^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|private|protected|static|final|synchronized|abstract|override|async)\s+)+(?:[\w<>\[\],.?]+\s+)?([A-Za-z_]\w*)\s*\(`), // Java, C#, TS methods with a modifier
		regexp.MustCompile(`^\s{2,}(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*(?::\s*[^{]+)?\{\s*$`),                                                                                     // indented method
	}
	typePatterns = []*regexp.Regexp{
		regexp.MustCompile(`^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:export\s+)?(?:default\s+)?(?:(?:public|private|protected|abstract|final|static|enum)\s+)*(?:class|interface|struct|enum|record|trait)\s+([A-Za-z_]\w*)`), // most languages
		regexp.MustCompile(`^\s*(?:export\s+)?type\s+([A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*=`), // TypeScript
	}
	keywords = map[string]bool{
		"if": true, "for": true, "while": true, "switch": true, "catch": true, "return": true, "function": true,
		"else": true, "do": true, "try": true, "with": true, "new": true, "typeof": true, "await": true,
	}
	callName = regexp.MustCompile(`(?:([A-Za-z_$][\w$]*)\s*\.\s*)?([A-Za-z_$][\w$]*)\s*\(`)
	typeName = regexp.MustCompile(`\b(?:([A-Za-z_]\w*)\s*\.\s*)?([A-Z][A-Za-z0-9_]*)\b`)
)

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

// lexicalAdapter supplies name-based candidates only. It never invents
// argument bindings or treats capitalized identifiers as external libraries.
type lexicalAdapter struct{}

func (lexicalAdapter) parse(file, text string) *sourceInfo {
	return parseLexical(file, text, matchDef)
}

func parseLexical(file, text string, declaration func(string) (Def, bool)) *sourceInfo {
	s := &sourceInfo{mode: "lexical", adapter: lexicalAdapter{}, language: language(file),
		// Unsupported languages retain lexical source handling. Applying one
		// language's literal rules here would misread e.g. Rust lifetimes.
		code: strings.Split(text, "\n")}
	offset := 0
	for i, line := range s.code {
		d, isDef := declaration(line)
		if isDef {
			d.File, d.Line = file, i+1
			s.defs = append(s.defs, d)
		}
		for _, m := range callName.FindAllStringSubmatchIndex(line, -1) {
			ref := reference{name: line[m[4]:m[5]], offset: offset + m[0]}
			if isDef && ref.name == d.Name {
				continue
			}
			if m[2] >= 0 {
				ref.qualifier = line[m[2]:m[3]]
			}
			s.calls = append(s.calls, call{reference: ref, start: offset + m[0], end: offset + m[1], line: i + 1})
		}
		offset += len(line) + 1
	}
	for i := range s.defs {
		s.defs[i].End = len(s.code)
		if i+1 < len(s.defs) {
			s.defs[i].End = s.defs[i+1].Line - 1
		}
	}
	return s
}

func (lexicalAdapter) resolve(ix *Index, file string, ref reference, typ bool) (Def, bool) {
	return onlyDefinition(ix.candidates(file, ref.name, typ))
}

// maskSource preserves byte offsets and newlines, replacing literals with an
// opaque token and comments with whitespace. Kotlin block comments can nest.
// Interpolation is deliberately opaque: it cannot establish a binding.
func maskSource(text string, hashComments bool) string {
	out := []byte(text)
	blank := func(lo, hi int) {
		for i := lo; i < hi; i++ {
			if out[i] != '\n' && out[i] != '\r' {
				out[i] = ' '
			}
		}
	}
	for i := 0; i < len(text); {
		start := i
		switch {
		case strings.HasPrefix(text[i:], "//") || (hashComments && text[i] == '#'):
			for i < len(text) && text[i] != '\n' {
				i++
			}
			blank(start, i)
		case strings.HasPrefix(text[i:], "/*"):
			i += 2
			depth := 1
			for i < len(text) && depth > 0 {
				switch {
				case strings.HasPrefix(text[i:], "/*"):
					depth++
					i += 2
				case strings.HasPrefix(text[i:], "*/"):
					depth--
					i += 2
				default:
					i++
				}
			}
			blank(start, i)
		case text[i] == '"' || text[i] == '\'' || text[i] == '`':
			quote := text[i : i+1]
			if strings.HasPrefix(text[i:], strings.Repeat(quote, 3)) {
				quote = strings.Repeat(quote, 3)
			}
			i += len(quote)
			for i < len(text) {
				if strings.HasPrefix(text[i:], quote) {
					i += len(quote)
					break
				}
				if text[i] == '\\' && len(quote) == 1 && quote != "`" && i+1 < len(text) {
					i++
				}
				i++
			}
			blank(start, i)
			out[start] = '~' // cannot be mistaken for an identifier
		default:
			i++
		}
	}
	return string(out)
}
