package sourceindex

import (
	"path"
	"strings"
)

// summarizeFile produces a one-line heuristic summary of a file's exports.
func summarizeFile(content, lang string) string {
	lines := strings.Split(content, "\n")
	var exports []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// JS/TS exports
		if strings.HasPrefix(trimmed, "export ") {
			if strings.Contains(trimmed, "function ") || strings.Contains(trimmed, "const ") ||
				strings.Contains(trimmed, "class ") || strings.Contains(trimmed, "interface ") ||
				strings.Contains(trimmed, "type ") || strings.Contains(trimmed, "default ") {
				// Extract the name
				name := extractExportName(trimmed)
				if name != "" {
					exports = append(exports, name)
				}
			}
		}

		// Python: def and class at module level (no indentation)
		if lang == "python" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			if strings.HasPrefix(trimmed, "def ") || strings.HasPrefix(trimmed, "class ") {
				name := extractPyName(trimmed)
				if name != "" && !strings.HasPrefix(name, "_") {
					exports = append(exports, name)
				}
			}
		}

		if len(exports) >= 8 {
			break
		}
	}

	if len(exports) == 0 {
		return ""
	}
	return strings.Join(exports, ", ")
}

func extractExportName(line string) string {
	// "export function foo(" → "foo()"
	// "export const bar =" → "bar"
	// "export class Baz" → "Baz"
	for _, keyword := range []string{"function ", "const ", "let ", "var ", "class ", "interface ", "type ", "default "} {
		idx := strings.Index(line, keyword)
		if idx < 0 {
			continue
		}
		rest := line[idx+len(keyword):]
		rest = strings.TrimSpace(rest)
		// Take until space, paren, equals, or brace.
		end := strings.IndexAny(rest, " (={<:")
		if end > 0 {
			name := rest[:end]
			if keyword == "function " {
				return name + "()"
			}
			return name
		}
		if len(rest) > 0 {
			return rest
		}
	}
	return ""
}

func extractPyName(line string) string {
	// "def foo(..." → "foo"
	// "class Bar:" → "Bar"
	for _, prefix := range []string{"def ", "class "} {
		if strings.HasPrefix(line, prefix) {
			rest := strings.TrimPrefix(line, prefix)
			end := strings.IndexAny(rest, "(: ")
			if end > 0 {
				return rest[:end]
			}
		}
	}
	return ""
}

// summarizeSource reuses parsed declarations where available. The legacy
// export syntax retains useful constants that a lexical declaration reader
// cannot see; other languages still get a bounded declaration summary.
func summarizeSource(file, text string, src *sourceInfo) string {
	if path.Ext(file) == ".go" {
		var names []string
		for _, d := range src.defs {
			if d.Name != "" && d.Name[0] >= 'A' && d.Name[0] <= 'Z' {
				name := d.Name
				if !d.Type {
					name += "()"
				}
				names = append(names, name)
				if len(names) == 8 {
					break
				}
			}
		}
		return strings.Join(names, ", ")
	}
	lang := ""
	if path.Ext(file) == ".py" {
		lang = "python"
	}
	if summary := summarizeFile(text, lang); summary != "" {
		return summary
	}
	var names []string
	for _, d := range src.defs {
		name := d.Name
		if !d.Type {
			name += "()"
		}
		names = append(names, name)
		if len(names) == 8 {
			break
		}
	}
	if len(names) == 0 {
		return ""
	}
	return "declarations: " + strings.Join(names, ", ")
}
