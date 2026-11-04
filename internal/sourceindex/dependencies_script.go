package sourceindex

import (
	"path"
	"regexp"
	"strings"
)

var jsAnyImport = regexp.MustCompile(`(?m)(?:\b(?:import|export)\s+[^\n;]*?\s+from\s*|\b(?:require|import)\s*\(\s*|\bimport\s*)['"]([^'"]+)['"]`)
var pyImport = regexp.MustCompile(`(?m)^\s*(?:from\s+([.\w]+)\s+import\s+([^\n#]+)|import\s+([\w.]+))`)

func javascriptImports(file, text string) []importRequest {
	dir := path.Dir(file)
	var out []importRequest
	for _, m := range jsAnyImport.FindAllStringSubmatch(text, -1) {
		raw := m[1]
		req := importRequest{name: raw}
		if strings.HasPrefix(raw, "./") || strings.HasPrefix(raw, "../") {
			req.candidates = resolveJSImport(dir, raw)
		} else {
			req.skip = "external_or_unsupported_import"
		}
		out = append(out, req)
	}
	return out
}
func pythonImports(file, text string) []importRequest {
	dir := path.Dir(file)
	var out []importRequest
	for _, m := range pyImport.FindAllStringSubmatch(text, -1) {
		raw := m[1]
		if raw == "" {
			raw = m[3]
		}
		base := "."
		rest := raw
		if strings.HasPrefix(raw, ".") {
			dots := len(raw) - len(strings.TrimLeft(raw, "."))
			base = dir
			for i := 1; i < dots; i++ {
				base = path.Dir(base)
			}
			rest = raw[dots:]
		}
		mod := path.Join(base, strings.ReplaceAll(rest, ".", "/"))
		candidates := []string{mod + ".py", path.Join(mod, "__init__.py")}
		// In "from . import helpers", helpers can be a sibling module.
		if rest == "" {
			candidates = []string{path.Join(base, "__init__.py")}
			for _, n := range strings.Split(m[2], ",") {
				n = strings.TrimSpace(strings.Split(n, " as ")[0])
				if regexpIdentifier(n) {
					child := path.Join(base, n)
					out = append(out, importRequest{name: raw + n, candidates: []string{child + ".py", path.Join(child, "__init__.py")}})
				}
			}
		}
		out = append(out, importRequest{name: raw, candidates: candidates})
	}
	return out
}
func regexpIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		if c != '_' && !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
