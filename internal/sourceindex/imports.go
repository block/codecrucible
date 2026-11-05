package sourceindex

import (
	"path"
	"strings"
)

var jsExtensions = []string{".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
var jsIndexFiles = []string{"/index.ts", "/index.tsx", "/index.js", "/index.jsx", "/index.mjs", "/index.cjs"}

// ParseImports preserves the candidate-path API used by ingestion. Full
// resolution, including non-relative local modules, requires an Index.
func ParseImports(file, content string) []string {
	var requests []importRequest
	switch strings.ToLower(path.Ext(file)) {
	case ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs":
		requests = javascriptImports(file, content)
	case ".py":
		requests = pythonImports(file, content)
	}
	var candidates []string
	for _, req := range requests {
		if req.skip != "" || !strings.HasPrefix(req.name, ".") {
			continue
		}
		for _, p := range req.candidates {
			candidates = appendUnique(candidates, p)
		}
	}
	return candidates
}

func resolveJSImport(dir, importPath string) []string {
	resolved := path.Join(dir, importPath)

	ext := path.Ext(resolved)
	for _, supported := range jsExtensions {
		if ext == supported {
			return []string{resolved}
		}
	}

	// A dotted basename (e.g. config.types) can still omit the source
	// extension. Exact admitted files take precedence during resolution.
	candidates := []string{resolved}
	for _, e := range jsExtensions {
		candidates = append(candidates, resolved+e)
	}
	for _, idx := range jsIndexFiles {
		candidates = append(candidates, resolved+idx)
	}
	return candidates
}
