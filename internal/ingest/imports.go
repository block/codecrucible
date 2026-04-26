package ingest

import (
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// jsImportFrom matches: import ... from '...' or "..."
var jsImportFrom = regexp.MustCompile(`(?m)(?:import|export)\s+.*?\s+from\s+['"](\.\.?/[^'"]+)['"]`)

// jsRequire matches: require('...') or require("...")
var jsRequire = regexp.MustCompile(`(?:require|import)\s*\(\s*['"](\.\.?/[^'"]+)['"]\s*\)`)

// jsSideEffectImport matches: import './foo' or import "../bar"
var jsSideEffectImport = regexp.MustCompile(`(?m)^import\s+['"](\.\.?/[^'"]+)['"]`)

// pyRelativeImport matches: from . import x, from .foo import x, from ..foo import x
var pyRelativeImport = regexp.MustCompile(`(?m)^from\s+(\.+\w*(?:\.\w+)*)\s+import`)

// jsExtensions are tried when a JS/TS import has no extension.
var jsExtensions = []string{".ts", ".tsx", ".js", ".jsx"}

// jsIndexFiles are tried when a JS/TS import might refer to a directory.
var jsIndexFiles = []string{"/index.ts", "/index.tsx", "/index.js", "/index.jsx"}

// ParseImports extracts local/relative import paths from a source file.
// path is the repo-root-relative file path; content is the file's text.
// Returns repo-root-relative paths that the file imports.
// This is best-effort; it never panics on malformed input.
func ParseImports(filePath string, content string) []string {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".ts", ".tsx", ".js", ".jsx":
		return parseJSImports(filePath, content)
	case ".py":
		return parsePyImports(filePath, content)
	default:
		// Go uses module paths, not relative imports — no parser needed.
		return nil
	}
}

func parseJSImports(filePath string, content string) []string {
	dir := path.Dir(filePath)
	seen := make(map[string]bool)
	var result []string

	addImport := func(raw string) {
		resolved := resolveJSImport(dir, raw)
		for _, p := range resolved {
			if !seen[p] {
				seen[p] = true
				result = append(result, p)
			}
		}
	}

	for _, m := range jsImportFrom.FindAllStringSubmatch(content, -1) {
		addImport(m[1])
	}
	for _, m := range jsRequire.FindAllStringSubmatch(content, -1) {
		addImport(m[1])
	}
	for _, m := range jsSideEffectImport.FindAllStringSubmatch(content, -1) {
		addImport(m[1])
	}

	return result
}

func resolveJSImport(dir, importPath string) []string {
	resolved := path.Join(dir, importPath)

	ext := path.Ext(resolved)
	if ext != "" {
		return []string{resolved}
	}

	var candidates []string
	for _, e := range jsExtensions {
		candidates = append(candidates, resolved+e)
	}
	for _, idx := range jsIndexFiles {
		candidates = append(candidates, resolved+idx)
	}
	return candidates
}

func parsePyImports(filePath string, content string) []string {
	dir := path.Dir(filePath)
	seen := make(map[string]bool)
	var result []string

	for _, m := range pyRelativeImport.FindAllStringSubmatch(content, -1) {
		modulePart := m[1] // e.g. ".", ".foo", "..foo.bar"

		// Count leading dots.
		dots := 0
		for _, c := range modulePart {
			if c == '.' {
				dots++
			} else {
				break
			}
		}

		// Start from the importing file's directory, go up (dots-1) levels.
		base := dir
		for i := 1; i < dots; i++ {
			base = path.Dir(base)
		}

		// The rest after the dots is the module path.
		rest := modulePart[dots:]
		if rest == "" {
			// "from . import x" — refers to __init__.py in current package.
			p := path.Join(base, "__init__.py")
			if !seen[p] {
				seen[p] = true
				result = append(result, p)
			}
			continue
		}

		// Convert dotted module name to path: foo.bar -> foo/bar
		parts := strings.Split(rest, ".")
		modPath := path.Join(append([]string{base}, parts...)...)

		// Could be a module file or a package directory.
		candidates := []string{
			modPath + ".py",
			path.Join(modPath, "__init__.py"),
		}
		for _, p := range candidates {
			if !seen[p] {
				seen[p] = true
				result = append(result, p)
			}
		}
	}

	return result
}

// ResolveImports takes all source files and returns a map from each file path
// to its local import paths, filtered to only include paths that actually
// exist in the file set.
func ResolveImports(files []SourceFile) map[string][]string {
	known := make(map[string]bool, len(files))
	for _, f := range files {
		known[f.Path] = true
	}

	result := make(map[string][]string)
	for _, f := range files {
		candidates := ParseImports(f.Path, f.Content)
		var resolved []string
		for _, c := range candidates {
			if known[c] {
				resolved = append(resolved, c)
			}
		}
		if len(resolved) > 0 {
			result[f.Path] = resolved
		}
	}

	return result
}
