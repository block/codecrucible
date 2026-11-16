package ingest

import "github.com/block/codecrucible/internal/sourceindex"

// ParseImports returns best-effort candidate paths for relative imports.
func ParseImports(filePath, content string) []string {
	return sourceindex.ParseImports(filePath, content)
}

// ResolveImports resolves imports only against the admitted source snapshot.
func ResolveImports(files []SourceFile) map[string][]string {
	contents := make(map[string]string, len(files))
	for _, f := range files {
		contents[f.Path] = f.Content
	}
	return sourceindex.New(contents).ImportGraph()
}
