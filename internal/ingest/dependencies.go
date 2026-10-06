package ingest

import (
	"go/parser"
	"go/token"
	"path"
	"sort"
	"strconv"
	"strings"
)

// ResolveDependencies augments the existing relative-import graph for optional
// Jev stages. Existing scans keep ResolveImports and its current behavior.
// Only files already admitted to the scan can become dependency edges.
func ResolveDependencies(files []SourceFile) map[string][]string {
	graph := ResolveImports(files)
	languages := newSourceIndex(files)
	known := map[string]bool{}
	packages := map[string][]string{}
	modules := map[string]string{}
	for _, f := range files {
		known[f.Path] = true
		if strings.HasSuffix(f.Path, ".go") {
			packages[path.Dir(f.Path)] = append(packages[path.Dir(f.Path)], f.Path)
		}
		if path.Base(f.Path) == "go.mod" {
			for _, line := range strings.Split(f.Content, "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 2 && fields[0] == "module" {
					modules[path.Dir(f.Path)] = strings.Trim(fields[1], "\"")
				}
			}
		}
	}
	for _, f := range files {
		switch path.Ext(f.Path) {
		case ".go":
			// Sibling Go files jointly define a package, even without an import edge.
			graph[f.Path] = append(graph[f.Path], packages[path.Dir(f.Path)]...)
			parsed, err := parser.ParseFile(token.NewFileSet(), f.Path, f.Content, parser.ImportsOnly)
			if err != nil {
				continue
			}
			root, module := "", ""
			for dir, name := range modules {
				if (dir == "." || strings.HasPrefix(f.Path, dir+"/")) && len(dir) > len(root) {
					root, module = dir, name
				}
			}
			for _, imp := range parsed.Imports {
				name, err := strconv.Unquote(imp.Path.Value)
				if err != nil {
					continue
				}
				if module != "" && (name == module || strings.HasPrefix(name, module+"/")) {
					local := path.Join(root, strings.TrimPrefix(strings.TrimPrefix(name, module), "/"))
					graph[f.Path] = append(graph[f.Path], packages[local]...)
				}
			}
		default:
			graph[f.Path] = append(graph[f.Path], languages.languageDependencies(f)...)
		}
	}
	for from, to := range graph {
		seen := map[string]bool{from: true}
		clean := []string{}
		for _, p := range to {
			if known[p] && !seen[p] {
				clean = append(clean, p)
				seen[p] = true
			}
		}
		sort.Strings(clean)
		if len(clean) == 0 {
			delete(graph, from)
		} else {
			graph[from] = clean
		}
	}
	return graph
}
