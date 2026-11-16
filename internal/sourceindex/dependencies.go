package sourceindex

import (
	"path"
	"sort"
	"strings"
)

// Import records the outcome of a local dependency lookup. An unresolved or
// ambiguous import is not evidence that the dependency or a guard is absent.
type Import struct {
	File      string   `json:"file"`
	Specifier string   `json:"specifier"`
	Status    string   `json:"status"` // resolved, unresolved, ambiguous, skipped
	Reason    string   `json:"reason,omitempty"`
	Targets   []string `json:"targets,omitempty"`
}

type importRequest struct {
	name       string
	exact      string // Prefer an existing literal path over inferred extensions.
	candidates []string
	many       bool
	skip       string
}

func vendored(p string) bool {
	for _, part := range strings.Split(p, "/") {
		switch part {
		case "vendor", "node_modules", "__pycache__", ".venv", "venv":
			return true
		}
	}
	return false
}

func (ix *Index) buildImports() {
	modules := map[string]string{}
	goDirs := map[string][]string{}
	kotlinNames := map[string][]string{}
	for _, p := range ix.paths {
		if vendored(p) {
			continue
		}
		if path.Base(p) == "go.mod" {
			if m := moduleLine.FindStringSubmatch(ix.files[p]); m != nil {
				modules[path.Dir(p)] = strings.Trim(m[1], "\"")
			}
		}
		if path.Ext(p) == ".go" {
			goDirs[path.Dir(p)] = append(goDirs[path.Dir(p)], p)
		}
		if ix.Language(p) == "kotlin" {
			for _, d := range ix.byFile[p] {
				name := d.Name
				if d.owner != "" {
					name = d.owner + "." + name
				}
				if pkg := ix.sources[p].packageName; pkg != "" {
					name = pkg + "." + name
				}
				kotlinNames[name] = appendUnique(kotlinNames[name], p)
			}
		}
	}
	for _, p := range ix.paths {
		if vendored(p) {
			continue
		}
		requests := ix.importRequests(p, modules, goDirs, kotlinNames)
		seen := map[string]bool{}
		for _, req := range requests {
			if seen[req.name] {
				continue
			}
			seen[req.name] = true
			imp := Import{File: p, Specifier: req.name, Status: "unresolved", Reason: "not_in_admitted_source"}
			if req.skip != "" {
				imp.Status, imp.Reason = "skipped", req.skip
			} else {
				vendor := false
				candidates := req.candidates
				if _, exists := ix.files[req.exact]; req.exact != "" && exists {
					candidates = []string{req.exact}
				}
				for _, candidate := range candidates {
					if vendored(candidate) {
						vendor = true
						continue
					}
					if candidate == p || candidate == ".." || strings.HasPrefix(candidate, "../") || path.IsAbs(candidate) {
						continue
					}
					if _, ok := ix.files[candidate]; ok {
						imp.Targets = appendUnique(imp.Targets, candidate)
					}
				}
				sort.Strings(imp.Targets)
				switch {
				case len(imp.Targets) > 1 && !req.many:
					imp.Status, imp.Reason = "ambiguous", "multiple_local_candidates"
				case len(imp.Targets) > 0:
					imp.Status, imp.Reason = "resolved", ""
				case vendor:
					imp.Status, imp.Reason = "skipped", "vendored_import"
				}
			}
			if imp.Status == "resolved" {
				for _, target := range imp.Targets {
					ix.graph[p] = appendUnique(ix.graph[p], target)
				}
			}
			ix.imports = append(ix.imports, imp)
			ix.snapshot.Imports[imp.Status]++
		}
		sort.Strings(ix.graph[p])
	}
	sort.Slice(ix.imports, func(i, j int) bool {
		a, b := ix.imports[i], ix.imports[j]
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Specifier < b.Specifier
	})
}

func appendUnique(values []string, s string) []string {
	for _, v := range values {
		if v == s {
			return values
		}
	}
	return append(values, s)
}

func (ix *Index) importRequests(file string, modules map[string]string, goDirs, kotlinNames map[string][]string) []importRequest {
	switch path.Ext(file) {
	case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs":
		return javascriptImports(file, ix.files[file])
	case ".py":
		return pythonImports(file, ix.files[file])
	case ".go":
		return ix.goImports(file, modules, goDirs)
	case ".kt", ".kts":
		return ix.kotlinImports(file, kotlinNames)
	case ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp":
		return cImports(file, ix.files[file])
	default:
		return nil
	}
}
