package sourceindex

import (
	"path"
	"regexp"
	"sort"
	"strings"
)

var moduleLine = regexp.MustCompile(`(?m)^\s*module\s+([^\s]+)`)

func (ix *Index) goImports(file string, modules map[string]string, goDirs map[string][]string) []importRequest {
	var out []importRequest
	names := append([]string(nil), ix.sources[file].importPaths...)
	sort.Strings(names)
	for _, raw := range names {
		out = append(out, goImportRequest(raw, modules, goDirs))
	}

	return out
}
func goImportRequest(raw string, modules map[string]string, dirs map[string][]string) importRequest {
	req := importRequest{name: raw, many: true}
	best := ""
	roots := []string{}
	for dir, mod := range modules {
		if raw == mod || strings.HasPrefix(raw, mod+"/") {
			if len(mod) > len(best) {
				best = mod
				roots = nil
			}
			if mod == best {
				roots = append(roots, dir)
			}
		}
	}
	if best != "" {
		matchedRoots := 0
		for _, root := range roots {
			local := path.Join(root, strings.TrimPrefix(strings.TrimPrefix(raw, best), "/"))
			// A nested module is not part of its parent module's package tree.
			if owningGoModule(local, modules) != root || len(dirs[local]) == 0 {
				continue
			}
			matchedRoots++
			req.candidates = append(req.candidates, dirs[local]...)
		}
		if matchedRoots > 1 {
			req.many = false
		}
		return req
	}
	// Without a go.mod, accept only one matching repository directory.
	if len(modules) == 0 {
		var matches []string
		for dir := range dirs {
			if raw == dir || (dir != "." && strings.HasSuffix(raw, "/"+dir)) {
				matches = append(matches, dir)
			}
		}
		sort.Strings(matches)
		for _, dir := range matches {
			req.candidates = append(req.candidates, dirs[dir]...)
		}
		if len(matches) > 1 {
			req.many = false
		}
		return req
	}
	req.skip = "external_import"
	return req
}

func owningGoModule(dir string, modules map[string]string) string {
	best := ""
	for root := range modules {
		if root == "." || dir == root || strings.HasPrefix(dir, root+"/") {
			if best == "" || (root != "." && (best == "." || len(root) > len(best))) {
				best = root
			}
		}
	}
	return best
}
