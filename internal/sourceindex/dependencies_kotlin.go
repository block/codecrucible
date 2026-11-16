package sourceindex

import (
	"sort"
	"strings"
)

func (ix *Index) kotlinImports(file string, kotlinNames map[string][]string) []importRequest {
	var out []importRequest
	names := append([]string(nil), ix.sources[file].importPaths...)
	sort.Strings(names)
	for _, raw := range names {
		if strings.HasSuffix(raw, ".*") {
			out = append(out, importRequest{name: raw, skip: "unsupported_wildcard_import"})
			continue
		}
		out = append(out, importRequest{name: raw, candidates: kotlinNames[raw]})
	}
	return out
}
