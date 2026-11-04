package sourceindex

import (
	"path"
	"regexp"
)

var quotedInclude = regexp.MustCompile(`(?m)^\s*#\s*include\s*"([^"\n]+)"`)

func cImports(file, text string) []importRequest {
	dir := path.Dir(file)
	var out []importRequest
	for _, m := range quotedInclude.FindAllStringSubmatch(text, -1) {
		out = append(out, importRequest{name: m[1], candidates: []string{path.Join(dir, m[1]), path.Clean(m[1])}})
	}
	return out
}
