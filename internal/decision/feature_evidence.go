package decision

import (
	"encoding/json"
	"sort"
	"strings"
)

// FeatureEvidenceBatches covers the admitted source in deterministic, bounded
// requests. Whole files stay together when possible; larger files use adjacent
// line ranges. The boolean reports whether every source line was representable.
// It does not certify that any feature is absent or that context is sufficient.
func FeatureEvidenceBatches(files map[string]string, budget int) ([][]Evidence, bool) {
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var batches [][]Evidence
	var batch []Evidence
	used, complete := 2, len(paths) > 0 // JSON array delimiters
	flush := func() {
		if len(batch) > 0 {
			batches = append(batches, batch)
		}
		batch, used = nil, 2
	}
	for _, path := range paths {
		content := files[path]
		lines := strings.Split(strings.TrimSuffix(content, "\n"), "\n")
		var spans []Evidence
		fileBytes := 0
		for start := 1; start <= len(lines); {
			end := min(start+23, len(lines))
			for {
				e, _ := SourceEvidence(path, content, start, end)
				encoded, _ := json.Marshal(e)
				size := len(encoded) + 1 // comma, conservatively also for the first item
				if size+2 <= budget {
					spans = append(spans, e)
					fileBytes += size
					break
				}
				if end == start {
					complete = false // Do not truncate an oversized source line.
					break
				}
				end = start + (end-start)/2
			}
			start = end + 1
		}
		if used+fileBytes > budget {
			flush()
		}
		for _, e := range spans {
			encoded, _ := json.Marshal(e)
			size := len(encoded) + 1
			if used+size > budget {
				flush()
			}
			batch = append(batch, e)
			used += size
		}
	}
	flush()
	return batches, complete
}
