package cli

import (
	"encoding/json"
	"fmt"

	"github.com/block/codecrucible/internal/chunk"
	"github.com/block/codecrucible/internal/sarif"
	"github.com/block/codecrucible/internal/sourceindex"
)

func recordSourceBundle(m *sarif.ScanMetadata, phase, label, content string) {
	if m == nil {
		return
	}
	m.Execution.SourceBundles = append(m.Execution.SourceBundles, sarif.SourceBundle{
		Phase: phase, Label: label, Fingerprint: fingerprint([]byte(content)),
	})
}

func recordAnalysisBundles(m *sarif.ScanMetadata, chunks []chunk.Chunk, contextLimit int, recovery bool) {
	for _, c := range chunks {
		// Include cross-file context: equal XML with different manifests or
		// dependency summaries is a different bundle.
		content, _ := json.Marshal(struct {
			XML      string
			Manifest []string
		}{c.XML, analysisManifest(c, contextLimit)})
		label := fmt.Sprintf("analysis %d/%d", c.Index+1, c.Total)
		if recovery {
			label = "recovery " + label
		}
		recordSourceBundle(m, "analysis", label, string(content))
	}
}

type sourceCoverage struct {
	index    *sourceindex.Index
	planned  map[string]int
	analyzed map[string]bool
}

func newSourceCoverage(index *sourceindex.Index) *sourceCoverage {
	return &sourceCoverage{index: index, planned: map[string]int{}, analyzed: map[string]bool{}}
}
func (c *sourceCoverage) plan(chunks []chunk.Chunk) {
	for _, ch := range chunks {
		for _, p := range ch.Paths {
			c.planned[p]++
		}
	}
}
func (c *sourceCoverage) complete(paths []string, doc sarif.SARIFDocument, err error) {
	if err != nil || len(doc.Runs) == 0 || scanExecutionError(doc) != nil {
		return
	}
	for _, p := range paths {
		c.analyzed[p] = true
	}
}
func (c *sourceCoverage) report() *sarif.SourceCoverage {
	r := &sarif.SourceCoverage{Admitted: len(c.index.Paths()), Unplanned: []string{}, Unanalyzed: []string{}}
	for _, p := range c.index.Paths() {
		if c.planned[p] > 0 {
			r.Planned++
		} else {
			r.Unplanned = append(r.Unplanned, p)
		}
		if c.analyzed[p] {
			r.Analyzed++
		} else {
			r.Unanalyzed = append(r.Unanalyzed, p)
		}
		if c.planned[p] > 1 {
			r.RepeatedFiles++
		}
	}
	return r
}
