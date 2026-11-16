package cli

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/block/codecrucible/internal/auditctx"
	"github.com/block/codecrucible/internal/chunk"
	"github.com/block/codecrucible/internal/sarif"
	"github.com/block/codecrucible/internal/sourceindex"
)

var sourceCitation = regexp.MustCompile(`([\w./-]+\.[\w]+):(\d+)(?:[-–](\d+))?`)

// citedAuditContext carries forward source references in the original claim.
// Only admitted local files and valid bounded ranges can enter the context.
func citedAuditContext(index *auditctx.Index, source *sourceindex.Index, claims []auditClaim, sent map[string]bool, counter *chunk.TokenCounter) (string, int) {
	files := sarif.FileMap{}
	for _, p := range source.Paths() {
		content, _ := source.Content(p)
		files[p] = content
	}
	var excerpts []auditctx.Excerpt
	for _, claim := range claims {
		for _, m := range sourceCitation.FindAllStringSubmatch(claim.UnverifiedExploitSketch, -1) {
			path, ok := sarif.ResolvePath(files, m[1])
			if !ok || sent[path] {
				continue
			}
			start, _ := strconv.Atoi(m[2])
			end := start
			if m[3] != "" {
				end, _ = strconv.Atoi(m[3])
			}
			n := len(source.Lines(path))
			if start < 1 || start > n || end < start {
				continue
			}
			excerpts = append(excerpts, auditctx.Excerpt{File: path, Start: max(1, start-2), End: min(n, min(end+2, start+80)), Reason: "original claim citation"})
		}
	}
	text, n := auditctx.Render(index, excerpts, auditRetrievalBudget/2, counter.Count)
	if n < len(excerpts) {
		text += fmt.Sprintf("\nAudit context is incomplete: some of %d cited ranges could not be included. Missing context does not refute a claim.\n", len(excerpts))
	}
	return strings.TrimSpace(text) + "\n", n
}
