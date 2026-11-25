package chunk

import (
	"fmt"
	"strings"

	"github.com/block/codecrucible/internal/ingest"
)

// Split reduces output work by dividing a multi-file parent into two groups
// of approximately equal source size. Each group is packed under budget and
// retains the parent's repository manifest and import-aware context. It does
// not recursively retry, split individual files, or change the model budget.
func (c *defaultChunker) Split(parent Chunk, files ingest.FileMap, budget int, opts *ChunkOptions) ([]Chunk, error) {
	if len(parent.Paths) < 2 {
		return nil, fmt.Errorf("chunk: cannot split fewer than two files")
	}
	total := 0
	for _, p := range parent.Paths {
		source, ok := files[p]
		if !ok {
			return nil, fmt.Errorf("chunk: missing source for %q", p)
		}
		total += len(source)
	}
	first, second := ingest.FileMap{}, ingest.FileMap{}
	seen := 0
	for i, p := range parent.Paths {
		if i == 0 || (i < len(parent.Paths)-1 && seen < total/2) {
			first[p] = files[p]
		} else {
			second[p] = files[p]
		}
		seen += len(files[p])
	}
	var children []Chunk
	for _, half := range []ingest.FileMap{first, second} {
		group, err := c.Chunk(ingest.FlattenResult{FileMap: half}, budget, opts)
		if err != nil {
			return nil, err
		}
		for _, child := range group {
			child.Manifest = append([]string(nil), parent.Manifest...)
			children = append(children, child)
		}
	}
	return c.Reindex(children, files)
}

// Reindex renders a combined batch from source, keeping its numbering and
// token counts consistent. It never edits XML with string replacement, which
// could leave cached token counts stale or mistake source text for metadata.
func (c *defaultChunker) Reindex(chunks []Chunk, files ingest.FileMap) ([]Chunk, error) {
	out := make([]Chunk, len(chunks))
	for i, ch := range chunks {
		var content strings.Builder
		for _, p := range ch.Paths {
			source, ok := files[p]
			if !ok {
				return nil, fmt.Errorf("chunk: missing source for %q", p)
			}
			content.WriteString(BuildFileXML(p, source))
		}
		ch.Index, ch.Total = i, len(chunks)
		ch.XML = buildChunkXMLWithFiles(i, len(chunks), ch.Paths, nil, content.String())
		ch.Tokens = c.counter.Count(ch.XML)
		out[i] = ch
	}
	return out, nil
}
