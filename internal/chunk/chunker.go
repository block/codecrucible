package chunk

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"

	"github.com/block/codecrucible/internal/ingest"
)

// Chunk represents a self-contained XML document with a subset of repository files.
type Chunk struct {
	XML              string   // Self-contained XML document for this chunk.
	Index            int      // 0-based index of this chunk.
	Total            int      // Total number of chunks.
	Paths            []string // File paths included in this chunk.
	Manifest         []string // ALL repository file paths (for cross-file context).
	Tokens           int      // Estimated token count for this chunk's XML.
	RelatedSummaries []string // One-line summaries of files related to this chunk but not included.
}

// ChunkOptions provides optional import-aware grouping hints.
type ChunkOptions struct {
	// ImportGraph maps file path → list of local imports (from ingest.ResolveImports).
	ImportGraph map[string][]string
	// ExportSummaries maps file path → short one-line summary of exports.
	ExportSummaries map[string]string
}

// Chunker splits a FlattenResult into token-budget-safe chunks.
type Chunker interface {
	Chunk(input ingest.FlattenResult, budget int, opts *ChunkOptions) ([]Chunk, error)
}

// defaultChunker implements Chunker with directory-proximity grouping.
type defaultChunker struct {
	counter *TokenCounter
	logger  *slog.Logger
}

// NewChunker creates a Chunker that groups files by directory proximity
// under the given token budget, preserving file boundaries.
func NewChunker(counter *TokenCounter, logger *slog.Logger) Chunker {
	if logger == nil {
		logger = slog.Default()
	}
	return &defaultChunker{
		counter: counter,
		logger:  logger,
	}
}

// fileEntry holds precomputed data for a single file during chunking.
type fileEntry struct {
	path     string
	content  string   // prebuilt <file> XML
	tokens   int      // cached token count
	imports  []string // from ImportGraph
	priority int      // computed score
}

// Chunk splits the FlattenResult into chunks that each fit within the token budget.
// Files are grouped by import graph (if provided) or directory proximity.
// File boundaries are never broken.
// Files that individually exceed the budget are skipped with a warning.
// Every chunk's Manifest field contains ALL repository file paths.
func (c *defaultChunker) Chunk(input ingest.FlattenResult, budget int, opts *ChunkOptions) ([]Chunk, error) {
	if budget <= 0 {
		return nil, fmt.Errorf("chunk: budget must be positive, got %d", budget)
	}

	// Collect all file paths for the manifest.
	allPaths := sortedPaths(input.FileMap)

	// Handle empty input — return a single empty chunk.
	if len(allPaths) == 0 {
		tokens := input.Tokens
		if tokens == 0 {
			tokens = c.counter.Count(input.XML)
		}
		return []Chunk{{
			XML:      input.XML,
			Index:    0,
			Total:    1,
			Paths:    nil,
			Manifest: nil,
			Tokens:   tokens,
		}}, nil
	}

	// Check if the entire flattened XML fits within budget.
	// Reuse precomputed count from FlattenResult if available.
	// Skip this fast-path when input.XML is empty but FileMap is populated
	// (e.g. overflow-recovery re-chunking passes only FileMap) — otherwise
	// Count("") returns 0, the fast-path fires, and we emit an empty chunk.
	if input.XML != "" {
		totalTokens := input.Tokens
		if totalTokens == 0 {
			totalTokens = c.counter.Count(input.XML)
		}
		if totalTokens <= budget {
			return []Chunk{{
				XML:      input.XML,
				Index:    0,
				Total:    1,
				Paths:    allPaths,
				Manifest: allPaths,
				Tokens:   totalTokens,
			}}, nil
		}
	}

	// Normalise options.
	if opts == nil {
		opts = &ChunkOptions{}
	}

	// Build fileEntry structs with cached token counts and priority scores.
	entryMap := make(map[string]*fileEntry, len(allPaths))
	entries := make([]*fileEntry, 0, len(allPaths))
	for _, p := range allPaths {
		content, ok := input.FileMap[p]
		if !ok {
			continue
		}
		xml := BuildFileXML(p, content)
		e := &fileEntry{
			path:     p,
			content:  xml,
			tokens:   c.counter.Count(xml),
			imports:  opts.ImportGraph[p],
			priority: computePriority(p),
		}
		entryMap[p] = e
		entries = append(entries, e)
	}

	// Sort by priority descending, then path alphabetically for determinism.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].priority != entries[j].priority {
			return entries[i].priority > entries[j].priority
		}
		return entries[i].path < entries[j].path
	})

	// Estimate overhead for the chunk wrapper XML (metadata, tags, paths listing).
	// The manifest is handled by the prompt template, not embedded in chunk XML.
	// For the <paths> section, estimate a representative per-chunk subset rather
	// than the full repo — each chunk holds at most budget/avgFileTokens files.
	avgFileTokens := sumTokens(entries) / max(len(entries), 1)
	filesPerChunk := budget / max(avgFileTokens, 1)
	if filesPerChunk > len(entries) {
		filesPerChunk = len(entries)
	}
	representativePaths := allPaths[:min(filesPerChunk, len(allPaths))]
	overheadTokens := heuristicCount(buildChunkWrapper(0, 1, representativePaths, nil))

	effectiveBudget := budget - overheadTokens
	if effectiveBudget <= 0 {
		return nil, fmt.Errorf("chunk: budget %d too small after overhead %d", budget, overheadTokens)
	}

	// Identify shared files: high priority + small enough to duplicate.
	sharedBudget := effectiveBudget / 10 // 10% of chunk budget
	const maxSharedPerChunk = 3
	const sharedTokenCap = 500
	const sharedPriorityMin = 80

	var sharedFiles []*fileEntry
	sharedTokenTotal := 0
	for _, e := range entries {
		if e.priority >= sharedPriorityMin && e.tokens <= sharedTokenCap {
			if sharedTokenTotal+e.tokens <= sharedBudget && len(sharedFiles) < maxSharedPerChunk {
				sharedFiles = append(sharedFiles, e)
				sharedTokenTotal += e.tokens
			}
		}
	}

	sharedSet := make(map[string]bool, len(sharedFiles))
	for _, sf := range sharedFiles {
		sharedSet[sf.path] = true
	}

	hasImportGraph := len(opts.ImportGraph) > 0

	// Group files into chunks.
	assigned := make(map[string]bool)
	var groups [][]*fileEntry

	if hasImportGraph {
		// Seed-and-grow: BFS through imports.
		for _, seed := range entries {
			if assigned[seed.path] || sharedSet[seed.path] {
				continue
			}
			if seed.tokens > effectiveBudget-sharedTokenTotal {
				c.logger.Warn("file exceeds chunk budget, skipping",
					"path", seed.path,
					"file_tokens", seed.tokens,
					"budget", effectiveBudget,
				)
				assigned[seed.path] = true
				continue
			}

			group := []*fileEntry{seed}
			assigned[seed.path] = true
			groupTokens := seed.tokens + sharedTokenTotal

			// BFS through imports.
			queue := make([]string, len(seed.imports))
			copy(queue, seed.imports)
			for len(queue) > 0 {
				imp := queue[0]
				queue = queue[1:]
				if assigned[imp] || sharedSet[imp] {
					continue
				}
				ie, ok := entryMap[imp]
				if !ok {
					continue
				}
				if groupTokens+ie.tokens > effectiveBudget {
					continue
				}
				group = append(group, ie)
				assigned[imp] = true
				groupTokens += ie.tokens
				queue = append(queue, ie.imports...)
			}

			// Fill remaining budget with directory-proximity files.
			seedDir := filepath.Dir(seed.path)
			for _, e := range entries {
				if assigned[e.path] || sharedSet[e.path] {
					continue
				}
				if filepath.Dir(e.path) != seedDir {
					continue
				}
				if groupTokens+e.tokens > effectiveBudget {
					continue
				}
				group = append(group, e)
				assigned[e.path] = true
				groupTokens += e.tokens
			}

			groups = append(groups, group)
		}

		// Pick up any remaining unassigned, non-shared files.
		var remaining []*fileEntry
		for _, e := range entries {
			if !assigned[e.path] && !sharedSet[e.path] {
				remaining = append(remaining, e)
			}
		}
		if len(remaining) > 0 {
			groups = append(groups, c.packGreedy(remaining, effectiveBudget-sharedTokenTotal)...)
		}
	} else {
		// No import graph: directory-proximity sort + greedy packing (original behaviour).
		sort.Slice(entries, func(i, j int) bool {
			di := filepath.Dir(entries[i].path)
			dj := filepath.Dir(entries[j].path)
			if di != dj {
				return di < dj
			}
			return entries[i].path < entries[j].path
		})

		var packable []*fileEntry
		for _, e := range entries {
			if sharedSet[e.path] {
				continue
			}
			if e.tokens > effectiveBudget-sharedTokenTotal {
				c.logger.Warn("file exceeds chunk budget, skipping",
					"path", e.path,
					"file_tokens", e.tokens,
					"budget", effectiveBudget,
				)
				continue
			}
			packable = append(packable, e)
		}
		groups = c.packGreedy(packable, effectiveBudget-sharedTokenTotal)
	}

	// Merge small groups to maximize context window utilization.
	// After import-graph BFS or greedy grouping, some groups may be well under
	// the budget. Combining them reduces the number of LLM calls and avoids
	// duplicating prompt overhead per call.
	if len(groups) > 1 {
		preCount := len(groups)
		mergeBudget := effectiveBudget - sharedTokenTotal
		groups = c.mergeGroups(groups, mergeBudget)
		if len(groups) < preCount {
			c.logger.Info("merged chunks to maximize context utilization",
				"before", preCount,
				"after", len(groups),
			)
		}
	}

	// If all files were skipped, return a single empty chunk.
	if len(groups) == 0 {
		return []Chunk{{
			XML:      buildChunkXML(0, 1, nil, nil),
			Index:    0,
			Total:    1,
			Paths:    nil,
			Manifest: allPaths,
			Tokens:   overheadTokens,
		}}, nil
	}

	// Build a map of which chunk each file ended up in.
	fileToChunk := make(map[string]int)
	for i, group := range groups {
		for _, e := range group {
			fileToChunk[e.path] = i
		}
	}

	// Build chunk XML documents.
	total := len(groups)
	chunks := make([]Chunk, total)
	for i, group := range groups {
		// Prepend shared files to each group (if they fit).
		fullGroup := make([]*fileEntry, 0, len(sharedFiles)+len(group))
		for _, sf := range sharedFiles {
			// Don't duplicate if already in group.
			already := false
			for _, g := range group {
				if g.path == sf.path {
					already = true
					break
				}
			}
			if !already {
				fullGroup = append(fullGroup, sf)
			}
		}
		fullGroup = append(fullGroup, group...)

		// Sort paths within chunk for deterministic output.
		sort.Slice(fullGroup, func(a, b int) bool {
			return fullGroup[a].path < fullGroup[b].path
		})

		paths := make([]string, len(fullGroup))
		var filesXML strings.Builder
		for j, e := range fullGroup {
			paths[j] = e.path
			filesXML.WriteString(e.content)
		}

		// Compute cross-chunk summaries.
		var relatedSummaries []string
		if len(opts.ExportSummaries) > 0 {
			chunkPaths := make(map[string]bool, len(paths))
			for _, p := range paths {
				chunkPaths[p] = true
			}
			seen := make(map[string]bool)
			for _, e := range fullGroup {
				for _, imp := range e.imports {
					if !chunkPaths[imp] && !seen[imp] {
						seen[imp] = true
						if summary, ok := opts.ExportSummaries[imp]; ok {
							relatedSummaries = append(relatedSummaries, imp+": "+summary)
						}
					}
				}
			}
			if len(relatedSummaries) > 50 {
				relatedSummaries = relatedSummaries[:50]
			}
		}

		xml := buildChunkXMLWithFiles(i, total, paths, nil, filesXML.String())
		chunks[i] = Chunk{
			XML:              xml,
			Index:            i,
			Total:            total,
			Paths:            paths,
			Manifest:         allPaths,
			Tokens:           c.counter.Count(xml),
			RelatedSummaries: relatedSummaries,
		}
	}

	return chunks, nil
}

// mergeGroups combines small file-entry groups to maximize context window utilization.
// Groups are merged greedily: adjacent groups are combined as long as their total
// token count fits within the budget.
func (c *defaultChunker) mergeGroups(groups [][]*fileEntry, budget int) [][]*fileEntry {
	if len(groups) <= 1 {
		return groups
	}

	var merged [][]*fileEntry
	current := groups[0]
	currentTokens := sumTokens(current)

	for i := 1; i < len(groups); i++ {
		nextTokens := sumTokens(groups[i])
		if currentTokens+nextTokens <= budget {
			current = append(current, groups[i]...)
			currentTokens += nextTokens
		} else {
			merged = append(merged, current)
			current = groups[i]
			currentTokens = nextTokens
		}
	}
	merged = append(merged, current)

	return merged
}

// sumTokens returns the total token count across all file entries in a group.
func sumTokens(entries []*fileEntry) int {
	total := 0
	for _, e := range entries {
		total += e.tokens
	}
	return total
}

// packGreedy groups file entries using greedy bin packing.
func (c *defaultChunker) packGreedy(entries []*fileEntry, effectiveBudget int) [][]*fileEntry {
	var groups [][]*fileEntry
	var current []*fileEntry
	currentTokens := 0

	for _, e := range entries {
		if currentTokens+e.tokens > effectiveBudget && len(current) > 0 {
			groups = append(groups, current)
			current = nil
			currentTokens = 0
		}
		current = append(current, e)
		currentTokens += e.tokens
	}
	if len(current) > 0 {
		groups = append(groups, current)
	}

	return groups
}

// computePriority assigns a priority score to a file based on its path.
func computePriority(p string) int {
	dir := filepath.Dir(p)
	base := filepath.Base(p)
	name := strings.TrimSuffix(base, filepath.Ext(base))

	// Check directory-based priorities.
	parts := strings.Split(filepath.ToSlash(dir), "/")
	for _, part := range parts {
		switch part {
		case "routes", "handlers", "controllers", "middleware", "api":
			return 100
		}
	}

	// Check filename-based priorities.
	switch name {
	case "main", "server", "app", "index":
		return 90
	}

	// Check lib/utils/auth/security directories.
	for _, part := range parts {
		switch part {
		case "lib", "utils", "auth", "security":
			return 80
		}
	}

	// Config/data files.
	switch base {
	case "package.json", "tsconfig.json", "go.mod", "go.sum",
		"Cargo.toml", "requirements.txt", "Makefile", ".gitignore",
		"Dockerfile", "docker-compose.yml":
		return 10
	}

	return 50
}

// sortedPaths returns the sorted keys of a FileMap.
func sortedPaths(fm ingest.FileMap) []string {
	if len(fm) == 0 {
		return nil
	}
	paths := make([]string, 0, len(fm))
	for p := range fm {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}

// BuildFileXML produces the XML element for a single file with numbered lines,
// matching the format used by the flattener.
func BuildFileXML(path, content string) string {
	var b strings.Builder
	escapedPath := ingest.EscapeXMLAttr(path)
	b.WriteString(fmt.Sprintf("<file path=\"%s\">\n", escapedPath))

	if content != "" {
		lines := ingest.SplitLines(content)
		totalLines := len(lines)
		padding := len(fmt.Sprintf("%d", totalLines))

		for i, line := range lines {
			num := i + 1
			b.WriteString(fmt.Sprintf("%*d | %s\n", padding, num, ingest.EscapeXMLContent(line)))
		}
	}

	b.WriteString("</file>\n")
	return b.String()
}

// buildChunkWrapper produces the wrapper XML without file content, for overhead estimation.
func buildChunkWrapper(index, total int, paths, manifest []string) string {
	return buildChunkXMLWithFiles(index, total, paths, manifest, "")
}

// buildChunkXML produces a complete chunk XML document with file content generated from paths.
func buildChunkXML(index, total int, paths, manifest []string) string {
	return buildChunkXMLWithFiles(index, total, paths, manifest, "")
}

// buildChunkXMLWithFiles produces a complete self-contained chunk XML document.
func buildChunkXMLWithFiles(index, total int, paths, manifest []string, filesContent string) string {
	var b strings.Builder
	b.Grow(len(filesContent) + 512)

	b.WriteString("<chunk>\n")
	b.WriteString(fmt.Sprintf("<metadata index=\"%d\" total=\"%d\" />\n", index, total))

	if len(paths) > 0 {
		b.WriteString("<paths>\n")
		for _, p := range paths {
			b.WriteString(ingest.EscapeXMLContent(p))
			b.WriteByte('\n')
		}
		b.WriteString("</paths>\n")
	}

	if len(manifest) > 0 {
		b.WriteString("<manifest>\n")
		for _, p := range manifest {
			b.WriteString(ingest.EscapeXMLContent(p))
			b.WriteByte('\n')
		}
		b.WriteString("</manifest>\n")
	}

	if filesContent != "" {
		b.WriteString("<files>\n")
		b.WriteString(filesContent)
		b.WriteString("</files>\n")
	}

	b.WriteString("</chunk>\n")
	return b.String()
}
