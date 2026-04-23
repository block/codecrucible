package chunk

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/block/codecrucible/internal/ingest"
)

// helper to create a FlattenResult from files.
func makeFlattenResult(files []ingest.SourceFile) ingest.FlattenResult {
	return ingest.Flatten(files, ingest.FlattenConfig{})
}

func newTestChunker(encoding string) Chunker {
	tc := NewTokenCounter(encoding, slog.Default())
	return NewChunker(tc, slog.Default())
}

func TestChunk_EmptyInput(t *testing.T) {
	ch := newTestChunker("cl100k_base")
	input := makeFlattenResult(nil)

	chunks, err := ch.Chunk(input, 10000, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk, got %d", len(chunks))
	}

	c := chunks[0]
	if c.Index != 0 {
		t.Errorf("Index = %d, want 0", c.Index)
	}
	if c.Total != 1 {
		t.Errorf("Total = %d, want 1", c.Total)
	}
	if c.Paths != nil {
		t.Errorf("Paths should be nil for empty input, got %v", c.Paths)
	}
	if c.Manifest != nil {
		t.Errorf("Manifest should be nil for empty input, got %v", c.Manifest)
	}
	if c.Tokens <= 0 {
		t.Errorf("Tokens should be > 0 (empty XML still has structure), got %d", c.Tokens)
	}
}

func TestChunk_SingleFileWithinBudget(t *testing.T) {
	ch := newTestChunker("cl100k_base")
	files := []ingest.SourceFile{
		{Path: "main.go", Content: "package main\n\nfunc main() {}\n", LineCount: 3, Language: "go"},
	}
	input := makeFlattenResult(files)

	chunks, err := ch.Chunk(input, 100000, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk for small input, got %d", len(chunks))
	}

	c := chunks[0]
	if c.Index != 0 {
		t.Errorf("Index = %d, want 0", c.Index)
	}
	if c.Total != 1 {
		t.Errorf("Total = %d, want 1", c.Total)
	}
	if len(c.Paths) != 1 || c.Paths[0] != "main.go" {
		t.Errorf("Paths = %v, want [main.go]", c.Paths)
	}
	if len(c.Manifest) != 1 || c.Manifest[0] != "main.go" {
		t.Errorf("Manifest = %v, want [main.go]", c.Manifest)
	}
	// Single chunk should use the original flattened XML.
	if c.XML != input.XML {
		t.Error("single chunk should return original flattened XML")
	}
}

func TestChunk_MultipleFilesWithinBudget(t *testing.T) {
	ch := newTestChunker("cl100k_base")
	files := []ingest.SourceFile{
		{Path: "a.go", Content: "package a\n", LineCount: 1, Language: "go"},
		{Path: "b.go", Content: "package b\n", LineCount: 1, Language: "go"},
		{Path: "c.go", Content: "package c\n", LineCount: 1, Language: "go"},
	}
	input := makeFlattenResult(files)

	chunks, err := ch.Chunk(input, 100000, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk, got %d", len(chunks))
	}

	c := chunks[0]
	if len(c.Paths) != 3 {
		t.Errorf("Paths should have 3 entries, got %d", len(c.Paths))
	}
	if len(c.Manifest) != 3 {
		t.Errorf("Manifest should have 3 entries, got %d", len(c.Manifest))
	}
}

func TestChunk_OversizedRepoProducesMultipleChunks(t *testing.T) {
	ch := newTestChunker("cl100k_base")

	// Create many files that will exceed a small budget.
	var files []ingest.SourceFile
	for i := 0; i < 50; i++ {
		content := fmt.Sprintf("package pkg%d\n\n// This is file %d with some content to consume tokens.\nfunc Handler%d() string {\n\treturn \"handler %d result\"\n}\n", i, i, i, i)
		files = append(files, ingest.SourceFile{
			Path:      fmt.Sprintf("pkg%d/handler.go", i),
			Content:   content,
			LineCount: 6,
			Language:  "go",
		})
	}
	input := makeFlattenResult(files)

	// Use a small budget that forces splitting.
	totalTokens := NewTokenCounter("cl100k_base", slog.Default()).Count(input.XML)
	budget := totalTokens / 3

	chunks, err := ch.Chunk(input, budget, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chunks) < 2 {
		t.Fatalf("expected multiple chunks, got %d (total tokens: %d, budget: %d)", len(chunks), totalTokens, budget)
	}

	// Verify each chunk is under budget.
	tc := NewTokenCounter("cl100k_base", slog.Default())
	for i, c := range chunks {
		tokens := tc.Count(c.XML)
		if tokens > budget {
			t.Errorf("chunk %d has %d tokens, exceeds budget %d", i, tokens, budget)
		}
	}
}

func TestChunk_FileBoundariesPreserved(t *testing.T) {
	ch := newTestChunker("cl100k_base")

	// Use a budget that forces 2 chunks (very small).
	// We need to make files big enough that they get split.
	bigFiles := []ingest.SourceFile{
		{Path: "alpha.go", Content: strings.Repeat("// alpha line\n", 500), LineCount: 500, Language: "go"},
		{Path: "beta.go", Content: strings.Repeat("// beta line\n", 500), LineCount: 500, Language: "go"},
	}
	input := makeFlattenResult(bigFiles)

	tc := NewTokenCounter("cl100k_base", slog.Default())
	totalTokens := tc.Count(input.XML)
	budget := totalTokens / 2

	chunks, err := ch.Chunk(input, budget, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify no file appears in two chunks (file boundaries preserved).
	seen := make(map[string]int)
	for i, c := range chunks {
		for _, p := range c.Paths {
			if prev, ok := seen[p]; ok {
				t.Errorf("file %q appears in chunk %d and chunk %d (file boundary broken)", p, prev, i)
			}
			seen[p] = i
		}
	}
}

func TestChunk_DirectoryProximityGrouping(t *testing.T) {
	ch := newTestChunker("cl100k_base")

	// Create files in different directories with enough content to force splitting.
	files := []ingest.SourceFile{
		{Path: "api/handler_a.go", Content: strings.Repeat("// api handler a\n", 200), LineCount: 200, Language: "go"},
		{Path: "api/handler_b.go", Content: strings.Repeat("// api handler b\n", 200), LineCount: 200, Language: "go"},
		{Path: "db/query_a.go", Content: strings.Repeat("// db query a\n", 200), LineCount: 200, Language: "go"},
		{Path: "db/query_b.go", Content: strings.Repeat("// db query b\n", 200), LineCount: 200, Language: "go"},
	}
	input := makeFlattenResult(files)

	tc := NewTokenCounter("cl100k_base", slog.Default())
	totalTokens := tc.Count(input.XML)
	// Budget that forces ~2 chunks.
	budget := totalTokens / 2

	chunks, err := ch.Chunk(input, budget, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(chunks) < 2 {
		t.Skipf("budget %d didn't force split (total: %d), skipping proximity test", budget, totalTokens)
	}

	// Find which chunk each file is in.
	fileChunk := make(map[string]int)
	for i, c := range chunks {
		for _, p := range c.Paths {
			fileChunk[p] = i
		}
	}

	// Files in the same directory should be in the same chunk when possible.
	if chA, ok1 := fileChunk["api/handler_a.go"]; ok1 {
		if chB, ok2 := fileChunk["api/handler_b.go"]; ok2 {
			if chA != chB {
				t.Logf("api/ files split across chunks %d and %d (acceptable if budget-constrained)", chA, chB)
			}
		}
	}

	// At minimum, files should be sorted by directory in their chunk paths.
	for _, c := range chunks {
		for i := 1; i < len(c.Paths); i++ {
			// Paths should be in directory order.
			if c.Paths[i] < c.Paths[i-1] {
				t.Errorf("paths not in directory order: %q before %q", c.Paths[i-1], c.Paths[i])
			}
		}
	}
}

func TestChunk_SingleFileExceedsBudget_SkippedWithWarning(t *testing.T) {
	ch := newTestChunker("cl100k_base")

	// Create one large file and one small file.
	files := []ingest.SourceFile{
		{Path: "huge.go", Content: strings.Repeat("// very long line of code\n", 5000), LineCount: 5000, Language: "go"},
		{Path: "small.go", Content: "package small\n", LineCount: 1, Language: "go"},
	}
	input := makeFlattenResult(files)

	// Budget that fits small.go but not huge.go.
	budget := 500

	chunks, err := ch.Chunk(input, budget, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// huge.go should be skipped; small.go should be in a chunk.
	for _, c := range chunks {
		for _, p := range c.Paths {
			if p == "huge.go" {
				t.Error("huge.go should be skipped (exceeds budget)")
			}
		}
	}

	// small.go should appear in some chunk.
	found := false
	for _, c := range chunks {
		for _, p := range c.Paths {
			if p == "small.go" {
				found = true
			}
		}
	}
	if !found {
		t.Error("small.go should appear in a chunk")
	}
}

func TestChunk_ManifestContainsAllPaths(t *testing.T) {
	ch := newTestChunker("cl100k_base")

	// Create files that will be split across multiple chunks.
	var files []ingest.SourceFile
	for i := 0; i < 30; i++ {
		files = append(files, ingest.SourceFile{
			Path:      fmt.Sprintf("dir%d/file.go", i),
			Content:   strings.Repeat(fmt.Sprintf("// content for file %d\n", i), 100),
			LineCount: 100,
			Language:  "go",
		})
	}
	input := makeFlattenResult(files)

	tc := NewTokenCounter("cl100k_base", slog.Default())
	totalTokens := tc.Count(input.XML)
	budget := totalTokens / 3

	chunks, err := ch.Chunk(input, budget, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(chunks) < 2 {
		t.Skipf("didn't produce multiple chunks, skipping manifest test")
	}

	// Every chunk's Manifest should contain ALL file paths.
	allPaths := make(map[string]bool)
	for _, f := range files {
		allPaths[f.Path] = true
	}

	for i, c := range chunks {
		manifestSet := make(map[string]bool)
		for _, p := range c.Manifest {
			manifestSet[p] = true
		}

		for p := range allPaths {
			if !manifestSet[p] {
				t.Errorf("chunk %d Manifest missing path %q", i, p)
			}
		}
	}
}

func TestChunk_MetadataCorrect(t *testing.T) {
	ch := newTestChunker("cl100k_base")

	// Create enough files to produce multiple chunks.
	var files []ingest.SourceFile
	for i := 0; i < 40; i++ {
		files = append(files, ingest.SourceFile{
			Path:      fmt.Sprintf("pkg%d/main.go", i),
			Content:   strings.Repeat(fmt.Sprintf("// line %d content padding\n", i), 100),
			LineCount: 100,
			Language:  "go",
		})
	}
	input := makeFlattenResult(files)

	tc := NewTokenCounter("cl100k_base", slog.Default())
	totalTokens := tc.Count(input.XML)
	budget := totalTokens / 4

	chunks, err := ch.Chunk(input, budget, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for i, c := range chunks {
		if c.Index != i {
			t.Errorf("chunk %d has Index=%d", i, c.Index)
		}
		if c.Total != len(chunks) {
			t.Errorf("chunk %d has Total=%d, want %d", i, c.Total, len(chunks))
		}
	}
}

func TestChunk_XMLContainsMetadata(t *testing.T) {
	ch := newTestChunker("cl100k_base")

	var files []ingest.SourceFile
	for i := 0; i < 30; i++ {
		files = append(files, ingest.SourceFile{
			Path:      fmt.Sprintf("pkg%d/file.go", i),
			Content:   strings.Repeat("// padding content\n", 200),
			LineCount: 200,
			Language:  "go",
		})
	}
	input := makeFlattenResult(files)

	tc := NewTokenCounter("cl100k_base", slog.Default())
	totalTokens := tc.Count(input.XML)
	budget := totalTokens / 3

	chunks, err := ch.Chunk(input, budget, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(chunks) < 2 {
		t.Skip("didn't produce multiple chunks")
	}

	for i, c := range chunks {
		// Check for metadata in XML.
		expectedMeta := fmt.Sprintf(`<metadata index="%d" total="%d" />`, c.Index, c.Total)
		if !strings.Contains(c.XML, expectedMeta) {
			t.Errorf("chunk %d XML missing metadata tag %q", i, expectedMeta)
		}

		// Check for <chunk> wrapper.
		if !strings.Contains(c.XML, "<chunk>") {
			t.Errorf("chunk %d XML missing <chunk> wrapper", i)
		}
		if !strings.Contains(c.XML, "</chunk>") {
			t.Errorf("chunk %d XML missing </chunk> closing tag", i)
		}

		// Manifest is no longer embedded in chunk XML (handled by prompt template).
		if strings.Contains(c.XML, "<manifest>") {
			t.Errorf("chunk %d XML should not contain <manifest> (handled by prompt)", i)
		}

		// Check for <paths> section.
		if len(c.Paths) > 0 && !strings.Contains(c.XML, "<paths>") {
			t.Errorf("chunk %d XML missing <paths> section", i)
		}

		// Check for <files> section.
		if len(c.Paths) > 0 && !strings.Contains(c.XML, "<files>") {
			t.Errorf("chunk %d XML missing <files> section", i)
		}
	}
}

func TestChunk_InvalidBudget(t *testing.T) {
	ch := newTestChunker("cl100k_base")
	input := makeFlattenResult(nil)

	_, err := ch.Chunk(input, 0, nil)
	if err == nil {
		t.Error("expected error for zero budget")
	}

	_, err = ch.Chunk(input, -100, nil)
	if err == nil {
		t.Error("expected error for negative budget")
	}
}

func TestChunk_AllFilesExceedBudget(t *testing.T) {
	ch := newTestChunker("cl100k_base")

	// Create files that all exceed a very small budget.
	files := []ingest.SourceFile{
		{Path: "big1.go", Content: strings.Repeat("// big content\n", 500), LineCount: 500, Language: "go"},
		{Path: "big2.go", Content: strings.Repeat("// big content\n", 500), LineCount: 500, Language: "go"},
	}
	input := makeFlattenResult(files)

	// Very small budget.
	chunks, err := ch.Chunk(input, 100, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should return a chunk (possibly empty of files) rather than error.
	if len(chunks) == 0 {
		t.Error("should return at least one chunk even when all files skipped")
	}

	// The chunk should have no file paths (all skipped).
	for _, c := range chunks {
		if len(c.Paths) > 0 {
			t.Errorf("all files should be skipped, but chunk has paths: %v", c.Paths)
		}
	}
}

func TestChunk_EachChunkUnderBudget(t *testing.T) {
	ch := newTestChunker("cl100k_base")

	// Use 20 files with significant content each so that budget/3 still leaves
	// room for manifest overhead per chunk.
	var files []ingest.SourceFile
	for i := 0; i < 20; i++ {
		files = append(files, ingest.SourceFile{
			Path:      fmt.Sprintf("src/pkg%d/impl.go", i),
			Content:   strings.Repeat(fmt.Sprintf("// implementation %d content\n", i), 50),
			LineCount: 50,
			Language:  "go",
		})
	}
	input := makeFlattenResult(files)

	tc := NewTokenCounter("cl100k_base", slog.Default())
	totalTokens := tc.Count(input.XML)
	budget := totalTokens / 3

	chunks, err := ch.Chunk(input, budget, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(chunks) < 2 {
		t.Fatalf("expected multiple chunks, got %d", len(chunks))
	}

	for i, c := range chunks {
		chunkTokens := tc.Count(c.XML)
		if chunkTokens > budget {
			t.Errorf("chunk %d has %d tokens, exceeds budget %d", i, chunkTokens, budget)
		}
	}
}

func TestChunk_HeuristicFallback(t *testing.T) {
	// Test with heuristic (empty encoding, simulating Gemini).
	ch := newTestChunker("")
	files := []ingest.SourceFile{
		{Path: "main.go", Content: "package main\n\nfunc main() {}\n", LineCount: 3, Language: "go"},
	}
	input := makeFlattenResult(files)

	chunks, err := ch.Chunk(input, 100000, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chunks) != 1 {
		t.Errorf("expected 1 chunk, got %d", len(chunks))
	}
	if chunks[0].Tokens <= 0 {
		t.Error("tokens should be positive even with heuristic counting")
	}
}

func TestChunk_ChunkXMLSelfContained(t *testing.T) {
	ch := newTestChunker("cl100k_base")

	// Create enough content to force multiple chunks.
	var files []ingest.SourceFile
	for i := 0; i < 50; i++ {
		files = append(files, ingest.SourceFile{
			Path:      fmt.Sprintf("dir%d/file.go", i),
			Content:   strings.Repeat(fmt.Sprintf("// content %d\n", i), 100),
			LineCount: 100,
			Language:  "go",
		})
	}
	input := makeFlattenResult(files)

	tc := NewTokenCounter("cl100k_base", slog.Default())
	totalTokens := tc.Count(input.XML)
	budget := totalTokens / 3

	chunks, err := ch.Chunk(input, budget, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(chunks) < 2 {
		t.Skip("didn't produce multiple chunks")
	}

	for i, c := range chunks {
		// Each chunk XML should be self-contained — start with <chunk> and end with </chunk>.
		if !strings.HasPrefix(c.XML, "<chunk>\n") {
			t.Errorf("chunk %d XML doesn't start with <chunk>", i)
		}
		if !strings.HasSuffix(c.XML, "</chunk>\n") {
			t.Errorf("chunk %d XML doesn't end with </chunk>", i)
		}

		// Should contain file content.
		for _, p := range c.Paths {
			if !strings.Contains(c.XML, p) {
				t.Errorf("chunk %d XML doesn't contain its file path %q", i, p)
			}
		}
	}
}

func TestChunk_SingleChunkUsesOriginalXML(t *testing.T) {
	ch := newTestChunker("cl100k_base")
	files := []ingest.SourceFile{
		{Path: "main.go", Content: "package main\n", LineCount: 1, Language: "go"},
	}
	input := makeFlattenResult(files)

	chunks, err := ch.Chunk(input, 100000, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk, got %d", len(chunks))
	}

	// The single-chunk path returns the original flattened XML (no wrapping).
	if chunks[0].XML != input.XML {
		t.Error("single chunk should use original flattened XML verbatim")
	}
}

// Regression: overflow-recovery re-chunking passes a FlattenResult with only
// FileMap populated (XML=""). The fast-path used to fire on Count("")==0 and
// emit a single chunk with empty XML and Tokens=0, sending no code to the LLM.
func TestChunk_FileMapOnlyInput_SkipsFastPath(t *testing.T) {
	ch := newTestChunker("cl100k_base")
	fm := ingest.FileMap{
		"a.go": "package a\nfunc A() {}\n",
		"b.go": "package b\nfunc B() {}\n",
		"c.go": "package c\nfunc C() {}\n",
	}
	input := ingest.FlattenResult{FileMap: fm} // XML="", Tokens=0

	chunks, err := ch.Chunk(input, 100000, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chunks) == 0 {
		t.Fatal("expected at least one chunk")
	}
	for i, c := range chunks {
		if c.XML == "" {
			t.Errorf("chunk %d: XML is empty", i)
		}
		if c.Tokens == 0 {
			t.Errorf("chunk %d: Tokens is 0", i)
		}
		for _, p := range c.Paths {
			if !strings.Contains(c.XML, p) {
				t.Errorf("chunk %d: XML missing file %s", i, p)
			}
		}
	}
}

func TestChunk_MergesSmallImportGroups(t *testing.T) {
	ch := newTestChunker("cl100k_base")

	// Create files each in their own directory with no import connections.
	// BFS will create many 1-file groups since there are no directory neighbors
	// or import links. Merging should combine them into fewer, larger chunks.
	var files []ingest.SourceFile
	importGraph := make(map[string][]string)
	for i := 0; i < 20; i++ {
		path := fmt.Sprintf("service%d/main.go", i)
		files = append(files, ingest.SourceFile{
			Path:      path,
			Content:   strings.Repeat(fmt.Sprintf("// service %d code\n", i), 50),
			LineCount: 50,
			Language:  "go",
		})
		importGraph[path] = nil
	}
	input := makeFlattenResult(files)

	tc := NewTokenCounter("cl100k_base", slog.Default())
	totalTokens := tc.Count(input.XML)
	// Budget ~1/3 of total forces chunking but allows merging groups together.
	budget := totalTokens / 3

	opts := &ChunkOptions{ImportGraph: importGraph}
	chunks, err := ch.Chunk(input, budget, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Without merging: 20 groups (one per isolated file).
	// With merging: should be ~3-4 chunks.
	if len(chunks) > 6 {
		t.Errorf("expected merging to reduce chunk count, got %d (total=%d, budget=%d)", len(chunks), totalTokens, budget)
	}

	// Verify all files are present.
	allPaths := make(map[string]bool)
	for _, c := range chunks {
		for _, p := range c.Paths {
			allPaths[p] = true
		}
	}
	if len(allPaths) != 20 {
		t.Errorf("expected 20 files in merged chunks, got %d", len(allPaths))
	}

	// Verify chunks are under budget.
	for i, c := range chunks {
		chunkTokens := tc.Count(c.XML)
		if chunkTokens > budget {
			t.Errorf("merged chunk %d has %d tokens, exceeds budget %d", i, chunkTokens, budget)
		}
	}
}

func TestEscapeXMLContent(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"no special chars", "hello world", "hello world"},
		{"empty", "", ""},
		{"ampersand", "a & b", "a &amp; b"},
		{"less than", "a < b", "a &lt; b"},
		{"greater than", "a > b", "a &gt; b"},
		{"all three", "<a> & <b>", "&lt;a&gt; &amp; &lt;b&gt;"},
		{"adjacent", "&<>", "&amp;&lt;&gt;"},
		{"quotes untouched", `"hello" 'world'`, `"hello" 'world'`},
		{"unicode preserved", "héllo & wörld", "héllo &amp; wörld"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ingest.EscapeXMLContent(tt.in); got != tt.want {
				t.Errorf("EscapeXMLContent(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestChunk_PathsAreSorted(t *testing.T) {
	ch := newTestChunker("cl100k_base")
	files := []ingest.SourceFile{
		{Path: "z.go", Content: "package z\n", LineCount: 1, Language: "go"},
		{Path: "a.go", Content: "package a\n", LineCount: 1, Language: "go"},
		{Path: "m.go", Content: "package m\n", LineCount: 1, Language: "go"},
	}
	input := makeFlattenResult(files)

	chunks, err := ch.Chunk(input, 100000, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk, got %d", len(chunks))
	}

	paths := chunks[0].Paths
	for i := 1; i < len(paths); i++ {
		if paths[i] < paths[i-1] {
			t.Errorf("paths not sorted: %q before %q", paths[i-1], paths[i])
		}
	}
}
