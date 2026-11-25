package chunk

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/block/codecrucible/internal/ingest"
)

func TestSplitPreservesCoverageManifestAndSummaries(t *testing.T) {
	counter := NewTokenCounter("unknown", nil)
	chunker := NewChunker(counter, nil)
	files := ingest.FileMap{"src/a.go": "package p\nvar A = B\n", "src/b.go": "package p\nvar B = 1\n"}
	parent := Chunk{Paths: []string{"src/a.go", "src/b.go"}, Manifest: []string{"src/a.go", "src/b.go", "elsewhere.go"}}
	opts := &ChunkOptions{ImportGraph: map[string][]string{"src/a.go": {"src/b.go"}}, ExportSummaries: map[string]string{"src/b.go": "exports B"}}
	children, err := chunker.Split(parent, files, 10000, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(children) != 2 {
		t.Fatalf("children=%d", len(children))
	}
	seen := map[string]int{}
	for i, ch := range children {
		if ch.Index != i || ch.Total != 2 || ch.Tokens != counter.Count(ch.XML) || !strings.Contains(ch.XML, fmt.Sprintf(`<metadata index="%d" total="2"`, i)) {
			t.Fatalf("invalid child: %+v", ch)
		}
		if !reflect.DeepEqual(ch.Manifest, parent.Manifest) {
			t.Fatalf("lost manifest: %v", ch.Manifest)
		}
		for _, p := range ch.Paths {
			seen[p]++
		}
	}
	if seen["src/a.go"] != 1 || seen["src/b.go"] != 1 {
		t.Fatalf("coverage=%v", seen)
	}
	if !reflect.DeepEqual(children[0].RelatedSummaries, []string{"src/b.go: exports B"}) {
		t.Fatalf("summaries=%v", children[0].RelatedSummaries)
	}
}

func TestSplitRejectsSingletonAndMissingSource(t *testing.T) {
	chunker := newTestChunker("unknown")
	for _, paths := range [][]string{{"a.go"}, {"a.go", "missing.go"}} {
		if _, err := chunker.Split(Chunk{Paths: paths}, ingest.FileMap{"a.go": "package p"}, 10000, nil); err == nil {
			t.Fatalf("accepted %v", paths)
		}
	}
}

func TestReindexRendersSourceAndRecountsTokens(t *testing.T) {
	counter := NewTokenCounter("unknown", nil)
	chunker := NewChunker(counter, nil)
	files := ingest.FileMap{"a.go": "// <metadata index=\"0\" total=\"1\" />\npackage p"}
	original := Chunk{Paths: []string{"a.go"}, XML: "stale", Tokens: 99999, Total: 1}
	combined := make([]Chunk, 12)
	for i := range combined {
		combined[i] = original
	}
	got, err := chunker.Reindex(combined, files)
	if err != nil {
		t.Fatal(err)
	}
	for i, ch := range got {
		if !strings.HasPrefix(ch.XML, chunkHeader(i, 12)) || !strings.Contains(ch.XML, BuildFileXML("a.go", files["a.go"])) || ch.Tokens != counter.Count(ch.XML) {
			t.Fatalf("bad render %+v", ch)
		}
	}
	if combined[0].XML != "stale" {
		t.Fatal("mutated input")
	}
}
