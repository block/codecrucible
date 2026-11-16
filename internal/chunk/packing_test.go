package chunk

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/block/codecrucible/internal/ingest"
)

func TestChunkSelectsGroupingWithoutLosingFilesOrSummaries(t *testing.T) {
	files := ingest.FileMap{}
	counter := NewTokenCounter("", nil)
	for _, p := range []string{"a/one.ts", "a/two.ts", "b/one.ts", "b/two.ts"} {
		files[p] = strings.Repeat("export const value = 123;\n", 100)
	}
	// Fit two ordinary files per chunk, plus wrapper and a small shared file.
	budget := 2*counter.Count(BuildFileXML("a/one.ts", files["a/one.ts"])) + 150
	files["main.ts"] = "import './a/one';"
	for _, tc := range []struct {
		name  string
		graph map[string][]string
		want  [][]string
	}{
		{
			"imports improve colocation",
			map[string][]string{"a/one.ts": {"b/one.ts"}, "a/two.ts": {"b/two.ts"}, "main.ts": {"a/one.ts"}},
			[][]string{{"a/one.ts", "b/one.ts", "main.ts"}, {"a/two.ts", "b/two.ts", "main.ts"}},
		},
		{
			"directory baseline has more colocated edges",
			map[string][]string{"a/one.ts": {"b/one.ts"}, "a/two.ts": {"a/one.ts"}, "b/one.ts": {"b/two.ts"}, "b/two.ts": {"b/one.ts"}, "main.ts": {"a/one.ts"}},
			[][]string{{"a/one.ts", "a/two.ts", "main.ts"}, {"b/one.ts", "b/two.ts", "main.ts"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			summaries := map[string]string{}
			for p := range files {
				summaries[p] = "declares value"
			}
			chunks, err := NewChunker(counter, nil).Chunk(ingest.FlattenResult{FileMap: files}, budget, &ChunkOptions{ImportGraph: tc.graph, ExportSummaries: summaries})
			if err != nil {
				t.Fatal(err)
			}
			var paths [][]string
			seen := map[string]int{}
			for _, c := range chunks {
				paths = append(paths, c.Paths)
				if c.Tokens > budget {
					t.Errorf("chunk %d exceeded budget: %d > %d", c.Index, c.Tokens, budget)
				}
				members := map[string]bool{}
				for _, p := range c.Paths {
					members[p] = true
					seen[p]++
				}
				for _, p := range c.Paths {
					for _, target := range tc.graph[p] {
						if !members[target] && !strings.Contains(strings.Join(c.RelatedSummaries, "\n"), target+": declares value") {
							t.Errorf("missing cross-chunk summary for %s", target)
						}
					}
				}
			}
			if !reflect.DeepEqual(paths, tc.want) {
				t.Errorf("paths = %v, want %v", paths, tc.want)
			}
			for p := range files {
				want := 1
				if p == "main.ts" {
					want = len(chunks)
				}
				if seen[p] != want {
					t.Errorf("%s appears %d times, want %d", p, seen[p], want)
				}
			}
		})
	}
}

func TestChunkGraphCannotWorsenDirectoryPacking(t *testing.T) {
	files, graph := ingest.FileMap{}, map[string][]string{}
	for i := 0; i < 18; i++ {
		p := fmt.Sprintf("pkg%d/file%d.ts", i/3, i%3)
		files[p] = strings.Repeat("const data = 'value';\n", 40+i*7)
		for _, n := range []int{(i + 4) % 18, (i + 1) % 18} {
			graph[p] = append(graph[p], fmt.Sprintf("pkg%d/file%d.ts", n/3, n%3))
		}
	}
	files["main.ts"] = "entrypoint()"
	input := ingest.FlattenResult{FileMap: files}
	ch := newTestChunker("")
	// Measure the actual chunks independently of the internal candidate score.
	measure := func(chunks []Chunk) (map[string]int, int, int) {
		counts, edges := map[string]int{}, map[[2]string]bool{}
		for _, c := range chunks {
			members := map[string]bool{}
			for _, p := range c.Paths {
				members[p] = true
				counts[p]++
			}
			for p := range members {
				for _, target := range graph[p] {
					if members[target] {
						edges[[2]string{p, target}] = true
					}
				}
			}
		}
		bytes := 0
		for p, count := range counts {
			bytes += (count - 1) * len(files[p])
		}
		return counts, len(edges), bytes
	}
	for _, budget := range []int{1800, 2400, 3500, 6000} {
		baseline, err := ch.Chunk(input, budget, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ch.Chunk(input, budget, &ChunkOptions{ImportGraph: graph})
		if err != nil {
			t.Fatal(err)
		}
		baseFiles, baseEdges, baseBytes := measure(baseline)
		gotFiles, gotEdges, gotBytes := measure(got)
		if len(got) > len(baseline) || gotEdges < baseEdges || gotBytes > baseBytes {
			t.Errorf("budget %d worsened packing: chunks %d/%d edges %d/%d duplicated bytes %d/%d", budget, len(got), len(baseline), gotEdges, baseEdges, gotBytes, baseBytes)
		}
		if len(gotFiles) != len(baseFiles) {
			t.Fatal("grouping changed source coverage")
		}
		for p := range baseFiles {
			if gotFiles[p] == 0 || (p != "main.ts" && gotFiles[p] != 1) {
				t.Errorf("source file lost or duplicated: %s", p)
			}
		}
		for _, c := range got {
			if c.Tokens > budget {
				t.Errorf("budget %d exceeded by chunk of %d tokens", budget, c.Tokens)
			}
		}
		// Input map and import iteration order must not affect either choice.
		reordered := map[string][]string{}
		for p, imports := range graph {
			reordered[p] = []string{imports[1], imports[0]}
		}
		again, err := ch.Chunk(input, budget, &ChunkOptions{ImportGraph: reordered})
		if err != nil || !reflect.DeepEqual(got, again) {
			t.Fatal("packing depends on import order", err)
		}
	}
}
