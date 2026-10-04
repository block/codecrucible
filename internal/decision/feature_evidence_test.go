package decision

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestFeatureBatchesCoverEveryLineWithinBudget(t *testing.T) {
	files := map[string]string{"large.kt": strings.Repeat("fun example() { println(\"日本語\") }\n", 1200)}
	for i := range 100 {
		files[fmt.Sprintf("very/long/path/to/package/with/many/files/%03d.kt", i)] = "package example\nfun short() {}\n"
	}
	batches, complete := FeatureEvidenceBatches(files, 18000)
	if !complete || len(batches) < 2 {
		t.Fatalf("coverage=%v batches=%d", complete, len(batches))
	}
	next := map[string]int{}
	for _, batch := range batches {
		encoded, _ := json.Marshal(batch)
		if len(encoded) > 18000 {
			t.Fatalf("oversized batch: %d", len(encoded))
		}
		for _, e := range batch {
			if next[e.Path] == 0 {
				next[e.Path] = 1
			}
			want, ok := SourceEvidence(e.Path, files[e.Path], e.Start, e.End)
			if !ok || !reflect.DeepEqual(e, want) || e.Start != next[e.Path] {
				t.Fatalf("missing, duplicated or altered source range: %+v", e)
			}
			next[e.Path] = e.End + 1
		}
	}
	for path, content := range files {
		if next[path] != len(strings.Split(strings.TrimSuffix(content, "\n"), "\n"))+1 {
			t.Fatalf("uncovered source: %s", path)
		}
	}
	again, _ := FeatureEvidenceBatches(files, 18000)
	if !reflect.DeepEqual(batches, again) {
		t.Fatal("unstable source batching")
	}
}

func TestFeatureBatchesReportUnrepresentableLines(t *testing.T) {
	files := map[string]string{"large.kt": "before\n" + strings.Repeat("x", 20000) + "\nafter\n"}
	batches, complete := FeatureEvidenceBatches(files, 18000)
	if complete || len(batches) == 0 {
		t.Fatal("oversized line silently lost or all useful source discarded")
	}
	var starts []int
	for _, batch := range batches {
		for _, e := range batch {
			starts = append(starts, e.Start)
		}
	}
	if !reflect.DeepEqual(starts, []int{1, 3}) {
		t.Fatalf("lost representable source: %v", starts)
	}
	if _, complete := FeatureEvidenceBatches(nil, 18000); complete {
		t.Fatal("empty scan certified complete feature evidence")
	}
}

func TestFeatureBatchesKeepFittingFilesTogether(t *testing.T) {
	files := map[string]string{"a.kt": strings.Repeat("fun a() {}\n", 100), "b.kt": strings.Repeat("fun b() {}\n", 100)}
	batches, complete := FeatureEvidenceBatches(files, 4000)
	if !complete || len(batches) != 2 {
		t.Fatalf("complete=%v batches=%d", complete, len(batches))
	}
	for _, batch := range batches {
		for _, e := range batch {
			if e.Path != batch[0].Path {
				t.Fatal("split a file unnecessarily")
			}
		}
	}
}
