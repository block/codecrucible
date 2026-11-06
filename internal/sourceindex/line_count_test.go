package sourceindex

import "testing"

func TestSourceLineCounts(t *testing.T) {
	for _, tc := range []struct {
		text string
		n    int
	}{{"", 1}, {"one", 1}, {"one\n", 1}, {"one\ntwo\n", 2}, {"one\n\n", 2}} {
		ix := New(map[string]string{"a.go": tc.text})
		if n := len(ix.Lines("a.go")); n != tc.n {
			t.Fatalf("%q lines=%d want %d", tc.text, n, tc.n)
		}
	}
}
