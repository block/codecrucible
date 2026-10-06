package tokenestimate

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

func TestEncodingsProduceDifferentCounts(t *testing.T) {
	// cl100k encodes this as 9 tokens; o200k as 8. Count adds 10%.
	for _, tc := range []struct {
		encoding string
		want     int
	}{{"cl100k_base", 10}, {"o200k_base", 9}} {
		e := New(Model{Encoding: tc.encoding}, nil)
		if got := e.Count("お誕生日おめでとう"); got != tc.want {
			t.Errorf("%s: got %d, want %d", tc.encoding, got, tc.want)
		}
		if e.Count("") != 0 || !strings.Contains(e.Method(), tc.encoding) {
			t.Fatalf("invalid empty count or strategy for %s", tc.encoding)
		}
	}
}

func TestUnsupportedEncodingsUseExplicitFallback(t *testing.T) {
	text := "func main() { println(42) }"
	for _, encoding := range []string{"", "heuristic", "claude", "unknown"} {
		e := New(Model{Encoding: encoding}, nil)
		if e.Method() != "heuristic" || e.Count(text) != heuristicCount(text) {
			t.Errorf("%q did not use heuristic fallback", encoding)
		}
	}
}

type countFunc func(string) (int, error)

func (f countFunc) Count(s string) (int, error) { return f(s) }

func TestSamplingBoundsWorkAndPreservesUTF8(t *testing.T) {
	e := New(Model{}, nil)
	bytes := 0
	e.codec = countFunc(func(s string) (int, error) {
		if !utf8.ValidString(s) {
			t.Fatal("sample split a UTF-8 character")
		}
		bytes += len(s)
		return utf8.RuneCountInString(s), nil
	})
	text := strings.Repeat("界", 1_000_000)
	if got := e.Count(text); got != 1_100_000 {
		t.Errorf("scaled count = %d, want 1100000", got)
	}
	if bytes > 3*sampleWindow {
		t.Fatalf("tokenized %d bytes of a large input", bytes)
	}
}

func TestTokenizerFailureFallsBack(t *testing.T) {
	e := New(Model{}, nil)
	e.codec = countFunc(func(string) (int, error) { return 0, errors.New("failed") })
	text := strings.Repeat("func main() {}\n", 1000)
	if got := e.Count(text); got != heuristicCount(text) {
		t.Fatalf("fallback count = %d", got)
	}
}

func TestCountConcurrent(t *testing.T) {
	e := New(Model{Encoding: "o200k_base"}, nil)
	text := strings.Repeat("func main() { println(42) }\n", 200)
	want := e.Count(text)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := e.Count(text); got != want {
				t.Errorf("concurrent count = %d, want %d", got, want)
			}
		}()
	}
	wg.Wait()
}

func BenchmarkCountLargeSource(b *testing.B) {
	text := strings.Repeat("func main() { println(42) }\n", 100_000)
	for _, encoding := range []string{"heuristic", "cl100k_base", "o200k_base"} {
		b.Run(encoding, func(b *testing.B) {
			e := New(Model{Encoding: encoding}, nil)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				e.Count(text)
			}
		})
	}
}
