package chunk

import (
	"log/slog"
	"strings"
	"testing"
)

func TestNewTokenCounter_NilLogger(t *testing.T) {
	tc := NewTokenCounter("cl100k_base", nil)
	if tc.logger == nil {
		t.Error("nil logger should be replaced with default")
	}
}

func TestCount_EmptyString(t *testing.T) {
	tc := NewTokenCounter("cl100k_base", slog.Default())
	if got := tc.Count(""); got != 0 {
		t.Errorf("Count(\"\") = %d, want 0", got)
	}
}

func TestCount_NonEmpty(t *testing.T) {
	tc := NewTokenCounter("cl100k_base", slog.Default())
	got := tc.Count("hello world")
	if got <= 0 {
		t.Errorf("Count(\"hello world\") should be > 0, got %d", got)
	}
}

func TestHeuristicCount_Prose(t *testing.T) {
	// Alphabetic text has zero punctuation → 4.0 chars/token ratio.
	tests := []struct {
		name string
		text string
		want int // ceil(len(bytes)/4.0 * 1.1)
	}{
		{"4 chars", "abcd", 2},          // 4/4=1, *1.1=1.1, ceil=2
		{"8 chars", "abcdefgh", 3},      // 8/4=2, *1.1=2.2, ceil=3
		{"12 chars", "abcdefghijkl", 4}, // 12/4=3, *1.1=3.3, ceil=4
		{"1 char", "a", 1},              // 1/4=0.25, *1.1=0.275, ceil=1
		{"empty", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := heuristicCount(tt.text)
			if got != tt.want {
				t.Errorf("heuristicCount(%q) = %d, want %d", tt.text, got, tt.want)
			}
		})
	}
}

func TestHeuristicCount_CodeDenserThanProse(t *testing.T) {
	// Same byte length, different punctuation density → code should
	// produce a higher token estimate.
	prose := "the quick brown fox jumps over the lazy dog again and again today"
	code := "if(a->b){x[i]=f(y,z);r=*p&&q;}else{g();h(m|n);}/*t*/return(v!=w);"
	if len(prose) != len(code) {
		t.Fatalf("test inputs must be equal length: prose=%d code=%d", len(prose), len(code))
	}
	proseTokens := heuristicCount(prose)
	codeTokens := heuristicCount(code)
	if codeTokens <= proseTokens {
		t.Errorf("code should estimate higher than prose at equal byte length: code=%d prose=%d", codeTokens, proseTokens)
	}
}

func TestCharsPerTokenRatio(t *testing.T) {
	tests := []struct {
		name string
		text string
		want float64
	}{
		{"empty", "", 4.0},
		{"prose", "the quick brown fox jumps over the lazy dog and runs through the field", 4.0},
		{"light punct", "one. two. three. four. five six seven eight nine.", 3.5},
		{"c code", "void f(int *p) { if (p != NULL) { *p = (a + b) * c; } }", 3.0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := charsPerTokenRatio(tt.text)
			if got != tt.want {
				t.Errorf("charsPerTokenRatio(%q) = %v, want %v", tt.text, got, tt.want)
			}
		})
	}
}

func TestCount_LargeInput(t *testing.T) {
	tc := NewTokenCounter("cl100k_base", slog.Default())

	// Generate a large input.
	var b strings.Builder
	for i := 0; i < 1000; i++ {
		b.WriteString("func handler(w http.ResponseWriter, r *http.Request) {\n")
		b.WriteString("\tw.Write([]byte(\"hello\"))\n")
		b.WriteString("}\n\n")
	}

	tokens := tc.Count(b.String())
	if tokens <= 0 {
		t.Errorf("large input should have positive token count, got %d", tokens)
	}

	// Each handler is ~84 bytes → ~23 heuristic tokens. 1000 handlers → ~23000.
	if tokens < 5000 || tokens > 50000 {
		t.Errorf("token count %d seems unreasonable for 1000 handler functions", tokens)
	}
}
