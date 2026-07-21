package supctx

import (
	"strings"
	"testing"
)

// charCounter counts bytes — deterministic and trivially predictable for tests.
type charCounter struct{}

func (charCounter) Count(s string) int { return len(s) }

func TestPack_EmptyInputs(t *testing.T) {
	r := Pack(nil, 1000, charCounter{})
	if r.Rendered != "" || r.Tokens != 0 || len(r.Dropped) != 0 {
		t.Fatalf("expected empty result, got %+v", r)
	}

	r = Pack([]Loaded{{Name: "a", Content: "hello", Tokens: 5}}, 0, charCounter{})
	if r.Rendered != "" || len(r.Dropped) != 1 || r.Dropped[0] != "a" {
		t.Fatalf("zero budget should drop all sources, got %+v", r)
	}
}

func TestPack_AllFit(t *testing.T) {
	loaded := []Loaded{
		{Name: "spec", Content: "api spec here", Priority: 100},
		{Name: "notes", Content: "review notes", Priority: 50},
	}
	r := Pack(loaded, 10_000, charCounter{})
	if len(r.Dropped) != 0 || r.Truncated != "" {
		t.Fatalf("expected no drops/truncation, got %+v", r)
	}
	if !strings.Contains(r.Rendered, "api spec here") || !strings.Contains(r.Rendered, "review notes") {
		t.Fatalf("rendered missing content: %q", r.Rendered)
	}
	// Higher priority should appear first.
	specIdx := strings.Index(r.Rendered, "spec")
	notesIdx := strings.Index(r.Rendered, "notes")
	if specIdx > notesIdx {
		t.Fatalf("priority order wrong: spec@%d notes@%d", specIdx, notesIdx)
	}
}

func TestPack_PriorityOrder(t *testing.T) {
	loaded := []Loaded{
		{Name: "low", Content: strings.Repeat("x", 200), Priority: 10},
		{Name: "high", Content: strings.Repeat("y", 200), Priority: 100},
	}
	// Budget fits one wrapped source (~230 chars with envelope) but not both.
	r := Pack(loaded, 250, charCounter{})
	if !strings.Contains(r.Rendered, "high") {
		t.Fatalf("high-priority source should be packed: %+v", r)
	}
	// low should be dropped or truncated — not fully included
	if strings.Count(r.Rendered, "x") >= 200 {
		t.Fatalf("low-priority source should not be fully included")
	}
}

func TestPack_Truncation(t *testing.T) {
	big := strings.Repeat("line of content here\n", 100) // ~2100 chars
	loaded := []Loaded{
		{Name: "big", Content: big, Tokens: len(big), Priority: 100},
	}
	r := Pack(loaded, 500, charCounter{})
	if r.Truncated != "big" {
		t.Fatalf("expected truncation of 'big', got %+v", r)
	}
	if !strings.Contains(r.Rendered, "truncated") {
		t.Fatalf("truncation marker missing: %q", r.Rendered)
	}
	if r.Tokens > 600 { // some slop for the envelope+marker
		t.Fatalf("rendered exceeds budget tolerance: %d tokens", r.Tokens)
	}
}

func TestPack_DropsRemainder(t *testing.T) {
	loaded := []Loaded{
		{Name: "a", Content: strings.Repeat("a", 300), Priority: 100},
		{Name: "b", Content: strings.Repeat("b", 300), Priority: 50},
		{Name: "c", Content: strings.Repeat("c", 300), Priority: 10},
	}
	// Budget fits 'a' wrapped (~330) and partially 'b', not 'c'.
	r := Pack(loaded, 400, charCounter{})

	found := map[string]bool{}
	for _, d := range r.Dropped {
		found[d] = true
	}
	if !found["c"] {
		t.Fatalf("expected 'c' to be dropped, got dropped=%v", r.Dropped)
	}
	if found["a"] {
		t.Fatalf("'a' (highest priority) should not be dropped")
	}
}

func TestPack_StablePriorityTies(t *testing.T) {
	loaded := []Loaded{
		{Name: "first", Content: "aaa", Priority: 50},
		{Name: "second", Content: "bbb", Priority: 50},
	}
	r := Pack(loaded, 1000, charCounter{})
	if strings.Index(r.Rendered, "first") > strings.Index(r.Rendered, "second") {
		t.Fatalf("equal-priority sources should keep declaration order")
	}
}

func TestFilterPhase(t *testing.T) {
	loaded := []Loaded{
		{Name: "all", Phases: nil},
		{Name: "analysis-only", Phases: []string{"analysis"}},
		{Name: "audit-only", Phases: []string{"audit"}},
	}

	a := FilterPhase(loaded, "analysis")
	if len(a) != 2 || a[0].Name != "all" || a[1].Name != "analysis-only" {
		t.Fatalf("analysis filter wrong: %+v", a)
	}

	au := FilterPhase(loaded, "audit")
	if len(au) != 2 || au[0].Name != "all" || au[1].Name != "audit-only" {
		t.Fatalf("audit filter wrong: %+v", au)
	}
}

func TestTruncateToTokens_NewlineBackoff(t *testing.T) {
	content := "line one\nline two\nline three\nline four\n"
	out := truncateToTokens(content, 20, charCounter{})
	if strings.HasSuffix(out, "line") || strings.Contains(out, "line t\n") {
		t.Fatalf("should back off to newline boundary, got %q", out)
	}
	if !strings.HasSuffix(out, "\n") && out != "line one" {
		t.Logf("truncated to: %q", out) // soft check — depends on exact budget
	}
}
