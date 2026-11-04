package auditctx

import (
	"github.com/block/codecrucible/internal/auditcore"
	"strings"
	"testing"
)

func TestBundleBoundedAndRepeatable(t *testing.T) {
	ix := NewIndex(map[string]string{"a.go": "package a\nfunc f(){sink(input)}\n", "b.go": "package a\nfunc guard() {}\n"})
	count := func(s string) int { return len(s) }
	claims := []Claim{{"a.go", 2, 2}}
	extras := []Excerpt{{"b.go", 2, 2, "guard"}, {"missing.go", 1, 1, "guard"}}
	a := ix.Bundle(claims, extras, 1000, count)
	b := ix.Bundle(claims, extras, 1000, count)
	if a.Fingerprint != b.Fingerprint || !strings.Contains(a.Text, "2| func guard") {
		t.Fatal(a, b)
	}
	if _, ok := ix.Verify(a, auditcore.Evidence{File: "b.go", Start: 2, End: 2, Quote: "guard()"}); !ok {
		t.Fatal("admitted quote rejected")
	}
	small := ix.Bundle(claims, extras, 1, count)
	if _, ok := ix.Verify(small, auditcore.Evidence{File: "b.go", Start: 2, End: 2, Quote: "guard()"}); ok {
		t.Fatal("unsent quote accepted")
	}
	if len(small.Omitted) == 0 {
		t.Fatal("omissions lost")
	}
}
