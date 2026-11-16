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

func TestBundleCarriesCallerOmissionNotes(t *testing.T) {
	ix := NewIndex(map[string]string{
		"handlers.ts": "export function listRecords(req, res) {\n return res.json(req.body);\n}\n",
		"router.ts":   "import { externalGuard } from 'external-library';\nrouter.get('/records', externalGuard, bindOwner, listRecords);\n",
		"one.ts":      "export function bindOwner() { return 1; }",
		"two.ts":      "export function bindOwner() { return 2; }",
	})
	count := func(s string) int { return len(s) }
	b := ix.Bundle([]Claim{{"handlers.ts", 2, 2}}, nil, 100000, count)
	text := b.PromptText()
	for _, want := range []string{"ambiguous caller reference bindOwner in router.ts", "unresolved or external caller reference externalGuard in router.ts", "absence is not refutation"} {
		if !strings.Contains(text, want) {
			t.Fatalf("prompt text lacks %q: %s", want, text)
		}
	}
	for _, o := range b.Omitted {
		if o.File == "" && o.Start == 0 && !strings.HasPrefix(o.Reason, "Audit context omitted:") {
			t.Fatalf("note recorded as a bad omission: %+v", o)
		}
		if o.Reason == "outside_scope" && o.File == "" {
			t.Fatalf("note misread as a missing file: %+v", o)
		}
	}
	// A note is not source: it can neither be included nor verify a quote.
	for _, e := range b.Included {
		if e.File == "" {
			t.Fatalf("note admitted as source: %+v", e)
		}
	}
	if again := ix.Bundle([]Claim{{"handlers.ts", 2, 2}}, nil, 100000, count); again.Fingerprint != b.Fingerprint {
		t.Fatal("bundle with notes is not repeatable")
	}
}
