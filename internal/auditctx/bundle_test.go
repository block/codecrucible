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

func TestNamedContextRequestsRespectAdmissionAndBudget(t *testing.T) {
	ix := NewIndex(map[string]string{
		"entry.ts":    "export function run() { return value; }\n",
		"identity.ts": "export function bindOwner(req) { req.owner = req.auth.id; }\n",
		"overload.ts": "export function choose(x: string) {}\nexport function choose(x: number) {}\n",
	})
	requests := []auditcore.ContextRequest{
		{File: "identity.ts", Symbol: "bindOwner"},
		{File: "overload.ts", Symbol: "choose"},
		{File: "identity.ts", Symbol: "missing"},
		{File: "../identity.ts", Symbol: "bindOwner"},
		{File: "identity.ts", Start: 1, End: 121},
	}
	count := func(s string) int { return len(s) }
	b := ix.Bundle([]Claim{{"entry.ts", 1, 1}}, nil, 5000, count, requests)
	want := []string{"included", "ambiguous_symbol", "symbol_not_found", "outside_scope", "invalid_range"}
	for i, status := range want {
		if b.Requests[i].Status != status {
			t.Fatalf("request %d: %+v", i, b.Requests[i])
		}
	}
	if !strings.Contains(b.PromptText(), "req.owner = req.auth.id") || !strings.Contains(b.PromptText(), "symbol_not_found") {
		t.Fatal("request evidence or omissions absent", b.PromptText())
	}
	if again := ix.Bundle([]Claim{{"entry.ts", 1, 1}}, nil, 5000, count, requests); again.Fingerprint != b.Fingerprint {
		t.Fatal("request bundle is not repeatable")
	}
	if small := ix.Bundle(nil, nil, 1, count, requests[:1]); small.Requests[0].Status != "budget_exhausted" || len(small.Included) != 0 {
		t.Fatal("request escaped budget", small)
	}
	_, records := ix.ResolveRequests(make([]auditcore.ContextRequest, 100))
	if len(records) != maxContextRequests+1 || records[maxContextRequests].Status != "request_limit" {
		t.Fatal("request limit not enforced", records)
	}
}

func TestContextRequestFailuresAreRecordedAsOmissions(t *testing.T) {
	long := "export function big() {\n" + strings.Repeat("  step();\n", 150) + "}\n"
	ix := NewIndex(map[string]string{"entry.ts": "export function run() { return 1; }\n", "big.ts": long, "dup.ts": "function f() {}\nfunction f() {}\n"})
	count := func(s string) int { return len(s) }
	requests := []auditcore.ContextRequest{
		{File: "dup.ts", Symbol: "f"},
		{File: "../entry.ts", Symbol: "run"},
		{File: "entry.ts", Symbol: "run", Start: 1, End: 1},
		{File: "entry.ts", Symbol: "not a name"},
		{File: "entry.ts"},
		{File: "big.ts", Symbol: "big"},
	}
	b := ix.Bundle([]Claim{{"entry.ts", 1, 1}}, nil, 100000, count, requests)
	want := []string{RequestAmbiguousSymbol, RequestOutsideScope, RequestInvalid, RequestInvalid, RequestInvalidRange, RequestIncluded}
	for i, status := range want {
		if b.Requests[i].Status != status {
			t.Fatalf("request %d: %+v", i, b.Requests[i])
		}
	}
	reasons := map[string]bool{}
	for _, o := range b.Omitted {
		reasons[o.Reason] = true
	}
	for _, reason := range []string{RequestAmbiguousSymbol, RequestOutsideScope, RequestInvalid, RequestInvalidRange} {
		if !reasons[reason] {
			t.Fatalf("request failure %q is not a bundle omission: %+v", reason, b.Omitted)
		}
	}
	got := b.Requests[5].Excerpt
	if got.End-got.Start+1 != maxRequestLines || !strings.Contains(got.Reason, "truncated") {
		t.Fatalf("long declaration was not bounded and labelled: %+v", got)
	}
	if _, ok := ix.Verify(b, auditcore.Evidence{File: "big.ts", Start: 2, End: 2, Quote: "step();"}); !ok {
		t.Fatal("requested source cannot be cited")
	}
	if _, ok := ix.Verify(b, auditcore.Evidence{File: "big.ts", Start: 140, End: 140, Quote: "step();"}); ok {
		t.Fatal("source beyond the requested range can be cited")
	}
	over := ix.Bundle(nil, nil, 1, count, requests[5:])
	if over.Requests[0].Status != RequestBudgetExhausted || len(over.Omitted) != 1 || over.Omitted[0].Reason != "budget_exhausted" {
		t.Fatalf("budget loss not recorded in both structures: %+v", over)
	}
	if plain := ix.Bundle([]Claim{{"entry.ts", 1, 1}}, nil, 100000, count); len(plain.Requests) != 0 || strings.Contains(plain.PromptText(), "Context request results") {
		t.Fatal("bundle without requests changed")
	}
}
