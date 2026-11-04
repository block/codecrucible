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
