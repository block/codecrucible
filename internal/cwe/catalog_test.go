package cwe

import (
	"strings"
	"testing"
)

func TestPinnedCatalogAndMappingRestrictions(t *testing.T) {
	if Version() != "4.20" || !strings.Contains(Notice(), "MITRE") {
		t.Fatal("missing catalog provenance")
	}
	for _, value := range []string{"CWE-999999", "CWE-089", "some CWE-89 text", "CWE-89\nCWE-79"} {
		if _, ok := Lookup(value); ok {
			t.Fatalf("accepted %q", value)
		}
	}
	for _, tc := range []struct {
		id       string
		mappable bool
	}{{"cwe-89: SQL Injection", true}, {"CWE-862", true}, {"CWE-284", false}, {"CWE-20", false}, {"CWE-71", false}} {
		e, ok := Lookup(tc.id)
		if !ok || e.Mappable() != tc.mappable {
			t.Fatalf("%s: %+v, %v", tc.id, e, ok)
		}
	}
}

func TestCandidatesRetrieveBeyondOriginalAndStayBounded(t *testing.T) {
	got := Candidates("SQL injection: query concatenates user strings into a SQL command rather than binding parameters", "CWE-79", 16)
	ids := map[string]bool{}
	for _, e := range got {
		ids[e.ID] = true
		if !e.Mappable() {
			t.Fatal("invalid mapping candidate")
		}
	}
	if len(got) > 16 || !ids["CWE-79"] || !ids["CWE-89"] {
		t.Fatalf("candidates: %v", ids)
	}
	if got := Candidates("the finding code", "CWE-999999", 16); len(got) != 0 {
		t.Fatal("invented candidate")
	}
}
