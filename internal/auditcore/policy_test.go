package auditcore

import "testing"

func fixture() (Claim, Assessment, VerifySource) {
	c := Seal(Claim{FindingID: "f", RevisionID: "r", Title: "unsafe", File: "a.go", Start: 2, End: 2, Material: []Material{{"title", "unsafe"}}})
	e := Evidence{File: "a.go", Start: 2, End: 2, Quote: "sink(value)"}
	a := Assessment{FindingID: c.FindingID, RevisionID: c.RevisionID, Digest: c.Digest, CoveredMaterial: []Coverage{{"title", "unsafe"}}}
	for _, q := range Questions {
		a.Assertions = append(a.Assertions, Assertion{GuardState: "does_not_block", Kind: q, Status: "established", Statement: q, Reason: "source", Subject: "value", Consumer: "sink", Guard: "sink", ConsumerInput: "value", GuardInput: "value", Evidence: []Evidence{e}, ConsumerEvidence: []Evidence{e}, GuardEvidence: []Evidence{e}})
	}
	verify := func(x Evidence) (Evidence, bool) { return x, x == e }
	return c, a, verify
}
func TestEvidencePolicy(t *testing.T) {
	c, a, v := fixture()
	if got := Evaluate(c, a, v); got.Status != "confirmed" {
		t.Fatal(got)
	}
	a.Assertions[4].ConsumerEvidence = nil
	if got := Evaluate(c, a, v); got.Status != "unverified" || got.Crux == "" {
		t.Fatal(got)
	}
	a.Assertions[4].Status = "refuted"
	if got := Evaluate(c, a, v); got.Status != "unverified" {
		t.Fatal("unsupported impact suppressed weakness", got)
	}
	c, a, v = fixture()
	a.Assertions[3].Status = "refuted"
	a.Assertions[3].GuardState = "blocks"
	if got := Evaluate(c, a, v); got.Status != "rejected" {
		t.Fatal(got)
	}
	a.Assertions[3].GuardEvidence = []Evidence{{File: "other.go", Quote: "sink(value)"}}
	if got := Evaluate(c, a, v); got.Status != "unverified" {
		t.Fatal("unrelated guard rejected claim", got)
	}
	c, a, v = fixture()
	a.Digest = "swapped"
	if got := Evaluate(c, a, v); got.Status != "unverified" {
		t.Fatal(got)
	}
	c, a, v = fixture()
	a.Assertions[3].Assumptions = []Assumption{{Runtime: "parser", Behavior: "normalizes filenames"}}
	if got := Evaluate(c, a, v); got.Status != "unverified" {
		t.Fatal("unversioned assumption accepted", got)
	}
}
func TestSplitCoverage(t *testing.T) {
	c, _, v := fixture()
	e := Evidence{File: "a.go", Start: 2, End: 2, Quote: "sink(value)"}
	child := Child{Title: "narrow", Detail: "valid", File: "a.go", Start: 2, End: 2, Covers: []Coverage{{"title", "safe"}}, Evidence: []Evidence{e}}
	if _, err := ValidateChild(c, child, v); err != nil {
		t.Fatal(err)
	}
	if CompleteCoverage(c, []Child{child}) {
		t.Fatal("partial text counted as complete")
	}
	child.Covers[0].Quote = "unsafe"
	child.Detail = "unsafe"
	if !CompleteCoverage(c, []Child{child}) {
		t.Fatal("complete coverage missing")
	}
	child.Covers[0].Quote = "invented"
	if _, err := ValidateChild(c, child, v); err == nil {
		t.Fatal("invented claim accepted")
	}
}
