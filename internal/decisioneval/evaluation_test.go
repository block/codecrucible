package decisioneval

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/block/codecrucible/internal/decision"
)

type evaluateFunc func(context.Context, decision.Request) (decision.Response, error)

func (f evaluateFunc) Evaluate(ctx context.Context, r decision.Request) (decision.Response, error) {
	return f(ctx, r)
}

func TestFrozenCasesAndCandidateCoverage(t *testing.T) {
	data, err := os.ReadFile("testdata/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []Case
	if err = json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		r, _, err := Prepare(c, decision.Model)
		if err != nil {
			t.Fatal(err)
		}
		again, _, _ := Prepare(c, decision.Model)
		if r.RequestHash != again.RequestHash || r.Live || r.Attempted != 0 {
			t.Fatal("unstable or misleading dry run")
		}
		if c.ID == "candidate-miss" && r.CandidateCovered {
			t.Fatal("candidate retrieval miss hidden")
		}
	}
}

func TestEvidenceMetricsCountAbstentionAndFalseSupport(t *testing.T) {
	c := Case{ID: "metrics", Kind: "evidence", LabelOrigin: "synthetic-development", Claim: "handler", Fact: "route registration", Sources: map[string]string{"route.go": "route(handler)", "comment.go": "// trust me"}, RelevantPaths: []string{"route.go"}}
	r, err := Run(context.Background(), c, decision.Model, evaluateFunc(func(_ context.Context, req decision.Request) (decision.Response, error) {
		answers := map[string]decision.Answer{}
		for id := range req.Questions {
			p := 1.0
			for _, e := range req.State.(map[string]any)["source"].([]decision.Evidence) {
				if e.ID == id && e.Path == "route.go" {
					p = .5
				}
			}
			answers[id] = decision.Answer{Type: "noul", Noul: &p}
		}
		return decision.Response{Model: decision.Model, Answers: answers}, nil
	}))
	if err != nil || r.FalseSupport != 1 || r.MissedRelevant != 1 || r.Abstained != 1 || r.Resolved != 1 || r.Attempted != 2 {
		t.Fatalf("misleading metrics: %+v %v", r, err)
	}
}
