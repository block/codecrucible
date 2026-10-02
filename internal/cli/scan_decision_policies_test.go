package cli

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/block/codecrucible/internal/chunk"
	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/decision"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/llm"
)

func TestFeatureCoverageSkipsCallsAndRecordsRetention(t *testing.T) {
	loader := llm.NewPromptLoader(fstest.MapFS{"analysis_sections.yaml": &fstest.MapFile{Data: []byte("sections:\n  auth:\n    title: Authentication\n    features: [auth]\n    content: Check authentication\n")}})
	d, _ := decisionFixture(t)
	d.cfg.FeatureDetection = "active"
	d.files["large.go"] = strings.Repeat("source\n", 20000)
	d.recorder.Client = evaluateFunc(func(context.Context, decision.Request) (decision.Response, error) {
		t.Fatal("paid call cannot affect retention")
		return decision.Response{}, nil
	})
	features, handled, err := d.featureDetection(context.Background(), loader)
	if err != nil || !handled || !reflect.DeepEqual(features, []string{"auth"}) {
		t.Fatalf("bad fallback: %v %v", features, err)
	}
	r := d.recorder.Records[0]
	if len(r.Features) != 1 || r.Features[0].Status != "unknown" || !r.Features[0].Retained || r.Outcomes["categories_omitted"] != 0 {
		t.Fatalf("incorrect observation: %+v", r)
	}
}

func TestAuditEveryNecessaryPrerequisiteMustBeEstablished(t *testing.T) {
	for _, missing := range []string{"reachability", "attacker_control", "operation", "impact", "mitigation"} {
		t.Run(missing, func(t *testing.T) {
			d, doc := decisionFixture(t)
			d.recorder.Client = evaluateFunc(func(_ context.Context, req decision.Request) (decision.Response, error) {
				resp := answersFor(req, map[string]string{"coverage": "sufficient", "verdict": "supported", "blocking_evidence": "none"})
				resp.Answers[missing] = strongAnswer(req.Questions[missing], "insufficient_evidence")
				return resp, nil
			})
			queue, routed, err := d.routeAudit(context.Background(), doc)
			if err != nil || len(queue.Runs[0].Results) != 2 || len(routed.Retained) != 0 {
				t.Fatal("missing prerequisite became support")
			}
		})
	}
}

func TestReviewChecksAssertionsAndReusesOnlyIdenticalEvidence(t *testing.T) {
	d, doc := decisionFixture(t)
	doc.Runs[0].Results = append(doc.Runs[0].Results[:1], doc.Runs[0].Results[0])
	doc.Runs[0].Results[0].Properties.TechnicalDetails = "The source contains a write. The write includes a password hash."
	calls := 0
	d.recorder.Client = evaluateFunc(func(_ context.Context, req decision.Request) (decision.Response, error) {
		calls++
		if len(req.Questions) != 2 {
			t.Fatalf("expected two assertions: %+v", req.Questions)
		}
		return answersFor(req, map[string]string{"assertion_0": "supported", "assertion_1": "contradicted"}), nil
	})
	out, err := d.reviewFindings(context.Background(), doc)
	if err != nil || calls != 1 || len(out.Runs[0].Results) != 2 {
		t.Fatalf("review calls=%d err=%v", calls, err)
	}
	for _, f := range out.Runs[0].Results {
		assessment := f.Properties.DecisionReview
		if assessment.Status != "contradicted" || len(assessment.Checks) != 2 || assessment.Checks[0].Status != "supported" || assessment.Checks[1].Status != "contradicted" {
			t.Fatalf("lost specific disagreement: %+v", assessment)
		}
	}
	if d.recorder.Records[1].Fallback != "unchanged_claim_and_evidence" {
		t.Fatal("duplicate request was not identified")
	}
	data, _ := json.Marshal(d.recorder.Report())
	if strings.Contains(string(data), "execute(input)") {
		t.Fatal("raw source leaked into decision log")
	}
	if doc.Runs[0].Results[0].Properties.DecisionReview != nil {
		t.Fatal("mutated original document")
	}
}

func TestReviewPartialAndNonfactualClaimsCannotBecomeSupported(t *testing.T) {
	for _, tc := range []struct{ text, answer string }{
		{strings.Repeat("This is an assertion. ", 15), "supported"},
		{"Consider a change.", "not_applicable"},
	} {
		d, doc := decisionFixture(t)
		doc.Runs[0].Results = doc.Runs[0].Results[:1]
		doc.Runs[0].Results[0].Properties.TechnicalDetails = tc.text
		d.recorder.Client = evaluateFunc(func(_ context.Context, req decision.Request) (decision.Response, error) {
			return answersFor(req, map[string]string{"claim_support": tc.answer}), nil
		})
		out, err := d.reviewFindings(context.Background(), doc)
		if err != nil || out.Runs[0].Results[0].Properties.DecisionReview.Status == "supported" {
			t.Fatal("incomplete or nonfactual review became verified")
		}
	}
}

func TestDependencyGroupingRunsWithoutJevCredentialsOrRequests(t *testing.T) {
	files := ingest.FileMap{"a.go": "package app\nfunc A() { B() }\n", "b.go": "package app\nfunc B() {}\n"}
	sources := []ingest.SourceFile{}
	for path, content := range files {
		sources = append(sources, ingest.SourceFile{Path: path, Content: content})
	}
	d, err := newScanDecisions(config.Decisions{DependencyGrouping: true}, files, sources)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := d.smartGrouping(context.Background(), nil)
	if err != nil || !hasGroupingEdge(graph, "a.go", "b.go") || d.recorder.Client != nil {
		t.Fatalf("deterministic control failed: %v %v", graph, err)
	}
}

func TestGroupingRecordsActualPlacementSeparatelyFromAcceptance(t *testing.T) {
	d, _ := decisionFixture(t)
	d.recorder.Records = []decision.Record{{Stage: "smart-chunking", Edges: []decision.GroupingEdge{{Left: "a", Right: "b", Origin: "jev", Applied: true}, {Left: "c", Right: "d", Origin: "jev", Applied: true}}}}
	d.recordGroupingPlacement([]chunk.Chunk{{Paths: []string{"a"}}, {Paths: []string{"b"}}, {Paths: []string{"c", "d"}}}, []chunk.Chunk{{Paths: []string{"a", "b"}}, {Paths: []string{"c", "d"}}})
	r := d.recorder.Records[0]
	if r.Outcomes["edges_changed_placement"] != 1 || r.Outcomes["edges_together"] != 2 {
		t.Fatalf("acceptance confused with actual effect: %+v", r)
	}
}

func TestDecisionStageLimitsAreBoundedAndDisabledStagesGetNoReservation(t *testing.T) {
	cfg := config.Decisions{MaxCalls: 7, FeatureDetection: "off", SmartChunking: "active", Audit: "active", Review: "shadow"}
	got := decisionStageLimits(cfg)
	if !reflect.DeepEqual(got, map[string]int{"smart-chunking": 3, "audit": 2, "review": 2}) {
		t.Fatalf("quotas: %v", got)
	}
}

func TestGroupingSkipsPairsWithoutBoundedSourceScopes(t *testing.T) {
	d, _ := decisionFixture(t)
	d.cfg.SmartChunking = "active"
	large := "package app\nfunc sharedOperation() {\n" + strings.Repeat(" sharedSecurityValue := inputValue\n", 1000) + "}\n"
	d.files = map[string]string{"a.go": large, "b.go": large}
	d.recorder.Client = evaluateFunc(func(context.Context, decision.Request) (decision.Response, error) {
		t.Fatal("unusable evidence must not cause a paid request")
		return decision.Response{}, nil
	})
	graph, err := d.smartGrouping(context.Background(), nil)
	if err != nil || len(graph) != 0 || d.recorder.Report().Outcomes["smart-chunking"]["pairs_skipped_missing_scopes"] != 1 {
		t.Fatalf("missing scopes not accounted for: %v %v %+v", graph, err, d.recorder.Report())
	}
}

func TestFeaturePositiveSignalOverridesAbsenceAndShadowPreservesDetector(t *testing.T) {
	loader := llm.NewPromptLoader(fstest.MapFS{"analysis_sections.yaml": &fstest.MapFile{Data: []byte("sections:\n  auth:\n    title: Authentication\n    features: [auth]\n    content: Check authentication\n")}})
	for _, mode := range []string{"active", "shadow"} {
		d, _ := decisionFixture(t)
		d.cfg.FeatureDetection = mode
		d.recorder.Client = evaluateFunc(func(_ context.Context, req decision.Request) (decision.Response, error) {
			return answersFor(req, map[string]string{"feature_0": "absent", "feature_0_signal": "yes"}), nil
		})
		features, handled, err := d.featureDetection(context.Background(), loader)
		if err != nil || handled != (mode == "active") {
			t.Fatalf("unexpected routing: %v %v", handled, err)
		}
		if mode == "active" && !reflect.DeepEqual(features, []string{"auth"}) {
			t.Fatal("positive evidence was omitted")
		}
		observation := d.featureObservations()[0]
		if !observation.Retained || observation.Status != "observed_present" {
			t.Fatalf("lost positive signal: %+v", observation)
		}
		if mode == "shadow" {
			r := d.recorder.Records[0]
			if features != nil || r.Outcomes["proposed_categories_retained"] != 1 {
				t.Fatal("shadow changed detector or counted a realized outcome")
			}
		}
	}
}

func TestReviewDifferentEvidenceIsNotReused(t *testing.T) {
	d, doc := decisionFixture(t)
	calls := 0
	d.recorder.Client = evaluateFunc(func(_ context.Context, req decision.Request) (decision.Response, error) {
		calls++
		return answersFor(req, map[string]string{"claim_support": "supported"}), nil
	})
	out, err := d.reviewFindings(context.Background(), doc)
	if err != nil || calls != 2 || len(out.Runs[0].Results) != 2 {
		t.Fatalf("different evidence reused: calls=%d err=%v", calls, err)
	}
}
