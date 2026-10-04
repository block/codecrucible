package cli

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/block/codecrucible/internal/decision"
	"github.com/block/codecrucible/internal/llm"
)

func featureBatchFixture(t *testing.T) (*scanDecisions, *llm.PromptLoader) {
	t.Helper()
	d, _ := decisionFixture(t)
	d.cfg.FeatureDetection = "active"
	d.files = map[string]string{"a.kt": strings.Repeat("fun example() {}\n", 1200)}
	loader := llm.NewPromptLoader(fstest.MapFS{"analysis_sections.yaml": &fstest.MapFile{Data: []byte("sections:\n  authentication:\n    title: Authentication\n    features: [auth]\n    content: Check auth\n  custom:\n    title: Custom feature\n    features: [custom_feature]\n    content: Check custom\n")}})
	return d, loader
}

func TestFeatureBatchesAggregateLatePositiveAndCompleteAbsence(t *testing.T) {
	d, loader := featureBatchFixture(t)
	calls := 0
	d.recorder.Client = evaluateFunc(func(_ context.Context, req decision.Request) (decision.Response, error) {
		calls++
		choices := map[string]string{"feature_0": "absent", "feature_1": "absent"}
		if calls == 2 {
			choices["feature_0"] = "present"
		}
		return answersFor(req, choices), nil
	})
	features, handled, err := d.featureDetection(context.Background(), loader)
	if err != nil || !handled || calls < 2 || !reflect.DeepEqual(features, []string{"auth"}) {
		t.Fatalf("features=%v handled=%v calls=%d err=%v", features, handled, calls, err)
	}
	observations := d.featureObservations()
	if observations[0].Status != "observed_present" || observations[1].Status != "absent" || observations[1].Retained {
		t.Fatalf("incorrect aggregate: %+v", observations)
	}
	outcomes := d.recorder.Report().Outcomes["feature-detection"]
	if outcomes["categories_omitted"] != 1 || outcomes["source_batches_completed"] != calls {
		t.Fatalf("incorrect aggregate counters: %+v", outcomes)
	}
}

func TestFeatureBatchesUncertaintyAndFailuresPreventOmission(t *testing.T) {
	for _, failure := range []string{"uncertain", "failed", "quota", "oversized_line"} {
		t.Run(failure, func(t *testing.T) {
			d, loader := featureBatchFixture(t)
			if failure == "oversized_line" {
				d.files["z.kt"] = strings.Repeat("x", 20000)
			}
			calls := 0
			d.recorder.Client = evaluateFunc(func(_ context.Context, req decision.Request) (decision.Response, error) {
				calls++
				choices := map[string]string{"feature_0": "present", "feature_1": "absent"}
				if calls == 2 {
					switch failure {
					case "uncertain":
						choices["feature_1"] = "insufficient_evidence"
					case "failed":
						return decision.Response{}, errors.New("provider unavailable")
					case "quota":
						return decision.Response{}, decision.ErrLimit
					}
				}
				return answersFor(req, choices), nil
			})
			features, _, err := d.featureDetection(context.Background(), loader)
			if err != nil || !reflect.DeepEqual(features, []string{"auth", "custom_feature"}) {
				t.Fatalf("uncertain source omitted a category: %v %v", features, err)
			}
			observations := d.featureObservations()
			if observations[0].Status != "observed_present" || observations[1].Status != "unknown" {
				t.Fatalf("lost positive or certified uncertain absence: %+v", observations)
			}
			if failure == "quota" && calls != 2 {
				t.Fatal("continued requests after exhausted quota")
			}
		})
	}
}

func TestFeatureBatchesShadowAndCancellation(t *testing.T) {
	d, loader := featureBatchFixture(t)
	d.cfg.FeatureDetection = "shadow"
	d.recorder.Client = evaluateFunc(func(_ context.Context, req decision.Request) (decision.Response, error) {
		return answersFor(req, map[string]string{"feature_0": "present", "feature_1": "absent"}), nil
	})
	features, handled, err := d.featureDetection(context.Background(), loader)
	if err != nil || handled || features != nil || d.recorder.Report().Outcomes["feature-detection"]["proposed_categories_omitted"] != 1 {
		t.Fatalf("shadow changed detector selection: %v %v %v", features, handled, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = d.featureDetection(ctx, loader)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

func TestFeatureBatchesAllPresentStopsRequestsAndEmptySelectionKeepsContract(t *testing.T) {
	for _, choice := range []string{"present", "absent"} {
		t.Run(choice, func(t *testing.T) {
			d, loader := featureBatchFixture(t)
			calls := 0
			d.recorder.Client = evaluateFunc(func(_ context.Context, req decision.Request) (decision.Response, error) {
				calls++
				return answersFor(req, map[string]string{"feature_0": choice, "feature_1": choice}), nil
			})
			features, handled, err := d.featureDetection(context.Background(), loader)
			if err != nil || !handled || len(features) != 2 {
				t.Fatalf("all-sections contract changed: %v %v %v", features, handled, err)
			}
			if choice == "present" && calls != 1 {
				t.Fatalf("queried already established features: %d", calls)
			}
			for _, observation := range d.featureObservations() {
				if !observation.Retained {
					t.Fatal("artifact disagrees with actual section retention")
				}
			}
		})
	}
}
