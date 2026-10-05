package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/block/codecrucible/internal/decision"
)

func TestJevReviewPreservesValidAnswersAfterPartialFailure(t *testing.T) {
	for _, status := range []string{"contradicted", "supported"} {
		t.Run(status, func(t *testing.T) {
			testJevReviewPartialFailure(t, status)
		})
	}
}

func testJevReviewPartialFailure(t *testing.T, status string) {
	t.Helper()
	d, doc := decisionFixture(t)
	// Identical inputs would use the cache after a complete successful review.
	doc.Runs[0].Results[1] = doc.Runs[0].Results[0]
	for i := range doc.Runs[0].Results {
		doc.Runs[0].Results[i].Properties.TechnicalDetails = "Input reaches execute. The caller authenticates first."
	}
	calls := 0
	d.recorder.Client = evaluateFunc(func(_ context.Context, req decision.Request) (decision.Response, error) {
		calls++
		if len(req.Questions) != 2 {
			t.Fatalf("expected two independent assertions, got %d", len(req.Questions))
		}
		return decision.Response{Model: decision.Model, Answers: map[string]decision.Answer{
			"assertion_0": strongAnswer(req.Questions["assertion_0"], status),
		}}, errors.New("remaining assertion unavailable")
	})
	got, err := d.reviewFindings(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Runs[0].Results) != len(doc.Runs[0].Results) || calls != 2 {
		t.Fatal("partial review removed findings or was cached")
	}
	expectedStatus := "unavailable"
	if status == "contradicted" {
		expectedStatus = status
	}
	for _, result := range got.Runs[0].Results {
		review := result.Properties.DecisionReview
		if review.Status != expectedStatus || len(review.Checks) != 2 || review.Checks[0].Status != status || review.Checks[1].Status != "unavailable" {
			t.Fatalf("valid answer lost or partial result reported as complete: %+v", review)
		}
	}
	for _, record := range d.recorder.Records {
		if record.Status != "fallback" || record.Fallback == "" {
			t.Fatalf("partial request failure must remain visible: %+v", record)
		}
	}
}
