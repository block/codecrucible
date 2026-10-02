package decision

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestQuestionShapesKeepUntrustedSourceAndSeparatePolicies(t *testing.T) {
	for _, q := range []Question{Noul("Is this condition present?"), Score("Is joint context useful?", []string{"none", "supporting", "direct"}), Choice("Established?", map[string]string{"yes": "shown", "unknown": "missing"})} {
		if !strings.Contains(q.Instructions.(string), "untrusted data") {
			t.Fatal("missing source boundary")
		}
		if strings.Contains(q.Instructions.(string), "Choose insufficient_evidence") {
			t.Fatal("forced an answer that the question cannot return")
		}
	}
	for _, value := range []float64{0, .5, .97, math.NaN(), 2} {
		if StrongYes(Answer{Type: "noul", Noul: number(value)}) {
			t.Fatalf("accepted %v", value)
		}
	}
	if !StrongYes(Answer{Type: "noul", Noul: number(.99)}) {
		t.Fatal("lost scoped yes")
	}
	a := Answer{Type: "score", Score: number(1.9), Confidence: number(.85), Probabilities: map[string]float64{"0": 0, "1": .1, "2": .9}}
	if !UsefulGrouping(a) || Strong(a, "2") {
		t.Fatal("grouping and verdict policies were conflated")
	}
	a.Confidence = number(.3)
	if UsefulGrouping(a) {
		t.Fatal("uncertain ranking authorized grouping")
	}
}

func TestStageBudgetReservesLaterWorkAndCountsVerification(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; _ = json.NewEncoder(w).Encode(testResponse()) }))
	defer srv.Close()
	opts := testOptions(srv.URL)
	opts.MaxCalls = 3
	opts.StageLimits = map[string]int{"smart-chunking": 1, "audit": 2, "review": 0}
	client, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	req := testRequest()
	req.Purpose = "smart-chunking"
	if _, err := client.Evaluate(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Evaluate(context.Background(), req); err != ErrLimit {
		t.Fatal("early stage consumed reserved capacity")
	}
	req.Purpose = "review"
	if _, err := client.Evaluate(context.Background(), req); err != ErrLimit {
		t.Fatal("zero budget was treated as unlimited")
	}
	req.Purpose = "audit"
	for i := 0; i < 2; i++ {
		if _, err := client.Evaluate(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := client.Evaluate(context.Background(), req); err != ErrLimit {
		t.Fatal("verification escaped the audit budget")
	}
	if calls != 3 {
		t.Fatalf("unexpected HTTP calls: %d", calls)
	}
}
