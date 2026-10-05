package decision

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRetryOnlyInvalidIndependentQuestions(t *testing.T) {
	for _, recover := range []bool{false, true} {
		t.Run(map[bool]string{false: "exhausted", true: "recovered"}[recover], func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				var req Request
				_ = json.NewDecoder(r.Body).Decode(&req)
				if calls > 1 && len(req.Questions) != 1 {
					t.Error("retried valid question")
				}
				resp := Response{Model: Model, Answers: map[string]Answer{}, Usage: TokenUsage{Input: count(10), Output: count(1)}}
				for id := range req.Questions {
					n := 1.0
					if id == "bad" && (!recover || calls == 1) {
						n = 2
					}
					resp.Answers[id] = Answer{Type: "noul", Noul: &n}
				}
				_ = json.NewEncoder(w).Encode(resp)
			}))
			defer srv.Close()
			client, _ := New(testOptions(srv.URL))
			req := Request{State: "source", Questions: map[string]Question{"good": Noul("Visible?"), "bad": Noul("Relevant?")}}
			response, err := client.Evaluate(context.Background(), req)
			if (err == nil) != recover || !StrongYes(response.Answers["good"]) {
				t.Fatalf("partial answers lost: %+v %v", response, err)
			}
			if len(req.Questions) != 2 {
				t.Fatal("mutated caller request")
			}
			if !recover && len(response.Answers) != 1 {
				t.Fatal("invalid answer escaped")
			}
		})
	}
}

func TestReleaseUnusedReservationsPreservesGlobalAndFutureLimits(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(testResponse()) }))
	defer srv.Close()
	opts := testOptions(srv.URL)
	opts.MaxCalls = 6
	opts.StageLimits = map[string]int{"feature": 2, "audit": 2, "review": 2}
	client, _ := New(opts)
	call := func(stage string) error {
		req := testRequest()
		req.Purpose = stage
		_, err := client.Evaluate(context.Background(), req)
		return err
	}
	client.CompleteStage("feature")
	client.CompleteStage("feature")
	for i := 0; i < 4; i++ {
		if err := call("audit"); err != nil {
			t.Fatal(err)
		}
	}
	if !errors.Is(call("audit"), ErrLimit) {
		t.Fatal("stole future review reservation")
	}
	client.CompleteStage("audit")
	for i := 0; i < 2; i++ {
		if err := call("review"); err != nil {
			t.Fatal(err)
		}
	}
	if !errors.Is(call("review"), ErrLimit) || !errors.Is(call("feature"), ErrLimit) {
		t.Fatal("exceeded global cap or reopened completed stage")
	}
}
