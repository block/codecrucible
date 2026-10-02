package decision

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/block/codecrucible/internal/usage"
)

func number(v float64) *float64 { return &v }
func count(v int) *int          { return &v }
func testRequest() Request {
	return Request{Purpose: "review", State: "source", Questions: map[string]Question{"check": Choice("Supported?", map[string]string{"yes": "supported", "no": "not supported"})}}
}
func testResponse() Response {
	return Response{Model: Model, Answers: map[string]Answer{"check": {Type: "choice", Choice: "yes", Confidence: number(1), Probabilities: map[string]float64{"yes": 1, "no": 0}}}, Usage: TokenUsage{Input: count(10), Output: count(2)}}
}
func testOptions(url string) Options {
	return Options{URL: url, APIKey: "private-test-key", Timeout: time.Second, MaxCalls: 10, Retries: 2, InputPrice: InputPricePerMillion, Backoff: func(int) time.Duration { return time.Millisecond }}
}

func TestTypedAnswers(t *testing.T) {
	req := testRequest()
	req.Questions["probability"] = Question{Type: "noul", Instructions: "Present?"}
	req.Questions["relevance"] = Question{Type: "score", Instructions: "Relevant?", Criteria: []string{"none", "some", "direct"}}
	response := testResponse()
	response.Answers["probability"] = Answer{Type: "noul", Noul: number(.6)}
	response.Answers["relevance"] = Answer{Type: "score", Score: number(1.8), Confidence: number(.8), Legend: map[string]string{"0": "none", "1": "some", "2": "direct"}, Probabilities: map[string]float64{"0": 0, "1": .2, "2": .8}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer private-test-key" || r.Method != "POST" {
			t.Error("missing authenticated POST")
		}
		var body Request
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.Model != Model || len(body.Questions) != 3 {
			t.Errorf("bad request: %+v", body)
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer srv.Close()
	client, err := New(testOptions(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	ledger := usage.New()
	got, err := client.Evaluate(usage.WithLedger(context.Background(), ledger), req)
	if err != nil {
		t.Fatal(err)
	}
	if got.Answers["relevance"].Score == nil || *got.Answers["relevance"].Score != 1.8 {
		t.Fatal("lost score")
	}
	report := ledger.Snapshot("completed")
	if report.Total.Attempts != 1 || !report.Total.Complete || report.Total.Tokens.PromptTokens != 10 {
		t.Fatalf("usage: %+v", report.Total)
	}
}
func TestRejectMalformedAnswers(t *testing.T) {
	for _, kind := range []string{"missing", "foreign", "type", "confidence", "range", "sum", "choice", "maximum", "noul", "score", "legend"} {
		t.Run(kind, func(t *testing.T) {
			req := testRequest()
			resp := testResponse()
			a := resp.Answers["check"]
			switch kind {
			case "missing":
				delete(resp.Answers, "check")
			case "foreign":
				delete(resp.Answers, "check")
				resp.Answers["other"] = a
			case "type":
				a.Type = "noul"
			case "confidence":
				a.Confidence = nil
			case "range":
				a.Probabilities["yes"] = 2
			case "sum":
				a.Probabilities["yes"] = .5
			case "choice":
				a.Choice = "unknown"
			case "maximum":
				a.Choice = "no"
			case "noul":
				req.Questions["check"] = Question{Type: "noul", Instructions: "Present?"}
				a = Answer{Type: "noul"}
			case "score", "legend":
				req.Questions["check"] = Question{Type: "score", Instructions: "Relevant?", Criteria: []string{"none", "direct"}}
				a = Answer{Type: "score", Score: number(.4), Confidence: number(.8), Legend: map[string]string{"0": "none", "1": "direct"}, Probabilities: map[string]float64{"0": 0, "1": 1}}
				if kind == "legend" {
					a.Score = number(1)
					a.Legend["1"] = "wrong"
				}
			}
			if kind != "missing" && kind != "foreign" {
				resp.Answers["check"] = a
			}
			if ValidateResponse(req, resp) == nil {
				t.Fatal("accepted malformed response")
			}
		})
	}
}
func TestRetriesCancellationAndUsage(t *testing.T) {
	for _, status := range []int{408, 429, 500, 503, 529, 401, 403, 422} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if calls == 1 {
					w.WriteHeader(status)
					_, _ = w.Write([]byte("private-test-key source should never be logged"))
					return
				}
				_ = json.NewEncoder(w).Encode(testResponse())
			}))
			defer srv.Close()
			client, _ := New(testOptions(srv.URL))
			ledger := usage.New()
			_, err := client.Evaluate(usage.WithLedger(context.Background(), ledger), testRequest())
			retryable := status == 408 || status == 429 || status >= 500
			if retryable && (err != nil || calls != 2) {
				t.Fatalf("retry: calls=%d err=%v", calls, err)
			}
			if !retryable && (err == nil || calls != 1) {
				t.Fatalf("permanent: calls=%d err=%v", calls, err)
			}
			if err != nil && strings.Contains(err.Error(), "private-test-key") {
				t.Fatal("leaked response")
			}
			if ledger.Snapshot("").Total.UnknownUsageAttempts != 1 {
				t.Fatal("unknown failed usage lost")
			}
		})
	}
	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(503)
		cancel()
	}))
	defer srv.Close()
	client, _ := New(testOptions(srv.URL))
	_, err := client.Evaluate(ctx, testRequest())
	if !errors.Is(err, context.Canceled) || calls.Load() != 1 {
		t.Fatalf("cancellation: %d %v", calls.Load(), err)
	}
}
func TestRedirectBoundsAndNoLeakedCredentials(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalls.Add(1) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	client, _ := New(testOptions(redirect.URL))
	if _, err := client.Evaluate(context.Background(), testRequest()); err == nil {
		t.Fatal("followed redirect")
	}
	if targetCalls.Load() != 0 {
		t.Fatal("sent credential to redirect")
	}
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; _ = json.NewEncoder(w).Encode(testResponse()) }))
	defer srv.Close()
	opts := testOptions(srv.URL)
	opts.MaxCalls = 1
	client, _ = New(opts)
	req := testRequest()
	req.State = strings.Repeat("x", 33000)
	if _, err := client.Evaluate(context.Background(), req); !errors.Is(err, ErrLimit) {
		t.Fatal("oversized state accepted")
	}
	if calls != 0 {
		t.Fatal("oversized request made HTTP call")
	}
	if _, err := client.Evaluate(context.Background(), testRequest()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Evaluate(context.Background(), testRequest()); !errors.Is(err, ErrLimit) {
		t.Fatal("call cap ignored")
	}
	if calls != 1 {
		t.Fatal("extra call after cap")
	}
}
func TestDeadlineAndInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(100 * time.Millisecond):
		}
	}))
	defer srv.Close()
	opts := testOptions(srv.URL)
	opts.Timeout = 10 * time.Millisecond
	opts.Retries = 0
	client, _ := New(opts)
	started := time.Now()
	if _, err := client.Evaluate(context.Background(), testRequest()); err == nil {
		t.Fatal("missing timeout")
	}
	if time.Since(started) > time.Second {
		t.Fatal("timeout not bounded")
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"answers":null}`)) }))
	defer bad.Close()
	client, _ = New(testOptions(bad.URL))
	if _, err := client.Evaluate(context.Background(), testRequest()); err == nil {
		t.Fatal("accepted incomplete response")
	}
}
func TestEvidenceCoverageAndNoSourceInReport(t *testing.T) {
	files := map[string]string{"a.go": "line1\nline2\n"}
	evidence, complete := CollectEvidence(files, []string{"a.go"}, 1000)
	if !complete || len(evidence) != 1 || evidence[0].Text != "line1\nline2" {
		t.Fatal("bad evidence")
	}
	if _, ok := CollectEvidence(files, []string{"missing.go"}, 1000); ok {
		t.Fatal("missing evidence called complete")
	}
	if _, ok := CollectEvidence(files, []string{"a.go"}, 1); ok {
		t.Fatal("truncated evidence called complete")
	}
}
