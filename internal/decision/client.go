// Package decision implements TypeSafe's typed decision API. It deliberately
// does not implement the generative chat interface.
package decision

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/block/codecrucible/internal/usage"
)

const Model = "jev-1.13.0"
const InputPricePerMillion = 0.042
const PolicyVersion = "jev-decisions-v2"

var ErrLimit = errors.New("decision request limit reached")

type Question struct {
	Type         string `json:"type"`
	Instructions any    `json:"instructions"`
	Criteria     any    `json:"criteria,omitempty"`
}
type Request struct {
	Model     string              `json:"model"`
	State     any                 `json:"state"`
	Questions map[string]Question `json:"questions"`
	Purpose   string              `json:"-"`
}
type Answer struct {
	Type          string             `json:"type"`
	Choice        string             `json:"choice,omitempty"`
	Noul          *float64           `json:"noul,omitempty"`
	Score         *float64           `json:"score,omitempty"`
	Confidence    *float64           `json:"confidence,omitempty"`
	Probabilities map[string]float64 `json:"probabilities,omitempty"`
	Legend        map[string]string  `json:"legend,omitempty"`
}
type TokenUsage struct {
	Input  *int `json:"input_tokens"`
	Output *int `json:"output_tokens"`
}
type Response struct {
	Model   string            `json:"model"`
	Answers map[string]Answer `json:"answers"`
	Usage   TokenUsage        `json:"usage"`
}
type Evaluator interface {
	Evaluate(context.Context, Request) (Response, error)
}

type Options struct {
	URL, APIKey, Model string
	Timeout            time.Duration
	MaxCalls, Retries  int
	InputPrice         float64
	// Limits use UTF-8 JSON byte counts as a conservative token upper bound.
	RequestLimit, StateQuestionLimit int
	Transport                        http.RoundTripper
	Backoff                          func(int) time.Duration
}
type Client struct {
	opts  Options
	http  *http.Client
	mu    sync.Mutex
	calls int
}

func New(opts Options) (*Client, error) {
	if opts.URL == "" {
		opts.URL = "https://api.typesafe.ai/v1/systemone"
	}
	if opts.Model == "" {
		opts.Model = Model
	}
	if opts.Timeout <= 0 || opts.MaxCalls <= 0 || opts.Retries < 0 || opts.Retries > 5 {
		return nil, errors.New("invalid decision request bounds")
	}
	if strings.TrimSpace(opts.APIKey) == "" {
		return nil, errors.New("TYPESAFE_API_KEY is required for enabled decisions")
	}
	u, err := url.Parse(opts.URL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid decision endpoint")
	}
	loopback := u.Hostname() == "localhost"
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		loopback = ip.IsLoopback()
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
		return nil, errors.New("decision endpoint requires HTTPS (HTTP is allowed only for loopback tests)")
	}
	if opts.RequestLimit <= 0 {
		opts.RequestLimit = 64000
	}
	if opts.StateQuestionLimit <= 0 {
		opts.StateQuestionLimit = 32000
	}
	if opts.Backoff == nil {
		opts.Backoff = func(attempt int) time.Duration {
			return time.Second*time.Duration(1<<attempt) + time.Duration(rand.IntN(250))*time.Millisecond
		}
	}
	return &Client{opts: opts, http: &http.Client{Transport: opts.Transport, Timeout: opts.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *Client) Evaluate(ctx context.Context, req Request) (Response, error) {
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	req.Model = c.opts.Model
	body, err := json.Marshal(req)
	if err != nil {
		return Response{}, errors.New("invalid decision request JSON")
	}
	if err := validateRequest(req, len(body), c.opts); err != nil {
		return Response{}, err
	}
	c.mu.Lock()
	if c.calls >= c.opts.MaxCalls {
		c.mu.Unlock()
		return Response{}, ErrLimit
	}
	c.calls++
	c.mu.Unlock()
	ctx = usage.WithPhase(ctx, usage.Phase{Name: "decision." + req.Purpose, Provider: "typesafe", PricingModel: c.opts.Model, Pricing: usage.Pricing{InputPerMillion: c.opts.InputPrice}})
	record := usage.Begin(ctx, "http", c.opts.Model, req.Purpose)
	var last error
	var delay time.Duration
	for attempt := 0; attempt <= c.opts.Retries; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return Response{}, ctx.Err()
			case <-timer.C:
			}
		}
		if err := ctx.Err(); err != nil {
			return Response{}, err
		}
		started := time.Now()
		result := usage.Result{Status: "error", Reason: "transport", UsageStatus: "unknown"}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.opts.URL, bytes.NewReader(body))
		if err != nil {
			return Response{}, errors.New("invalid decision request")
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+c.opts.APIKey)
		resp, callErr := c.http.Do(request)
		retry := true
		delay = c.opts.Backoff(attempt)
		var decoded Response
		if callErr != nil {
			// Do not expose URL errors or provider bodies, which can echo credentials/data.
			last = errors.New("decision transport failed")
		} else {
			result.HTTPStatus = resp.StatusCode
			raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024+1))
			_ = resp.Body.Close()
			if readErr != nil {
				last = errors.New("decision response read failed")
			} else if len(raw) > 2*1024*1024 {
				retry = false
				last = errors.New("decision response too large")
			} else if resp.StatusCode != http.StatusOK {
				result.Reason = "http_status"
				retry = resp.StatusCode == 408 || resp.StatusCode == 429 || resp.StatusCode >= 500 && resp.StatusCode < 600
				last = fmt.Errorf("decision request failed (HTTP %d)", resp.StatusCode)
				if d := retryAfter(resp.Header.Get("Retry-After")); d > delay {
					delay = d
				}
			} else {
				// A malformed successful response consumes the same bounded
				// retry budget as transient transport failures.
				result.Reason = "invalid_response"
				decodeErr := json.Unmarshal(raw, &decoded)
				if decoded.Usage.Input != nil && *decoded.Usage.Input >= 0 {
					result.Tokens.PromptTokens = *decoded.Usage.Input
					result.UsageStatus = "partial"
				}
				if decoded.Usage.Output != nil && *decoded.Usage.Output >= 0 {
					result.Tokens.CompletionTokens = *decoded.Usage.Output
					result.UsageStatus = "partial"
				}
				if decoded.Usage.Input != nil && decoded.Usage.Output != nil && *decoded.Usage.Input >= 0 && *decoded.Usage.Output >= 0 {
					result.UsageStatus = "reported"
				}
				result.Model = decoded.Model
				result.Unpriced = decoded.Model != "" && decoded.Model != c.opts.Model
				if decodeErr != nil {
					last = responseError("invalid_json")
				} else {
					last = ValidateResponse(req, decoded)
				}
				if last != nil {
					result.Reason = FailureReason(last)
				}
				if last == nil {
					result.Status = "completed"
					result.Reason = ""
				}
			}
		}
		if ctx.Err() != nil {
			result.Status = "cancelled"
			result.Reason = "context_cancelled"
			last = ctx.Err()
			retry = false
		}
		record.Record(attempt+1, started, result)
		if last == nil {
			return decoded, nil
		}
		if !retry {
			return Response{}, last
		}
	}
	return Response{}, last
}

func validateRequest(req Request, size int, opts Options) error {
	if len(req.Questions) == 0 || len(req.Questions) > 128 {
		return errors.New("decision requires 1-128 questions")
	}
	state, err := json.Marshal(req.State)
	if err != nil || req.State == nil {
		return errors.New("decision state is required")
	}
	if size+256 > opts.RequestLimit {
		return fmt.Errorf("decision request exceeds conservative context limit: %w", ErrLimit)
	}
	for id, q := range req.Questions {
		if id == "" || q.Instructions == nil {
			return errors.New("decision question requires ID and instructions")
		}
		qb, err := json.Marshal(q)
		if err != nil || len(state)+len(qb)+256 > opts.StateQuestionLimit {
			return fmt.Errorf("decision state and question exceed conservative context limit: %w", ErrLimit)
		}
		switch q.Type {
		case "choice":
			c, ok := q.Criteria.(map[string]string)
			if !ok || len(c) < 2 || len(c) > 255 {
				return errors.New("choice requires 2-255 named criteria")
			}
		case "score":
			c, ok := q.Criteria.([]string)
			if !ok || len(c) < 2 || len(c) > 10 {
				return errors.New("score requires 2-10 levels")
			}
		case "noul":
		default:
			return errors.New("unsupported decision question type")
		}
	}
	return nil
}

// ValidateResponse treats missing, foreign, and inconsistent answers as a whole
// request failure. A plausible subset must not masquerade as complete evidence.
func ValidateResponse(req Request, resp Response) error {
	if resp.Model == "" || len(resp.Answers) != len(req.Questions) {
		return responseError("incomplete_response")
	}
	for id, q := range req.Questions {
		a, ok := resp.Answers[id]
		if !ok || a.Type != q.Type {
			return responseError("answer_id_or_type")
		}
		if q.Type == "noul" {
			if a.Choice != "" || a.Score != nil || a.Confidence != nil || len(a.Probabilities) > 0 || len(a.Legend) > 0 {
				return responseError("mixed_noul_shape")
			}
			if a.Noul == nil || !probability(*a.Noul) {
				return responseError("noul_range")
			}
			continue
		}
		if a.Noul != nil || (q.Type == "choice" && (a.Score != nil || len(a.Legend) > 0)) || (q.Type == "score" && a.Choice != "") {
			return responseError("mixed_answer_shape")
		}
		if a.Confidence == nil || !probability(*a.Confidence) {
			return responseError("confidence")
		}
		expected := map[string]string{}
		if q.Type == "choice" {
			expected, _ = q.Criteria.(map[string]string)
		} else {
			levels, _ := q.Criteria.([]string)
			for i, level := range levels {
				expected[strconv.Itoa(i)] = level
			}
			if len(a.Legend) != len(expected) {
				return responseError("legend_size")
			}
			for k, v := range expected {
				if a.Legend[k] != v {
					return responseError("legend_values")
				}
			}
		}
		if len(a.Probabilities) != len(expected) {
			return responseError("probability_count")
		}
		sum, weighted, highest := 0.0, 0.0, 0.0
		for k := range expected {
			p, ok := a.Probabilities[k]
			if !ok || !probability(p) {
				return responseError("probability_range")
			}
			sum += p
			highest = math.Max(highest, p)
			level, _ := strconv.Atoi(k)
			weighted += float64(level) * p
		}
		if math.Abs(sum-1) > 0.001 {
			return responseError("probability_sum")
		}
		if q.Type == "choice" {
			if _, ok := expected[a.Choice]; !ok || a.Probabilities[a.Choice]+0.000001 < highest {
				return responseError("choice")
			}
		} else if a.Score == nil || math.IsNaN(*a.Score) || math.Abs(*a.Score-weighted) > 0.001 {
			return responseError("weighted_score")
		}
	}
	return nil
}
func probability(p float64) bool { return !math.IsNaN(p) && !math.IsInf(p, 0) && p >= 0 && p <= 1 }
func retryAfter(value string) time.Duration {
	if n, err := strconv.Atoi(value); err == nil && n >= 0 {
		return time.Duration(min(n, 120)) * time.Second
	}
	if t, err := http.ParseTime(value); err == nil {
		return min(max(time.Until(t), 0), 120*time.Second)
	}
	return 0
}

// responseError is constructed exclusively from fixed validation codes. Never
// wrap provider errors or include model-selected IDs, text, or response bodies.
type responseError string

func (e responseError) Error() string { return "invalid decision response: " + string(e) }
func FailureReason(err error) string {
	var invalid responseError
	if errors.As(err, &invalid) {
		return "invalid_response_" + string(invalid)
	}
	if errors.Is(err, ErrLimit) {
		return "decision_limit"
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "context_cancelled"
	}
	return "decision_unavailable"
}
