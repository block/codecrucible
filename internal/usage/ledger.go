// Package usage records request attempts without retaining prompts, responses,
// endpoints, or credentials. It is shared by generative and decision clients.
package usage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
)

type Tokens struct {
	PromptTokens        int `json:"prompt_tokens"`
	CompletionTokens    int `json:"completion_tokens"`
	ReasoningTokens     int `json:"reasoning_tokens,omitempty"`      // Subset of completion tokens.
	CacheCreationTokens int `json:"cache_creation_tokens,omitempty"` // Additional Anthropic input.
	CacheReadTokens     int `json:"cache_read_tokens,omitempty"`     // Additional Anthropic input.
	CachedPromptTokens  int `json:"cached_prompt_tokens,omitempty"`  // Subset of OpenAI-compatible input.
	ThinkingChars       int `json:"thinking_chars,omitempty"`        // Characters, never billed as tokens.
}

func (t *Tokens) Add(other Tokens) {
	t.PromptTokens += other.PromptTokens
	t.CompletionTokens += other.CompletionTokens
	t.ReasoningTokens += other.ReasoningTokens
	t.CacheCreationTokens += other.CacheCreationTokens
	t.CacheReadTokens += other.CacheReadTokens
	t.CachedPromptTokens += other.CachedPromptTokens
	t.ThinkingChars += other.ThinkingChars
}

// Pricing is the configured rate snapshot, not a claim about the provider's bill.
// Zero input and output rates mean unpriced, not free. Cache rates are not yet
// configured by CodeCrucible; cache usage makes the calculated cost incomplete.
type Pricing struct {
	InputPerMillion      float64 `json:"input_per_million"`
	OutputPerMillion     float64 `json:"output_per_million"`
	LongContextThreshold int     `json:"long_context_threshold,omitempty"`
	LongInputPerMillion  float64 `json:"long_input_per_million,omitempty"`
	LongOutputPerMillion float64 `json:"long_output_per_million,omitempty"`
}

func (p Pricing) cost(t Tokens) (float64, bool) {
	in, out := p.InputPerMillion, p.OutputPerMillion
	if p.LongContextThreshold > 0 && t.PromptTokens+t.CacheCreationTokens+t.CacheReadTokens > p.LongContextThreshold {
		if p.LongInputPerMillion != 0 {
			in = p.LongInputPerMillion
		}
		if p.LongOutputPerMillion != 0 {
			out = p.LongOutputPerMillion
		}
	}
	known := (in > 0 || out > 0) && in >= 0 && out >= 0
	if !known {
		return 0, false
	}
	uncached := max(0, t.PromptTokens-t.CachedPromptTokens)
	return (float64(uncached)*in + float64(t.CompletionTokens)*out) / 1_000_000,
		t.CacheCreationTokens == 0 && t.CacheReadTokens == 0 && t.CachedPromptTokens == 0
}

type Phase struct {
	Name           string
	Provider       string
	PricingModel   string
	Pricing        Pricing
	FallbackReason string
}

type contextKey struct{}
type phaseKey struct{}

func WithLedger(ctx context.Context, ledger *Ledger) context.Context {
	return context.WithValue(ctx, contextKey{}, ledger)
}

func WithPhase(ctx context.Context, phase Phase) context.Context {
	return context.WithValue(ctx, phaseKey{}, phase)
}

type Ledger struct {
	mu      sync.Mutex
	runID   string
	started time.Time
	nextID  int
	records []Record
}

func New() *Ledger {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		panic(err)
	}
	return &Ledger{runID: hex.EncodeToString(id[:]), started: time.Now(), records: []Record{}}
}

type Request struct {
	ledger                    *Ledger
	id                        string
	phase                     Phase
	model, purpose, transport string
}

// Begin assigns one ID to the logical call; retries share it and have distinct
// attempt numbers. No record is made until a transport attempt is started.
func Begin(ctx context.Context, transport, model, purpose string) *Request {
	l, _ := ctx.Value(contextKey{}).(*Ledger)
	if l == nil {
		return nil
	}
	phase, _ := ctx.Value(phaseKey{}).(Phase)
	l.mu.Lock()
	l.nextID++
	id := fmt.Sprintf("%s-%d", l.runID, l.nextID)
	l.mu.Unlock()
	return &Request{ledger: l, id: id, phase: phase, model: model, purpose: purpose, transport: transport}
}

type Result struct {
	Tokens      Tokens
	UsageStatus string // reported, partial, unknown
	Model       string // Empty if no model was returned.
	Status      string // completed, error, cancelled
	Reason      string // Categorical only: never raw errors or response bodies.
	HTTPStatus  int
	Unpriced    bool // For opaque CLI calls spanning more than one model.
}

type Record struct {
	RequestID       string    `json:"request_id"`
	Attempt         int       `json:"attempt"`
	Phase           string    `json:"phase"`
	Purpose         string    `json:"purpose"`
	Provider        string    `json:"provider"`
	Transport       string    `json:"transport"`
	RequestedModel  string    `json:"requested_model"`
	ReportedModel   string    `json:"reported_model,omitempty"`
	PricingModel    string    `json:"pricing_model"`
	PricingVersion  string    `json:"pricing_version"`
	Pricing         Pricing   `json:"pricing"`
	StartedAt       time.Time `json:"started_at"`
	DurationMS      int64     `json:"duration_ms"`
	Status          string    `json:"status"`
	Reason          string    `json:"reason,omitempty"`
	FallbackReason  string    `json:"fallback_reason,omitempty"`
	HTTPStatus      int       `json:"http_status,omitempty"`
	UsageStatus     string    `json:"usage_status"`
	Tokens          Tokens    `json:"tokens"`
	KnownCostUSD    float64   `json:"known_cost_usd"`
	PricingComplete bool      `json:"pricing_complete"`
}

func (r *Request) Record(attempt int, started time.Time, result Result) {
	if r == nil {
		return
	}
	if result.UsageStatus == "" {
		result.UsageStatus = "unknown"
	}
	data, _ := json.Marshal(r.phase.Pricing)
	hash := sha256.Sum256(data)
	cost, priced := r.phase.Pricing.cost(result.Tokens)
	if result.Unpriced {
		cost, priced = 0, false
	}
	record := Record{RequestID: r.id, Attempt: attempt, Phase: r.phase.Name, Purpose: r.purpose,
		Provider: r.phase.Provider, Transport: r.transport, RequestedModel: r.model,
		ReportedModel: result.Model, PricingModel: r.phase.PricingModel,
		PricingVersion: hex.EncodeToString(hash[:]), Pricing: r.phase.Pricing,
		StartedAt: started.UTC(), DurationMS: time.Since(started).Milliseconds(),
		Status: result.Status, Reason: result.Reason, FallbackReason: r.phase.FallbackReason,
		HTTPStatus: result.HTTPStatus, UsageStatus: result.UsageStatus, Tokens: result.Tokens,
		KnownCostUSD: cost, PricingComplete: priced}
	r.ledger.mu.Lock()
	r.ledger.records = append(r.ledger.records, record)
	r.ledger.mu.Unlock()
}

type Totals struct {
	Attempts             int     `json:"attempts"`
	Tokens               Tokens  `json:"tokens"`
	KnownCostUSD         float64 `json:"known_cost_usd"`
	UnknownUsageAttempts int     `json:"unknown_usage_attempts"`
	PartialUsageAttempts int     `json:"partial_usage_attempts"`
	UnpricedAttempts     int     `json:"unpriced_attempts"`
	Complete             bool    `json:"complete"`
}

func (t *Totals) add(r Record) {
	t.Attempts++
	t.Tokens.Add(r.Tokens)
	t.KnownCostUSD += r.KnownCostUSD
	switch r.UsageStatus {
	case "reported":
	case "partial":
		t.PartialUsageAttempts++
	default:
		t.UnknownUsageAttempts++
	}
	if !r.PricingComplete {
		t.UnpricedAttempts++
	}
	t.Complete = t.UnknownUsageAttempts == 0 && t.PartialUsageAttempts == 0 && t.UnpricedAttempts == 0
}

type Report struct {
	SchemaVersion int               `json:"schema_version"`
	RunID         string            `json:"run_id"`
	StartedAt     time.Time         `json:"started_at"`
	DurationMS    int64             `json:"duration_ms"`
	Status        string            `json:"status"`
	Total         Totals            `json:"total"`
	Phases        map[string]Totals `json:"phases"`
	Requests      []Record          `json:"requests"`
}

func (l *Ledger) Snapshot(status string) Report {
	l.mu.Lock()
	defer l.mu.Unlock()
	r := Report{SchemaVersion: 1, RunID: l.runID, StartedAt: l.started.UTC(),
		DurationMS: time.Since(l.started).Milliseconds(), Status: status,
		Total: Totals{Complete: true}, Phases: map[string]Totals{}, Requests: append([]Record{}, l.records...)}
	sort.Slice(r.Requests, func(i, j int) bool { return r.Requests[i].StartedAt.Before(r.Requests[j].StartedAt) })
	for _, request := range r.Requests {
		r.Total.add(request)
		phase := r.Phases[request.Phase]
		phase.add(request)
		r.Phases[request.Phase] = phase
	}
	return r
}
