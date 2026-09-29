package usage

import (
	"context"
	"math"
	"sync"
	"testing"
	"time"
)

func TestLedgerAccountsForRetriesPartialAndUnpricedUsage(t *testing.T) {
	l := New()
	ctx := WithPhase(WithLedger(context.Background(), l), Phase{Name: "analysis", Provider: "openai", PricingModel: "model", Pricing: Pricing{InputPerMillion: 2, OutputPerMillion: 10}})
	r := Begin(ctx, "http", "model", "chunk 1")
	r.Record(1, time.Now(), Result{Status: "error", Reason: "rate_limited", HTTPStatus: 429})
	r.Record(2, time.Now(), Result{Status: "completed", UsageStatus: "reported", Model: "model-v1", Tokens: Tokens{PromptTokens: 1000, CompletionTokens: 100, ReasoningTokens: 40}})
	ctx = WithPhase(ctx, Phase{Name: "audit", Provider: "anthropic", PricingModel: "audit", Pricing: Pricing{InputPerMillion: 2, OutputPerMillion: 10}})
	Begin(ctx, "http", "audit", "audit 1").Record(1, time.Now(), Result{Status: "error", UsageStatus: "partial", Tokens: Tokens{PromptTokens: 500, CacheReadTokens: 1000}})
	ctx = WithPhase(ctx, Phase{Name: "feature-detection", Provider: "custom", PricingModel: "unknown"})
	Begin(ctx, "http", "unknown", "feature-detection").Record(1, time.Now(), Result{Status: "completed", UsageStatus: "reported", Tokens: Tokens{PromptTokens: 100}})
	report := l.Snapshot("failed")
	if report.Total.Attempts != 4 || report.Total.Tokens.PromptTokens != 1600 || report.Total.Tokens.ReasoningTokens != 40 {
		t.Fatalf("wrong totals: %+v", report.Total)
	}
	if math.Abs(report.Total.KnownCostUSD-0.004) > 1e-12 {
		t.Fatalf("cost = %v; reasoning must not be charged twice", report.Total.KnownCostUSD)
	}
	if report.Total.Complete || report.Total.UnknownUsageAttempts != 1 || report.Total.PartialUsageAttempts != 1 || report.Total.UnpricedAttempts != 2 {
		t.Fatalf("incomplete usage hidden: %+v", report.Total)
	}
	if report.Requests[0].RequestID != report.Requests[1].RequestID || report.Requests[1].Attempt != 2 {
		t.Fatal("retry correlation lost")
	}
	if report.Requests[1].ReportedModel != "model-v1" || report.Requests[1].PricingVersion == "" {
		t.Fatal("model/rate provenance lost")
	}
	if report.Phases["audit"].Tokens.CacheReadTokens != 1000 {
		t.Fatal("cache usage lost")
	}
}

func TestLedgerConcurrentCallsAndSnapshots(t *testing.T) {
	l := New()
	ctx := WithLedger(context.Background(), l)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			Begin(ctx, "http", "m", "analysis").Record(1, time.Now(), Result{Status: "completed", UsageStatus: "reported", Tokens: Tokens{PromptTokens: 1}})
			l.Snapshot("running")
		}()
	}
	wg.Wait()
	r := l.Snapshot("completed")
	ids := map[string]bool{}
	for _, a := range r.Requests {
		if ids[a.RequestID] {
			t.Fatal("duplicate request ID")
		}
		ids[a.RequestID] = true
	}
	if r.Total.Attempts != 100 || r.Total.Tokens.PromptTokens != 100 {
		t.Fatalf("lost requests: %+v", r.Total)
	}
}

func TestPricingLongContextAndCachedSubsets(t *testing.T) {
	p := Pricing{InputPerMillion: 2, OutputPerMillion: 10, LongContextThreshold: 1000, LongInputPerMillion: 4, LongOutputPerMillion: 20}
	cost, complete := p.cost(Tokens{PromptTokens: 1100, CompletionTokens: 100, ReasoningTokens: 50})
	if !complete || math.Abs(cost-0.0064) > 1e-12 {
		t.Fatalf("long-context price = %v, %v", cost, complete)
	}
	cost, complete = p.cost(Tokens{PromptTokens: 1000, CachedPromptTokens: 400, CompletionTokens: 100})
	if complete || math.Abs(cost-0.0022) > 1e-12 {
		t.Fatalf("unpriced cached tokens charged as normal input: %v, %v", cost, complete)
	}
}
