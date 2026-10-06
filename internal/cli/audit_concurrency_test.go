package cli

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/llm"
	"github.com/block/codecrucible/internal/sarif"
	"github.com/block/codecrucible/internal/tokenestimate"
)

func TestAuditConcurrencyBoundAndCancellation(t *testing.T) {
	for _, cancelRun := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "cancelled"}[cancelRun], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			doc := auditFixture()
			doc.Runs[0].Results = append(doc.Runs[0].Results, doc.Runs[0].Results...)
			started := make(chan struct{}, 4)
			release := make(chan struct{})
			var active, peak, calls atomic.Int32
			client := auditClientFunc(func(ctx context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
				n := active.Add(1)
				defer active.Add(-1)
				for old := peak.Load(); n > old; old = peak.Load() {
					if peak.CompareAndSwap(old, n) {
						break
					}
				}
				calls.Add(1)
				started <- struct{}{}
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-release:
				}
				return verdictResponse(requestedClaims(t, req)...), nil
			})
			type outcome struct {
				doc   *sarif.SARIFDocument
				usage llm.TokenUsage
				err   error
			}
			done := make(chan outcome, 1)
			go func() {
				got, usage, _, err := runAuditPhase(ctx, doc, "fixture", client, "", config.ModelConfig{Name: "test"}, llm.NewPromptLoader(os.DirFS("../../prompts/default")), llm.OutputModeNone,
					ingest.FileMap{"a.go": "sink()", "b.go": "sink()"}, .3, nil, "", 1, 2, true, tokenestimate.New(tokenestimate.Model{}, nil), nil, nil)
				done <- outcome{got, usage, err}
			}()
			for i := 0; i < 2; i++ {
				select {
				case <-started:
				case <-time.After(3 * time.Second):
					cancel()
					t.Fatal("audit did not run two batches concurrently")
				}
			}
			if cancelRun {
				cancel()
			} else {
				close(release)
			}
			var got outcome
			select {
			case got = <-done:
			case <-time.After(3 * time.Second):
				cancel()
				t.Fatal("audit workers did not finish")
			}
			if got.doc == nil || len(got.doc.Runs[0].Results) != 4 {
				t.Fatal("lost findings")
			}
			if peak.Load() != 2 || active.Load() != 0 {
				t.Fatalf("peak=%d active=%d", peak.Load(), active.Load())
			}
			wantStatus := "confirmed"
			if cancelRun {
				wantStatus = "not_audited"
				if !errors.Is(got.err, context.Canceled) || calls.Load() != 2 {
					t.Fatalf("cancellation calls=%d err=%v", calls.Load(), got.err)
				}
			} else if got.err != nil || calls.Load() != 4 || got.usage.PromptTokens != 40 {
				t.Fatalf("calls=%d err=%v usage=%+v", calls.Load(), got.err, got.usage)
			}
			ids := map[string]bool{}
			for i, result := range got.doc.Runs[0].Results {
				if result.RuleID != doc.Runs[0].Results[i].RuleID || result.Properties.AuditStatus != wantStatus {
					t.Fatal("nondeterministic order or lost status")
				}
				if ids[result.Properties.FindingID] || result.Properties.FindingID == "" {
					t.Fatal("duplicate finding ID")
				}
				ids[result.Properties.FindingID] = true
			}
		})
	}
}

func TestAuditCancellationPreservesCompletedConcurrentBatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	firstReturned := make(chan struct{})
	client := auditClientFunc(func(ctx context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
		findings := requestedClaims(t, req)
		if findings[0].OriginalIssue == "First" {
			close(firstReturned)
			return verdictResponse(findings...), nil
		}
		<-firstReturned
		cancel()
		return nil, ctx.Err()
	})
	doc, _, _, err := runAuditPhase(ctx, auditFixture(), "fixture", client, "", config.ModelConfig{Name: "test"}, llm.NewPromptLoader(os.DirFS("../../prompts/default")), llm.OutputModeNone,
		ingest.FileMap{"a.go": "sink()", "b.go": "sink()"}, .3, nil, "", 1, 2, true, tokenestimate.New(tokenestimate.Model{}, nil), nil, nil)
	if !errors.Is(err, context.Canceled) || doc == nil || len(doc.Runs[0].Results) != 2 {
		t.Fatalf("err=%v doc=%+v", err, doc)
	}
	if doc.Runs[0].Results[0].Properties.AuditStatus != "confirmed" || doc.Runs[0].Results[1].Properties.AuditStatus != "not_audited" {
		t.Fatal("cancellation lost completed verdicts")
	}
}
