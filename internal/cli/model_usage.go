package cli

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"sync"

	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/llm"
	"github.com/block/codecrucible/internal/provenance"
	"github.com/block/codecrucible/internal/sarif"
)

// modelUsage tallies each phase's LLM calls by the model ID sent. Phase
// clients run concurrently, so calls update this guarded state and apply
// copies it into the scan metadata from the scan goroutine.
type modelUsage struct {
	maxInputTokens int64
	inputTokens    int64
	budgetDenied   bool
	mu             sync.Mutex
	phases         map[string]map[string]*sarif.ModelExecution
	lineage        *provenance.Ledger
}

func newModelUsage() *modelUsage {
	return &modelUsage{phases: map[string]map[string]*sarif.ModelExecution{}}
}

// wrap records the calls a phase makes through client, costed at model's prices.
func (u *modelUsage) wrap(phase string, client llm.Client, model config.ModelConfig) llm.Client {
	if u == nil || client == nil {
		return client
	}
	// A fallback reuses the transport, not the originating phase's observers.
	// Remove both wrappers regardless of their order so the call is counted
	// and traced exactly once under the phase that actually made it.
	for {
		switch c := client.(type) {
		case *recordingClient:
			client = c.next
		case *lineageClient:
			client = c.base
		default:
			if u.lineage != nil {
				client = traceClient(client, u.lineage, phase)
			}
			return &recordingClient{next: client, usage: u, phase: phase, model: model}
		}
	}
}

type recordingClient struct {
	next  llm.Client
	usage *modelUsage
	phase string
	model config.ModelConfig
}

func (c *recordingClient) ChatCompletion(ctx context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
	if err := c.usage.admit(); err != nil {
		return nil, err
	}
	resp, err := c.next.ChatCompletion(ctx, req)
	c.usage.record(c.phase, llm.RequestModel(req), c.model, resp, err)
	logModelResponse(c.phase, req, resp)
	return resp, err
}

// logModelResponse records every response's completion metadata before any
// caller parses its content, so an output-limit stop is visible even when the
// answer is empty. It logs counts only: never prompts, content or reasoning.
func logModelResponse(phase string, req llm.ChatRequest, resp *llm.ChatResponse) {
	if resp == nil {
		return
	}
	attrs := []any{
		"phase", phase,
		"label", req.Label,
		"finish_reason", resp.FinishReason,
		"max_output_tokens", req.MaxTokens,
		"completion_tokens", resp.Usage.CompletionTokens,
		"reasoning_tokens", resp.Usage.ReasoningTokens,
		"content_bytes", len(resp.Content),
		"model", llm.RequestModel(req),
	}
	if resp.Model != "" {
		attrs = append(attrs, "resolved_model", resp.Model)
	}
	if resp.OutputLimited() {
		slog.Warn("model response stopped at output limit", attrs...)
		return
	}
	slog.Info("model response received", attrs...)
}

func (u *modelUsage) record(phase, model string, cfg config.ModelConfig, resp *llm.ChatResponse, err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	models := u.phases[phase]
	if models == nil {
		models = map[string]*sarif.ModelExecution{}
		u.phases[phase] = models
	}
	m := models[model]
	if m == nil {
		m = &sarif.ModelExecution{Model: model, ResponseModels: []string{}}
		models[model] = m
	}
	m.Calls++
	if err != nil || resp == nil {
		m.Failures++
	}
	if resp == nil {
		return
	}
	u.inputTokens += int64(max(0, resp.Usage.PromptTokens))
	m.PromptTokens += resp.Usage.PromptTokens
	m.CompletionTokens += resp.Usage.CompletionTokens
	m.ReasoningTokens += resp.Usage.ReasoningTokens
	m.EstimatedCost += cfg.EstimateCost(resp.Usage.PromptTokens, resp.Usage.CompletionTokens)
	if resp.Model != "" && !slices.Contains(m.ResponseModels, resp.Model) {
		m.ResponseModels = append(m.ResponseModels, resp.Model)
		sort.Strings(m.ResponseModels)
	}
	if resp.Sent != nil {
		if resp.Sent.TemperatureOmitted {
			m.TemperatureOmitted++
		}
		if resp.Sent.MaxTokensParam == "max_completion_tokens" {
			m.MaxCompletionTokens++
		}
	}
}

// apply replaces the metadata's model tallies with the calls recorded so far.
func (u *modelUsage) apply(m *sarif.ScanMetadata) {
	if u == nil || m == nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	m.Execution.InputTokens = u.inputTokens
	m.Execution.InputTokenBudgetExhausted = u.budgetDenied || u.maxInputTokens > 0 && u.inputTokens > u.maxInputTokens
	used := map[string]bool{}
	for phase, models := range u.phases {
		list := make([]sarif.ModelExecution, 0, len(models))
		for _, model := range models {
			entry := *model
			entry.ResponseModels = append([]string{}, model.ResponseModels...)
			list = append(list, entry)
			for _, served := range entry.ResponseModels {
				used[served] = true
			}
			if len(entry.ResponseModels) == 0 && entry.Calls > entry.Failures {
				used[entry.Model] = true
			}
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Model < list[j].Model })
		state := m.Execution.Phases[phase]
		state.Models = list
		m.Execution.Phases[phase] = state
	}
	m.Execution.Models = make([]string, 0, len(used))
	for model := range used {
		m.Execution.Models = append(m.Execution.Models, model)
	}
	sort.Strings(m.Execution.Models)
}

// admit checks reported usage at request boundaries. Already-running requests
// may finish over the threshold; they remain accounted and are never cancelled.
func (u *modelUsage) admit() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.maxInputTokens > 0 && u.inputTokens >= u.maxInputTokens {
		u.budgetDenied = true
		return fmt.Errorf("input token budget exhausted: used %d, limit %d", u.inputTokens, u.maxInputTokens)
	}
	return nil
}

func (u *modelUsage) budgetError() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.budgetDenied || u.maxInputTokens > 0 && u.inputTokens > u.maxInputTokens {
		return fmt.Errorf("input token budget exhausted: used %d, limit %d; partial results retained", u.inputTokens, u.maxInputTokens)
	}
	return nil
}
