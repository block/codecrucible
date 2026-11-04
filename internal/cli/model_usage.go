package cli

import (
	"context"
	"slices"
	"sort"
	"sync"

	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/llm"
	"github.com/block/codecrucible/internal/sarif"
)

// modelUsage tallies each phase's LLM calls by the model ID sent. Phase
// clients run concurrently, so calls update this guarded state and apply
// copies it into the scan metadata from the scan goroutine.
type modelUsage struct {
	mu     sync.Mutex
	phases map[string]map[string]*sarif.ModelExecution
}

func newModelUsage() *modelUsage {
	return &modelUsage{phases: map[string]map[string]*sarif.ModelExecution{}}
}

// wrap records the calls a phase makes through client, costed at model's prices.
func (u *modelUsage) wrap(phase string, client llm.Client, model config.ModelConfig) llm.Client {
	if u == nil || client == nil {
		return client
	}
	// A phase that falls back to another phase's client is tallied as itself.
	if recording, ok := client.(*recordingClient); ok {
		client = recording.next
	}
	return &recordingClient{next: client, usage: u, phase: phase, model: model}
}

type recordingClient struct {
	next  llm.Client
	usage *modelUsage
	phase string
	model config.ModelConfig
}

func (c *recordingClient) ChatCompletion(ctx context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
	resp, err := c.next.ChatCompletion(ctx, req)
	c.usage.record(c.phase, llm.RequestModel(req), c.model, resp, err)
	return resp, err
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
		return
	}
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
