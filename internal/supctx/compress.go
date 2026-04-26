package supctx

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/block/codecrucible/internal/llm"
)

// Compressor holds everything the compress pre-pass needs: an LLM client
// wired to the context-compress phase config, the prompt template, and a
// counter for re-measuring the result.
type Compressor struct {
	Client  llm.Client
	Prompt  llm.ContextCompressPrompt
	Counter TokenCounter
	Model   string // sent in ChatRequest.Model
}

// Compress squeezes sources that exceed their fair share of the budget. Only
// sources with Compress==true are touched; the rest pass through unchanged.
// Failures log and fall back to the original content — packing will then
// truncate instead.
//
// "Fair share" is budget / len(sources): crude, but it means a single huge
// doc doesn't starve a set of small ones just because it was listed first.
func (c *Compressor) Compress(ctx context.Context, loaded []Loaded, budget int) []Loaded {
	if budget <= 0 || len(loaded) == 0 {
		return loaded
	}
	share := budget / len(loaded)
	if share < 200 {
		share = 200 // floor — below this the summary is useless
	}

	out := make([]Loaded, len(loaded))
	copy(out, loaded)

	for i := range out {
		l := &out[i]
		if !l.Compress || l.Tokens <= share {
			continue
		}
		slog.Info("compressing context source", "name", l.Name, "tokens", l.Tokens, "target", share)

		compressed, err := c.compressOne(ctx, l.Name, l.Content, share)
		if err != nil {
			slog.Warn("context compression failed, will truncate instead",
				"name", l.Name, "error", err)
			continue
		}
		l.Content = compressed
		l.Tokens = c.Counter.Count(compressed)
		slog.Info("context source compressed", "name", l.Name, "tokens", l.Tokens)
	}
	return out
}

func (c *Compressor) compressOne(ctx context.Context, name, content string, target int) (string, error) {
	user := c.Prompt.UserPromptTemplate
	user = strings.ReplaceAll(user, "{source_name}", name)
	user = strings.ReplaceAll(user, "{target_tokens}", fmt.Sprintf("%d", target))
	user = strings.ReplaceAll(user, "{content}", content)

	resp, err := c.Client.ChatCompletion(ctx, llm.ChatRequest{
		Label: fmt.Sprintf("context-compress %s", name),
		Model: c.Model,
		Messages: []llm.Message{
			{Role: "system", Content: c.Prompt.SystemMessage},
			{Role: "user", Content: user},
		},
		// Give the model headroom above target — it can't count its own
		// tokens precisely, and truncating a summary mid-sentence is worse
		// than going slightly over. Pack will enforce the hard budget.
		MaxTokens:  target * 2,
		OutputMode: llm.OutputModeNone,
	})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(resp.Content), nil
}
