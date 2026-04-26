package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/block/codecrucible/internal/chunk"
	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/llm"
	"github.com/block/codecrucible/internal/sarif"
)

// analyzeChunk processes a single chunk: assembles the prompt, calls the LLM, parses
// the response, and builds a per-chunk SARIF document. Safe for concurrent use.
func analyzeChunk(
	ctx context.Context,
	c chunk.Chunk,
	repoName string,
	client llm.Client,
	endpoint string,
	modelCfg config.ModelConfig,
	promptLoader *llm.PromptLoader,
	schema *json.RawMessage,
	outputMode llm.OutputMode,
	customRequirements string,
	supContext string,
	enabledFeatures []string,
	fileMap ingest.FileMap,
	modelParams map[string]any,
) (sarif.SARIFDocument, llm.TokenUsage, float64, error) {
	start := time.Now()
	slog.Info("analyzing chunk",
		"chunk", fmt.Sprintf("%d/%d", c.Index+1, c.Total),
		"files", len(c.Paths),
		"tokens", c.Tokens,
	)

	// Build manifest of files not in this chunk.
	var otherPaths []string
	if c.Total > 1 {
		pathSet := make(map[string]bool, len(c.Paths))
		for _, p := range c.Paths {
			pathSet[p] = true
		}
		for _, p := range c.Manifest {
			if !pathSet[p] {
				otherPaths = append(otherPaths, p)
			}
		}
	}

	// Build manifest with summaries for cross-chunk context.
	// Cap manifest size to ~10% of context limit (in characters, ~4 chars/token)
	// to avoid crowding out file content in large repos.
	manifestCharBudget := modelCfg.ContextLimit / 10 * 4
	manifest := capManifest(otherPaths, manifestCharBudget)
	if len(c.RelatedSummaries) > 0 {
		// Prepend related summaries before the raw path list.
		var enriched []string
		enriched = append(enriched, "Related files (summaries):")
		enriched = append(enriched, c.RelatedSummaries...)
		enriched = append(enriched, "")
		enriched = append(enriched, "Other files:")
		enriched = append(enriched, manifest...)
		manifest = enriched
	}

	// Expand per-chunk placeholders in custom requirements so that prompt
	// templates can reference the files in this specific chunk, the chunk
	// index/total, and the detected feature set.
	expandedRequirements := customRequirements
	if strings.Contains(expandedRequirements, "{") {
		expandedRequirements = strings.ReplaceAll(expandedRequirements, "{chunk_files}", strings.Join(c.Paths, "\n"))
		expandedRequirements = strings.ReplaceAll(expandedRequirements, "{chunk_index}", fmt.Sprintf("%d", c.Index+1))
		expandedRequirements = strings.ReplaceAll(expandedRequirements, "{chunk_total}", fmt.Sprintf("%d", c.Total))
		expandedRequirements = strings.ReplaceAll(expandedRequirements, "{detected_features}", strings.Join(enabledFeatures, ", "))
	}

	messages, err := promptLoader.AssembleMessages(llm.PromptParams{
		RepoName:             repoName,
		XML:                  c.XML,
		Schema:               string(*schema),
		Manifest:             manifest,
		ChunkIndex:           c.Index,
		ChunkTotal:           c.Total,
		CustomRequirements:   expandedRequirements,
		EnabledFeatures:      enabledFeatures,
		SupplementaryContext: supContext,
	})
	if err != nil {
		slog.Error("failed to assemble prompt", "chunk", c.Index, "error", err)
		doc := sarif.Build(sarif.AnalysisResult{RepoName: repoName}, nil, sarif.BuilderConfig{})
		doc.Runs[0].Invocations = []sarif.SARIFInvocation{{
			ExecutionSuccessful: false,
			ToolExecutionNotifications: []sarif.SARIFNotification{{
				Level:   "error",
				Message: sarif.SARIFMessage{Text: fmt.Sprintf("chunk %d/%d: failed to assemble prompt: %v", c.Index+1, c.Total, err)},
			}},
		}}
		return doc, llm.TokenUsage{}, 0, nil
	}

	chunkLabel := fmt.Sprintf("analysis chunk %d/%d", c.Index+1, c.Total)
	resp, err := client.ChatCompletion(ctx, llm.ChatRequest{
		Label:          chunkLabel,
		Endpoint:       endpoint,
		Model:          modelCfg.Name,
		Messages:       messages,
		Temperature:    modelCfg.Temperature,
		MaxTokens:      modelCfg.MaxOutputTokens,
		ResponseSchema: schema,
		OutputMode:     outputMode,
		ModelParams:    modelParams,
	})
	if err != nil {
		// Context overflow is recoverable by the caller (split and retry).
		// Signal it distinctly instead of burying it in a SARIF notification.
		if errors.Is(err, llm.ErrContextLengthExceeded) {
			slog.Warn("chunk exceeded context window; caller will split and retry",
				"chunk", c.Index,
				"estimated_tokens", c.Tokens,
			)
			return sarif.SARIFDocument{}, llm.TokenUsage{}, 0, err
		}
		slog.Error("chunk analysis failed", "chunk", c.Index, "error", err)
		doc := sarif.Build(sarif.AnalysisResult{RepoName: repoName}, nil, sarif.BuilderConfig{})
		doc.Runs[0].Invocations = []sarif.SARIFInvocation{{
			ExecutionSuccessful: false,
			ToolExecutionNotifications: []sarif.SARIFNotification{{
				Level:   "error",
				Message: sarif.SARIFMessage{Text: fmt.Sprintf("chunk %d/%d failed: %v", c.Index+1, c.Total, err)},
			}},
		}}
		return doc, llm.TokenUsage{}, 0, nil
	}

	usage := resp.Usage
	chunkCost := float64(usage.PromptTokens)*modelCfg.InputPricePerM/1_000_000 +
		float64(usage.CompletionTokens)*modelCfg.OutputPricePerM/1_000_000

	elapsed := time.Since(start)
	attrs := []any{
		"chunk", fmt.Sprintf("%d/%d", c.Index+1, c.Total),
		"elapsed", elapsed.Round(time.Millisecond),
		"prompt_tokens", usage.PromptTokens,
		"completion_tokens", usage.CompletionTokens,
		"max_output_tokens", modelCfg.MaxOutputTokens,
		"finish_reason", resp.FinishReason,
		"cost", fmt.Sprintf("$%.4f", chunkCost),
	}
	if secs := elapsed.Seconds(); secs > 0 {
		attrs = append(attrs, "tokens_per_sec", fmt.Sprintf("%.1f", float64(usage.CompletionTokens)/secs))
	}
	// Streaming-only: ttft is prompt-processing + thinking (everything before
	// the first visible byte), gen_time is the pure output phase.
	if resp.TimeToFirstToken > 0 {
		attrs = append(attrs,
			"ttft", resp.TimeToFirstToken.Round(time.Millisecond),
			"gen_time", resp.GenerationTime.Round(time.Millisecond),
		)
	}
	if usage.ThinkingChars > 0 {
		attrs = append(attrs, "thinking_chars", usage.ThinkingChars)
	}
	if usage.CacheReadTokens > 0 || usage.CacheCreationTokens > 0 {
		attrs = append(attrs,
			"cache_read_tokens", usage.CacheReadTokens,
			"cache_creation_tokens", usage.CacheCreationTokens,
		)
	}
	if resp.Model != "" && resp.Model != modelCfg.Name {
		// API sometimes resolves aliases to dated snapshot names.
		attrs = append(attrs, "resolved_model", resp.Model)
	}
	slog.Info("chunk analysis complete", attrs...)

	// Warn if output was truncated — findings may be incomplete.
	if resp.FinishReason == "length" {
		slog.Warn("LLM output was truncated (finish_reason=length), findings may be incomplete",
			"chunk", fmt.Sprintf("%d/%d", c.Index+1, c.Total),
			"completion_tokens", usage.CompletionTokens,
			"max_output_tokens", modelCfg.MaxOutputTokens,
		)
	}

	// Parse LLM response. Three escalating attempts:
	//   1. Direct unmarshal.
	//   2. Local repair (strip fences, extract JSON, coerce string→[]).
	//   3. Ask the model to reformat its own output against the schema.
	// Only the third costs money, and only runs when 1+2 both fail.
	var result sarif.AnalysisResult
	parseErr := json.Unmarshal([]byte(resp.Content), &result)
	if parseErr != nil {
		if repaired, changed := llm.RepairJSON(resp.Content); changed {
			if err := json.Unmarshal([]byte(repaired), &result); err == nil {
				slog.Info("recovered malformed LLM response via local repair", "chunk", c.Index)
				parseErr = nil
			}
		}
	}
	if parseErr != nil && resp.FinishReason == "length" {
		// Truncation, not drift. The JSON was cut mid-object when it hit
		// max_tokens. Model-repair gets the same cap — it would re-truncate
		// or emit {"security_issues":[]} to fit, which is worse than honest
		// failure. Point at the flag that actually fixes this.
		slog.Error("output truncated at max_tokens; repair would hit the same cap",
			"chunk", c.Index,
			"completion_tokens", usage.CompletionTokens,
			"max_output_tokens", modelCfg.MaxOutputTokens,
			"fix", "increase --max-output-tokens (thinking tokens count against this limit)",
		)
		doc := sarif.Build(sarif.AnalysisResult{RepoName: repoName}, nil, sarif.BuilderConfig{})
		doc.Runs[0].Invocations = []sarif.SARIFInvocation{{
			ExecutionSuccessful: false,
			ToolExecutionNotifications: []sarif.SARIFNotification{{
				Level: "error",
				Message: sarif.SARIFMessage{Text: fmt.Sprintf(
					"chunk %d/%d: output truncated at max_tokens=%d (finish_reason=length). "+
						"Increase --max-output-tokens; thinking tokens count against this limit.",
					c.Index+1, c.Total, modelCfg.MaxOutputTokens)},
			}},
		}}
		return doc, usage, chunkCost, nil
	}
	if parseErr != nil {
		slog.Warn("local JSON repair failed; asking model to reformat",
			"chunk", c.Index,
			"parse_error", parseErr,
		)
		repairResp, repairErr := client.ChatCompletion(ctx, llm.ChatRequest{
			Label:    chunkLabel + " repair",
			Endpoint: endpoint,
			Model:    modelCfg.Name,
			Messages: []llm.Message{{
				Role: "user",
				Content: "The following output failed to parse against the required schema " +
					"(error: " + parseErr.Error() + "). " +
					"Return ONLY the corrected JSON object, nothing else:\n\n" + resp.Content,
			}},
			Temperature:    modelCfg.Temperature,
			MaxTokens:      modelCfg.MaxOutputTokens,
			ResponseSchema: schema,
			OutputMode:     outputMode,
			ModelParams:    modelParams,
		})
		if repairErr == nil {
			usage.PromptTokens += repairResp.Usage.PromptTokens
			usage.CompletionTokens += repairResp.Usage.CompletionTokens
			chunkCost += float64(repairResp.Usage.PromptTokens)*modelCfg.InputPricePerM/1_000_000 +
				float64(repairResp.Usage.CompletionTokens)*modelCfg.OutputPricePerM/1_000_000
			repaired, _ := llm.RepairJSON(repairResp.Content)
			if err := json.Unmarshal([]byte(repaired), &result); err == nil {
				slog.Info("recovered malformed LLM response via model reformat", "chunk", c.Index)
				parseErr = nil
			}
		}
	}
	if parseErr != nil {
		slog.Error("failed to parse LLM response after repair attempts", "chunk", c.Index, "error", parseErr)
		doc := sarif.Build(sarif.AnalysisResult{RepoName: repoName}, nil, sarif.BuilderConfig{})
		doc.Runs[0].Invocations = []sarif.SARIFInvocation{{
			ExecutionSuccessful: false,
			ToolExecutionNotifications: []sarif.SARIFNotification{{
				Level:   "error",
				Message: sarif.SARIFMessage{Text: fmt.Sprintf("chunk %d/%d: failed to parse LLM response: %v", c.Index+1, c.Total, parseErr)},
			}},
		}}
		return doc, usage, chunkCost, nil
	}

	doc := sarif.Build(result, sarif.FileMap(fileMap), sarif.BuilderConfig{
		ToolVersion: version,
	})
	return doc, usage, chunkCost, nil
}

// runFeatureDetection performs a lightweight LLM call to detect which security-relevant
// features the codebase uses. Returns nil (not an error) if detection fails, causing
// the analysis to fall back to including all sections.
func runFeatureDetection(
	ctx context.Context,
	files []ingest.SourceFile,
	repoName string,
	client llm.Client,
	endpoint string,
	modelCfg config.ModelConfig,
	promptLoader *llm.PromptLoader,
	outputMode llm.OutputMode,
	modelParams map[string]any,
	counter *chunk.TokenCounter,
) ([]string, float64, error) {
	// Build file manifest, capped to fit within the model's context.
	// Reserve ~50% of context for the manifest, rest for samples + prompt overhead.
	manifestCharBudget := modelCfg.ContextLimit / 2 * 4 // tokens → chars
	allPaths := make([]string, len(files))
	for i, f := range files {
		allPaths[i] = f.Path
	}
	manifest := capManifest(allPaths, manifestCharBudget)

	// Build representative code samples (capped at ~2000 tokens).
	fileEntries := make([]llm.FileEntry, len(files))
	for i, f := range files {
		fileEntries[i] = llm.FileEntry{Path: f.Path, Content: f.Content}
	}
	samples := llm.BuildFeatureSamples(fileEntries, 2000)

	messages, err := promptLoader.AssembleFeatureDetectionMessages(llm.FeaturePromptParams{
		RepoName: repoName,
		Manifest: manifest,
		Samples:  samples,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("assembling feature detection prompt: %w", err)
	}

	featureSchema := llm.FeatureDetectionSchema()

	// Local estimate of everything we're about to send: messages + tool schema.
	// The API's PromptTokens in the response is ground truth for the same
	// payload — the ratio between them is a measured correction factor for
	// this model and this repo's content, which we can apply to chunk sizing.
	localEstimate := 0
	for _, m := range messages {
		localEstimate += counter.Count(m.Content)
	}
	if outputMode == llm.OutputModeToolUse && featureSchema != nil {
		localEstimate += counter.Count(string(*featureSchema))
	}

	slog.Info("running feature detection pre-pass")

	resp, err := client.ChatCompletion(ctx, llm.ChatRequest{
		Label:          "feature-detection",
		Endpoint:       endpoint,
		Model:          modelCfg.Name,
		Messages:       messages,
		Temperature:    modelCfg.Temperature,
		MaxTokens:      modelCfg.MaxOutputTokens,
		ResponseSchema: featureSchema,
		OutputMode:     outputMode,
		ModelParams:    modelParams,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("feature detection LLM call: %w", err)
	}

	// Correction factor: actual/estimated. 1.0 means the heuristic is exact;
	// >1.0 means we undercount and need to shrink chunks; <1.0 means we're
	// conservative already. 0 signals "no calibration available".
	var correction float64
	if localEstimate > 0 && resp.Usage.PromptTokens > 0 {
		correction = float64(resp.Usage.PromptTokens) / float64(localEstimate)
		slog.Info("tokenizer calibration measured",
			"local_estimate", localEstimate,
			"api_actual", resp.Usage.PromptTokens,
			"correction_factor", fmt.Sprintf("%.3f", correction),
		)
	}

	var result struct {
		DetectedFeatures []string `json:"detected_features"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		return nil, correction, fmt.Errorf("parsing feature detection response: %w", err)
	}

	return result.DetectedFeatures, correction, nil
}
