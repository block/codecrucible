package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"strings"

	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/llm"
)

// runLegacyAuditBatch preserves accepted verdicts and retries only unassessed
// claims. Transport retries remain the client's responsibility.
func runLegacyAuditBatch(ctx context.Context, batch []auditClaim, label string, model config.ModelConfig,
	call func([]auditClaim, string) (*llm.ChatResponse, error),
) (AuditResult, llm.TokenUsage, float64, error) {
	var result AuditResult
	var usage llm.TokenUsage
	var cost float64
	var lastErr error
	pending := batch
	newFindings := make(map[auditFindingKey]bool)
	for attempt := 0; attempt < 2 && len(pending) > 0; attempt++ {
		if err := ctx.Err(); err != nil {
			return result, usage, cost, err
		}
		if attempt > 0 {
			slog.Warn("audit response incomplete; retrying unassessed claims", "label", label, "claims", len(pending), "error", lastErr)
		}
		resp, err := call(pending, label)
		if err != nil {
			return result, usage, cost, fmt.Errorf("LLM call: %w", err)
		}
		usage.PromptTokens += resp.Usage.PromptTokens
		usage.CompletionTokens += resp.Usage.CompletionTokens
		cost += model.EstimateCost(resp.Usage.PromptTokens, resp.Usage.CompletionTokens)
		var parsed AuditResult
		lastErr = json.Unmarshal([]byte(resp.Content), &parsed)
		if lastErr != nil {
			if content, changed := llm.RepairJSON(resp.Content); changed {
				parsed = AuditResult{}
				lastErr = json.Unmarshal([]byte(content), &parsed)
			}
		}
		if resp.FinishReason == "length" || resp.FinishReason == "max_tokens" {
			lastErr = fmt.Errorf("audit response exceeded output token limit")
		}
		if lastErr != nil {
			continue
		}
		accepted, err := acceptLegacyVerdicts(pending, parsed.AuditedFindings)
		lastErr = err
		result.AuditedFindings = append(result.AuditedFindings, accepted...)
		if err != nil {
			slog.Warn("audit response contains missing or invalid verdicts", "label", label, "accepted", len(accepted), "error", err)
		}
		for _, finding := range parsed.NewFindings {
			key := auditFindingKey{finding.FilePath, finding.StartLine, finding.Issue}
			if !newFindings[key] {
				result.NewFindings = append(result.NewFindings, finding)
				newFindings[key] = true
			}
		}
		if parsed.AuditSummary != "" {
			result.AuditSummary = strings.TrimSpace(result.AuditSummary + "\n\n" + parsed.AuditSummary)
		}
		got := make(map[string]bool, len(accepted))
		for _, finding := range accepted {
			got[finding.FindingID] = true
		}
		var remaining []auditClaim
		for _, claim := range pending {
			if !got[claim.FindingID] {
				remaining = append(remaining, claim)
			}
		}
		pending = remaining
	}
	if len(pending) > 0 {
		return result, usage, cost, fmt.Errorf("audit left %d of %d findings unassessed after 2 attempts: %w", len(pending), len(batch), lastErr)
	}
	slog.Info("audit batch complete", "label", label, "audited", len(result.AuditedFindings),
		"prompt_tokens", usage.PromptTokens, "completion_tokens", usage.CompletionTokens, "cost", fmt.Sprintf("$%.4f", cost))
	return result, usage, cost, nil
}

type auditFindingKey struct {
	filePath  string
	startLine int
	issue     string
}

// acceptLegacyVerdicts matches IDs first. Responses from older/custom prompts
// without IDs can match only an exact, unique original key. Unknown IDs never
// fall back to location matching, and conflicting duplicates are both ignored.
func acceptLegacyVerdicts(claims []auditClaim, findings []AuditedFinding) ([]AuditedFinding, error) {
	want := make(map[string]bool, len(claims))
	byKey := make(map[auditFindingKey]string, len(claims))
	for _, claim := range claims {
		want[claim.FindingID] = true
		key := auditFindingKey{claim.FilePath, claim.StartLine, claim.Issue}
		if _, exists := byKey[key]; exists {
			byKey[key] = "" // Ambiguous old-style keys must not select a finding.
		} else {
			byKey[key] = claim.FindingID
		}
	}
	var problem error
	note := func(err error) {
		if problem == nil {
			problem = err
		}
	}
	counts := make(map[string]int)
	var matched []AuditedFinding
	for _, finding := range findings {
		finding.FindingID = strings.TrimSpace(finding.FindingID)
		if finding.FindingID == "" {
			finding.FindingID = byKey[auditFindingKey{finding.FilePath, finding.StartLine, finding.OriginalIssue}]
		}
		if !want[finding.FindingID] {
			note(fmt.Errorf("audit returned an unknown or ambiguous finding: %q %s:%d %q", finding.FindingID, finding.FilePath, finding.StartLine, finding.OriginalIssue))
			continue
		}
		counts[finding.FindingID]++
		matched = append(matched, finding)
	}
	var accepted []AuditedFinding
	for _, finding := range matched {
		if counts[finding.FindingID] != 1 {
			note(fmt.Errorf("audit returned duplicate finding_id %q", finding.FindingID))
			continue
		}
		switch finding.Verdict {
		case "confirmed", "refined", "rejected", "escalated", "unverified":
		default:
			note(fmt.Errorf("audit returned invalid verdict %q", finding.Verdict))
			continue
		}
		if math.IsNaN(finding.Confidence) || finding.Confidence < 0 || finding.Confidence > 1 {
			note(fmt.Errorf("audit returned invalid confidence"))
			continue
		}
		accepted = append(accepted, finding)
	}
	if len(accepted) < len(claims) {
		note(fmt.Errorf("audit omitted valid verdicts for %d findings", len(claims)-len(accepted)))
	}
	return accepted, problem
}
