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
	"github.com/block/codecrucible/internal/sarif"
)

// runLegacyAuditBatch preserves accepted verdicts and retries only unassessed
// claims. Transport retries remain the client's responsibility.
func runLegacyAuditBatch(ctx context.Context, batch []auditClaim, label string, model config.ModelConfig,
	call func([]auditClaim, string) (*llm.ChatResponse, error),
	observers ...func([]auditClaim, *llm.ChatResponse, map[string]json.RawMessage, map[string]bool, error) error,
) (result AuditResult, usage llm.TokenUsage, cost float64, returnErr error) {
	defer func() { result.NewFindings, result.DiscardedAdditions = deduplicateLegacyAdditions(result.NewFindings) }()
	var lastErr error
	pending := batch
	for attempt := 0; attempt < 2 && len(pending) > 0; attempt++ {
		if err := ctx.Err(); err != nil {
			return result, usage, cost, err
		}
		if attempt > 0 {
			slog.Warn("audit response incomplete; retrying unassessed claims", "label", label, "claims", len(pending), "error", lastErr)
		}
		resp, err := call(pending, label)
		if err != nil {
			for _, observe := range observers {
				if e := observe(pending, resp, nil, nil, err); e != nil {
					return result, usage, cost, e
				}
			}
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
			for _, observe := range observers {
				if e := observe(pending, resp, nil, nil, lastErr); e != nil {
					return result, usage, cost, e
				}
			}
			continue
		}
		accepted, err := acceptLegacyVerdicts(pending, parsed.AuditedFindings)
		lastErr = err
		acceptedIDs := map[string]bool{}
		for _, a := range accepted {
			acceptedIDs[a.FindingID] = true
		}
		for _, observe := range observers {
			if e := observe(pending, resp, rawAssessments(parsed.AuditedFindings, func(a AuditedFinding) string { return a.FindingID }), acceptedIDs, err); e != nil {
				return result, usage, cost, e
			}
		}
		result.AuditedFindings = append(result.AuditedFindings, accepted...)
		if err != nil {
			slog.Warn("audit response contains missing or invalid verdicts", "label", label, "accepted", len(accepted), "error", err)
		}
		for ordinal, finding := range parsed.NewFindings {
			finding.ProducerID = resp.ProducerID
			finding.ProducerOrdinal = ordinal
			result.NewFindings = append(result.NewFindings, finding)
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
	originals := make(map[string]auditClaim, len(claims))
	byKey := make(map[auditFindingKey]string, len(claims))
	for _, claim := range claims {
		want[claim.FindingID] = true
		originals[claim.FindingID] = claim
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
		original := originals[finding.FindingID]
		if (finding.OriginalIssue != "" && finding.OriginalIssue != original.Issue) ||
			(finding.FilePath != "" && finding.FilePath != original.FilePath) ||
			(finding.StartLine != 0 && finding.StartLine != original.StartLine) {
			note(fmt.Errorf("audit claim identity mismatch for %s", finding.FindingID))
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

// legacyAdditionKey groups retry candidates without model CWE relabeling.
func legacyAdditionKey(f NewFinding) string {
	key, _ := json.Marshal([]any{f.FilePath, f.StartLine, strings.ToLower(strings.Join(strings.Fields(f.Issue), " "))})
	return string(key)
}
func legacyAdditionAnchors(f NewFinding) string {
	if len(f.CodePath) == 0 {
		return ""
	}
	first, last := f.CodePath[0], f.CodePath[len(f.CodePath)-1]
	key, _ := json.Marshal([]any{first.FilePath, first.StartLine, last.FilePath, last.StartLine})
	return string(key)
}

// sameLegacyAddition compares structured identity, never diagnostic prose.
func sameLegacyAddition(a, b NewFinding) bool {
	if a.FilePath != b.FilePath || a.StartLine != b.StartLine {
		return false
	}
	ac, bc := sarif.NormalizeCWE(a.CWEID), sarif.NormalizeCWE(b.CWEID)
	return legacyAdditionKey(a) == legacyAdditionKey(b) || (ac != "" && ac != "CWE-0" && ac == bc && legacyAdditionAnchors(a) != "" && legacyAdditionAnchors(a) == legacyAdditionAnchors(b))
}

func deduplicateLegacyAdditions(findings []NewFinding, originals ...*NewFinding) (kept, discarded []NewFinding) {
	all := append([]NewFinding{}, findings...)
	for _, original := range originals {
		all = append(all, *original)
	}
	signature := func(f NewFinding) string {
		sig := legacyAdditionAnchors(f)
		if sig != "" {
			return sig
		}
		anchors := map[string]bool{}
		for _, other := range all {
			if legacyAdditionKey(f) == legacyAdditionKey(other) {
				if anchor := legacyAdditionAnchors(other); anchor != "" {
					anchors[anchor] = true
				}
			}
		}
		if len(anchors) == 1 {
			for anchor := range anchors {
				return anchor
			}
		}
		return ""
	}
	var identities []NewFinding
	for _, f := range findings {
		sig := signature(f)
		var matches []*NewFinding
		for i, original := range originals {
			identity := all[len(findings)+i]
			if sameLegacyAddition(f, identity) && sig == signature(identity) {
				matches = append(matches, original)
			}
		}
		if len(matches) == 1 {
			if len(matches[0].CodePath) == 0 {
				matches[0].CodePath = f.CodePath
			}
			f.DiscardReason = "duplicate of analysis finding"
			discarded = append(discarded, f)
			continue
		}
		match := -1
		for i, previous := range identities {
			if sameLegacyAddition(f, previous) && sig == signature(previous) {
				match = i
				break
			}
		}
		if match < 0 {
			kept = append(kept, f)
			identities = append(identities, f)
			continue
		}
		if f.Confidence > kept[match].Confidence {
			identities[match] = f
			discarded = append(discarded, kept[match])
			if len(f.CodePath) == 0 {
				f.CodePath = kept[match].CodePath
			}
			kept[match] = f
		} else {
			if len(kept[match].CodePath) == 0 {
				kept[match].CodePath = f.CodePath
			}
			discarded = append(discarded, f)
		}
	}
	return
}
