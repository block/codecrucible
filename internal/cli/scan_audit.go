package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/block/codecrucible/internal/chunk"
	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/llm"
	"github.com/block/codecrucible/internal/sarif"
)

// AuditResult represents the structured output from the audit phase LLM call.
type AuditResult struct {
	AuditedFindings []AuditedFinding `json:"audited_findings"`
	NewFindings     []NewFinding     `json:"new_findings"`
	AuditSummary    string           `json:"audit_summary"`
}

// AuditedFinding is the audit verdict for a single initial finding.
type AuditedFinding struct {
	OriginalIssue           string  `json:"original_issue"`
	FilePath                string  `json:"file_path"`
	StartLine               int     `json:"start_line"`
	EndLine                 int     `json:"end_line"`
	Verdict                 string  `json:"verdict"`
	Confidence              float64 `json:"confidence"`
	RefinedSeverity         float64 `json:"refined_severity"`
	RefinedTechnicalDetails string  `json:"refined_technical_details"`
	RefinedCWEID            string  `json:"refined_cwe_id"`
	Justification           string  `json:"justification"`
}

// NewFinding is an additional finding discovered during the audit phase.
type NewFinding struct {
	Issue            string  `json:"issue"`
	FilePath         string  `json:"file_path"`
	StartLine        int     `json:"start_line"`
	EndLine          int     `json:"end_line"`
	TechnicalDetails string  `json:"technical_details"`
	Severity         float64 `json:"severity"`
	CWEID            string  `json:"cwe_id"`
	Confidence       float64 `json:"confidence"`
}

// runAuditPhase performs a CWE-specific scrutiny pass on the initial findings.
// It sends the findings + relevant code + CWE prompts to the LLM for validation.
// Returns the audited SARIF document, token usage, and cost.
// Returns nil doc (not error) if the audit fails, allowing fallback to unaudited results.
func runAuditPhase(
	ctx context.Context,
	doc sarif.SARIFDocument,
	repoName string,
	client llm.Client,
	endpoint string,
	modelCfg config.ModelConfig,
	promptLoader *llm.PromptLoader,
	outputMode llm.OutputMode,
	fileMap ingest.FileMap,
	confidenceThreshold float64,
	modelParams map[string]any,
	supContext string,
	batchSize int,
	productionOnly bool,
	counter *chunk.TokenCounter,
) (*sarif.SARIFDocument, llm.TokenUsage, float64) {
	slog.Info("starting audit phase",
		"findings_to_audit", len(doc.Runs[0].Results),
		"batch_size", batchSize,
	)

	// Extract initial findings as AnalysisResult for JSON serialization.
	run := doc.Runs[0]
	ruleByID := make(map[string]sarif.SARIFRule, len(run.Tool.Driver.Rules))
	for _, rule := range run.Tool.Driver.Rules {
		ruleByID[rule.ID] = rule
	}

	// claimToVerify wraps an analysis-phase finding as an unverified hypothesis
	// for the audit phase. The field names are deliberate: the audit prompt
	// must treat `unverified_exploit_sketch` as a claim to test against the
	// source code, not as a conclusion to accept. `issue` is kept to allow the
	// audit schema's `original_issue` output field to round-trip back into the
	// (file, line, issue) match key that applyAuditVerdicts uses.
	type claimToVerify struct {
		Issue                   string  `json:"issue"`
		FilePath                string  `json:"file_path"`
		StartLine               int     `json:"start_line"`
		EndLine                 int     `json:"end_line"`
		UnverifiedExploitSketch string  `json:"unverified_exploit_sketch"`
		Severity                float64 `json:"severity"`
		CWEID                   string  `json:"cwe_id"`
	}

	var findings []claimToVerify
	for _, result := range run.Results {
		rule := ruleByID[result.RuleID]
		var filePath string
		var startLine, endLine int
		if len(result.Locations) > 0 {
			filePath = result.Locations[0].PhysicalLocation.ArtifactLocation.URI
			if result.Locations[0].PhysicalLocation.Region != nil {
				startLine = result.Locations[0].PhysicalLocation.Region.StartLine
				endLine = result.Locations[0].PhysicalLocation.Region.EndLine
			}
		}

		var severity float64
		if sevStr, ok := rule.Properties["security-severity"].(string); ok {
			if _, err := fmt.Sscanf(sevStr, "%f", &severity); err != nil {
				slog.Debug("failed to parse security severity", "value", sevStr, "error", err)
			}
		}

		findings = append(findings, claimToVerify{
			Issue:                   rule.ShortDescription.Text,
			FilePath:                filePath,
			StartLine:               startLine,
			EndLine:                 endLine,
			UnverifiedExploitSketch: result.Message.Text,
			Severity:                severity,
			CWEID:                   sarif.CWEForRule(rule),
		})
	}

	// Batch boundaries. 0 (or oversized) = one call, same as before.
	if batchSize <= 0 || batchSize >= len(findings) {
		batchSize = len(findings)
	}
	numBatches := (len(findings) + batchSize - 1) / batchSize

	auditSchema := llm.AuditSchema()

	// auditBatch runs one self-contained audit call: just this batch's
	// findings, just their CWE IDs, just the files they reference. Each call
	// is independently valid so one batch failing doesn't poison the rest.
	// Files shared across batches get sent more than once — a deliberate
	// tradeoff: more tokens, but each call is stateless and can be retried
	// without coordination.
	auditBatch := func(batch []claimToVerify, label string) (AuditResult, llm.TokenUsage, float64, error) {
		var cweIDs []string
		filesNeeded := make(map[string]bool)
		for _, f := range batch {
			if f.CWEID != "" {
				cweIDs = append(cweIDs, f.CWEID)
			}
			if f.FilePath != "" {
				filesNeeded[f.FilePath] = true
			}
		}

		// Wrap the batch as { "claims_to_verify": [...] } so the prompt can
		// refer to the input as claims (unverified hypotheses) rather than
		// findings (settled facts). The wrapper framing is anti-anchoring:
		// it discourages the audit model from accepting conclusory phrases
		// in `unverified_exploit_sketch` without checking the source code.
		findingsJSON, err := json.Marshal(map[string]any{"claims_to_verify": batch})
		if err != nil {
			return AuditResult{}, llm.TokenUsage{}, 0, fmt.Errorf("marshal findings: %w", err)
		}

		var codeCtx strings.Builder
		for path := range filesNeeded {
			if content, ok := fileMap[path]; ok {
				fmt.Fprintf(&codeCtx, "<file path=\"%s\">\n%s\n</file>\n\n", path, content)
			}
		}

		messages, err := promptLoader.AssembleAuditMessages(llm.AuditParams{
			RepoName:             repoName,
			FindingsJSON:         string(findingsJSON),
			CodeContext:          codeCtx.String(),
			CWEIDs:               cweIDs,
			Schema:               string(*auditSchema),
			ProductionOnly:       productionOnly,
			SupplementaryContext: supContext,
		})
		if err != nil {
			return AuditResult{}, llm.TokenUsage{}, 0, fmt.Errorf("assemble audit prompt: %w", err)
		}

		var estTokens int
		for _, m := range messages {
			estTokens += counter.Count(m.Content)
		}
		slog.Info("running audit batch",
			"label", label,
			"findings", len(batch),
			"cwe_categories", len(cweIDs),
			"files_in_context", len(filesNeeded),
			"estimated_tokens", estTokens,
			"estimated_input_cost", fmt.Sprintf("$%.4f", float64(estTokens)*modelCfg.InputPricePerM/1_000_000),
		)

		resp, err := client.ChatCompletion(ctx, llm.ChatRequest{
			Label:          label,
			Endpoint:       endpoint,
			Model:          modelCfg.Name,
			Messages:       messages,
			Temperature:    modelCfg.Temperature,
			MaxTokens:      modelCfg.MaxOutputTokens,
			ResponseSchema: auditSchema,
			OutputMode:     outputMode,
			ModelParams:    modelParams,
		})
		if err != nil {
			return AuditResult{}, llm.TokenUsage{}, 0, fmt.Errorf("LLM call: %w", err)
		}

		u := resp.Usage
		c := float64(u.PromptTokens)*modelCfg.InputPricePerM/1_000_000 +
			float64(u.CompletionTokens)*modelCfg.OutputPricePerM/1_000_000
		slog.Info("audit batch complete",
			"label", label,
			"prompt_tokens", u.PromptTokens,
			"completion_tokens", u.CompletionTokens,
			"cost", fmt.Sprintf("$%.4f", c),
		)

		var r AuditResult
		if err := json.Unmarshal([]byte(resp.Content), &r); err != nil {
			// Try local repair (strip markdown fences, extract JSON object)
			// before giving up — same pattern as the analysis phase.
			if repaired, changed := llm.RepairJSON(resp.Content); changed {
				if err2 := json.Unmarshal([]byte(repaired), &r); err2 == nil {
					slog.Info("recovered malformed audit response via local repair", "label", label)
					return r, u, c, nil
				}
			}
			return AuditResult{}, u, c, fmt.Errorf("parse audit response: %w", err)
		}
		return r, u, c, nil
	}

	// Sequential — the point is to keep each request under the server's
	// connection-age limit, not to go faster.
	var auditResult AuditResult
	var usage llm.TokenUsage
	var cost float64
	for i := 0; i < len(findings); i += batchSize {
		end := i + batchSize
		if end > len(findings) {
			end = len(findings)
		}
		label := "audit"
		if numBatches > 1 {
			label = fmt.Sprintf("audit %d/%d", i/batchSize+1, numBatches)
		}
		r, u, c, err := auditBatch(findings[i:end], label)
		usage.PromptTokens += u.PromptTokens
		usage.CompletionTokens += u.CompletionTokens
		cost += c
		if err != nil {
			slog.Error("audit batch failed; findings in this batch will not be audited",
				"label", label, "error", err, "findings", end-i)
			continue
		}
		auditResult.AuditedFindings = append(auditResult.AuditedFindings, r.AuditedFindings...)
		auditResult.NewFindings = append(auditResult.NewFindings, r.NewFindings...)
		if r.AuditSummary != "" {
			if auditResult.AuditSummary != "" {
				auditResult.AuditSummary += "\n\n"
			}
			auditResult.AuditSummary += r.AuditSummary
		}
	}

	if len(auditResult.AuditedFindings) == 0 && len(auditResult.NewFindings) == 0 {
		slog.Error("all audit batches failed")
		return nil, usage, cost
	}

	// Apply audit verdicts to produce the final SARIF document.
	auditedDoc := applyAuditVerdicts(doc, auditResult, fileMap, confidenceThreshold)

	slog.Info("audit phase complete",
		"audited", len(auditResult.AuditedFindings),
		"new_findings", len(auditResult.NewFindings),
		"summary", auditResult.AuditSummary,
	)

	return &auditedDoc, usage, cost
}

// applyAuditVerdicts takes the original SARIF document and the audit results,
// and produces a new SARIF document with findings filtered, refined, and enriched.
func applyAuditVerdicts(
	doc sarif.SARIFDocument,
	audit AuditResult,
	fileMap ingest.FileMap,
	confidenceThreshold float64,
) sarif.SARIFDocument {
	run := doc.Runs[0]

	// Build audit lookup by (file_path, start_line, original_issue).
	// Using original_issue prevents collisions when multiple findings
	// share the same location (e.g. SQL injection + log forging on one line).
	type auditKey struct {
		filePath      string
		startLine     int
		originalIssue string
	}
	auditByKey := make(map[auditKey]AuditedFinding)
	for _, af := range audit.AuditedFindings {
		key := auditKey{filePath: af.FilePath, startLine: af.StartLine, originalIssue: af.OriginalIssue}
		auditByKey[key] = af
	}

	// Process existing results: apply verdicts.
	var keptResults []sarif.SARIFResult
	ruleByID := make(map[string]sarif.SARIFRule, len(run.Tool.Driver.Rules))
	for _, rule := range run.Tool.Driver.Rules {
		ruleByID[rule.ID] = rule
	}

	rejected := 0
	refined := 0
	escalated := 0
	confirmed := 0

	for _, result := range run.Results {
		var filePath string
		var startLine int
		if len(result.Locations) > 0 {
			filePath = result.Locations[0].PhysicalLocation.ArtifactLocation.URI
			if result.Locations[0].PhysicalLocation.Region != nil {
				startLine = result.Locations[0].PhysicalLocation.Region.StartLine
			}
		}

		rule := ruleByID[result.RuleID]
		key := auditKey{filePath: filePath, startLine: startLine, originalIssue: rule.ShortDescription.Text}
		af, found := auditByKey[key]

		if !found {
			// No audit verdict for this finding — keep as-is.
			keptResults = append(keptResults, result)
			continue
		}

		// Reject findings below confidence threshold.
		if af.Verdict == "rejected" || af.Confidence < confidenceThreshold {
			rejected++
			slog.Debug("audit: rejected finding",
				"issue", af.OriginalIssue,
				"file", af.FilePath,
				"confidence", af.Confidence,
				"reason", af.Justification,
			)
			continue
		}

		// Apply refinements.
		switch af.Verdict {
		case "refined":
			refined++
		case "escalated":
			escalated++
		default:
			confirmed++
		}

		// Update the result with refined details.
		if af.RefinedTechnicalDetails != "" {
			result.Message = sarif.SARIFMessage{
				Text: fmt.Sprintf("%s\n\n[Audit confidence: %.0f%%] %s",
					af.RefinedTechnicalDetails, af.Confidence*100, af.Justification),
			}
		}

		// Update rule severity if refined.
		if rule, ok := ruleByID[result.RuleID]; ok && af.RefinedSeverity > 0 {
			rule.Properties["security-severity"] = fmt.Sprintf("%.1f", af.RefinedSeverity)
			result.Level = severityLevelScan(af.RefinedSeverity)
			ruleByID[result.RuleID] = rule
		}

		keptResults = append(keptResults, result)
	}

	// Add new findings from the audit phase.
	newCount := 0
	for _, nf := range audit.NewFindings {
		if nf.Confidence < confidenceThreshold {
			continue
		}

		issue := sarif.SecurityIssue{
			Issue:            nf.Issue,
			FilePath:         nf.FilePath,
			StartLine:        nf.StartLine,
			EndLine:          nf.EndLine,
			TechnicalDetails: fmt.Sprintf("%s\n\n[Audit confidence: %.0f%%]", nf.TechnicalDetails, nf.Confidence*100),
			Severity:         nf.Severity,
			CWEID:            nf.CWEID,
		}

		newDoc := sarif.Build(sarif.AnalysisResult{
			SecurityIssues: []sarif.SecurityIssue{issue},
		}, sarif.FileMap(fileMap), sarif.BuilderConfig{ToolVersion: version})

		if len(newDoc.Runs) > 0 && len(newDoc.Runs[0].Results) > 0 {
			keptResults = append(keptResults, newDoc.Runs[0].Results...)
			for _, rule := range newDoc.Runs[0].Tool.Driver.Rules {
				ruleByID[rule.ID] = rule
			}
			newCount++
		}
	}

	slog.Info("audit verdicts applied",
		"confirmed", confirmed,
		"refined", refined,
		"escalated", escalated,
		"rejected", rejected,
		"new", newCount,
	)

	// Rebuild rules slice from the map.
	var rules []sarif.SARIFRule
	usedRuleIDs := make(map[string]bool)
	for _, r := range keptResults {
		usedRuleIDs[r.RuleID] = true
	}
	for id, rule := range ruleByID {
		if usedRuleIDs[id] {
			rules = append(rules, rule)
		}
	}
	if rules == nil {
		rules = []sarif.SARIFRule{}
	}
	if keptResults == nil {
		keptResults = []sarif.SARIFResult{}
	}

	run.Results = keptResults
	run.Tool.Driver.Rules = rules
	doc.Runs[0] = run

	return doc
}

// severityLevelScan maps a numeric severity to a SARIF level (scan package version).
func severityLevelScan(sev float64) string {
	switch {
	case sev <= 0:
		return "none"
	case sev < 4.0:
		return "note"
	case sev < 7.0:
		return "warning"
	default:
		return "error"
	}
}
