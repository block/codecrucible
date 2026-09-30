package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"sort"
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
//
// BlockingCode is the audit phase's quoted source-line citation that
// justifies a "rejected" verdict. applyAuditVerdicts coerces any
// "rejected" verdict with an empty BlockingCode to "unverified" — this
// prevents the audit phase from silently dropping multi-file invariant
// findings it couldn't fully re-prove in one pass. See the audit prompt's
// "AUDIT REJECTION DISCIPLINE" section.
type AuditedFinding struct {
	OriginalIssue           string               `json:"original_issue"`
	FilePath                string               `json:"file_path"`
	StartLine               int                  `json:"start_line"`
	EndLine                 int                  `json:"end_line"`
	Verdict                 string               `json:"verdict"`
	Confidence              float64              `json:"confidence"`
	RefinedSeverity         float64              `json:"refined_severity"`
	RefinedTechnicalDetails string               `json:"refined_technical_details"`
	RefinedCWEID            string               `json:"refined_cwe_id"`
	Justification           string               `json:"justification"`
	BlockingCode            string               `json:"blocking_code"`
	Summary                 string               `json:"summary"`
	Remediation             string               `json:"remediation"`
	CodePath                []sarif.CodePathStep `json:"code_path"`
}

// NewFinding is an additional finding discovered during the audit phase.
type NewFinding struct {
	Issue            string               `json:"issue"`
	FilePath         string               `json:"file_path"`
	StartLine        int                  `json:"start_line"`
	EndLine          int                  `json:"end_line"`
	TechnicalDetails string               `json:"technical_details"`
	Severity         float64              `json:"severity"`
	CWEID            string               `json:"cwe_id"`
	Confidence       float64              `json:"confidence"`
	Summary          string               `json:"summary"`
	Remediation      string               `json:"remediation"`
	CodePath         []sarif.CodePathStep `json:"code_path"`
}

// runAuditPhase performs a CWE-specific scrutiny pass on the initial findings.
// It sends the findings + relevant code + CWE prompts to the LLM for validation.
// Returns the audited SARIF document, token usage, and cost.
// Returns partial results AND an error if any finding could not be audited.
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
	metadata *sarif.ScanMetadata,
) (*sarif.SARIFDocument, llm.TokenUsage, float64, error) {
	if len(doc.Runs) == 0 || len(doc.Runs[0].Results) == 0 {
		return &doc, llm.TokenUsage{}, 0, nil
	}
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
		Issue                   string                `json:"issue"`
		FilePath                string                `json:"file_path"`
		StartLine               int                   `json:"start_line"`
		EndLine                 int                   `json:"end_line"`
		UnverifiedExploitSketch string                `json:"unverified_exploit_sketch"`
		Severity                float64               `json:"severity"`
		CWEID                   string                `json:"cwe_id"`
		CodeFlows               []sarif.SARIFCodeFlow `json:"code_flows,omitempty"`
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
			CodeFlows:               result.CodeFlows,
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
			for _, flow := range f.CodeFlows {
				for _, thread := range flow.ThreadFlows {
					for _, step := range thread.Locations {
						filesNeeded[step.Location.PhysicalLocation.ArtifactLocation.URI] = true
					}
				}
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
		paths := make([]string, 0, len(filesNeeded))
		for path := range filesNeeded {
			paths = append(paths, path)
		}
		sort.Strings(paths)
		for _, path := range paths {
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
			"estimated_input_cost", fmt.Sprintf("$%.4f", modelCfg.EstimateInputCost(estTokens)),
		)

		request := llm.ChatRequest{
			Label:                  label,
			Endpoint:               endpoint,
			Model:                  modelCfg.Name,
			Messages:               messages,
			Temperature:            modelCfg.Temperature,
			OmitTemperature:        modelCfg.OmitTemperature,
			MaxTokens:              modelCfg.MaxOutputTokens,
			UseMaxCompletionTokens: modelCfg.UseMaxCompletionTokens,
			ResponseSchema:         auditSchema,
			OutputMode:             outputMode,
			NativeStructuredOutput: modelCfg.NativeStructuredOutput,
			ModelParams:            modelParams,
		}
		var usage llm.TokenUsage
		var cost float64
		var lastErr error
		// Transport retries belong to the client. One additional generation
		// recovers malformed, truncated, or incomplete verdicts without
		// multiplying the HTTP retry budget for permission failures.
		for attempt := 0; attempt < 2; attempt++ {
			if err := ctx.Err(); err != nil {
				return AuditResult{}, usage, cost, err
			}
			resp, err := client.ChatCompletion(ctx, request)
			if err != nil {
				return AuditResult{}, usage, cost, fmt.Errorf("LLM call: %w", err)
			}
			usage.PromptTokens += resp.Usage.PromptTokens
			usage.CompletionTokens += resp.Usage.CompletionTokens
			cost += modelCfg.EstimateCost(resp.Usage.PromptTokens, resp.Usage.CompletionTokens)
			var r AuditResult
			lastErr = json.Unmarshal([]byte(resp.Content), &r)
			if lastErr != nil {
				if content, changed := llm.RepairJSON(resp.Content); changed {
					r = AuditResult{}
					lastErr = json.Unmarshal([]byte(content), &r)
				}
			}
			if lastErr == nil && (resp.FinishReason == "length" || resp.FinishReason == "max_tokens") {
				lastErr = fmt.Errorf("audit response exceeded output token limit")
			}
			if lastErr == nil {
				expected := make(map[auditFindingKey]bool, len(batch))
				for _, f := range batch {
					expected[auditFindingKey{f.FilePath, f.StartLine, f.Issue}] = true
				}
				lastErr = validateAuditCoverage(r, expected)
			}
			if lastErr == nil {
				slog.Info("audit batch complete",
					"label", label,
					"prompt_tokens", usage.PromptTokens,
					"completion_tokens", usage.CompletionTokens,
					"cost", fmt.Sprintf("$%.4f", cost),
				)
				return r, usage, cost, nil
			}
			if attempt == 0 {
				slog.Warn("invalid audit response; retrying batch", "label", label, "error", lastErr)
			}
		}
		return AuditResult{}, usage, cost, fmt.Errorf("invalid audit response after 2 attempts: %w", lastErr)
	}

	// Sequential — the point is to keep each request under the server's
	// connection-age limit, not to go faster.
	var auditResult AuditResult
	var usage llm.TokenUsage
	var cost float64
	var firstBatchErr error
	failedBatches := 0
	for i := 0; i < len(findings); i += batchSize {
		if err := ctx.Err(); err != nil {
			firstBatchErr = err
			failedBatches += (len(findings) - i + batchSize - 1) / batchSize
			break
		}
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
			failedBatches++
			if firstBatchErr == nil {
				firstBatchErr = err
			}
			slog.Warn("audit batch unavailable; retaining findings without audit",
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

	if failedBatches > 0 {
		if metadata != nil {
			setPhaseStatus(metadata, "audit", "incomplete", "unaudited findings retained")
		}
		slog.Warn("audit coverage incomplete; affected findings require manual review",
			"failed_batches", failedBatches,
			"total_batches", numBatches,
		)
	}

	// Apply audit verdicts to produce the final SARIF document.
	auditedDoc := applyAuditVerdicts(doc, auditResult, fileMap, confidenceThreshold)
	if err := ctx.Err(); err != nil {
		return &auditedDoc, usage, cost, fmt.Errorf("audit cancelled: %w", err)
	}
	if failedBatches > 0 {
		return &auditedDoc, usage, cost, fmt.Errorf("audit incomplete: %d of %d batches failed; unaudited findings retained: %w", failedBatches, numBatches, firstBatchErr)
	}

	slog.Info("audit phase complete",
		"audited", len(auditResult.AuditedFindings),
		"new_findings", len(auditResult.NewFindings),
		"summary", auditResult.AuditSummary,
	)

	return &auditedDoc, usage, cost, nil
}

type auditFindingKey struct {
	filePath  string
	startLine int
	issue     string
}

func validateAuditCoverage(result AuditResult, expected map[auditFindingKey]bool) error {
	seen := make(map[auditFindingKey]bool, len(expected))
	for _, finding := range result.AuditedFindings {
		key := auditFindingKey{finding.FilePath, finding.StartLine, finding.OriginalIssue}
		if !expected[key] || seen[key] {
			return fmt.Errorf("audit returned an unknown or duplicate finding")
		}
		switch finding.Verdict {
		case "confirmed", "refined", "rejected", "escalated", "unverified":
		default:
			return fmt.Errorf("audit returned invalid verdict %q", finding.Verdict)
		}
		if math.IsNaN(finding.Confidence) || finding.Confidence < 0 || finding.Confidence > 1 {
			return fmt.Errorf("audit returned invalid confidence")
		}
		seen[key] = true
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("audit omitted verdicts for %d findings", len(expected)-len(seen))
	}
	return nil
}

// applyAuditVerdicts takes the original SARIF document and the audit results,
// and produces a new SARIF document with findings filtered, refined, and enriched.
func applyAuditVerdicts(
	doc sarif.SARIFDocument,
	audit AuditResult,
	fileMap ingest.FileMap,
	confidenceThreshold float64,
) sarif.SARIFDocument {
	doc.Runs = append([]sarif.SARIFRun(nil), doc.Runs...)
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
		properties := make(map[string]any, len(rule.Properties))
		for k, v := range rule.Properties {
			properties[k] = v
		}
		rule.Properties = properties
		ruleByID[rule.ID] = rule
	}

	rejected := 0
	refined := 0
	escalated := 0
	confirmed := 0
	unverified := 0
	coerced := 0

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

		props := sarif.FindingProperties{}
		if result.Properties != nil {
			props = *result.Properties
		}
		result.Properties = &props
		if !found {
			props.AuditStatus = "not_audited"
			keptResults = append(keptResults, result)
			continue
		}

		// Symmetric-skepticism gate: a "rejected" verdict without a
		// quoted blocking source line is an unsubstantiated rejection.
		// Coerce to "unverified" so the finding survives instead of
		// silently disappearing — multi-file invariants (e.g. Copy
		// Fail-style splice→sink chains) routinely get rejected here
		// just because the auditor couldn't re-prove the whole chain
		// in one pass.
		if af.Verdict == "rejected" && strings.TrimSpace(af.BlockingCode) == "" {
			slog.Warn("audit: rejection without blocking_code — coerced to unverified",
				"issue", af.OriginalIssue,
				"file", af.FilePath,
				"justification", af.Justification,
			)
			af.Verdict = "unverified"
			coerced++
		}

		// "unverified" findings are retained. Floor confidence at the
		// threshold so a low score doesn't immediately re-drop them.
		// They are clearly marked as unverified in the SARIF message.
		if af.Verdict == "unverified" {
			unverified++
			if af.Confidence < confidenceThreshold {
				af.Confidence = confidenceThreshold
			}
			if af.RefinedTechnicalDetails == "" {
				af.RefinedTechnicalDetails = result.Message.Text
			}
			af.RefinedTechnicalDetails = "[UNVERIFIED — audit could not re-prove the full chain; treat as a lead]\n\n" + af.RefinedTechnicalDetails
		}

		// Reject explicit rejections (now guaranteed to have blocking_code)
		// and findings below confidence threshold.
		if af.Verdict == "rejected" || af.Confidence < confidenceThreshold {
			rejected++
			slog.Debug("audit: rejected finding",
				"issue", af.OriginalIssue,
				"file", af.FilePath,
				"confidence", af.Confidence,
				"blocking_code", af.BlockingCode,
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
		case "unverified":
			// counted above
		default:
			confirmed++
		}

		// Update the result with refined details.
		props.AuditStatus = af.Verdict
		props.AuditConfidence = &af.Confidence
		props.Summary = af.Summary // Empty means derive from the final evidence.
		props.Remediation = af.Remediation
		props.TechnicalDetails = ""
		// Audit paths replace analysis paths; an unavailable/unverified path
		// must not leave an obsolete analysis walkthrough in the final report.
		result.CodeFlows = sarif.BuildCodeFlows(af.CodePath, sarif.FileMap(fileMap))
		if af.Verdict == "unverified" {
			result.CodeFlows = nil
		}
		if af.RefinedTechnicalDetails == "" {
			af.RefinedTechnicalDetails = result.Message.Text
		}
		result.Message = sarif.SARIFMessage{
			Text: fmt.Sprintf("%s\n\n[Audit confidence: %.0f%%] %s",
				af.RefinedTechnicalDetails, af.Confidence*100, af.Justification),
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
			Summary:          nf.Summary,
			Remediation:      nf.Remediation,
			CodePath:         nf.CodePath,
		}

		newDoc := sarif.Build(sarif.AnalysisResult{
			SecurityIssues: []sarif.SecurityIssue{issue},
		}, sarif.FileMap(fileMap), sarif.BuilderConfig{ToolVersion: version})

		if len(newDoc.Runs) > 0 && len(newDoc.Runs[0].Results) > 0 {
			newDoc.Runs[0].Results[0].Properties.AuditStatus = "new"
			newDoc.Runs[0].Results[0].Properties.AuditConfidence = &nf.Confidence
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
		"unverified", unverified,
		"rejected", rejected,
		"coerced_rejected_to_unverified", coerced,
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
