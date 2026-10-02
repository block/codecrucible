package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"strings"
	"sync"

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
	FindingID               string               `json:"finding_id"`
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
	batchSize, auditConcurrency int,
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
		"concurrency", max(1, auditConcurrency),
	)

	doc = sarif.WithFindingIDs(doc)
	// Extract initial findings as AnalysisResult for JSON serialization.
	run := doc.Runs[0]
	ruleByID := make(map[string]sarif.SARIFRule, len(run.Tool.Driver.Rules))
	for _, rule := range run.Tool.Driver.Rules {
		ruleByID[rule.ID] = rule
	}

	// Findings are unverified hypotheses. Only finding_id identifies a verdict;
	// titles and locations may be refined without changing that identity.
	type claimToVerify struct {
		FindingID               string                `json:"finding_id"`
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
			FindingID:               result.Properties.FindingID,
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

	// Rebuild each retry from unresolved claims, including only their source.
	buildRequest := func(batch []claimToVerify, label string) (llm.ChatRequest, error) {
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
			return llm.ChatRequest{}, fmt.Errorf("marshal findings: %w", err)
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
			return llm.ChatRequest{}, fmt.Errorf("assemble audit prompt: %w", err)
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
		return request, nil
	}

	auditBatch := func(batch []claimToVerify, label string) (AuditResult, llm.TokenUsage, float64, error) {
		var accepted AuditResult
		var usage llm.TokenUsage
		var cost float64
		var lastErr error
		pending := batch
		newSeen := map[string]bool{}
		// Transport retries belong to the client. Retry invalid generations
		// once, preserving valid verdicts and requesting only unresolved IDs.
		for attempt := 0; attempt < 2; attempt++ {
			if err := ctx.Err(); err != nil {
				return accepted, usage, cost, err
			}
			request, err := buildRequest(pending, label)
			if err != nil {
				return accepted, usage, cost, err
			}
			resp, err := client.ChatCompletion(ctx, request)
			if err != nil {
				return accepted, usage, cost, fmt.Errorf("LLM call: %w", err)
			}
			usage.PromptTokens += resp.Usage.PromptTokens
			usage.CompletionTokens += resp.Usage.CompletionTokens
			cost += modelCfg.EstimateCost(resp.Usage.PromptTokens, resp.Usage.CompletionTokens)
			var r AuditResult
			r, lastErr = decodeAuditResult(resp.Content)
			if lastErr != nil {
				if content, changed := llm.RepairJSON(resp.Content); changed {
					r, lastErr = decodeAuditResult(content)
				}
			}
			if lastErr == nil && (resp.FinishReason == "length" || resp.FinishReason == "max_tokens") {
				lastErr = fmt.Errorf("audit response exceeded output token limit")
			}
			if lastErr == nil {
				expected := make(map[string]bool, len(pending))
				for _, f := range pending {
					expected[f.FindingID] = true
				}
				var valid []AuditedFinding
				valid, lastErr = partitionAuditVerdicts(r, expected)
				for _, f := range valid {
					delete(expected, f.FindingID)
				}
				accepted.AuditedFindings = append(accepted.AuditedFindings, valid...)
				remaining := make([]claimToVerify, 0, len(expected))
				for _, f := range pending {
					if expected[f.FindingID] {
						remaining = append(remaining, f)
					}
				}
				pending = remaining
				for _, f := range r.NewFindings {
					key, _ := json.Marshal([]any{f.Issue, f.FilePath, f.StartLine})
					if !newSeen[string(key)] {
						accepted.NewFindings = append(accepted.NewFindings, f)
						newSeen[string(key)] = true
					}
				}
				if r.AuditSummary != "" {
					accepted.AuditSummary = r.AuditSummary
				}
				if len(pending) == 0 {
					if lastErr != nil {
						slog.Warn("ignored invalid extra audit verdicts", "label", label, "error", lastErr)
					}
					slog.Info("audit batch complete", "label", label, "findings", len(accepted.AuditedFindings), "prompt_tokens", usage.PromptTokens, "completion_tokens", usage.CompletionTokens, "cost", fmt.Sprintf("$%.4f", cost))
					return accepted, usage, cost, nil
				}
			}
			if attempt == 0 {
				slog.Warn("invalid audit response; retrying unresolved findings", "label", label, "unresolved_findings", len(pending), "error", lastErr)
			}
		}
		return accepted, usage, cost, fmt.Errorf("%d findings unresolved after 2 attempts: %w", len(pending), lastErr)
	}

	// Workers write disjoint slots. Aggregate in batch order after joining so
	// output, warnings and cost accumulation do not depend on completion order.
	type batchOutcome struct {
		result AuditResult
		usage  llm.TokenUsage
		cost   float64
		err    error
	}
	outcomes := make([]batchOutcome, numBatches)
	jobs := make(chan int, numBatches)
	for i := 0; i < numBatches; i++ {
		jobs <- i
	}
	close(jobs)
	var workers sync.WaitGroup
	for worker := 0; worker < min(max(1, auditConcurrency), numBatches); worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for batch := range jobs {
				if err := ctx.Err(); err != nil {
					outcomes[batch].err = err
					continue
				}
				start := batch * batchSize
				label := "audit"
				if numBatches > 1 {
					label = fmt.Sprintf("audit %d/%d", batch+1, numBatches)
				}
				r, u, c, err := auditBatch(findings[start:min(start+batchSize, len(findings))], label)
				outcomes[batch] = batchOutcome{r, u, c, err}
			}
		}()
	}
	workers.Wait()
	var auditResult AuditResult
	var usage llm.TokenUsage
	var cost float64
	var firstBatchErr error
	failedBatches := 0
	for batch, outcome := range outcomes {
		r := outcome.result
		usage.PromptTokens += outcome.usage.PromptTokens
		usage.CompletionTokens += outcome.usage.CompletionTokens
		cost += outcome.cost
		if outcome.err != nil {
			failedBatches++
			if firstBatchErr == nil {
				firstBatchErr = outcome.err
			}
			unresolved := min(batchSize, len(findings)-batch*batchSize) - len(r.AuditedFindings)
			slog.Warn("audit batch unavailable; retaining unresolved findings", "batch", batch+1, "error", outcome.err, "findings", unresolved)
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

// partitionAuditVerdicts admits only unique, known IDs with valid verdicts.
// A duplicate makes that ID ambiguous, even if one copy otherwise looks valid.
func partitionAuditVerdicts(result AuditResult, expected map[string]bool) ([]AuditedFinding, error) {
	counts := map[string]int{}
	for _, f := range result.AuditedFindings {
		counts[f.FindingID]++
	}
	var valid []AuditedFinding
	invalid := 0
	for _, f := range result.AuditedFindings {
		if f.FindingID == "" || !expected[f.FindingID] || counts[f.FindingID] != 1 {
			invalid++
			continue
		}
		switch f.Verdict {
		case "confirmed", "refined", "rejected", "escalated", "unverified":
		default:
			invalid++
			continue
		}
		if math.IsNaN(f.Confidence) || f.Confidence < 0 || f.Confidence > 1 {
			invalid++
			continue
		}
		valid = append(valid, f)
	}
	if invalid > 0 || len(valid) != len(expected) {
		return valid, fmt.Errorf("audit has %d invalid verdicts and %d unresolved findings", invalid, len(expected)-len(valid))
	}
	return valid, nil
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

	auditByID := make(map[string]AuditedFinding)
	counts := map[string]int{}
	for _, af := range audit.AuditedFindings {
		counts[af.FindingID]++
	}
	for _, af := range audit.AuditedFindings {
		if af.FindingID != "" && counts[af.FindingID] == 1 {
			auditByID[af.FindingID] = af
		}
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
	cweAssignments := map[string]sarif.CWEAssignment{}

	for _, result := range run.Results {

		props := sarif.FindingProperties{}
		if result.Properties != nil {
			props = *result.Properties
		}
		result.Properties = &props
		af, found := auditByID[props.FindingID]
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

		// Apply location refinements only when grounded in admitted source.
		// An invalid suggestion leaves the original location intact.
		if source, ok := fileMap[af.FilePath]; ok {
			lines := strings.Split(strings.TrimSuffix(source, "\n"), "\n")
			end := af.EndLine
			if end == 0 {
				end = af.StartLine
			}
			if af.StartLine >= 1 && end >= af.StartLine && end <= len(lines) {
				result.Locations = []sarif.SARIFLocation{{PhysicalLocation: sarif.SARIFPhysicalLocation{
					ArtifactLocation: sarif.SARIFArtifactLocation{URI: af.FilePath},
					Region:           &sarif.SARIFRegion{StartLine: af.StartLine, EndLine: end, Snippet: &sarif.SARIFSnippet{Text: strings.Join(lines[af.StartLine-1:end], "\n")}},
				}}}
			}
		}

		// Apply refinements.
		if af.RefinedCWEID != "" {
			cweAssignments[props.FindingID] = sarif.CWEAssignment{ID: af.RefinedCWEID, Source: "generative_audit"}
		}
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
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	run.Tool.Driver.Rules = rules
	doc.Runs[0] = run

	if len(cweAssignments) > 0 {
		return sarif.ApplyCWEAssignments(doc, cweAssignments)
	}
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
