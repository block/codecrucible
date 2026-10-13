package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/block/codecrucible/internal/auditctx"
	"github.com/block/codecrucible/internal/chunk"
	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/llm"
	"github.com/block/codecrucible/internal/sarif"
)

// The v2 audit asks the model evidentiary questions about each claim and
// computes the verdict in code (auditVerdictV2). Claims are matched by
// finding_id, quotes are checked against the scanned source, and a batch that
// covers only some claims keeps those assessments.

// auditClaimV2 is an analysis finding presented to the v2 audit as a claim.
type auditClaimV2 struct {
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

// auditResponseV2 is the structured output of one v2 audit call.
type auditResponseV2 struct {
	Assessments []auditAssessmentV2 `json:"assessments"`
	Leads       []string            `json:"leads"`
}

type auditAssessmentV2 struct {
	FindingID          string                   `json:"finding_id"`
	AttackerControl    sarif.AuditAnswer        `json:"attacker_control"`
	PrivilegeBoundary  sarif.AuditAnswer        `json:"privilege_boundary"`
	Unmitigated        sarif.AuditAnswer        `json:"unmitigated"`
	DeploymentExposure sarif.DeploymentExposure `json:"deployment_exposure"`
	DuplicateOf        string                   `json:"duplicate_of"`
	RefinedSeverity    float64                  `json:"refined_severity"`
	RefinedCWEID       string                   `json:"refined_cwe_id"`
	Crux               string                   `json:"crux"`
	Summary            string                   `json:"summary"`
	Remediation        string                   `json:"remediation"`
}

func (a auditAssessmentV2) answer(question string) sarif.AuditAnswer {
	switch question {
	case "attacker_control":
		return a.AttackerControl
	case "privilege_boundary":
		return a.PrivilegeBoundary
	case "unmitigated":
		return a.Unmitigated
	}
	return sarif.AuditAnswer{}
}

// valid reports whether every answer carries a known status.
func (a auditAssessmentV2) valid() bool {
	for _, q := range llm.AuditQuestions {
		switch answerStatus(a.answer(q).Status) {
		case "established", "refuted", "unknown":
		default:
			return false
		}
	}
	return true
}

func answerStatus(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// auditV2Run holds what every v2 audit call shares.
type auditV2Run struct {
	repoName       string
	client         llm.Client
	endpoint       string
	modelCfg       config.ModelConfig
	promptLoader   *llm.PromptLoader
	outputMode     llm.OutputMode
	fileMap        ingest.FileMap
	modelParams    map[string]any
	supContext     string
	productionOnly bool
	counter        *chunk.TokenCounter
	metadata       *sarif.ScanMetadata
	// claims are all of the scan's claims, so each batch can list the rest.
	claims []auditClaimV2
	index  *auditctx.Index
}

// auditRetrievalBudget caps the tokens of retrieved context per batch, on
// top of the files the claims cite.
const auditRetrievalBudget = 24000

func (r *auditV2Run) run(ctx context.Context, doc sarif.SARIFDocument, batchSize int) (*sarif.SARIFDocument, llm.TokenUsage, float64, error) {
	claims := auditClaimsV2(doc)
	r.claims = claims
	r.index = auditctx.NewIndex(r.fileMap)
	if batchSize <= 0 || batchSize >= len(claims) {
		batchSize = len(claims)
	}
	numBatches := (len(claims) + batchSize - 1) / batchSize
	slog.Info("starting audit phase", "contract", "v2", "findings_to_audit", len(claims), "batch_size", batchSize)

	assessments := make(map[string]auditAssessmentV2, len(claims))
	batchOf := make(map[string]int, len(claims))
	var leads []string
	var usage llm.TokenUsage
	var cost float64
	var firstBatchErr error
	failedBatches := 0
	for i := 0; i < len(claims); i += batchSize {
		if err := ctx.Err(); err != nil {
			firstBatchErr = err
			failedBatches += (len(claims) - i + batchSize - 1) / batchSize
			break
		}
		end := min(i+batchSize, len(claims))
		label := "audit"
		if numBatches > 1 {
			label = fmt.Sprintf("audit %d/%d", i/batchSize+1, numBatches)
		}
		got, batchLeads, u, c, err := r.batch(ctx, claims[i:end], label)
		usage.PromptTokens += u.PromptTokens
		usage.CompletionTokens += u.CompletionTokens
		cost += c
		for id, a := range got {
			assessments[id] = a
			batchOf[id] = i / batchSize
		}
		leads = append(leads, batchLeads...)
		if err != nil {
			failedBatches++
			if firstBatchErr == nil {
				firstBatchErr = err
			}
			slog.Warn("audit batch unavailable; retaining findings without audit", "label", label, "error", err, "findings", end-i)
		}
	}

	auditedDoc := applyAuditAssessments(doc, assessments, batchOf, r.fileMap)
	missing := len(claims) - len(assessments)
	if r.metadata != nil {
		r.metadata.Execution.AuditLeads = auditLeads(leads)
		if missing > 0 {
			setPhaseStatus(r.metadata, "audit", "incomplete", "unaudited findings retained")
		}
	}
	if err := ctx.Err(); err != nil {
		return &auditedDoc, usage, cost, fmt.Errorf("audit cancelled: %w", err)
	}
	if failedBatches > 0 {
		return &auditedDoc, usage, cost, fmt.Errorf("audit incomplete: %d of %d batches failed; unaudited findings retained: %w", failedBatches, numBatches, firstBatchErr)
	}
	if missing > 0 {
		return &auditedDoc, usage, cost, fmt.Errorf("audit incomplete: %d of %d findings have no assessment; unaudited findings retained", missing, len(claims))
	}
	slog.Info("audit phase complete", "contract", "v2", "audited", len(assessments), "leads", len(leads))
	return &auditedDoc, usage, cost, nil
}

// batch audits one batch. Claims the response omits or answers invalidly are
// re-sent once on their own; assessments already received are kept, so one
// bad entry no longer costs the whole batch. The error is set only when no
// claim could be assessed.
func (r *auditV2Run) batch(ctx context.Context, claims []auditClaimV2, label string) (map[string]auditAssessmentV2, []string, llm.TokenUsage, float64, error) {
	got := make(map[string]auditAssessmentV2, len(claims))
	var leads []string
	var usage llm.TokenUsage
	var cost float64
	var lastErr error
	pending := claims
	for attempt := 0; attempt < 2 && len(pending) > 0; attempt++ {
		if err := ctx.Err(); err != nil {
			return got, leads, usage, cost, err
		}
		if attempt > 0 {
			slog.Warn("audit response incomplete; retrying unassessed claims", "label", label, "claims", len(pending), "error", lastErr)
		}
		resp, err := r.call(ctx, pending, label)
		if err != nil {
			return got, leads, usage, cost, err
		}
		usage.PromptTokens += resp.Usage.PromptTokens
		usage.CompletionTokens += resp.Usage.CompletionTokens
		cost += r.modelCfg.EstimateCost(resp.Usage.PromptTokens, resp.Usage.CompletionTokens)

		parsed, err := parseAuditResponseV2(resp.Content, resp.FinishReason)
		if err != nil {
			lastErr = err
			continue
		}
		leads = append(leads, parsed.Leads...)
		lastErr = acceptAssessments(got, pending, parsed.Assessments, label)
		var rest []auditClaimV2
		for _, c := range pending {
			if _, ok := got[c.FindingID]; !ok {
				rest = append(rest, c)
			}
		}
		pending = rest
	}
	if len(got) == 0 && lastErr != nil {
		return got, leads, usage, cost, fmt.Errorf("invalid audit response after 2 attempts: %w", lastErr)
	}
	if len(pending) > 0 {
		slog.Warn("audit left claims unassessed", "label", label, "claims", len(pending), "error", lastErr)
	}
	slog.Info("audit batch complete", "label", label, "assessed", len(got), "prompt_tokens", usage.PromptTokens,
		"completion_tokens", usage.CompletionTokens, "cost", fmt.Sprintf("$%.4f", cost))
	return got, leads, usage, cost, nil
}

func (r *auditV2Run) call(ctx context.Context, claims []auditClaimV2, label string) (*llm.ChatResponse, error) {
	var cweIDs []string
	files := make(map[string]bool)
	for _, c := range claims {
		if c.CWEID != "" {
			cweIDs = append(cweIDs, c.CWEID)
		}
		if c.FilePath != "" {
			files[c.FilePath] = true
		}
		for _, flow := range c.CodeFlows {
			for _, thread := range flow.ThreadFlows {
				for _, step := range thread.Locations {
					files[step.Location.PhysicalLocation.ArtifactLocation.URI] = true
				}
			}
		}
	}
	claimsJSON, err := json.Marshal(map[string]any{"claims_to_verify": claims})
	if err != nil {
		return nil, fmt.Errorf("marshal claims: %w", err)
	}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var codeCtx strings.Builder
	for _, p := range paths {
		if content, ok := r.fileMap[p]; ok {
			fmt.Fprintf(&codeCtx, "<file path=\"%s\">\n%s</file>\n\n", p, numberedSource(content))
		}
	}
	retrieved, excerpts := r.retrieve(claims, files)
	codeCtx.WriteString(retrieved)

	schema := llm.AuditSchemaV2()
	messages, err := r.promptLoader.AssembleAuditMessages(llm.AuditParams{
		RepoName:             r.repoName,
		FindingsJSON:         string(claimsJSON),
		CodeContext:          codeCtx.String(),
		CWEIDs:               cweIDs,
		Schema:               string(*schema),
		ProductionOnly:       r.productionOnly,
		SupplementaryContext: r.supContext,
		OtherClaims:          otherClaims(r.claims, claims),
	})
	if err != nil {
		return nil, fmt.Errorf("assemble audit prompt: %w", err)
	}
	var estTokens int
	for _, m := range messages {
		estTokens += r.counter.Count(m.Content)
	}
	slog.Info("running audit batch", "label", label, "findings", len(claims), "files_in_context", len(paths), "retrieved_excerpts", excerpts,
		"estimated_tokens", estTokens, "estimated_input_cost", fmt.Sprintf("$%.4f", r.modelCfg.EstimateInputCost(estTokens)))

	resp, err := r.client.ChatCompletion(ctx, llm.ChatRequest{
		Label:                  label,
		Endpoint:               r.endpoint,
		Model:                  r.modelCfg.Name,
		Messages:               messages,
		Temperature:            r.modelCfg.Temperature,
		OmitTemperature:        r.modelCfg.OmitTemperature,
		MaxTokens:              r.modelCfg.MaxOutputTokens,
		UseMaxCompletionTokens: r.modelCfg.UseMaxCompletionTokens,
		ResponseSchema:         schema,
		OutputMode:             r.outputMode,
		NativeStructuredOutput: r.modelCfg.NativeStructuredOutput,
		ModelParams:            r.modelParams,
	})
	if err != nil {
		return nil, fmt.Errorf("LLM call: %w", err)
	}
	return resp, nil
}

// retrieve renders context the claims' own files lack. Excerpts are taken
// round-robin across claims, so each claim gets its most useful context
// before any claim gets its next.
func (r *auditV2Run) retrieve(claims []auditClaimV2, sent map[string]bool) (string, int) {
	if r.index == nil {
		return "", 0
	}
	perClaim := make([][]auditctx.Excerpt, len(claims))
	for i, c := range claims {
		perClaim[i] = r.index.Retrieve(auditctx.Claim{File: c.FilePath, Start: c.StartLine, End: c.EndLine}, sent)
	}
	var ordered []auditctx.Excerpt
	for depth := 0; ; depth++ {
		added := false
		for _, list := range perClaim {
			if depth < len(list) {
				ordered = append(ordered, list[depth])
				added = true
			}
		}
		if !added {
			break
		}
	}
	return auditctx.Render(r.index, ordered, auditRetrievalBudget, r.counter.Count)
}

// otherClaims lists the claims outside batch, one line each.
func otherClaims(all, batch []auditClaimV2) string {
	in := make(map[string]bool, len(batch))
	for _, c := range batch {
		in[c.FindingID] = true
	}
	var b strings.Builder
	for _, c := range all {
		if !in[c.FindingID] {
			fmt.Fprintf(&b, "- %s (%s:%d)\n", c.Issue, c.FilePath, c.StartLine)
		}
	}
	if b.Len() == 0 {
		return "(none)"
	}
	return strings.TrimRight(b.String(), "\n")
}

// auditClaimsV2 presents each result as a claim keyed by its finding ID.
func auditClaimsV2(doc sarif.SARIFDocument) []auditClaimV2 {
	run := doc.Runs[0]
	rules := make(map[string]sarif.SARIFRule, len(run.Tool.Driver.Rules))
	for _, rule := range run.Tool.Driver.Rules {
		rules[rule.ID] = rule
	}
	ids := auditFindingIDs(run.Results)
	claims := make([]auditClaimV2, len(run.Results))
	for i, result := range run.Results {
		rule := rules[result.RuleID]
		c := auditClaimV2{
			FindingID:               ids[i],
			Issue:                   rule.ShortDescription.Text,
			UnverifiedExploitSketch: result.Message.Text,
			Severity:                sarif.ResultSeverity(result, rule),
			CWEID:                   sarif.ResultCWE(result, rule),
			CodeFlows:               result.CodeFlows,
		}
		if len(result.Locations) > 0 {
			loc := result.Locations[0].PhysicalLocation
			c.FilePath = loc.ArtifactLocation.URI
			if loc.Region != nil {
				c.StartLine, c.EndLine = loc.Region.StartLine, loc.Region.EndLine
			}
		}
		if result.Properties != nil && result.Properties.TechnicalDetails != "" {
			c.UnverifiedExploitSketch = result.Properties.TechnicalDetails
		}
		claims[i] = c
	}
	return claims
}

// auditFindingIDs returns a unique ID per result: its finding ID, or a
// positional one when IDs were not assigned.
func auditFindingIDs(results []sarif.SARIFResult) []string {
	ids := make([]string, len(results))
	seen := make(map[string]bool, len(results))
	for i, r := range results {
		id := ""
		if r.Properties != nil {
			id = r.Properties.FindingID
		}
		if id == "" || seen[id] {
			id = fmt.Sprintf("result-%d", i+1)
		}
		seen[id] = true
		ids[i] = id
	}
	return ids
}

// numberedSource prefixes each line with its 1-based number, the form audit
// evidence cites.
func numberedSource(content string) string {
	var out strings.Builder
	for i, line := range strings.SplitAfter(content, "\n") {
		if line == "" {
			break
		}
		fmt.Fprintf(&out, "%d| %s", i+1, line)
		if !strings.HasSuffix(line, "\n") {
			out.WriteByte('\n')
		}
	}
	return out.String()
}

func parseAuditResponseV2(content, finishReason string) (auditResponseV2, error) {
	var resp auditResponseV2
	err := json.Unmarshal([]byte(content), &resp)
	if err != nil {
		if repaired, changed := llm.RepairJSON(content); changed {
			resp = auditResponseV2{}
			err = json.Unmarshal([]byte(repaired), &resp)
		}
	}
	if err != nil {
		return auditResponseV2{}, fmt.Errorf("parse audit response: %w", err)
	}
	// A truncated response may end mid-assessment; keep only the complete ones.
	if (finishReason == "length" || finishReason == "max_tokens") && len(resp.Assessments) > 0 {
		resp.Assessments = resp.Assessments[:len(resp.Assessments)-1]
	}
	return resp, nil
}

// acceptAssessments adds the valid assessments of pending claims to got and
// describes the first problem with the rest.
func acceptAssessments(got map[string]auditAssessmentV2, pending []auditClaimV2, assessments []auditAssessmentV2, label string) error {
	want := make(map[string]bool, len(pending))
	for _, c := range pending {
		want[c.FindingID] = true
	}
	var problem error
	note := func(err error) {
		slog.Warn("audit assessment ignored", "label", label, "error", err)
		if problem == nil {
			problem = err
		}
	}
	for _, a := range assessments {
		a.FindingID = strings.TrimSpace(a.FindingID)
		switch _, dup := got[a.FindingID]; {
		case !want[a.FindingID] && !dup:
			note(fmt.Errorf("audit returned an unknown finding_id %q", a.FindingID))
		case dup:
			note(fmt.Errorf("audit returned finding_id %q twice", a.FindingID))
		case !a.valid():
			note(fmt.Errorf("audit returned an invalid answer status for %q", a.FindingID))
		default:
			got[a.FindingID] = a
		}
	}
	if problem == nil && len(got) < len(want) {
		missing := 0
		for id := range want {
			if _, ok := got[id]; !ok {
				missing++
			}
		}
		if missing > 0 {
			problem = fmt.Errorf("audit omitted %d claims", missing)
		}
	}
	return problem
}

// auditOutcomeV2 is the code-computed result for one assessed finding.
type auditOutcomeV2 struct {
	status      string
	reasons     []string
	answers     map[string]sarif.AuditAnswer
	exposure    *sarif.DeploymentExposure
	duplicateOf string
}

// auditVerdictV2 is the verdict policy. A question refuted with verified
// evidence rejects the finding; all questions established confirm it;
// anything else is unverified. Missing evidence never rejects.
func auditVerdictV2(answers map[string]sarif.AuditAnswer) (status string, reasons []string) {
	var refuted, unknown []string
	for _, q := range llm.AuditQuestions {
		switch answers[q].Status {
		case "refuted":
			refuted = append(refuted, q)
		case "established":
		default:
			unknown = append(unknown, q)
		}
	}
	switch {
	case len(refuted) > 0:
		for _, q := range refuted {
			reasons = append(reasons, "refuted:"+q)
		}
		return "rejected", reasons
	case len(unknown) == 0:
		return "confirmed", nil
	}
	for _, q := range unknown {
		reasons = append(reasons, "unknown:"+q)
	}
	return "unverified", reasons
}

func evaluateAssessment(a auditAssessmentV2, ev *evidenceVerifier) auditOutcomeV2 {
	out := auditOutcomeV2{answers: make(map[string]sarif.AuditAnswer, len(llm.AuditQuestions))}
	var downgraded []string
	for _, q := range llm.AuditQuestions {
		ans, reason := ev.answer(a.answer(q))
		out.answers[q] = ans
		if reason != "" {
			downgraded = append(downgraded, reason+":"+q)
		}
	}
	out.status, out.reasons = auditVerdictV2(out.answers)
	out.reasons = append(out.reasons, downgraded...)
	out.exposure = ev.exposure(a.DeploymentExposure)
	return out
}

// applyAuditAssessments records each v2 outcome on its own result. Rejected
// and duplicate findings stay in the report as suppressed records.
func applyAuditAssessments(doc sarif.SARIFDocument, assessments map[string]auditAssessmentV2, batchOf map[string]int, fileMap ingest.FileMap) sarif.SARIFDocument {
	doc.Runs = append([]sarif.SARIFRun(nil), doc.Runs...)
	run := &doc.Runs[0]
	run.Results = append([]sarif.SARIFResult(nil), run.Results...)
	rules := make(map[string]sarif.SARIFRule, len(run.Tool.Driver.Rules))
	for _, rule := range run.Tool.Driver.Rules {
		rules[rule.ID] = rule
	}
	ids := auditFindingIDs(run.Results)
	ev := &evidenceVerifier{files: fileMap, lines: map[string][]string{}}
	outcomes := make(map[string]*auditOutcomeV2, len(assessments))
	for _, id := range ids {
		if a, ok := assessments[id]; ok {
			o := evaluateAssessment(a, ev)
			outcomes[id] = &o
		}
	}
	markDuplicates(ids, assessments, batchOf, outcomes)

	counts := map[string]int{}
	for i := range run.Results {
		result := &run.Results[i]
		props := sarif.FindingProperties{}
		if result.Properties != nil {
			props = *result.Properties
		}
		result.Properties = &props
		props.AuditConfidence = nil
		o, ok := outcomes[ids[i]]
		if !ok {
			props.AuditStatus = "not_audited"
			props.AuditReasons = []string{"missing_verdict"}
			counts["not_audited"]++
			continue
		}
		a := assessments[ids[i]]
		props.AuditAnswers = o.answers
		props.DeploymentExposure = o.exposure
		props.AuditReasons = o.reasons
		props.DuplicateOf = o.duplicateOf
		props.AuditStatus = o.status
		switch o.status {
		case "rejected":
			result.Suppressions = []sarif.SARIFSuppression{{Kind: "external", Status: "accepted", Justification: rejectionJustification(o)}}
		case "duplicate":
			result.Suppressions = []sarif.SARIFSuppression{{Kind: "external", Status: "accepted",
				Justification: "Duplicate of " + o.duplicateOf + ": same root cause and fix."}}
		default:
			if o.status == "unverified" {
				props.AuditCrux = strings.TrimSpace(a.Crux)
			}
			rule := rules[result.RuleID]
			if sev := a.RefinedSeverity; sev > 0 && !math.IsNaN(sev) {
				sev = math.Min(sev, 10)
				if o.status == "confirmed" && math.Abs(sev-sarif.ResultSeverity(*result, rule)) >= 0.05 {
					props.AuditStatus = "refined"
				}
				props.Severity = &sev
				result.Level = severityLevelScan(sev)
			}
			if cwe := sarif.NormalizeCWE(a.RefinedCWEID); cwe != "" && cwe != sarif.ResultCWE(*result, rule) {
				if o.status == "confirmed" {
					props.AuditStatus = "refined"
				}
				props.CWE = cwe
			}
			if s := strings.TrimSpace(a.Summary); s != "" {
				props.Summary = s
			}
			if s := strings.TrimSpace(a.Remediation); s != "" {
				props.Remediation = s
			}
			if props.TechnicalDetails == "" {
				props.TechnicalDetails = result.Message.Text
			}
			result.Message = sarif.SARIFMessage{Text: props.TechnicalDetails}
		}
		counts[props.AuditStatus]++
	}
	slog.Info("audit verdicts applied", "contract", "v2", "confirmed", counts["confirmed"], "refined", counts["refined"],
		"unverified", counts["unverified"], "rejected", counts["rejected"], "duplicate", counts["duplicate"], "not_audited", counts["not_audited"])
	return doc
}

// markDuplicates honors duplicate_of when it names another claim from the
// same batch that is not itself marked a duplicate and is assessed at least
// as strongly, so the finding left visible is never the weaker one.
func markDuplicates(ids []string, assessments map[string]auditAssessmentV2, batchOf map[string]int, outcomes map[string]*auditOutcomeV2) {
	rank := func(status string) int {
		switch status {
		case "confirmed":
			return 2
		case "unverified":
			return 1
		}
		return 0
	}
	for _, id := range ids {
		o, ok := outcomes[id]
		if !ok || o.status == "rejected" {
			continue
		}
		target := strings.TrimSpace(assessments[id].DuplicateOf)
		t, ok := outcomes[target]
		if target == "" || target == id || !ok || batchOf[target] != batchOf[id] ||
			strings.TrimSpace(assessments[target].DuplicateOf) != "" || rank(t.status) < rank(o.status) {
			continue
		}
		o.status, o.duplicateOf = "duplicate", target
		o.reasons = append(o.reasons, "duplicate")
	}
}

func rejectionJustification(o *auditOutcomeV2) string {
	var b strings.Builder
	b.WriteString("Rejected by audit")
	for _, q := range llm.AuditQuestions {
		ans := o.answers[q]
		if ans.Status != "refuted" {
			continue
		}
		fmt.Fprintf(&b, "\n\n%s refuted", q)
		if ans.Reason != "" {
			b.WriteString(": " + ans.Reason)
		}
		for _, e := range ans.Evidence {
			fmt.Fprintf(&b, "\n%s:%d: %s", e.File, e.Line, e.Quote)
		}
	}
	return b.String()
}

// auditLeads trims, de-duplicates, and bounds the audit's follow-up notes.
func auditLeads(leads []string) []string {
	const maxLeads, maxLen = 50, 500
	var out []string
	seen := map[string]bool{}
	for _, l := range leads {
		l = strings.TrimSpace(l)
		if len(l) > maxLen {
			l = l[:maxLen]
		}
		if l == "" || seen[l] || len(out) == maxLeads {
			continue
		}
		seen[l] = true
		out = append(out, l)
	}
	return out
}

// evidenceVerifier checks audit quotes against the scanned source.
type evidenceVerifier struct {
	files ingest.FileMap
	lines map[string][]string
}

// lineNumberPrefix matches the "N| " prefix numberedSource adds, which models
// sometimes copy into quotes.
var lineNumberPrefix = regexp.MustCompile(`^\s*\d+\|\s?`)

// verify keeps the quotes that appear, whitespace-normalized, within two
// lines of the cited line of a scanned file. Quotes too short to identify a
// line (a lone brace) never verify.
func (v *evidenceVerifier) verify(evidence []sarif.AuditEvidence) []sarif.AuditEvidence {
	var out []sarif.AuditEvidence
	for _, e := range evidence {
		file, ok := sarif.ResolvePath(sarif.FileMap(v.files), e.File)
		if !ok {
			continue
		}
		lines, ok := v.lines[file]
		if !ok {
			lines = strings.Split(v.files[file], "\n")
			v.lines[file] = lines
		}
		if e.Line < 1 || e.Line > len(lines) {
			continue
		}
		window := normalizeSpace(strings.Join(lines[max(0, e.Line-3):min(len(lines), e.Line+2)], " "))
		for _, quote := range []string{e.Quote, lineNumberPrefix.ReplaceAllString(e.Quote, "")} {
			q := normalizeSpace(quote)
			if len(q) >= 4 && strings.IndexFunc(q, unicode.IsLetter) >= 0 && strings.Contains(window, q) {
				out = append(out, sarif.AuditEvidence{File: file, Line: e.Line, Quote: strings.TrimSpace(quote)})
				break
			}
		}
	}
	return out
}

// answer keeps verified quotes only. An answer whose quotes all fail, or a
// refutation with none, becomes unknown; reason names the downgrade.
func (v *evidenceVerifier) answer(a sarif.AuditAnswer) (sarif.AuditAnswer, string) {
	out := sarif.AuditAnswer{Status: answerStatus(a.Status), Reason: strings.TrimSpace(a.Reason), Evidence: v.verify(a.Evidence)}
	if out.Status == "unknown" || len(out.Evidence) > 0 {
		return out, ""
	}
	if len(a.Evidence) > 0 {
		out.Status = "unknown"
		return out, "unverified_evidence"
	}
	if out.Status == "refuted" {
		out.Status = "unknown"
		return out, "ungrounded_refutation"
	}
	return out, ""
}

// exposure records deployment exposure under the same evidence rule as the
// answers; not_deployed needs a verified quote. It never affects the verdict.
func (v *evidenceVerifier) exposure(e sarif.DeploymentExposure) *sarif.DeploymentExposure {
	out := sarif.DeploymentExposure{Status: answerStatus(e.Status), Detail: strings.TrimSpace(e.Detail), Evidence: v.verify(e.Evidence)}
	switch out.Status {
	case "default_on", "config_enabled", "config_dependent", "not_deployed", "unknown":
	default:
		out.Status = "unknown"
	}
	if len(out.Evidence) == 0 && (len(e.Evidence) > 0 || out.Status == "not_deployed") {
		out.Status = "unknown"
	}
	if out.Status == "unknown" && out.Detail == "" {
		return nil
	}
	return &out
}

func normalizeSpace(s string) string { return strings.Join(strings.Fields(s), " ") }
