package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/block/codecrucible/internal/auditcore"
	"github.com/block/codecrucible/internal/auditctx"
	"github.com/block/codecrucible/internal/llm"
	"github.com/block/codecrucible/internal/sarif"
	"github.com/block/codecrucible/internal/sourceindex"
)

type auditRunOptions struct {
	semanticDedup      string
	maxCost, priorCost float64
}
type auditV3Run struct {
	auditV2Run
	options    auditRunOptions
	usage      llm.TokenUsage
	cost       float64
	incomplete int
	fatal      error
}
type assessedV3 struct {
	raw      auditcore.Assessment
	outcome  auditcore.Outcome
	bundle   auditctx.Bundle
	producer string
}

func claimsV3(doc sarif.SARIFDocument) []auditcore.Claim {
	old := auditClaims(doc)
	out := make([]auditcore.Claim, len(old))
	for i, c := range old {
		v := auditcore.Claim{FindingID: c.FindingID, Title: c.Issue, Detail: c.UnverifiedExploitSketch, File: c.FilePath, Start: c.StartLine, End: c.EndLine, CWE: c.CWEID, Severity: c.Severity}
		v.Material = []auditcore.Material{{ID: "title", Text: v.Title}, {ID: "detail", Text: v.Detail}}
		for j, f := range c.CodeFlows {
			b, _ := json.Marshal(f)
			v.Material = append(v.Material, auditcore.Material{ID: fmt.Sprintf("code_flow_%d", j+1), Text: string(b)})
			for _, thread := range f.ThreadFlows {
				for _, step := range thread.Locations {
					loc := step.Location.PhysicalLocation
					if loc.Region != nil {
						quote := ""
						if loc.Region.Snippet != nil {
							quote = loc.Region.Snippet.Text
						}
						v.Evidence = append(v.Evidence, auditcore.NamedEvidence{Kind: "code_path", Evidence: auditcore.Evidence{File: loc.ArtifactLocation.URI, Start: loc.Region.StartLine, End: loc.Region.EndLine, Quote: quote}})
					}
				}
			}

		}
		p := doc.Runs[0].Results[i].Properties
		if p != nil {
			v.Evidence = append(v.Evidence, p.InitialEvidence...)
			for j, e := range v.Evidence {
				b, _ := json.Marshal(e)
				v.Material = append(v.Material, auditcore.Material{ID: fmt.Sprintf("evidence_%d", j+1), Text: string(b)})
			}
		}
		if p != nil && p.Provenance != nil {
			v.RevisionID = p.Provenance.RevisionID
		}
		if v.RevisionID == "" {
			v.RevisionID = "claim-" + auditcore.Digest(v)
		}
		out[i] = auditcore.Seal(v)
	}
	return out
}
func legacyClaimsV3(in []auditcore.Claim) []auditClaim {
	out := make([]auditClaim, len(in))
	for i, c := range in {
		out[i] = auditClaim{FindingID: c.FindingID, FilePath: c.File, StartLine: c.Start, EndLine: c.End, Issue: c.Title, UnverifiedExploitSketch: c.Detail, CWEID: c.CWE, Severity: c.Severity}
	}
	return out
}
func (r *auditV3Run) runV3(ctx context.Context, doc sarif.SARIFDocument, batchSize int) (*sarif.SARIFDocument, llm.TokenUsage, float64, error) {
	claims := claimsV3(doc)
	if batchSize <= 0 {
		batchSize = len(claims)
	}
	got := map[string]assessedV3{}
	for i := 0; i < len(claims); i += batchSize {
		r.assess(ctx, claims[i:min(i+batchSize, len(claims))], fmt.Sprintf("audit v3 %d", i/batchSize+1), got)
	}
	// Copy the result slice before adding children. Existing IDs remain stable.
	doc.Runs = append([]sarif.SARIFRun{}, doc.Runs...)
	doc.Runs[0].Results = append([]sarif.SARIFResult{}, doc.Runs[0].Results...)
	for i, c := range claims {
		a, ok := got[c.FindingID]
		if !ok {
			r.incomplete++
			applyMissingV3(&doc.Runs[0].Results[i])
			continue
		}
		applyOutcomeV3(&doc.Runs[0].Results[i], a)
		if len(a.raw.Children) > 0 {
			if err := r.split(ctx, &doc, i, c, a); err != nil {
				return &doc, r.usage, r.cost, err
			}
		}
	}
	var pairs []duplicatePairV3
	if r.options.semanticDedup != "off" && ctx.Err() == nil {
		pairs = r.duplicates(ctx, &doc)
	}
	if err := r.journal.finish(&doc); err != nil {
		return &doc, r.usage, r.cost, err
	}
	if err := r.recordPairs(doc, pairs); err != nil {
		return &doc, r.usage, r.cost, err
	}
	if ctx.Err() != nil {
		return &doc, r.usage, r.cost, ctx.Err()
	}
	if r.fatal != nil {
		return &doc, r.usage, r.cost, r.fatal
	}
	if r.incomplete > 0 {
		return &doc, r.usage, r.cost, fmt.Errorf("audit incomplete: %d claims could not be assessed; findings retained", r.incomplete)
	}
	return &doc, r.usage, r.cost, nil
}
func applyMissingV3(result *sarif.SARIFResult) {
	p := sarif.FindingProperties{}
	if result.Properties != nil {
		p = *result.Properties
	}
	p.AuditStatus = "not_audited"
	p.AuditReasons = []string{"missing_verdict"}
	result.Properties = &p
}
func applyOutcomeV3(result *sarif.SARIFResult, a assessedV3) {
	p := sarif.FindingProperties{}
	if result.Properties != nil {
		p = *result.Properties
	}
	result.Properties = &p
	p.AuditIntegrity = &a.outcome
	p.AuditStatus = a.outcome.Status
	p.AuditReasons = a.outcome.Reasons
	p.AuditCrux = a.outcome.Crux
	p.AuditConfidence = nil
	p.Verified = a.outcome.Status == "confirmed"
	result.Suppressions = nil
	if a.outcome.Status == "rejected" {
		result.Suppressions = []sarif.SARIFSuppression{{Kind: "external", Status: "accepted", Justification: "Audit v3: " + strings.Join(a.outcome.Reasons, ", ")}}
	}
	// Keep the original narrative/severity on unresolved claims. A broad claim
	// cannot be quietly replaced by the auditor's narrower explanation.
	if a.outcome.Status == "confirmed" {
		if a.raw.Summary != "" {
			p.Summary = a.raw.Summary
		}
		if a.raw.Remediation != "" {
			p.Remediation = a.raw.Remediation
		}
		if a.raw.SeverityBasis != "" && a.raw.RefinedSeverity > 0 && a.raw.RefinedSeverity <= 10 && !math.IsNaN(a.raw.RefinedSeverity) {
			sev := a.raw.RefinedSeverity
			p.Severity = &sev
			result.Level = severityLevelScan(sev)
		}
		if cwe := sarif.NormalizeCWE(a.raw.RefinedCWE); cwe != "" && cwe != "CWE-0" {
			p.CWE = cwe
		}
	}
}
func (r *auditV3Run) assess(ctx context.Context, claims []auditcore.Claim, label string, got map[string]assessedV3) {
	if len(claims) == 0 || ctx.Err() != nil {
		return
	}
	accepted := r.assessCall(ctx, claims, label, nil)
	for id, a := range accepted {
		got[id] = a
	}
	// An invalid or omitted assessment gets exactly one individual retry.
	for _, c := range claims {
		a, ok := got[c.FindingID]
		if !ok {
			for id, retry := range r.assessCall(ctx, []auditcore.Claim{c}, label+" retry "+c.FindingID, nil) {
				got[id] = retry
			}
			a, ok = got[c.FindingID]
		}
		if !ok {
			continue
		}
		// One targeted retrieval round, not an unbounded agent loop.
		if a.outcome.Status == "unverified" {
			refs := append([]auditcore.Evidence{}, a.raw.Missing...)
			for _, assertion := range a.raw.Assertions {
				for _, list := range [][]auditcore.Evidence{assertion.Evidence, assertion.ConsumerEvidence, assertion.GuardEvidence} {
					for _, e := range list {
						if _, ok := r.index.Verify(a.bundle, e); !ok {
							refs = append(refs, e)
						}
					}
				}
			}
			var missing []auditcore.Evidence
			for _, e := range refs {
				if !a.bundle.Includes(e.File, e.Start, e.End) {
					missing = append(missing, e)
				}
			}
			extra := missingExcerpts(missing)
			if len(extra) > 0 {
				for id, retry := range r.assessCall(ctx, []auditcore.Claim{c}, label+" context "+c.FindingID, extra) {
					got[id] = retry
				}
			}
		}
	}
}
func missingExcerpts(refs []auditcore.Evidence) []auditctx.Excerpt {
	var out []auditctx.Excerpt
	for _, e := range refs {
		if e.File != "" && e.Start > 0 {
			out = append(out, auditctx.Excerpt{File: e.File, Start: max(1, e.Start-3), End: min(max(e.Start, e.End)+3, e.Start+120), Reason: "requested deciding evidence"})
		}
	}
	return out
}
func (r *auditV3Run) assessCall(ctx context.Context, claims []auditcore.Claim, label string, extra []auditctx.Excerpt) map[string]assessedV3 {
	out := map[string]assessedV3{}
	if ctx.Err() != nil {
		return out
	}
	schema := llm.AuditSchemaV3()
	payload, _ := json.Marshal(map[string]any{"claims_to_verify": claims})
	resp, bundle, err := r.callV3(ctx, label, string(payload), schema, claims, extra, "")
	if err != nil {
		slog.Warn("v3 audit request unavailable", "label", label, "error", err)
		if e := r.journal.attempt(legacyClaimsV3(claims), resp, nil, nil, err); e != nil {
			r.fatal = e
		}
		return out
	}
	var parsed struct {
		Assessments []auditcore.Assessment `json:"assessments"`
	}
	content, _ := llm.RepairJSON(resp.Content)
	err = json.Unmarshal([]byte(content), &parsed)
	producer, pErr := parsedProducer(r.client, resp, content)
	if pErr != nil {
		err = pErr
		r.fatal = pErr
	}
	if producer != "" {
		copyResp := *resp
		copyResp.ProducerID = producer
		copyResp.Content = content
		resp = &copyResp
	}
	if err == nil && (resp.FinishReason == "length" || resp.FinishReason == "max_tokens") {
		err = fmt.Errorf("truncated audit response")
	}
	counts := map[string]int{}
	for _, a := range parsed.Assessments {
		counts[a.FindingID]++
	}
	accepted := map[string]bool{}
	if err == nil {
		wanted := map[string]auditcore.Claim{}
		for _, c := range claims {
			wanted[c.FindingID] = c
		}
		for _, a := range parsed.Assessments {
			c, ok := wanted[a.FindingID]
			if !ok || counts[a.FindingID] != 1 || !auditcore.ValidIdentity(c, a) || !auditcore.ValidShape(a) {
				continue
			}
			outcome := auditcore.Evaluate(c, a, func(e auditcore.Evidence) (auditcore.Evidence, bool) { return r.index.Verify(bundle, e) }, func(e auditcore.Evidence) (auditcore.Evidence, bool) { return r.verifyAssumption(bundle, e) })
			out[c.FindingID] = assessedV3{a, outcome, bundle, producer}
			accepted[c.FindingID] = true
		}
		if len(out) != len(claims) {
			err = fmt.Errorf("missing or invalid claim-bound assessments")
		}
	}
	if e := r.journal.attempt(legacyClaimsV3(claims), resp, rawAssessments(parsed.Assessments, func(a auditcore.Assessment) string { return a.FindingID }), accepted, err); e != nil {
		r.fatal = e
	}
	return out
}
func (r *auditV3Run) callV3(ctx context.Context, label, payload string, schema *json.RawMessage, claims []auditcore.Claim, extra []auditctx.Excerpt, system string) (*llm.ChatResponse, auditctx.Bundle, error) {
	var locations []auditctx.Claim
	var cwes []string
	for _, c := range claims {
		locations = append(locations, auditctx.Claim{File: c.File, Start: c.Start, End: c.End})
		cwes = append(cwes, c.CWE)
		for _, e := range c.Evidence {
			extra = append(extra, auditctx.Excerpt{File: e.Evidence.File, Start: e.Evidence.Start, End: max(e.Evidence.Start, e.Evidence.End), Reason: "first-pass " + e.Kind})
		}
		for _, m := range sourceCitation.FindAllStringSubmatch(c.Detail, -1) {
			start, _ := strconv.Atoi(m[2])
			end := start
			if m[3] != "" {
				end, _ = strconv.Atoi(m[3])
			}
			extra = append(extra, auditctx.Excerpt{File: m[1], Start: max(1, start-2), End: min(end+2, start+120), Reason: "original claim citation"})
		}
	}
	assemble := func(code string) ([]llm.Message, error) {
		if system != "" {
			return []llm.Message{{Role: "system", Content: system}, {Role: "user", Content: payload + "\nSOURCE:\n" + code}}, nil
		}
		return r.promptLoader.AssembleAuditMessages(llm.AuditParams{RepoName: r.repoName, FindingsJSON: payload, CodeContext: code, CWEIDs: cwes, Schema: string(*schema), ProductionOnly: r.productionOnly, SupplementaryContext: numberedSource(r.supContext)})
	}
	fixed, err := assemble("")
	if err != nil {
		return nil, auditctx.Bundle{}, err
	}
	fixedTokens := 0
	for _, m := range fixed {
		fixedTokens += r.counter.Count(m.Content)
	}
	budget := min(auditRetrievalBudget, max(0, r.modelCfg.ContextLimit-r.modelCfg.MaxOutputTokens-fixedTokens-1024))
	bundle := r.index.Bundle(locations, extra, budget, r.counter.Count)
	messages, err := assemble(bundle.PromptText())
	if err != nil {
		return nil, bundle, err
	}
	tokens := 0
	for _, m := range messages {
		tokens += r.counter.Count(m.Content)
	}
	if tokens+r.modelCfg.MaxOutputTokens > r.modelCfg.ContextLimit {
		return nil, bundle, fmt.Errorf("audit request exceeds context limit")
	}
	if r.options.maxCost > 0 && r.options.priorCost+r.cost+r.modelCfg.EstimateInputCost(tokens) > r.options.maxCost {
		return nil, bundle, fmt.Errorf("audit cost limit reached")
	}
	if l := clientLedger(r.client); l != nil {
		if err := l.Artifact("bundle/"+label+"/"+bundle.Fingerprint, bundle); err != nil {
			return nil, bundle, err
		}
	}
	recordSourceBundle(r.metadata, "audit", label, bundle.Text)
	resp, err := r.client.ChatCompletion(ctx, llm.ChatRequest{Label: label, SourceBundleFingerprint: bundle.Fingerprint, Endpoint: r.endpoint, Model: r.modelCfg.Name, Messages: messages, Temperature: r.modelCfg.Temperature, OmitTemperature: r.modelCfg.OmitTemperature, MaxTokens: r.modelCfg.MaxOutputTokens, UseMaxCompletionTokens: r.modelCfg.UseMaxCompletionTokens, ResponseSchema: schema, OutputMode: r.outputMode, NativeStructuredOutput: r.modelCfg.NativeStructuredOutput, ModelParams: r.modelParams})
	if resp != nil {
		r.usage.PromptTokens += resp.Usage.PromptTokens
		r.usage.CompletionTokens += resp.Usage.CompletionTokens
		r.cost += r.modelCfg.EstimateCost(resp.Usage.PromptTokens, resp.Usage.CompletionTokens)
	}
	return resp, bundle, err
}
func (r *auditV3Run) split(ctx context.Context, doc *sarif.SARIFDocument, index int, parent auditcore.Claim, a assessedV3) error {
	// A split can add independently assessed children. Until coverage is proven,
	// the original remains an unresolved remainder even if its broad claim failed.
	p := doc.Runs[0].Results[index].Properties
	rejectedParent := p.AuditStatus == "rejected"
	if !rejectedParent {
		p.AuditStatus = "unverified"
		if p.AuditIntegrity != nil {
			v := *p.AuditIntegrity
			v.Status = "unverified"
			v.Reasons = append(append([]string{}, v.Reasons...), "independent_subclaims")
			p.AuditIntegrity = &v
		}
		p.Verified = false
		p.AuditCrux = "Grouped claim requires independent child decisions."
		doc.Runs[0].Results[index].Suppressions = nil
	}
	var valid []auditcore.Child
	var ids []string
	proposals := a.raw.Children
	if len(proposals) > 8 {
		proposals = proposals[:8]
	}
	for ordinal, c := range proposals {
		child, err := auditcore.ValidateChild(parent, c, func(e auditcore.Evidence) (auditcore.Evidence, bool) { return r.index.Verify(a.bundle, e) })
		if err != nil {
			continue
		}
		id := "CC-" + strings.ToUpper(auditcore.Digest([]any{"split", parent.RevisionID, a.producer, ordinal})[:16])
		childDoc := sarif.Build(sarif.AnalysisResult{SecurityIssues: []sarif.SecurityIssue{{Issue: child.Title, FilePath: child.File, StartLine: child.Start, EndLine: child.End, TechnicalDetails: child.Detail, CWEID: parent.CWE, Severity: parent.Severity}}}, sarif.FileMap(r.fileMap), sarif.BuilderConfig{ToolVersion: version})
		cr := &childDoc.Runs[0].Results[0]
		cr.Properties.FindingID = id
		cr.PartialFingerprints = map[string]string{sarif.FingerprintKey: auditcore.Digest([]any{"split", parent.RevisionID, a.producer, ordinal})}
		cr.Properties.ParentFindingID = parent.FindingID
		cr.Properties.ClaimCoverage = child.Covers
		if r.journal.ledger != nil && p.Provenance != nil {
			if err := r.journal.ledger.Child(id, a.producer, *p.Provenance, &childDoc); err != nil {
				return err
			}
			r.journal.revisions[id] = cr.Properties.Provenance.RevisionID
		}
		cc := claimsV3(childDoc)[0]
		out := map[string]assessedV3{}
		r.assess(ctx, []auditcore.Claim{cc}, "audit v3 child "+id, out)
		if assessed, ok := out[id]; ok {
			applyOutcomeV3(cr, assessed)
		} else {
			applyMissingV3(cr)
			r.incomplete++
		}
		// Depth is bounded at one. Further proposed splits stay unresolved.
		if assessed, ok := out[id]; ok && len(assessed.raw.Children) > 0 {
			supported := assessed.outcome.Status != "rejected"
			for _, proposal := range assessed.raw.Children {
				if _, err := auditcore.ValidateChild(cc, proposal, func(e auditcore.Evidence) (auditcore.Evidence, bool) { return r.index.Verify(assessed.bundle, e) }); err == nil {
					supported = true
					break
				}
			}
			if supported {
				cr.Properties.AuditStatus = "unverified"
				cr.Properties.Verified = false
				cr.Properties.AuditCrux = "Additional subclaims require review."
				cr.Suppressions = nil
				if cr.Properties.AuditIntegrity != nil {
					integrity := *cr.Properties.AuditIntegrity
					integrity.Status = "unverified"
					cr.Properties.AuditIntegrity = &integrity
				}
			}
		}
		doc.Runs[0].Results = append(doc.Runs[0].Results, *cr)
		for _, rule := range childDoc.Runs[0].Tool.Driver.Rules {
			found := false
			for _, old := range doc.Runs[0].Tool.Driver.Rules {
				if old.ID == rule.ID {
					found = true
					break
				}
			}
			if !found {
				doc.Runs[0].Tool.Driver.Rules = append(doc.Runs[0].Tool.Driver.Rules, rule)
			}
		}
		valid = append(valid, child)
		ids = append(ids, id)
	}
	p.ChildFindingIDs = ids
	if !rejectedParent && len(valid) == len(a.raw.Children) && auditcore.CompleteCoverage(parent, valid) {
		p.AuditStatus = "superseded"
		if p.AuditIntegrity != nil {
			v := *p.AuditIntegrity
			v.Status = "superseded"
			p.AuditIntegrity = &v
		}
		p.AuditCrux = ""
		doc.Runs[0].Results[index].Suppressions = []sarif.SARIFSuppression{{Kind: "external", Status: "accepted", Justification: "Independently assessed children: " + strings.Join(ids, ", ")}}
	}
	return nil
}

// Keep the candidate order deterministic even when upstream work is concurrent.
func sortedIDs(values []string) []string { sort.Strings(values); return values }

func (r *auditV3Run) verifyAssumption(bundle auditctx.Bundle, e auditcore.Evidence) (auditcore.Evidence, bool) {
	if e.File != "supplementary_context" {
		return r.index.Verify(bundle, e)
	}
	if e.End == 0 {
		e.End = e.Start
	}
	lines := strings.Split(r.supContext, "\n")
	if e.Start < 1 || e.End < e.Start || e.End > len(lines) || e.End-e.Start > 120 || strings.TrimSpace(e.Quote) == "" || !strings.Contains(strings.Join(lines[e.Start-1:e.End], "\n"), e.Quote) {
		return e, false
	}
	e.Fingerprint = sourceindex.Fingerprint(r.supContext)
	e.Validation = "supplied_context_quote_matched"
	return e, true
}
