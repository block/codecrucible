package cli

import (
	"context"

	"github.com/block/codecrucible/internal/decision"
	"github.com/block/codecrucible/internal/sarif"
)

// selectAuditEvidence keeps every finding in generative audit. Jev can add relevant
// source packets; it cannot confirm, suppress, rewrite, or remove a finding.
func (d *scanDecisions) selectAuditEvidence(ctx context.Context, doc sarif.SARIFDocument) error {
	if !d.enabled("audit") || len(doc.Runs) == 0 {
		return nil
	}
	d.auditEvidence = map[string][]decision.Evidence{}
	mode := d.cfg.Audit
	if !d.auditPolicySupported {
		d.recorder.Skip("audit", mode, "prompt_set_requires_generative_audit")
		return nil
	}
	titles := map[string]string{}
	for _, rule := range doc.Runs[0].Tool.Driver.Rules {
		titles[rule.ID] = rule.ShortDescription.Text
	}
	for _, finding := range doc.Runs[0].Results {
		if err := ctx.Err(); err != nil {
			return err
		}
		selection := d.citedEvidence(finding, 9000)
		claim := decisionClaim(finding, titles[finding.RuleID])
		if !selection.Complete() || len(claim) > 6000 {
			d.recorder.Skip("audit", mode, "incomplete_or_oversized_claim_context")
			d.recorder.FindingCoverage(decisionSubject(finding), selection)
			continue
		}
		candidates := d.evidenceIndex.RelatedEvidence(selection.Evidence, 7000)
		if len(candidates) == 0 {
			d.recorder.Skip("audit", mode, "no_optional_evidence_candidates")
			d.recorder.FindingCoverage(decisionSubject(finding), selection)
			continue
		}
		questions := map[string]decision.Question{}
		facts := map[string]string{
			"use":        "a caller, route registration, or template attachment connecting the cited operation to its use",
			"definition": "the definition of an input source or protection referenced by the cited operation",
		}
		for _, e := range candidates {
			for kind, fact := range facts {
				questions[e.ID+":"+kind] = decision.RelevanceQuestion(e.ID, fact)
			}
		}
		evidence := append(append([]decision.Evidence{}, selection.Evidence...), candidates...)
		state := map[string]any{"claim": claim, "mandatory_source": selection.Evidence, "optional_candidates": candidates, "required_facts": facts, "scope": "context selection only; missing context is not evidence against the claim"}
		response, _ := d.recorder.Evaluate(ctx, "audit", mode, decisionSubject(finding), state, questions, evidence, false)
		if err := ctx.Err(); err != nil {
			return err
		}
		d.recorder.Records[len(d.recorder.Records)-1].CoverageScope = "optional_source_candidates"
		d.recorder.Outcome("generative_candidates", 1)
		for _, e := range candidates {
			// Each relevance answer is independent. Valid answers can be used even
			// if a different candidate exhausted its retries.
			if !decision.StrongYes(response.Answers[e.ID+":use"]) && !decision.StrongYes(response.Answers[e.ID+":definition"]) {
				continue
			}
			if mode == "shadow" {
				d.recorder.Outcome("proposed_selected_evidence", 1)
			} else {
				d.recorder.Outcome("selected_evidence", 1)
			}
			if mode == "active" {
				d.auditEvidence[decisionSubject(finding)] = append(d.auditEvidence[decisionSubject(finding)], e)
			}
		}
		if mode == "shadow" {
			d.recorder.Action("shadow_proposed_evidence")
		} else {
			d.recorder.Action("existing_audit_with_optional_evidence")
		}
	}
	return nil
}
func evidenceIDs(evidence []decision.Evidence) []string {
	ids := make([]string, 0, len(evidence))
	for _, e := range evidence {
		ids = append(ids, e.ID)
	}
	return ids
}
