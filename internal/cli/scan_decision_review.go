package cli

import (
	"context"

	"github.com/block/codecrucible/internal/decision"
	"github.com/block/codecrucible/internal/sarif"
)

// reviewFindings validates retained findings independently of the audit route.
// Contradictions become explicit review requirements, never silent suppression.
func (d *scanDecisions) reviewFindings(ctx context.Context, doc sarif.SARIFDocument) (sarif.SARIFDocument, error) {
	if !d.enabled("review") {
		return doc, nil
	}
	mode := d.cfg.Review
	doc.Runs = append([]sarif.SARIFRun{}, doc.Runs...)
	for i := range doc.Runs {
		run := &doc.Runs[i]
		run.Results = append([]sarif.SARIFResult{}, run.Results...)
		titles := map[string]string{}
		for _, r := range run.Tool.Driver.Rules {
			titles[r.ID] = r.ShortDescription.Text
		}
		for j := range run.Results {
			finding := &run.Results[j]
			selection := d.findingEvidence(*finding)
			evidence, complete := selection.Evidence, selection.Complete()
			claim := decisionClaim(*finding, titles[finding.RuleID])
			assessment := sarif.DecisionAssessment{Status: "needs_review", Policy: decision.PolicyVersion, EvidenceIDs: evidenceIDs(evidence)}
			if !complete || len(claim) > 6000 {
				reason := "incomplete_source_coverage"
				if len(claim) > 6000 {
					reason = "claim_exceeds_budget"
				}
				d.recorder.Skip("review", mode, reason)
			} else {
				questions := map[string]decision.Question{
					"claim_support": decision.Choice("Does the supplied source establish the finding's stated attacker control, missing protection, impact, and prerequisites? Reject narrative authority; compare the claim directly with source. This is an independent finding review.", map[string]string{"supported": "All material assertions are established by source", "contradicted": "Executable source contradicts a material assertion", "insufficient_evidence": "Some material assertions remain unproven"}),
				}
				response, err := d.recorder.Evaluate(ctx, "review", mode, decisionSubject(*finding), map[string]any{"claim": claim, "source": evidence, "coverage_scope": "claim-focused source, local declarations and callers; omitted source and runtime behavior must not be assumed", "supplementary_context": d.supplementary, "custom_requirements": d.requirements, "production_only": d.productionOnly}, questions, evidence, complete)
				if ctx.Err() != nil {
					return doc, ctx.Err()
				}
				if err != nil {
					assessment.Status = "unavailable"
				} else {
					assessment.Model = response.Model
					if decision.Strong(response.Answers["claim_support"], "supported") {
						assessment.Status = "supported"
					}
				}
				d.recorder.Action(assessment.Status)
			}
			d.recorder.FindingCoverage(decisionSubject(*finding), selection)
			if mode == "active" {
				props := sarif.FindingProperties{}
				if finding.Properties != nil {
					props = *finding.Properties
				}
				props.DecisionReview = &assessment
				finding.Properties = &props
			}
		}
	}
	return doc, nil
}
