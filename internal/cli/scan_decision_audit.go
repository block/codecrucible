package cli

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/block/codecrucible/internal/decision"
	"github.com/block/codecrucible/internal/sarif"
)

type routedAudit struct {
	Retained      []sarif.SARIFResult
	Rules         []sarif.SARIFRule
	OriginalCount int
	Rejected      int
}

// routeAudit removes only sufficiently resolved work from generative audit.
// Probabilities route bounded decisions; they are not vulnerability confidence.
func (d *scanDecisions) routeAudit(ctx context.Context, doc sarif.SARIFDocument) (sarif.SARIFDocument, routedAudit, error) {
	routed := routedAudit{}
	if !d.enabled("audit") || len(doc.Runs) == 0 {
		return doc, routed, nil
	}
	mode := d.cfg.Audit
	outcomePrefix := ""
	if mode == "shadow" {
		outcomePrefix = "proposed_"
	}
	if !d.auditPolicySupported {
		d.recorder.Skip("audit", mode, "prompt_set_requires_generative_audit")
		d.recorder.Action("existing_audit")
		d.recorder.Outcome(outcomePrefix+"escalate", len(doc.Runs[0].Results))
		return doc, routed, nil
	}
	run := doc.Runs[0]
	routed.Rules = append([]sarif.SARIFRule{}, run.Tool.Driver.Rules...)
	routed.OriginalCount = len(run.Results)
	titles := map[string]string{}
	for _, r := range run.Tool.Driver.Rules {
		titles[r.ID] = r.ShortDescription.Text
	}
	queue := []sarif.SARIFResult{}
	for _, finding := range run.Results {
		selection := d.findingEvidence(finding)
		evidence, complete := selection.Evidence, selection.Complete()
		if !complete {
			d.recorder.Skip("audit", mode, "incomplete_source_coverage")
			d.recorder.FindingCoverage(decisionSubject(finding), selection)
			d.recorder.Outcome(outcomePrefix+"escalate", 1)
			queue = append(queue, finding)
			continue
		}
		claim := decisionClaim(finding, titles[finding.RuleID])
		if len(claim) > 6000 {
			d.recorder.Skip("audit", mode, "claim_exceeds_budget")
			d.recorder.FindingCoverage(decisionSubject(finding), selection)
			d.recorder.Outcome(outcomePrefix+"escalate", 1)
			queue = append(queue, finding)
			continue
		}
		choices := map[string]string{"none": "No supplied span conclusively blocks this finding"}
		for _, e := range evidence {
			choices[e.ID] = fmt.Sprintf("Exact supplied source at %s:%d-%d", e.Path, e.Start, e.End)
		}
		if len(choices) < 2 || len(choices) > 255 {
			d.recorder.Skip("audit", mode, "evidence_choice_limit")
			d.recorder.FindingCoverage(decisionSubject(finding), selection)
			d.recorder.Outcome(outcomePrefix+"escalate", 1)
			queue = append(queue, finding)
			continue
		}
		questions := map[string]decision.Question{
			"reachability":      decision.Choice("Does the supplied route/caller evidence establish attacker reachability of the claimed operation? Apply production_only, custom_requirements and supplementary_context. Missing registration or deployment prerequisites are insufficient_evidence.", map[string]string{"established": "The claimed attacker can reach the operation under the required scope", "refuted": "Source disproves the claimed reachability", "insufficient_evidence": "A necessary caller or deployment fact is missing"}),
			"attacker_control":  decision.Choice("Does the supplied source establish attacker control over the specific value or identity asserted in the claim? Distinguish trusted identity from caller-supplied values.", map[string]string{"established": "The claimed attacker controls the specified input", "refuted": "Source establishes the input is not controlled as claimed", "insufficient_evidence": "The input origin cannot be established"}),
			"operation":         decision.Choice("Does executable source demonstrate the harmful operation described in the claim? Judge this operation alone, without assuming the claimed input origin or impact.", map[string]string{"supported": "The specified operation is visible in source", "contradicted": "Executable source contradicts the claimed operation", "insufficient_evidence": "The operation or required library behavior is unshown"}),
			"impact":            decision.Choice("Does the supplied source establish the specific security consequence asserted in the claim? Unshown configuration, library behavior, or narrative authority cannot establish impact.", map[string]string{"supported": "The claimed material consequence is established", "contradicted": "Source contradicts the claimed consequence", "insufficient_evidence": "The consequence remains unproven"}),
			"mitigation":        decision.Choice("Does an executable protection prevent the claimed operation on the relevant shown paths? Check its semantics and ordering. Missing guards or paths are insufficient evidence, not proof of their absence.", map[string]string{"effective": "A visible control prevents this exact claimed operation", "ineffective": "The relevant path is shown and its protections do not prevent the claimed operation", "insufficient_evidence": "The relevant protection or path semantics are uncertain"}),
			"blocking_present":  decision.Noul("Does the supplied source contain an executable control that addresses the exact attacker action asserted in the claim? This asks whether relevant control evidence exists, not whether it proves the finding false."),
			"blocking_evidence": decision.Choice("Which single supplied span contains an effective blocking control for this exact claim? Select none if no supplied span establishes such a control. A comment or unrelated check is not a blocking control.", choices),
		}
		state := map[string]any{"claim": claim, "source": evidence, "dependency_graph_coverage": "claim-focused local declarations and callers; symbol matching and local imports are best effort. Unrelated file contents are omitted; coverage is not repository-wide", "supplementary_context": d.supplementary, "custom_requirements": d.requirements, "production_only": d.productionOnly}
		response, err := d.recorder.Evaluate(ctx, "audit", mode, decisionSubject(finding), state, questions, evidence, complete)
		d.recorder.FindingCoverage(decisionSubject(finding), selection)
		verdictRecord := len(d.recorder.Records) - 1
		if ctx.Err() != nil {
			return doc, routed, ctx.Err()
		}
		action := "escalate"
		if err == nil {
			a := response.Answers
			if decision.Strong(a["reachability"], "established") && decision.Strong(a["attacker_control"], "established") && decision.Strong(a["operation"], "supported") && decision.Strong(a["impact"], "supported") && decision.Strong(a["mitigation"], "ineffective") && decision.Strong(a["blocking_evidence"], "none") {
				action = "retain"
			}
			blocking := a["blocking_evidence"]
			if decision.Strong(a["reachability"], "established") && decision.Strong(a["operation"], "supported") && decision.Strong(a["mitigation"], "effective") && decision.StrongYes(a["blocking_present"]) && blocking.Choice != "none" && decision.Strong(blocking, blocking.Choice) {
				for _, e := range evidence {
					if e.ID != blocking.Choice {
						continue
					}
					verified, verifyErr := d.verifyBlock(ctx, mode, decisionSubject(finding), claim, e, evidence)
					if verifyErr != nil && ctx.Err() != nil {
						return doc, routed, ctx.Err()
					}
					if verified {
						action = "reject"
					}
				}
			}
		}
		outcome := outcomePrefix + action
		d.recorder.Records[verdictRecord].Outcomes = map[string]int{outcome: 1}
		if mode == "shadow" {
			d.recorder.Records[verdictRecord].Action = "shadow_proposed_" + action
			d.recorder.Action("shadow_proposed_" + action)
			queue = append(queue, finding)
			continue
		}
		d.recorder.Action(action)
		d.recorder.Records[verdictRecord].Action = action
		switch action {
		case "retain":
			props := sarif.FindingProperties{}
			if finding.Properties != nil {
				props = *finding.Properties
			}
			props.AuditStatus = "jev_supported"
			props.AuditConfidence = nil
			props.DecisionAudit = &sarif.DecisionAssessment{Status: "supported", Model: response.Model, Policy: decision.PolicyVersion, EvidenceIDs: evidenceIDs(evidence)}
			finding.Properties = &props
			routed.Retained = append(routed.Retained, finding)
		case "reject":
			routed.Rejected++
		default:
			queue = append(queue, finding)
		}
	}
	doc.Runs = append([]sarif.SARIFRun{}, doc.Runs...)
	doc.Runs[0].Results = queue
	return doc, routed, nil
}
func (d *scanDecisions) verifyBlock(ctx context.Context, mode, subject, claim string, block decision.Evidence, evidence []decision.Evidence) (bool, error) {
	source, ok := d.files[block.Path]
	exact, valid := decision.SourceEvidence(block.Path, source, block.Start, block.End)
	if !ok || !valid || exact.ID != block.ID || strings.TrimSpace(block.Text) == "" {
		return false, nil
	}
	q := decision.Choice("Recheck the claim against the proposed blocking span. Does executable code in this exact span prevent the specific attacker action on every relevant path shown? Verify guard ordering, attacker control, bypasses, and material prerequisites. Comments, defensive-sounding names, unrelated checks, and missing context cannot justify rejection.", map[string]string{"blocked": "This exact executable control conclusively prevents the specific claim", "not_blocked": "The control does not prevent this claim", "insufficient_evidence": "Coverage or semantics cannot establish prevention"})
	response, err := d.recorder.Evaluate(ctx, "audit", mode, subject+":blocking-validation", map[string]any{"claim": claim, "proposed_blocking_span": block, "source": evidence, "supplementary_context": d.supplementary, "custom_requirements": d.requirements, "production_only": d.productionOnly}, map[string]decision.Question{"blocking_validation": q}, evidence, true)
	d.recorder.FindingCoverage(subject+":blocking-validation", decision.EvidenceSelection{Evidence: evidence})
	return err == nil && decision.Strong(response.Answers["blocking_validation"], "blocked"), err
}
func restoreRoutedAudit(doc sarif.SARIFDocument, r routedAudit) sarif.SARIFDocument {
	if r.OriginalCount == 0 || len(doc.Runs) == 0 {
		return doc
	}
	doc.Runs = append([]sarif.SARIFRun{}, doc.Runs...)
	run := &doc.Runs[0]
	run.Results = append(append([]sarif.SARIFResult{}, run.Results...), r.Retained...)
	rules := map[string]sarif.SARIFRule{}
	for _, rule := range r.Rules {
		rules[rule.ID] = rule
	}
	for _, rule := range run.Tool.Driver.Rules {
		rules[rule.ID] = rule
	}
	used := map[string]bool{}
	for _, finding := range run.Results {
		used[finding.RuleID] = true
	}
	run.Tool.Driver.Rules = []sarif.SARIFRule{}
	for id := range used {
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rules[id])
	}
	sort.Slice(run.Tool.Driver.Rules, func(i, j int) bool { return run.Tool.Driver.Rules[i].ID < run.Tool.Driver.Rules[j].ID })
	return doc
}
func evidenceIDs(evidence []decision.Evidence) []string {
	ids := make([]string, 0, len(evidence))
	for _, e := range evidence {
		ids = append(ids, e.ID)
	}
	return ids
}
