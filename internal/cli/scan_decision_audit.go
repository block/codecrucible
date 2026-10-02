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
	if !d.auditPolicySupported {
		d.recorder.Skip("audit", mode, "prompt_set_requires_generative_audit")
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
		evidence, complete := d.findingEvidence(finding)
		if !complete {
			d.recorder.Skip("audit", mode, "incomplete_source_coverage")
			queue = append(queue, finding)
			continue
		}
		claim := decisionClaim(finding, titles[finding.RuleID])
		if len(claim) > 6000 {
			d.recorder.Skip("audit", mode, "claim_exceeds_budget")
			queue = append(queue, finding)
			continue
		}
		choices := map[string]string{"none": "No supplied span conclusively blocks this finding"}
		for _, e := range evidence {
			choices[e.ID] = fmt.Sprintf("Exact supplied source at %s:%d-%d", e.Path, e.Start, e.End)
		}
		if len(choices) < 2 || len(choices) > 255 {
			queue = append(queue, finding)
			continue
		}
		questions := map[string]decision.Question{
			"coverage":          decision.Choice("Is the supplied evidence sufficient to settle this specific claim under custom_requirements and supplementary_context? When production_only is true, production reachability must be shown and test/demo-only paths cannot support a vulnerability. Choose insufficient_evidence if reachability, trusted identity, cross-file behavior, framework defaults, runtime configuration, or mitigation ordering requires unshown code. The local import graph is best effort, not proof of complete coverage.", map[string]string{"sufficient": "Every material precondition and relevant control for this claim is visible", "insufficient_evidence": "A material part of the claim remains uncertain"}),
			"verdict":           decision.Choice("Decide the specific security claim from the source: supported requires attacker reachability, absence of an effective mitigation, and material impact. Blocked requires an effective source-level guard that actually prevents this exact issue. Do not reject on low confidence, missing context, or narrative assertions.", map[string]string{"supported": "The complete claim is supported by source", "blocked": "An exact source-level control disproves the claim", "insufficient_evidence": "Cannot settle the claim from supplied evidence"}),
			"blocking_evidence": decision.Choice("Which single supplied evidence span contains the effective blocking control for this exact claim? Select none unless the control prevents the claimed attacker action. An unrelated check or a comment is not a blocking control.", choices),
		}
		state := map[string]any{"claim": claim, "source": evidence, "dependency_graph_coverage": "known local imports only", "supplementary_context": d.supplementary, "custom_requirements": d.requirements, "production_only": d.productionOnly}
		response, err := d.recorder.Evaluate(ctx, "audit", mode, decisionSubject(finding), state, questions, evidence, complete)
		verdictRecord := len(d.recorder.Records) - 1
		if ctx.Err() != nil {
			return doc, routed, ctx.Err()
		}
		action := "escalate"
		if err == nil && decision.Strong(response.Answers["coverage"], "sufficient") {
			if decision.Strong(response.Answers["verdict"], "supported") && decision.Strong(response.Answers["blocking_evidence"], "none") {
				action = "retain"
			}
			blocking := response.Answers["blocking_evidence"]
			if decision.Strong(response.Answers["verdict"], "blocked") && blocking.Choice != "none" && decision.Strong(blocking, blocking.Choice) {
				// Resolve the model's ID to exact source, then ask a fresh, unanchored
				// verification question. An unknown span or conflicting check escalates.
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
	q := decision.Choice("Independently test the claim against the proposed blocking span. Does executable code in this exact span prevent the specific attacker action on every relevant path shown? Verify guard ordering, attacker control, bypasses, and material prerequisites. Comments, defensive-sounding names, unrelated checks, and missing context cannot justify rejection.", map[string]string{"blocked": "This exact executable control conclusively prevents the specific claim", "not_blocked": "The control does not prevent this claim", "insufficient_evidence": "Coverage or semantics cannot establish prevention"})
	response, err := d.recorder.Evaluate(ctx, "audit", mode, subject+":blocking-validation", map[string]any{"claim": claim, "proposed_blocking_span": block, "source": evidence, "supplementary_context": d.supplementary, "custom_requirements": d.requirements, "production_only": d.productionOnly}, map[string]decision.Question{"blocking_validation": q}, evidence, true)
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
