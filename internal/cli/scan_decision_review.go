package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/block/codecrucible/internal/decision"
	"github.com/block/codecrucible/internal/sarif"
)

// Sentences remain verbatim and the full original claim accompanies every check.
// A bounded extract is never allowed to represent a completely verified report.
var assertionBoundary = regexp.MustCompile(`(?:[.!?][ \t]+|\n[ \t]*\n)`)

func reviewAssertions(claim string) ([]string, bool) {
	spans := assertionBoundary.FindAllStringIndex(claim, -1)
	assertions := []string{}
	start := 0
	for _, span := range spans {
		end := span[0]
		if claim[end] != '\n' {
			end++
		}
		if text := strings.TrimSpace(claim[start:end]); text != "" {
			assertions = append(assertions, text)
		}
		start = span[1]
	}
	if text := strings.TrimSpace(claim[start:]); text != "" {
		assertions = append(assertions, text)
	}
	complete := len(assertions) <= 12 && len(assertions) > 0
	if len(assertions) > 12 {
		assertions = assertions[:12]
	}
	return assertions, complete
}

// reviewFindings preserves findings and exposes assertion-level disagreements.
func (d *scanDecisions) reviewFindings(ctx context.Context, doc sarif.SARIFDocument) (sarif.SARIFDocument, error) {
	if !d.enabled("review") {
		return doc, nil
	}
	mode := d.cfg.Review
	outcomePrefix := ""
	if mode == "shadow" {
		outcomePrefix = "proposed_"
	}
	type cachedReview struct {
		subject    string
		assessment sarif.DecisionAssessment
	}
	cache := map[string]cachedReview{}
	doc.Runs = append([]sarif.SARIFRun{}, doc.Runs...)
	for i := range doc.Runs {
		run := &doc.Runs[i]
		run.Results = append([]sarif.SARIFResult{}, run.Results...)
		titles := map[string]string{}
		for _, r := range run.Tool.Driver.Rules {
			titles[r.ID] = r.ShortDescription.Text
		}
		for j := range run.Results {
			if err := ctx.Err(); err != nil {
				return doc, err
			}
			finding := &run.Results[j]
			selection := d.findingEvidence(*finding)
			evidence, complete := selection.Evidence, selection.Complete()
			claim := decisionClaim(*finding, titles[finding.RuleID])
			assertions, assertionsComplete := reviewAssertions(claim)
			assessment := sarif.DecisionAssessment{Status: "insufficient_context", Policy: decision.PolicyVersion, EvidenceIDs: evidenceIDs(evidence)}
			state := map[string]any{"claim": claim, "assertions": assertions, "source": evidence, "coverage_scope": "Claim scopes and incoming callers are shown where available; omitted source and runtime behavior must not be assumed", "supplementary_context": d.supplementary, "custom_requirements": d.requirements, "production_only": d.productionOnly}
			encoded, _ := json.Marshal(state)
			cacheKey := decision.Digest(string(encoded))
			if !complete || len(claim) > 6000 || len(assertions) == 0 {
				reason := "incomplete_source_coverage"
				if len(claim) > 6000 {
					reason = "claim_exceeds_budget"
				}
				if len(assertions) == 0 {
					reason = "missing_claim"
				}
				d.recorder.Skip("review", mode, reason)
			} else if prior, ok := cache[cacheKey]; ok {
				assessment = prior.assessment
				assessment.ReusedFrom = prior.subject
				d.recorder.Skip("review", mode, "unchanged_claim_and_evidence")
				d.recorder.Records[len(d.recorder.Records)-1].ReusedFrom = prior.subject
				d.recorder.Outcome("reused_assessments", 1)
			} else {
				questions := map[string]decision.Question{}
				for k := range assertions {
					id := fmt.Sprintf("assertion_%d", k)
					questions[id] = decision.Choice(fmt.Sprintf("How does executable `source` relate to the factual assertion in `assertions[%d]`? Use `claim` to resolve references without treating its narrative as evidence. Evaluate this assertion only. Select contradicted only when source establishes the opposite. Missing source or prerequisite behavior is insufficient_evidence. Advice or wording with no factual assertion is not_applicable.", k), map[string]string{"supported": "Source establishes this assertion", "contradicted": "Source establishes this assertion is false", "unsupported": "The supplied source does not support this assertion despite the relevant scope being available", "insufficient_evidence": "Required context is missing or semantics remain uncertain", "not_applicable": "This sentence contains no verifiable factual assertion"})
				}
				response, err := d.recorder.Evaluate(ctx, "review", mode, decisionSubject(*finding), state, questions, evidence, complete)
				if ctx.Err() != nil {
					return doc, ctx.Err()
				}
				assessment.Model = response.Model
				assessment.Status = "supported"
				supported := 0
				completeAnswers := true
				for k, assertion := range assertions {
					id := fmt.Sprintf("assertion_%d", k)
					a := response.Answers[id]
					status := "insufficient_context"
					one := decision.Request{Questions: map[string]decision.Question{id: questions[id]}}
					answer := decision.Response{Model: response.Model, Answers: map[string]decision.Answer{id: a}}
					if decision.ValidateResponse(one, answer) != nil {
						completeAnswers = false
						status = "unavailable"
					} else {
						for _, candidate := range []string{"supported", "contradicted", "unsupported", "insufficient_evidence", "not_applicable"} {
							if decision.Strong(a, candidate) {
								status = candidate
								break
							}
						}
						if status == "insufficient_evidence" {
							status = "insufficient_context"
						}
					}
					if status == "supported" {
						supported++
					}
					assessment.Checks = append(assessment.Checks, sarif.DecisionCheck{ID: decision.Digest(assertion), Assertion: assertion, Status: status})
					d.recorder.Outcome(outcomePrefix+"assertions_"+status, 1)
					assessment.Status = mergeReviewStatus(assessment.Status, status)
				}
				if !assertionsComplete || supported == 0 {
					assessment.Status = mergeReviewStatus(assessment.Status, "insufficient_context")
				}
				if err != nil || !completeAnswers {
					assessment.Status = mergeReviewStatus(assessment.Status, "unavailable")
				} else {
					cache[cacheKey] = cachedReview{decisionSubject(*finding), assessment}
				}
			}
			d.recorder.Action(assessment.Status)
			d.recorder.Outcome(outcomePrefix+"findings_"+assessment.Status, 1)
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

func mergeReviewStatus(current, next string) string {
	rank := map[string]int{"not_applicable": 0, "supported": 0, "insufficient_context": 1, "unsupported": 2, "unavailable": 3, "contradicted": 4}
	if rank[next] > rank[current] {
		return next
	}
	return current
}
