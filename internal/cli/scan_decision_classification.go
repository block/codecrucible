package cli

import (
	"context"
	"encoding/json"

	"github.com/block/codecrucible/internal/cwe"
	"github.com/block/codecrucible/internal/decision"
	"github.com/block/codecrucible/internal/sarif"
)

func (d *scanDecisions) citedEvidence(result sarif.SARIFResult, budget int) decision.EvidenceSelection {
	var cited []decision.SourceRange
	add := func(loc sarif.SARIFLocation) {
		p := loc.PhysicalLocation
		s := decision.SourceRange{Path: p.ArtifactLocation.URI}
		if p.Region != nil {
			s.Start, s.End = p.Region.StartLine, p.Region.EndLine
		}
		cited = append(cited, s)
	}
	for _, loc := range result.Locations {
		add(loc)
	}
	for _, flow := range result.CodeFlows {
		for _, thread := range flow.ThreadFlows {
			for _, step := range thread.Locations {
				add(step.Location)
			}
		}
	}
	if d.evidenceIndex == nil {
		d.evidenceIndex = decision.NewEvidenceIndex(d.files, d.graph)
	}
	return d.evidenceIndex.SelectCited(cited, budget)
}

func (d *scanDecisions) mapCWEs(ctx context.Context, doc sarif.SARIFDocument) (sarif.SARIFDocument, error) {
	if !d.enabled("cwe-mapping") {
		return doc, nil
	}
	mode := d.cfg.CWEMapping
	out := sarif.WithFindingIDs(doc)
	assignments := map[string]sarif.CWEAssignment{}
	for i := range out.Runs {
		run := &out.Runs[i]
		rules := map[string]sarif.SARIFRule{}
		for _, rule := range run.Tool.Driver.Rules {
			rules[rule.ID] = rule
		}
		for j := range run.Results {
			if err := ctx.Err(); err != nil {
				return doc, err
			}
			r := &run.Results[j]
			rule := rules[r.RuleID]
			claim := decisionClaim(*r, rule.ShortDescription.Text)
			selection := d.citedEvidence(*r, 9000)
			assessment := sarif.CWEAssessment{Status: "insufficient_evidence", Original: sarif.CWEForRule(rule), CatalogVersion: cwe.Version(), Policy: decision.PolicyVersion, EvidenceIDs: evidenceIDs(selection.Evidence)}
			options := map[string]string{"none_of_these": "The reported root cause is outside these candidates, or several distinct root causes were combined", "insufficient_evidence": "The source and finding do not establish the distinctions needed to assign a primary CWE"}
			candidateByID := map[string]cwe.Entry{}
			if len(claim) <= 6000 && selection.Complete() {
				budget := 10000
				for _, e := range cwe.Candidates(claim, assessment.Original, 16) {
					definition := e.Name + " (" + e.Abstraction + ", " + e.Mapping + "). " + e.Description + " Mapping notes: " + e.MappingNotes
					encoded, _ := json.Marshal(definition)
					if len(encoded)+len(e.ID)+8 > budget {
						continue
					}
					budget -= len(encoded) + len(e.ID) + 8
					options[e.ID] = definition
					candidateByID[e.ID] = e
					assessment.Candidates = append(assessment.Candidates, e.ID)
				}
			}
			switch {
			case !selection.Complete():
				d.recorder.Skip("cwe-mapping", mode, "incomplete_cited_scopes")
			case len(claim) > 6000:
				d.recorder.Skip("cwe-mapping", mode, "claim_exceeds_budget")
			case len(candidateByID) == 0:
				d.recorder.Skip("cwe-mapping", mode, "no_mapping_candidates")
			default:
				q := decision.Choice("Classify the primary root-cause mechanism described by the finding using the supplied source. Choose the most specific justified definition, respecting its mapping notes. Distinguish a root cause from a consequence. This bounded candidate list may omit the correct CWE: use none_of_these then. Do not force a Base/Variant when its distinguishing condition is unproven. This classification does not validate exploitability or certify the finding.", options)
				state := map[string]any{"finding": claim, "source": selection.Evidence, "coverage_scope": "cited declarations only; callers and deployment are not established", "catalog_version": cwe.Version(), "candidate_coverage": "bounded lexical retrieval, not exhaustive", "custom_requirements": d.requirements, "supplementary_context": d.supplementary}
				response, err := d.recorder.Evaluate(ctx, "cwe-mapping", mode, decisionSubject(*r), state, map[string]decision.Question{"primary_cwe": q}, selection.Evidence, true)
				if ctx.Err() != nil {
					return doc, ctx.Err()
				}
				a := response.Answers["primary_cwe"]
				assessment.Model = response.Model
				if err != nil {
					assessment.Status = "unavailable"
				} else if e, ok := candidateByID[a.Choice]; ok {
					assessment.Proposed, assessment.Probability, assessment.Confidence = e.ID, a.Probabilities[e.ID], a.Confidence
					if decision.Strong(a, e.ID) {
						assessment.Status = "proposed"
						if e.Mapping == "Allowed-with-Review" {
							assessment.Status = "review_required"
						} else if e.ID == assessment.Original {
							assessment.Status = "unchanged"
						} else if mode == "active" {
							assessment.Status, assessment.Applied = "mapped", true
							assignments[r.Properties.FindingID] = sarif.CWEAssignment{ID: e.ID, Source: "jev"}
						}
					}
				} else if a.Choice == "none_of_these" {
					assessment.Status = "outside_candidates"
				}
			}
			d.recorder.FindingCoverage(decisionSubject(*r), selection)
			record := &d.recorder.Records[len(d.recorder.Records)-1]
			record.CoverageScope = "cited_declarations"
			record.FindingIDs, record.Candidates, record.CatalogVersion = []string{r.Properties.FindingID}, assessment.Candidates, cwe.Version()
			d.recorder.Action(assessment.Status)
			d.recorder.Outcome(assessment.Status, 1)
			if mode == "active" {
				r.Properties.DecisionCWE = &assessment
			}
		}
	}
	if mode == "shadow" {
		return doc, nil
	}
	if len(assignments) > 0 {
		out = sarif.ApplyCWEAssignments(out, assignments)
	}
	return out, nil
}

func (d *scanDecisions) recordClassificationPhase(m *sarif.ScanMetadata, phase string) {
	recordDecisionPhase(m, phase, d.cfg)
	state := m.Execution.Phases[phase]
	state.RequestPolicy = "Bounded optional classification; unknown decisions preserve findings and existing labels"
	completed, failed := 0, 0
	for _, r := range d.recorder.Records {
		if r.Stage != phase {
			continue
		}
		if r.Model != "" {
			state.Actual.Model = r.Model
			completed++
		}
		if r.Status == "fallback" {
			failed++
		}
	}
	if failed > 0 {
		state.Status, state.Reason, state.Fallback = "incomplete", "some decisions unavailable", "preserve_findings_and_labels"
	} else if completed == 0 {
		state.Status, state.Reason, state.Actual = "skipped", "no eligible decisions", nil
	}
	m.Execution.Phases[phase] = state
}
