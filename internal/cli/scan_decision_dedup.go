package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/block/codecrucible/internal/decision"
	"github.com/block/codecrucible/internal/sarif"
)

// deduplicateFindings compares each duplicate directly with an unchanged
// representative. A=B and B=C never authorizes A=C. The original records remain
// available in SARIF even when active mode consolidates their display entries.
func (d *scanDecisions) deduplicateFindings(ctx context.Context, doc sarif.SARIFDocument) (sarif.SARIFDocument, error) {
	if !d.enabled("deduplication") {
		return doc, nil
	}
	mode := d.cfg.Deduplication
	out := sarif.WithFindingIDs(doc)
	limit := min(128, decisionStageLimits(d.cfg)["deduplication"])
	pairs, total, merged := 0, 0, 0
	for ri := range out.Runs {
		run := &out.Runs[ri]
		rules := map[string]sarif.SARIFRule{}
		for _, r := range run.Tool.Driver.Rules {
			rules[r.ID] = r
		}
		total += len(run.Results)
		order := make([]int, len(run.Results))
		for i := range order {
			order[i] = i
		}
		severity := func(i int) float64 {
			s, _ := strconv.ParseFloat(fmt.Sprint(rules[run.Results[i].RuleID].Properties["security-severity"]), 64)
			return s
		}
		sort.SliceStable(order, func(i, j int) bool {
			if severity(order[i]) != severity(order[j]) {
				return severity(order[i]) > severity(order[j])
			}
			return decisionSubject(run.Results[order[i]]) < decisionSubject(run.Results[order[j]])
		})
		selections := map[int]decision.EvidenceSelection{}
		claims := map[int]string{}
		byScope := map[string][]int{}
		for _, i := range order {
			if err := ctx.Err(); err != nil {
				return doc, err
			}
			r := run.Results[i]
			s := d.citedEvidence(r, 7500)
			claim := decisionClaim(r, rules[r.RuleID].ShortDescription.Text)
			reason := ""
			switch {
			case !s.Complete():
				reason = "incomplete_cited_scopes"
			case len(claim) > 4500:
				reason = "claim_exceeds_budget"
			case len(r.Properties.Deduplicated) > 0:
				reason = "already_consolidated"
			}
			if reason != "" {
				d.recorder.Skip("deduplication", mode, reason)
				d.recorder.FindingCoverage(decisionSubject(r), s)
				d.recorder.Records[len(d.recorder.Records)-1].CoverageScope = "cited_declarations"
				d.recorder.Action("retain")
				d.recorder.Outcome("findings_skipped", 1)
				continue
			}
			selections[i], claims[i] = s, claim
			for _, e := range s.Evidence {
				byScope[e.ID] = append(byScope[e.ID], i)
			}
		}
		removed := map[int]bool{}
		attachments := map[int][]sarif.DeduplicatedFinding{}
		rank := map[int]int{}
		for pos, i := range order {
			rank[i] = pos
		}
		for _, left := range order {
			if removed[left] {
				continue
			}
			candidates := map[int]bool{}
			for _, e := range selections[left].Evidence {
				for _, right := range byScope[e.ID] {
					if rank[right] > rank[left] && !removed[right] {
						candidates[right] = true
					}
				}
			}
			var rights []int
			for right := range candidates {
				rights = append(rights, right)
			}
			sort.Slice(rights, func(i, j int) bool { return rank[rights[i]] < rank[rights[j]] })
			for _, right := range rights {
				if pairs >= limit {
					break
				}
				if err := ctx.Err(); err != nil {
					return doc, err
				}
				l, r := run.Results[left], run.Results[right]
				anchors := map[string]string{"none": "No shared source scope establishes a single root cause covering both entire findings"}
				evidence := append([]decision.Evidence(nil), selections[left].Evidence...)
				seen := map[string]bool{}
				for _, e := range evidence {
					seen[e.ID] = true
				}
				for _, e := range selections[right].Evidence {
					if seen[e.ID] {
						anchors[e.ID] = fmt.Sprintf("%s:%d-%d", e.Path, e.Start, e.End)
					} else {
						evidence = append(evidence, e)
					}
				}
				q := decision.Choice("Do these two complete findings describe the SAME concrete root cause at the SAME source operation, so one specific fix resolves both in full? Different vulnerable operations, independent checks, attacker capabilities, or combined additional weaknesses mean distinct, even within one function or with the same CWE. Different caller locations qualify only when source establishes the same shared defective operation. Similar prose, a shared helper name, or a common weakness category is insufficient. Do not judge validity or discard an uncertain finding.", map[string]string{"duplicate": "One identical source-backed root cause and specific fix cover both findings in full", "distinct": "The findings describe distinct operations, root causes, or additional weaknesses", "insufficient_evidence": "The supplied source cannot establish identity of the complete root cause"})
				anchor := decision.Choice("Which shared source scope establishes the single defective operation underlying BOTH findings? Select none unless its actual source establishes this, rather than merely containing both operations.", anchors)
				state := map[string]any{"left": map[string]any{"id": decisionSubject(l), "finding": claims[left], "locations": l.Locations}, "right": map[string]any{"id": decisionSubject(r), "finding": claims[right], "locations": r.Locations}, "source": evidence, "coverage_scope": "cited declarations only; omitted behavior must not be inferred", "custom_requirements": d.requirements}
				response, err := d.recorder.Evaluate(ctx, "deduplication", mode, decision.Digest(decisionSubject(l)+":"+decisionSubject(r)), state, map[string]decision.Question{"relationship": q, "shared_root": anchor}, evidence, true)
				pairs++
				if ctx.Err() != nil {
					return doc, ctx.Err()
				}
				record := &d.recorder.Records[len(d.recorder.Records)-1]
				record.FindingIDs = []string{decisionSubject(l), decisionSubject(r)}
				record.CoverageScope = "cited_declarations"
				d.recorder.Outcome("pairs_evaluated", 1)
				root := response.Answers["shared_root"]
				_, known := anchors[root.Choice]
				if err == nil && decision.Strong(response.Answers["relationship"], "duplicate") && known && root.Choice != "none" && decision.Strong(root, root.Choice) {
					removed[right] = true
					merged++
					action := "proposed_merge"
					if mode == "active" {
						action = "merged"
						attachments[left] = append(attachments[left], sarif.DeduplicatedFinding{Result: r, Rule: rules[r.RuleID], Model: response.Model, Policy: decision.PolicyVersion, EvidenceIDs: evidenceIDs(evidence)})
					}
					d.recorder.Action(action)
					d.recorder.Outcome(action, 1)
				} else {
					d.recorder.Action("retain")
					d.recorder.Outcome("pairs_retained", 1)
				}
			}
		}
		if mode == "active" {
			kept := make([]sarif.SARIFResult, 0, len(run.Results))
			for i, r := range run.Results {
				if removed[i] {
					continue
				}
				if duplicates := attachments[i]; len(duplicates) > 0 {
					r.Properties.Deduplicated = append([]sarif.DeduplicatedFinding(nil), duplicates...)
					for _, duplicate := range duplicates {
						r.Locations = unionJSON(r.Locations, duplicate.Result.Locations)
						r.CodeFlows = unionJSON(r.CodeFlows, duplicate.Result.CodeFlows)
					}
				}
				kept = append(kept, r)
			}
			run.Results = kept
			used := map[string]bool{}
			for _, r := range kept {
				used[r.RuleID] = true
			}
			keptRules := make([]sarif.SARIFRule, 0, len(run.Tool.Driver.Rules))
			for _, rule := range run.Tool.Driver.Rules {
				if used[rule.ID] {
					keptRules = append(keptRules, rule)
				}
			}
			run.Tool.Driver.Rules = keptRules
		}
	}
	counts := map[string]int{"input_findings": total, "output_findings": total}
	if mode == "active" {
		counts["output_findings"] -= merged
	}
	d.recorder.Records = append(d.recorder.Records, decision.Record{Stage: "deduplication", Mode: mode, Policy: decision.PolicyVersion, Status: "completed", Action: "summary", Outcomes: counts})
	if pairs >= limit {
		d.recorder.Records[len(d.recorder.Records)-1].Fallback = "pair_limit_remaining_findings_retained"
	}
	if mode == "shadow" {
		return doc, nil
	}
	return out, nil
}

func unionJSON[T any](left, right []T) []T {
	out := append([]T(nil), left...)
	seen := map[string]bool{}
	for _, item := range out {
		data, _ := json.Marshal(item)
		seen[string(data)] = true
	}
	for _, item := range right {
		data, _ := json.Marshal(item)
		if !seen[string(data)] {
			out = append(out, item)
			seen[string(data)] = true
		}
	}
	return out
}
