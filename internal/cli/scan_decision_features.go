package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/block/codecrucible/internal/decision"
	"github.com/block/codecrucible/internal/llm"
)

func (d *scanDecisions) featureDetection(ctx context.Context, loader *llm.PromptLoader) ([]string, bool, error) {
	if !d.enabled("feature-detection") {
		return nil, false, nil
	}
	mode := d.cfg.FeatureDetection
	sections, err := loader.LoadAnalysisSections()
	if err != nil {
		return nil, false, err
	}
	descriptions := map[string][]string{}
	for _, section := range sections.Sections {
		for _, feature := range section.Features {
			descriptions[feature] = append(descriptions[feature], section.Title)
		}
	}
	if len(descriptions) == 0 {
		d.recorder.Skip("feature-detection", mode, "no_conditional_sections")
		return nil, false, nil
	}
	names := make([]string, 0, len(descriptions))
	for name := range descriptions {
		names = append(names, name)
		sort.Strings(descriptions[name])
	}
	sort.Strings(names)
	batches, covered := decision.FeatureEvidenceBatches(d.files, 18000)
	present, absent := map[string]bool{}, map[string]bool{}
	for _, name := range names {
		absent[name] = covered
	}
	completed, attempted, observed := 0, 0, 0
	model := ""
	for index, evidence := range batches {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		questions := map[string]decision.Question{}
		for i, name := range names {
			if present[name] {
				continue // One positive observation already requires retention.
			}
			description := name + " (" + strings.Join(descriptions[name], ", ") + ")"
			questions[fmt.Sprintf("feature_%d", i)] = decision.Choice("Does the supplied source batch contain use of security-relevant feature "+description+"? Answer only about these source ranges, not the entire repository. Select absent only when all supplied ranges clearly lack relevant use. If split declarations, unresolved calls, framework behavior, or missing context could conceal use, select insufficient_evidence. A missing keyword is not proof of absence.", map[string]string{"present": "Source shows relevant feature use", "absent": "All supplied source ranges clearly lack this feature", "insufficient_evidence": "Source context or feature use is uncertain"})
			questions[fmt.Sprintf("feature_%d_signal", i)] = decision.Noul("Does the supplied source contain executable use of feature " + description + "? This concerns positive evidence in these ranges only. A dependency name or comment alone is insufficient.")
		}
		if len(questions) == 0 {
			break
		}
		slog.Info("running Jev feature batch", "batch", index+1, "total_batches", len(batches), "features", len(questions)/2)
		response, callErr := d.recorder.Evaluate(ctx, "feature-detection", mode, fmt.Sprintf("source_batch_%d", index+1), map[string]any{"source": evidence, "scope": "supplied_source_ranges", "batch": index + 1, "total_batches": len(batches)}, questions, evidence, true)
		attempted++
		record := &d.recorder.Records[len(d.recorder.Records)-1]
		record.CoverageScope = "source_batch"
		d.recorder.Action("observe_features")
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		if callErr == nil {
			completed++
			model = response.Model
		}
		for i, name := range names {
			if present[name] {
				continue
			}
			choice := response.Answers[fmt.Sprintf("feature_%d", i)]
			positive := callErr == nil && (decision.StrongYes(response.Answers[fmt.Sprintf("feature_%d_signal", i)]) || decision.Strong(choice, "present"))
			omittable := callErr == nil && !positive && decision.Strong(choice, "absent")
			present[name] = positive
			absent[name] = absent[name] && omittable
			status := "unknown"
			if positive {
				observed++
				status = "observed_present"
			} else if omittable {
				status = "absent"
			} else if callErr != nil {
				status = "unavailable"
			}
			record.Features = append(record.Features, decision.FeatureObservation{Name: name, Status: status, Retained: !omittable})
		}
		if errors.Is(callErr, decision.ErrLimit) {
			break // Remaining source stays unknown; avoid repeated rejected calls.
		}
	}
	complete := covered && completed == len(batches)
	summary := decision.Record{Stage: "feature-detection", Mode: mode, Subject: "repository", Policy: decision.PolicyVersion, Status: "completed", Model: model, Complete: complete, CoverageScope: "scanned_source"}
	retained := []string{}
	for _, name := range names {
		omit := complete && absent[name] && !present[name]
		status := "unknown"
		if present[name] {
			status = "observed_present"
		} else if omit {
			status = "absent"
		}
		summary.Features = append(summary.Features, decision.FeatureObservation{Name: name, Status: status, Retained: !omit})
		if !omit {
			retained = append(retained, name)
		}
	}
	// Preserve the existing empty-list contract: no names means all sections.
	if len(retained) == 0 {
		retained = names
		for i := range summary.Features {
			summary.Features[i].Retained = true
		}
	}
	if !complete && observed < len(names) {
		summary.Status = "fallback"
		summary.Fallback = "incomplete_source_batches"
	}
	d.recorder.Records = append(d.recorder.Records, summary)
	d.recorder.Outcome("source_batches_total", len(batches))
	d.recorder.Outcome("source_batches_attempted", attempted)
	d.recorder.Outcome("source_batches_completed", completed)
	d.recorder.Outcome("categories_observed", observed)
	prefix := ""
	if mode == "shadow" {
		prefix = "proposed_"
	}
	d.recorder.Outcome(prefix+"categories_retained", len(retained))
	d.recorder.Outcome(prefix+"categories_omitted", len(names)-len(retained))
	if mode == "shadow" {
		d.recorder.Action("existing_feature_detection")
		return nil, false, nil
	}
	d.recorder.Action("conservative_feature_selection")
	return retained, true, nil
}
