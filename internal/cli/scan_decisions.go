package cli

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/decision"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/llm"
	"github.com/block/codecrucible/internal/sarif"
)

type scanDecisions struct {
	evidenceIndex        *decision.EvidenceIndex
	auditPolicySupported bool
	supplementary        string
	requirements         string
	productionOnly       bool
	cfg                  config.Decisions
	recorder             *decision.Recorder
	files                map[string]string
	graph                map[string][]string
	groupingBaseline     map[string][]string
}

func newScanDecisions(cfg config.Decisions, files ingest.FileMap, sources []ingest.SourceFile) (*scanDecisions, error) {
	if !cfg.AnyEnabled() && !cfg.DependencyGrouping {
		return nil, nil
	}
	var client decision.Evaluator
	if cfg.AnyEnabled() {
		var err error
		client, err = decision.New(decision.Options{URL: cfg.URL, APIKey: cfg.APIKey, Model: cfg.Model, Timeout: time.Duration(cfg.Timeout) * time.Second, MaxCalls: cfg.MaxCalls, Retries: cfg.Retries, InputPrice: cfg.InputPrice, StageLimits: decisionStageLimits(cfg)})
		if err != nil {
			return nil, err
		}
	}
	graph := ingest.ResolveDependencies(sources)
	var index *decision.EvidenceIndex
	if cfg.Audit != "off" || cfg.Review != "off" {
		index = decision.NewEvidenceIndex(map[string]string(files), graph)
	}
	return &scanDecisions{evidenceIndex: index, cfg: cfg, recorder: &decision.Recorder{Client: client}, files: map[string]string(files), graph: graph}, nil
}

func decisionStageLimits(cfg config.Decisions) map[string]int {
	stages := []string{}
	for _, stage := range []string{"feature-detection", "smart-chunking", "audit", "review", "cwe-mapping", "deduplication"} {
		if mode := cfg.Modes()[stage]; mode == "active" || mode == "shadow" {
			stages = append(stages, stage)
		}
	}
	limits := map[string]int{}
	for i, stage := range stages {
		limits[stage] = cfg.MaxCalls / len(stages)
		if i < cfg.MaxCalls%len(stages) {
			limits[stage]++
		}
	}
	return limits
}
func (d *scanDecisions) enabled(stage string) bool {
	if d == nil {
		return false
	}
	mode := d.cfg.Modes()[stage]
	return mode == "active" || mode == "shadow"
}
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
	for _, s := range sections.Sections {
		for _, f := range s.Features {
			descriptions[f] = append(descriptions[f], s.Title)
		}
	}
	if len(descriptions) == 0 {
		d.recorder.Skip("feature-detection", mode, "no_conditional_sections")
		return nil, false, nil
	}
	paths := make([]string, 0, len(d.files))
	for p := range d.files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	evidence, complete := decision.CollectEvidence(d.files, paths, 18000)
	// Bound the manifest too; incomplete coverage never justifies absence.
	manifest := append([]string{}, paths...)
	if len(strings.Join(manifest, "\n")) > 4000 {
		manifest = nil
		complete = false
	}
	names := make([]string, 0, len(descriptions))
	for f := range descriptions {
		names = append(names, f)
	}
	sort.Strings(names)
	// In active mode incomplete coverage cannot omit a single category. Avoid
	// paying for answers that cannot change this outcome; shadow can measure them.
	if !complete && mode == "active" {
		d.recorder.Skip("feature-detection", mode, "incomplete_coverage_all_sections")
		d.recorder.Action("all_sections")
		for _, name := range names {
			d.recorder.Records[len(d.recorder.Records)-1].Features = append(d.recorder.Records[len(d.recorder.Records)-1].Features, decision.FeatureObservation{Name: name, Status: "unknown", Retained: true})
		}
		d.recorder.Outcome("categories_retained", len(names))
		d.recorder.Outcome("categories_omitted", 0)
		return names, true, nil
	}
	questions := map[string]decision.Question{}
	for i, f := range names {
		sort.Strings(descriptions[f])
		questions[fmt.Sprintf("feature_%d", i)] = decision.Choice("Does the scanned source use feature "+f+"? Associated analysis sections: "+strings.Join(descriptions[f], ", ")+". An absence decision requires complete supplied source coverage; missing a signal in a sample is insufficient evidence.", map[string]string{"present": "Positive source evidence of this feature", "absent": "The complete scanned source establishes this feature is unused", "insufficient_evidence": "Coverage or behavior is uncertain"})
		questions[fmt.Sprintf("feature_%d_signal", i)] = decision.Noul("Does `source` contain executable use of feature " + f + "? Interpret the feature using these analysis section descriptions: " + strings.Join(descriptions[f], ", ") + ". A dependency name or a comment alone is not executable use. This question concerns positive evidence in the supplied source only.")
	}
	response, err := d.recorder.Evaluate(ctx, "feature-detection", mode, "repository", map[string]any{"manifest": manifest, "source": evidence, "coverage_complete": complete}, questions, evidence, complete)
	if ctx.Err() != nil {
		return nil, false, ctx.Err()
	}
	if err != nil {
		if mode == "shadow" {
			d.recorder.Action("existing_feature_detection")
			return nil, false, nil
		}
		d.recorder.Action("all_sections")
		slog.Warn("Jev feature detection unavailable; using all sections")
		for _, name := range names {
			d.recorder.Records[len(d.recorder.Records)-1].Features = append(d.recorder.Records[len(d.recorder.Records)-1].Features, decision.FeatureObservation{Name: name, Status: "unavailable", Retained: true})
		}
		d.recorder.Outcome("categories_retained", len(names))
		d.recorder.Outcome("categories_omitted", 0)
		return names, true, nil
	}
	retained := []string{}
	for i, f := range names {
		positive := decision.StrongYes(response.Answers[fmt.Sprintf("feature_%d_signal", i)])
		omit := complete && !positive && decision.Strong(response.Answers[fmt.Sprintf("feature_%d", i)], "absent")
		status := "unknown"
		if positive {
			status = "observed_present"
		} else if omit {
			status = "absent"
		}
		d.recorder.Records[len(d.recorder.Records)-1].Features = append(d.recorder.Records[len(d.recorder.Records)-1].Features, decision.FeatureObservation{Name: f, Status: status, Retained: !omit})
		if !omit {
			retained = append(retained, f)
		}
	}
	// Empty feature lists mean all sections in the existing prompt contract.
	if len(retained) == 0 {
		retained = names
		for i := range d.recorder.Records[len(d.recorder.Records)-1].Features {
			d.recorder.Records[len(d.recorder.Records)-1].Features[i].Retained = true
		}
	}
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
	// Empty retains the historical all-sections convention, including custom prompts.
	d.recorder.Action("conservative_feature_selection")
	return retained, true, nil
}

func (d *scanDecisions) findingEvidence(result sarif.SARIFResult) decision.EvidenceSelection {
	cited := []decision.SourceRange{}
	add := func(location sarif.SARIFLocation) {
		physical := location.PhysicalLocation
		span := decision.SourceRange{Path: physical.ArtifactLocation.URI}
		if physical.Region != nil {
			span.Start = physical.Region.StartLine
			span.End = physical.Region.EndLine
		}
		cited = append(cited, span)
	}
	for _, location := range result.Locations {
		add(location)
	}
	for _, flow := range result.CodeFlows {
		for _, thread := range flow.ThreadFlows {
			for _, step := range thread.Locations {
				add(step.Location)
			}
		}
	}
	index := d.evidenceIndex
	if index == nil {
		index = decision.NewEvidenceIndex(d.files, d.graph)
	}
	return index.Select(cited, 18000)
}
func decisionSubject(result sarif.SARIFResult) string {
	if result.Properties != nil && result.Properties.FindingID != "" {
		return result.Properties.FindingID
	}
	location := ""
	if len(result.Locations) > 0 {
		p := result.Locations[0].PhysicalLocation
		location = p.ArtifactLocation.URI
		if p.Region != nil {
			location += fmt.Sprintf(":%d", p.Region.StartLine)
		}
	}
	return decision.Digest(result.RuleID + "\n" + location)
}
func decisionClaim(result sarif.SARIFResult, title string) string {
	details := result.Message.Text
	if result.Properties != nil && result.Properties.TechnicalDetails != "" {
		details = result.Properties.TechnicalDetails
	}
	return title + "\n" + details
}

func (d *scanDecisions) recordPhase(m *sarif.ScanMetadata, phase string) {
	recordDecisionPhase(m, phase, d.cfg)
	state := m.Execution.Phases[phase]
	for _, r := range d.recorder.Records {
		if r.Stage != phase {
			continue
		}
		if r.Model != "" {
			state.Actual.Model = r.Model
		}
		if r.Status == "fallback" {
			state.Status = "failed"
			state.Reason = "decision unavailable; conservative fallback"
			state.Fallback = "all_sections"
		}
		if r.Status == "skipped" {
			state.Status = "skipped"
			state.Reason = r.Fallback
			state.Fallback = "all_sections"
			state.Actual = nil
		}
	}
	m.Execution.Phases[phase] = state
}

func (d *scanDecisions) featureObservations() []decision.FeatureObservation {
	for _, record := range d.recorder.Records {
		if record.Stage == "feature-detection" {
			return record.Features
		}
	}
	return nil
}

func (d *scanDecisions) observedFeatures() []string {
	out := []string{}
	for _, feature := range d.featureObservations() {
		if feature.Status == "observed_present" {
			out = append(out, feature.Name)
		}
	}
	return out
}
