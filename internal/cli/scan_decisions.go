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
	auditPolicySupported bool
	supplementary        string
	requirements         string
	productionOnly       bool
	cfg                  config.Decisions
	recorder             *decision.Recorder
	files                map[string]string
	graph                map[string][]string
}

func newScanDecisions(cfg config.Decisions, files ingest.FileMap, sources []ingest.SourceFile) (*scanDecisions, error) {
	if !cfg.AnyEnabled() {
		return nil, nil
	}
	client, err := decision.New(decision.Options{URL: cfg.URL, APIKey: cfg.APIKey, Model: cfg.Model, Timeout: time.Duration(cfg.Timeout) * time.Second, MaxCalls: cfg.MaxCalls, Retries: cfg.Retries, InputPrice: cfg.InputPrice})
	if err != nil {
		return nil, err
	}
	return &scanDecisions{cfg: cfg, recorder: &decision.Recorder{Client: client}, files: map[string]string(files), graph: ingest.ResolveDependencies(sources)}, nil
}
func (d *scanDecisions) enabled(stage string) bool { return d != nil && d.cfg.Modes()[stage] != "off" }
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
	questions := map[string]decision.Question{}
	for i, f := range names {
		sort.Strings(descriptions[f])
		questions[fmt.Sprintf("feature_%d", i)] = decision.Choice("Does the scanned source use feature "+f+"? Associated analysis sections: "+strings.Join(descriptions[f], ", ")+". An absence decision requires complete supplied source coverage; missing a signal in a sample is insufficient evidence.", map[string]string{"present": "Positive source evidence of this feature", "absent": "The complete scanned source establishes this feature is unused", "insufficient_evidence": "Coverage or behavior is uncertain"})
	}
	response, err := d.recorder.Evaluate(ctx, "feature-detection", mode, "repository", map[string]any{"manifest": manifest, "source": evidence, "coverage_complete": complete}, questions, evidence, complete)
	if ctx.Err() != nil {
		return nil, false, ctx.Err()
	}
	if mode == "shadow" {
		d.recorder.Action("existing_feature_detection")
		return nil, false, nil
	}
	if err != nil {
		d.recorder.Action("all_sections")
		slog.Warn("Jev feature detection unavailable; using all sections")
		return nil, true, nil
	}
	retained := []string{}
	for i, f := range names {
		if !complete || !decision.Strong(response.Answers[fmt.Sprintf("feature_%d", i)], "absent") {
			retained = append(retained, f)
		}
	}
	// Empty retains the historical all-sections convention, including custom prompts.
	d.recorder.Action("conservative_feature_selection")
	return retained, true, nil
}

func (d *scanDecisions) findingEvidence(result sarif.SARIFResult) ([]decision.Evidence, bool) {
	paths := []string{}
	valid := true
	add := func(location sarif.SARIFLocation) {
		p := location.PhysicalLocation
		if p.Region == nil {
			valid = false
			return
		}
		end := p.Region.EndLine
		if end == 0 {
			end = p.Region.StartLine
		}
		source, ok := d.files[p.ArtifactLocation.URI]
		_, rangeOK := decision.SourceEvidence(p.ArtifactLocation.URI, source, p.Region.StartLine, end)
		if !ok || !rangeOK {
			valid = false
		}
		paths = append(paths, p.ArtifactLocation.URI)
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
	if len(paths) == 0 {
		valid = false
	}
	// Traverse known local imports, retaining explicit incompleteness when bounded.
	seen := map[string]bool{}
	for i := 0; i < len(paths); i++ {
		p := paths[i]
		if seen[p] {
			continue
		}
		seen[p] = true
		if len(seen) > 32 {
			valid = false
			break
		}
		for _, dep := range d.graph[p] {
			if !seen[dep] {
				paths = append(paths, dep)
			}
		}
	}
	if len(seen) > 32 {
		paths = paths[:min(len(paths), 32)]
	}
	evidence, complete := decision.CollectEvidence(d.files, paths, 18000)
	return evidence, valid && complete
}
func decisionSubject(result sarif.SARIFResult) string {
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
	}
	m.Execution.Phases[phase] = state
}
