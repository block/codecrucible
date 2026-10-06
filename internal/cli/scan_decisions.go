package cli

import (
	"fmt"
	"time"

	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/decision"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/sarif"
)

type scanDecisions struct {
	auditEvidence        map[string][]decision.Evidence
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
	// File triage needs one call per admitted file, so it has its own client
	// and does not draw on this shared budget.
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
		if r.Model != "" && state.Actual != nil {
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
	for i := len(d.recorder.Records) - 1; i >= 0; i-- {
		record := d.recorder.Records[i]
		if record.Stage == "feature-detection" && record.Subject == "repository" {
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

func (d *scanDecisions) finishStage(stage string) {
	if d == nil || d.recorder == nil {
		return
	}
	if client, ok := d.recorder.Client.(interface{ CompleteStage(string) }); ok {
		client.CompleteStage(stage)
	}
}
func (d *scanDecisions) auditContext() map[string][]decision.Evidence {
	if d == nil {
		return nil
	}
	return d.auditEvidence
}
