package cli

import (
	"log/slog"
	"strings"

	"github.com/block/codecrucible/internal/decision"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/sarif"
)

var exposureStatuses = map[string]bool{"default_on": true, "config_enabled": true, "config_dependent": true, "not_deployed": true, "unknown": true}

// applyDeploymentExposure records each finding's deployment exposure next to
// its verdict. Exposure never changes validity, severity, or confidence; an
// ungrounded not_deployed claim is recorded as unknown, and findings without
// a verdict keep their trace as not_assessed.
func applyDeploymentExposure(doc sarif.SARIFDocument, audit AuditResult, files ingest.FileMap, traces map[string]decision.DeploymentTrace) sarif.SARIFDocument {
	if len(doc.Runs) == 0 {
		return doc
	}
	byID := map[string]*AuditExposure{}
	counts := map[string]int{}
	for _, af := range audit.AuditedFindings {
		counts[af.FindingID]++
		byID[af.FindingID] = af.DeploymentExposure
	}
	doc.Runs = append([]sarif.SARIFRun(nil), doc.Runs...)
	run := &doc.Runs[0]
	run.Results = append([]sarif.SARIFResult(nil), run.Results...)
	tally := map[string]int{}
	for i := range run.Results {
		r := &run.Results[i]
		if r.Properties == nil || r.Properties.FindingID == "" {
			continue
		}
		props := *r.Properties
		id := props.FindingID
		trace, traced := traces[id]
		reported, audited := byID[id]
		if !traced && (!audited || counts[id] != 1) {
			continue
		}
		exposure := &sarif.DeploymentExposure{Status: "unknown"}
		if traced {
			exposure.Trace = &sarif.DeploymentTraceSummary{EntryPointFound: trace.EntryPoint, ConfigKeys: trace.ConfigKeys, Gaps: trace.Gaps}
		}
		switch {
		case !audited || counts[id] != 1:
			exposure.Status = "not_assessed"
		case reported == nil:
			props.AuditReasons = append(props.AuditReasons, "missing_deployment_exposure")
		case !exposureStatuses[reported.Status]:
			props.AuditReasons = append(props.AuditReasons, "invalid_deployment_exposure")
		default:
			exposure.Status = reported.Status
			exposure.EnablingKey = strings.TrimSpace(reported.EnablingKey)
			exposure.Reason = reported.Reason
			if c := reported.Evidence; c != nil {
				exposure.Evidence = &sarif.SourceCitation{Path: c.Path, StartLine: c.Start, EndLine: c.End, Quote: c.Quote}
				exposure.Grounded = groundedCitation(c, files, trace)
			}
			if exposure.Status == "not_deployed" && !exposure.Grounded {
				exposure.Status = "unknown"
				props.AuditReasons = append(props.AuditReasons, "ungrounded_not_deployed")
			}
		}
		props.DeploymentExposure = exposure
		r.Properties = &props
		tally[exposure.Status]++
	}
	if len(tally) > 0 {
		slog.Info("deployment exposure", "default_on", tally["default_on"], "config_enabled", tally["config_enabled"],
			"config_dependent", tally["config_dependent"], "not_deployed", tally["not_deployed"], "unknown", tally["unknown"])
	}
	return doc
}

// groundedCitation reports whether the quote is exactly the cited lines,
// either in scanned source or in deployment files the trace retrieved.
func groundedCitation(c *AuditCitation, files ingest.FileMap, trace decision.DeploymentTrace) bool {
	quote := strings.TrimSpace(c.Quote)
	if quote == "" || c.Start < 1 {
		return false
	}
	end := max(c.End, c.Start)
	if source, ok := files[c.Path]; ok {
		e, valid := decision.SourceEvidence(c.Path, source, c.Start, end)
		return valid && strings.TrimSpace(e.Text) == quote
	}
	for _, s := range trace.Steps {
		if s.Path != c.Path || c.Start < s.Start || end > s.End {
			continue
		}
		lines := strings.Split(s.Text, "\n")
		if end-s.Start < len(lines) && strings.TrimSpace(strings.Join(lines[c.Start-s.Start:end-s.Start+1], "\n")) == quote {
			return true
		}
	}
	return false
}
