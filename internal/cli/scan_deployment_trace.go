package cli

import (
	"fmt"
	"html"
	"log/slog"
	"strings"

	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/decision"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/sarif"
)

const (
	traceFindingBudget = 6000  // evidence text bytes per finding
	traceBatchBudget   = 30000 // rendered trace bytes per audit request
)

// auditDeploymentTraces walks back from each finding to entry points, the
// guards on the way, and where the repository sets their configuration.
// walked is the unfiltered ingest: deployment files are evidence even where
// the analysis filter excludes them.
func auditDeploymentTraces(cfg *config.Config, doc sarif.SARIFDocument, walked, filtered []ingest.SourceFile, files ingest.FileMap, decisions *scanDecisions) map[string]decision.DeploymentTrace {
	if !cfg.AuditDeploymentTrace || len(doc.Runs) == 0 {
		return nil
	}
	maxSize := cfg.MaxFileSize
	if maxSize <= 0 {
		maxSize = ingest.DefaultMaxFileSize
	}
	deploy := ingest.DeploymentFiles(walked, maxSize)
	var index *decision.EvidenceIndex
	if decisions != nil && decisions.evidenceIndex != nil {
		index = decisions.evidenceIndex
	} else {
		index = decision.NewEvidenceIndex(map[string]string(files), ingest.ResolveDependencies(filtered))
	}
	traces := map[string]decision.DeploymentTrace{}
	reached := 0
	for _, r := range sarif.WithFindingIDs(doc).Runs[0].Results {
		if len(r.Locations) == 0 || r.Properties == nil {
			continue
		}
		loc := r.Locations[0].PhysicalLocation
		span := decision.SourceRange{Path: loc.ArtifactLocation.URI}
		if loc.Region != nil {
			span.Start, span.End = loc.Region.StartLine, loc.Region.EndLine
		}
		trace := index.DeploymentTrace(span, deploy, traceFindingBudget)
		traces[r.Properties.FindingID] = trace
		if trace.EntryPoint {
			reached++
		}
	}
	slog.Info("deployment traces built", "findings", len(traces), "entry_point_found", reached, "deployment_files", len(deploy))
	return traces
}

const deploymentTraceNote = `<deployment_trace_notes>
Each deployment_trace was retrieved deterministically by walking backward from the claim's location: enclosing code, callers, route or framework registration, guards on the path, the configuration those guards read, and where the repository sets it (Dockerfiles, manifests, CI workflows, config defaults). Retrieval is lexical and best effort. A missing step, no_callers_found, or entry_point_not_found is not evidence that the code is unreachable or not deployed: dynamic dispatch, reflection, and other repositories are not traced, and anything in a shipped file (such as a hardcoded secret) ships regardless. config_key_not_set_in_repo means the key's value comes from outside this repository. Steps without text are in files supplied in full above.
</deployment_trace_notes>
`

// renderDeploymentTraces lists each claim's trace after the source files.
// Evidence already shown in full or earlier in the batch is cited by
// location only.
func renderDeploymentTraces(ids []string, traces map[string]decision.DeploymentTrace, fullFiles, seen map[string]bool) string {
	var b strings.Builder
	for _, id := range ids {
		trace, ok := traces[id]
		if !ok {
			continue
		}
		var t strings.Builder
		fmt.Fprintf(&t, "<deployment_trace finding_id=\"%s\" entry_point_found=\"%t\"", html.EscapeString(id), trace.EntryPoint)
		if len(trace.ConfigKeys) > 0 {
			fmt.Fprintf(&t, " config_keys=\"%s\"", html.EscapeString(strings.Join(trace.ConfigKeys, ",")))
		}
		if len(trace.Gaps) > 0 {
			fmt.Fprintf(&t, " gaps=\"%s\"", html.EscapeString(strings.Join(trace.Gaps, ",")))
		}
		t.WriteString(">\n")
		for _, s := range trace.Steps {
			fmt.Fprintf(&t, "%s %s:%d-%d", s.Kind, s.Path, s.Start, s.End)
			if s.Note != "" {
				fmt.Fprintf(&t, " — %s", s.Note)
			}
			t.WriteString("\n")
			if !fullFiles[s.Path] && !seen[s.ID] {
				t.WriteString(s.Text)
				t.WriteString("\n")
			}
		}
		t.WriteString("</deployment_trace>\n")
		if b.Len()+t.Len() > traceBatchBudget {
			fmt.Fprintf(&b, "<deployment_trace finding_id=\"%s\" omitted=\"batch_trace_budget\"/>\n", html.EscapeString(id))
			continue
		}
		for _, s := range trace.Steps {
			seen[s.ID] = true
		}
		b.WriteString(t.String())
	}
	if b.Len() == 0 {
		return ""
	}
	return "\n" + deploymentTraceNote + b.String()
}
