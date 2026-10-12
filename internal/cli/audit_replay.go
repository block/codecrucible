package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/sarif"
)

// loadAuditReplay reads a saved pre-audit SARIF (the analysis phase artifact,
// or the final output of a --skip-audit scan) and restores the internal form
// the audit consumed. Presentation moves the analysis evidence from
// message.text to properties.technicalDetails and marks findings not_audited;
// both are inverted here so the replayed audit request matches the original.
// Findings keep their IDs, so replayed verdicts are comparable across runs.
func loadAuditReplay(path string, files ingest.FileMap) (sarif.SARIFDocument, *sarif.AuditReplaySource, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return sarif.SARIFDocument{}, nil, fmt.Errorf("reading --audit-from: %w", err)
	}
	var doc sarif.SARIFDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return sarif.SARIFDocument{}, nil, fmt.Errorf("parsing --audit-from: %w", err)
	}
	if len(doc.Runs) != 1 {
		return sarif.SARIFDocument{}, nil, fmt.Errorf("--audit-from must contain exactly one run, found %d", len(doc.Runs))
	}
	digest := sha256.Sum256(data)
	source := &sarif.AuditReplaySource{SHA256: hex.EncodeToString(digest[:])}
	run := &doc.Runs[0]
	if run.Properties != nil && run.Properties.CodeCrucible != nil {
		meta := run.Properties.CodeCrucible
		source.RecipeFingerprint = meta.RecipeFingerprint
		source.ArtifactStage = meta.Execution.ArtifactStage
		if meta.Execution.ArtifactStage == "audit" || (meta.Execution.ArtifactStage == "final" && auditRan(meta)) {
			return sarif.SARIFDocument{}, nil, fmt.Errorf("--audit-from needs pre-audit findings, but %s is a %q artifact of an audited scan; use the analysis phase artifact", path, meta.Execution.ArtifactStage)
		}
	}
	run.Properties = nil
	run.Results = append([]sarif.SARIFResult(nil), run.Results...)
	for i := range run.Results {
		r := &run.Results[i]
		props := sarif.FindingProperties{}
		if r.Properties != nil {
			props = *r.Properties
		}
		if audited(*r) {
			return sarif.SARIFDocument{}, nil, fmt.Errorf("--audit-from finding %q already carries audit results; use the analysis phase artifact", props.FindingID)
		}
		if props.TechnicalDetails != "" {
			r.Message = sarif.SARIFMessage{Text: props.TechnicalDetails}
		}
		props.Verified = false
		props.AuditStatus = ""
		props.AuditReasons = nil
		r.Properties = &props
	}
	// Repair model paths that missed a directory prefix before the drift check,
	// as Build now does for new findings.
	doc = sarif.AssignFindingIDs(sarif.ResolveLocations(doc, sarif.FileMap(files)))
	source.Findings = len(run.Results)
	source.MissingFiles, source.ChangedSnippets = replayDrift(doc, files)
	if source.Findings > 0 && source.MissingFiles == source.Findings {
		return sarif.SARIFDocument{}, nil, fmt.Errorf("--audit-from: none of the %d findings' files are in the scanned source; scan the same root the analysis used", source.Findings)
	}
	if source.MissingFiles > 0 || source.ChangedSnippets > 0 {
		slog.Warn("replayed findings do not match the current source; audit verdicts are not comparable for these findings",
			"missing_files", source.MissingFiles, "changed_snippets", source.ChangedSnippets)
	}
	return doc, source, nil
}

func auditRan(meta *sarif.ScanMetadata) bool {
	status := meta.Execution.Phases["audit"].Status
	return status != "" && status != "skipped" && status != "pending"
}

// audited reports whether a result carries any audit outcome. not_audited is
// what presentation records on analysis-stage findings, so it does not count.
func audited(r sarif.SARIFResult) bool {
	if len(r.Suppressions) > 0 {
		return true
	}
	if r.Properties == nil {
		return false
	}
	p := r.Properties
	return (p.AuditStatus != "" && p.AuditStatus != "not_audited") || p.AuditConfidence != nil ||
		p.AuditJustification != "" || p.AuditBlockingCode != ""
}

// replayDrift counts findings whose file is no longer scanned and snippets
// that no longer match the source lines they were taken from.
func replayDrift(doc sarif.SARIFDocument, files ingest.FileMap) (missing, changed int) {
	for _, r := range doc.Runs[0].Results {
		if len(r.Locations) == 0 {
			continue
		}
		loc := r.Locations[0].PhysicalLocation
		content, ok := files[loc.ArtifactLocation.URI]
		if !ok {
			missing++
			continue
		}
		region := loc.Region
		if region == nil || region.Snippet == nil || region.StartLine < 1 {
			continue
		}
		lines := strings.Split(content, "\n")
		end := max(region.EndLine, region.StartLine)
		if region.StartLine > len(lines) || strings.Join(lines[region.StartLine-1:min(end, len(lines))], "\n") != region.Snippet.Text {
			changed++
		}
	}
	return missing, changed
}
