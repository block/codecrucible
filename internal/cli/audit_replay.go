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

// Stages whose findings already carry audit or later decisions. Replaying
// them would audit the auditor's output instead of the analysis claims.
var postAuditStages = map[string]bool{"audit": true, "review": true, "cwe-mapping": true, "deduplication": true}

// loadAuditReplay reads a saved pre-audit SARIF (the analysis phase artifact,
// or the final output of a --skip-audit scan) and restores the internal form
// the audit consumed: presentation moves the analysis evidence from
// message.text to properties.technicalDetails, which is inverted here.
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
		if postAuditStages[meta.Execution.ArtifactStage] || (meta.Execution.ArtifactStage == "final" && auditRan(meta)) {
			return sarif.SARIFDocument{}, nil, fmt.Errorf("--audit-from needs pre-audit findings, but %s is a %q artifact of an audited scan; use the analysis phase artifact", path, meta.Execution.ArtifactStage)
		}
	}
	run.Properties = nil
	run.Results = append([]sarif.SARIFResult(nil), run.Results...)
	for i := range run.Results {
		r := &run.Results[i]
		if r.Properties == nil {
			r.Properties = &sarif.FindingProperties{}
		}
		props := *r.Properties
		if audited(props) {
			return sarif.SARIFDocument{}, nil, fmt.Errorf("--audit-from finding %q already carries audit results; use the analysis phase artifact", props.FindingID)
		}
		if props.TechnicalDetails != "" {
			r.Message.Text = props.TechnicalDetails
			props.TechnicalDetails = ""
		}
		r.Properties = &props
	}
	doc = sarif.WithFindingIDs(doc)
	source.Findings = len(run.Results)
	source.MissingFiles, source.ChangedSnippets = replayDrift(doc, files)
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

func audited(p sarif.FindingProperties) bool {
	return p.AuditStatus != "" || p.AuditConfidence != nil || p.AuditOriginal != nil || p.AuditJustification != "" ||
		len(p.AuditGates) > 0 || len(p.AuditReasons) > 0 || len(p.AuditRevision) > 0 || p.DecisionAudit != nil
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
