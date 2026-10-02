package cli

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/decision"
	"github.com/block/codecrucible/internal/sarif"
	"github.com/block/codecrucible/internal/usage"
)

type phaseArtifactWriter struct {
	paths    map[string]string
	metadata *sarif.ScanMetadata
}

type featureDetectionArtifact struct {
	Phase               string                        `json:"phase"`
	Status              string                        `json:"status"`
	Repo                string                        `json:"repo,omitempty"`
	Provider            string                        `json:"provider,omitempty"`
	Model               string                        `json:"model,omitempty"`
	DetectedFeatures    []string                      `json:"detected_features"`
	RetainedFeatures    []string                      `json:"retained_features,omitempty"`
	FeatureObservations []decision.FeatureObservation `json:"feature_observations,omitempty"`
	TokenCorrection     float64                       `json:"token_correction,omitempty"`
	Reason              string                        `json:"reason,omitempty"`
	Error               string                        `json:"error,omitempty"`
	Fallback            string                        `json:"fallback,omitempty"`
}

func newPhaseArtifactWriter(cfg *config.Config) phaseArtifactWriter {
	if strings.TrimSpace(cfg.PhaseOutputDir) != "" {
		dir := cfg.PhaseOutputDir
		return phaseArtifactWriter{paths: map[string]string{
			"feature-detection": filepath.Join(dir, "feature-detection.json"),
			"analysis":          filepath.Join(dir, "analysis.sarif"),
			"audit":             filepath.Join(dir, "audit.sarif"),
			"usage":             filepath.Join(dir, "usage.json"),
			"decisions":         filepath.Join(dir, "decisions.json"),
			"review":            filepath.Join(dir, "review.sarif"),
			"cwe-mapping":       filepath.Join(dir, "cwe-mapping.sarif"),
			"deduplication":     filepath.Join(dir, "deduplication.sarif"),
		}}
	}

	if !canDerivePhaseArtifactSidecars(cfg.Output) {
		return phaseArtifactWriter{}
	}

	dir := filepath.Dir(cfg.Output)
	base := filepath.Base(cfg.Output)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	if stem == "" {
		stem = base
	}

	return phaseArtifactWriter{paths: map[string]string{
		"feature-detection": filepath.Join(dir, stem+".feature-detection.json"),
		"analysis":          filepath.Join(dir, stem+".analysis.sarif"),
		"audit":             filepath.Join(dir, stem+".audit.sarif"),
		"usage":             filepath.Join(dir, stem+".usage.json"),
		"decisions":         filepath.Join(dir, stem+".decisions.json"),
		"review":            filepath.Join(dir, stem+".review.sarif"),
		"cwe-mapping":       filepath.Join(dir, stem+".cwe-mapping.sarif"),
		"deduplication":     filepath.Join(dir, stem+".deduplication.sarif"),
	}}
}

func canDerivePhaseArtifactSidecars(output string) bool {
	output = strings.TrimSpace(output)
	if output == "" || output == "-" {
		return false
	}
	clean := filepath.Clean(output)
	return clean != "/dev/stdout" && clean != "/dev/stderr"
}

func (w phaseArtifactWriter) Enabled() bool {
	return len(w.paths) > 0
}

func (w phaseArtifactWriter) Path(phase string) string {
	return w.paths[phase]
}

func (w phaseArtifactWriter) WriteFeatureDetection(artifact featureDetectionArtifact) error {
	return w.writeJSON("feature-detection", artifact)
}

func (w phaseArtifactWriter) WriteSARIF(phase string, doc sarif.SARIFDocument) error {
	var err error
	doc, err = prepareSARIF(doc, w.metadata, phase)
	if err != nil {
		return err
	}
	return w.writeJSON(phase, doc)
}

func (w phaseArtifactWriter) writeJSON(phase string, value any) error {
	path := w.Path(phase)
	if path == "" {
		return nil
	}

	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s artifact: %w", phase, err)
	}
	data = append(data, '\n')
	if err := writeArtifactFile(path, data); err != nil {
		return err
	}
	slog.Info("phase artifact written", "phase", phase, "path", path)
	return nil
}

func writeArtifactFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating artifact directory %q: %w", dir, err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("writing artifact file %q: %w", path, err)
	}
	return nil
}

func (w phaseArtifactWriter) WriteUsage(report usage.Report) error {
	return w.writeJSON("usage", report)
}

func (w phaseArtifactWriter) WriteDecisions(report decision.Report) error {
	return w.writeJSON("decisions", report)
}
