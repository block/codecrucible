package cli

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/sarif"
)

type phaseArtifactWriter struct {
	paths map[string]string
}

type featureDetectionArtifact struct {
	Phase            string   `json:"phase"`
	Status           string   `json:"status"`
	Repo             string   `json:"repo,omitempty"`
	Provider         string   `json:"provider,omitempty"`
	Model            string   `json:"model,omitempty"`
	DetectedFeatures []string `json:"detected_features"`
	TokenCorrection  float64  `json:"token_correction,omitempty"`
	Reason           string   `json:"reason,omitempty"`
	Error            string   `json:"error,omitempty"`
	Fallback         string   `json:"fallback,omitempty"`
}

func newPhaseArtifactWriter(cfg *config.Config) phaseArtifactWriter {
	if strings.TrimSpace(cfg.PhaseOutputDir) != "" {
		dir := cfg.PhaseOutputDir
		return phaseArtifactWriter{paths: map[string]string{
			"feature-detection": filepath.Join(dir, "feature-detection.json"),
			"analysis":          filepath.Join(dir, "analysis.sarif"),
			"audit":             filepath.Join(dir, "audit.sarif"),
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
