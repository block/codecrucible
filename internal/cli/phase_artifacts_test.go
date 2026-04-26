package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/sarif"
)

func TestPhaseArtifactWriter_DerivesSidecarPathsFromOutput(t *testing.T) {
	dir := t.TempDir()
	w := newPhaseArtifactWriter(&config.Config{
		Output: filepath.Join(dir, "results.sarif"),
	})

	if !w.Enabled() {
		t.Fatal("writer should be enabled when --output is a file")
	}

	tests := map[string]string{
		"feature-detection": filepath.Join(dir, "results.feature-detection.json"),
		"analysis":          filepath.Join(dir, "results.analysis.sarif"),
		"audit":             filepath.Join(dir, "results.audit.sarif"),
	}
	for phase, want := range tests {
		if got := w.Path(phase); got != want {
			t.Errorf("Path(%q) = %q, want %q", phase, got, want)
		}
	}
}

func TestPhaseArtifactWriter_UsesExplicitDirectoryForStdoutOutput(t *testing.T) {
	dir := t.TempDir()
	w := newPhaseArtifactWriter(&config.Config{
		Output:         "/dev/stdout",
		PhaseOutputDir: dir,
	})

	if !w.Enabled() {
		t.Fatal("writer should be enabled when --phase-output-dir is set")
	}
	if got, want := w.Path("analysis"), filepath.Join(dir, "analysis.sarif"); got != want {
		t.Fatalf("analysis path = %q, want %q", got, want)
	}
}

func TestPhaseArtifactWriter_DisabledForStdoutWithoutDirectory(t *testing.T) {
	for _, output := range []string{"", "-", "/dev/stdout", "/dev/stderr"} {
		t.Run(output, func(t *testing.T) {
			w := newPhaseArtifactWriter(&config.Config{Output: output})
			if w.Enabled() {
				t.Fatalf("writer should be disabled for output %q", output)
			}
		})
	}
}

func TestPhaseArtifactWriter_WritesArtifacts(t *testing.T) {
	dir := t.TempDir()
	w := newPhaseArtifactWriter(&config.Config{PhaseOutputDir: dir})

	if err := w.WriteFeatureDetection(featureDetectionArtifact{
		Phase:            "feature-detection",
		Status:           "completed",
		Repo:             "repo",
		Provider:         "openai",
		Model:            "gpt-5.5",
		DetectedFeatures: []string{"web"},
		TokenCorrection:  1.25,
	}); err != nil {
		t.Fatalf("WriteFeatureDetection: %v", err)
	}
	if err := w.WriteSARIF("analysis", sarif.SARIFDocument{
		Version: "2.1.0",
		Runs:    []sarif.SARIFRun{{Results: []sarif.SARIFResult{}}},
	}); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	fdData, err := os.ReadFile(filepath.Join(dir, "feature-detection.json"))
	if err != nil {
		t.Fatalf("read feature artifact: %v", err)
	}
	var fd map[string]any
	if err := json.Unmarshal(fdData, &fd); err != nil {
		t.Fatalf("feature artifact is not JSON: %v", err)
	}
	if fd["status"] != "completed" {
		t.Fatalf("feature status = %v, want completed", fd["status"])
	}

	sarifData, err := os.ReadFile(filepath.Join(dir, "analysis.sarif"))
	if err != nil {
		t.Fatalf("read analysis artifact: %v", err)
	}
	var doc sarif.SARIFDocument
	if err := json.Unmarshal(sarifData, &doc); err != nil {
		t.Fatalf("analysis artifact is not SARIF JSON: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Fatalf("analysis SARIF version = %q, want 2.1.0", doc.Version)
	}
}
