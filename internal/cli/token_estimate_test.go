package cli

import (
	"math"
	"strings"
	"testing"

	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/ingest"
)

func TestSourceTokenEstimatesUseEachPhaseEncoding(t *testing.T) {
	cfg := &config.Config{Phases: config.Phases{
		Analysis: config.PhaseConfig{Provider: "openai", ModelCfg: config.ModelConfig{Name: "analysis", Encoding: "cl100k_base", InputPricePerM: 2, OutputPricePerM: 8}},
		Audit:    config.PhaseConfig{Provider: "openai", ModelCfg: config.ModelConfig{Name: "audit", Encoding: "o200k_base", InputPricePerM: 1, OutputPricePerM: 4}},
	}}
	fm := ingest.FileMap{"example.go": "// " + strings.Repeat("お誕生日おめでとう", 30)}
	analysis, audit := newPhaseTokenEstimator(cfg.Phases.Analysis), newPhaseTokenEstimator(cfg.Phases.Audit)
	counts := estimateSourceTokens(fm, ingest.FlattenConfig{}, analysis, audit)
	if counts.Analysis <= counts.Audit || counts.Audit <= 0 {
		t.Fatalf("phase encodings not reflected in source counts: %+v", counts)
	}
	cost := estimateScanCost(counts, cfg)
	want := float64(counts.Analysis)*2/1e6 + float64(counts.Audit)/1e6
	if math.Abs(cost.TotalInput-want) > 1e-12 {
		t.Fatalf("cost = %v, want %v", cost.TotalInput, want)
	}
	if cost.checkBudget(want-0.000001) == nil {
		t.Fatal("budget did not use both phase estimates")
	}
	counts = estimateSourceTokens(fm, ingest.FlattenConfig{}, analysis, nil)
	if counts.Audit != 0 {
		t.Fatal("disabled audit was counted")
	}
}

func TestPhaseEstimatorPreservesCalibrationScope(t *testing.T) {
	phase := config.PhaseConfig{Provider: "openai", BaseURL: "https://a", Endpoint: "endpoint", ModelCfg: config.ModelConfig{Name: "model", Encoding: "o200k_base"}}
	calibration := newPhaseTokenEstimator(phase).Calibrate(100, 150)
	if newPhaseTokenEstimator(phase).ChunkBudget(900, calibration) != 600 {
		t.Fatal("same phase lost calibration")
	}
	phase.BaseURL = "https://b"
	if newPhaseTokenEstimator(phase).ChunkBudget(900, calibration) != 900 {
		t.Fatal("reused calibration across deployments")
	}
}
