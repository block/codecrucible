package cli

import (
	"log/slog"

	"github.com/block/codecrucible/internal/chunk"
	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/tokenestimate"
)

// scanTokenCounts keeps token units separate when phases use different models.
type scanTokenCounts struct {
	Analysis int
	Audit    int
}

func newPhaseTokenEstimator(phase config.PhaseConfig) *tokenestimate.Estimator {
	return tokenestimate.New(tokenestimate.Model{
		Provider: phase.Provider,
		Name:     phase.ModelCfg.Name,
		BaseURL:  phase.BaseURL,
		Endpoint: phase.Endpoint,
		Encoding: phase.ModelCfg.Encoding,
	}, slog.Default())
}

func estimateSourceTokens(fm ingest.FileMap, cfg ingest.FlattenConfig, analysis, audit tokenestimate.Counter) scanTokenCounts {
	counts := scanTokenCounts{Analysis: streamingTokenCount(fm, analysis, cfg)}
	if audit != nil {
		counts.Audit = streamingTokenCount(fm, audit, cfg)
	}
	return counts
}

// streamingTokenCount estimates the total token count of the flattened XML by
// iterating FileMap entries one at a time. Each per-file XML string is built,
// counted, and discarded, so peak memory is max(single file XML) rather than
// sum(all file XML). Independent sampling and token boundaries can differ from
// counting the complete concatenated document.
func streamingTokenCount(fm ingest.FileMap, counter tokenestimate.Counter, cfg ingest.FlattenConfig) int {
	paths := make([]string, 0, len(fm))
	for p := range fm {
		paths = append(paths, p)
	}

	// Envelope: header + directory structure + <files></files> wrapper.
	envelope := ingest.EnvelopeXML(paths, cfg)
	total := counter.Count(envelope)

	// Per-file: build XML one at a time, count, discard.
	for _, p := range paths {
		fileXML := chunk.BuildFileXML(p, fm[p])
		total += counter.Count(fileXML)
	}

	return total
}
