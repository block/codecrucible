// Package tokenestimate provides offline token estimates for scan planning and
// context sizing. Estimates include a safety allowance; they are not billed usage.
package tokenestimate

import (
	"log/slog"
	"math"
	"unicode/utf8"

	"github.com/tiktoken-go/tokenizer"
)

// Counter is shared by chunking and supplementary-context packing.
type Counter interface {
	Count(string) int
}

// Model identifies both the tokenizer and the deployment that reports usage.
// A calibration must not cross deployments, even when model names match.
type Model struct {
	Provider string
	Name     string
	BaseURL  string
	Endpoint string
	Encoding string
}

type codec interface {
	Count(string) (int, error)
}

// Estimator uses an embedded vocabulary when supported, otherwise the generic
// content-aware heuristic. It is safe to share between concurrent readers.
type Estimator struct {
	model  Model
	codec  codec
	logger *slog.Logger
}

// New never downloads vocabularies or makes provider requests. Only explicitly
// configured local encodings are used; provider names alone do not identify one.
func New(model Model, logger *slog.Logger) *Estimator {
	if logger == nil {
		logger = slog.Default()
	}
	e := &Estimator{model: model, logger: logger}
	switch model.Encoding {
	case "cl100k_base", "o200k_base":
		e.codec, _ = tokenizer.Get(tokenizer.Encoding(model.Encoding))
	}
	return e
}

// Method describes the configured estimation strategy, including fallback.
func (e *Estimator) Method() string {
	if e.codec == nil {
		return "heuristic"
	}
	return e.model.Encoding + " (sampled)"
}

const sampleWindow = 1024
const fullCountLimit = 3 * sampleWindow

// Count includes a 10% allowance. Larger inputs use three bounded samples
// (start, middle, end), avoiding full-file BPE work on large repositories.
// Even short-input counts exclude provider framing and are only estimates.
func (e *Estimator) Count(text string) int {
	if text == "" {
		return 0
	}
	if e.codec == nil {
		return heuristicCount(text)
	}
	count, err := e.countSampled(text)
	if err != nil {
		e.logger.Debug("tokenizer failed; using heuristic", "encoding", e.model.Encoding, "error", err)
		return heuristicCount(text)
	}
	return int(math.Ceil(count * 1.1))
}

func (e *Estimator) countSampled(text string) (float64, error) {
	if len(text) <= fullCountLimit {
		n, err := e.codec.Count(text)
		return float64(n), err
	}
	var tokens, bytes int
	for _, start := range []int{0, (len(text) - sampleWindow) / 2, len(text) - sampleWindow} {
		end := start + sampleWindow
		// Avoid cutting valid UTF-8 characters at sampling boundaries.
		for start < end && !utf8.RuneStart(text[start]) {
			start++
		}
		for end > start && end < len(text) && !utf8.RuneStart(text[end]) {
			end--
		}
		n, err := e.codec.Count(text[start:end])
		if err != nil {
			return 0, err
		}
		tokens += n
		bytes += end - start
	}
	if bytes == 0 {
		return float64(heuristicCount(text)) / 1.1, nil
	}
	return float64(tokens) * float64(len(text)) / float64(bytes), nil
}
