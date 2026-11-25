package cli

import (
	"errors"

	"github.com/block/codecrucible/internal/llm"
)

// contextRecoveryBudget converts a provider's total-size diagnosis back into
// local estimated source tokens. Output is a fixed reservation, not part of
// the tokenizer ratio. Prompt/manifest overhead must fit alongside the source.
// Never enlarge the existing fallback budget or add another recovery round.
func contextRecoveryBudget(fallback, sourceTokens, promptOverhead, recoveryOverhead int, err error) int {
	var diagnosis *llm.ContextLengthError
	if !errors.As(err, &diagnosis) || diagnosis.CurrentTokens <= diagnosis.LimitTokens || diagnosis.LimitTokens <= 0 || diagnosis.OutputTokens < 0 {
		return fallback
	}
	available := diagnosis.LimitTokens - diagnosis.OutputTokens
	reportedInput := diagnosis.CurrentTokens - diagnosis.OutputTokens
	if available <= 0 || reportedInput <= 0 {
		return 0 // The unchanged output reservation alone cannot fit.
	}
	// Keep 20% headroom for framing, manifests and token-density differences
	// between children. Use floating point before multiplying to avoid overflow.
	estimatedInput := float64(sourceTokens) + float64(promptOverhead)
	budget := int(estimatedInput*(float64(available)/float64(reportedInput))*0.8) - recoveryOverhead
	return max(0, min(fallback, budget))
}
