package llm

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
)

// ContextLengthError preserves a provider's total request size (input plus
// output reservation) and context limit. It still matches ErrContextLengthExceeded.
// Only known total-size diagnostics populate this type; input-only or unknown
// formats retain the sentinel, so callers cannot mistake input for total size.
type ContextLengthError struct {
	CurrentTokens int
	LimitTokens   int
	OutputTokens  int // Actual wire reservation, including model-params overrides.
}

func (e *ContextLengthError) Error() string {
	return fmt.Sprintf("%v: current=%d limit=%d output_reserve=%d", ErrContextLengthExceeded, e.CurrentTokens, e.LimitTokens, e.OutputTokens)
}

func (e *ContextLengthError) Unwrap() error { return ErrContextLengthExceeded }

var totalContextSize = regexp.MustCompile(`(?i)\bcurrent length is ([0-9]+) while limit is ([0-9]+)\b`)

// Parse the full provider message, before diagnostic truncation. Do not keep
// the message itself: it can contain request content.
func contextLengthError(message string, requestBody []byte) error {
	match := totalContextSize.FindStringSubmatch(message)
	if match == nil {
		return ErrContextLengthExceeded
	}
	current, currentErr := strconv.Atoi(match[1])
	limit, limitErr := strconv.Atoi(match[2])
	if currentErr != nil || limitErr != nil || limit <= 0 || current <= limit {
		return ErrContextLengthExceeded
	}
	var wire struct {
		MaxTokens           int  `json:"max_tokens"`
		MaxCompletionTokens *int `json:"max_completion_tokens"`
	}
	if json.Unmarshal(requestBody, &wire) != nil {
		return ErrContextLengthExceeded
	}
	output := wire.MaxTokens
	if wire.MaxCompletionTokens != nil {
		output = *wire.MaxCompletionTokens
	}
	if output < 0 {
		return ErrContextLengthExceeded
	}
	return &ContextLengthError{CurrentTokens: current, LimitTokens: limit, OutputTokens: output}
}
