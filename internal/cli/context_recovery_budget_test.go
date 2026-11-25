package cli

import (
	"fmt"
	"testing"

	"github.com/block/codecrucible/internal/llm"
)

func TestContextRecoveryBudget(t *testing.T) {
	diagnosis := &llm.ContextLengthError{CurrentTokens: 517967, LimitTokens: 256000, OutputTokens: 40960}
	got := contextRecoveryBudget(90000, 140000, 10000, 12000, fmt.Errorf("analysis: %w", diagnosis))
	// Independent check: convert the proposed complete prompt back to provider
	// tokens. Output reservation must still fit with at least 20% input headroom.
	predicted := float64(got+12000) * float64(517967-40960) / 150000
	if got <= 0 || got >= 90000 || predicted > float64(256000-40960)*0.8 {
		t.Fatalf("budget=%d predicted input=%f", got, predicted)
	}
	if fallback := contextRecoveryBudget(90000, 140000, 10000, 12000, llm.ErrContextLengthExceeded); fallback != 90000 {
		t.Fatalf("fallback=%d", fallback)
	}
	if tighter := contextRecoveryBudget(10000, 140000, 10000, 12000, diagnosis); tighter != 10000 {
		t.Fatalf("must not enlarge pooled budget: %d", tighter)
	}
	diagnosis.OutputTokens = diagnosis.LimitTokens
	if impossible := contextRecoveryBudget(90000, 140000, 10000, 12000, diagnosis); impossible != 0 {
		t.Fatalf("impossible output reservation: %d", impossible)
	}
	diagnosis.OutputTokens = 40960
	if impossible := contextRecoveryBudget(90000, 100, 10000, 12000, diagnosis); impossible != 0 {
		t.Fatalf("impossible overhead reservation: %d", impossible)
	}
}
