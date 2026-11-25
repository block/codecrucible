package cli

import (
	"errors"
	"fmt"

	"github.com/block/codecrucible/internal/sarif"
)

// ErrIncompleteScan is returned after writing partial results when strict
// coverage was requested and declared analysis/audit work could not complete.
var ErrIncompleteScan = errors.New("scan incomplete")

func scanCompletenessError(doc sarif.SARIFDocument, metadata *sarif.ScanMetadata) error {
	if err := scanExecutionError(doc); err != nil {
		return fmt.Errorf("%w: %v", ErrIncompleteScan, err)
	}
	if metadata == nil {
		return nil
	}
	if coverage := metadata.Execution.SourceCoverage; coverage != nil && (coverage.Analyzed < coverage.Admitted || len(coverage.Unanalyzed) > 0 || len(coverage.Unplanned) > 0) {
		return fmt.Errorf("%w: admitted source was not fully analyzed", ErrIncompleteScan)
	}
	for _, phase := range []string{"analysis", "audit"} {
		state := metadata.Execution.Phases[phase]
		if state.Status == "incomplete" || state.Status == "failed" || state.Status == "pending" {
			return fmt.Errorf("%w: %s phase %s", ErrIncompleteScan, phase, state.Status)
		}
	}
	return nil
}
