package tokenestimate

import "math"

// Calibration is a measured actual/estimated prompt-token ratio. The zero value
// means no measurement is available. It adjusts sizing, not reported usage.
type Calibration struct {
	model Model
	Ratio float64
}

func (e *Estimator) Calibrate(estimated, actual int) Calibration {
	if estimated <= 0 || actual <= 0 {
		return Calibration{}
	}
	return Calibration{model: e.model, Ratio: float64(actual) / float64(estimated)}
}

// Applies reports whether c was measured against this exact model/deployment.
func (e *Estimator) Applies(c Calibration) bool {
	return c.Ratio > 0 && c.model == e.model
}

// ChunkBudget applies only measurements from this exact model/deployment. Only
// shrink, and cap the correction at 2x: framing can dominate a small FD payload.
func (e *Estimator) ChunkBudget(budget int, c Calibration) int {
	if !e.Applies(c) || c.Ratio <= 1 || math.IsNaN(c.Ratio) || math.IsInf(c.Ratio, 0) {
		return budget
	}
	return int(float64(budget) / math.Min(c.Ratio, 2))
}
