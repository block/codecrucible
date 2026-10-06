package tokenestimate

import "testing"

func TestCalibrationOnlyAppliesToSameDeployment(t *testing.T) {
	model := Model{Provider: "openai", Name: "model", BaseURL: "https://a", Endpoint: "deployment", Encoding: "o200k_base"}
	e := New(model, nil)
	c := e.Calibrate(100, 150)
	if got := e.ChunkBudget(900, c); got != 600 {
		t.Fatalf("same deployment budget = %d", got)
	}
	for _, field := range []string{"provider", "model", "base_url", "endpoint", "encoding"} {
		different := model
		switch field {
		case "provider":
			different.Provider = "other"
		case "model":
			different.Name = "other"
		case "base_url":
			different.BaseURL = "https://b"
		case "endpoint":
			different.Endpoint = "other"
		case "encoding":
			different.Encoding = "cl100k_base"
		}
		if got := New(different, nil).ChunkBudget(900, c); got != 900 || New(different, nil).Applies(c) {
			t.Errorf("reused calibration across %s", field)
		}
	}
}

func TestCalibrationBounds(t *testing.T) {
	e := New(Model{}, nil)
	for _, tc := range []struct{ estimated, actual, want int }{
		{0, 100, 1000}, {100, 0, 1000}, {-1, 100, 1000}, {100, 80, 1000},
		{100, 100, 1000}, {100, 125, 800}, {100, 500, 500},
	} {
		if got := e.ChunkBudget(1000, e.Calibrate(tc.estimated, tc.actual)); got != tc.want {
			t.Errorf("%+v: got %d", tc, got)
		}
	}
}
