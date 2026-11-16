package sarif

import "testing"

func TestInvalidLocationRetainedWithoutInventedAnchor(t *testing.T) {
	for _, region := range []SARIFRegion{{StartLine: 4, EndLine: 2}, {StartLine: 99}, {StartLine: 1, EndLine: 99}, {StartLine: -1}} {
		d := testDoc(nil, []SARIFResult{{Locations: []SARIFLocation{{PhysicalLocation: SARIFPhysicalLocation{ArtifactLocation: SARIFArtifactLocation{URI: "a.go"}, Region: &region}}}}}, nil)
		got := ValidateSourceLocations(d, FileMap{"a.go": "one\ntwo\n"}).Runs[0].Results[0]
		if got.Locations[0].PhysicalLocation.Region != nil || len(got.Properties.ReportedLocations) != 1 {
			t.Fatal("invalid region emitted or original lost")
		}
		if d.Runs[0].Results[0].Locations[0].PhysicalLocation.Region == nil {
			t.Fatal("mutated input")
		}
	}
}
