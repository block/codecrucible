package sarif

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestInvalidLocationRetainedWithoutInventedAnchor(t *testing.T) {
	for _, region := range []SARIFRegion{{StartLine: 4, EndLine: 2}, {StartLine: 99}, {StartLine: -1}} {
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

func TestSourceEndClampPreservesStart(t *testing.T) {
	for _, end := range []int{99, 1, -1} {
		region := SARIFRegion{StartLine: 2, EndLine: end}
		d := testDoc(nil, []SARIFResult{{Locations: []SARIFLocation{{PhysicalLocation: SARIFPhysicalLocation{ArtifactLocation: SARIFArtifactLocation{URI: "a.go"}, Region: &region}}}}}, nil)
		got := ValidateSourceLocations(d, FileMap{"a.go": "one\ntwo\nthree\n"}).Runs[0].Results[0]
		reg := got.Locations[0].PhysicalLocation.Region
		want := 2
		if end == 99 {
			want = 3
		}
		if reg == nil || reg.StartLine != 2 || reg.EndLine != want {
			t.Fatalf("end %d: %+v", end, reg)
		}
		if region.EndLine != end || got.Properties.ReportedLocations[0].PhysicalLocation.Region.EndLine != end {
			t.Fatal("original region lost or mutated")
		}
	}
}

func TestReversedRegionWithoutFileKeepsStart(t *testing.T) {
	region := SARIFRegion{StartLine: 4, EndLine: 2}
	d := testDoc(nil, []SARIFResult{{Locations: []SARIFLocation{{PhysicalLocation: SARIFPhysicalLocation{ArtifactLocation: SARIFArtifactLocation{URI: "unknown.go"}, Region: &region}}}}}, nil)
	r := ValidateSourceLocations(d, nil).Runs[0].Results[0]
	got := r.Locations[0].PhysicalLocation.Region
	if got == nil || got.StartLine != 4 || got.EndLine != 4 || r.Properties.LocationWarnings[0] != "clamped_source_region" {
		t.Fatalf("%+v %+v", got, r.Properties)
	}
}

func TestBuildPreservesZeroStartDiagnostic(t *testing.T) {
	for _, start := range []int{0, -1} {
		for _, files := range []FileMap{{"a.go": "sink()\n"}, {}} {
			doc := Build(AnalysisResult{SecurityIssues: []SecurityIssue{{Issue: "Synthetic", FilePath: "a.go", StartLine: start, EndLine: 3, Severity: 8}}}, files, BuilderConfig{})
			r := doc.Runs[0].Results[0]
			if r.Locations[0].PhysicalLocation.Region != nil {
				t.Fatal("invented primary region")
			}
			if len(r.Properties.ReportedLocations) != 1 || r.Properties.ReportedLocations[0].PhysicalLocation.Region.StartLine != start || r.Properties.ReportedLocations[0].PhysicalLocation.Region.EndLine != 3 {
				t.Fatalf("lost reported coordinates: %+v", r.Properties)
			}
			if len(r.Properties.LocationWarnings) != 1 || r.Properties.LocationWarnings[0] != "invalid_source_region" {
				t.Fatal(r.Properties.LocationWarnings)
			}
			raw, err := json.Marshal(r)
			if err != nil || !strings.Contains(string(raw), `"reportedLocations"`) {
				t.Fatal(string(raw), err)
			}
		}
	}
}
