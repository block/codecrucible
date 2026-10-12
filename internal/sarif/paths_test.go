package sarif

import "testing"

func TestResolvePath(t *testing.T) {
	files := FileMap{
		"app/routes/auth.js":     "a",
		"app/server.js":          "b",
		"svc/a/handler.go":       "c",
		"svc/b/handler.go":       "d",
		"lib/myroutes/auth.js":   "e",
		"internal/db/queries.go": "f",
	}
	for _, tc := range []struct {
		reported, want string
		ok             bool
	}{
		{"app/server.js", "app/server.js", true},
		{"./app/server.js", "app/server.js", true},
		{"/app/server.js", "/app/server.js", false},
		{"server.js", "app/server.js", true},
		{"routes/auth.js", "app/routes/auth.js", true}, // segment boundary: not lib/myroutes
		{"db/queries.go", "internal/db/queries.go", true},
		{"handler.go", "handler.go", false}, // ambiguous
		{"missing.go", "missing.go", false},
		{"../app/server.js", "../app/server.js", false},
		{"", "", false},
	} {
		got, ok := ResolvePath(files, tc.reported)
		if got != tc.want || ok != tc.ok {
			t.Errorf("ResolvePath(%q) = %q, %v; want %q, %v", tc.reported, got, ok, tc.want, tc.ok)
		}
	}
}

func TestBuildRepairsDroppedPathPrefix(t *testing.T) {
	files := FileMap{"app/routes/auth.js": "one\ntwo\nthree\n", "app/server.js": "s1\ns2\n"}
	doc := Build(AnalysisResult{SecurityIssues: []SecurityIssue{{
		Issue: "Mass assignment", FilePath: "routes/auth.js", StartLine: 2, EndLine: 2, Severity: 7,
		TechnicalDetails: "role is copied from the body.",
		CodePath: []CodePathStep{
			{FilePath: "server.js", StartLine: 1, Message: "router mounted"},
			{FilePath: "routes/auth.js", StartLine: 2, Message: "role assigned"},
		},
	}}}, files, BuilderConfig{})
	r := doc.Runs[0].Results[0]
	loc := r.Locations[0].PhysicalLocation
	if loc.ArtifactLocation.URI != "app/routes/auth.js" || loc.Region.Snippet == nil || loc.Region.Snippet.Text != "two" {
		t.Fatalf("location not repaired: %+v %+v", loc.ArtifactLocation, loc.Region)
	}
	if r.Properties.ReportedPath != "routes/auth.js" {
		t.Fatalf("reported path not recorded: %+v", r.Properties)
	}
	if len(r.CodeFlows) != 1 || r.CodeFlows[0].ThreadFlows[0].Locations[0].Location.PhysicalLocation.ArtifactLocation.URI != "app/server.js" {
		t.Fatalf("code flow not repaired: %+v", r.CodeFlows)
	}

	exact := Build(AnalysisResult{SecurityIssues: []SecurityIssue{{Issue: "X", FilePath: "app/server.js", StartLine: 1}}}, files, BuilderConfig{})
	if p := exact.Runs[0].Results[0].Properties.ReportedPath; p != "" {
		t.Fatalf("exact path recorded as repaired: %q", p)
	}
}

func TestResolveLocationsRepairsSavedFindings(t *testing.T) {
	files := FileMap{"app/routes/auth.js": "one\ntwo\n"}
	doc := SARIFDocument{Runs: []SARIFRun{{Results: []SARIFResult{{
		RuleID: "r",
		Locations: []SARIFLocation{{PhysicalLocation: SARIFPhysicalLocation{
			ArtifactLocation: SARIFArtifactLocation{URI: "routes/auth.js"},
			Region:           &SARIFRegion{StartLine: 2},
		}}},
	}}}}}
	out := ResolveLocations(doc, files)
	r := out.Runs[0].Results[0]
	if r.Locations[0].PhysicalLocation.ArtifactLocation.URI != "app/routes/auth.js" || r.Locations[0].PhysicalLocation.Region.Snippet.Text != "two" || r.Properties.ReportedPath != "routes/auth.js" {
		t.Fatalf("saved finding not repaired: %+v %+v", r.Locations[0].PhysicalLocation, r.Properties)
	}
	if doc.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI != "routes/auth.js" || doc.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.Snippet != nil {
		t.Fatal("input document mutated")
	}
}
