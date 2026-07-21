package sarif

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
)

// ---------------------------------------------------------------------------
// severityLevel
// ---------------------------------------------------------------------------

func TestSeverityLevel(t *testing.T) {
	tests := []struct {
		severity float64
		want     string
	}{
		{0, "none"},
		{0.1, "note"},
		{1.0, "note"},
		{3.9, "note"},
		{4.0, "warning"},
		{5.0, "warning"},
		{6.9, "warning"},
		{7.0, "error"},
		{9.0, "error"},
		{10.0, "error"},
	}
	for _, tt := range tests {
		got := severityLevel(tt.severity)
		if got != tt.want {
			t.Errorf("severityLevel(%v) = %q, want %q", tt.severity, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// slugify
// ---------------------------------------------------------------------------

func TestSlugify(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"SQL Injection Vulnerability", "codecrucible.sql-injection-vulnerability"},
		{"XSS (Reflected)", "codecrucible.xss-reflected"},
		{"  leading/trailing  ", "codecrucible.leading-trailing"},
		{"multiple---hyphens", "codecrucible.multiple-hyphens"},
		{"UPPER CASE", "codecrucible.upper-case"},
		{"special!@#chars$%^&*()", "codecrucible.special-chars"},
		{"a", "codecrucible.a"},
	}
	for _, tt := range tests {
		got := slugify(tt.input)
		if got != tt.want {
			t.Errorf("slugify(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// extractCWETag
// ---------------------------------------------------------------------------

func TestExtractCWETag(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"CWE-89: SQL Injection", "cwe-89"},
		{"CWE-79", "cwe-79"},
		{"cwe-22: Path Traversal", "cwe-22"},
		{"no cwe here", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got := extractCWETag(tt.input)
		if got != tt.want {
			t.Errorf("extractCWETag(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Rule deduplication
// ---------------------------------------------------------------------------

func TestBuild_RuleDeduplication(t *testing.T) {
	result := AnalysisResult{
		SecurityIssues: []SecurityIssue{
			{Issue: "SQL Injection", FilePath: "a.go", StartLine: 1, Severity: 9, CWEID: "CWE-89"},
			{Issue: "SQL Injection", FilePath: "b.go", StartLine: 5, Severity: 9, CWEID: "CWE-89"},
		},
	}
	doc := Build(result, nil, BuilderConfig{})

	rules := doc.Runs[0].Tool.Driver.Rules
	if len(rules) != 1 {
		t.Fatalf("expected 1 deduplicated rule, got %d", len(rules))
	}

	results := doc.Runs[0].Results
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for _, r := range results {
		if r.RuleID != rules[0].ID {
			t.Errorf("result ruleId %q != rule id %q", r.RuleID, rules[0].ID)
		}
	}
}

// ---------------------------------------------------------------------------
// Snippet population
// ---------------------------------------------------------------------------

func TestBuild_SnippetPopulation(t *testing.T) {
	fm := FileMap{
		"src/main.go": "line1\nline2\nline3\nline4\nline5\n",
	}
	result := AnalysisResult{
		SecurityIssues: []SecurityIssue{
			{Issue: "Bug", FilePath: "src/main.go", StartLine: 2, EndLine: 4, Severity: 5},
		},
	}
	doc := Build(result, fm, BuilderConfig{})

	loc := doc.Runs[0].Results[0].Locations[0].PhysicalLocation
	if loc.Region == nil {
		t.Fatal("expected region")
	}
	if loc.Region.Snippet == nil {
		t.Fatal("expected snippet")
	}
	want := "line2\nline3\nline4"
	if loc.Region.Snippet.Text != want {
		t.Errorf("snippet = %q, want %q", loc.Region.Snippet.Text, want)
	}
}

// ---------------------------------------------------------------------------
// Missing file in FileMap — snippet is nil, no panic
// ---------------------------------------------------------------------------

func TestBuild_MissingFileNoSnippet(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	result := AnalysisResult{
		SecurityIssues: []SecurityIssue{
			{Issue: "Bug", FilePath: "missing.go", StartLine: 1, EndLine: 2, Severity: 3},
		},
	}
	doc := Build(result, FileMap{}, BuilderConfig{Logger: logger})

	loc := doc.Runs[0].Results[0].Locations[0].PhysicalLocation
	if loc.Region.Snippet != nil {
		t.Errorf("expected nil snippet for missing file, got %+v", loc.Region.Snippet)
	}

	if !bytes.Contains(buf.Bytes(), []byte("file not found in FileMap")) {
		t.Error("expected warning log about missing file")
	}
}

// ---------------------------------------------------------------------------
// Empty SecurityIssues → valid SARIF with zero findings
// ---------------------------------------------------------------------------

func TestBuild_EmptyIssues(t *testing.T) {
	doc := Build(AnalysisResult{}, nil, BuilderConfig{})

	if len(doc.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(doc.Runs))
	}
	if len(doc.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(doc.Runs[0].Results))
	}
	if len(doc.Runs[0].Tool.Driver.Rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(doc.Runs[0].Tool.Driver.Rules))
	}

	// Must marshal cleanly (non-nil slices).
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if !json.Valid(data) {
		t.Error("output is not valid JSON")
	}
}

// ---------------------------------------------------------------------------
// CWE tags in rule properties
// ---------------------------------------------------------------------------

func TestBuild_CWETags(t *testing.T) {
	result := AnalysisResult{
		SecurityIssues: []SecurityIssue{
			{Issue: "Injection", Severity: 8, CWEID: "CWE-89: SQL Injection", FilePath: "a.go", StartLine: 1},
		},
	}
	doc := Build(result, nil, BuilderConfig{})

	rule := doc.Runs[0].Tool.Driver.Rules[0]

	// Verify tags include "security" and CWE in GitHub's expected format.
	tags, ok := rule.Properties["tags"]
	if !ok {
		t.Fatal("expected tags property")
	}
	tagSlice, ok := tags.([]string)
	if !ok {
		t.Fatalf("tags is %T, want []string", tags)
	}
	if len(tagSlice) != 2 {
		t.Fatalf("tags length = %d, want 2, got %v", len(tagSlice), tagSlice)
	}
	if tagSlice[0] != "security" {
		t.Errorf("tags[0] = %q, want %q", tagSlice[0], "security")
	}
	if tagSlice[1] != "external/cwe/cwe-89" {
		t.Errorf("tags[1] = %q, want %q", tagSlice[1], "external/cwe/cwe-89")
	}

	// Verify relationship to CWE taxonomy.
	if len(rule.Relationships) != 1 {
		t.Fatalf("expected 1 relationship, got %d", len(rule.Relationships))
	}
	rel := rule.Relationships[0]
	if rel.Target.ID != "CWE-89" {
		t.Errorf("relationship target ID = %q, want %q", rel.Target.ID, "CWE-89")
	}
	if rel.Target.ToolComponent.Name != "CWE" {
		t.Errorf("relationship toolComponent = %q, want %q", rel.Target.ToolComponent.Name, "CWE")
	}

	// Verify CWE taxonomy is included.
	if len(doc.Runs[0].Taxonomies) != 1 {
		t.Fatalf("expected 1 taxonomy, got %d", len(doc.Runs[0].Taxonomies))
	}
	tax := doc.Runs[0].Taxonomies[0]
	if tax.Name != "CWE" {
		t.Errorf("taxonomy name = %q, want %q", tax.Name, "CWE")
	}
	if len(tax.Taxa) != 1 || tax.Taxa[0].ID != "CWE-89" {
		t.Errorf("taxonomy taxa = %v, want [{ID: CWE-89}]", tax.Taxa)
	}
}

// ---------------------------------------------------------------------------
// security-severity property is set as string
// ---------------------------------------------------------------------------

func TestBuild_SecuritySeverityProperty(t *testing.T) {
	result := AnalysisResult{
		SecurityIssues: []SecurityIssue{
			{Issue: "Bug", Severity: 7.5, FilePath: "a.go", StartLine: 1},
		},
	}
	doc := Build(result, nil, BuilderConfig{})

	rule := doc.Runs[0].Tool.Driver.Rules[0]
	val, ok := rule.Properties["security-severity"]
	if !ok {
		t.Fatal("expected security-severity property")
	}
	s, ok := val.(string)
	if !ok {
		t.Fatalf("security-severity is %T, want string", val)
	}
	if s != "7.5" {
		t.Errorf("security-severity = %q, want %q", s, "7.5")
	}
}

// ---------------------------------------------------------------------------
// Full Build produces valid JSON with correct schema/version
// ---------------------------------------------------------------------------

func TestBuild_ValidJSON(t *testing.T) {
	fm := FileMap{
		"app/handler.go": "package app\n\nfunc Handle() {}\n",
	}
	result := AnalysisResult{
		RepoName:    "test-repo",
		Description: "A test repository",
		SecurityIssues: []SecurityIssue{
			{
				Issue:            "Hardcoded Secret",
				FilePath:         "app/handler.go",
				StartLine:        3,
				EndLine:          3,
				TechnicalDetails: "Secret found in source",
				Severity:         8.0,
				CWEID:            "CWE-798",
			},
		},
	}
	doc := Build(result, fm, BuilderConfig{ToolName: "myTool", ToolVersion: "1.0.0"})

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// Re-parse to verify structure.
	var parsed SARIFDocument
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if parsed.Schema != sarifSchema {
		t.Errorf("schema = %q, want %q", parsed.Schema, sarifSchema)
	}
	if parsed.Version != sarifVersion {
		t.Errorf("version = %q, want %q", parsed.Version, sarifVersion)
	}
	if parsed.Runs[0].Tool.Driver.Name != "myTool" {
		t.Errorf("tool name = %q, want %q", parsed.Runs[0].Tool.Driver.Name, "myTool")
	}
	if parsed.Runs[0].Tool.Driver.Version != "1.0.0" {
		t.Errorf("tool version = %q, want %q", parsed.Runs[0].Tool.Driver.Version, "1.0.0")
	}
}

// ---------------------------------------------------------------------------
// Schema and version constants
// ---------------------------------------------------------------------------

func TestBuild_SchemaAndVersion(t *testing.T) {
	doc := Build(AnalysisResult{}, nil, BuilderConfig{})

	if doc.Schema != "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json" {
		t.Errorf("unexpected schema: %s", doc.Schema)
	}
	if doc.Version != "2.1.0" {
		t.Errorf("unexpected version: %s", doc.Version)
	}
}

// ---------------------------------------------------------------------------
// Nil/empty AnalysisResult fields — no panics
// ---------------------------------------------------------------------------

func TestBuild_NilFields(t *testing.T) {
	cases := []struct {
		name   string
		result AnalysisResult
	}{
		{"zero value", AnalysisResult{}},
		{"nil issues", AnalysisResult{SecurityIssues: nil}},
		{"nil routes", AnalysisResult{PublicAPIRoutes: nil}},
		{"empty issues", AnalysisResult{SecurityIssues: []SecurityIssue{}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := Build(tc.result, nil, BuilderConfig{})
			data, err := json.Marshal(doc)
			if err != nil {
				t.Fatalf("marshal failed: %v", err)
			}
			if !json.Valid(data) {
				t.Error("output is not valid JSON")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Invocation metadata
// ---------------------------------------------------------------------------

func TestBuild_Invocation(t *testing.T) {
	doc := Build(AnalysisResult{}, nil, BuilderConfig{})

	invocations := doc.Runs[0].Invocations
	if len(invocations) != 1 {
		t.Fatalf("expected 1 invocation, got %d", len(invocations))
	}
	if !invocations[0].ExecutionSuccessful {
		t.Error("expected executionSuccessful = true")
	}
}

// ---------------------------------------------------------------------------
// Default config values
// ---------------------------------------------------------------------------

func TestBuild_DefaultConfig(t *testing.T) {
	doc := Build(AnalysisResult{}, nil, BuilderConfig{})

	driver := doc.Runs[0].Tool.Driver
	if driver.Name != "codecrucible" {
		t.Errorf("default tool name = %q, want %q", driver.Name, "codecrucible")
	}
	if driver.Version != "dev" {
		t.Errorf("default tool version = %q, want %q", driver.Version, "dev")
	}
}
