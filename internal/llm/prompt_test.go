package llm

import (
	"strings"
	"testing"
	"testing/fstest"
)

const testBaseYAML = `system_message: >
  You are a senior security engineer.

analysis_intro: >
  Analyze the following repository.

infrastructure_note: >
  IMPORTANT - INFRASTRUCTURE ANALYSIS.

analysis_requirements_header: >
  ANALYSIS REQUIREMENTS:

custom_requirements_placeholder: "{custom_requirements_section}"

repo_info: >
  The repository name is: {repo_name}.
  Repomix XML Content:
  ---
  {xml_content}
  ---

critical_instructions: >
  CRITICAL INSTRUCTIONS:
  Report all vulnerabilities.

json_formatting_rules: >
  Respond with ONLY valid JSON.
  JSON Schema:
  ---
  {schema}
  ---
`

const testSectionsYAML = `sections:
  public_api:
    title: "PUBLIC API SECURITY"
    features: ["public_api", "websockets"]
    content: >
      Identify all public-facing endpoints.
  code_quality:
    title: "CODE QUALITY"
    features: []
    content: >
      Report risky code patterns.
`

func testFS() fstest.MapFS {
	return fstest.MapFS{
		"security_analysis_base.yaml": &fstest.MapFile{Data: []byte(testBaseYAML)},
		"analysis_sections.yaml":      &fstest.MapFile{Data: []byte(testSectionsYAML)},
	}
}

func TestLoadBasePrompt(t *testing.T) {
	loader := NewPromptLoader(testFS())

	bp, err := loader.LoadBasePrompt()
	if err != nil {
		t.Fatalf("LoadBasePrompt() error: %v", err)
	}

	if !strings.Contains(bp.SystemMessage, "senior security engineer") {
		t.Errorf("SystemMessage = %q, want to contain 'senior security engineer'", bp.SystemMessage)
	}
	if !strings.Contains(bp.AnalysisIntro, "Analyze the following") {
		t.Errorf("AnalysisIntro = %q, want to contain 'Analyze the following'", bp.AnalysisIntro)
	}
	if !strings.Contains(bp.RepoInfo, "{repo_name}") {
		t.Errorf("RepoInfo = %q, want to contain '{repo_name}'", bp.RepoInfo)
	}
	if !strings.Contains(bp.JSONFormattingRules, "{schema}") {
		t.Errorf("JSONFormattingRules = %q, want to contain '{schema}'", bp.JSONFormattingRules)
	}
}

func TestLoadAnalysisSections(t *testing.T) {
	loader := NewPromptLoader(testFS())

	af, err := loader.LoadAnalysisSections()
	if err != nil {
		t.Fatalf("LoadAnalysisSections() error: %v", err)
	}

	if len(af.Sections) != 2 {
		t.Fatalf("got %d sections, want 2", len(af.Sections))
	}

	api, ok := af.Sections["public_api"]
	if !ok {
		t.Fatal("missing 'public_api' section")
	}
	if api.Title != "PUBLIC API SECURITY" {
		t.Errorf("public_api.Title = %q, want %q", api.Title, "PUBLIC API SECURITY")
	}
	if len(api.Features) != 2 {
		t.Errorf("public_api.Features length = %d, want 2", len(api.Features))
	}

	cq, ok := af.Sections["code_quality"]
	if !ok {
		t.Fatal("missing 'code_quality' section")
	}
	if len(cq.Features) != 0 {
		t.Errorf("code_quality.Features length = %d, want 0", len(cq.Features))
	}
}

func TestAssembleMessages_BasicSubstitution(t *testing.T) {
	loader := NewPromptLoader(testFS())

	msgs, err := loader.AssembleMessages(PromptParams{
		RepoName:   "my-repo",
		XML:        "<file>contents</file>",
		Schema:     `{"type":"object"}`,
		ChunkTotal: 1,
	})
	if err != nil {
		t.Fatalf("AssembleMessages() error: %v", err)
	}

	if len(msgs) != 2 {
		t.Fatalf("got %d messages, want 2", len(msgs))
	}

	if msgs[0].Role != "system" {
		t.Errorf("msgs[0].Role = %q, want %q", msgs[0].Role, "system")
	}
	if !strings.Contains(msgs[0].Content, "senior security engineer") {
		t.Errorf("system message missing expected content")
	}

	if msgs[1].Role != "user" {
		t.Errorf("msgs[1].Role = %q, want %q", msgs[1].Role, "user")
	}

	user := msgs[1].Content
	if !strings.Contains(user, "my-repo") {
		t.Error("user message missing repo name substitution")
	}
	if !strings.Contains(user, "<file>contents</file>") {
		t.Error("user message missing XML content substitution")
	}
	if !strings.Contains(user, `{"type":"object"}`) {
		t.Error("user message missing schema substitution")
	}
}

func TestAssembleMessages_IncludesAnalysisSections(t *testing.T) {
	loader := NewPromptLoader(testFS())

	msgs, err := loader.AssembleMessages(PromptParams{
		RepoName:   "test-repo",
		XML:        "<xml/>",
		Schema:     "{}",
		ChunkTotal: 1,
	})
	if err != nil {
		t.Fatalf("AssembleMessages() error: %v", err)
	}

	user := msgs[1].Content
	if !strings.Contains(user, "ANALYSIS REQUIREMENTS:") {
		t.Error("user message missing ANALYSIS REQUIREMENTS header")
	}
	if !strings.Contains(user, "PUBLIC API SECURITY") {
		t.Error("user message missing PUBLIC API SECURITY section title")
	}
	if !strings.Contains(user, "Identify all public-facing endpoints") {
		t.Error("user message missing public_api section content")
	}
	if !strings.Contains(user, "CODE QUALITY") {
		t.Error("user message missing CODE QUALITY section title")
	}
	if !strings.Contains(user, "Report risky code patterns") {
		t.Error("user message missing code_quality section content")
	}
}

func TestAssembleMessages_SectionsBeforeRepoInfo(t *testing.T) {
	loader := NewPromptLoader(testFS())

	msgs, err := loader.AssembleMessages(PromptParams{
		RepoName:   "order-test",
		XML:        "<xml/>",
		Schema:     "{}",
		ChunkTotal: 1,
	})
	if err != nil {
		t.Fatalf("AssembleMessages() error: %v", err)
	}

	user := msgs[1].Content
	sectionsIdx := strings.Index(user, "ANALYSIS REQUIREMENTS:")
	repoInfoIdx := strings.Index(user, "order-test")
	if sectionsIdx < 0 || repoInfoIdx < 0 {
		t.Fatal("missing expected content in user message")
	}
	if sectionsIdx > repoInfoIdx {
		t.Error("analysis sections should appear before repo info in the prompt")
	}
}

func TestAssembleMessages_GracefulWithoutSectionsFile(t *testing.T) {
	noSectionsFS := fstest.MapFS{
		"security_analysis_base.yaml": &fstest.MapFile{Data: []byte(testBaseYAML)},
	}
	loader := NewPromptLoader(noSectionsFS)

	msgs, err := loader.AssembleMessages(PromptParams{
		RepoName:   "no-sections",
		XML:        "<xml/>",
		Schema:     "{}",
		ChunkTotal: 1,
	})
	if err != nil {
		t.Fatalf("AssembleMessages() should not fail without sections file: %v", err)
	}

	user := msgs[1].Content
	if !strings.Contains(user, "no-sections") {
		t.Error("user message missing repo name")
	}
}

func TestAssembleMessages_ChunkManifest(t *testing.T) {
	loader := NewPromptLoader(testFS())

	msgs, err := loader.AssembleMessages(PromptParams{
		RepoName:   "chunked-repo",
		XML:        "<xml/>",
		Schema:     "{}",
		Manifest:   []string{"file1.go", "file2.go", "file3.go"},
		ChunkIndex: 1,
		ChunkTotal: 3,
	})
	if err != nil {
		t.Fatalf("AssembleMessages() error: %v", err)
	}

	user := msgs[1].Content
	if !strings.Contains(user, "chunk 2 of 3") {
		t.Error("user message missing chunk indicator")
	}
	if !strings.Contains(user, "file1.go") {
		t.Error("user message missing manifest file1.go")
	}
	if !strings.Contains(user, "file2.go") {
		t.Error("user message missing manifest file2.go")
	}
	if !strings.Contains(user, "Focus your analysis on the files shown in this chunk") {
		t.Error("user message missing chunk focus instruction")
	}
}

func TestAssembleMessages_SingleChunk_NoManifest(t *testing.T) {
	loader := NewPromptLoader(testFS())

	msgs, err := loader.AssembleMessages(PromptParams{
		RepoName:   "single-repo",
		XML:        "<xml/>",
		Schema:     "{}",
		ChunkTotal: 1,
	})
	if err != nil {
		t.Fatalf("AssembleMessages() error: %v", err)
	}

	user := msgs[1].Content
	if strings.Contains(user, "chunk") {
		t.Error("single-chunk message should not contain chunk info")
	}
	if strings.Contains(user, "Focus your analysis") {
		t.Error("single-chunk message should not contain chunk focus instruction")
	}
}

func TestAssembleMessages_CustomRequirements(t *testing.T) {
	loader := NewPromptLoader(testFS())

	msgs, err := loader.AssembleMessages(PromptParams{
		RepoName:           "custom-repo",
		XML:                "<xml/>",
		Schema:             "{}",
		ChunkTotal:         1,
		CustomRequirements: "Focus on auth bypass vulnerabilities.",
	})
	if err != nil {
		t.Fatalf("AssembleMessages() error: %v", err)
	}

	user := msgs[1].Content
	if !strings.Contains(user, "ADDITIONAL REQUIREMENTS:") {
		t.Error("user message missing ADDITIONAL REQUIREMENTS header")
	}
	if !strings.Contains(user, "Focus on auth bypass vulnerabilities.") {
		t.Error("user message missing custom requirements content")
	}
}

func TestAssembleMessages_SupplementaryContext(t *testing.T) {
	loader := NewPromptLoader(testFS())

	msgs, err := loader.AssembleMessages(PromptParams{
		RepoName:             "repo",
		XML:                  "<repo>code</repo>",
		Schema:               "{}",
		ChunkTotal:           1,
		CustomRequirements:   "custom reqs here",
		SupplementaryContext: "<context name=\"api-spec\">openapi: 3.0</context>",
	})
	if err != nil {
		t.Fatalf("AssembleMessages() error: %v", err)
	}

	user := msgs[1].Content
	if !strings.Contains(user, "SUPPLEMENTARY CONTEXT") {
		t.Error("user message missing SUPPLEMENTARY CONTEXT header")
	}
	if !strings.Contains(user, "openapi: 3.0") {
		t.Error("user message missing supplementary content")
	}

	// Order: custom-requirements < supplementary-context < repo-info.
	reqIdx := strings.Index(user, "custom reqs here")
	supIdx := strings.Index(user, "openapi: 3.0")
	repoIdx := strings.Index(user, "<repo>code</repo>")
	if !(reqIdx < supIdx && supIdx < repoIdx) {
		t.Errorf("section order wrong: reqs=%d sup=%d repo=%d", reqIdx, supIdx, repoIdx)
	}
}

func TestAssembleMessages_NoSupplementaryContext(t *testing.T) {
	loader := NewPromptLoader(testFS())
	msgs, _ := loader.AssembleMessages(PromptParams{
		RepoName: "r", XML: "x", Schema: "{}", ChunkTotal: 1,
	})
	if strings.Contains(msgs[1].Content, "SUPPLEMENTARY CONTEXT") {
		t.Error("header should be omitted when SupplementaryContext is empty")
	}
}

func TestAssembleMessages_NoCustomRequirements(t *testing.T) {
	loader := NewPromptLoader(testFS())

	msgs, err := loader.AssembleMessages(PromptParams{
		RepoName:   "no-custom-repo",
		XML:        "<xml/>",
		Schema:     "{}",
		ChunkTotal: 1,
	})
	if err != nil {
		t.Fatalf("AssembleMessages() error: %v", err)
	}

	user := msgs[1].Content
	if strings.Contains(user, "ADDITIONAL REQUIREMENTS:") {
		t.Error("user message should not contain ADDITIONAL REQUIREMENTS when none provided")
	}
}

func TestAssembleMessages_MissingTemplateFile(t *testing.T) {
	emptyFS := fstest.MapFS{}
	loader := NewPromptLoader(emptyFS)

	_, err := loader.AssembleMessages(PromptParams{
		RepoName:   "missing",
		XML:        "<xml/>",
		Schema:     "{}",
		ChunkTotal: 1,
	})
	if err == nil {
		t.Fatal("AssembleMessages() with missing template should return error")
	}
	if !strings.Contains(err.Error(), "loading base prompt") {
		t.Errorf("error = %q, want to contain 'loading base prompt'", err.Error())
	}
}

func TestAssembleMessages_AllParamsEmpty(t *testing.T) {
	loader := NewPromptLoader(testFS())

	msgs, err := loader.AssembleMessages(PromptParams{})
	if err != nil {
		t.Fatalf("AssembleMessages() with empty params should not panic/error: %v", err)
	}

	if len(msgs) != 2 {
		t.Fatalf("got %d messages, want 2", len(msgs))
	}
	if msgs[0].Role != "system" {
		t.Errorf("msgs[0].Role = %q, want %q", msgs[0].Role, "system")
	}
	if msgs[1].Role != "user" {
		t.Errorf("msgs[1].Role = %q, want %q", msgs[1].Role, "user")
	}
}

func TestLoadBasePrompt_MissingFile(t *testing.T) {
	emptyFS := fstest.MapFS{}
	loader := NewPromptLoader(emptyFS)

	_, err := loader.LoadBasePrompt()
	if err == nil {
		t.Fatal("LoadBasePrompt() with missing file should return error")
	}
	if !strings.Contains(err.Error(), "loading base prompt") {
		t.Errorf("error = %q, want to contain 'loading base prompt'", err.Error())
	}
}

func TestLoadAnalysisSections_MissingFile(t *testing.T) {
	emptyFS := fstest.MapFS{}
	loader := NewPromptLoader(emptyFS)

	_, err := loader.LoadAnalysisSections()
	if err == nil {
		t.Fatal("LoadAnalysisSections() with missing file should return error")
	}
	if !strings.Contains(err.Error(), "loading analysis sections") {
		t.Errorf("error = %q, want to contain 'loading analysis sections'", err.Error())
	}
}

// --- Feature detection prompt tests ---

const testFeatureYAML = `system_message: >
  You are a feature detector.

user_prompt_template: >
  Repo: {repo_name}
  Content:
  {xml_content}
  Schema:
  {schema}
`

func testFeatureFS() fstest.MapFS {
	return fstest.MapFS{
		"feature_detection.yaml": &fstest.MapFile{Data: []byte(testFeatureYAML)},
	}
}

func TestLoadFeatureDetectionPrompt(t *testing.T) {
	loader := NewPromptLoader(testFeatureFS())

	fd, err := loader.LoadFeatureDetectionPrompt()
	if err != nil {
		t.Fatalf("LoadFeatureDetectionPrompt() error: %v", err)
	}

	if !strings.Contains(fd.SystemMessage, "feature detector") {
		t.Errorf("SystemMessage = %q, want to contain 'feature detector'", fd.SystemMessage)
	}
	if !strings.Contains(fd.UserPromptTemplate, "{repo_name}") {
		t.Errorf("UserPromptTemplate = %q, want to contain '{repo_name}'", fd.UserPromptTemplate)
	}

	// Second call should return the cached instance.
	fd2, err := loader.LoadFeatureDetectionPrompt()
	if err != nil {
		t.Fatalf("cached LoadFeatureDetectionPrompt() error: %v", err)
	}
	if fd != fd2 {
		t.Error("expected cached pointer to be returned on second call")
	}
}

func TestLoadFeatureDetectionPrompt_MissingFile(t *testing.T) {
	loader := NewPromptLoader(fstest.MapFS{})

	_, err := loader.LoadFeatureDetectionPrompt()
	if err == nil {
		t.Fatal("LoadFeatureDetectionPrompt() with missing file should return error")
	}
	if !strings.Contains(err.Error(), "loading feature detection prompt") {
		t.Errorf("error = %q, want to contain 'loading feature detection prompt'", err.Error())
	}
}

func TestAssembleFeatureDetectionMessages(t *testing.T) {
	loader := NewPromptLoader(testFeatureFS())

	msgs, err := loader.AssembleFeatureDetectionMessages(FeaturePromptParams{
		RepoName: "feat-repo",
		Manifest: []string{"src/main.go", "src/db.go"},
		Samples:  `<file path="src/main.go">package main</file>`,
	})
	if err != nil {
		t.Fatalf("AssembleFeatureDetectionMessages() error: %v", err)
	}

	if len(msgs) != 2 {
		t.Fatalf("got %d messages, want 2", len(msgs))
	}
	if msgs[0].Role != "system" {
		t.Errorf("msgs[0].Role = %q, want %q", msgs[0].Role, "system")
	}
	if !strings.Contains(msgs[0].Content, "feature detector") {
		t.Error("system message missing expected content")
	}

	user := msgs[1].Content
	if !strings.Contains(user, "feat-repo") {
		t.Error("user message missing repo name substitution")
	}
	if !strings.Contains(user, "<manifest>") {
		t.Error("user message missing <manifest> wrapper")
	}
	if !strings.Contains(user, "src/main.go") {
		t.Error("user message missing manifest path src/main.go")
	}
	if !strings.Contains(user, "src/db.go") {
		t.Error("user message missing manifest path src/db.go")
	}
	if !strings.Contains(user, "package main") {
		t.Error("user message missing sample content")
	}
	if strings.Contains(user, "{schema}") {
		t.Error("user message has unsubstituted {schema} placeholder")
	}
	if strings.Contains(user, "{xml_content}") {
		t.Error("user message has unsubstituted {xml_content} placeholder")
	}
}

func TestAssembleFeatureDetectionMessages_MissingTemplate(t *testing.T) {
	loader := NewPromptLoader(fstest.MapFS{})

	_, err := loader.AssembleFeatureDetectionMessages(FeaturePromptParams{
		RepoName: "x",
	})
	if err == nil {
		t.Fatal("AssembleFeatureDetectionMessages() with missing template should return error")
	}
}

// --- sectionEnabled table-driven tests ---

func TestSectionEnabled(t *testing.T) {
	tests := []struct {
		name            string
		section         AnalysisSection
		enabledFeatures []string
		want            bool
	}{
		{
			name:            "no filter includes all",
			section:         AnalysisSection{Features: []string{"db"}},
			enabledFeatures: nil,
			want:            true,
		},
		{
			name:            "empty filter includes all",
			section:         AnalysisSection{Features: []string{"db"}},
			enabledFeatures: []string{},
			want:            true,
		},
		{
			name:            "section with no features always included",
			section:         AnalysisSection{Features: nil},
			enabledFeatures: []string{"web"},
			want:            true,
		},
		{
			name:            "overlapping feature included",
			section:         AnalysisSection{Features: []string{"db", "sql"}},
			enabledFeatures: []string{"web", "sql"},
			want:            true,
		},
		{
			name:            "no overlap excluded",
			section:         AnalysisSection{Features: []string{"db", "sql"}},
			enabledFeatures: []string{"web", "api"},
			want:            false,
		},
		{
			name:            "single match",
			section:         AnalysisSection{Features: []string{"auth"}},
			enabledFeatures: []string{"auth"},
			want:            true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sectionEnabled(tt.section, tt.enabledFeatures)
			if got != tt.want {
				t.Errorf("sectionEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

// --- baseName table-driven tests ---

func TestBaseName(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"foo/bar/baz.go", "baz.go"},
		{"baz.go", "baz.go"},
		{"foo/bar/", ""},
		{"", ""},
		{"/leading/slash.txt", "slash.txt"},
		{"single/", ""},
		{"a/b/c/d/e.js", "e.js"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := baseName(tt.path)
			if got != tt.want {
				t.Errorf("baseName(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

// --- isEntrypoint table-driven tests ---

func TestIsEntrypoint(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"main.go", true},
		{"cmd/server/main.go", true},
		{"src/Main.GO", true}, // case-insensitive on base name
		{"app.py", true},
		{"index.js", true},
		{"server.ts", true},
		{"src/routes/users.go", true},
		{"internal/handlers/auth.go", true},
		{"pkg/controllers/admin.rb", true},
		{"src/api/v1.go", true},
		{"lib/middleware/cors.js", true},
		{"src/ROUTES/upper.go", true}, // case-insensitive on path
		{"util.go", false},
		{"src/helpers/format.go", false},
		{"README.md", false},
		{"main_test.go", false},
		{"application.go", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isEntrypoint(tt.path)
			if got != tt.want {
				t.Errorf("isEntrypoint(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// --- BuildFeatureSamples tests ---

func TestBuildFeatureSamples_PrioritizesManifests(t *testing.T) {
	files := []FileEntry{
		{Path: "src/util.go", Content: "package util"},
		{Path: "package.json", Content: `{"name":"app","dependencies":{}}`},
		{Path: "go.mod", Content: "module example.com/app\ngo 1.22"},
	}

	out := BuildFeatureSamples(files, 10000)

	if !strings.Contains(out, `<file path="package.json">`) {
		t.Error("output missing package.json manifest")
	}
	if !strings.Contains(out, `<file path="go.mod">`) {
		t.Error("output missing go.mod manifest")
	}
	if !strings.Contains(out, "module example.com/app") {
		t.Error("output missing go.mod content")
	}
	if strings.Contains(out, "src/util.go") {
		t.Error("non-entrypoint non-manifest file should not be included")
	}
}

func TestBuildFeatureSamples_IncludesEntrypoints(t *testing.T) {
	files := []FileEntry{
		{Path: "cmd/server/main.go", Content: "package main\nfunc main(){}"},
		{Path: "src/routes/users.go", Content: "package routes\nfunc Users(){}"},
		{Path: "docs/README.md", Content: "# readme"},
	}

	out := BuildFeatureSamples(files, 10000)

	if !strings.Contains(out, `<file path="cmd/server/main.go">`) {
		t.Error("output missing main.go entrypoint")
	}
	if !strings.Contains(out, `<file path="src/routes/users.go">`) {
		t.Error("output missing routes/ entrypoint")
	}
	if strings.Contains(out, "README.md") {
		t.Error("non-entrypoint file should not be included")
	}
}

func TestBuildFeatureSamples_SkipsGoSum(t *testing.T) {
	files := []FileEntry{
		{Path: "go.sum", Content: "example.com/pkg v1.0.0 h1:abc"},
		{Path: "go.mod", Content: "module x"},
	}

	out := BuildFeatureSamples(files, 10000)

	if strings.Contains(out, "go.sum") {
		t.Error("go.sum should be skipped")
	}
	if !strings.Contains(out, "go.mod") {
		t.Error("go.mod should be included")
	}
}

func TestBuildFeatureSamples_RespectsCharBudget(t *testing.T) {
	big := strings.Repeat("x", 5000)
	files := []FileEntry{
		{Path: "package.json", Content: big},
		{Path: "go.mod", Content: big},
		{Path: "Cargo.toml", Content: big},
	}

	// maxTokens=100 → maxChars=400, so only part of the first file fits.
	out := BuildFeatureSamples(files, 100)

	if len(out) > 400 {
		t.Errorf("output length = %d, want <= 400", len(out))
	}
}

func TestBuildFeatureSamples_TruncatesEntrypointLines(t *testing.T) {
	var lines []string
	for i := 0; i < 100; i++ {
		lines = append(lines, "line")
	}
	content := strings.Join(lines, "\n")

	files := []FileEntry{
		{Path: "main.go", Content: content},
	}

	out := BuildFeatureSamples(files, 10000)

	// Entrypoints are capped at 50 lines.
	got := strings.Count(out, "line")
	if got > 50 {
		t.Errorf("entrypoint content has %d 'line' occurrences, want <= 50", got)
	}
}

func TestBuildFeatureSamples_Empty(t *testing.T) {
	out := BuildFeatureSamples(nil, 1000)
	if out != "" {
		t.Errorf("BuildFeatureSamples(nil) = %q, want empty", out)
	}
}

// --- Audit prompt tests ---

const testAuditYAML = `system_message: >
  You are an auditor. {production_only_gate}

user_prompt_template: >
  Repo: {repo_name}
  Findings:
  {findings_json}
  CWE Prompts:
  {cwe_analysis_prompts}
  Code:
  {code_context}
  Gate: {production_only_gate}

json_formatting_rules: >
  Respond with JSON matching:
  {schema}

production_only_gate: >
  PRODUCTION-ONLY: prove reachability from production entrypoints.
`

const testCWEYAML = `cwe_prompts:
  CWE-89:
    title: "SQL Injection"
    analysis_prompt: "Trace user input to SQL queries."
    validation_checks:
      - "Input reaches query unsanitized"
      - "No parameterized queries"
    false_positive_indicators:
      - "Input is constant"
  CWE-79:
    title: "XSS"
    analysis_prompt: "Check output encoding."
    validation_checks: []
    false_positive_indicators: []
`

func testAuditFS() fstest.MapFS {
	return fstest.MapFS{
		"audit.yaml":             &fstest.MapFile{Data: []byte(testAuditYAML)},
		"cwe_deep_analysis.yaml": &fstest.MapFile{Data: []byte(testCWEYAML)},
	}
}

func TestLoadAuditPrompt(t *testing.T) {
	loader := NewPromptLoader(testAuditFS())

	ap, err := loader.LoadAuditPrompt()
	if err != nil {
		t.Fatalf("LoadAuditPrompt() error: %v", err)
	}

	if !strings.Contains(ap.SystemMessage, "auditor") {
		t.Errorf("SystemMessage = %q, want to contain 'auditor'", ap.SystemMessage)
	}
	if !strings.Contains(ap.UserPromptTemplate, "{findings_json}") {
		t.Errorf("UserPromptTemplate missing {findings_json} placeholder")
	}
	if !strings.Contains(ap.ProductionOnlyGate, "PRODUCTION-ONLY") {
		t.Errorf("ProductionOnlyGate = %q, want to contain 'PRODUCTION-ONLY'", ap.ProductionOnlyGate)
	}

	// Second call should return cached instance.
	ap2, err := loader.LoadAuditPrompt()
	if err != nil {
		t.Fatalf("cached LoadAuditPrompt() error: %v", err)
	}
	if ap != ap2 {
		t.Error("expected cached pointer on second call")
	}
}

func TestLoadAuditPrompt_MissingFile(t *testing.T) {
	loader := NewPromptLoader(fstest.MapFS{})

	_, err := loader.LoadAuditPrompt()
	if err == nil {
		t.Fatal("LoadAuditPrompt() with missing file should return error")
	}
	if !strings.Contains(err.Error(), "loading audit prompt") {
		t.Errorf("error = %q, want to contain 'loading audit prompt'", err.Error())
	}
}

func TestLoadCWEPrompts(t *testing.T) {
	loader := NewPromptLoader(testAuditFS())

	cf, err := loader.LoadCWEPrompts()
	if err != nil {
		t.Fatalf("LoadCWEPrompts() error: %v", err)
	}

	if len(cf.CWEPrompts) != 2 {
		t.Fatalf("got %d CWE prompts, want 2", len(cf.CWEPrompts))
	}

	sqli, ok := cf.CWEPrompts["CWE-89"]
	if !ok {
		t.Fatal("missing CWE-89 entry")
	}
	if sqli.Title != "SQL Injection" {
		t.Errorf("CWE-89.Title = %q, want %q", sqli.Title, "SQL Injection")
	}
	if len(sqli.ValidationChecks) != 2 {
		t.Errorf("CWE-89.ValidationChecks length = %d, want 2", len(sqli.ValidationChecks))
	}
	if len(sqli.FalsePositiveIndicators) != 1 {
		t.Errorf("CWE-89.FalsePositiveIndicators length = %d, want 1", len(sqli.FalsePositiveIndicators))
	}

	// Second call should return cached instance.
	cf2, err := loader.LoadCWEPrompts()
	if err != nil {
		t.Fatalf("cached LoadCWEPrompts() error: %v", err)
	}
	if cf != cf2 {
		t.Error("expected cached pointer on second call")
	}
}

func TestLoadCWEPrompts_MissingFile(t *testing.T) {
	loader := NewPromptLoader(fstest.MapFS{})

	_, err := loader.LoadCWEPrompts()
	if err == nil {
		t.Fatal("LoadCWEPrompts() with missing file should return error")
	}
	if !strings.Contains(err.Error(), "loading CWE prompts") {
		t.Errorf("error = %q, want to contain 'loading CWE prompts'", err.Error())
	}
}

func TestAssembleAuditMessages_ProductionOnlyTrue(t *testing.T) {
	loader := NewPromptLoader(testAuditFS())

	msgs, err := loader.AssembleAuditMessages(AuditParams{
		RepoName:       "audit-repo",
		FindingsJSON:   `[{"id":1}]`,
		CodeContext:    "func vuln(){}",
		CWEIDs:         []string{"CWE-89"},
		Schema:         `{"type":"array"}`,
		ProductionOnly: true,
	})
	if err != nil {
		t.Fatalf("AssembleAuditMessages() error: %v", err)
	}

	if len(msgs) != 2 {
		t.Fatalf("got %d messages, want 2", len(msgs))
	}

	system := msgs[0].Content
	user := msgs[1].Content

	if !strings.Contains(system, "PRODUCTION-ONLY") {
		t.Error("system message missing production gate when ProductionOnly=true")
	}
	if !strings.Contains(user, "PRODUCTION-ONLY") {
		t.Error("user message missing production gate when ProductionOnly=true")
	}
	if strings.Contains(user, "{production_only_gate}") {
		t.Error("user message has unsubstituted {production_only_gate} placeholder")
	}
	if !strings.Contains(user, "audit-repo") {
		t.Error("user message missing repo name substitution")
	}
	if !strings.Contains(user, `[{"id":1}]`) {
		t.Error("user message missing findings JSON")
	}
	if !strings.Contains(user, "func vuln(){}") {
		t.Error("user message missing code context")
	}
	if !strings.Contains(user, `{"type":"array"}`) {
		t.Error("user message missing schema substitution")
	}
	if !strings.Contains(user, "SQL Injection") {
		t.Error("user message missing CWE-89 prompt content")
	}
}

func TestAssembleAuditMessages_ProductionOnlyFalse(t *testing.T) {
	loader := NewPromptLoader(testAuditFS())

	msgs, err := loader.AssembleAuditMessages(AuditParams{
		RepoName:       "audit-repo",
		FindingsJSON:   `[]`,
		CodeContext:    "code",
		CWEIDs:         nil,
		Schema:         "{}",
		ProductionOnly: false,
	})
	if err != nil {
		t.Fatalf("AssembleAuditMessages() error: %v", err)
	}

	system := msgs[0].Content
	user := msgs[1].Content

	if strings.Contains(system, "PRODUCTION-ONLY") {
		t.Error("system message should not contain production gate when ProductionOnly=false")
	}
	if strings.Contains(user, "PRODUCTION-ONLY") {
		t.Error("user message should not contain production gate when ProductionOnly=false")
	}
	if strings.Contains(system, "{production_only_gate}") {
		t.Error("system message has unsubstituted {production_only_gate} placeholder")
	}
	if strings.Contains(user, "{production_only_gate}") {
		t.Error("user message has unsubstituted {production_only_gate} placeholder")
	}
}

func TestAssembleAuditMessages_MissingAuditTemplate(t *testing.T) {
	loader := NewPromptLoader(fstest.MapFS{})

	_, err := loader.AssembleAuditMessages(AuditParams{RepoName: "x"})
	if err == nil {
		t.Fatal("AssembleAuditMessages() with missing template should return error")
	}
}

func TestAssembleAuditMessages_MissingCWEFile(t *testing.T) {
	// Audit template present but CWE file missing: should not fail.
	fsys := fstest.MapFS{
		"audit.yaml": &fstest.MapFile{Data: []byte(testAuditYAML)},
	}
	loader := NewPromptLoader(fsys)

	msgs, err := loader.AssembleAuditMessages(AuditParams{
		RepoName: "x",
		CWEIDs:   []string{"CWE-89"},
	})
	if err != nil {
		t.Fatalf("AssembleAuditMessages() should not fail without CWE file: %v", err)
	}

	user := msgs[1].Content
	if !strings.Contains(user, "CWE-specific prompts not available") {
		t.Error("user message missing fallback text for unavailable CWE prompts")
	}
}

// --- buildCWESection tests ---

func TestBuildCWESection_MatchesAndFormats(t *testing.T) {
	loader := NewPromptLoader(testAuditFS())

	out, err := loader.buildCWESection([]string{"CWE-89"})
	if err != nil {
		t.Fatalf("buildCWESection() error: %v", err)
	}

	if !strings.Contains(out, "### CWE-89: SQL Injection") {
		t.Error("output missing CWE-89 header")
	}
	if !strings.Contains(out, "Trace user input to SQL queries") {
		t.Error("output missing analysis prompt")
	}
	if !strings.Contains(out, "Validation Checks:") {
		t.Error("output missing validation checks header")
	}
	if !strings.Contains(out, "Input reaches query unsanitized") {
		t.Error("output missing validation check item")
	}
	if !strings.Contains(out, "False Positive Indicators:") {
		t.Error("output missing false positive header")
	}
	if !strings.Contains(out, "Input is constant") {
		t.Error("output missing false positive indicator")
	}
}

func TestBuildCWESection_NormalizesIDs(t *testing.T) {
	loader := NewPromptLoader(testAuditFS())

	out, err := loader.buildCWESection([]string{
		"cwe-89: SQL Injection",
		"CWE-89",   // duplicate after normalization
		" CWE-79 ", // whitespace
	})
	if err != nil {
		t.Fatalf("buildCWESection() error: %v", err)
	}

	if strings.Count(out, "### CWE-89") != 1 {
		t.Error("CWE-89 should appear exactly once after dedup")
	}
	if !strings.Contains(out, "### CWE-79: XSS") {
		t.Error("output missing normalized CWE-79 entry")
	}
}

func TestBuildCWESection_NoMatches(t *testing.T) {
	loader := NewPromptLoader(testAuditFS())

	out, err := loader.buildCWESection([]string{"CWE-999"})
	if err != nil {
		t.Fatalf("buildCWESection() error: %v", err)
	}

	if !strings.Contains(out, "No CWE-specific prompts matched") {
		t.Errorf("output = %q, want fallback message", out)
	}
}

func TestBuildCWESection_EmptyInput(t *testing.T) {
	loader := NewPromptLoader(testAuditFS())

	out, err := loader.buildCWESection(nil)
	if err != nil {
		t.Fatalf("buildCWESection() error: %v", err)
	}

	if !strings.Contains(out, "No CWE-specific prompts matched") {
		t.Errorf("output = %q, want fallback message for empty input", out)
	}
}
