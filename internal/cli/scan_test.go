package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/block/codecrucible/internal/chunk"
	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/sarif"
)

// createTestRepo creates a temp directory with a few Go source files for testing.
func createTestRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	// Create a source file.
	srcDir := filepath.Join(dir, "src")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "handler.go"), []byte("package main\n\nfunc handler() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a prompts/default directory so the scan command can find templates.
	promptsDir := filepath.Join(dir, "prompts", "default")
	if err := os.MkdirAll(promptsDir, 0755); err != nil {
		t.Fatal(err)
	}
	basePrompt := `system_message: "You are a security analyst."
analysis_intro: "Analyze the code."
infrastructure_note: ""
analysis_requirements_header: ""
custom_requirements_placeholder: ""
repo_info: "Repo: {repo_name}\n{xml_content}"
critical_instructions: "Be thorough."
json_formatting_rules: "Return JSON: {schema}"
`
	if err := os.WriteFile(filepath.Join(promptsDir, "security_analysis_base.yaml"), []byte(basePrompt), 0644); err != nil {
		t.Fatal(err)
	}

	return dir
}

func TestScanCommand_DryRunWithRepo(t *testing.T) {
	dir := createTestRepo(t)

	// Change to the test repo dir so prompts are found.
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	defer func() {
		if err := os.Chdir(origDir); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	}()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir to test repo: %v", err)
	}

	cmd := NewRootCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"scan", "--dry-run", dir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Dry run should print scope info to stdout.
	// Note: output goes to os.Stdout from fmt.Printf, not cmd's buffer.
	// Just verify no error occurred.
}

func TestScanCommand_EmptyRepoProducesValidSARIF(t *testing.T) {
	// Create an empty directory (no source files).
	dir := t.TempDir()
	outFile := filepath.Join(dir, "results.sarif")

	cmd := NewRootCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"scan", "--output", outFile, dir})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Verify output file is valid SARIF.
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}

	var doc sarif.SARIFDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}

	if doc.Version != "2.1.0" {
		t.Errorf("version: got %q, want %q", doc.Version, "2.1.0")
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(doc.Runs))
	}
	if len(doc.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results for empty repo, got %d", len(doc.Runs[0].Results))
	}
	// Should have a notification about no source files.
	if len(doc.Runs[0].Invocations) > 0 && len(doc.Runs[0].Invocations[0].ToolExecutionNotifications) > 0 {
		msg := doc.Runs[0].Invocations[0].ToolExecutionNotifications[0].Message.Text
		if !strings.Contains(msg, "no source files") {
			t.Errorf("expected notification about no source files, got: %s", msg)
		}
	}
}

func TestScanCommand_MissingCredentialsReturnsError(t *testing.T) {
	dir := createTestRepo(t)
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	defer func() {
		if err := os.Chdir(origDir); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	}()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir to test repo: %v", err)
	}

	// Clear all provider env vars so no provider can be configured.
	t.Setenv("DATABRICKS_HOST", "")
	t.Setenv("DATABRICKS_TOKEN", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("PATH", t.TempDir())

	cmd := NewRootCommand()
	cmd.SetArgs([]string{"scan", dir})

	err = cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing credentials")
	}
	// With no API keys and no Claude CLI on PATH, auth setup should fail.
	// Exact wording varies by which provider the resolver picked; match
	// on the universal bit.
	if !strings.Contains(strings.ToLower(err.Error()), "api key") && !strings.Contains(err.Error(), "is not set") {
		t.Errorf("expected missing-credentials error, got: %v", err)
	}
}

func TestBuildLLMClient_AnthropicFallsBackToClaudeCLI(t *testing.T) {
	dir := t.TempDir()
	claudePath := filepath.Join(dir, "claude")
	script := "#!/bin/sh\nexit 0\n"
	if err := os.WriteFile(claudePath, []byte(script), 0755); err != nil {
		t.Fatalf("write fake claude: %v", err)
	}
	t.Setenv("PATH", dir)

	client, endpoint, err := buildPhaseClient(config.PhaseConfig{
		Provider: "anthropic",
		ModelCfg: config.ModelConfig{Name: "claude-sonnet-4-6"},
		// APIKey deliberately empty — exercises the CLI fallback path.
	}, &config.Config{})
	if err != nil {
		t.Fatalf("buildPhaseClient returned error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if endpoint != "" {
		t.Fatalf("endpoint = %q, want empty", endpoint)
	}
}

func TestScanCommand_MaxCostAbort(t *testing.T) {
	// The default models have $0 pricing, so max-cost only triggers with
	// non-zero pricing. We test the check in resolveModel + cost estimation.
	// Instead, we verify the max-cost flag is accepted and dry-run shows cost.
	dir := createTestRepo(t)
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	defer func() {
		if err := os.Chdir(origDir); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	}()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir to test repo: %v", err)
	}

	cmd := NewRootCommand()
	cmd.SetArgs([]string{"scan", "--max-cost", "100", "--dry-run", dir})

	err = cmd.Execute()
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
}

func TestResolveModel_Default(t *testing.T) {
	m := resolveModel("")
	if m.Name != "claude-sonnet-4-6" {
		t.Errorf("expected default model claude-sonnet-4-6, got %s", m.Name)
	}
}

func TestResolveModel_Known(t *testing.T) {
	m := resolveModel("gpt-5.2")
	if m.Name != "gpt-5.2" {
		t.Errorf("expected gpt-5.2, got %s", m.Name)
	}
	if m.ContextLimit != 400000 {
		t.Errorf("expected context limit 400000, got %d", m.ContextLimit)
	}
}

func TestResolveModel_Unknown(t *testing.T) {
	m := resolveModel("custom-model-v2")
	if m.Name != "custom-model-v2" {
		t.Errorf("expected custom-model-v2, got %s", m.Name)
	}
	if m.ContextLimit != 128000 {
		t.Errorf("expected default context limit 128000, got %d", m.ContextLimit)
	}
}

func TestIngestFiles_PathsUseRepoRootGitignore(t *testing.T) {
	repo := t.TempDir()

	if err := os.WriteFile(filepath.Join(repo, ".gitignore"), []byte("firmware/generated/\n"), 0644); err != nil {
		t.Fatalf("write .gitignore: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(repo, "firmware", "generated"), 0755); err != nil {
		t.Fatalf("mkdir generated: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(repo, "firmware", "src"), 0755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, "firmware", "generated", "ignored.go"), []byte("package generated\n"), 0644); err != nil {
		t.Fatalf("write ignored.go: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, "firmware", "src", "kept.go"), []byte("package main\n"), 0644); err != nil {
		t.Fatalf("write kept.go: %v", err)
	}

	files, err := ingestFiles(repo, &config.Config{Paths: []string{"firmware/"}})
	if err != nil {
		t.Fatalf("ingestFiles: %v", err)
	}

	if len(files) != 1 {
		got := make([]string, len(files))
		for i := range files {
			got[i] = files[i].Path
		}
		t.Fatalf("expected 1 file after gitignore + paths filtering, got %d: %v", len(files), got)
	}
	if files[0].Path != "firmware/src/kept.go" {
		t.Fatalf("expected firmware/src/kept.go, got %s", files[0].Path)
	}
}

func TestIngestFiles_PathsDoNotDuplicateOverlappingEntries(t *testing.T) {
	repo := t.TempDir()

	if err := os.MkdirAll(filepath.Join(repo, "firmware", "src"), 0755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, "firmware", "src", "main.go"), []byte("package main\n"), 0644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}

	files, err := ingestFiles(repo, &config.Config{Paths: []string{"firmware", "firmware/src"}})
	if err != nil {
		t.Fatalf("ingestFiles: %v", err)
	}

	if len(files) != 1 {
		got := make([]string, len(files))
		for i := range files {
			got[i] = files[i].Path
		}
		t.Fatalf("expected 1 deduplicated file, got %d: %v", len(files), got)
	}
	if files[0].Path != "firmware/src/main.go" {
		t.Fatalf("expected firmware/src/main.go, got %s", files[0].Path)
	}
}

func TestIngestAndFilter_PathsAndFiltersMatrix(t *testing.T) {
	repo := t.TempDir()

	writeRepoFile := func(relPath, content string) {
		t.Helper()
		fullPath := filepath.Join(repo, relPath)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(relPath), err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", relPath, err)
		}
	}

	writeRepoFile(".gitignore", "firmware/generated/\n")
	writeRepoFile("firmware/main.c", "int main() { return 0; }\n")
	writeRepoFile("firmware/src/boot.c", "int boot() { return 1; }\n")
	writeRepoFile("firmware/third-party/direct.c", "int dep() { return 2; }\n")
	writeRepoFile("firmware/third-party/nested/deep.c", "int deep() { return 3; }\n")
	writeRepoFile("firmware/generated/should_be_ignored.c", "int ignored() { return 4; }\n")
	writeRepoFile("app/main.go", "package main\n")

	testCases := []struct {
		name    string
		paths   []string
		include []string
		exclude []string
		want    []string
	}{
		{
			name:    "no_paths_exclude_recursive_directory",
			exclude: []string{"firmware/third-party/**"},
			want:    []string{"app/main.go", "firmware/main.c", "firmware/src/boot.c"},
		},
		{
			name:    "firmware_path_with_recursive_exclude",
			paths:   []string{"firmware"},
			exclude: []string{"firmware/third-party/**"},
			want:    []string{"firmware/main.c", "firmware/src/boot.c"},
		},
		{
			name:    "include_overrides_recursive_exclude_within_path_scope",
			paths:   []string{"firmware"},
			include: []string{"firmware/third-party/nested/deep.c"},
			exclude: []string{"firmware/third-party/**"},
			want:    []string{"firmware/main.c", "firmware/src/boot.c", "firmware/third-party/nested/deep.c"},
		},
		{
			name:    "subpath_scope_respected_with_exclude",
			paths:   []string{"firmware/src"},
			exclude: []string{"firmware/third-party/**"},
			want:    []string{"firmware/src/boot.c"},
		},
		{
			name:    "exclude_can_eliminate_all_files_in_selected_path",
			paths:   []string{"firmware/third-party"},
			exclude: []string{"firmware/third-party/**"},
			want:    []string{},
		},
		{
			name:    "overlapping_paths_with_broad_exclude_and_specific_include",
			paths:   []string{"firmware", "firmware/src"},
			include: []string{"firmware/src/boot.c"},
			exclude: []string{"firmware/**"},
			want:    []string{"firmware/src/boot.c"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			files, err := ingestFiles(repo, &config.Config{Paths: tc.paths})
			if err != nil {
				t.Fatalf("ingestFiles: %v", err)
			}

			kept, _ := ingest.FilterFiles(files, ingest.FilterConfig{
				IncludeTests: true,
				IncludeDocs:  true,
				Include:      tc.include,
				Exclude:      tc.exclude,
				MaxFileSize:  0,
			})

			got := make([]string, len(kept))
			for i, f := range kept {
				got[i] = f.Path
			}
			sort.Strings(got)

			want := make([]string, len(tc.want))
			copy(want, tc.want)
			sort.Strings(want)

			if !reflect.DeepEqual(got, want) {
				t.Fatalf("kept files mismatch\n  got:  %v\n  want: %v", got, want)
			}
		})
	}
}

func TestParseCustomHeaders_Valid(t *testing.T) {
	headers, err := parseCustomHeaders([]string{
		"anthropic-beta: context-1m-2025-08-07",
		"x-feature-flag: enabled",
		"anthropic-beta: another-beta",
	})
	if err != nil {
		t.Fatalf("parseCustomHeaders returned error: %v", err)
	}

	betaValues := headers.Values("Anthropic-Beta")
	if len(betaValues) != 2 {
		t.Fatalf("expected 2 Anthropic-Beta values, got %d: %v", len(betaValues), betaValues)
	}
	if betaValues[0] != "context-1m-2025-08-07" || betaValues[1] != "another-beta" {
		t.Fatalf("unexpected Anthropic-Beta values: %v", betaValues)
	}

	if got := headers.Get("X-Feature-Flag"); got != "enabled" {
		t.Fatalf("expected X-Feature-Flag=enabled, got %q", got)
	}
}

func TestParseCustomHeaders_Invalid(t *testing.T) {
	testCases := []struct {
		name    string
		headers []string
	}{
		{name: "missing_separator", headers: []string{"invalid"}},
		{name: "empty_name", headers: []string{": value"}},
		{name: "empty_value", headers: []string{"x-test: "}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseCustomHeaders(tc.headers)
			if err == nil {
				t.Fatalf("expected parseCustomHeaders error for %v", tc.headers)
			}
		})
	}
}

func TestSeverityLevelScan(t *testing.T) {
	testCases := []struct {
		name string
		sev  float64
		want string
	}{
		{name: "zero", sev: 0.0, want: "none"},
		{name: "negative", sev: -1.5, want: "none"},
		{name: "low", sev: 2.0, want: "note"},
		{name: "boundary_note_warning", sev: 3.9, want: "note"},
		{name: "medium_low", sev: 4.0, want: "warning"},
		{name: "medium", sev: 5.5, want: "warning"},
		{name: "boundary_warning_error", sev: 6.9, want: "warning"},
		{name: "high", sev: 7.0, want: "error"},
		{name: "critical", sev: 9.8, want: "error"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := severityLevelScan(tc.sev)
			if got != tc.want {
				t.Errorf("severityLevelScan(%v) = %q, want %q", tc.sev, got, tc.want)
			}
		})
	}
}

func TestCWEForRuleScan(t *testing.T) {
	testCases := []struct {
		name string
		rule sarif.SARIFRule
		want string
	}{
		{
			name: "from_relationship",
			rule: sarif.SARIFRule{
				Relationships: []sarif.SARIFRelationship{{
					Target: sarif.SARIFRelationshipTarget{ID: "CWE-89"},
				}},
			},
			want: "CWE-89",
		},
		{
			name: "relationship_not_cwe_prefix",
			rule: sarif.SARIFRule{
				Relationships: []sarif.SARIFRelationship{{
					Target: sarif.SARIFRelationshipTarget{ID: "OWASP-A01"},
				}},
			},
			want: "",
		},
		{
			name: "from_tags",
			rule: sarif.SARIFRule{
				Properties: map[string]any{
					"tags": []string{"security", "external/cwe/cwe-79"},
				},
			},
			want: "CWE-79",
		},
		{
			name: "tags_wrong_type",
			rule: sarif.SARIFRule{
				Properties: map[string]any{
					"tags": "not-a-slice",
				},
			},
			want: "",
		},
		{
			name: "relationship_wins_over_tags",
			rule: sarif.SARIFRule{
				Relationships: []sarif.SARIFRelationship{{
					Target: sarif.SARIFRelationshipTarget{ID: "CWE-22"},
				}},
				Properties: map[string]any{
					"tags": []string{"external/cwe/cwe-79"},
				},
			},
			want: "CWE-22",
		},
		{
			name: "empty_rule",
			rule: sarif.SARIFRule{},
			want: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := sarif.CWEForRule(tc.rule)
			if got != tc.want {
				t.Errorf("sarif.CWEForRule() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestExtractExportName(t *testing.T) {
	testCases := []struct {
		name string
		line string
		want string
	}{
		{name: "function", line: "export function foo() {", want: "foo()"},
		{name: "async_function", line: "export async function fetchData(url) {", want: "fetchData()"},
		{name: "const", line: "export const bar = 42;", want: "bar"},
		{name: "let", line: "export let mutable = true;", want: "mutable"},
		{name: "class", line: "export class Baz {", want: "Baz"},
		{name: "interface", line: "export interface Props {", want: "Props"},
		{name: "type_alias", line: "export type ID = string;", want: "ID"},
		{name: "generic_type", line: "export type Result<T> = T | Error;", want: "Result"},
		{name: "default_class", line: "export default class App {", want: "App"},
		{name: "no_keyword_match", line: "export { foo, bar };", want: ""},
		{name: "empty_after_keyword", line: "export const ", want: ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractExportName(tc.line)
			if got != tc.want {
				t.Errorf("extractExportName(%q) = %q, want %q", tc.line, got, tc.want)
			}
		})
	}
}

func TestExtractPyName(t *testing.T) {
	testCases := []struct {
		name string
		line string
		want string
	}{
		{name: "def", line: "def foo():", want: "foo"},
		{name: "def_with_args", line: "def process_items(items, *, key=None):", want: "process_items"},
		{name: "class", line: "class Bar:", want: "Bar"},
		{name: "class_with_base", line: "class Child(Parent):", want: "Child"},
		{name: "class_space_before_colon", line: "class Thing :", want: "Thing"},
		{name: "no_match", line: "import os", want: ""},
		{name: "def_no_paren", line: "def ", want: ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractPyName(tc.line)
			if got != tc.want {
				t.Errorf("extractPyName(%q) = %q, want %q", tc.line, got, tc.want)
			}
		})
	}
}

func TestCapManifest(t *testing.T) {
	t.Run("fits_within_budget", func(t *testing.T) {
		paths := []string{"a.go", "b.go", "c.go"}
		got := capManifest(paths, 100)
		if !reflect.DeepEqual(got, paths) {
			t.Errorf("got %v, want %v", got, paths)
		}
	})

	t.Run("zero_budget", func(t *testing.T) {
		got := capManifest([]string{"a.go"}, 0)
		if got != nil {
			t.Errorf("got %v, want nil", got)
		}
	})

	t.Run("negative_budget", func(t *testing.T) {
		got := capManifest([]string{"a.go"}, -10)
		if got != nil {
			t.Errorf("got %v, want nil", got)
		}
	})

	t.Run("truncates_and_appends_note", func(t *testing.T) {
		// capManifest mutates the input via append; use a fresh slice.
		paths := []string{"aaaa", "bbbb", "cccc", "dddd"}
		// Each path costs len+1; "aaaa" = 5, "bbbb" = 10. Budget 9 admits
		// only the first path before the second blows past it.
		got := capManifest(paths, 9)
		if len(got) != 2 {
			t.Fatalf("expected 2 entries (1 kept + note), got %d: %v", len(got), got)
		}
		if got[0] != "aaaa" {
			t.Errorf("first kept = %q, want %q", got[0], "aaaa")
		}
		if !strings.Contains(got[1], "3 more files") {
			t.Errorf("omitted note = %q, want to contain %q", got[1], "3 more files")
		}
	})

	t.Run("empty_input", func(t *testing.T) {
		got := capManifest(nil, 100)
		if len(got) != 0 {
			t.Errorf("got %v, want empty", got)
		}
	})
}

func TestResolvePromptLoader(t *testing.T) {
	t.Run("explicit_dir", func(t *testing.T) {
		dir := t.TempDir()
		loader, err := resolvePromptLoader(dir)
		if err != nil {
			t.Fatalf("resolvePromptLoader(%q) returned error: %v", dir, err)
		}
		if loader == nil {
			t.Fatal("expected non-nil loader")
		}
	})

	t.Run("default_cwd_prompts", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "prompts", "default"), 0755); err != nil {
			t.Fatal(err)
		}
		origDir, err := os.Getwd()
		if err != nil {
			t.Fatalf("Getwd: %v", err)
		}
		defer func() {
			if err := os.Chdir(origDir); err != nil {
				t.Fatalf("restore working directory: %v", err)
			}
		}()
		if err := os.Chdir(dir); err != nil {
			t.Fatalf("chdir: %v", err)
		}

		loader, err := resolvePromptLoader("")
		if err != nil {
			t.Fatalf("resolvePromptLoader(\"\") returned error: %v", err)
		}
		if loader == nil {
			t.Fatal("expected non-nil loader")
		}
	})

	t.Run("not_found", func(t *testing.T) {
		dir := t.TempDir()
		origDir, err := os.Getwd()
		if err != nil {
			t.Fatalf("Getwd: %v", err)
		}
		defer func() {
			if err := os.Chdir(origDir); err != nil {
				t.Fatalf("restore working directory: %v", err)
			}
		}()
		if err := os.Chdir(dir); err != nil {
			t.Fatalf("chdir: %v", err)
		}

		_, err = resolvePromptLoader("")
		if err == nil {
			t.Fatal("expected error when prompts directory not found")
		}
		if !strings.Contains(err.Error(), "prompts directory not found") {
			t.Errorf("unexpected error message: %v", err)
		}
	})
}

// mkSARIFResult builds a SARIFResult with a single physical location. Used by
// applyAuditVerdicts tests so fixtures stay readable.
func mkSARIFResult(ruleID, file string, line int, msg string) sarif.SARIFResult {
	return sarif.SARIFResult{
		RuleID:  ruleID,
		Level:   "warning",
		Message: sarif.SARIFMessage{Text: msg},
		Locations: []sarif.SARIFLocation{{
			PhysicalLocation: sarif.SARIFPhysicalLocation{
				ArtifactLocation: sarif.SARIFArtifactLocation{URI: file},
				Region:           &sarif.SARIFRegion{StartLine: line},
			},
		}},
	}
}

func TestApplyAuditVerdicts_RejectsAndConfirms(t *testing.T) {
	doc := sarif.SARIFDocument{
		Runs: []sarif.SARIFRun{{
			Tool: sarif.SARIFTool{Driver: sarif.SARIFDriver{
				Rules: []sarif.SARIFRule{
					{ID: "R1", Properties: map[string]any{}},
					{ID: "R2", Properties: map[string]any{}},
				},
			}},
			Results: []sarif.SARIFResult{
				mkSARIFResult("R1", "src/a.go", 10, "finding A"),
				mkSARIFResult("R2", "src/b.go", 20, "finding B"),
			},
		}},
	}
	audit := AuditResult{
		AuditedFindings: []AuditedFinding{
			{FilePath: "src/a.go", StartLine: 10, Verdict: "rejected", Confidence: 0.9},
			{FilePath: "src/b.go", StartLine: 20, Verdict: "confirmed", Confidence: 0.95},
		},
	}

	out := applyAuditVerdicts(doc, audit, ingest.FileMap{}, 0.5)

	if len(out.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 kept result, got %d", len(out.Runs[0].Results))
	}
	if out.Runs[0].Results[0].RuleID != "R2" {
		t.Errorf("kept RuleID = %q, want %q", out.Runs[0].Results[0].RuleID, "R2")
	}
	// Only rules for kept results should survive.
	if len(out.Runs[0].Tool.Driver.Rules) != 1 {
		t.Fatalf("expected 1 kept rule, got %d", len(out.Runs[0].Tool.Driver.Rules))
	}
	if out.Runs[0].Tool.Driver.Rules[0].ID != "R2" {
		t.Errorf("kept rule ID = %q, want %q", out.Runs[0].Tool.Driver.Rules[0].ID, "R2")
	}
}

func TestApplyAuditVerdicts_ConfidenceThreshold(t *testing.T) {
	doc := sarif.SARIFDocument{
		Runs: []sarif.SARIFRun{{
			Tool: sarif.SARIFTool{Driver: sarif.SARIFDriver{
				Rules: []sarif.SARIFRule{{ID: "R1", Properties: map[string]any{}}},
			}},
			Results: []sarif.SARIFResult{
				mkSARIFResult("R1", "src/a.go", 10, "finding A"),
			},
		}},
	}
	audit := AuditResult{
		AuditedFindings: []AuditedFinding{
			// Confirmed but below threshold — should be dropped.
			{FilePath: "src/a.go", StartLine: 10, Verdict: "confirmed", Confidence: 0.3},
		},
	}

	out := applyAuditVerdicts(doc, audit, ingest.FileMap{}, 0.7)

	if len(out.Runs[0].Results) != 0 {
		t.Fatalf("expected 0 results after confidence cutoff, got %d", len(out.Runs[0].Results))
	}
}

func TestApplyAuditVerdicts_RefinesSeverityAndMessage(t *testing.T) {
	doc := sarif.SARIFDocument{
		Runs: []sarif.SARIFRun{{
			Tool: sarif.SARIFTool{Driver: sarif.SARIFDriver{
				Rules: []sarif.SARIFRule{{ID: "R1", Properties: map[string]any{}}},
			}},
			Results: []sarif.SARIFResult{
				mkSARIFResult("R1", "src/a.go", 10, "original"),
			},
		}},
	}
	audit := AuditResult{
		AuditedFindings: []AuditedFinding{{
			FilePath:                "src/a.go",
			StartLine:               10,
			Verdict:                 "refined",
			Confidence:              0.9,
			RefinedSeverity:         8.5,
			RefinedTechnicalDetails: "new details",
			Justification:           "because",
		}},
	}

	out := applyAuditVerdicts(doc, audit, ingest.FileMap{}, 0.5)

	if len(out.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(out.Runs[0].Results))
	}
	result := out.Runs[0].Results[0]
	if result.Level != "error" {
		t.Errorf("Level = %q, want %q (severity 8.5)", result.Level, "error")
	}
	if !strings.Contains(result.Message.Text, "new details") {
		t.Errorf("message %q missing refined details", result.Message.Text)
	}
	if !strings.Contains(result.Message.Text, "90%") {
		t.Errorf("message %q missing confidence percentage", result.Message.Text)
	}
	rule := out.Runs[0].Tool.Driver.Rules[0]
	if rule.Properties["security-severity"] != "8.5" {
		t.Errorf("rule security-severity = %v, want %q", rule.Properties["security-severity"], "8.5")
	}
}

func TestApplyAuditVerdicts_UnauditedKeptAsIs(t *testing.T) {
	doc := sarif.SARIFDocument{
		Runs: []sarif.SARIFRun{{
			Tool: sarif.SARIFTool{Driver: sarif.SARIFDriver{
				Rules: []sarif.SARIFRule{{ID: "R1", Properties: map[string]any{}}},
			}},
			Results: []sarif.SARIFResult{
				mkSARIFResult("R1", "src/a.go", 10, "untouched"),
			},
		}},
	}

	out := applyAuditVerdicts(doc, AuditResult{}, ingest.FileMap{}, 0.5)

	if len(out.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 kept result, got %d", len(out.Runs[0].Results))
	}
	if out.Runs[0].Results[0].Message.Text != "untouched" {
		t.Errorf("message = %q, want unchanged", out.Runs[0].Results[0].Message.Text)
	}
}

func TestApplyAuditVerdicts_NewFindings(t *testing.T) {
	doc := sarif.SARIFDocument{
		Runs: []sarif.SARIFRun{{
			Tool:    sarif.SARIFTool{Driver: sarif.SARIFDriver{Rules: []sarif.SARIFRule{}}},
			Results: []sarif.SARIFResult{},
		}},
	}
	audit := AuditResult{
		NewFindings: []NewFinding{
			{
				Issue:            "SQL injection",
				FilePath:         "src/db.go",
				StartLine:        42,
				EndLine:          44,
				TechnicalDetails: "raw query with user input",
				Severity:         8.0,
				CWEID:            "CWE-89",
				Confidence:       0.95,
			},
			{
				// Below threshold — should be filtered out.
				Issue:      "maybe issue",
				FilePath:   "src/x.go",
				StartLine:  1,
				Confidence: 0.2,
			},
		},
	}

	out := applyAuditVerdicts(doc, audit, ingest.FileMap{}, 0.5)

	if len(out.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 new result, got %d", len(out.Runs[0].Results))
	}
	if len(out.Runs[0].Tool.Driver.Rules) != 1 {
		t.Fatalf("expected 1 new rule, got %d", len(out.Runs[0].Tool.Driver.Rules))
	}
}

func TestStreamingTokenCount_MatchesFullXMLCount(t *testing.T) {
	files := []ingest.SourceFile{
		{Path: "cmd/main.go", Content: "package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Println(\"hello\")\n}\n", LineCount: 7, Language: "go"},
		{Path: "internal/handler.go", Content: "package internal\n\ntype Handler struct {\n\tDB *sql.DB\n}\n\nfunc (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {\n\tw.Write([]byte(\"ok\"))\n}\n", LineCount: 9, Language: "go"},
		{Path: "config.yaml", Content: "server:\n  port: 8080\n  host: localhost\n", LineCount: 3, Language: "yaml"},
	}

	cfg := ingest.FlattenConfig{Compress: false}
	full := ingest.Flatten(files, cfg)
	counter := chunk.NewTokenCounter("cl100k_base", nil)

	fullCount := counter.Count(full.XML)
	streamCount := streamingTokenCount(full.FileMap, counter, cfg)

	// The streaming count sums envelope + per-file independently. The full
	// count includes inter-file blank lines and <files></files> wrapper that
	// the streaming count approximates. Allow 5% divergence.
	diff := fullCount - streamCount
	if diff < 0 {
		diff = -diff
	}
	maxDrift := fullCount / 20 // 5%
	if maxDrift < 5 {
		maxDrift = 5
	}
	if diff > maxDrift {
		t.Errorf("streaming count %d diverges from full XML count %d by %d (max allowed %d)",
			streamCount, fullCount, diff, maxDrift)
	}
}
