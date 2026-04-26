package sarif

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const fixtureDir = "../../testdata/fixtures/llm-responses"

// stripMarkdownFences removes ```json ... ``` wrapping from LLM output.
func stripMarkdownFences(data []byte) []byte {
	s := strings.TrimSpace(string(data))
	re := regexp.MustCompile("(?s)^```(?:json)?\\s*\n?(.*?)\\s*```$")
	if m := re.FindStringSubmatch(s); len(m) == 2 {
		return []byte(m[1])
	}
	return data
}

func TestContract_LLMResponseFixtures(t *testing.T) {
	tests := []struct {
		file            string
		wantUnmarshalOK bool
		wantIssues      int // expected issue count (-1 = don't check)
		wantRoutes      int // expected route count (-1 = don't check)
		stripMarkdown   bool
	}{
		// Valid fixtures
		{
			file:            "valid_claude_single_finding.json",
			wantUnmarshalOK: true,
			wantIssues:      1,
			wantRoutes:      0,
		},
		{
			file:            "valid_gpt_multiple_findings.json",
			wantUnmarshalOK: true,
			wantIssues:      3,
			wantRoutes:      0,
		},
		{
			file:            "valid_gemini_zero_findings.json",
			wantUnmarshalOK: true,
			wantIssues:      0,
			wantRoutes:      0,
		},
		{
			file:            "valid_with_api_routes.json",
			wantUnmarshalOK: true,
			wantIssues:      2,
			wantRoutes:      3,
		},

		// Malformed fixtures — still parseable by Go's json package
		{
			file:            "malformed_missing_fields.json",
			wantUnmarshalOK: true,
			wantIssues:      1,
			wantRoutes:      0,
		},
		{
			file:            "malformed_extra_fields.json",
			wantUnmarshalOK: true,
			wantIssues:      1,
			wantRoutes:      0,
		},
		{
			file:            "malformed_empty_arrays.json",
			wantUnmarshalOK: true,
			wantIssues:      0,
			wantRoutes:      0,
		},
		{
			file:            "malformed_null_values.json",
			wantUnmarshalOK: true,
			wantIssues:      1,
			wantRoutes:      0,
		},

		// Type mismatch — json.Unmarshal will fail
		{
			file:            "malformed_wrong_types.json",
			wantUnmarshalOK: false,
			wantIssues:      -1,
			wantRoutes:      -1,
		},

		// Markdown-wrapped — needs fence stripping first
		{
			file:            "malformed_markdown_wrapped.json",
			wantUnmarshalOK: true,
			wantIssues:      1,
			wantRoutes:      0,
			stripMarkdown:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			path := filepath.Join(fixtureDir, tt.file)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("failed to read fixture %s: %v", tt.file, err)
			}

			data := raw
			if tt.stripMarkdown {
				data = stripMarkdownFences(raw)
			}

			var result AnalysisResult
			unmarshalErr := json.Unmarshal(data, &result)

			if tt.wantUnmarshalOK && unmarshalErr != nil {
				t.Fatalf("expected unmarshal to succeed, got: %v", unmarshalErr)
			}
			if !tt.wantUnmarshalOK && unmarshalErr == nil {
				t.Fatal("expected unmarshal to fail, but it succeeded")
			}

			// Even on unmarshal failure, Build() must not panic and must
			// produce valid SARIF from the zero/partial result.
			doc := Build(result, nil, BuilderConfig{})

			sarifJSON, err := json.Marshal(doc)
			if err != nil {
				t.Fatalf("json.Marshal of SARIF document failed: %v", err)
			}
			if !json.Valid(sarifJSON) {
				t.Fatal("Build() produced invalid JSON")
			}

			// Verify SARIF schema and version.
			var parsed SARIFDocument
			if err := json.Unmarshal(sarifJSON, &parsed); err != nil {
				t.Fatalf("failed to re-parse SARIF output: %v", err)
			}
			if parsed.Schema != sarifSchema {
				t.Errorf("schema = %q, want %q", parsed.Schema, sarifSchema)
			}
			if parsed.Version != sarifVersion {
				t.Errorf("version = %q, want %q", parsed.Version, sarifVersion)
			}
			if len(parsed.Runs) != 1 {
				t.Fatalf("expected 1 run, got %d", len(parsed.Runs))
			}

			// Verify counts when expected.
			if tt.wantIssues >= 0 {
				got := len(parsed.Runs[0].Results)
				if got != tt.wantIssues {
					t.Errorf("result count = %d, want %d", got, tt.wantIssues)
				}
			}
			if tt.wantRoutes >= 0 && tt.wantUnmarshalOK {
				got := len(result.PublicAPIRoutes)
				if got != tt.wantRoutes {
					t.Errorf("route count = %d, want %d", got, tt.wantRoutes)
				}
			}
		})
	}
}

// TestContract_MarkdownStripping verifies that the fence-stripping helper
// correctly unwraps markdown-wrapped JSON so it can be parsed.
func TestContract_MarkdownStripping(t *testing.T) {
	path := filepath.Join(fixtureDir, "malformed_markdown_wrapped.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	// Raw content should NOT parse as valid JSON.
	if json.Valid(raw) {
		t.Fatal("expected raw markdown-wrapped content to be invalid JSON")
	}

	// After stripping, it should parse.
	stripped := stripMarkdownFences(raw)
	if !json.Valid(stripped) {
		t.Fatal("expected stripped content to be valid JSON")
	}

	var result AnalysisResult
	if err := json.Unmarshal(stripped, &result); err != nil {
		t.Fatalf("unmarshal of stripped content failed: %v", err)
	}
	if len(result.SecurityIssues) != 1 {
		t.Errorf("expected 1 security issue, got %d", len(result.SecurityIssues))
	}
}
