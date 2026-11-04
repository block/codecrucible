package llm

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestReasoningPromptSetContract(t *testing.T) {
	for _, name := range []string{"reasoning", "reasoning-recall", "reasoning-investigator"} {
		t.Run(name, func(t *testing.T) { assertReasoningPromptSetContract(t, name) })
	}
}

func assertReasoningPromptSetContract(t *testing.T, name string) {
	t.Helper()
	l := NewPromptLoader(os.DirFS("../../prompts/" + name))
	if _, err := l.Fingerprint(); err != nil {
		t.Fatal(err)
	}
	ap, err := l.LoadAuditPrompt()
	if err != nil {
		t.Fatal(err)
	}
	if ap.Contract != "" {
		t.Fatalf("reasoning experiment changed its audit policy: %q", ap.Contract)
	}
	if ap.AllowsNewFindings() || !(AuditPrompt{}).AllowsNewFindings() {
		t.Fatal("audit addition policy did not preserve the opt-in/default distinction")
	}
	if _, err := l.LoadCWEPrompts(); err != nil {
		t.Fatal(err)
	}
	cp, err := l.LoadContextCompressPrompt()
	if err != nil || !strings.Contains(cp.UserPromptTemplate, "{content}") {
		t.Fatalf("compression template: %+v, %v", cp, err)
	}

	params := PromptParams{RepoName: "fixture", XML: "SOURCE_SENTINEL", Schema: string(*SecurityAnalysisSchema()),
		Manifest: []string{"one.go", "two.go"}, ChunkIndex: 1, ChunkTotal: 2, CustomRequirements: "CUSTOM_SENTINEL", SupplementaryContext: "REFERENCE_SENTINEL"}
	all, err := l.AssembleMessages(params)
	if err != nil {
		t.Fatal(err)
	}
	params.EnabledFeatures = []string{"cryptography"}
	filtered, err := l.AssembleMessages(params)
	if err != nil {
		t.Fatal(err)
	}
	if all[1].Content != filtered[1].Content {
		t.Fatal("feature sampling removed discovery coverage")
	}
	for _, want := range []string{"SOURCE_SENTINEL", "CUSTOM_SENTINEL", "REFERENCE_SENTINEL", "chunk 2 of 2", "security_analysis"} {
		if !strings.Contains(all[1].Content, want) {
			t.Errorf("analysis prompt lost %q", want)
		}
	}

	fd, err := l.AssembleFeatureDetectionMessages(FeaturePromptParams{RepoName: "fixture", Manifest: []string{"one.go"}, Samples: "SAMPLE_SENTINEL"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"one.go", "SAMPLE_SENTINEL", "feature_detection"} {
		if !strings.Contains(fd[1].Content, want) {
			t.Errorf("feature prompt lost %q", want)
		}
	}
	audit, err := l.AssembleAuditMessages(AuditParams{RepoName: "fixture", FindingsJSON: "CLAIMS_SENTINEL", CodeContext: "CODE_SENTINEL",
		Schema: string(*AuditSchemaExistingClaims()), CWEIDs: []string{"CWE-89"}, ProductionOnly: true, SupplementaryContext: "AUDIT_REFERENCE_SENTINEL"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"CLAIMS_SENTINEL", "CODE_SENTINEL", "AUDIT_REFERENCE_SENTINEL", "security_audit", "scanner excluded"} {
		if !strings.Contains(audit[1].Content, want) {
			t.Errorf("audit prompt lost %q", want)
		}
	}
	for _, messages := range [][]Message{all, fd, audit} {
		for _, message := range messages {
			for _, placeholder := range []string{"{repo_name}", "{xml_content}", "{schema}", "{findings_json}", "{code_context}", "{cwe_analysis_prompts}", "{production_only_gate}", "{supplementary_context}"} {
				if strings.Contains(message.Content, placeholder) {
					t.Errorf("unexpanded placeholder %s", placeholder)
				}
			}
		}
	}
}

func TestReasoningRecallIsolatesDiscovery(t *testing.T) {
	for _, name := range []string{"audit.yaml", "cwe_deep_analysis.yaml", "feature_detection.yaml", "context_compress.yaml"} {
		baseline, err := os.ReadFile("../../prompts/reasoning/" + name)
		if err != nil {
			t.Fatal(err)
		}
		candidate, err := os.ReadFile("../../prompts/reasoning-recall/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if string(baseline) != string(candidate) {
			t.Errorf("recall experiment changes %s outside discovery", name)
		}
	}
}

func TestReasoningInvestigatorIsolatesFraming(t *testing.T) {
	for _, name := range []string{"analysis_sections.yaml", "audit.yaml", "cwe_deep_analysis.yaml", "feature_detection.yaml", "context_compress.yaml"} {
		baseline, err := os.ReadFile("../../prompts/reasoning-recall/" + name)
		if err != nil {
			t.Fatal(err)
		}
		candidate, err := os.ReadFile("../../prompts/reasoning-investigator/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if string(baseline) != string(candidate) {
			t.Errorf("investigator experiment changes %s outside framing", name)
		}
	}
	baseline, err := NewPromptLoader(os.DirFS("../../prompts/reasoning-recall")).LoadBasePrompt()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := NewPromptLoader(os.DirFS("../../prompts/reasoning-investigator")).LoadBasePrompt()
	if err != nil {
		t.Fatal(err)
	}
	if baseline.SystemMessage == candidate.SystemMessage {
		t.Fatal("investigator framing is unchanged")
	}
	baseline.SystemMessage, candidate.SystemMessage = "", ""
	if !reflect.DeepEqual(baseline, candidate) {
		t.Fatal("investigator experiment changes the discovery contract outside its system message")
	}
}

func TestAuditSchemaExistingClaims(t *testing.T) {
	for _, tc := range []struct {
		name    string
		raw     *json.RawMessage
		limited bool
	}{{"default", AuditSchema(), false}, {"existing", AuditSchemaExistingClaims(), true}} {
		t.Run(tc.name, func(t *testing.T) {
			var schema struct {
				Schema struct {
					Properties map[string]struct {
						MaxItems *int `json:"maxItems"`
					} `json:"properties"`
				} `json:"schema"`
			}
			if err := json.Unmarshal(*tc.raw, &schema); err != nil {
				t.Fatal(err)
			}
			limit := schema.Schema.Properties["new_findings"].MaxItems
			if (limit != nil) != tc.limited || (limit != nil && *limit != 0) {
				t.Fatalf("new_findings limit = %v", limit)
			}
		})
	}
}
