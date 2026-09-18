package llm

import (
	"encoding/json"
	"github.com/block/codecrucible/internal/config"
	"testing"
)

func TestSecurityAnalysisSchema_BasicShape(t *testing.T) {
	raw := SecurityAnalysisSchema()
	payload := decodeSchemaPayload(t, raw)

	if payload["name"] != "security_analysis" {
		t.Fatalf("schema name = %v, want %q", payload["name"], "security_analysis")
	}
	if payload["strict"] != true {
		t.Fatalf("strict = %v, want true", payload["strict"])
	}

	schemaObj, ok := payload["schema"].(map[string]any)
	if !ok {
		t.Fatalf("schema payload missing object body")
	}
	required, ok := schemaObj["required"].([]any)
	if !ok || len(required) == 0 {
		t.Fatalf("required fields missing from schema")
	}
}

func TestFeatureDetectionSchema_HasDetectedFeatures(t *testing.T) {
	raw := FeatureDetectionSchema()
	payload := decodeSchemaPayload(t, raw)

	if payload["name"] != "feature_detection" {
		t.Fatalf("schema name = %v, want %q", payload["name"], "feature_detection")
	}

	schemaObj := payload["schema"].(map[string]any)
	properties := schemaObj["properties"].(map[string]any)
	detected := properties["detected_features"].(map[string]any)
	items := detected["items"].(map[string]any)
	enumValues := items["enum"].([]any)
	if len(enumValues) == 0 {
		t.Fatal("detected_features enum must not be empty")
	}
}

func TestAuditSchema_BasicShape(t *testing.T) {
	raw := AuditSchema()
	payload := decodeSchemaPayload(t, raw)

	if payload["name"] != "security_audit" {
		t.Fatalf("schema name = %v, want %q", payload["name"], "security_audit")
	}

	schemaObj := payload["schema"].(map[string]any)
	required := schemaObj["required"].([]any)
	if len(required) != 3 {
		t.Fatalf("required field count = %d, want 3", len(required))
	}
}

func TestOutputModeForModel_Classification(t *testing.T) {
	cases := []struct {
		name  string
		model string
		want  OutputMode
	}{
		{name: "gpt", model: "gpt-5.5", want: OutputModeJSONSchema},
		{name: "o-series", model: "o3-mini", want: OutputModeJSONSchema},
		{name: "claude", model: "claude-sonnet-5", want: OutputModeToolUse},
		{name: "gemini", model: "gemini-3.1-pro-preview", want: OutputModeJSONSchema},
		{name: "other", model: "llama-3-405b", want: OutputModeNone},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := OutputModeForModel(tc.model)
			if got != tc.want {
				t.Fatalf("OutputModeForModel(%q) = %q, want %q", tc.model, got, tc.want)
			}
		})
	}
}

func decodeSchemaPayload(t *testing.T, raw *json.RawMessage) map[string]any {
	t.Helper()
	if raw == nil {
		t.Fatal("schema raw message is nil")
	}

	var payload map[string]any
	if err := json.Unmarshal(*raw, &payload); err != nil {
		t.Fatalf("unmarshal schema: %v", err)
	}
	return payload
}

func TestConfiguredOutputMode(t *testing.T) {
	for _, tc := range []struct {
		model config.ModelConfig
		want  OutputMode
	}{
		{config.ModelConfig{Name: "custom-glm", SupportsStructuredOutput: true}, OutputModeJSONSchema},
		{config.ModelConfig{Name: "gpt-custom", SupportsStructuredOutput: false}, OutputModeNone},
		{config.ModelConfig{Name: "claude-sonnet-5", SupportsStructuredOutput: true}, OutputModeToolUse},
	} {
		if got := OutputModeForConfig(tc.model); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.model.Name, got, tc.want)
		}
	}
}

// Cerebras version 2 requires every strict object to disallow extra keys
// and include every property in required, including nested array objects.
func TestStrictSchemaObjects(t *testing.T) {
	var check func(any)
	check = func(value any) {
		switch node := value.(type) {
		case map[string]any:
			if node["type"] == "object" {
				if node["additionalProperties"] != false {
					t.Error("object allows additional properties")
				}
				required := map[string]bool{}
				for _, key := range node["required"].([]any) {
					required[key.(string)] = true
				}
				for key := range node["properties"].(map[string]any) {
					if !required[key] {
						t.Errorf("property %s not required", key)
					}
				}
			}
			for _, child := range node {
				check(child)
			}
		case []any:
			for _, child := range node {
				check(child)
			}
		}
	}
	for _, raw := range []*json.RawMessage{SecurityAnalysisSchema(), FeatureDetectionSchema(), AuditSchema()} {
		check(decodeSchemaPayload(t, raw)["schema"])
	}
}
