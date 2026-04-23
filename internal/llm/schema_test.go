package llm

import (
	"encoding/json"
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
		{name: "gpt", model: "gpt-5.2", want: OutputModeJSONSchema},
		{name: "o-series", model: "o3-mini", want: OutputModeJSONSchema},
		{name: "claude", model: "claude-sonnet-4-6", want: OutputModeToolUse},
		{name: "gemini", model: "gemini-3-pro", want: OutputModeJSONSchema},
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
