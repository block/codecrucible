package llm

import (
	"encoding/json"
	"reflect"
	"strings"

	"github.com/block/codecrucible/internal/auditcore"
)

type auditEnvelopeV3 struct {
	Assessments []auditcore.Assessment `json:"assessments"`
}

// AuditSchemaV3 is derived from the wire contract so its required fields cannot
// silently diverge from the decoder. Internal validation fields are omitted.
func AuditSchemaV3() *json.RawMessage {
	b, _ := json.Marshal(map[string]any{"name": "security_audit_v3", "strict": true, "schema": auditWireSchema(reflect.TypeOf(auditEnvelopeV3{}))})
	raw := json.RawMessage(b)
	return &raw
}
func auditWireSchema(t reflect.Type) map[string]any {
	switch t.Kind() {
	case reflect.Slice:
		return map[string]any{"type": "array", "items": auditWireSchema(t.Elem())}
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Int:
		return map[string]any{"type": "integer"}
	case reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Struct:
		props := map[string]any{}
		required := []string{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := f.Tag.Get("json")
			name, opts, _ := strings.Cut(tag, ",")
			if name == "" || name == "-" || strings.Contains(opts, "omitempty") {
				continue
			}
			props[name] = auditWireSchema(f.Type)
			required = append(required, name)
		}
		describe := func(name, text string) {
			if p, ok := props[name].(map[string]any); ok {
				p["description"] = text
			}
		}
		if t == reflect.TypeOf(auditcore.Assertion{}) {
			props["kind"].(map[string]any)["enum"] = auditcore.Questions
			props["status"].(map[string]any)["enum"] = []string{"established", "refuted", "unknown"}
			props["guard_state"].(map[string]any)["enum"] = []string{"blocks", "does_not_block", "not_found", "unknown"}
			describe("guard_state", "Whether a real control blocks this specific path. For not_found, quote the actual protection point in guard_evidence and leave nonexistent guard expressions empty.")
			for _, name := range []string{"subject_expression", "consumer_expression", "guard_expression", "consumer_input_expression", "guard_input_expression"} {
				describe(name, "Exact source identifier or expression, copied from the corresponding evidence quote. No explanation, file prefix, or natural-language sentence. Use empty when unknown.")
			}
			describe("flow", "Quote-backed renaming/passing steps connecting subject_expression to consumer_input_expression and guard_input_expression. Empty when the expressions are already identical.")
			describe("guard_evidence", "Quote the actual control, or the existing operation where the missing control should act. The guard expression and its input must occur in these quotes.")
		}
		if t == reflect.TypeOf(auditcore.Evidence{}) {
			describe("file", "Exact admitted repository-relative file path. Only framework assumptions may use supplementary_context.")
			describe("quote", "Exact nontrivial source text in the stated inclusive range, without N| prefixes.")
		}
		if t == reflect.TypeOf(auditcore.ContextRequest{}) {
			describe("file", "Exact admitted repository-relative file path. External dependencies and arbitrary filesystem paths are unavailable.")
			describe("symbol", "Exact unqualified declaration name in that file when its line number is unknown. Otherwise empty. Ambiguous declarations are not guessed.")
			describe("start_line", "Use 0 for a symbol request; otherwise the first line of a source range of at most 120 lines.")
			describe("end_line", "Use 0 for a symbol request; otherwise the inclusive last line of the requested range.")
		}
		if t == reflect.TypeOf(auditcore.Coverage{}) {
			describe("material_id", "Copy the original material ID.")
			describe("quote", "Copy the entire original material text exactly for a whole-claim assessment; for a child, copy the exact original assertion it retains.")
		}
		if t == reflect.TypeOf(auditcore.FlowStep{}) {
			describe("from_expression", "Exact source expression occurring in evidence.")
			describe("to_expression", "Exact source expression receiving that value, occurring in evidence.")
		}
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": props}
	default:
		panic("unsupported audit wire type: " + t.String())
	}
}

func DuplicateSchemaV3() *json.RawMessage {
	b, _ := json.Marshal(map[string]any{"name": "security_duplicates_v3", "strict": true, "schema": auditWireSchema(reflect.TypeOf(auditcore.PairJudgment{}))})
	raw := json.RawMessage(b)
	return &raw
}

// SecurityAnalysisSchemaV3 adds optional-in-old-input evidence to the opt-in
// first pass. Strict providers receive a required array; empty is permitted.
func SecurityAnalysisSchemaV3() *json.RawMessage {
	var root map[string]any
	_ = json.Unmarshal([]byte(securityAnalysisSchemaJSON), &root)
	item := root["schema"].(map[string]any)["properties"].(map[string]any)["security_issues"].(map[string]any)["items"].(map[string]any)
	item["required"] = append(item["required"].([]any), "finding_evidence")
	item["properties"].(map[string]any)["finding_evidence"] = map[string]any{"type": "array", "description": "Exact source, entry_point, guard, consumer or sink references for this atomic claim; [] when unavailable.", "items": auditWireSchema(reflect.TypeOf(auditcore.NamedEvidence{}))}
	b, _ := json.Marshal(root)
	raw := json.RawMessage(b)
	return &raw
}
