package llm

import (
	"encoding/json"
	"testing"
)

func TestRepairJSON_CleanInputUnchanged(t *testing.T) {
	in := `{"security_issues":[],"repo_name":"x"}`
	out, changed := RepairJSON(in)
	if changed {
		t.Errorf("clean input should not be changed: out=%q", out)
	}
}

func TestRepairJSON_StripsMarkdownFence(t *testing.T) {
	in := "```json\n{\"security_issues\":[]}\n```"
	out, changed := RepairJSON(in)
	if !changed {
		t.Fatal("expected repair to trigger")
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("repaired output should parse: %v\nout=%q", err, out)
	}
}

func TestRepairJSON_StripsPlainFence(t *testing.T) {
	in := "```\n{\"a\":1}\n```"
	out, changed := RepairJSON(in)
	if !changed || out != `{"a":1}` {
		t.Fatalf("got changed=%v out=%q", changed, out)
	}
}

func TestRepairJSON_ExtractsFromProse(t *testing.T) {
	in := `Here is my analysis:

{"security_issues":[],"repo_name":"x"}

Let me know if you need anything else.`
	out, changed := RepairJSON(in)
	if !changed {
		t.Fatal("expected repair to trigger")
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("repaired output should parse: %v\nout=%q", err, out)
	}
	if m["repo_name"] != "x" {
		t.Errorf("repo_name = %v, want x", m["repo_name"])
	}
}

func TestRepairJSON_CoercesStringToEmptyArray(t *testing.T) {
	// The exact failure from the Java scan: security_issues as a string.
	in := `{"repo_name":"x","security_issues":"No security issues were found in this chunk.","public_api_routes":[]}`
	out, changed := RepairJSON(in)
	if !changed {
		t.Fatal("expected repair to trigger")
	}
	var m struct {
		SecurityIssues []any `json:"security_issues"`
	}
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("repaired output should parse into []any: %v\nout=%q", err, out)
	}
	if len(m.SecurityIssues) != 0 {
		t.Errorf("SecurityIssues = %v, want empty slice", m.SecurityIssues)
	}
}

func TestRepairJSON_CoercesBothArrayFields(t *testing.T) {
	in := `{"security_issues":"none","public_api_routes":"not applicable"}`
	out, changed := RepairJSON(in)
	if !changed {
		t.Fatal("expected repair to trigger")
	}
	var m struct {
		SecurityIssues  []any `json:"security_issues"`
		PublicAPIRoutes []any `json:"public_api_routes"`
	}
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("repaired output should parse: %v\nout=%q", err, out)
	}
}

func TestRepairJSON_LeavesRealArraysAlone(t *testing.T) {
	in := `{"security_issues":[{"issue":"x","file_path":"a.go","start_line":1,"end_line":2,"technical_details":"d","severity":5.0,"cwe_id":"CWE-79"}]}`
	out, changed := RepairJSON(in)
	if changed {
		t.Errorf("valid array should not be coerced: out=%q", out)
	}
}

func TestExtractJSONObject_IgnoresBracesInStrings(t *testing.T) {
	// A path with braces inside a string literal must not confuse depth tracking.
	in := `prose {"k":"a/{b}/c","n":{"m":1}} trailing`
	out, changed := extractJSONObject(in)
	if !changed {
		t.Fatal("expected extraction")
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("extracted object should parse: %v\nout=%q", err, out)
	}
	if m["k"] != "a/{b}/c" {
		t.Errorf("k = %v, want a/{b}/c", m["k"])
	}
}

func TestExtractJSONObject_NoObject(t *testing.T) {
	in := "just some prose with no braces"
	_, changed := extractJSONObject(in)
	if changed {
		t.Error("no-brace input should not change")
	}
}
