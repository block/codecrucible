package llm

import (
	"encoding/json"
	"regexp"
	"strings"
)

// RepairJSON attempts to extract a valid JSON object from LLM output that
// didn't quite follow the schema. It handles the common failure modes:
// markdown fences, prose preamble, and string-where-array-expected.
// Returns the repaired JSON and true if any repair was applied.
// Callers should try the original parse first and only call this on failure.
func RepairJSON(raw string) (string, bool) {
	repaired := raw
	changed := false

	// Strip markdown code fences: ```json ... ``` or ``` ... ```.
	if s, ok := stripCodeFence(repaired); ok {
		repaired, changed = s, true
	}

	// If the model wrote prose around the JSON, extract the outermost object.
	if s, ok := extractJSONObject(repaired); ok {
		repaired, changed = s, true
	}

	// Coerce string values into empty arrays for fields the schema declares
	// as arrays — models sometimes write "none found" instead of [].
	if s, ok := coerceStringsToEmptyArrays(repaired); ok {
		repaired, changed = s, true
	}

	return repaired, changed
}

var fenceRE = regexp.MustCompile("(?s)```(?:json)?\\s*\\n(.*?)\\n```")

func stripCodeFence(s string) (string, bool) {
	trimmed := strings.TrimSpace(s)
	if !strings.HasPrefix(trimmed, "```") {
		return s, false
	}
	if m := fenceRE.FindStringSubmatch(trimmed); len(m) == 2 {
		return m[1], true
	}
	return s, false
}

// extractJSONObject finds the first { and its matching } using a depth counter.
// It ignores braces inside string literals so a path like "a/{b}/c" doesn't
// confuse the balance. Returns the substring and true if it's not already the
// entire input.
func extractJSONObject(s string) (string, bool) {
	start := strings.IndexByte(s, '{')
	if start < 0 {
		return s, false
	}
	depth := 0
	inStr := false
	esc := false
	for i := start; i < len(s); i++ {
		c := s[i]
		if esc {
			esc = false
			continue
		}
		if c == '\\' {
			esc = true
			continue
		}
		if c == '"' {
			inStr = !inStr
			continue
		}
		if inStr {
			continue
		}
		switch c {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				extracted := s[start : i+1]
				if extracted == strings.TrimSpace(s) {
					return s, false
				}
				return extracted, true
			}
		}
	}
	return s, false
}

// arrayFields lists the AnalysisResult fields that must be arrays. Models
// occasionally emit a string like "no issues" for these when the answer is
// empty; we coerce those to [].
var arrayFields = []string{"security_issues", "public_api_routes"}

func coerceStringsToEmptyArrays(s string) (string, bool) {
	var payload map[string]any
	if err := json.Unmarshal([]byte(s), &payload); err != nil {
		return s, false
	}
	changed := false
	for _, f := range arrayFields {
		v, ok := payload[f]
		if !ok {
			continue
		}
		if _, isString := v.(string); isString {
			payload[f] = []any{}
			changed = true
		}
	}
	if !changed {
		return s, false
	}
	out, err := json.Marshal(payload)
	if err != nil {
		return s, false
	}
	return string(out), true
}
