package llm

import "encoding/json"

// AuditQuestions are the evidentiary questions the v2 audit answers for each
// claim, in prompt order. Each has the same polarity: "established" supports
// the finding and "refuted" defeats it, so code can compute the verdict.
var AuditQuestions = []string{"attacker_control", "privilege_boundary", "unmitigated"}

// AuditSchemaV2 returns the JSON Schema for the v2 audit contract: per-claim
// answers with quoted evidence instead of a model-chosen verdict.
func AuditSchemaV2() *json.RawMessage {
	schema := json.RawMessage(auditSchemaV2JSON)
	return &schema
}

const auditAnswerJSON = `{
              "type": "object",
              "additionalProperties": false,
              "required": ["status", "reason", "evidence"],
              "properties": {
                "status": {"type": "string", "enum": ["established", "refuted", "unknown"]},
                "reason": {"type": "string", "description": "One sentence."},
                "evidence": {
                  "type": "array",
                  "description": "Source lines that support the status, quoted exactly from the numbered source. Required for refuted.",
                  "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["file", "line", "quote"],
                    "properties": {
                      "file": {"type": "string"},
                      "line": {"type": "integer"},
                      "quote": {"type": "string", "description": "Exact text of that line, or a contiguous part of it, without the line-number prefix."}
                    }
                  }
                }
              }
            }`

const auditSchemaV2JSON = `{
  "name": "security_audit_v2",
  "strict": true,
  "schema": {
    "type": "object",
    "additionalProperties": false,
    "required": ["assessments", "leads"],
    "properties": {
      "assessments": {
        "type": "array",
        "description": "Exactly one assessment per claim, in claim order.",
        "items": {
          "type": "object",
          "additionalProperties": false,
          "required": ["finding_id", "attacker_control", "privilege_boundary", "unmitigated", "deployment_exposure", "duplicate_of", "refined_severity", "refined_cwe_id", "crux", "summary", "remediation"],
          "properties": {
            "finding_id": {"type": "string", "description": "The claim's finding_id, copied exactly."},
            "attacker_control": ` + auditAnswerJSON + `,
            "privilege_boundary": ` + auditAnswerJSON + `,
            "unmitigated": ` + auditAnswerJSON + `,
            "deployment_exposure": {
              "type": "object",
              "additionalProperties": false,
              "required": ["status", "detail", "evidence"],
              "properties": {
                "status": {"type": "string", "enum": ["default_on", "config_enabled", "config_dependent", "not_deployed", "unknown"]},
                "detail": {"type": "string", "description": "The enabling configuration key or deployment fact, or empty."},
                "evidence": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["file", "line", "quote"],
                    "properties": {
                      "file": {"type": "string"},
                      "line": {"type": "integer"},
                      "quote": {"type": "string"}
                    }
                  }
                }
              }
            },
            "duplicate_of": {"type": "string", "description": "finding_id of another claim in this batch with the same root cause and fix, or empty."},
            "refined_severity": {"type": "number", "description": "Severity 0-10 for the attacker and impact actually supported by the source."},
            "refined_cwe_id": {"type": "string", "description": "A more accurate CWE, or empty to keep the claim's."},
            "crux": {"type": "string", "description": "When any answer is unknown: the specific code or fact that would decide it. Otherwise empty."},
            "summary": {"type": "string", "description": "2-4 sentence reviewer summary of the audited conclusion, at most 1000 characters; empty to keep the claim's."},
            "remediation": {"type": "string", "description": "Concise fix, or empty to keep the claim's."}
          }
        }
      },
      "leads": {
        "type": "array",
        "description": "Short notes on possible issues outside the claims, for a human to follow up. Not findings.",
        "items": {"type": "string"}
      }
    }
  }
}`
