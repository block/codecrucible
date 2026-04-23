package llm

import (
	"encoding/json"
	"strings"
)

// SecurityAnalysisSchema returns the JSON Schema for the security analysis response format.
// This matches the SECURITY_ANALYSIS_SCHEMA from the current Python tool.
func SecurityAnalysisSchema() *json.RawMessage {
	schema := json.RawMessage(securityAnalysisSchemaJSON)
	return &schema
}

const securityAnalysisSchemaJSON = `{
  "name": "security_analysis",
  "strict": true,
  "schema": {
    "type": "object",
    "required": ["repo_name", "description", "public_api_routes", "security_issues", "security_risk", "risk_justification"],
    "additionalProperties": false,
    "properties": {
      "repo_name": {
        "type": "string",
        "description": "Name of the repository or project being analyzed"
      },
      "description": {
        "type": "string",
        "description": "Brief description of what the codebase does"
      },
      "public_api_routes": {
        "type": "array",
        "description": "List of public API routes found in the codebase",
        "items": {
          "type": "object",
          "required": ["route", "citation"],
          "additionalProperties": false,
          "properties": {
            "route": {
              "type": "string",
              "description": "The API route path"
            },
            "citation": {
              "type": "string",
              "description": "File and line number where the route is defined"
            }
          }
        }
      },
      "security_issues": {
        "type": "array",
        "description": "List of security issues found in the codebase",
        "items": {
          "type": "object",
          "required": ["issue", "file_path", "start_line", "end_line", "technical_details", "severity", "cwe_id"],
          "additionalProperties": false,
          "properties": {
            "issue": {
              "type": "string",
              "description": "Short title describing the security issue"
            },
            "file_path": {
              "type": "string",
              "description": "Relative path to the file containing the issue"
            },
            "start_line": {
              "type": "integer",
              "description": "Starting line number of the vulnerable code"
            },
            "end_line": {
              "type": "integer",
              "description": "Ending line number of the vulnerable code"
            },
            "technical_details": {
              "type": "string",
              "description": "Detailed technical explanation of the vulnerability and remediation"
            },
            "severity": {
              "type": "number",
              "description": "Severity score from 0 (info) to 10 (critical)"
            },
            "cwe_id": {
              "type": "string",
              "description": "CWE identifier (e.g., CWE-89 for SQL injection)"
            }
          }
        }
      },
      "security_risk": {
        "type": "number",
        "description": "Overall security risk score from 0 (no risk) to 10 (critical risk)"
      },
      "risk_justification": {
        "type": "string",
        "description": "Justification for the overall security risk score"
      }
    }
  }
}`

// FeatureDetectionSchema returns the JSON Schema for the feature detection response format.
// This is used in the first pass of a two-pass analysis to detect which security features
// the codebase uses.
func FeatureDetectionSchema() *json.RawMessage {
	schema := json.RawMessage(featureDetectionSchemaJSON)
	return &schema
}

const featureDetectionSchemaJSON = `{
  "name": "feature_detection",
  "strict": true,
  "schema": {
    "type": "object",
    "required": ["detected_features"],
    "additionalProperties": false,
    "properties": {
      "detected_features": {
        "type": "array",
        "description": "Security-relevant features detected in the codebase",
        "items": {
          "type": "string",
          "enum": [
            "public_api", "authentication", "authorization", "database_operations",
            "user_input_handling", "file_operations", "cryptography", "session_management",
            "external_api_calls", "third_party_dependencies", "infrastructure_as_code",
            "blockchain_crypto_finance", "websockets", "graphql", "grpc",
            "xml_processing", "deserialization", "template_rendering",
            "shell_command_execution", "sensitive_data_handling"
          ]
        }
      }
    }
  }
}`

// AuditSchema returns the JSON Schema for the audit phase response format.
func AuditSchema() *json.RawMessage {
	schema := json.RawMessage(auditSchemaJSON)
	return &schema
}

const auditSchemaJSON = `{
  "name": "security_audit",
  "strict": true,
  "schema": {
    "type": "object",
    "required": ["audited_findings", "new_findings", "audit_summary"],
    "additionalProperties": false,
    "properties": {
      "audited_findings": {
        "type": "array",
        "description": "Audit verdicts for each initial finding",
        "items": {
          "type": "object",
          "required": ["original_issue", "file_path", "start_line", "end_line", "verdict", "confidence", "refined_severity", "refined_technical_details", "refined_cwe_id", "justification"],
          "additionalProperties": false,
          "properties": {
            "original_issue": {
              "type": "string",
              "description": "The original issue title from the initial finding"
            },
            "file_path": {
              "type": "string",
              "description": "File path of the finding"
            },
            "start_line": {
              "type": "integer",
              "description": "Starting line number"
            },
            "end_line": {
              "type": "integer",
              "description": "Ending line number"
            },
            "verdict": {
              "type": "string",
              "enum": ["confirmed", "refined", "rejected", "escalated"],
              "description": "Audit verdict: confirmed, refined, rejected, or escalated"
            },
            "confidence": {
              "type": "number",
              "description": "Confidence score from 0.0 (unlikely) to 1.0 (certain)"
            },
            "refined_severity": {
              "type": "number",
              "description": "Refined severity score (0-10), adjusted based on deeper analysis"
            },
            "refined_technical_details": {
              "type": "string",
              "description": "Refined technical details incorporating deep CWE analysis"
            },
            "refined_cwe_id": {
              "type": "string",
              "description": "Refined CWE identifier, may differ from initial if more specific CWE applies"
            },
            "justification": {
              "type": "string",
              "description": "Justification for the verdict, explaining why the finding was confirmed, refined, rejected, or escalated"
            }
          }
        }
      },
      "new_findings": {
        "type": "array",
        "description": "Additional findings discovered during the deep CWE analysis",
        "items": {
          "type": "object",
          "required": ["issue", "file_path", "start_line", "end_line", "technical_details", "severity", "cwe_id", "confidence"],
          "additionalProperties": false,
          "properties": {
            "issue": {
              "type": "string",
              "description": "Short title describing the new security issue"
            },
            "file_path": {
              "type": "string",
              "description": "Relative path to the file containing the issue"
            },
            "start_line": {
              "type": "integer",
              "description": "Starting line number"
            },
            "end_line": {
              "type": "integer",
              "description": "Ending line number"
            },
            "technical_details": {
              "type": "string",
              "description": "Detailed technical explanation"
            },
            "severity": {
              "type": "number",
              "description": "Severity score from 0 to 10"
            },
            "cwe_id": {
              "type": "string",
              "description": "CWE identifier"
            },
            "confidence": {
              "type": "number",
              "description": "Confidence score from 0.0 to 1.0"
            }
          }
        }
      },
      "audit_summary": {
        "type": "string",
        "description": "Brief summary of the audit results including counts of confirmed, refined, rejected, escalated, and new findings"
      }
    }
  }
}`

// OutputModeForModel returns the appropriate OutputMode for a model name.
// OpenAI/GPT models use JSON Schema response_format, Claude uses tool_use,
// and other models fall back to unstructured output.
func OutputModeForModel(modelName string) OutputMode {
	lower := strings.ToLower(modelName)

	// OpenAI / GPT models support response_format JSON Schema.
	if strings.Contains(lower, "gpt") || strings.Contains(lower, "o1") || strings.Contains(lower, "o3") {
		return OutputModeJSONSchema
	}

	// Claude models use tool_use for structured output.
	if strings.Contains(lower, "claude") || strings.Contains(lower, "anthropic") {
		return OutputModeToolUse
	}

	// Gemini via the OpenAI-compat endpoint accepts response_format with
	// json_schema. The native generateContent API uses a different
	// schema dialect, but we don't speak that — the compat layer handles
	// translation.
	if strings.Contains(lower, "gemini") {
		return OutputModeJSONSchema
	}

	return OutputModeNone
}
