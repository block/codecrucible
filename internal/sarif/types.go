package sarif

import "encoding/json"

// AnalysisResult represents the structured output from the LLM security analysis.
type AnalysisResult struct {
	RepoName          string          `json:"repo_name"`
	Description       string          `json:"description"`
	PublicAPIRoutes   []APIRoute      `json:"public_api_routes"`
	SecurityIssues    []SecurityIssue `json:"security_issues"`
	SecurityRisk      float64         `json:"security_risk"`
	RiskJustification string          `json:"risk_justification"`
}

// APIRoute describes a discovered public API endpoint.
type APIRoute struct {
	Route    string `json:"route"`
	Citation string `json:"citation"`
}

// SecurityIssue describes a single finding from the LLM analysis.
type SecurityIssue struct {
	Issue            string         `json:"issue"`
	FilePath         string         `json:"file_path"`
	StartLine        int            `json:"start_line"`
	EndLine          int            `json:"end_line"`
	TechnicalDetails string         `json:"technical_details"`
	Severity         float64        `json:"severity"`
	CWEID            string         `json:"cwe_id"`
	Summary          string         `json:"summary"`
	Remediation      string         `json:"remediation"`
	CodePath         []CodePathStep `json:"code_path"`
}

// CodePathStep is a source-backed step in the reported exploit path.
type CodePathStep struct {
	FilePath  string `json:"file_path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Message   string `json:"message"`
}

// ---------------------------------------------------------------------------
// SARIF v2.1.0 output types
// ---------------------------------------------------------------------------

// SARIFDocument is the top-level SARIF v2.1.0 envelope.
type SARIFDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun groups tool information, results, and invocations.
type SARIFRun struct {
	Tool        SARIFTool         `json:"tool"`
	Results     []SARIFResult     `json:"results"`
	Invocations []SARIFInvocation `json:"invocations,omitempty"`
	Taxonomies  []SARIFTaxonomy   `json:"taxonomies,omitempty"`
	Properties  *RunProperties    `json:"properties,omitempty"`
}

// SARIFTool describes the analysis tool.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver holds tool metadata and the set of rules.
type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []SARIFRule `json:"rules"`
}

// SARIFRule defines a unique finding category.
type SARIFRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name,omitempty"`
	ShortDescription SARIFMessage        `json:"shortDescription"`
	FullDescription  *SARIFMessage       `json:"fullDescription,omitempty"`
	Help             *SARIFMessage       `json:"help,omitempty"`
	Properties       map[string]any      `json:"properties,omitempty"`
	Relationships    []SARIFRelationship `json:"relationships,omitempty"`
}

// SARIFRelationship links a rule to an external taxonomy (e.g., CWE).
type SARIFRelationship struct {
	Target SARIFRelationshipTarget `json:"target"`
	Kinds  []string                `json:"kinds"`
}

// SARIFRelationshipTarget identifies a taxonomy entry.
type SARIFRelationshipTarget struct {
	ID            string                `json:"id"`
	GUID          string                `json:"guid,omitempty"`
	ToolComponent SARIFToolComponentRef `json:"toolComponent"`
}

// SARIFToolComponentRef references a tool component (taxonomy) by name.
type SARIFToolComponentRef struct {
	Name string `json:"name"`
}

// SARIFTaxonomy describes an external taxonomy like CWE.
type SARIFTaxonomy struct {
	Name             string       `json:"name"`
	Organization     string       `json:"organization"`
	ShortDescription SARIFMessage `json:"shortDescription"`
	Taxa             []SARIFTaxon `json:"taxa"`
}

// SARIFTaxon is a single entry in a taxonomy.
type SARIFTaxon struct {
	ID               string       `json:"id"`
	ShortDescription SARIFMessage `json:"shortDescription"`
}

// SARIFMessage is a simple text message wrapper used throughout SARIF.
type SARIFMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

// SARIFResult is a single finding referencing a rule.
type SARIFResult struct {
	RuleID     string             `json:"ruleId"`
	Level      string             `json:"level"`
	Message    SARIFMessage       `json:"message"`
	Locations  []SARIFLocation    `json:"locations,omitempty"`
	CodeFlows  []SARIFCodeFlow    `json:"codeFlows,omitempty"`
	Properties *FindingProperties `json:"properties,omitempty"`
}

// DecisionAssessment records bounded evidence checks separately from audit confidence.
type DecisionAssessment struct {
	Status      string          `json:"status"`
	Model       string          `json:"model,omitempty"`
	Policy      string          `json:"policy"`
	EvidenceIDs []string        `json:"evidenceIds,omitempty"`
	Checks      []DecisionCheck `json:"checks,omitempty"`
	ReusedFrom  string          `json:"reusedFrom,omitempty"`
}

type DecisionCheck struct {
	ID        string `json:"id"`
	Assertion string `json:"assertion"`
	Status    string `json:"status"`
}

// FindingProperties keeps full evidence available outside the inline annotation.
type FindingProperties struct {
	AuditOriginal    *AuditOriginalFinding `json:"auditOriginal,omitempty"`
	AuditRevision    json.RawMessage       `json:"auditRevision,omitempty"`
	FindingID        string                `json:"findingId,omitempty"`
	CWEChanges       []CWEChange           `json:"cweChanges,omitempty"`
	DecisionCWE      *CWEAssessment        `json:"decisionCWE,omitempty"`
	Deduplicated     []DeduplicatedFinding `json:"deduplicatedFindings,omitempty"`
	DecisionAudit    *DecisionAssessment   `json:"decisionAudit,omitempty"`
	DecisionReview   *DecisionAssessment   `json:"decisionReview,omitempty"`
	Summary          string                `json:"summary,omitempty"`
	Remediation      string                `json:"remediation,omitempty"`
	TechnicalDetails string                `json:"technicalDetails,omitempty"`
	AuditStatus      string                `json:"auditStatus,omitempty"`
	AuditConfidence  *float64              `json:"auditConfidence,omitempty"`
}

type CWEChange struct {
	Original string `json:"original"`
	Assigned string `json:"assigned"`
	Source   string `json:"source"`
}

type CWEAssessment struct {
	Status         string   `json:"status"`
	Original       string   `json:"original,omitempty"`
	Proposed       string   `json:"proposed,omitempty"`
	Applied        bool     `json:"applied"`
	CatalogVersion string   `json:"catalogVersion"`
	Candidates     []string `json:"candidates,omitempty"`
	Model          string   `json:"model,omitempty"`
	Policy         string   `json:"policy"`
	Probability    float64  `json:"probability,omitempty"`
	Confidence     *float64 `json:"confidence,omitempty"`
	EvidenceIDs    []string `json:"evidenceIds,omitempty"`
}

// DeduplicatedFinding preserves the complete original record and its rule.
// Merging display entries must never destroy source evidence or audit provenance.
type DeduplicatedFinding struct {
	Result      SARIFResult `json:"result"`
	Rule        SARIFRule   `json:"rule"`
	Model       string      `json:"model"`
	Policy      string      `json:"policy"`
	EvidenceIDs []string    `json:"evidenceIds"`
}

type SARIFCodeFlow struct {
	ThreadFlows []SARIFThreadFlow `json:"threadFlows"`
}

type SARIFThreadFlow struct {
	Locations []SARIFThreadFlowLocation `json:"locations"`
}

type SARIFThreadFlowLocation struct {
	Location       SARIFLocation `json:"location"`
	ExecutionOrder int           `json:"executionOrder"`
}

// SARIFLocation wraps a physical location.
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
	Message          *SARIFMessage         `json:"message,omitempty"`
}

// SARIFPhysicalLocation points to a file and optional region.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

// SARIFArtifactLocation identifies a file by URI.
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFRegion identifies a range of lines within a file.
type SARIFRegion struct {
	StartLine int           `json:"startLine"`
	EndLine   int           `json:"endLine,omitempty"`
	Snippet   *SARIFSnippet `json:"snippet,omitempty"`
}

// SARIFSnippet holds extracted source text.
type SARIFSnippet struct {
	Text string `json:"text"`
}

// SARIFInvocation records metadata about a tool execution.
type SARIFInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []SARIFNotification `json:"toolExecutionNotifications,omitempty"`
}

// SARIFNotification represents a runtime message from the tool.
type SARIFNotification struct {
	Level   string       `json:"level"`
	Message SARIFMessage `json:"message"`
}

// AuditOriginalFinding preserves claim semantics and citations across rewrites.
// Result omits recursive audit history to keep the archive finite.
type AuditOriginalFinding struct {
	Result           SARIFResult `json:"result"`
	Rule             SARIFRule   `json:"rule"`
	TechnicalDetails string      `json:"technicalDetails,omitempty"`
	Summary          string      `json:"summary,omitempty"`
	Remediation      string      `json:"remediation,omitempty"`
}
