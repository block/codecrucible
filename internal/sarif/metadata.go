package sarif

import "github.com/block/codecrucible/internal/usage"

// RunProperties contains the versioned CodeCrucible extension to SARIF.
// Authentication material must never be copied into these types.
type RunProperties struct {
	CodeCrucible *ScanMetadata `json:"codecrucible,omitempty"`
}

type ScanMetadata struct {
	SchemaVersion     int           `json:"schemaVersion"`
	RecipeFingerprint string        `json:"recipeFingerprint"`
	Recipe            ScanRecipe    `json:"recipe"`
	Execution         ScanExecution `json:"execution"`
}

type DecisionRecipe struct {
	DependencyGrouping bool              `json:"dependencyGrouping"`
	StageCallLimits    map[string]int    `json:"stageCallLimits,omitempty"`
	Modes              map[string]string `json:"modes"`
	Model              string            `json:"model"`
	Endpoint           string            `json:"endpoint"`
	Policy             string            `json:"policy"`
	Timeout            int               `json:"requestTimeoutSeconds"`
	MaxCalls           int               `json:"maxCalls"`
	Retries            int               `json:"retries"`
	InputPrice         float64           `json:"inputPricePerMillion"`
}

type ScanRecipe struct {
	Decisions                     *DecisionRecipe        `json:"decisions,omitempty"`
	ToolVersion                   string                 `json:"toolVersion"`
	ToolCommit                    string                 `json:"toolCommit"`
	Phases                        map[string]PhaseRecipe `json:"phases"`
	Controls                      ScanControls           `json:"controls"`
	Prompts                       PromptIdentity         `json:"prompts"`
	CustomRequirementsFingerprint string                 `json:"customRequirementsFingerprint,omitempty"`
	ContextSources                []ContextIdentity      `json:"contextSources"`
}

type PhaseRecipe struct {
	Provider               string         `json:"provider"`
	Model                  string         `json:"model"`
	BaseURL                string         `json:"baseUrl,omitempty"`
	Endpoint               string         `json:"endpoint,omitempty"`
	Transport              string         `json:"transport"`
	ModelParams            map[string]any `json:"modelParams"`
	ContextLimit           int            `json:"contextLimit"`
	MaxOutputTokens        int            `json:"maxOutputTokens"`
	Temperature            float64        `json:"temperature"`
	OmitTemperature        bool           `json:"omitTemperature"`
	UseMaxCompletionTokens bool           `json:"useMaxCompletionTokens"`
	OutputMode             string         `json:"outputMode"`
	RequestTimeoutSeconds  int            `json:"requestTimeoutSeconds"`
	Tokenizer              string         `json:"tokenizer"`
	Pricing                ModelPricing   `json:"pricing"`
}

type ModelPricing struct {
	InputPerMillion             float64 `json:"inputPerMillion"`
	OutputPerMillion            float64 `json:"outputPerMillion"`
	LongContextThreshold        int     `json:"longContextThreshold"`
	LongContextInputPerMillion  float64 `json:"longContextInputPerMillion"`
	LongContextOutputPerMillion float64 `json:"longContextOutputPerMillion"`
}

type ScanControls struct {
	Paths                    []string `json:"paths"`
	Include                  []string `json:"include"`
	Exclude                  []string `json:"exclude"`
	IncludeTests             bool     `json:"includeTests"`
	IncludeDocs              bool     `json:"includeDocs"`
	MaxFileSize              int      `json:"maxFileSize"`
	Compress                 bool     `json:"compress"`
	Concurrency              int      `json:"concurrency"`
	MaxCost                  float64  `json:"maxCost"`
	FailOnSeverity           float64  `json:"failOnSeverity"`
	SkipFeatureDetection     bool     `json:"skipFeatureDetection"`
	SkipAudit                bool     `json:"skipAudit"`
	AuditConfidenceThreshold float64  `json:"auditConfidenceThreshold"`
	AuditBatchSize           int      `json:"auditBatchSize"`
	AuditConcurrency         int      `json:"auditConcurrency"`
	ContextBudgetPct         int      `json:"contextBudgetPct"`
}

type PromptIdentity struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type ContextIdentity struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Priority int      `json:"priority"`
	Compress bool     `json:"compress"`
	Phases   []string `json:"phases"`
	Include  []string `json:"include"`
	Exclude  []string `json:"exclude"`
	// Hash loaded content, never a credential-bearing URL or local path.
	ContentFingerprint string `json:"contentFingerprint,omitempty"`
}

type ScanExecution struct {
	Usage            *usage.Report             `json:"usage,omitempty"`
	ArtifactStage    string                    `json:"artifactStage"`
	Phases           map[string]PhaseExecution `json:"phases"`
	RetainedFeatures []string                  `json:"retainedFeatures,omitempty"`
	DetectedFeatures []string                  `json:"detectedFeatures"`
	TokenCorrection  float64                   `json:"tokenCorrection"`
	Chunks           ChunkExecution            `json:"chunks"`
	ContextSources   []ContextExecution        `json:"contextSources"`
	ContextPacking   map[string]ContextPacking `json:"contextPacking"`
}

type PhaseExecution struct {
	Status   string       `json:"status"`           // pending, completed, skipped, failed
	Reason   string       `json:"reason,omitempty"` // fixed labels, never raw errors
	Fallback string       `json:"fallback,omitempty"`
	Actual   *PhaseRecipe `json:"actual,omitempty"`
	// Context compression uses per-source limits, no structured output, and
	// does not currently forward configured model parameters.
	RequestPolicy string `json:"requestPolicy,omitempty"`
}

type ChunkExecution struct {
	Initial        int `json:"initial"`
	Recovery       int `json:"recovery"`
	Completed      int `json:"completed"`
	Failed         int `json:"failed"`
	Overflowed     int `json:"overflowed"`
	Budget         int `json:"budget"`
	RecoveryBudget int `json:"recoveryBudget"`
}

type ContextExecution struct {
	SourceIndex     int    `json:"sourceIndex"`
	Status          string `json:"status"`
	Compression     string `json:"compression"`
	Fingerprint     string `json:"fingerprint,omitempty"`
	MaxOutputTokens int    `json:"maxOutputTokens,omitempty"`
}

type ContextPacking struct {
	Fingerprint string   `json:"fingerprint"`
	Tokens      int      `json:"tokens"`
	Dropped     []string `json:"dropped"`
	Truncated   string   `json:"truncated,omitempty"`
}
