package llm

import (
	"fmt"
	"io/fs"
	"strings"
	"sync"

	"go.yaml.in/yaml/v3"
)

// BasePrompt represents the parsed security_analysis_base.yaml template.
type BasePrompt struct {
	SystemMessage                 string `yaml:"system_message"`
	AnalysisIntro                 string `yaml:"analysis_intro"`
	InfrastructureNote            string `yaml:"infrastructure_note"`
	AnalysisRequirementsHeader    string `yaml:"analysis_requirements_header"`
	CustomRequirementsPlaceholder string `yaml:"custom_requirements_placeholder"`
	RepoInfo                      string `yaml:"repo_info"`
	CriticalInstructions          string `yaml:"critical_instructions"`
	JSONFormattingRules           string `yaml:"json_formatting_rules"`
}

// AnalysisSectionsFile represents the parsed analysis_sections.yaml.
type AnalysisSectionsFile struct {
	Sections map[string]AnalysisSection `yaml:"sections"`
}

// AnalysisSection is a single dynamic analysis section.
type AnalysisSection struct {
	Title    string   `yaml:"title"`
	Features []string `yaml:"features"`
	Content  string   `yaml:"content"`
}

// PromptParams holds the dynamic values used when assembling prompt messages.
type PromptParams struct {
	RepoName           string
	XML                string   // Flattened repo XML content.
	Schema             string   // JSON schema string.
	Manifest           []string // All file paths in the full repo (for chunk context).
	ChunkIndex         int      // 0-based chunk index.
	ChunkTotal         int      // Total number of chunks.
	CustomRequirements string   // User-provided requirements from --custom-requirements.
	EnabledFeatures    []string // If non-empty, only include sections whose features overlap.
	// SupplementaryContext is the packed output of internal/supctx — docs,
	// API specs, sibling-repo snippets — shown to the model as reference
	// material. Findings must not be reported against it.
	SupplementaryContext string
}

// FeaturePromptParams holds the dynamic values for feature detection prompt assembly.
type FeaturePromptParams struct {
	RepoName string
	Manifest []string // All file paths in the repo.
	Samples  string   // Representative code samples (small subset of files).
}

// FeatureDetectionPrompt represents the parsed feature_detection.yaml template.
type FeatureDetectionPrompt struct {
	SystemMessage      string `yaml:"system_message"`
	UserPromptTemplate string `yaml:"user_prompt_template"`
}

// AuditPrompt represents the parsed audit.yaml template.
type AuditPrompt struct {
	SystemMessage       string `yaml:"system_message"`
	UserPromptTemplate  string `yaml:"user_prompt_template"`
	JSONFormattingRules string `yaml:"json_formatting_rules"`
	// ProductionOnlyGate is injected at {production_only_gate} when the scan
	// excluded test files (--include-tests not set). Adversarial pre-filter
	// that forces the auditor to prove production reachability.
	ProductionOnlyGate string `yaml:"production_only_gate"`
}

// CWEPromptsFile represents the parsed cwe_deep_analysis.yaml.
type CWEPromptsFile struct {
	CWEPrompts map[string]CWEPrompt `yaml:"cwe_prompts"`
}

// CWEPrompt is a single CWE-specific deep analysis prompt.
type CWEPrompt struct {
	Title                   string   `yaml:"title"`
	AnalysisPrompt          string   `yaml:"analysis_prompt"`
	ValidationChecks        []string `yaml:"validation_checks"`
	FalsePositiveIndicators []string `yaml:"false_positive_indicators"`
}

// AuditParams holds the dynamic values used when assembling audit prompt messages.
type AuditParams struct {
	RepoName       string
	FindingsJSON   string   // Initial findings as JSON.
	CodeContext    string   // Relevant source code for the findings.
	CWEIDs         []string // CWE IDs to include analysis prompts for.
	Schema         string   // JSON schema string for the audit response.
	ProductionOnly bool     // When true, inject the production_only_gate section.
	// SupplementaryContext is the packed output of internal/supctx for the
	// audit phase.
	SupplementaryContext string
}

// PromptLoader loads and assembles prompt templates from an fs.FS.
// Templates are cached after first load to avoid repeated disk I/O and YAML parsing.
type PromptLoader struct {
	fsys fs.FS
	mu   sync.Mutex // protects cached* fields for concurrent access

	// Cached templates (populated on first load).
	cachedBase     *BasePrompt
	cachedSections *AnalysisSectionsFile
	cachedFeature  *FeatureDetectionPrompt
	cachedAudit    *AuditPrompt
	cachedCWE      *CWEPromptsFile
	cachedCompress *ContextCompressPrompt
}

// ContextCompressPrompt is the parsed context_compress.yaml template used by
// the supctx compression pre-pass.
type ContextCompressPrompt struct {
	SystemMessage      string `yaml:"system_message"`
	UserPromptTemplate string `yaml:"user_prompt_template"`
}

// NewPromptLoader creates a PromptLoader that reads templates from fsys.
// The caller provides either os.DirFS("prompts/default") or an embed.FS sub-directory.
func NewPromptLoader(fsys fs.FS) *PromptLoader {
	return &PromptLoader{fsys: fsys}
}

// LoadBasePrompt reads and parses the security_analysis_base.yaml template.
// The result is cached after the first successful load.
func (l *PromptLoader) LoadBasePrompt() (*BasePrompt, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cachedBase != nil {
		return l.cachedBase, nil
	}

	data, err := fs.ReadFile(l.fsys, "security_analysis_base.yaml")
	if err != nil {
		return nil, fmt.Errorf("loading base prompt: %w", err)
	}

	var bp BasePrompt
	if err := yaml.Unmarshal(data, &bp); err != nil {
		return nil, fmt.Errorf("parsing base prompt YAML: %w", err)
	}
	l.cachedBase = &bp
	return &bp, nil
}

// LoadAnalysisSections reads and parses the analysis_sections.yaml file.
// The result is cached after the first successful load.
func (l *PromptLoader) LoadAnalysisSections() (*AnalysisSectionsFile, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cachedSections != nil {
		return l.cachedSections, nil
	}

	data, err := fs.ReadFile(l.fsys, "analysis_sections.yaml")
	if err != nil {
		return nil, fmt.Errorf("loading analysis sections: %w", err)
	}

	var af AnalysisSectionsFile
	if err := yaml.Unmarshal(data, &af); err != nil {
		return nil, fmt.Errorf("parsing analysis sections YAML: %w", err)
	}
	l.cachedSections = &af
	return &af, nil
}

// AssembleMessages builds the system and user messages for a security analysis
// LLM call using the base prompt template and the given parameters.
func (l *PromptLoader) AssembleMessages(params PromptParams) ([]Message, error) {
	bp, err := l.LoadBasePrompt()
	if err != nil {
		return nil, err
	}

	var user strings.Builder

	// 1. Analysis intro.
	user.WriteString(bp.AnalysisIntro)
	user.WriteString("\n")

	// 2. Chunk manifest note (only for multi-chunk).
	if params.ChunkTotal > 1 {
		fmt.Fprintf(&user, "NOTE: This is chunk %d of %d. Files in this chunk are shown below. Other files in the repository:\n%s\nFocus your analysis on the files shown in this chunk.\n\n",
			params.ChunkIndex+1,
			params.ChunkTotal,
			strings.Join(params.Manifest, "\n"),
		)
	}

	// 3. Analysis requirements header and sections.
	sections, err := l.LoadAnalysisSections()
	if err == nil && len(sections.Sections) > 0 {
		user.WriteString(bp.AnalysisRequirementsHeader)
		user.WriteString("\n")
		for _, section := range sections.Sections {
			if !sectionEnabled(section, params.EnabledFeatures) {
				continue
			}
			fmt.Fprintf(&user, "### %s\n%s\n", section.Title, section.Content)
		}
		user.WriteString("\n")
	}

	// 4. Custom requirements.
	if params.CustomRequirements != "" {
		fmt.Fprintf(&user, "ADDITIONAL REQUIREMENTS:\n%s\n\n", params.CustomRequirements)
	}

	// 4.5. Supplementary context. Placed before the repo so the model reads
	// reference material first, then the actual scan target — matching how a
	// human reviewer would skim the API spec before diving into handlers.
	if params.SupplementaryContext != "" {
		fmt.Fprintf(&user, "SUPPLEMENTARY CONTEXT — reference material, do NOT report findings against it:\n%s\n\n", params.SupplementaryContext)
	}

	// 5. Repo info with placeholders replaced.
	repoInfo := strings.ReplaceAll(bp.RepoInfo, "{repo_name}", params.RepoName)
	repoInfo = strings.ReplaceAll(repoInfo, "{xml_content}", params.XML)
	user.WriteString(repoInfo)
	user.WriteString("\n")

	// 6. Critical instructions.
	user.WriteString(bp.CriticalInstructions)
	user.WriteString("\n")

	// 7. JSON formatting rules with schema replaced.
	jsonRules := strings.ReplaceAll(bp.JSONFormattingRules, "{schema}", params.Schema)
	user.WriteString(jsonRules)

	return []Message{
		{Role: "system", Content: bp.SystemMessage},
		{Role: "user", Content: user.String()},
	}, nil
}

// LoadFeatureDetectionPrompt reads and parses the feature_detection.yaml template.
// The result is cached after the first successful load.
func (l *PromptLoader) LoadFeatureDetectionPrompt() (*FeatureDetectionPrompt, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cachedFeature != nil {
		return l.cachedFeature, nil
	}

	data, err := fs.ReadFile(l.fsys, "feature_detection.yaml")
	if err != nil {
		return nil, fmt.Errorf("loading feature detection prompt: %w", err)
	}

	var fd FeatureDetectionPrompt
	if err := yaml.Unmarshal(data, &fd); err != nil {
		return nil, fmt.Errorf("parsing feature detection prompt YAML: %w", err)
	}
	l.cachedFeature = &fd
	return &fd, nil
}

// AssembleFeatureDetectionMessages builds the system and user messages for a
// feature detection LLM call using the feature_detection.yaml template.
func (l *PromptLoader) AssembleFeatureDetectionMessages(params FeaturePromptParams) ([]Message, error) {
	fd, err := l.LoadFeatureDetectionPrompt()
	if err != nil {
		return nil, err
	}

	// Build the XML content from manifest + samples.
	var xmlContent strings.Builder
	xmlContent.WriteString("<manifest>\n")
	for _, path := range params.Manifest {
		fmt.Fprintf(&xmlContent, "  %s\n", path)
	}
	xmlContent.WriteString("</manifest>\n\n")
	if params.Samples != "" {
		xmlContent.WriteString(params.Samples)
	}

	schemaRaw := FeatureDetectionSchema()
	schemaStr := string(*schemaRaw)

	userContent := fd.UserPromptTemplate
	userContent = strings.ReplaceAll(userContent, "{repo_name}", params.RepoName)
	userContent = strings.ReplaceAll(userContent, "{xml_content}", xmlContent.String())
	userContent = strings.ReplaceAll(userContent, "{schema}", schemaStr)

	return []Message{
		{Role: "system", Content: fd.SystemMessage},
		{Role: "user", Content: userContent},
	}, nil
}

// sectionEnabled returns true if a section should be included given the enabled features.
// A section is included if:
// - enabledFeatures is empty (no filtering),
// - the section has no required features (always included), or
// - at least one of the section's features is in enabledFeatures.
func sectionEnabled(section AnalysisSection, enabledFeatures []string) bool {
	if len(enabledFeatures) == 0 {
		return true
	}
	if len(section.Features) == 0 {
		return true
	}
	enabled := make(map[string]bool, len(enabledFeatures))
	for _, f := range enabledFeatures {
		enabled[f] = true
	}
	for _, f := range section.Features {
		if enabled[f] {
			return true
		}
	}
	return false
}

// FileEntry represents a file with its path and content for feature sample building.
type FileEntry struct {
	Path    string
	Content string
}

// BuildFeatureSamples selects a representative subset of files to include as samples
// for feature detection. It prioritizes dependency manifests and entrypoint files,
// and caps total output at roughly maxTokens * 4 characters.
func BuildFeatureSamples(files []FileEntry, maxTokens int) string {
	maxChars := maxTokens * 4

	// Dependency manifest filenames to always include.
	manifests := map[string]bool{
		"package.json":     true,
		"go.mod":           true,
		"go.sum":           false, // skip, too large and not informative
		"requirements.txt": true,
		"Cargo.toml":       true,
		"Gemfile":          true,
		"pom.xml":          true,
		"build.gradle":     true,
		"composer.json":    true,
		"pyproject.toml":   true,
		"setup.py":         true,
		"Pipfile":          true,
		"pubspec.yaml":     true,
		"Package.swift":    true,
		"mix.exs":          true,
		"project.clj":      true,
	}

	var out strings.Builder
	written := 0

	addFile := func(path, content string, maxLines int) bool {
		if written >= maxChars {
			return false
		}
		var trimmed string
		if maxLines > 0 {
			lines := strings.SplitN(content, "\n", maxLines+1)
			if len(lines) > maxLines {
				lines = lines[:maxLines]
			}
			trimmed = strings.Join(lines, "\n")
		} else {
			trimmed = content
		}
		entry := fmt.Sprintf("<file path=\"%s\">\n%s\n</file>\n", path, trimmed)
		if written+len(entry) > maxChars {
			remaining := maxChars - written
			if remaining < 100 {
				return false
			}
			entry = entry[:remaining]
		}
		out.WriteString(entry)
		written += len(entry)
		return written < maxChars
	}

	// Pass 1: dependency manifests (full content).
	for _, f := range files {
		base := baseName(f.Path)
		if include, ok := manifests[base]; ok && include {
			if !addFile(f.Path, f.Content, 0) {
				return out.String()
			}
		}
	}

	// Pass 2: entrypoints and routers (first ~50 lines).
	for _, f := range files {
		if isEntrypoint(f.Path) {
			if !addFile(f.Path, f.Content, 50) {
				return out.String()
			}
		}
	}

	return out.String()
}

// baseName returns the last component of a slash-separated path.
func baseName(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}

// LoadAuditPrompt reads and parses the audit.yaml template.
// The result is cached after the first successful load.
func (l *PromptLoader) LoadAuditPrompt() (*AuditPrompt, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cachedAudit != nil {
		return l.cachedAudit, nil
	}

	data, err := fs.ReadFile(l.fsys, "audit.yaml")
	if err != nil {
		return nil, fmt.Errorf("loading audit prompt: %w", err)
	}

	var ap AuditPrompt
	if err := yaml.Unmarshal(data, &ap); err != nil {
		return nil, fmt.Errorf("parsing audit prompt YAML: %w", err)
	}
	l.cachedAudit = &ap
	return &ap, nil
}

// LoadCWEPrompts reads and parses the cwe_deep_analysis.yaml file.
// The result is cached after the first successful load.
func (l *PromptLoader) LoadCWEPrompts() (*CWEPromptsFile, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cachedCWE != nil {
		return l.cachedCWE, nil
	}

	data, err := fs.ReadFile(l.fsys, "cwe_deep_analysis.yaml")
	if err != nil {
		return nil, fmt.Errorf("loading CWE prompts: %w", err)
	}

	var cf CWEPromptsFile
	if err := yaml.Unmarshal(data, &cf); err != nil {
		return nil, fmt.Errorf("parsing CWE prompts YAML: %w", err)
	}
	l.cachedCWE = &cf
	return &cf, nil
}

// LoadContextCompressPrompt reads and parses context_compress.yaml.
// Missing file returns a usable fallback so the feature degrades gracefully
// when users run with a custom --prompts-dir that predates this template.
func (l *PromptLoader) LoadContextCompressPrompt() (*ContextCompressPrompt, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cachedCompress != nil {
		return l.cachedCompress, nil
	}
	data, err := fs.ReadFile(l.fsys, "context_compress.yaml")
	if err != nil {
		l.cachedCompress = &ContextCompressPrompt{
			SystemMessage:      "You are a technical writer specialising in security documentation. Compress reference material while preserving security-relevant detail.",
			UserPromptTemplate: "Summarise the following reference material named \"{source_name}\" into approximately {target_tokens} tokens. Preserve authentication flows, trust boundaries, input validation rules, and known issues. Omit boilerplate.\n\n{content}",
		}
		return l.cachedCompress, nil
	}
	var cp ContextCompressPrompt
	if err := yaml.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("parsing context compress prompt YAML: %w", err)
	}
	l.cachedCompress = &cp
	return &cp, nil
}

// AssembleAuditMessages builds the system and user messages for the audit phase.
func (l *PromptLoader) AssembleAuditMessages(params AuditParams) ([]Message, error) {
	ap, err := l.LoadAuditPrompt()
	if err != nil {
		return nil, err
	}

	// Build CWE-specific analysis section.
	cweSection, err := l.buildCWESection(params.CWEIDs)
	if err != nil {
		// Non-fatal: proceed without CWE prompts.
		cweSection = "(CWE-specific prompts not available)"
	}

	prodGate := ""
	if params.ProductionOnly {
		prodGate = ap.ProductionOnlyGate
	}

	userContent := ap.UserPromptTemplate
	userContent = strings.ReplaceAll(userContent, "{repo_name}", params.RepoName)
	userContent = strings.ReplaceAll(userContent, "{findings_json}", params.FindingsJSON)
	userContent = strings.ReplaceAll(userContent, "{cwe_analysis_prompts}", cweSection)
	userContent = strings.ReplaceAll(userContent, "{code_context}", params.CodeContext)
	userContent = strings.ReplaceAll(userContent, "{production_only_gate}", prodGate)

	supSection := ""
	if params.SupplementaryContext != "" {
		supSection = "=== SUPPLEMENTARY CONTEXT (reference material — do NOT report findings against it) ===\n\n" +
			params.SupplementaryContext
	}
	userContent = strings.ReplaceAll(userContent, "{supplementary_context}", supSection)

	system := strings.ReplaceAll(ap.SystemMessage, "{production_only_gate}", prodGate)

	// Append JSON formatting rules with schema.
	jsonRules := strings.ReplaceAll(ap.JSONFormattingRules, "{schema}", params.Schema)
	userContent += "\n" + jsonRules

	// Append schema to user content.
	userContent = strings.ReplaceAll(userContent, "{schema}", params.Schema)

	return []Message{
		{Role: "system", Content: system},
		{Role: "user", Content: userContent},
	}, nil
}

// buildCWESection assembles the CWE-specific analysis prompts for the given CWE IDs.
func (l *PromptLoader) buildCWESection(cweIDs []string) (string, error) {
	cf, err := l.LoadCWEPrompts()
	if err != nil {
		return "", err
	}

	// Normalize CWE IDs: extract "CWE-89" from "CWE-89: SQL Injection".
	seen := make(map[string]bool)
	var normalized []string
	for _, id := range cweIDs {
		// Extract just the CWE-NNN part.
		key := id
		if idx := strings.Index(id, ":"); idx > 0 {
			key = strings.TrimSpace(id[:idx])
		}
		key = strings.ToUpper(strings.TrimSpace(key))
		if !seen[key] {
			seen[key] = true
			normalized = append(normalized, key)
		}
	}

	var out strings.Builder
	for _, key := range normalized {
		prompt, ok := cf.CWEPrompts[key]
		if !ok {
			continue
		}

		fmt.Fprintf(&out, "### %s: %s\n\n", key, prompt.Title)
		fmt.Fprintf(&out, "**Deep Analysis Guidance:**\n%s\n\n", prompt.AnalysisPrompt)

		if len(prompt.ValidationChecks) > 0 {
			out.WriteString("**Validation Checks:**\n")
			for _, check := range prompt.ValidationChecks {
				fmt.Fprintf(&out, "  - %s\n", check)
			}
			out.WriteString("\n")
		}

		if len(prompt.FalsePositiveIndicators) > 0 {
			out.WriteString("**False Positive Indicators:**\n")
			for _, indicator := range prompt.FalsePositiveIndicators {
				fmt.Fprintf(&out, "  - %s\n", indicator)
			}
			out.WriteString("\n")
		}
	}

	if out.Len() == 0 {
		return "(No CWE-specific prompts matched the findings)", nil
	}

	return out.String(), nil
}

// isEntrypoint returns true if the file path looks like an entrypoint or router file.
func isEntrypoint(path string) bool {
	base := strings.ToLower(baseName(path))
	lower := strings.ToLower(path)

	entrypointNames := []string{
		"main.go", "main.py", "main.ts", "main.js", "main.rs", "main.rb",
		"server.go", "server.py", "server.ts", "server.js",
		"app.go", "app.py", "app.ts", "app.js", "app.rb",
		"index.ts", "index.js",
	}
	for _, name := range entrypointNames {
		if base == name {
			return true
		}
	}

	routerDirs := []string{"/routes/", "/handlers/", "/controllers/", "/api/", "/middleware/"}
	for _, dir := range routerDirs {
		if strings.Contains(lower, dir) {
			return true
		}
	}

	return false
}
