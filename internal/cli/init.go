package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newInitCommand() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "init [path]",
		Short: "Write a commented .codecrucible.yaml config file",
		Long: `Writes a commented example config to .codecrucible.yaml (or the given path).

The file is a worked example, not a schema dump — it shows the per-phase
provider/model override shape and the flags that actually matter when running
against large repos with thinking models. Delete what you don't need.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := ".codecrucible.yaml"
			if len(args) == 1 {
				path = args[0]
			}
			if !force {
				if _, err := os.Stat(path); err == nil {
					return fmt.Errorf("%s already exists (use --force to overwrite)", path)
				}
			}
			if err := os.WriteFile(path, []byte(configTemplate), 0o644); err != nil {
				return fmt.Errorf("writing %s: %w", path, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", path)
			return nil
		},
	}
	cmd.Flags().BoolVarP(&force, "force", "f", false, "overwrite an existing file")
	return cmd
}

// configTemplate is a worked example, not a schema dump. Shows the per-phase
// override shape and the flags that bite when running large-context scans.
// Everything is optional — flat top-level fields are inherited by all phases.
const configTemplate = `# codecrucible config — loaded from ./.codecrucible.yaml by default,
# or pass --config path/to/file.yaml. Flags > env vars > this file > defaults.

# --- Scope ---------------------------------------------------------------

paths:
  - src/
exclude:
  - "**/third-party/**"
  - "**/vendor/**"
# include-tests: false
# include-docs: false
# max-file-size: 102400   # bytes; files larger than this are skipped

# --- Cost / concurrency --------------------------------------------------

max-cost: 100.0           # dollar ceiling; scan aborts if estimated cost exceeds
concurrency: 4            # parallel chunk requests
# dry-run: true           # print plan without LLM calls

# --- Model sizing --------------------------------------------------------
# These matter for models not in the built-in registry (unknown models get
# weak defaults: 100k context, 4096 output). Set both.

context-limit: 200000
max-output-tokens: 16384
request-timeout: 900      # seconds; bump for large-context + thinking models

# --- Provider (flat form — inherited by all phases) ----------------------
# Providers: anthropic, openai, google, ollama, openai-compat, databricks
# API keys come from env: ANTHROPIC_API_KEY, OPENAI_API_KEY, GOOGLE_API_KEY,
# DATABRICKS_HOST + DATABRICKS_TOKEN. Provider auto-detects from whichever
# is set unless pinned here. ollama and openai-compat don't require API keys.

provider: anthropic
model: claude-sonnet-4-6
# base-url: ""   # override default provider URL (required for openai-compat)
# custom-headers:
#   - "anthropic-beta: context-1m-2025-08-07"

# model-params is raw JSON merged into every request body. tool_choice and
# response_format are REPLACED; everything else deep-merges. Prefer
# --max-output-tokens over "max_tokens" here — the chunker reads the former.
# model-params:
#   thinking:
#     type: enabled
#     budget_tokens: 10000

# --- Per-phase overrides -------------------------------------------------
# Any field left unset inherits from the flat fields above. Analysis is the
# main scan pass; feature-detection is a cheap pre-pass (also calibrates
# the tokenizer — don't skip it on large repos); audit re-checks findings.
#
# Env form: PHASES_AUDIT_PROVIDER, PHASES_AUDIT_MODEL, PHASES_AUDIT_API_KEY, ...

phases:
  # analysis:
  #   model: claude-opus-4-6
  #   context-limit: 500000
  #   max-output-tokens: 32000
  #   headers:
  #     - "anthropic-beta: context-1m-2025-08-07"

  # feature-detection:
  #   # Cheap model is fine here — output is a small feature list. But if
  #   # you use a different model than analysis, its tokenizer calibration
  #   # is discarded (different tokenizer = invalid measurement).
  #   provider: openai
  #   model: gpt-5.2
  #   api-key: ${OPENAI_API_KEY}

  # audit:
  #   # Example: run audit on a different provider entirely.
  #   provider: google
  #   model: gemini-3-pro
  #   api-key: ${GOOGLE_API_KEY}
  #   # Drop analysis-phase model-params that don't apply here:
  #   model-params: {}

# --- Audit tuning --------------------------------------------------------

# skip-audit: false
audit-confidence-threshold: 0.3   # reject findings below this (0.0-1.0)

# --- Output --------------------------------------------------------------

# output: results.sarif
# prompts-dir: ./prompts/default   # prompt set directory (see prompts/ for available sets)
`
