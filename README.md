# codecrucible

CodeCrucible is a command-line security analysis tool for source code
repositories. It uses large language models to review application code for
exploitable vulnerabilities, validates findings through a dedicated audit pass,
and writes standards-compliant [SARIF v2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
for GitHub Code Scanning and other SARIF-compatible workflows.

## Overview

CodeCrucible is designed for cost-aware, reproducible security scans of real
repositories. It ingests source files, filters low-value inputs, chunks large
codebases into model-safe prompts, runs configurable LLM analysis and audit
phases, and preserves phase artifacts for debugging and review.

- **No Node.js/Python runtime** — single binary, distroless Docker image (<50MB)
- **Structured output enforcement** — JSON Schema (`response_format`) for GPT/Gemini, `tool_use` for Claude
- **Per-phase LLM configuration** — run feature detection, analysis, and audit on different models, providers, keys, and params
- **Streaming responses** — SSE for Anthropic keeps long generations alive past edge idle timeouts
- **Token-aware chunking** — large repos are split into budget-safe chunks with cross-file manifests
- **Retry with backoff** — exponential backoff on 429/5xx, `Retry-After` header respect
- **Aggressive filtering** — test, vendor, binary, and doc file exclusion saves 20–40% token budget
- **Valid SARIF every time** — even on LLM failure, partial results produce schema-valid SARIF

## Quick Start

```bash
# Build
make build

# Databricks-backed scan
export DATABRICKS_HOST=https://your-workspace.databricks.com
export DATABRICKS_TOKEN=your-token

./codecrucible scan /path/to/repo --output results.sarif

# Direct Anthropic API scan
export ANTHROPIC_API_KEY=your-anthropic-key
./codecrucible scan /path/to/repo --provider anthropic --model claude-sonnet-5

# Anthropic API scan with higher effort
./codecrucible scan /path/to/repo \
  --provider anthropic \
  --model claude-sonnet-5 \
  --model-params '{"output_config":{"effort":"high"}}'

# Or use Claude Code CLI auth (SSO/login) with no API key
claude auth status
./codecrucible scan /path/to/repo --provider anthropic --model claude-sonnet-5

# In Claude CLI auth mode, Anthropic beta headers are forwarded via `claude --betas`
# (for example: --custom-headers "anthropic-beta: context-1m-2025-08-07").

# Direct OpenAI API scan
export OPENAI_API_KEY=your-openai-key
./codecrucible scan /path/to/repo --provider openai --model gpt-5.6

# Direct Google Gemini scan (OpenAI-compat endpoint)
export GOOGLE_API_KEY=your-google-key
./codecrucible scan /path/to/repo --provider google --model gemini-3.5-flash

# Mix providers per phase: opus for analysis, gemini for audit
export ANTHROPIC_API_KEY=your-anthropic-key
export GOOGLE_API_KEY=your-google-key
./codecrucible scan /path/to/repo \
  --model claude-opus-4-8 \
  --audit-provider google --audit-model gemini-3.1-pro-preview \
  --fd-model gemini-3.5-flash --fd-provider google

# Preview scope without making API calls
./codecrucible scan /path/to/repo --dry-run

# Scan specific paths in a monorepo
./codecrucible scan /path/to/repo --paths src/ --paths lib/
```

When `--output results.sarif` writes to a file, CodeCrucible also writes
phase artifacts beside it: `results.feature-detection.json`,
`results.analysis.sarif`, `results.audit.sarif` (when audit runs), and
`results.lineage.jsonl`. Use
`--phase-output-dir DIR` to choose an explicit artifact directory, including
for stdout workflows.

The versioned lineage file records model responses, immutable observations before
merge/filtering, subsequent finding revisions and each observation's final
disposition. SARIF results link to it through `properties.provenance`; existing
finding IDs and partial fingerprints remain the correlation keys. A shared
location and CWE no longer suffice to discard different evidence. Original
observations remain available even when the final result is suppressed or its
evidence is refined. A missing `run-complete` event indicates an interrupted run.
Lineage contains source excerpts and model output, like the other phase artifacts;
request headers and API credentials are not recorded. It is written incrementally
with owner-only permissions. No lineage file is written for stdout-only scans
without an artifact directory.

The v2 ledger binds observations to model responses (including repair operations),
records individual accepted, retried and unresolved audit decisions, and supports
split and semantic duplicate relationships. Validate either ledger version and
optionally reconcile final SARIF with:

```bash
codecrucible validate-lineage results.lineage.jsonl --sarif results.sarif
```

A recorded model verdict or source quote is not proof of exploitability.

To compare audit prompts or models without analysis variance, replay the audit
on saved findings: `codecrucible scan REPO --audit-from results.analysis.sarif`.
Replay ingests REPO with the same filters, skips feature detection and analysis,
and audits the saved claims under their original finding IDs. Only audit
requests are sent, and the cost preflight excludes analysis. The input can be
an analysis artifact or the final output of a `--skip-audit` scan; audited SARIF
is rejected, as is a replay where none of the findings' files are in REPO.
`recipe.auditReplay` in the run metadata records the input's SHA-256 and counts
findings whose file or snippet no longer matches the checkout; verdicts for
those findings are not comparable. Replay never rewrites the analysis artifact.

Dry runs show source-input cost plus a separate rough input-and-output estimate.
The planning estimate assumes 25% input overhead, output tokens equal to 1/16
of padded input, and one repository-sized audit pass when audit is enabled.
It displays a 2–3× allowance, not a ceiling. Separate feature detection,
context compression, retries, and repeated audit batches are excluded.
The existing preflight budget check uses source-input cost; runtime accounting
uses reported token usage. All dollar values depend on configured model rates.

## Installation

### From Source

```bash
git clone <repo-url> && cd codecrucible
make build
```

### Docker

```bash
make docker-build
docker run --rm \
  -e DATABRICKS_HOST=https://your-workspace.databricks.com \
  -e DATABRICKS_TOKEN=your-token \
  -v /path/to/repo:/repo:ro \
  codecrucible:latest scan /repo --output /dev/stdout
```

## Usage

```
codecrucible scan [repo-path] [flags]
```

### Per-phase LLM selection

Four symmetric flag families. The unprefixed flags configure the analysis
phase; feature-detection, audit, and context-compress inherit any knob
they don't set.

| analysis              | feature-detection *(alias: `--fd-*`)*    | audit                   | context-compress *(alias: `--cc-*`)*    |
|-----------------------|------------------------------------------|-------------------------|-----------------------------------------|
| `--model`             | `--feature-detection-model`              | `--audit-model`         | `--context-compress-model`              |
| `--provider`          | `--feature-detection-provider`           | `--audit-provider`      | `--context-compress-provider`           |
| `--api-key`           | `--feature-detection-api-key`            | `--audit-api-key`       | `--context-compress-api-key`            |
| `--base-url`          | `--feature-detection-base-url`           | `--audit-base-url`      | `--context-compress-base-url`           |
| `--model-params`      | `--feature-detection-model-params`       | `--audit-model-params`  | `--context-compress-model-params`       |

Providers: `anthropic`, `openai`, `google`, `cerebras`, `ollama`, `openai-compat`, `databricks`. Auto-detected from env vars when unset.

### Cerebras

Set `CEREBRAS_API_KEY` in your environment, then discover available model IDs:

```bash
codecrucible list-models --provider cerebras
codecrucible scan ./target --provider cerebras --model "$CEREBRAS_MODEL" --dry-run
codecrucible scan ./target --provider cerebras --model "$CEREBRAS_MODEL" --output results.sarif
```

`CEREBRAS_MODEL` here is a shell variable containing your selected model ID;
CodeCrucible reads the model from `--model` (or YAML / `PHASES_ANALYSIS_MODEL`).
You can select this deployment with `--provider cerebras --model kimi` (or
`PHASES_ANALYSIS_MODEL=kimi`). Kimi aliases are case-insensitive and tolerate
spaces, hyphens, underscores, and dots: `Kimi`, `kimi-k2`, and
`kimi-k2.6` resolve to `kimi-k2.6`. For an account-specific deployment ID,
set `model` in `model-params` (or `PHASES_ANALYSIS_MODEL_PARAMS_JSON` in your
local environment); this overrides the API model name without changing the
registry entry used for sizing and estimates. Exact custom registry entries
win; unknown versions and unrelated names are not rewritten.

Cerebras requires an explicit model. `kimi-k2.6` has a provisional registry
entry with **assumed** rates of $2/M input and $8/M output, not verified contract
pricing. It retains fallback limits of 128K context and 8192 output tokens and
uses live-verified JSON Schema output support. Every scan selecting it emits a
warning. Override the entry under `models:` once deployment settings are known.
Use `--fd-model`, `--audit-model`, and `--cc-model` to choose different models,
and the corresponding provider flags to mix providers.

The default base URL is `https://api.cerebras.ai`. Base URL overrides use the
same convention as the OpenAI provider: omit `/v1`, since the client appends
`/v1/chat/completions` (and model discovery appends `/v1/models`).

For a model absent from the registry, configure verified context/output limits,
pricing, and `supports_structured_output: true` under `models:` when the model
supports JSON Schema. See “Adding models via config” below. Unknown models use
128K context, 8192 output tokens, and no schema enforcement; these assumptions
may not match your endpoint. Use `--context-limit` and `--max-output-tokens` to
override limits. Cerebras models with no configured pricing emit a warning:
reported costs exclude their usage and `--max-cost` cannot enforce that spend.
Model listing discovers IDs; it does not populate pricing or capabilities.

The `zai-glm-5.3-flash` profile is an explicit opt-in for Cerebras deployments
that support JSON Schema output. It requires a full, case-insensitive name
match; shorter or custom IDs retain unknown-model defaults. Keep the actual
endpoint ID in local configuration, for example:

```bash
export PHASES_ANALYSIS_MODEL=zai-glm-5.3-flash
export PHASES_ANALYSIS_MODEL_PARAMS_JSON='{"model":"YOUR_DEPLOYMENT_ID","reasoning_effort":"max"}'
codecrucible scan ./target --provider cerebras --dry-run
codecrucible scan ./target --provider cerebras --output results.sarif
```

The profile uses the upstream model limits: 1,048,576 context tokens and
131,072 output tokens (including reasoning). Cerebras supports `low`, `high`,
and `max` reasoning effort for this model and defaults to `max`; reasoning
cannot be disabled. The example makes `max` explicit. See the
[model documentation](https://docs.z.ai/guides/vlm/glm-5.3-flash) and
[Cerebras reasoning controls](https://inference-docs.cerebras.ai/capabilities/reasoning).
Deployment-specific limits may be lower; override them under `models:` or with
per-phase context/output settings when necessary. JSON Schema output, `max`
reasoning, and the 131,072-token output allowance were accepted in a live
request, and a complete analysis/audit scan was verified. This does not
establish maximum-length generation or a fully occupied 1M-token context.

Pricing is unconfigured: reported costs exclude this model, and `--max-cost`
cannot enforce its spend. Configure contract pricing under `models:` before
relying on cost estimates.

When switching deployments, update the `model` override in local
`model-params` / `PHASES_ANALYSIS_MODEL_PARAMS_JSON` as well as the selected
profile. Request-body overrides determine the actual endpoint even after
changing `--model`. Clear old per-phase output-limit overrides to use the
profile's default. Set `exact_match: true` on custom `models:` entries to
exclude them from aliases and partial-name matching too.

### Custom / Local LLMs

Use `--provider ollama` for Ollama (no API key needed, defaults to `localhost:11434`):

```bash
codecrucible scan --provider ollama --model llama3.1:70b --context-limit 131072 .
```

Use `--provider openai-compat` for any OpenAI-compatible API (vLLM, LM Studio, text-generation-inference):

```bash
codecrucible scan --provider openai-compat --model my-model --base-url http://localhost:8000 .
```

### Per-Phase Overrides

Each pipeline phase (analysis, feature-detection, audit, context-compress) can use a different provider/model. Per-phase flags are hidden from `--help` for clarity but work as documented:

```bash
# Cheap model for feature detection, expensive model for analysis
codecrucible scan --model claude-opus-4-8 --feature-detection-model claude-sonnet-5 .
```

Per-phase flags follow the pattern `--{phase}-{flag}` (e.g. `--audit-model`, `--audit-provider`, `--audit-api-key`, `--audit-base-url`). Short aliases: `--fd-*` for feature-detection, `--cc-*` for context-compress.

### Everything else

```
  --audit-batch-size int               split audit into N-finding batches (default 25)
  --audit-confidence-threshold float   reject findings below this confidence (default 0.3)
  --audit-from string                  audit a saved analysis SARIF instead of running analysis
  --semantic-dedup string              v3 duplicate relationships: off or report (default report)
  --base-url string                    override default provider URL
  --compress                           compress whitespace in source files to save tokens
  --concurrency int                    max parallel chunks (default 3)
  --context-budget-pct int             % of context window for supplementary context (default 15, max 40)
  --context-limit int                  override model context window in tokens (0 = model default)
  --context-source strings             supplementary context: name=X,type=<path|repo|url|inline>,location=Y
  --custom-headers strings             extra HTTP headers, format 'Name: Value'
  --custom-requirements string         additional requirements appended to the prompt
  --dry-run                            preview scope and cost without API calls
  --exclude strings                    glob patterns to exclude
  --fail-on-severity float             exit code 2 if any finding >= this severity (0-10)
  --include strings                    glob patterns to force-include
  --include-docs                       include documentation files in analysis
  --include-tests                      include test files in analysis
  --max-cost float                     maximum cost budget in dollars (default 25)
  --max-file-size int                  exclude files larger than this (default 102400)
  --max-output-tokens int              override model max output tokens (0 = model default)
  -o, --output string                  write SARIF to file (default: stdout)
  --phase-output-dir string            write per-phase artifacts to this directory
  --paths strings                      paths within the repo to analyze
  --prompts-dir string                 prompt set directory (default: prompts/default)
  --request-timeout int                HTTP timeout in seconds (0 = default 600s)
  --skip-audit                         skip CWE-specific audit phase
  --skip-feature-detection             skip feature detection pre-pass

Global Flags:
  --config string   config file (default: .codecrucible.yaml)
  --verbose         enable debug logging
```

## Agent Skill

An agent-facing skill for running and interpreting CodeCrucible scans lives at
[`.agents/skills/codecrucible/SKILL.md`](.agents/skills/codecrucible/SKILL.md).
It covers scan planning, model and prompt selection, cost checks, and SARIF
interpretation.

## Prompt Sets

The `prompts/` directory contains multiple prompt sets, each a complete set of YAML templates that control how the LLM analyzes code. The default set is `prompts/default/`.

To use a different prompt set:

```bash
codecrucible scan --prompts-dir prompts/carlini .
```

Available sets:

| Set | Description |
|-----|-------------|
| `default` | General-purpose security analysis (used when no `--prompts-dir` is specified) |
| `core` | Default analysis with the v2 audit contract: evidentiary questions, code-computed verdicts, and weakness-family cards (experimental) |
| `carlini` | Slim Carlini-style adversarial CTF-researcher prompts |
| `carlini-curated` | Carlini v2 with targeted suppression rules and line-precision guidance |
| `exploit-proof` | Language-agnostic set that requires a concrete exploit per finding |
| `exploit-proof-c-kernel` | Kernel / driver / systems C — syscalls, copy{in,out}, locking, refcounts |
| `exploit-proof-c-userland` | C/C++ userland daemons, setuid binaries, parsers |
| `exploit-proof-rust` | Rust (`unsafe`, FFI, serde, integer casts, web frameworks) |
| `exploit-proof-solidity` | Solidity / Vyper — reentrancy, oracle manipulation, access control |
| `exploit-proof-web-go` | Go web services (net/http, gin, chi, echo, fiber, gRPC) |
| `exploit-proof-web-java` | JVM web apps (Spring, Jakarta EE, Quarkus, Micronaut, Ktor) |
| `exploit-proof-web-js` | Node.js backends and JS/TS frontends (Express, Next.js, React, Vue) |
| `exploit-proof-web-python` | Python web apps (Django, Flask, FastAPI, Starlette, Tornado, aiohttp) |
| `nano-analyzer` | Terse attacker-first voice adapted from weareaisle/nano-analyzer |

See [PROMPT_SETS.md](PROMPT_SETS.md) for a fuller walkthrough of when to reach for each set.

Each prompt set directory must contain: `security_analysis_base.yaml`, `analysis_sections.yaml`, `feature_detection.yaml`, `audit.yaml`, and optionally `context_compress.yaml`. A legacy audit (`audit.yaml` without a contract) also reads `cwe_deep_analysis.yaml`; v2 and v3 audits require `audit_families.yaml` instead.

## Configuration

Configuration follows a priority chain: **CLI flags > environment variables > config file > defaults**.

### Environment Variables

**Ambient credentials** — cascade to any phase that doesn't set its own key:

| Variable | Description |
|----------|-------------|
| `DATABRICKS_HOST` | Databricks workspace URL |
| `DATABRICKS_TOKEN` | Bearer token for API authentication |
| `DATABRICKS_ENDPOINT` | Model serving endpoint (overrides `--model`) |
| `ANTHROPIC_API_KEY` | Anthropic API key (optional if Claude Code CLI is installed and logged in) |
| `OPENAI_API_KEY` | OpenAI API key |
| `CEREBRAS_API_KEY` | Cerebras API key |
| `GOOGLE_API_KEY` / `GEMINI_API_KEY` | Google AI Studio API key |
| `CODECRUCIBLE_PROVIDER` | Provider override (`databricks`, `anthropic`, `openai`, `google`, `cerebras`) |
| `CODECRUCIBLE_MODEL_PARAMS` | JSON object merged into model request body |

**Per-phase overrides** — `PHASES_<PHASE>_<KEY>` where `<PHASE>` is `ANALYSIS`,
`FEATURE_DETECTION`, `AUDIT`, or `CONTEXT_COMPRESS`:

| Variable | Maps to |
|----------|---------|
| `PHASES_AUDIT_PROVIDER` | `--audit-provider` |
| `PHASES_AUDIT_MODEL` | `--audit-model` |
| `PHASES_AUDIT_API_KEY` | `--audit-api-key` |
| `PHASES_AUDIT_MODEL_PARAMS_JSON` | `--audit-model-params` |
| `PHASES_AUDIT_BASE_URL` | override the provider's default base URL (proxies, Azure, Vertex) |
| `PHASES_AUDIT_ENDPOINT` | Databricks serving-endpoint override for this phase |
| `PHASES_AUDIT_REQUEST_TIMEOUT` | per-phase HTTP timeout in seconds |
| `PHASES_AUDIT_CONTEXT_LIMIT` | per-phase context window override |
| `PHASES_AUDIT_MAX_OUTPUT_TOKENS` | per-phase max output override |

Same keys with `PHASES_ANALYSIS_*`, `PHASES_FEATURE_DETECTION_*`, and
`PHASES_CONTEXT_COMPRESS_*`. Handy for wrapper scripts that inject
per-phase config via env.

### Config File

Create `.codecrucible.yaml` in your repo root or home directory:

```yaml
model: claude-sonnet-5
provider: anthropic
include-tests: false
include-docs: false
max-cost: 25
fail-on-severity: 7.0
concurrency: 3
model-params:
  output_config:
    effort: high
skip-audit: false
audit-confidence-threshold: 0.3
exclude:
  - "*.generated.go"
  - "**/generated/**"
```

### Per-Phase Configuration

The pipeline has four LLM phases: **feature detection** (gating, skipped for
small repos), **analysis** (the main loop), **audit** (validation), and
**context compress** (optional supplementary-context summarization). Each can
run on a different provider, model, API key, and params.

The flat keys above (`model`, `provider`, `model-params`) configure the
analysis phase and are **inherited** by the other phases. A `phases:` block
overrides selectively:

```yaml
# Analysis: Opus with adaptive thinking and xhigh effort. Slow, thorough, expensive.
model: claude-opus-4-8
provider: anthropic
model-params:
  thinking:
    type: adaptive
  output_config:
    effort: xhigh

phases:
  # Feature detection is a cheap gating pass on a file manifest. A small
  # fast model is plenty. Skipped entirely when the repo fits in one chunk.
  feature-detection:
    provider: google
    model: gemini-3.5-flash
    api-key: ${GOOGLE_API_KEY}
    # Switching providers clears inherited provider-specific parameters.
    # Optional Gemini-specific parameters:
    model-params:
      max_tokens: 2048

  # Audit is a validation pass — short, structured output. Dropping
  # analysis-only adaptive-thinking params keeps it fast without hurting
  # quality.
  audit:
    model: claude-sonnet-5
    model-params:
      output_config:
        effort: low
    # provider, api-key: inherited from analysis (anthropic + its key)
```

**Inheritance rules**

- Any per-phase field left at its zero value inherits from the analysis phase.
- When the resolved provider changes, API key, base URL, endpoint, headers, and
  model parameters are reset before applying explicit phase overrides. The new
  provider uses its own ambient credentials and default URL.
- `model-params` inherits on empty; a phase that sets its own params gets
  **exactly** those params (replace, not merge) — so you can drop inherited
  keys.
- `--context-limit` / `--max-output-tokens` inherit per-phase too. Previously
  they only applied to the main model; now `--audit-model gemini-3.1-pro-preview` with
  `--context-limit 500000` gives audit the override as well.

**Provider resolution**, per phase: explicit `--<phase>-provider`, else the
model registry's hint for that phase's model, else Databricks ambient env
(Databricks proxies all providers), else whichever direct-provider key is
set, else `databricks`.

### Supplementary Context

Security review in isolation is pattern-matching. Security review with the
API spec, the threat model, and the sibling repo that implements the other
side of an RPC contract is *understanding*. Supplementary context feeds that
material to the analysis and audit prompts so the model can distinguish
"unvalidated input" from "input validated by the gateway three hops upstream".

**Source types:**

| type     | `location` is…                       | notes                                        |
|----------|--------------------------------------|----------------------------------------------|
| `path`   | filesystem path (file or directory)  | directories go through the ingest walker — `.gitignore`, binary-skip, and `include`/`exclude` globs all apply |
| `repo`   | git clone URL                        | shallow-cloned to a temp dir, then treated as `path` |
| `url`    | HTTP(S) URL                          | 4 MiB cap, HTML stripped to text, non-HTTP schemes and private-IP redirects refused |
| `inline` | the content itself                   | for short notes — "admin routes are mTLS-gated" |

**Budget discipline.** Supplementary context shares the context window with
the scan target, so it's capped at `--context-budget-pct` (default 15%, hard
ceiling 40%). When sources exceed the cap:

1. **Priority packing** (always): sources are sorted by `priority` descending
   and packed greedily. The last source that doesn't fully fit is truncated
   with a `[... N tokens truncated ...]` marker; anything after is dropped.
2. **LLM compression** (opt-in per source): sources with `compress: true`
   that exceed their fair share of the budget go through a one-shot
   `context-compress` pre-pass that summarises them down. Runs once per scan
   on the `phases.context-compress` model — typically a cheap flash/haiku.

Why this approach: relevance-filtering and embedding retrieval both assume
you can pick different context per chunk, but supplementary context is shared
across all chunks — the API spec is relevant everywhere. Priority packing is
deterministic and free; LLM compression handles the "200-page API reference"
case without adding an embedding-model dependency.

```yaml
context-sources:
  - name: "Payments API Spec"
    type: path
    location: ../api-contracts/payments/openapi.yaml
    priority: 100
    phases: [analysis, audit]        # empty/omitted = both phases

  - name: "Auth SDK"
    type: repo
    location: git@github.com:org/auth-sdk.git
    priority: 80
    include: ["**/*.go"]
    compress: true                   # squeeze via LLM if over budget

  - name: "Threat model"
    type: url
    location: https://wiki.internal/threat-model/payments
    priority: 90
    phases: [audit]                  # only the auditor needs this

  - name: "Review notes"
    type: inline
    location: |
      The /admin endpoints sit behind mTLS at the gateway. Findings
      there must demonstrate gateway bypass, not just handler weakness.
    priority: 70

context-budget-pct: 15

phases:
  context-compress:
    model: claude-haiku-4-5          # compression is a writing task, not analysis
```

On the CLI (scalar fields only — use the config file for globs and phase lists):

```bash
./codecrucible scan ./target \
  --context-source 'name=spec,type=path,location=../contracts/api.yaml,priority=100' \
  --context-source 'name=notes,type=inline,location=admin is mTLS-gated,priority=50' \
  --context-budget-pct 20 \
  --cc-model claude-haiku-4-5
```

**Guardrails.** Load failures (404, clone error, missing file) log a warning
and skip that source — the scan continues. If context consumes so much of the
window that less than 5000 tokens remain for actual source code, the scan
aborts before any LLM call with a clear error.

### Model Params

`model-params` is merged into the top level of the request body — use it for
provider-specific knobs (adaptive thinking, reasoning effort, custom safety
settings).

- YAML map form in config files; JSON string form on the CLI and in env vars.
- When both are present, the JSON string deep-merges onto the map; JSON wins
  on conflict.
- Not forwarded when Anthropic falls back to Claude CLI auth.
- Unknown keys are passed through; the provider rejects what it doesn't
  understand.

## Supported Models

| Model | Provider | Context Limit | Max Output | Structured Output |
|-------|----------|--------------|------------|-------------------|
| claude-sonnet-5 | anthropic | 1M | 128K | output_config.format JSON Schema |
| claude-opus-4-8 | anthropic | 1M | 128K | output_config.format JSON Schema |
| claude-fable-5 | anthropic | 1M | 128K | output_config.format JSON Schema |
| claude-haiku-4-5 | anthropic | 200K | 64K | output_config.format JSON Schema |
| goose-claude-4-6-opus | databricks | 200K | 32K | tool_use |
| goose-claude-4-7-opus | databricks | 1M | 128K | tool_use |
| gpt-5.6 | openai | 1.05M | 128K | response_format JSON Schema |
| gpt-5.6-sol | openai | 1.05M | 128K | response_format JSON Schema |
| gpt-5.6-terra | openai | 1.05M | 128K | response_format JSON Schema |
| gpt-5.6-luna | openai | 1.05M | 128K | response_format JSON Schema |
| gpt-5.5 | openai | 1.05M | 128K | response_format JSON Schema |
| gpt-5.5-cyber-preview | openai | 272K | 128K | response_format JSON Schema |
| gpt-5.5-cyber | openai | 272K | 128K | response_format JSON Schema |
| gpt-5.4 | openai | 1.05M | 128K | response_format JSON Schema |
| gpt-5.4-mini | openai | 400K | 128K | response_format JSON Schema |
| gpt-5.4-nano | openai | 400K | 128K | response_format JSON Schema |
| gemini-3.1-pro-preview | google | 1M | 64K | response_format JSON Schema |
| gemini-3.5-flash | google | 1M | 64K | response_format JSON Schema |
| gemini-3.1-flash-lite | google | 1M | 64K | response_format JSON Schema |

The registry also carries the documented long-context pricing tiers for the
`gpt-5.6` family, `gpt-5.5`, and `gpt-5.4` prompts above 272K input tokens,
and `gemini-3.1-pro-preview` prompts above 200K input tokens.

`gpt-5.6` is OpenAI's stable alias for `gpt-5.6-sol`; both entries use Sol
pricing. The direct `gpt-5.6-terra` and `gpt-5.6-luna` entries expose the
documented lower-cost tiers. All GPT-5.6 entries emit an execution warning
because OpenAI documents real-time cyber safeguards that can block or pause
generation during security work.

`gpt-5.5-cyber-preview` and `gpt-5.5-cyber` are private/preview aliases with
no public provider model page yet. Their built-in entries use the currently
observed 272K context window plus GPT-5.5 request semantics and pricing, and
emit a warning that those registry parameters and cost estimates are
provisional. Override the entry under `models:` when your provider exposes
different limits or billing.

`claude-fable-5` also emits an execution warning because security-policy
errors during a security scan can invalidate the resulting findings. Some
Anthropic workspaces also require data retention to be enabled before this
model is accessible; when the provider rejects access, CodeCrucible writes a
failed SARIF invocation and exits non-zero.

The `goose-*` Databricks rows are workspace serving aliases, not public model
IDs. They stay explicit because a public provider release does not establish
which deployment name a Databricks workspace exposes.

Gemini goes through Google's OpenAI-compat endpoint
(`generativelanguage.googleapis.com/v1beta/openai`) — Bearer auth, OpenAI
request/response shapes. Gemini-specific features (grounding, code execution)
are not available through this path; set `phases.<phase>.base-url` to point
at Vertex or a proxy if you need them.

All providers are also reachable via Databricks model serving when
`DATABRICKS_HOST`/`DATABRICKS_TOKEN` are set.

Unknown models get conservative defaults (128K context, 8192 max output,
unstructured). Override with `--context-limit` / `--max-output-tokens`.

### Adding models via config

The table above is the *built-in* registry compiled into the binary. You can
extend or override it from the config file under a `models:` key — useful when
a new model ships, when you run behind a proxy with a custom endpoint, or when
you want to retune pricing / context limits without recompiling.

```yaml
models:
  # Extend: a model the binary doesn't know about yet.
  - name: gpt-acme-frontier-v1
    provider: openai-compat
    execution_warning: registry parameters are operator supplied
    input_price_per_million: 3.0
    output_price_per_million: 15.0
    context_limit: 1000000
    max_output_tokens: 64000
    tokenizer_encoding: o200k_base
    supports_structured_output: true

  # Override: change a built-in's pricing without forking.
  - name: gpt-5.5
    provider: openai
    input_price_per_million: 4.5   # negotiated rate
    output_price_per_million: 27.0
    long_context_threshold: 272000
    long_context_input_price_per_million: 9.0
    long_context_output_price_per_million: 40.5
    context_limit: 1050000
    max_output_tokens: 128000
    tokenizer_encoding: o200k_base
    supports_structured_output: true
    use_max_completion_tokens: true

  # Azure / self-hosted: point at a non-standard endpoint.
  - name: azure-gpt-5
    provider: openai-compat
    endpoint: deployments/my-azure-deploy/chat/completions
    context_limit: 400000
    max_output_tokens: 16384
    tokenizer_encoding: o200k_base
```

Entries are keyed by `name`: a user entry sharing a name with a built-in
replaces it wholesale (case-insensitive), a new name extends the registry.
Empty `endpoint` defaults to `<name>/invocations` to match the built-in
convention (Databricks serving path; other providers ignore it). `name` is
required; other fields follow the same YAML schema as the built-in registry.
Set `execution_warning` when a model has provisional limits, estimated
pricing, or operational caveats that should be logged whenever a scan selects
it.


## Architecture

```
Repository on disk
    │
    ▼
┌──────────────┐
│   Walker     │  filepath.WalkDir + .gitignore
├──────────────┤
│   Filter     │  Test/vendor/binary/doc exclusion
├──────────────┤
│  Flattener   │  Repomix-compatible XML with line numbers
├──────────────┤
│   Chunker    │  Token-budget-aware splitting by directory
└──────┬───────┘
       │
       │         PhaseConfig: each box has its own (provider, model,
       │         api-key, base-url, model-params, timeout). Unset
       │         fields inherit from analysis. Resolved once at
       │         startup by config.ResolvePhases.
       │
       │  repo > one chunk?
       ▼
┌─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┐    ┌──────────────────────────┐
                                       │ phases.feature-detection │
│  FEATURE DETECTION  (optional)  │◀───│  --fd-provider           │
                                       │  --fd-model              │
│  file manifest → features       │    │  --fd-api-key            │
                                       │  --fd-model-params       │
└─ ─ ─ ─ ─ ─ ─ ─ ┬ ─ ─ ─ ─ ─ ─ ─ ─┘    └──────────────────────────┘
                 │ enabled features → prunes analysis_sections
                 ▼
┌─────────────────────────────────┐    ┌──────────────────────────┐
│                                 │    │ phases.analysis          │
│  ANALYSIS  (main loop)          │◀───│  --provider              │
│                                 │    │  --model                 │
│  chunk 1 ──▶ findings           │    │  --api-key               │
│  chunk 2 ──▶ findings  } merge  │    │  --model-params          │
│  chunk N ──▶ findings           │    └──────────────────────────┘
│  (concurrent, --concurrency)    │
│                                 │
└────────────────┬────────────────┘
                 │ initial findings + CWE categories
                 ▼
┌─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┐    ┌──────────────────────────┐
                                       │ phases.audit             │
│  AUDIT  (optional, --skip-audit)│◀───│  --audit-provider        │
                                       │  --audit-model           │
│  findings + code + CWE prompts  │    │  --audit-api-key         │
│  → confirm / reject / refine    │    │  --audit-model-params    │
                                       └──────────────────────────┘
└─ ─ ─ ─ ─ ─ ─ ─ ┬ ─ ─ ─ ─ ─ ─ ─ ─┘
                 │ audited findings
                 ▼
┌─────────────────────────────────┐
│   SARIF build + merge + dedup   │
└────────────────┬────────────────┘
                 ▼
          SARIF v2.1.0 output
          + phase artifacts
```

Each phase builds its own `llm.Client` from its `PhaseConfig` — there is no
shared client object. A fresh client per phase means the learned endpoint
constraints (`noForcedToolChoice`, `dropTemperature`) reset at phase
boundaries; at most one extra 400→retry per phase when the model rejects
a feature.

### Source ingestion and context

After walking and filtering the repository, CodeCrucible builds one immutable
index of the admitted source. Feature sampling, dependency-aware chunking,
cross-chunk declaration summaries, and both audit contracts reuse that index.
The scanner needs source files, not a successful build: it does not install
dependencies, invoke a compiler, or fetch missing imports. Unknown languages
retain their original source and lexical context. A failed Go parse falls back
to lexical extraction without inventing argument bindings.

Dependency grouping follows imports only when they resolve to admitted local
files. The current resolvers cover JavaScript/TypeScript relative imports,
Python repository and relative modules, Go packages (including local `go.mod`
roots), explicit Kotlin imports, and quoted C/C++ includes. External and
vendored imports are skipped; missing and ambiguous candidates remain
unresolved. Unsupported import forms use the existing directory grouping.
Language-specific readers produce source facts, not security rules or verdicts.
Relative JavaScript/TypeScript imports prefer an exact admitted file, then
try source extensions and index files, including dotted basenames such as
`./config.types`. Multiple inferred matches remain ambiguous.

Small repositories keep the single-chunk path. Larger scans keep whole files
together where the token budget permits, assign dependencies alongside their
importers, and use short declaration summaries for dependencies in other
chunks. Graph grouping is compared with directory grouping at the same budget.
It is selected only when it improves chunk count, unique dependency-edge
co-location, or duplicated bytes without worsening another measure; ties and
tradeoffs keep directory grouping. Both candidates retain cross-chunk summaries
and are checked against the rendered XML budget. These are packing measures,
not evidence of better vulnerability detection.
A few small, high-priority files can be shared. Files larger than a
chunk budget remain in the coverage report and cause an incomplete-analysis
warning; a manifest entry alone does not count as analyzed source.

Audit can request additional numbered excerpts from the same indexed bytes,
independent of the original analysis chunk. `--audit-from` builds a fresh index
of the supplied checkout and keeps its existing drift checks and finding IDs.
Supplementary context retains its separate loading, packing, and compression
policy.

The extractor interface allows richer parsers later. A new parser must first
demonstrate useful local-import/declaration accuracy on incomplete source,
lower context duplication or better evidence retrieval, and acceptable runtime
and memory use. It must also preserve `CGO_ENABLED=0` builds and the documented
single-binary/container constraints. No additional parser runtime is required.

### Project Structure

```
cmd/codecrucible/       CLI entry point
internal/
  cli/                  Cobra commands (scan, list-models, init), pipeline orchestration
  config/               Viper config, model registry, per-phase resolution (phase.go)
  ingest/               File walker, filter, XML flattener
  sourceindex/          Shared source facts, local imports, declarations, fingerprints
  auditctx/             Bounded audit context selection and rendering
  chunk/                Token counting (tiktoken), budget-aware chunking
  supctx/               Supplementary-context loaders, priority packing, LLM compression
  llm/                  HTTP client, prompt templates, JSON schema
  sarif/                SARIF types, builder, merger, post-processor, contract tests
  logging/              slog-based structured logging
prompts/                Prompt sets (each subdirectory is a complete set of YAML templates)
  default/                  Default prompt set
  carlini/                  Carlini-style adversarial prompts
  carlini-curated/          Carlini v2 with targeted suppression
  exploit-proof/            Language-agnostic concrete-exploit gate
  exploit-proof-c-kernel/   Kernel / systems C
  exploit-proof-c-userland/ C/C++ userland, setuid, parsers
  exploit-proof-rust/       Rust (unsafe, FFI, web frameworks)
  exploit-proof-solidity/   Solidity / Vyper smart contracts
  exploit-proof-web-go/     Go web services
  exploit-proof-web-java/   JVM web applications
  exploit-proof-web-js/     JS/TS backends and frontends
  exploit-proof-web-python/ Python web applications
  nano-analyzer/            Terse attacker-first voice (nano-analyzer port)
testdata/fixtures/      LLM response fixtures for contract tests
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Analysis completed, possibly with audit warnings (no findings above threshold) |
| 1 | Error (analysis/pipeline failure, cancellation, or SARIF invocation failure) |
| 2 | Findings exceed `--fail-on-severity` threshold |

Analysis failures still write partial SARIF when possible and return exit code 1.
Check `runs[0].invocations[0].executionSuccessful` and
`toolExecutionNotifications` for failure details.

Audit is best effort. If any audit batch remains unavailable, completed audit
verdicts are preserved and the remaining findings are retained with
`properties.auditStatus: "not_audited"` and `auditReasons: ["missing_verdict"]`. The run
contains a warning notification and its audit phase metadata has status
`incomplete`. This does not fail CI, even when all audit batches are unavailable.
It does not turn an analysis failure or cancellation into a successful scan.
The `--fail-on-severity` threshold still applies to retained findings.

HTTP requests use up to three retries for network/read failures, request
timeouts, HTTP 408/429, and all 5xx responses. Retries use exponential backoff
with jitter and respect `Retry-After`. HTML 403 responses from intermediaries
use the same policy; JSON/plain-text permission errors and HTTP 401 fail
immediately. Cancellation stops retries. Audit additionally retries malformed,
truncated, or incomplete verdict output once after attempting local JSON repair.
Valid verdicts are retained, and only unassessed claims are retried. Both audit
contracts match by `finding_id`, so a refined title or location cannot invalidate
another finding's verdict. Older responses without IDs can match only an exact,
unique original title/file/line key. Primary source and retrieved excerpts use
the same original line numbering.
Both generations count toward reported token usage and cost. Transport retry
exhaustion does not start a second audit-level HTTP retry cycle.

## SARIF descriptions and scan comparisons

Each result is a self-contained finding with its own rule, whose ID is
`codecrucible.` plus the finding ID. GitHub renders result messages as plain
text and only `rule.help` as Markdown, so the writeup lives on the rule:
`rule.fullDescription` is the finding's summary, and `rule.help` adds its audit
status, remediation, and technical details (escaped, collapsed in Markdown).
`result.message.text` is a one-line annotation: the summary's first sentence and
the audit status. The rule's `security-severity` and CWE tag are the finding's
own. Rule IDs exclude model wording, so a reworded title keeps its alert.

Per-finding state lives in `result.properties`:

| Property | Meaning |
|----------|---------|
| `findingId` | Stable ID (`CC-` + 16 hex). Also in `partialFingerprints["codecrucibleFinding/v1"]` |
| `verified` | `true` only when the audit confirmed, refined, or escalated the finding and did not suppress it |
| `auditStatus` | `confirmed`, `refined`, `escalated`, `unverified`, `rejected`, `duplicate` (v2), `new` (added by the audit), or `not_audited` |
| `auditConfidence` | Audit confidence, 0–1 |
| `auditJustification`, `auditBlockingCode` | The auditor's reasoning and, for rejections, the quoted blocking source |
| `auditReasons` | Machine-readable qualifiers: `missing_verdict`, `audit_skipped`, `ungrounded_rejection`, `below_confidence_threshold`; v2 adds `refuted:<question>`, `unknown:<question>`, `ungrounded_refutation:<question>`, `unverified_evidence:<question>`, and `duplicate` |
| `auditAnswers` | v2: each audit question's `status` (`established`, `refuted`, `unknown`), reason, and the evidence quotes that matched the source |
| `auditCrux` | v2: for an unverified finding, the code or fact that would decide it |
| `duplicateOf` | v2: the finding ID this one duplicates (same root cause and fix) |
| `deploymentExposure` | v2: `default_on`, `config_enabled`, `config_dependent`, `not_deployed`, or `unknown`, with detail and evidence. Informational; never changes the verdict |
| `severity`, `cwe` | This finding's own severity (0–10) and CWE, including audit refinements |
| `summary`, `remediation`, `technicalDetails` | Reviewer summary, fix, and full evidence |
| `reportedPath` | The model's file path, when it named no scanned file and was repaired to the one scanned file it uniquely matches (for example a dropped `app/` prefix) |

The finding ID hashes the CWE (or rule ID), file path, and whitespace-normalized
flagged source. It excludes model wording and line numbers, so rescans of
unchanged code and unrelated edits that shift lines keep the same ID. IDs are
assigned before the audit, so an audit-refined CWE does not change them.

Audit rejections and findings below `--audit-confidence-threshold` are retained
as suppressed results (`suppressions[].kind: "external"`, `status: "accepted"`,
with the audit justification) and `auditStatus: "rejected"`. They do not count
toward `--fail-on-severity`. Consumers that ignore SARIF suppressions will
display them; filter on `suppressions` or `properties.auditStatus`.

A prompt set opts into the v2 audit contract with `contract: v2` in
`audit.yaml`. For each finding, the auditor answers three questions with quoted
source evidence. `attacker_control` asks whether attacker input reaches the
flagged code. `privilege_boundary` asks whether the finding grants more than the
attacker already holds. `unmitigated` asks whether the path lacks a guard. The
verdict is computed from the answers. A question refuted by a quote that matches
the source, within two lines of the cited line, rejects the finding. If all
three are established, the finding is confirmed. Anything else leaves it
unverified. A refutation without a matching quote counts as unknown, so missing
evidence never rejects. A v2 audit has no confidence, so
`--audit-confidence-threshold` does not apply. Findings are matched by
`findingId`, and claims the response omits are retried once.

The opt-in `prompts/core` set uses `contract: v3`. V3 binds each assessment to
an immutable claim revision and digest. It asks separately about attacker
control, the source weakness, the security boundary, the missing control, and
the claimed impact. Established and refuted answers require source evidence.
Consumer and guard expressions must occur in their respective quotes; renamed
values require explicit, quoted flow steps. A missing guard is represented by
`guard_state: not_found` with source evidence for the actual protection point. These checks establish source
correspondence, not whole-program data flow. Unsupported impact stays unresolved.
Version-dependent framework assumptions require the runtime, version and cited
behavior. Explicit supplementary context can support an assumption, but cannot
become a source location.

V3 retries invalid claims individually and permits one bounded local-context
expansion. Its context artifacts record included ranges and omissions. Grouped
claims can produce separately audited children with stable IDs and `split_from`
lineage. An unresolved remainder remains visible unless the child records retain
all original material. `--semantic-dedup report` adds attributed duplicate
relationships without hiding findings; `off` disables those extra requests.
Suppression is deliberately unavailable until held-out duplicate-precision and
claim-preservation checks pass. Legacy and v2 prompt sets retain their contracts.

Use frozen analysis artifacts to compare audit implementations. The offline
scorer accepts independently adjudicated labels:

```bash
codecrucible evaluate-audit results.sarif --labels labels.json
```

The label file contains `cases` and `pairs` arrays. A case identifies a
`finding_id` and labels `weakness` as `valid`, `invalid`, or `unknown`; optional
`impact` is `supported`, `unsupported`, or `unknown`. A child can instead be
selected by `parent_id`, `file`, `line`, and `claim_contains`. A pair contains
`left`, `right`, and a Boolean `duplicate`. The report includes missing cases,
known-positive suppression, invalid/unsupported-impact confirmations, labeled
duplicate precision with 95% intervals, and recorded audit-model usage. Keep
tuning cases separate from held-out evaluation and record elapsed time alongside
each replay.

All audit contracts carry more than the files the findings cite. Up to about 24K
tokens of excerpts are retrieved per batch, with real line numbers, so the
auditor can check what decides a claim:

- references to the flagged function, such as route registration;
- templates the flagged code renders;
- functions or constructors receiving the flagged expression, and one further
  call using the corresponding parameter;
- definitions of the functions and types it uses.

Retrieval is deterministic. Language adapters supply syntax and name lookup;
the shared engine controls traversal limits, ranking, excerpt coverage and the
token budget. Go uses its standard parser. Kotlin has a dedicated syntax reader
for ordinary functions, primary constructors, objects, named arguments and
import aliases. Other languages retain lexical retrieval without parameter
binding. Go parse failures also fall back to lexical retrieval.

Retrieval supplies context candidates, not vulnerability verdicts or proof of
data flow. Ambiguous definitions and unsupported Kotlin dispatch remain
unresolved; overload selection, extension dispatch, wildcard imports and
implicit receivers are not inferred. Comments and string contents cannot
establish a parameter binding. Supplying an excerpt does not mark the rest of
its file as supplied, so a helper elsewhere in that file can still be retrieved.

Each v2 batch also lists the scan's other findings, so the auditor
doesn't repeat them as leads. Notes the auditor
makes about possible issues outside the findings are recorded as
`execution.auditLeads` in the run metadata, not as findings.

Older/custom prompts without a reviewer summary use the first narrative
paragraph of the technical details, limited to 1000 characters.

Analysis and audit schemas request an ordered `code_path` of exact files,
line ranges, and step explanations. Valid paths become
`codeFlows[].threadFlows[].locations[]`, which GitHub uses for expandable source
walkthroughs. Every step must refer to source present in the scan with a valid
range; an invalid step omits the whole path rather than inventing a connection.
Audit receives the path's source files and replaces the analysis path with its
reviewed path. Unverified findings have no final code flow. These fields describe
model-reported evidence, not a proven execution trace.

Every SARIF run includes `properties.codecrucible` with `schemaVersion: 1`:

| Field | Contents |
|-------|----------|
| `recipe` | Scanner version/commit, resolved phase configurations, scan controls, prompt identity, custom-requirement and supplementary-source fingerprints |
| `recipe.phases` | Analysis, feature detection, audit, and context compression: provider/model, sanitized base URL/endpoint, transport, model parameters, context/output limits, temperature settings, output mode, timeout, tokenizer, and pricing assumptions |
| `recipe.controls` | Scope filters, test/document inclusion, file-size limit, compression, concurrency, cost limit, severity gate, phase toggles, audit confidence/batch size, and context budget |
| `recipeFingerprint` | SHA-256 of the canonical JSON recipe (sorted object keys, preserved array order); excludes output paths, credentials, timestamps, and execution outcomes |
| `execution` | Artifact stage, phase statuses and actual phase configurations, fallbacks, per-phase model calls, the models used, detected features, token correction, chunk/recovery counts, source loading/compression outcomes, and packed-context fingerprints/truncation |
| `execution.sourceIndex` | Extractor version, fingerprints of admitted source bytes and the index, file/line counts, extraction modes, and import-resolution counts |
| `execution.sourceBundles` | Fingerprints of the source context assembled for feature detection, analysis chunks/recovery, and audit batches |
| `execution.sourceCoverage` | Admitted, planned, and successfully analyzed file counts; repeated files (including retries), and repo-relative lists of unplanned or unanalyzed files |

Phase configuration reflects inheritance and overrides after configuration
resolution. Model parameters are recorded separately from model-registry
defaults; they can override request-body fields. `execution.phases.*.actual`
identifies the configuration used when a phase ran, including fallback to the
analysis client. `requestPolicy` explains exceptions such as Claude CLI-managed
sampling and context compression's per-source output limits.

`execution.phases.*.models` tallies each phase's requests by the model ID sent,
which is the `model-params.model` override when one is set. For each ID it
records the IDs the provider reported serving the requests, call and failure
counts, token usage, and the cost estimated at the configured prices. It also
counts successful requests that were sent without a temperature or with
`max_completion_tokens`, including after the client drops a field the endpoint
rejected. `execution.models` lists the distinct models that served the scan:
the provider-reported IDs, or the sent ID when a provider reports none. Calls
count client requests, not the client's internal retries. Provider-side
defaults are not recorded.

Analysis, audit, and final files have independent execution snapshots and the
same recipe fingerprint. `pending` means a phase had not run at that snapshot;
`skipped`, `completed`, `incomplete`, and `failed` describe its outcome. Empty scans include
metadata too, but do not fetch supplementary sources; prompt fingerprints are
included when local templates are available. Failed or empty context sources
have no content fingerprint, and a skipped audit has no audit artifact.

API keys, tokens, header values, raw arguments, and environment variables are
excluded from metadata. URLs omit credentials, queries, and fragments. Known
numeric/boolean tuning parameters and supported enumerations are readable;
other parameter values use `{ "omitted": true, "fingerprint": "sha256:…" }`.
Credential-named parameter fields are excluded entirely. Prompt templates,
custom requirements, and loaded context are fingerprinted, not embedded;
context locations and absolute prompt-directory paths are omitted. Treat the
SARIF file itself as source-derived data: finding messages and snippets still
contain evidence from the scanned repository.

Compare the saved SARIF artifacts directly; GitHub does not expose arbitrary
custom SARIF properties in its alert interface:

```bash
# Inspect configuration and execution outcomes.
jq '.runs[0].properties.codecrucible' results.sarif

# Show the models each phase used.
jq '.runs[0].properties.codecrucible.execution | {models, phases: (.phases | map_values(.models))}' results.sarif

# Compare recipes, excluding differences caused only by run outcomes.
jq -S '.runs[0].properties.codecrucible.recipe' before.sarif > before.recipe.json
jq -S '.runs[0].properties.codecrucible.recipe' after.sarif > after.recipe.json
diff -u before.recipe.json after.recipe.json
```

Matching recipe fingerprints identify matching recorded settings and reference
inputs, not identical source revisions or guaranteed identical model responses.
Compare `execution.sourceIndex.sourceFingerprint` for matching admitted source,
the index version/fingerprint for matching extraction, and source-bundle
fingerprints for matching assembled context. These hashes do not archive the
source or guarantee identical model responses. Compare execution outcomes too,
particularly coverage gaps, partial failures, and fallbacks.

## CI Integration

```yaml
# GitHub Actions example
- name: Security scan
  run: |
    ./codecrucible scan . \
      --output results.sarif \
      --fail-on-severity 7.0

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Utility Commands

```bash
# List available models for a provider (alias: list-endpoints).
# Provider auto-detected from env; override with --provider.
./codecrucible list-models
./codecrucible list-models --provider anthropic
./codecrucible list-models --provider openai-compat --base-url http://localhost:8000

# Write a commented .codecrucible.yaml to the current directory (or given path).
# A worked example, not a schema dump — shows the per-phase override shape.
./codecrucible init
./codecrucible init --force path/to/config.yaml
```

## Development

```bash
make build       # Build binary
make test        # Run tests with race detector
make lint        # golangci-lint (or go vet fallback)
make coverage    # Coverage report
make fmt         # Format all Go files
make vet         # go vet
```

## License

See [LICENSE](LICENSE) for the full license text.
