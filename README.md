# codecrucible

A purpose-built Go CLI tool that analyzes Git repositories for security vulnerabilities using LLM-based analysis and produces [SARIF v2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) output for GitHub Code Scanning integration.

## Overview

codecrucible replaces the original Python/repomix pipeline with a single static Go binary. Key improvements:

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
./codecrucible scan /path/to/repo --provider anthropic --model claude-sonnet-4-6

# Anthropic API scan with adaptive thinking always enabled
./codecrucible scan /path/to/repo \
  --provider anthropic \
  --model claude-sonnet-4-6 \
  --model-params '{"thinking":{"type":"enabled","budget_tokens":4096}}'

# Or use Claude Code CLI auth (SSO/login) with no API key
claude auth status
./codecrucible scan /path/to/repo --provider anthropic --model claude-sonnet-4-6

# In Claude CLI auth mode, Anthropic beta headers are forwarded via `claude --betas`
# (for example: --custom-headers "anthropic-beta: context-1m-2025-08-07").

# Direct OpenAI API scan
export OPENAI_API_KEY=your-openai-key
./codecrucible scan /path/to/repo --provider openai --model gpt-5.2

# Direct Google Gemini scan (OpenAI-compat endpoint)
export GOOGLE_API_KEY=your-google-key
./codecrucible scan /path/to/repo --provider google --model gemini-3-pro

# Mix providers per phase: opus for analysis, gemini for audit
export ANTHROPIC_API_KEY=your-anthropic-key
export GOOGLE_API_KEY=your-google-key
./codecrucible scan /path/to/repo \
  --model claude-opus-4-6 \
  --audit-provider google --audit-model gemini-3-pro \
  --fd-model gemini-3-flash --fd-provider google

# Preview scope without making API calls
./codecrucible scan /path/to/repo --dry-run

# Scan specific paths in a monorepo
./codecrucible scan /path/to/repo --paths src/ --paths lib/
```

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

Providers: `anthropic`, `openai`, `google`, `ollama`, `openai-compat`, `databricks`. Auto-detected from env vars when unset.

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
codecrucible scan --model claude-opus-4-6 --feature-detection-model claude-sonnet-4-6 .
```

Per-phase flags follow the pattern `--{phase}-{flag}` (e.g. `--audit-model`, `--audit-provider`, `--audit-api-key`, `--audit-base-url`). Short aliases: `--fd-*` for feature-detection, `--cc-*` for context-compress.

### Everything else

```
  --audit-batch-size int               split audit into N-finding batches (default 25)
  --audit-confidence-threshold float   reject findings below this confidence (default 0.3)
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
  --paths strings                      paths within the repo to analyze
  --prompts-dir string                 prompt set directory (default: prompts/default)
  --request-timeout int                HTTP timeout in seconds (0 = default 600s)
  --skip-audit                         skip CWE-specific audit phase
  --skip-feature-detection             skip feature detection pre-pass

Global Flags:
  --config string   config file (default: .codecrucible.yaml)
  --verbose         enable debug logging
```

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

See [SKILLS.md](SKILLS.md) for a fuller walkthrough of when to reach for each set.

Each prompt set directory must contain: `security_analysis_base.yaml`, `analysis_sections.yaml`, `feature_detection.yaml`, `audit.yaml`, `cwe_deep_analysis.yaml`, and optionally `context_compress.yaml`.

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
| `GOOGLE_API_KEY` / `GEMINI_API_KEY` | Google AI Studio API key |
| `CODECRUCIBLE_PROVIDER` | Provider override (`databricks`, `anthropic`, `openai`, `google`) |
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
model: claude-sonnet-4-6
provider: databricks
include-tests: false
include-docs: false
max-cost: 25
fail-on-severity: 7.0
concurrency: 3
model-params:
  thinking:
    type: enabled
    budget_tokens: 4096
skip-audit: false
audit-confidence-threshold: 0.3
exclude:
  - "*.generated.go"
  - "**/generated/**"
```

### Per-Phase Configuration

The pipeline has three LLM phases: **feature detection** (gating, skipped for
small repos), **analysis** (the main loop), and **audit** (validation). Each
can run on a different provider, model, API key, and params.

The flat keys above (`model`, `provider`, `model-params`) configure the
analysis phase and are **inherited** by the other two. A `phases:` block
overrides selectively:

```yaml
# Analysis: claude-opus with extended thinking. Slow, thorough, expensive.
model: claude-opus-4-6
provider: anthropic
model-params:
  thinking:
    type: enabled
    budget_tokens: 8192

phases:
  # Feature detection is a cheap gating pass on a file manifest. A small
  # fast model is plenty. Skipped entirely when the repo fits in one chunk.
  feature-detection:
    provider: google
    model: gemini-3-flash
    api-key: ${GOOGLE_API_KEY}
    # NOT setting model-params inherits thinking-mode from analysis, which
    # gemini would reject. Setting any params replaces the inherited set
    # wholesale (see inheritance rules below) — so put something gemini
    # actually wants:
    model-params:
      max_tokens: 2048

  # Audit is a validation pass — short, structured output. Dropping
  # thinking-mode and capping max_tokens keeps it fast without hurting
  # quality.
  audit:
    model: claude-sonnet-4-6
    model-params:
      max_tokens: 8192
    # provider, api-key: inherited from analysis (anthropic + its key)
```

**Inheritance rules**

- Any per-phase field left at its zero value inherits from the analysis phase.
- `model-params` inherits on empty; a phase that sets its own params gets
  **exactly** those params (replace, not merge) — so you can drop inherited
  keys.
- `--context-limit` / `--max-output-tokens` inherit per-phase too. Previously
  they only applied to the main model; now `--audit-model gemini-3-pro` with
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
provider-specific knobs (thinking budgets, reasoning effort, custom safety
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
| claude-sonnet-4-6 | anthropic | 200K | 16K | tool_use |
| claude-opus-4-6 | anthropic | 200K | 32K | tool_use |
| claude-opus-4-7 | anthropic | 1M | 128K | tool_use |
| gpt-5.2 | openai | 400K | 16K | response_format JSON Schema |
| gpt-5.4 | openai | 1M | 128K | response_format JSON Schema |
| gpt-5.5 | openai | 1M | 128K | response_format JSON Schema |
| gpt-5.4-mini | openai | 400K | 128K | response_format JSON Schema |
| gpt-5.4-nano | openai | 400K | 128K | response_format JSON Schema |
| gemini-3-pro | google | 1M | 64K | response_format JSON Schema |
| gemini-3-flash | google | 1M | 64K | response_format JSON Schema |

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
  - name: claude-sonnet-4-8
    provider: anthropic
    input_price_per_million: 3.0
    output_price_per_million: 15.0
    context_limit: 1000000
    max_output_tokens: 64000
    tokenizer_encoding: claude
    supports_structured_output: true

  # Override: change a built-in's pricing without forking.
  - name: claude-sonnet-4-6
    provider: anthropic
    input_price_per_million: 1.5   # negotiated rate
    output_price_per_million: 7.5
    context_limit: 200000
    max_output_tokens: 16384
    tokenizer_encoding: claude
    supports_structured_output: true

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
```

Each phase builds its own `llm.Client` from its `PhaseConfig` — there is no
shared client object. A fresh client per phase means the learned endpoint
constraints (`noForcedToolChoice`, `dropTemperature`) reset at phase
boundaries; at most one extra 400→retry per phase when the model rejects
a feature.

### Project Structure

```
cmd/codecrucible/       CLI entry point
internal/
  cli/                  Cobra commands (scan, list-models, init), pipeline orchestration
  config/               Viper config, model registry, per-phase resolution (phase.go)
  ingest/               File walker, filter, XML flattener, import graph
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
| 0 | Success (no findings above threshold) |
| 1 | Error (pipeline failure) |
| 2 | Findings exceed `--fail-on-severity` threshold |

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
