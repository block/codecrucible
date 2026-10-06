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
`results.usage.json`. Use
`--phase-output-dir DIR` to choose an explicit artifact directory, including
for stdout workflows.

To compare audit prompts or models without analysis variance, replay the audit
on saved findings: `codecrucible scan REPO --audit-from results.analysis.sarif`.
Replay ingests REPO with the same filters, skips feature detection and analysis,
and audits the saved claims under their original finding IDs. Only audit (and
later Jev) requests are sent, and the cost preflight excludes analysis. The
input can be an analysis artifact or the final output of a `--skip-audit` scan;
audited SARIF is rejected. `recipe.auditReplay` in the run metadata records the
input's SHA-256 and counts findings whose file or snippet no longer matches the
checkout. Those verdicts are not comparable. Replay never rewrites the analysis
artifact.

Dry runs show source-input cost plus a separate rough input-and-output estimate.
The planning estimate assumes 25% input overhead, output tokens equal to 1/16
of padded input, and one repository-sized audit pass when audit is enabled.
It displays a 2–3× allowance, not a ceiling. Separate feature detection,
context compression, retries, and repeated audit batches are excluded.
The existing preflight budget check uses source-input cost; runtime accounting
uses reported token usage. All dollar values depend on configured model rates.

### Request usage and cost

The usage artifact contains a versioned report with a unique `run_id`, scan
duration, totals by phase, and one record per HTTP attempt or Claude CLI
invocation. It covers feature detection, supplementary-context compression,
analysis, model repair, retries, context-limit recovery, and audit batches,
including calls whose output cannot be parsed. Once scan execution begins,
the report is also written on failure. With `--phase-output-dir`, its filename
is `usage.json`; stdout scans need that flag to retain a report. Dry runs and
scans that exit before model execution do not write one.

Each request records its phase, purpose, requested and returned model,
configured pricing model and rate snapshot/hash, duration, status, and token
categories. Retries share a request ID with separate attempt numbers. The
artifact contains no prompt/response bodies, endpoint URLs, or credentials.
The final `scan usage` log provides the same overall totals.

`known_cost_usd` is calculated from reported tokens and configured rates. It
is not an invoice total. Check `total.complete` before comparing scan costs:

- `unknown_usage_attempts`: the provider returned no usable token counts.
- `partial_usage_attempts`: some counts were available, for example before
  a stream disconnected. Observed counts are retained across retries.
- `unpriced_attempts`: usage could not be fully priced. Models with both rates
  set to zero are unpriced, not assumed free. Cache tokens are preserved but
  their charges are excluded because cache rates are not configured yet.

Reasoning tokens are a subset of completion tokens and are never charged
twice. Anthropic cache input is separate from ordinary input; OpenAI-compatible
cached input is a subset of prompt tokens. Unpriced cached input is excluded
from the ordinary-input calculation. Claude CLI records describe whole CLI
invocations: internal calls/retries are opaque, and multi-model invocations
are left unpriced. `complete` describes accounting under the configured
rates, not confirmation of the provider's billing.

For benchmrk comparisons, retain this report beside each final SARIF and link
its `run_id` to the imported benchmark run. Use `duration_ms` for scan latency;
benchmrk import time measures a different operation. `--max-cost` remains a
source-input preflight check and does not cap billed runtime spend.

### Optional Jev decisions

Jev is disabled by default. Existing scans use their configured feature detector,
chunker, and auditor; setting `TYPESAFE_API_KEY` alone does not enable it.
Select each experimental stage explicitly. Bare `--jev` returns an actionable
configuration error; it no longer enables a bundle of stages. Each stage accepts
`off`, `shadow`, or `active`, with `off` as its default.

```bash
# Set TYPESAFE_API_KEY alongside the usual LLM credentials.
# Observe evidence selection without changing the auditor's context:
codecrucible scan ./my-repo --jev-audit shadow --output results.sarif
# Add selected evidence to the existing auditor:
codecrucible scan ./my-repo --jev-audit active
# Evaluate or apply CWE classification independently:
codecrucible scan ./my-repo --jev-cwe-mapping shadow
codecrucible scan ./my-repo --jev-cwe-mapping active
```

| Flag | Active behavior | Uncertainty or failure |
| --- | --- | --- |
| `--jev-feature-detection` | Uses Noul for positive feature evidence and Choice for presence/absence. Aggregates bounded source batches; only strong absence in every batch can authorize omission. | Coverage gaps, failed requests, or exhausted quotas retain uncertain categories. Shadow mode runs the existing detector. |
| `--jev-smart-chunking` | Scores the additional context of candidate source scopes, then adds accepted grouping hints to the existing import graph. | Missing scopes skip the request. Failed batches keep earlier hints. File boundaries and token limits remain enforced. |
| `--jev-audit` | Uses independent Noul relevance questions to select optional caller, guard, input-source and template evidence. Every finding still reaches the configured generative auditor. | Mandatory source stays intact. Unknown answers add nothing. Jev never issues a finding verdict. |
| `--jev-review` | Checks individual report assertions and identifies supported, contradicted, unsupported, or unresolved statements. Identical claim/evidence checks are reused within the phase. | Preserves every finding, with the specific disagreement or missing context available in SARIF. |
| `--jev-cwe-mapping` | Classifies final findings against a bounded shortlist from the pinned CWE 4.20 catalog. Records original and proposed labels and updates each affected SARIF rule independently. | Uncertain, outside-candidate, and MITRE review-required mappings preserve the original label. Classification never removes findings or certifies their validity. |
| `--jev-deduplication` | Compares findings sharing a primary source operation or terminal source-to-sink step, excluding matches caused only by secondary router citations. Strong duplicate and shared-root answers consolidate display entries into the highest-severity representative. | Uncertain and partially overlapping pairs remain separate. Every merge preserves the full original result and rule, locations, code flows, and decision provenance. No transitive merges are inferred. |

Shadow mode makes Jev requests and records proposed decisions without changing
findings or grouping. `--skip-feature-detection` and `--skip-audit` still apply;
final review, CWE mapping and deduplication are independent of audit. All stages require explicit settings; `active` is required
to apply their decisions. Feature detection and smart chunking are
skipped when their existing single-chunk conditions do not require them.

`--dependency-grouping` independently enables enhanced local dependency grouping
without Jev or a TypeSafe credential. It is no longer implicit in `--jev`. Use
`--dependency-grouping --jev-smart-chunking active` to combine deterministic
dependencies with semantic hints. This separation lets you measure whether Jev
adds value beyond the dependency graph.

The bundled `default` audit prompt opts into optional Jev context selection with
`decision_audit: true` in `audit.yaml`. Other prompt sets keep their existing context
unless they opt in. Every prompt set keeps its generative audit. Jev preserves
original finding prose and never replaces the generative audit.

```yaml
decisions:
  enabled: false                 # explicit stage modes are always required
  dependency-grouping: false     # deterministic; independent of Jev
  # feature-detection: active    # off | shadow | active
  # smart-chunking: active
  # audit: shadow
  # review: active
  # cwe-mapping: shadow
  # deduplication: shadow
  model: jev-1.13.0
  request-timeout: 30             # seconds per HTTP attempt
  max-calls: 128                  # logical requests, including verification
  retries: 2                     # additional attempts per request
```

Flags include `--jev-model`, `--jev-base-url` (the full evaluation endpoint),
`--jev-request-timeout`, and `--jev-max-calls`. Environment settings use
`DECISIONS_…`, such as `DECISIONS_AUDIT=shadow`; the credential is
`TYPESAFE_API_KEY`. Dry runs show enabled stages and request caps without
requiring that credential or calling Jev. HTTP 408/429/5xx and transport failures
and malformed successful responses share the bounded retry budget; authentication
errors fall back without a retry loop. Valid independent answers survive a partial
response; retries contain only unresolved questions. Numeric tolerances remain
strict, and a compound decision still requires all its answers. The logical call
cap is initially split equally among enabled stages. Completed stages release
unused reservations for later stages, while future reservations and the global
cap remain protected. Validation failures record fixed categories
such as `invalid_response_probability_sum`, without response bodies.

Enabled scans write `results.decisions.json` with evidence references, coverage,
returned model, policy version, typed answers, routing actions, and outcome totals
by stage. Outcomes distinguish retained categories from omissions, accepted edges
from measured chunk-placement changes, audit evidence selection, and assertion review results.
Shadow outcomes are proposed decisions. Per-finding records include an immutable subject ID and categorical coverage gaps. It excludes
source text and credentials. Feature artifacts distinguish `detected_features`
from `retained_features` and record unknown or unavailable observations. Review
also writes `results.review.sarif`, with assertion statuses and explicit reuse
provenance in finding properties. The new stages write `results.cwe-mapping.sarif`
and `results.deduplication.sarif`. Mapping records the candidate IDs and catalog
version; merged findings retain their original records in
`properties.deduplicatedFindings`. CWE mapping does not rerun the earlier
CWE-dependent deduplication. These policies require evaluation on human-reviewed
findings before their accuracy or savings can be claimed.
`--phase-output-dir` puts these alongside the other phase artifacts; stdout scans
need that flag to retain them. The usage report includes every Jev attempt under
`decision.<stage>`, including retries and unknown usage from failed requests.

Audit and review prioritize cited Go functions, their enclosing guards, referenced
local declarations, incoming calls, and handler registrations. Ancestor scopes
preserve guard ordering and conventional middleware context, while unrelated
handlers reached through shared helpers do not expand the selection. The source
index is built once for audit and review. Other
languages and files that cannot be parsed use full-file evidence. Required scopes
that cannot fit, missing source and invalid locations cause conservative fallback;
unrelated Go declarations do not consume the evidence budget. Records marked
`coverage_scope: "claim_context"` describe the selected context, not repository-wide
coverage. Audit evidence selection does not certify reachability or exploitability.

This integration uses an experimental evidence policy. Its decision thresholds
are not calibrated vulnerability probabilities and never replace SARIF audit
confidence. Local dependency resolution is best effort. Missing or oversized
evidence falls back conservatively. These policies still need human-reviewed
efficacy evaluation; the [implementation and evaluation notes](docs/plans/jev-integration.md)
describe the comparisons and remaining work. Jev spend is additional to the existing `--max-cost`
source-input preflight estimate.

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
  --audit-concurrency int              max parallel audit batches, 1-32 (default 1)
  --audit-confidence-threshold float   mark existing findings below this confidence unverified (default 0.3)
  --audit-deployment-trace             trace each finding back to entry points, guards, and deploy config (default true)
  --audit-from string                  audit a saved analysis SARIF instead of running analysis
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
  --max-cost float                     source-input cost preflight limit, not a billed ceiling (default 25)
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
audit-concurrency: 1
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
`tokenizer_encoding` controls offline token estimates for chunking and cost
preflight: `o200k_base` and `cl100k_base` use embedded BPE vocabularies
(sampled on large files), and any other value uses a content-aware heuristic.
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
| 0 | Analysis completed, possibly with audit warnings (no findings above threshold) |
| 1 | Error (analysis/pipeline failure, cancellation, or SARIF invocation failure) |
| 2 | Findings exceed `--fail-on-severity` threshold |

Analysis failures still write partial SARIF when possible and return exit code 1.
Check `runs[0].invocations[0].executionSuccessful` and
`toolExecutionNotifications` for failure details.

Audit batches run sequentially by default. Set `--audit-concurrency 2` (or
`audit-concurrency: 2` / `AUDIT_CONCURRENCY=2`) to run two batches concurrently.
This is independent of analysis `--concurrency`, is bounded to 1-32 workers,
and preserves output order. Choose concurrency to fit provider rate limits;
each worker retains the same request timeout and retry bounds.

Audit is best effort. If any audit batch remains unavailable, completed audit
verdicts are preserved and the remaining findings are retained with
`properties.auditStatus: "not_audited"` and
`properties.auditReasons: ["missing_verdict"]`. The run
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
Every input carries an immutable `finding_id`, echoed by its verdict and preserved
as SARIF `properties.findingId`. Proposed title or source-location changes do not
change identity; location refinements must refer to admitted source. Valid verdicts
are preserved and only unresolved IDs are retried. Duplicate IDs are ambiguous;
unknown IDs cannot affect findings. Both generations count toward reported token
usage and cost. Transport retry
exhaustion does not start a second audit-level HTTP retry cycle.

## SARIF descriptions and scan comparisons

GitHub's issue panel shows a concise description of attacker control, impact,
prerequisites, and remediation in `rule.help`. Inline `result.message.text`
annotations contain the issue title. Audit and review metadata stay in properties.
Findings that share a rule have separate, location-labelled sections in its help. Rejected findings
are excluded before these sections are built. Existing rule IDs stay unchanged.

Technical evidence is available under the help's **Technical details** disclosure
and in `result.properties.technicalDetails`. Audit justification is preserved
separately in `result.properties.auditJustification`. Markdown help escapes source
text so payloads remain literal. Viewers without disclosure support can read the SARIF
property. Older/custom prompts without a reviewer summary use the first
narrative paragraph, limited to 1000 characters, before audit justification.

Finding metadata uses the standard SARIF `result.properties` extension point.
Consumers can filter or badge these typed values without parsing descriptions.
No HTML-comment convention is required. Existing property names and finding IDs
are retained.

| Result property | Meaning |
|-----------------|---------|
| `findingId` | Immutable scanner finding identity, separate from the category's `ruleId` |
| `auditStatus` | Effective verdict: `confirmed`, `refined`, `escalated`, `unverified`, `new`, or `not_audited` |
| `auditConfidence` | Auditor's numeric confidence from 0 to 1, including explicit zero. Omitted when unavailable. This is a model assessment, not a calibrated probability. |
| `auditGates[]` | Model-reported gate `id`, `status` (`passed`, `failed`, `unknown`, `not_applicable`), and `reason`. Standard IDs: `production_reachability`, `reachability`, `absence_of_mitigation`, `material_impact`. Omitted when the auditor supplies no structured gates. |
| `auditReasons[]` | Scanner reasons: `missing_verdict`, `ungrounded_rejection`, `below_confidence_threshold`, `incomplete_claim_coverage`, `unresolved_claims` |
| `auditJustification` | Full verdict reasoning, including legacy free-text gates |
| `auditOriginal`, `auditRevision` | Original claim and complete proposed audit revision, including claim coverage, unresolved claims and blocking evidence. The proposed verdict can differ from the effective `auditStatus`. |
| `decisionAudit`, `decisionReview` | Bounded evidence assessments and individual assertion checks, with status, model, policy and evidence IDs |
| `decisionCWE`, `cweChanges`, `deduplicatedFindings` | Classification and consolidation provenance |

Gate results describe the model's assessment of a vulnerability. Operational
failures use `run.invocations[].toolExecutionNotifications` and
`run.properties.codecrucible.execution.phases` and `.chunks`. A missing verdict
marks a finding as unaudited without guessing which provider error caused it.
Rejected findings remain excluded from the final result set.

Request token usage, retries, categorical failure reasons and known costs are
available in `run.properties.codecrucible.execution.usage`, using the same schema
as the usage sidecar. Each artifact captures usage to that point in the scan.
Counts remain scoped to requests and phases: analysis chunks and audit batches
can cover multiple findings, so there is no invented per-finding allocation.
Check `usage_status` and the unknown/partial attempt counts before treating zeros
as measured values. Older artifacts and scans without a usage ledger omit it.
The usage report's status describes execution at serialization time, before any
later output-write error or severity-based exit decision.

For example, select findings needing audit review:

```bash
jq '.runs[].results[] | select(.properties.auditStatus == "not_audited" or .properties.auditStatus == "unverified") | {id: .properties.findingId, audit: .properties.auditStatus, confidence: .properties.auditConfidence, gates: .properties.auditGates}' results.sarif
```

Downstream tools must read these properties to build filters or badges. GitHub's
alert UI does not automatically display custom properties.

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
| `recipe.controls` | Scope filters, test/document inclusion, file-size limit, compression, concurrency, cost limit, severity gate, phase toggles, audit confidence/batch size/concurrency, and context budget |
| `recipeFingerprint` | SHA-256 of the canonical JSON recipe (sorted object keys, preserved array order); excludes output paths, credentials, timestamps, and execution outcomes |
| `execution` | Artifact stage, phase statuses and actual phase configurations, fallbacks, detected features, token correction, chunk/recovery counts, source loading/compression outcomes, and packed-context fingerprints/truncation |

Phase configuration reflects inheritance and overrides after configuration
resolution. Model parameters are recorded separately from model-registry
defaults; they can override request-body fields. `execution.phases.*.actual`
identifies the configuration used when a phase ran, including fallback to the
analysis client. `requestPolicy` explains exceptions such as Claude CLI-managed
sampling and context compression's per-source output limits. This is not a
trace of provider-side defaults or per-request retry adaptations.

Analysis, audit, and final files have independent execution snapshots and the
same recipe fingerprint. `pending` means a phase had not run at that snapshot;
`skipped`, `completed`, and `failed` describe its outcome. Empty scans include
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

# Compare recipes, excluding differences caused only by run outcomes.
jq -S '.runs[0].properties.codecrucible.recipe' before.sarif > before.recipe.json
jq -S '.runs[0].properties.codecrucible.recipe' after.sarif > after.recipe.json
diff -u before.recipe.json after.recipe.json
```

Matching recipe fingerprints identify matching recorded settings and reference
inputs, not identical source revisions or guaranteed identical model responses.
Compare execution outcomes too, particularly partial failures and fallbacks.

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

### Fixed-case decision evaluation

`go run ./cmd/decision-eval -cases internal/decisioneval/testdata/cases.json -out /tmp/decision-cases.json`
prepares frozen requests and deterministic CWE baselines without network calls.
Add `-live` to evaluate the same cases with Jev. Outputs include source packets,
request hashes, typed responses, candidate coverage, abstentions, errors, usage,
and elapsed time. Keep private cases and outputs outside Git. The bundled cases
are synthetic development fixtures, not evidence of real-world accuracy. See
[decision evaluation](docs/decision-evaluation.md) for the promotion criteria.

Audit uncertainty preserves the original finding. Rejection requires a structured,
exact source citation and a complete claim assessment; a low confidence score,
missing context, or conditional execution alone cannot remove a finding. Partial
refinements retain the original claim and location. Original findings and proposed
revisions remain available in `auditOriginal` and `auditRevision` properties.
