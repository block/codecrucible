---
name: codecrucible
description: Use CodeCrucible to run, configure, troubleshoot, or interpret LLM-backed security scans and SARIF output. Use when a user asks to scan a repository with codecrucible, choose a provider/model or prompt set, estimate scan cost, inspect phase artifacts, automate a scan, or explain CodeCrucible findings. Do not use for general security review requests that do not involve CodeCrucible.
---

# CodeCrucible

Use CodeCrucible as a cost-aware security scanning CLI. Treat its output as evidence to verify against source, not as a final vulnerability verdict.

## Workflow

1. Identify the target repository, requested scope, output destination, and whether the user wants an exploratory scan or a CI gate.
2. Read the target repository's agent instructions before scanning it.
3. Inspect the CodeCrucible repository docs before choosing flags:
   - Read `README.md` for CLI flags, provider setup, config precedence, and built-in supported models.
   - Read `PROMPT_SETS.md` when choosing a prompt set.
   - Run `./codecrucible list-models --provider <provider>` when credentials are configured and provider-reported endpoints matter; do not invent model IDs or provider-specific parameters.
4. Use `./codecrucible` from the repository root when the binary exists. Run `make build` first when working from a fresh checkout.
5. Start with a dry run unless the user explicitly asks to execute immediately:

```bash
./codecrucible scan /path/to/repo --dry-run
```

6. Review the dry-run scope, token estimate, and cost estimate. Narrow with `--paths`, `--include`, or `--exclude` when the scan is broader than the user's request.
7. Run the real scan with an explicit output path and preserve phase artifacts when analysis or troubleshooting matters:

```bash
./codecrucible scan /path/to/repo \
  --output /tmp/codecrucible-results.sarif \
  --phase-output-dir /tmp/codecrucible-phases
```

8. Verify reported findings in source before presenting them. Distinguish the final audited SARIF from pre-audit analysis artifacts.

## Selection Guidance

- Use `prompts/default` for general first-pass coverage.
- Use the closest `prompts/exploit-proof-*` set for language-specific, precision-oriented reviews.
- Use `prompts/exploit-proof` for polyglot targets or when no language-specific set fits.
- Use `carlini`, `carlini-curated`, or `nano-analyzer` only when the user asks for that style or when the constraints described in `PROMPT_SETS.md` fit the task.
- Prefer cheaper models for feature detection and stronger reasoning models for analysis when cost matters; use per-phase flags instead of forcing one model across every phase.
- Keep `--max-cost` set for exploratory work. Use `--fail-on-severity` only when the user wants a gating exit code.

## Provider And Config Rules

- Keep API keys in environment variables; do not put them in commands, config files committed to git, or responses.
- Respect config precedence: CLI flags override environment variables, which override config files, which override defaults.
- For custom or newly released models, inspect `README.md`, `internal/config/models.go`, and provider documentation before setting context limits, output limits, structured-output flags, or model params.
- If a model or provider is unknown to the built-in registry, use explicit `--context-limit` and `--max-output-tokens` rather than assuming defaults are correct.

## Reading Results

- The main `--output` file is the final SARIF result after audit when audit is enabled.
- `*.analysis.sarif` is the pre-audit finding set.
- `*.audit.sarif` shows the audited result.
- `*.feature-detection.json` helps explain why sections were included or pruned.
- When a finding disappears between analysis and audit, inspect the audit artifact before concluding the scanner missed it.
- When reporting findings, include file path, line, CWE/rule ID when present, exploitability reasoning, and whether the finding survived audit.

## Common Commands

```bash
# Query provider-reported models/endpoints when credentials are configured.
./codecrucible list-models --provider anthropic

# General scan with a precision-oriented Go prompt set.
./codecrucible scan /path/to/repo \
  --prompts-dir prompts/exploit-proof-web-go \
  --output /tmp/codecrucible-results.sarif

# Cost-aware mixed-model scan.
./codecrucible scan /path/to/repo \
  --fd-provider google --fd-model gemini-3.5-flash \
  --provider anthropic --model claude-opus-4-8 \
  --audit-provider anthropic --audit-model claude-sonnet-5 \
  --max-cost 25 \
  --output /tmp/codecrucible-results.sarif
```
