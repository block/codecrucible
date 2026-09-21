# Cerebras deployment validation

Status: mock tests and controlled live calls completed; see findings below.
The development environment did not have CEREBRAS_API_KEY configured, and the
repository's bd issue-tracking command was unavailable when this follow-up was recorded.

Before relying on an account's Cerebras deployment:

1. Set CEREBRAS_API_KEY through the usual credential mechanism and run
   `codecrucible list-models --provider cerebras`.
2. Select an available model ID. Confirm its context window, maximum output,
   structured-output support, and account-specific input/output pricing.
   Configure these under `models:`; discovery alone does not register metadata.
3. Run a dry run and a small synthetic fixture scan with explicit provider and
   model flags. Confirm the SARIF invocation succeeds, usage is returned, and
   JSON Schema requests are accepted for analysis, feature detection and audit.
4. Exercise a mixed-provider scan and compare findings against a known fixture.
5. Benchmark larger prompts at the default concurrency of three before tuning
   concurrency. Check context overflow, rate limits, latency and actual cost.

No real repository needs to be submitted to complete the initial smoke test.

## Observed truncation on block-kimi-k2.6

Live user runs reported `finish_reason=length` and exactly 8192 completion
tokens with requested output limits of 32768 and 65536. A local wire capture
confirmed the old binary sent `max_tokens: 65536`; no local clamp was observed.
Cerebras requests now use canonical `max_completion_tokens` instead of the
legacy alias, with contract tests covering 65536 and model-parameter overrides.
This is a compatibility change, not a confirmed resolution: both parameter
names are documented as aliases. Verify with a small scan before repeating
whole-repository scans. If the same cutoff persists, investigate deployment
caps and reasoning-token usage accounting. The model metadata endpoint returned
HTTP 403 with the configured credentials, so account limits remain unverified.

## Controlled live probes (2026-09-21)

Direct authenticated calls using the captured one-file prompt established:

| Request | Result |
| --- | --- |
| max_tokens=512 | length at 512, all reasoning, no final content |
| max_completion_tokens=512 | length at 512, all reasoning, no final content |
| max_completion_tokens=16384, one-file prompt | stop at 2860; 2729 reasoning tokens |
| max_completion_tokens=65536, instrumented one-file scan | stop at 5107; 4955 reasoning tokens |
| max_completion_tokens=12288, synthetic long-output prompt | length at 8192, including 1695 reasoning tokens |
| max_tokens=12288, synthetic long-output prompt | length at 8192, all reasoning |
| reasoning_effort=none, max_completion_tokens=8192, one-file prompt | stop at 1771, zero reasoning tokens |

Both limit aliases work below 8192. The larger synthetic requests demonstrate
an observed 8192-token effective ceiling independent of the scanner; deployment
configuration is still not exposed. GET /v1/models succeeds with the client's
User-Agent and lists the model, but provides no limits. The earlier 403 was an
HTTP-client difference, not proof that the API key lacks model-discovery access.

The verified workaround is --model-params '{"reasoning_effort":"none"}'. This
trades away reasoning behavior and must not be presented as equivalent security
coverage. Prefer a deployment with sufficient reasoning/output capacity when
reasoning-enabled analysis is required. Use --verbose to see allowlisted wire
limits after parameter merging; reasoning_tokens is now logged separately as a
subset of completion_tokens, without exposing generated reasoning text.

### Additional follow-up

The first reasoning-disabled full run completed analysis but three of four
25-finding audit batches failed (two malformed/truncated responses and one
HTTP 403). Its process nevertheless exited zero. Track propagation of partial
audit failures to the CLI exit status separately; do not use exit status alone
as evidence that every finding was audited. This was recorded here because bd
is unavailable. Smaller batches and strict schema output are being validated
as the operational workaround, not as a fix for that exit-status behavior.

### Full validation outcome

The subsequent full Sandpit run with reasoning_effort=none, native JSON Schema,
and audit-batch-size=5 completed all 9 analysis chunks and all 8 audit batches
without logged API errors or truncation. It produced 40 initial candidates and
1 final model-reported finding. Usage: 375951 input tokens and 33052 completion
tokens; estimated cost $1.0163 using provisional rates. Results are local at
output/sandpit-verified-settings.sarif. This validates execution, not finding
accuracy or equivalence to reasoning-enabled analysis.
