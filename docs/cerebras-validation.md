# Cerebras deployment validation

Status: implementation verified with mock HTTP responses; live validation pending.
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
