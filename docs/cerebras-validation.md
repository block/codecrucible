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
