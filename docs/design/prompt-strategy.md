# Prompt strategy experiment

Status: opt-in experiment. The default prompt set and audit policies are unchanged.

CodeCrucible should use the model for security reasoning and the application for
source admission, bounded context, identity, evidence provenance, accounting, and
output integrity. It remains a source-only static analyzer. A successful build,
dependency installation, external import resolution, and runtime access are not
prerequisites.

## Review of the existing approach

| Area | Current constraint | Consequence | Experiment |
|---|---|---|---|
| Discovery | `default/security_analysis_base.yaml` says the whole codebase is visible, while `AssembleMessages` can provide one chunk. | The model may infer nonexistent cross-file knowledge or discard a real defect whose caller is elsewhere. | Describe partial source accurately. Require a concrete unsafe operation or violated invariant and qualify missing context. |
| Coverage | Feature detection supplies a small sample and the loader removes sections by feature name. | An uncertain classification can remove useful review guidance. Missing authorization is particularly awkward to detect as an existing feature. | Keep a compact, language-neutral coverage reminder unconditional. Retain feature detection as metadata, not a completeness claim. |
| Proof threshold | `exploit-proof` requires a specific runnable request and a very short reproduction; `nano-analyzer` concentrates on a small set of low-level failure modes. | Useful library, concurrency, state-machine, partial-repository, and cross-file defects can be excluded before audit. | Ask for an adversarial scenario appropriate to the mechanism. Allow a source-backed claim with an explicit deciding uncertainty. |
| Validation | The legacy schema permits direct verdicts. V2 computes a verdict from three questions. V3 requires five established assertions, source-expression correspondence, and complete material coverage. | Stronger structural assurance can also prevent useful narrow verdicts. Rewording a v3 prompt cannot remove its code-enforced conditions. | Test direct model verdicts with independent source review and explicit rules for narrowing impact. Keep v2/v3 available as comparison arms. |
| Reporting | The schema already separates summary, remediation, detailed evidence, and code path. | Long deliberation or repeated CWE guidance consumes output without improving the reviewer-facing report. | Return the conclusion, decisive source facts, uncertainty, and fix. Let SARIF rendering handle presentation. |

The relevant runtime is `internal/llm/prompt.go`, `internal/cli/scan_analyze.go`,
`internal/cli/scan_audit.go`, `internal/cli/scan_audit_v2.go`,
`internal/cli/scan_audit_v3.go`, and `internal/auditcore/policy.go`. In particular,
legacy rejection only checks that `blocking_code` is nonempty. It does not provide
v3's structured proof checks. The experiment therefore tests a quality hypothesis,
not a stronger assurance guarantee.

Current [OpenAI guidance on prompt and scaffold design](https://developers.openai.com/blog/rethinking-skills-and-prompts-for-gpt-6-astra)
supports removing instructions that no longer help the selected model. Its
[reasoning guidance](https://developers.openai.com/api/docs/guides/reasoning-best-practices)
also favors a clear task and outcome over a prescribed reasoning transcript.
Those recommendations are model-dependent. They motivate a controlled experiment,
not automatic promotion across every provider.

## The new set

`prompts/reasoning` is a complete, provider-neutral prompt set. It uses the
existing analysis schema and legacy model-chosen audit verdict schema. It changes
no verdict policy, default model, source admission rule, or suppression flag.
It asks the model to find atomic causes, test relevant counterevidence, distinguish
a source weakness from a speculative consequence, and report usable evidence.
It avoids CWE-specific audit cards so an incorrect initial CWE cannot steer the
entire validation pass.

The existing runtime still assigns finding IDs, records original observations and
audit decisions, retries incomplete verdicts, saves partial results, and reports
an incomplete audit without failing CI. `unverified` results remain active. The
new set does not gain v3's explicit child decisions or semantic duplicate edges.
It must not reject findings merely to remove duplicates. Its audit returns an
empty `new_findings` array: discovery owns new claims, and an audit batch lacks
the complete claim set needed to avoid rediscovering another batch's findings.
The opt-in `allow_new_findings: false` setting constrains the legacy response
schema and excludes additions even if the model ignores it. Excluded candidates
remain observations in the lineage ledger with an explicit policy reason and a
filtered disposition. Other sets continue to allow additions by default.

The `reasoning` discovery prompt asks the model to review the available
operations and security-sensitive helpers before settling on a final list, and
to report each independently fixable cause separately, even when causes can be
chained. A serious injection does not subsume a broken permission check,
credential lifecycle, or state transition. A safer modern path does not
establish that a retained compatibility or fallback path is safe. Five
always-included coverage sections ask the model to review: identity and
authorization boundaries for each resource action; untrusted data and
interpreters; credentials, cryptography, and retained paths; state, lifetime,
and business rules; and secondary and indirect execution surfaces. They declare
no features, so feature detection cannot remove them. They are investigation
aids, not required findings or a limit on the classes of defect the model may
report, and a category without evidence yields no finding.

The reporting contract splits causes whose fixes differ and anchors each finding
where its own fix belongs. A systemic finding needs a narrow, concrete primary
location, with the other demonstrated paths in `technical_details` or
`code_path`. It sets no finding quota and does not weaken the evidence
requirements. It adds no language-specific detector code, agent loop, tool
access, or runnable-exploit requirement.

This coverage may increase findings, output tokens, audit work, and false
positives. A larger result count is useful only when it represents additional
supported causes. The set stays opt-in until held-out evaluation supports a
change in defaults.

Use the set explicitly:

```bash
codecrucible scan /path/to/source \
  --prompts-dir /path/to/codecrucible/prompts/reasoning \
  --output /tmp/reasoning.sarif \
  --phase-output-dir /tmp/reasoning-phases
```

## Evaluation and promotion

Freeze source, filters, model deployment, model parameters, context/output limits,
prices, and concurrency. Compare `default`, `reasoning`, and `core` with at least
two iterations. Run independent jobs concurrently within the provider's limits.
Record the actual chunk plan as well. Prompt length changes the source budget,
so identical context limits can produce different chunks and different numbers
of discovery calls. A prompt-only discovery comparison needs the same admitted
source bundles, or must report that planning difference as a confound.

Use two comparisons. Full scans measure discovery and final report quality.
`--audit-from` replays the same pre-audit SARIF under each set and isolates audit
behavior from stochastic discovery. Label independently actionable root causes,
supported impact, benign controls, and duplicate pairs. Separate tuning examples
from held-out cases. Use `validate-lineage` for every result and `evaluate-audit`
for the frozen labeled replay.

Measure unique valid causes found, known-positive suppression, false confirmation,
unsupported-impact confirmation, unresolved and not-audited rates, duplicate
precision, source-citation accuracy, report usefulness, token cost, elapsed time,
and variation across iterations. Reconcile raw observations, analysis results,
audit additions, suppressed results, and final results. A lower finding count or
an increased confirmation rate alone is not evidence of improvement. Keep private
evaluation inputs, labels, and outputs outside the repository.

Promoting `reasoning`, or any part of it, into the defaults requires
independently labeled held-out cases evaluated across multiple models. Report
recall of important causes and precision of active reports, each with its
uncertainty, alongside token cost.

## Scaffolding that still needs work

Prompt changes cannot retrieve source that was never sent. A later experiment
should let the model request bounded excerpts from the immutable local source
index, using validated paths/ranges and a fixed request/token budget. The model
should receive explicit completion and omission records. The harness should keep
admission, source fingerprints, and request provenance authoritative. No shell,
build, external dependency fetch, or unrestricted repository access is required.

The audit contracts also need to separate source-weakness confidence from impact
and exposure, support concise independently decided subclaims, and size batches
for expected output. Preserve structured, checkable evidence without requiring
the model to repeat entire prior reports. Explicit report-only duplicate handling
should eventually be available independently of the chosen audit policy. These
are runtime changes and need their own tests and held-out evaluation.
An exportable, replayable analysis chunk plan would also make discovery prompt
comparisons more reproducible without requiring another audit-contract change.
