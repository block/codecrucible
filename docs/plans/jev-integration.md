# Optional Jev integration

The runtime integration covers feature detection, smart chunking, audit, and
finding review. All stages default to off. `--jev` enables unspecified stages;
individual `--jev-<stage> off|shadow|active` settings override it. A credential
alone never enables requests. Generative analysis remains the discovery pass.

## Implementation

| Area | Behavior |
| --- | --- |
| Client | Typed Choice, Noul, and Score contracts with question-ID, answer-shape, range, and probability validation. Separate from the generative chat interface. |
| Feature detection | Derives feature IDs from the loaded conditional sections, including custom features. Omits a feature only with complete supplied source and a strong absence answer. Partial coverage keeps sections. Existing single-chunk and skip guards apply. |
| Smart chunking | Resolves admitted local imports and Go package/Python module dependencies; a bounded lexical shortlist feeds Jev file-pair decisions. Supported relationships add grouping hints. Existing file preservation and token packing remain authoritative. |
| Audit | Resolves source locations and follows admitted local dependencies. Strong coverage and support can retain the original finding without generative audit. Rejection requires an exact blocking evidence ID plus a fresh source-grounded verification request. Everything else goes to the existing auditor. |
| Review | Independently checks retained findings. Support is recorded; contradictions, uncertainty, missing context, and failures retain the finding with a manual-validation requirement. |
| Accounting | The common usage ledger records actual HTTP attempts, returned models, retries, reported token categories, and unknown or unpriced usage. |
| Provenance | Decision artifacts record policy/model, typed answers, coverage, source hashes/ranges, state hash, and final action. They omit source text, prompt bodies, and credentials. SARIF records supported audits and review requirements separately from legacy audit confidence. |

The bundled `default` audit template declares `decision_audit: true`. This opts
into the fixed Jev evidence policy, including the possibility that a resolved
finding never reaches the template. Other prompt sets retain generative audit
unless they explicitly opt in. This preserves custom discovery and specialized
audit procedures. Jev does not refine prose, severity, or CWE labels and does not
create findings. Unresolved findings are repacked into real generative batches;
Jev-retained findings are restored afterward, outside legacy confidence filtering.

Shadow mode records decisions and proposed actions while preserving baseline
output. Stage controls are independent. Final review may run with `--skip-audit`;
`--skip-feature-detection` prevents both feature-detection implementations.
Changing the generative model is outside this integration.

## Bounds and fallback

The client uses the [TypeSafe API](https://docs.typesafe.ai/api), pins
`jev-1.13.0`, and records the returned model. The initial configured input rate is
$0.042 per million tokens with free output, from the
[model documentation](https://docs.typesafe.ai/models) reviewed September 29,
2026. Rates are configurable and are accounting estimates, not invoices.

Default bounds are 128 logical requests, two retries, and a 30-second timeout
per attempt. Verification requests count toward the same cap. HTTP 408, 429,
5xx, and transport/read failures can retry with bounded backoff; other HTTP
errors fall back immediately. Parent cancellation interrupts calls and backoff.
Redirects are rejected so credentials cannot follow them. Provider response
bodies are not included in error messages.

Request validation conservatively budgets JSON UTF-8 bytes plus overhead under
64K for the full request and 32K for state plus one question. These are upper
bounds rather than a Jev tokenizer estimate. Oversized requests never reach the
provider. Jev token counts do not calibrate the generative model's chunk budget.
`--max-cost` remains the existing source-input preflight check. Decision calls
have their own bounds and their spend appears in the usage ledger.

Audit/review source evidence contains full files in exact 24-line spans, bounded
to 18K serialized bytes and 32 files during dependency traversal. Source scope
is the existing admitted scan input. Missing locations, oversized claims, omitted
source, and request limits prevent authoritative routing. Local dependency
coverage does not prove whole-program coverage: the questions require escalation
when callers, runtime configuration, framework behavior, or mitigation ordering
cannot be established. Supplementary audit context and custom requirements are
supplied within the same request bounds.

The versioned routing policy requires selected-choice probability at least 0.98
and answer confidence at least 0.95. These are experimental routing thresholds,
not measured security accuracy. They are never copied into the generative
`auditConfidence` field, and correlated decisions are not multiplied. TypeSafe's
[confidence documentation](https://docs.typesafe.ai/confidence) describes the
meaning of its answer confidence. A second Jev request is an additional check,
not independent human ground truth.

## Verification and remaining evaluation

Deterministic mock-provider tests cover response contracts, retries, cancellation,
redirects, request caps, disabled-mode compatibility, stage overrides, skip flags,
dry runs, conservative feature selection, grouping/file budgets, evidence-based
routing, independent rejection verification, and whole-scan usage reporting.
These tests verify application behavior. They do not measure live model quality
or prove cost savings.

Held-out efficacy and pricing work remains tracked separately. Build a versioned,
reviewed corpus with true positives, decoys, and unresolved findings. Include
multiple languages, custom prompts, missing cross-file context, mitigation
lookalikes, misleading comments, and adversarial source instructions. Separate
repositories used for tuning from those used for evaluation. Existing LLM
verdicts are comparison data rather than labels.

Compare baseline, shadow, each active stage, and all stages together while
holding the generative model, prompts, corpus revision, and scan settings fixed.
Use independent scan repetitions. Join final SARIF and usage/decision artifacts
to benchmark run IDs, preserving configuration, annotation, scorer, and artifact
hashes. Measure recall, precision, false suppression, retained uncertainty,
feature omissions, evidence coverage, fallback rates, actual generative requests,
total cost, and scan latency. Inspect individual lost vulnerabilities. Shadow
mode measures decision behavior and added overhead, not realized savings.

Net saving is baseline spend minus remaining generative work, Jev, retries, and
fallbacks. Unknown usage and unpriced cache charges must remain visible. No live
quality, savings, or suppression-risk claims accompany this implementation.
Wider rollout should follow held-out results and a documented acceptable risk
bound. Disable any stage independently to roll back its behavior.

## Tracked work

Beads tracks the integration under `codecrucible-ngo`; its database and exports
remain gitignored. Usage accounting and the typed client are foundation tasks.
Feature detection, smart chunking, audit routing, and review have implementation
and regression coverage. Held-out benchmark verification and suppression policy
evaluation remain follow-ups. Extractive supplementary-context selection,
additional audit evidence ranking, semantic deduplication, and cache pricing are
separate planned work, not implied capabilities of these flags.
