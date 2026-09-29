# Jev integration plan

Status: proposed; no runtime integration in this change.

Baseline: `main` at `874f99f`, reviewed 2026-09-29.

CodeCrucible uses generative models to discover vulnerabilities and audit the resulting findings. Introduce TypeSafe Jev for bounded semantic decisions around those calls: selecting analysis instructions, choosing supporting context, and checking supplied evidence. Start with feature detection; make audit-call avoidance a later, separately evaluated capability.

The success measure is lower **total scan cost at maintained finding quality**. A cheap extra model call is only a saving when it removes work or reduces downstream tokens. Keep vulnerability discovery and complex exploit reasoning on generative models. Keep filtering, token arithmetic, exact source lookup, and SARIF serialization in ordinary Go code.

## Current integration points

| Workflow | Current implementation | Proposed change | Priority |
| --- | --- | --- | --- |
| Usage and cost | [scan.go](../../internal/cli/scan.go), [cost_estimate.go](../../internal/cli/cost_estimate.go) aggregate analysis and audit; separate feature detection and compression are omitted from final totals | Record every request and price known usage before comparing alternatives | Foundation |
| Feature detection | [runFeatureDetection](../../internal/cli/scan_analyze.go) generates a feature list from a manifest and small code sample | Jev judges each known feature; application code selects prompt sections conservatively | First release |
| Supplementary context | [compress.go](../../internal/supctx/compress.go) generates summaries; [scan_helpers.go](../../internal/cli/scan_helpers.go) packs context once per phase | Select relevant existing passages with Jev; preserve exact text and provenance | Second release |
| Audit context | [scan_audit.go](../../internal/cli/scan_audit.go) sends files named by findings plus shared supplementary context | Retrieve bounded candidate evidence, then use Jev to rank relevance | Second release |
| Audit decisions | Generative auditor produces verdicts, confidence, and narrative; `applyAuditVerdicts` filters findings | Check narrow evidence claims, then use explicit rules to route eligible findings or escalate | Experimental third release |
| Semantic duplicates and source spans | [postprocess.go](../../internal/sarif/postprocess.go) deduplicates exact keys; [builder.go](../../internal/sarif/builder.go) extracts supplied locations | Optional semantic grouping and candidate-span selection | Deferred |

Feature detection currently runs only when the repository exceeds the single-chunk budget. Of the bundled prompt sets, only `default` conditionally enables sections by feature. Its direct cost saving will therefore be limited on many scans. The largest plausible saving is reducing repeated audit context and, eventually, avoiding some audit calls. Measure both before expanding scope.

## First release: a small, observable integration

### 1. Account for every phase

Introduce one request-usage record used by generative and decision clients. Include phase, purpose, request/attempt ID, provider, actual model, usage, pricing version, elapsed time, status, and fallback reason. Aggregate exactly once across retries, repair calls, failed audit batches, recovery chunks, feature detection, and context compression. Preserve provider-specific token categories rather than inventing equivalence between them.

Distinguish estimated cost, cost calculated from reported usage, and unpriced or unknown usage. A failed request with no usage must not be counted as known zero spend. Extend existing phase artifacts with versioned usage and decision records; exclude credentials and authorization headers. Raw source remains subject to the existing artifact options.

The existing `--max-cost` is a source-input preflight check, not a runtime spending ceiling. Keep that contract explicit. This project does not require a global concurrent budget scheduler; add bounded Jev attempts and calls, include planned decision spend in estimates where possible, and report unknown cost honestly.

### 2. Add a typed decision client

Create `internal/decision` with a small evaluator interface and a TypeSafe HTTP implementation using Go's standard HTTP client. Do not route Jev through `llm.Client.ChatCompletion`: its output cannot satisfy the existing narrative analysis/audit schemas.

Support Choice, Noul, and Score requests and their distinct answer shapes. Validate expected question IDs, answer types, permitted choices, numeric ranges, and required probability fields before consuming a response. Each question must contain its full instructions; IDs are correlation keys. Questions that depend on previous answers require a later request or composition in Go.

Use `POST /v1/systemone`, Bearer authentication from `TYPESAFE_API_KEY`, explicit deadlines, context cancellation, bounded retry/backoff for transient errors, and injectable transport for tests. Never forward credentials across an endpoint redirect. Invalid authentication or request schema is not a retry loop. These requirements follow the [API contract](https://docs.typesafe.ai/api).

Pin the initial model to `jev-1.13.0`; record the returned version. On the review date, TypeSafe lists $0.042 per million input tokens and free output, with two simultaneous limits: 64K for the complete request and 32K for state plus its longest question. Keep limits and price in configurable model metadata, use conservative request estimates, and reject or split oversized requests without silently dropping evidence. Refresh these values before implementation. [Model reference](https://docs.typesafe.ai/models).

Do not use Jev usage to calibrate the analysis model's tokenizer. The baseline feature-detection call also supplies a token correction factor; replacing it must retain conservative chunk budgeting when matching analysis-provider calibration is unavailable. Coordinate with any separately merged tokenizer work before touching this seam.

### 3. Replace feature-list generation

Derive supported feature IDs from the loaded prompt set and its existing feature contract, including custom templates. Use one Choice per feature with `present`, `absent`, and `insufficient_evidence`, evaluated against an explicit rubric. Presence of one feature must not exclude another. Record sample/manifest truncation and coverage.

Initially run Jev in shadow mode: the existing path owns section selection. Active mode may omit a section only under a validated absence policy. A missing signal in a small sample is insufficient evidence of repository-wide absence. Keep uncertain features and always-on sections. On errors, enable all sections; preserve the current empty-list-means-all behavior in [prompt.go](../../internal/llm/prompt.go).

Skip the decision when there is no downstream consumer. Check conditional sections, custom feature placeholders, and calibration behavior before removing the existing call. Preserve `--skip-feature-detection` and the current single-chunk shortcut. Acceptance requires correct custom-prompt handling and reduced measured cost on workloads where feature detection actually runs.

## Configuration and compatibility

Use a separate `decisions` configuration block; leave generative `phases` intact. The following is a proposed interface, **not working configuration yet**:

```yaml
decisions:
  provider: typesafe
  model: jev-1.13.0
  feature-detection: shadow
  context-selection: off
  audit-evidence: off
```

Each capability accepts `off`, `shadow`, or `active`; all default to `off` during introduction. Presence of an API key never enables a capability. Shadow mode makes additional paid requests, records proposed actions, and preserves the existing workflow's outputs. Active selects Jev first for the explicitly enabled capability, with the documented fallback. Configuration errors fail at startup when a capability is enabled. Runtime failures use the capability's conservative fallback; user cancellation stops the scan.

The initial release exposes only implemented settings and rejects unknown values. Later capabilities add their own settings when available. Keep `--skip-audit` authoritative. Existing configurations require no Jev credentials and retain their current behavior. Add relevant CLI/env bindings, dry-run visibility, init examples, and README guidance with each implemented capability. Thresholds live in versioned task policies backed by evaluations, not one global confidence flag.

## Second release: select useful evidence

Create immutable evidence records from already loaded, permitted inputs: stable ID, source path/URI, revision or content hash, line range or passage offsets, exact text, role, and retrieval origin. Source text is untrusted data, including instructions embedded in comments. Code validates that returned candidate IDs exist and resolves them to the original text. Jev does not invent quotations, paths, or line numbers.

For supplementary context, split documents into passages with headings and adjacent qualifications. Score relevance against an explicit security-context rubric, then pack selected passages deterministically within the phase's actual token budget. Reserve space for user-pinned constraints and required definitions. Respect source phase/include/exclude rules and existing compression opt-in. If pinned material cannot fit, expose the limitation rather than silently presenting a complete context. Selection failures use the existing configured compression/packing path.

Start with phase-level extraction to replace optional summary generation. Per-chunk selection and per-finding audit selection require moving context preparation closer to prompt assembly; the current once-per-phase pack cannot provide that behavior. Record excluded passages and coverage. Exact quotation avoids fabricated summaries but does not establish that all relevant context was selected. The [reranking cookbook](https://docs.typesafe.ai/cookbooks/rerank_typesafe) provides the retrieval-then-judgment pattern; benchmark it on security evidence here.

For audit retrieval, always preserve the cited finding span and sufficient surrounding code. Retrieve additional candidates using lexical/symbol matches and existing import metadata before ranking them. Limit the search to configured scan/context scope. The current import graph is incomplete; missing callers, dynamic dispatch, or dependencies must remain explicit gaps. On poor coverage or no useful match, retain the original audit context and escalate rather than treating missing evidence as a mitigation.

## Third release: evaluate an audit cascade

First use Jev to check narrow predicates against supplied evidence, such as whether a quoted condition supports a stated local precondition. Return `supports`, `contradicts`, or `insufficient_evidence` with validated evidence references. A local ownership comparison alone does not prove trustworthy identity or end-to-end authorization. The [citation-checking cookbook](https://docs.typesafe.ai/cookbooks/citation_check) informs this decomposition, not its security accuracy.

Introduce a separate decision record; never copy Jev confidence into `AuditedFinding.Confidence` or the existing rejection threshold. Noul has no separate confidence field. Choice/Score confidence describes the answer distribution, not independently verified security correctness. Combine answers with explicit rules; do not multiply probabilities as though correlated checks were independent. [Confidence guidance](https://docs.typesafe.ai/confidence).

Run evidence checks beside the full generative audit first. The first active optimization may retain an eligible finding without a generative audit, preserving its original explanation and marking the limited verification accurately. It must not claim a complete exploit proof. Repack unresolved findings into actual audit requests so eligible findings cause real call/token savings.

Automatic suppression needs a separate promotion gate and remains disabled initially. The baseline rejects a finding when `blocking_code` is nonempty without verifying its existence or relevance. Before any Jev-led suppression, require exact source validation, a task-specific contradiction policy, sufficient context coverage, and held-out evidence of acceptable false-suppression risk. Cross-file invariants, conflicting judgments, incomplete candidates, or unsupported cases go to the existing auditor; unavailable audit retains an unverified finding. Check the whole verdict application path so a later low-confidence filter cannot undo that retention.

Generative audit continues to own nuanced exploit reasoning and prose refinement. Preserve prompt-set-specific new-finding behavior where enabled. Do not switch main analysis to a weaker model on the assumption that Jev can catch vulnerabilities it never reports.

## Evaluation and promotion

Use [block/benchmrk](https://github.com/block/benchmrk) for end-to-end finding-quality verification. Extend the evaluation task with a reproducible benchmrk workflow and a join to CodeCrucible's usage artifacts. Keep narrow decision-contract and fixed-finding replay tests in CodeCrucible.

Build a versioned corpus of synthetic or suitably licensed source fixtures with human-reviewed true findings, false positives, and unresolved cases. Include multiple languages and prompt sets, single/multiple chunks, missing cross-file evidence, misleading comments, adversarial instructions, mitigation lookalikes, no-match candidates, and conflicting supplementary documents. Hold out repositories, not merely individual findings, from threshold tuning. Existing LLM judgments are comparison data, not ground truth.

Compare baseline, shadow, and each active capability independently, then together. Track end-to-end recall and precision, retained unresolved findings, false suppressions, evidence recall, feature-section omissions, fallback rate, actual audit request count, token usage, total cost, and latency. Separate audit-routing evaluation on fixed findings from full scans so discovery variance does not hide regressions. Repeat stochastic baselines where necessary.

Cost comparison: `baseline total - (remaining generative work + Jev + retries/fallbacks)`. Report both absolute savings and percentages, with unknown billing identified. Shadow mode measures quality and overhead; it does not demonstrate realized savings. Reduced finding count only saves whole audit calls when batching changes.

Promotion requires no missed known-positive regression in the held-out release corpus, no unsupported suppression, measured positive net savings for the intended workloads, and recorded uncertainty/sample size. Zero observed misses alone is not proof of a safe rate: choose and document the acceptable risk bound and corpus size before enabling suppression. Keep a per-capability rollback to `off` and rerun evaluations when model, prompt, candidate generation, or policy changes.

### Verification with benchmrk

Plan against benchmrk revision [`0979862`](https://github.com/block/benchmrk/tree/0979862d4281eb9954be51d12a4ccd0cb965bc2e); verify its CLI contract when implementing J3. Its [scanner and scoring documentation](https://github.com/block/benchmrk/blob/0979862d4281eb9954be51d12a4ccd0cb965bc2e/README.md) provides the integration points.

1. Register pinned corpus projects and import reviewed annotations, including valid vulnerabilities and invalid decoys. Tag criticality as `must`, `should`, or `may`. Prefer fresh fixtures for efficacy measurements; use familiar public benchmarks for setup checks. Freeze annotations before held-out evaluation, and retain their hash and the matcher version with results. Review unmatched findings and matching ambiguities before treating every unmatched result as a scanner false positive.
2. Register distinct scanner variants for Jev off, shadow, each active capability, and the combined configuration. Hold the CodeCrucible build, generative models, prompt set, inputs, and scan settings constant within a comparison. Record the Jev model and policy version separately. Include workloads that exercise conditional feature sections, oversized supplementary context, and multiple audit batches; report skipped capabilities separately.
3. Initially run CodeCrucible externally and use [`benchmrk import`](https://github.com/block/benchmrk/blob/0979862d4281eb9954be51d12a4ccd0cb965bc2e/cmd/benchmrk/import.go) to associate each final SARIF with an explicit experiment and iteration. Start with at least three independently executed scans per variant/project to expose variance; increase repetitions and corpus size for promotion decisions. Never count a reused SARIF as a fresh scan. benchmrk's [`--reuse` path](https://github.com/block/benchmrk/blob/0979862d4281eb9954be51d12a4ccd0cb965bc2e/internal/experiment/experiment.go) can import an earlier result, so leave it disabled for efficacy and latency measurements. A later local wrapper can automate execution using `TARGET_DIR` and `OUTPUT_DIR/results.sarif`; explicitly supply required credentials at runtime because the runner limits environment inheritance. Its network-disabled Docker mode is unsuitable for direct Jev/API calls.
4. Produce benchmrk JSON plus a readable comparison report covering TP/FP/FN, precision, recall, F1, and criticality-tier recall. Inspect individual lost vulnerabilities, especially `must` cases; an aggregate F1 improvement cannot offset a known-positive regression. Check that every intended run completed and was scored against the same annotations and matcher. Keep unresolved labels and disputed matches visible.
5. Join each benchmrk run ID to a manifest containing the variant, iteration, corpus revision, configuration hash, final SARIF hash, and CodeCrucible usage/decision artifact paths. Calculate net savings and actual scan duration from those artifacts: import duration is not scan latency. Include Jev overhead, retries, fallbacks, unknown costs, and audit calls avoided. Record decision-level coverage and false suppression from the replay harness alongside the end-to-end scores; do not assume benchmrk natively measures them.

J3 delivers the registration/import recipe, run manifest, and report join. J4–J8 supply benchmark results for their own capability before promotion. Attach the commands, pinned inputs, score exports, cost/latency comparison, run failures, and reviewed regressions to each verification record. Setup can use saved SARIF fixtures; live efficacy runs require independent scans. This planning change does not execute benchmarks.

Use mock HTTP responses for deterministic contract/failure tests; live paid evaluations are explicit, separate runs. Implementation gates are `make test` and `make lint`, plus targeted CLI compatibility, SARIF contract, fallback, accounting, and fixture evaluations. No live Jev calls or application tests are required for this planning-only change.

## Delivery order and tracked work

Implement and review each item separately. Only the foundation, evaluation harness, and feature-detection slice belong in the first release. Context and audit work must not delay that slice.

| Item | Deliverable | Depends on | Completion evidence |
| --- | --- | --- | --- |
| J1 | Complete request usage and cost accounting | — | All request paths reconcile; unknown usage is visible; baseline report |
| J2 | Typed Jev client, capability configuration, decision artifacts | J1 | HTTP/schema/failure tests; disabled configuration unchanged; request limits enforced |
| J3 | Reviewed corpus, benchmrk verification workflow, and decision replay tests | J1 | Pinned annotations/scorer, independent iterations, run manifest, joined quality/cost report |
| J4 | Feature detection with shadow and conservative active mode | J2, J3 | Default/custom prompt coverage, tokenizer isolation, fallback tests, benchmrk verification and measured saving |
| J5 | Evidence records and extractive supplementary context | J2, J3 | Exact provenance, pinned context, qualification preservation, benchmrk and coverage/cost results |
| J6 | Audit evidence retrieval and ranking | J5 | Required spans retained; coverage gaps and scope enforced; benchmrk audit quality/cost results |
| J7 | Shadow audit predicates and experimental retain/escalate cascade | J6 | Independent evidence records; actual batching reduction; benchmrk verification; no silent suppression |
| J8 | Suppression policy evaluation and promotion decision | J7 | Explicit risk bound, held-out benchmrk and replay results, source-validation gate, rollback decision |
| J9 | Optional duplicate grouping and source-span selection | J5 | Separate benefit study; preserve original findings/evidence; no blind transitive merging |

J9 is deferred and is not a dependency of the main rollout. Exact duplicate handling and exact source validation remain deterministic. Budget enforcement beyond the existing preflight contract, new vulnerability generators, provider-wide model routing, and general-purpose agent orchestration are outside this plan.

Beads epic: `codecrucible-ngo`. Items J1–J9 correspond to `codecrucible-ngo.1` through `codecrucible-ngo.9`. The [task export](jev-issues.jsonl) includes descriptions, acceptance criteria, and dependencies. The repository ignores `.beads`, so this reviewed export makes the planned work available with the branch. The installed Beads version has no legacy `bd sync`; refresh the export before committing status changes:

```sh
bd --sandbox show codecrucible-ngo.1
bd --sandbox export --no-memories --output docs/plans/jev-issues.jsonl
```

Start with J1 and the baseline measurements; the next concrete implementation PR should establish what today's scans actually spend.
