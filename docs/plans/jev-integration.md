# Optional Jev integration

The runtime integration covers feature detection, smart chunking, audit, and
finding review, CWE mapping, and semantic deduplication. All stages default to off.
`--jev` enables the original four unspecified stages in active mode and the new
mapping/deduplication stages in shadow mode;
individual `--jev-<stage> off|shadow|active` settings override it. A credential
alone never enables requests. Generative analysis remains the discovery pass.

## Phase contracts

Policy `jev-decisions-v5` uses different question shapes for different actions.
Choice describes categorical evidence, Noul tests a scoped yes/no proposition,
and Score ranks optional context. Question builders preserve the untrusted-source
boundary without instructing a Noul or Score to return a Choice category.

| Phase | Questions and evidence | Action |
| --- | --- | --- |
| Feature detection | One Noul for executable use and one Choice for presence/absence per conditional feature in each bounded source batch, including custom features. | Positive evidence retains the section. Only complete coverage and strong absence in every batch can omit it. Failures, missing source, and exhausted quotas retain uncertain categories. |
| Smart chunking | A bounded identifier shortlist selects pairs not already connected by the grouping graph. Score compares no demonstrated benefit, supporting context, and directly connected operations. | Accepted pairs add optional edges. The existing chunker still controls file accounting and token packing. |
| Audit | Separate Choice checks for reachability, attacker control, operation, impact, and mitigation. Noul checks for relevant control evidence; Choice locates a candidate blocking span. | All support prerequisites must pass to avoid generative audit. Rejection requires an exact blocking span and a second source-grounded verification. Everything unresolved goes to the existing auditor. |
| Review | Choice for each sentence-sized assertion, using the original claim and exact source as shared state. | Record supported, contradicted, unsupported, insufficient context, unavailable, or nonfactual status. Keep every finding. Reuse only identical claim/evidence/context checks within this phase. |
| CWE mapping | Choice among at most 16 retrieved CWE definitions, plus outside-candidate and insufficient-evidence options. | Explicit active mode applies strong Allowed mappings. Review-required and uncertain suggestions preserve the original label. |
| Deduplication | Separate Choice questions for complete root-cause identity and an exact shared source scope. | Explicit active mode consolidates strongly supported duplicates and preserves the full original records. Every duplicate is compared directly with its representative. |

Feature evidence is packed deterministically into at most 18K serialized bytes per
batch. Files stay together where possible; larger files use adjacent source
ranges. Questions require uncertainty when a split declaration or missing context
prevents classification. Unrepresentable lines create a coverage gap instead of
being silently truncated. The repository filename list is no longer a coverage
gate. A positive observation in any batch retains the feature and stops further
questions about it. Absence requires strong answers in every batch and complete
source coverage. Batch records distinguish local observations from the final
repository aggregate, including attempted/completed batch counts. The shared
request quotas and retries still apply; incomplete work cannot authorize omission.

Feature observations separate `observed_present`, `absent`, `unknown`, and
`unavailable` from `retained_for_analysis`. A low Noul value is not proof of
absence. A conflicting positive signal prevents omission. The existing empty
feature-list convention means all sections: if every feature would be omitted,
the integration retains them all and reports the actual retention. Single-chunk
and skip guards remain in force. `--skip-feature-detection` supplies an all-sections
control without a detector request.

The bundled `default` audit template declares `decision_audit: true`. This opts
into the fixed Jev evidence policy, including the possibility that a resolved
finding never reaches the template. Other prompt sets retain generative audit
unless they explicitly opt in. Jev does not refine prose, severity, or CWE labels
and does not create findings. Unresolved findings are repacked into generative
batches. Jev-retained findings are restored afterward, outside legacy confidence
filtering. Exhausted generative audit retries preserve unaudited findings and
allow CI to continue with an incomplete-audit warning.

Review checks at most 12 assertions. Truncated checklists and reports containing
only nonfactual advice cannot become fully supported. A disagreement remains
attached to its assertion and appears in SARIF help. It never suppresses the
finding. An identical check can be reused with a `reused_from` reference; changed
source, assertions, custom requirements, or supplementary context cause a fresh
check. This cache does not reuse the audit's different question contract.

Shadow mode records proposed model decisions while preserving the stage's
existing output. Stage controls are independent. Review may run with
`--skip-audit`; `--skip-feature-detection` prevents both detectors.

## Deterministic grouping and source selection

`--dependency-grouping` enables enhanced admitted local dependencies, including
Go package and Python module relationships, without a Jev credential or request.
This flag is independent of the model stages. `--jev` no longer implicitly enables
it. Existing import grouping remains the baseline when both options are off.

Compare these three grouping configurations with the same model, prompts,
source revision, chunk budget, and audit settings:

```bash
codecrucible scan ./my-repo --skip-feature-detection --output baseline.sarif
codecrucible scan ./my-repo --skip-feature-detection --dependency-grouping --output dependencies.sarif
codecrucible scan ./my-repo --skip-feature-detection --dependency-grouping --jev-smart-chunking active --output semantic.sarif
```

Semantic candidates use identifiers throughout each file. Common identifiers
appearing in more than 16 files are excluded. At most three candidate pairs per
file and 128 total are considered, in batches of six. Go evidence uses complete
relevant declarations below the file header, up to three per file and 1,800
serialized bytes per file for each pair. Other languages use full files only
when they fit. Evidence is deduplicated within a request. A pair with no bounded
scope for either file is skipped without a model question. Grouping is optional:
no pair score excludes a source file.

Audit and review use an index of admitted source. Cited Go declarations are
reserved first, followed by referenced local definitions and incoming uses,
including function values passed as handlers. Ancestor scopes retain registration
and guard ordering. Conventional `Use`/`With` middleware references and condition
references supply additional definitions. Shared helpers do not recursively pull
in unrelated callers. Other languages and Go parse failures use full files.

These are best-effort source relations, not a typed call graph or control-flow
proof. Source scopes are supplied in exact 24-line spans within an 18K serialized
byte budget. A partial function cannot authorize a verdict. Missing files,
invalid locations, or required scopes that do not fit create coverage gaps.
`coverage_scope: "claim_context"` describes this selection, not whole-program
coverage. Jev must still establish prerequisites, runtime behavior, and control
ordering from the evidence. Uncertainty routes to the generative auditor.

## Bounds, policies, and accounting

CWE mapping runs after audit and review, followed by semantic deduplication. Each
has independent `off|shadow|active` controls and its own SARIF phase artifact.
The original location/CWE deduplication still runs before audit; remapping does
not rerun it. Generative audit CWE refinements now update the individual finding's
rule and taxonomy as well, without changing its finding ID or other users of a
shared rule. Classification history records both assignments.

The offline CWE 4.20 catalog includes official definitions and mapping notes with
the MITRE license and source hash in `internal/cwe/NOTICE`. Candidate retrieval is
lexical and bounded, so candidate coverage must be evaluated separately from
classification accuracy. Deprecated, Prohibited and Discouraged entries are not
offered. Allowed-with-Review entries can be proposed but are never automatically
applied by Jev. A classification is about the reported source mechanism and does
not establish exploitability. No network catalog download happens during a scan.

The new stages select complete cited Go declarations, or full files for other
languages, without recursively requiring caller coverage. Their scope is
classification, not reachability proof. Invalid citations, oversized claims, or
incomplete cited scopes retain the original result. Mapping supplies at most 9K
serialized evidence bytes and 10K definition bytes; deduplication supplies at most
7.5K evidence bytes and 4.5K claim bytes per finding. The client still enforces the
complete serialized request limits. Shared scopes shortlist deduplication pairs;
matching prose, CWE, or a common file alone cannot authorize a merge. At most 128
pairs and the stage's allocated request quota are considered. Unexamined findings
are retained. Already consolidated inputs are not merged again.

Deduplication chooses the highest-severity representative, breaking ties by stable
finding ID, and compares every member directly to that unchanged representative.
It never uses a transitive closure of pairwise answers. Active merges retain all
locations and code flows, and archive each complete original result and rule in
`properties.deduplicatedFindings`. SARIF help identifies the consolidated entries.
Input/output finding counters reconcile every merge. Shadow mode records proposed
merges with unchanged SARIF findings. Independent human evaluation remains
necessary before treating these policies or thresholds as effective.

The client uses the [TypeSafe API](https://docs.typesafe.ai/api), pins
`jev-1.13.0`, and records the returned model. The configured input rate is $0.042
per million tokens with free output, from the
[model documentation](https://docs.typesafe.ai/models). Rates are configurable
accounting estimates, not invoices.

Default bounds are 128 logical requests, two retries, and a 30-second timeout
per attempt. The logical cap is divided equally among enabled stages, including
shadow stages. Remainders go in feature detection, grouping, audit, review, CWE
mapping, deduplication order.
Disabled stages reserve nothing. Unused capacity is not borrowed. Verification
requests consume the audit quota. Quotas are recorded in the scan recipe.

HTTP 408, 429, 5xx, transport/read failures, and invalid successful responses share
bounded retries. Other HTTP errors fall back immediately. Parent cancellation
interrupts requests and backoff. Redirects are rejected. Errors and decision
records exclude provider response bodies and credentials.

Request validation budgets JSON UTF-8 bytes plus overhead under 64K for the full
request and 32K for state plus one question. These conservative upper bounds are
not a Jev tokenizer estimate. Oversized requests never reach the provider. Jev
token counts do not calibrate the generative model's chunk budget. `--max-cost`
remains the existing source-input preflight check, not a billed-spend cap.

Verdict and omission gates require selected Choice probability at least 0.98 and
confidence at least 0.95. Scoped positive Noul checks require at least 0.98.
Optional grouping has a separate experimental policy: Score at least 1.6,
probability of the directly-connected level at least 0.8, and confidence at least
0.7. These thresholds require evaluation. They are not calibrated security
accuracy and never populate the generative `auditConfidence` field. Correlated
answers are not multiplied. A second request to the same model is an additional
check, not independent proof. See [TypeSafe confidence](https://docs.typesafe.ai/confidence).

The common usage ledger records actual HTTP attempts, returned models, retries,
reported token categories, and unknown or unpriced usage. Logical caps include
verification; the retry cap separately bounds additional HTTP attempts.

## Observable outcomes

Decision artifacts record policy, model, typed answers, evidence hashes/ranges,
coverage gaps, state hash, action, and stage totals. They omit raw source and
prompt bodies. Counts describe decisions and their effects:

- Feature categories retained and omitted, distinct from observed features.
- Deterministic dependency edges, semantic pairs evaluated or skipped, and edges
  accepted or applied. Edge origin distinguishes deterministic and Jev behavior.
- For applied Jev edges, whether the endpoints share a resulting chunk and whether
  that placement differs from packing the same input without those edges.
  `placement_measured` distinguishes a completed comparison from unmeasured edges.
  A comparison failure warns and does not discard the successful scan.
- Audit retain, reject, and escalate outcomes. These count findings routed away
  from or toward generative audit, not a claim about the number of batches saved.
- Assertions supported, contradicted, unsupported, unresolved, or unavailable;
  finding review statuses and reused assessments. Assertion counters count fresh
  evaluations; finding counters include explicit reuse.

Shadow feature, audit, and review counters use `proposed_` names. Grouping records
accepted proposals separately from applied edges and measured placement. A
completed request does not by itself count as a useful decision.

Feature artifacts and SARIF scan metadata separate detected features from retained
categories. SARIF finding properties preserve per-assertion review statuses and
reuse provenance. Review help exposes unresolved assertions for human validation.

## Verification and remaining evaluation

Mock-provider tests cover typed contracts, retries, cancellation, redirects,
request and stage caps, disabled-mode compatibility, deterministic grouping
without credentials, conservative feature selection, callback evidence,
file/chunk budgets, required audit prerequisites, exact rejection verification,
assertion review, duplicate reuse, and whole-scan usage reporting. These tests
verify implementation behavior. They do not establish live model quality or
savings.

Build a human-reviewed evaluation corpus with true positives, decoys, unresolved
findings, custom prompts, multiple languages, misleading comments, missing
cross-file context, and mitigation lookalikes. Keep tuning repositories separate
from holdouts. Existing model verdicts are comparison data, not labels.

Evaluate fixed pre-audit findings to isolate retrieval changes from question
changes. Compare feature detection with the existing detector and all-sections
control, grouping with both deterministic baselines above, and review with
altered assertions and citations. Measure omissions, evidence coverage, correct
confirmations, false suppression, false support and contradiction, abstentions,
packing changes, actual generative requests, total cost, and latency.

Then compare isolated active stages and combined stages using repeated scans
with pinned inputs. Join SARIF and usage/decision artifacts to run IDs, including
configuration and artifact hashes. Inspect individual lost vulnerabilities.
Shadow mode measures proposals and overhead, not realized savings. Promote a
stage only after its incremental benefit and error policy are established.

Beads tracks implementation and evaluation separately under `codecrucible-ngo`.
The database and exports stay gitignored. Further work includes human-reviewed
policy calibration, rule-specific proof obligations, bounded follow-up retrieval,
feature indexes for larger repositories, structured criteria, evidence extraction,
and cache pricing. These are not implied capabilities of the current flags.
