# Audit integrity and finding relationships

Status: opt-in implementation; default promotion and held-out evaluation remain pending.

## Objective

Preserve every independently actionable claim, require evidence for the impact
actually asserted, and consolidate duplicate reports without hiding distinct
causes. Make each transformation attributable and reproducible. This improves
how the scanner handles its evidence; it does not make an LLM verdict proof of
exploitability.

The implementation must retain the project's existing constraints: one Go
binary, static analysis of incomplete repositories, local admitted source only,
bounded context and cost, provider-neutral contracts, and valid partial SARIF
when a remote audit fails. It must not require a build, dependency installation,
a language server, an external source fetch, or a graph service. Language
readers extract source facts; security policy stays in shared code.

## Existing foundations and gaps

- `internal/sourceindex` pins admitted source and resolves local dependencies.
  `internal/auditctx` retrieves numbered excerpts from those bytes.
- `internal/provenance` records responses, observations, revisions and terminal
  dispositions. Earlier ledgers lacked explicit producer links, individual
  audit decisions and semantic split/duplicate edges. The v2 ledger now
  records producers, `decision` events, and `split_from`/`duplicate_of`
  relationships (`internal/provenance/ledger.go`).
- `internal/cli/model_usage.go` now records every phase's usage and lineage,
  including fallback clients. Extend this common path rather than add another
  provider-specific recorder.
- `internal/cli/scan_audit_v2.go` already has code-computed verdicts, quote
  verification, partial-response recovery and a bounded duplicate check. An
  established answer may currently have no quote, and quote matching proves
  source fidelity rather than claim correspondence or data flow.
- Legacy audit output can still rewrite an entire grouped claim. The supplied
  identity fields prevent some cross-wiring, but an echoed ID/title is not
  evidence that an explanation concerns the right claim.
- Deduplication groups results by location and normalized CWE, then splits
  each group by source/sink anchors. Wording decides identity in neither
  direction: reworded reports of one defect merge, and different sources or
  sinks at the same location remain separate.

## Data model

Introduce provider-independent types and deterministic policy in
`internal/auditcore`. The CLI owns request orchestration; SARIF and JSONL are
projections of these records.

| Record | Required content |
|---|---|
| Producer | Run, operation, phase, request, attempt and response IDs; requested/resolved model; prompt/schema and source-bundle fingerprints |
| Observation | Producing response ID and result ordinal; immutable original claim, rule, locations and evidence |
| Claim revision | Finding ID, parent revision IDs, immutable claim digest, subject/root-cause scope, source/sink/boundary assertions, and assessed outcome |
| Evidence reference | Pinned source fingerprint, admitted path, bounded range, quote/hash, and deterministic validation result |
| Assertion | Kind, statement, evidence IDs, `established/refuted/unknown`, reasoning, producer and validation state |
| Decision | Input claim revision, raw assessment, applied outcome, policy version, reasons, evidence IDs and output revision IDs |
| Relationship | Typed `derived_from`, `split_from`, `merged_from` or `duplicate_of` edge with reason, producer and evidence |

Keep existing public finding IDs and `codecrucibleFinding/v1` fingerprints for
unchanged findings. Add opaque child IDs derived from a persisted split operation
and child ordinal; do not derive identity from mutable prose, severity or CWE.
A correlation fingerprint remains a matching hint, never a root-cause assertion.
Relationships express parentage; IDs do not encode it. Cross-run ownership,
remediation and issue lifecycle remain downstream concerns.

Use a versioned JSONL event schema with readers for the current version. Allocate
request and attempt identities before calling a provider. Carry the resulting
response ID explicitly through parsing, local repair and model reformatting.
A repaired response names the response it repairs. A replay of the same recorded
operation does not create fresh observations; a new paid response does.

Decision events must distinguish accepted, invalid, retried, unresolved,
refined, split, duplicate, suppressed and failed operations. Preserve the raw
model assessment as well as the code-applied decision. Record each discarded
candidate and the selected survivor. Add an offline validator that checks IDs,
references, acyclic derivation, operation replay, dispositions and SARIF-to-ledger
reconciliation. Keep credentials and full credential-bearing requests out of
artifacts; preserve complete written events on interruption and fail explicitly
on ledger write errors.

## Audit contract and policy

Extend the existing v2 mechanism with an explicit `contract: v3`. Keep readers
and execution adapters for legacy/v2 prompt sets and old `--audit-from` files.
Start v3 in the opt-in `prompts/core` set; change the default only after the
promotion checks below. Do not silently reinterpret an old prompt's response.

Every assessment names the exact input revision and claim digest, not just the
finding ID. The following assertions are separate:

1. The attacker controls the identified value or action.
2. The source-level weakness and violated security boundary exist.
3. The identified path is not blocked by the relevant guard.
4. Each claimed material impact is supported by its actual consumer and
   decisive guard, or has an explicit unresolved precondition.

The shared verifier checks paths, ranges, quote/hash matches, assertion-to-claim
references, and required consumer/guard evidence. Source-index call/import edges
are supporting facts with known extraction limits; they are not whole-program
flow proofs. A model's interpretation of a real quote remains an attributed
assertion. Contradictory or insufficient evidence becomes `unknown` and cannot
be used to establish a concrete escalation.

Reject an atomic claim only when verified, relevant evidence refutes an essential
condition. Confirm only the scope established by the evidence. A latent weakness
can be valid without a deployed HTTP entry point: missing production deployment
information is recorded separately and never becomes a universal rejection gate.
If a broad impact is unsupported, retain the original claim as unresolved and
create a narrower confirmed revision/child only when that narrower claim has its
own evidence. Preserve the reported severity; adopt a new assessed severity only
with a basis tied to the assessed scope. Never promote an unsupported impact
merely because the original analyzer assigned a high severity.

Schema/identity failures get one retry containing only the affected claim; valid
peer assessments survive. An undecided claim must identify its crux and the
missing evidence. There is at most one targeted context-expansion round per
claim by default, subject to the existing request/context/cost limits. Transport
retry policy remains in the provider client. Exhausted audit retries retain the
claim and produce the existing incomplete-audit warning without failing CI.

## Independent subclaims

Prefer atomic first-pass findings. Extend the first-pass schema with optional
entry-point, guard and evidence references so audit need not rediscover them.
Normalize older/grouped findings before destructive audit decisions. A proposed
split must identify the original assertions/evidence covered by each child and
any residual uncertainty. Give children distinct IDs and `split_from` edges;
preserve the grouped observation and its prior revisions.

Coverage cannot be established solely by an LLM saying “complete.” Validate the
referenced original spans, locations and evidence, check for unmapped material,
and retain an unresolved parent/remainder when correspondence is uncertain.
Adjudicate each child independently. A rejected child never suppresses a sibling.
Only mark a parent fully superseded when its complete accepted child set and
any residual disposition are recorded. SARIF keeps suppressed/superseded parent
records with references to the visible children. The ledger validator accounts
for every original observation even when several children share it.

## Retrieval and framework evidence

Use the shared source index to assemble a repeatable bundle for each claim:
primary evidence, original code-path/citation ranges, local callers/imports,
consumer and guard candidates, then bounded surrounding context. Record both
included evidence and omissions (`unresolved_import`, `ambiguous_symbol`,
`outside_scope`, `budget_exhausted`, `source_changed`). An invalid primary anchor
must not strand other valid evidence. An omitted import is not proof of an
absent guard. Before accepting “not supplied” as a reason to narrow or reject,
run the single targeted retrieval round and preserve the unresolved crux if it
still cannot be satisfied.

Framework behavior is a separate assumption record: library/runtime identity,
version or version range, asserted behavior, source of that behavior, and
validation state. Default evidence comes from admitted manifests/source or
explicitly supplied, versioned supplementary context. Optional curated knowledge
packs may provide deterministic facts later; arbitrary online retrieval and
external dependency ingestion are outside this change. Unknown version/default
behavior remains conditional. A cited parser/guard must apply to the actual path,
not merely exist elsewhere in the repository.

## Semantic deduplication

Run this after claim normalization and evidence assessment. Use a bounded
candidate index over source anchors/declarations, root-cause scope, weakness
family and fix location. Similar CWE or prose can nominate a pair, never decide
it. The structured pair judgment is `same_cause_same_fix`, `distinct`, or
`unknown`, with evidence and an explanation of which child claims are covered.
Do not collapse a record containing an independent child that the proposed
survivor does not cover.

Begin with `semantic-dedup: report`: emit relationships/candidates while leaving
all findings visible. Support `off` and a later `suppress` mode. Suppression
requires verified matching evidence, complete child coverage, consistent
assessments and a survivor at least as well supported. Choose the survivor
deterministically by evidence completeness, assessed status, then stable ID.
Keep duplicate records, original IDs and evidence as suppressed SARIF results;
never delete them. Resolve canonical targets before writing edges so chains and
cycles cannot emerge. Contradictory assessments require one focused comparison
or remain separate. Account for every pair-judgment request and abstention.

## Validation and rollout

Synthetic fixtures must cover request repair/retry, reversed completion order,
identity swaps, a genuine weakness with an unrelated consumer, a guard that
reads a different value, parser normalization, version-unknown framework
behavior, a grouped claim with one refuted and one valid child, distinct causes
at the same location, contradictory duplicates, partial responses, interrupted
writes, and older SARIF/ledger replay. Include positive controls beside negative
controls. Run race tests and static Linux builds; preserve the single-binary and
CGO-disabled constraints.

For policy quality, freeze analysis input and source snapshots. Compare legacy,
v2 and v3 audits on independently adjudicated cases; separate tuning from held-out
evaluation. Start with at least two independent iterations per arm and run arms
concurrently. Report sample sizes and uncertainty for unsupported-impact
confirmations, known-positive suppression, per-child preservation, precision by
verdict, unresolved/crux rates, duplicate precision, harmful merges, elapsed time
and complete phase costs. End-to-end scans are a separate recall/coverage check.
Private evaluation artifacts stay outside Git and outside PR descriptions.

Promotion gates are declared before evaluation:

- All deterministic accounting/graph/source invariants pass, with zero hidden
  valid siblings or distinct-cause merges in the regression suite.
- Held-out v3 results reduce unsupported-impact confirmations without increasing
  known-positive suppression; report uncertainty rather than claim significance
  from a small sample.
- Semantic suppression remains opt-in until manually adjudicated held-out pairs
  achieve at least 99% observed duplicate precision, with zero known-positive
  child losses; publish the sample size and confidence interval. Insufficient
  evidence keeps report-only mode.
- Report latency/cost changes against the frozen-input baseline and account for
  normalization, retrieval retries, pair judgments and model reformatting.
- Legacy/v2 execution, old audit replay, current public IDs/fingerprints, and
  incomplete-audit CI behavior remain compatible.

## Scope boundary

This branch plans scanner-local evidence, claim relationships and reproducible
policy. It does not add dynamic exploitation, a full cross-language compiler,
organization-wide issue graphs, new model vendors, or automatic fetching of
external code. Better parsers and downstream issue management can consume the
same contracts later.
