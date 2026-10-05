# Evaluating optional decisions

Jev stages are experimental and off by default. Evaluate evidence selection and
CWE classification independently before testing a combined configuration.
General audit verdict replacement is removed. The generative auditor receives
every finding, including when Jev fails or exhausts its budget.

## Fixed cases

`cmd/decision-eval` accepts a JSON array of cases. The synthetic examples in
`internal/decisioneval/testdata/cases.json` show the format. Every case needs an
ID, label origin, an atomic claim, and frozen source. Evidence cases specify one
required fact and label each candidate path as relevant or irrelevant. CWE cases
freeze their candidate IDs and acceptable answers against the pinned catalog.
Neither kind asks Jev to prove exploitability.

Prepare requests without a credential or network calls:

```sh
go run ./cmd/decision-eval \
  -cases internal/decisioneval/testdata/cases.json \
  -out /tmp/decision-prepared.json
```

For a paid evaluation, set `TYPESAFE_API_KEY` and add `-live`. Pin `-model` and
use a fresh output path. Output files are created with mode 0600 and never
overwritten. They contain source, request hashes, responses, per-case counters,
wall time, and the usage ledger including retries. Do not commit private cases,
source packets, output, or corpus identifiers. A dry run has no attempted or
resolved decisions; it must not be reported as a model-quality result.

The evidence question is the same Noul constructor used by the scanner. The CWE
question shares the runtime Choice constructor. The frozen evaluation state is
deliberately smaller than scan state; it does not validate all runtime retrieval,
context packing, or effects on the generative auditor. Freeze those separately
before an end-to-end comparison. A candidate hit means the correct label was
available, not that Jev selected it.

## Comparisons and measures

Start with independently reviewed labels covering true, false, and unknown cases.
Keep development fixtures separate from held-out examples. Include partial
overlap, compound findings, missing templates/callers, actual protective code,
conditional execution, misleading comments, and multiple source languages.

For evidence selection, compare deterministic retrieval with Jev selection over
the same candidates. Measure candidate recall, selected relevant evidence,
irrelevant additions, missed relevant candidates, source tokens supplied, and
downstream audit correctness. Change retrieval while holding questions fixed;
then change questions while holding evidence fixed. Mandatory cited source must
survive both arms. Selected context never establishes complete program coverage.

For CWE classification, compare keeping the original label, lexical retrieval,
and Jev on the same atomic mechanisms. Report candidate coverage separately from
classification correctness and abstention. Record broad versus specific labels,
outside-list responses, and review-required mappings. Do not reward changing a
correct label. The tool includes a lexical first-candidate baseline; retained
original labels can be compared using each case's `original_cwe` field.

Count attempted, resolved, correct, incorrect, abstained, and unavailable
decisions. Report false support and missed relevant evidence, not just resolved
accuracy. Preserve valid independent answers on partial response failure; do not
combine incomplete prerequisites into a final verdict. Numeric validation remains
strict until a verified provider contract supports different tolerances.

## Promotion and stopping

Before a live comparison, record the metric to improve, the minimum useful gain,
the acceptable error bound, and the sample-size rationale. Thresholds of 0.98 for
Noul or 0.98 probability / 0.95 confidence for Choice are routing policies, not
calibrated guarantees. Test option ordering and abstention tradeoffs without
lowering thresholds simply to manufacture useful actions.

Promote only if held-out cases beat the deterministic or existing-model baseline
at the agreed error bound. Then run isolated stage arms through Benchmrk's native
concurrent runner, with identical per-scan concurrency and frozen inputs. Report
all attempts, rate limits, retries, cache effects, cost, elapsed time, finding
identity and claim-preservation checks. Test combinations only after individual
stages show value. If neither evidence selection nor CWE classification beats
the simpler baseline, remove the runtime Jev path while retaining deterministic
source retrieval, accounting, and audit-preservation fixes.
