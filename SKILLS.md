# Prompt Sets

A "prompt set" is a complete bundle of YAML templates that drives every
LLM phase (feature detection, analysis, audit, CWE deep-dive, optional
context compression) with a consistent persona, threat model, and output
contract. The active set is chosen with `--prompts-dir`; the shipped sets
live under `prompts/` and are swappable without touching Go code.

```bash
codecrucible scan /path/to/repo --prompts-dir prompts/exploit-proof-web-go
```

Each directory contains:

- `security_analysis_base.yaml` — system prompt and framing (persona, threat
  model, reporting rules, schema pointer)
- `analysis_sections.yaml` — the enumerated vulnerability classes the
  analyzer walks through; pruned by feature detection on multi-chunk scans
- `feature_detection.yaml` — file-manifest pre-pass that decides which
  sections are worth keeping
- `audit.yaml` — second-pass validator that challenges each finding
- `cwe_deep_analysis.yaml` — CWE-specific deep dives used by the audit
- `context_compress.yaml` *(optional)* — one-shot compressor for large
  supplementary-context sources

If a prompt set is missing `context_compress.yaml`, `--cc-*` compression
falls back to whichever template is available at `prompts/default/`.

## Choosing a set

| Set | When to reach for it |
|-----|----------------------|
| `default` | First-pass, language-agnostic, two-stage (recall-tuned analyzer + adversarial audit). The right starting point for most repos. |
| `carlini` | Slim CTF-researcher persona. Maximizes code-to-instruction ratio — use when the context budget is tight and you want the model thinking like an attacker, not a linter. |
| `carlini-curated` | Carlini with added suppression rules and tighter line-precision guidance. Lower false-positive rate at modest token cost. |
| `exploit-proof` | Language-agnostic with a *concrete exploit required* per finding. The model's own exploitation reasoning replaces the deny-list — good precision without hand-curated rules. |
| `exploit-proof-c-kernel` | Kernel / driver / protocol parser C. Persona knows syscalls, `copy_{from,to}_user`, mbuf/skbuff chains, locking, RCU, refcount lifecycles. |
| `exploit-proof-c-userland` | C/C++ userland — setuid binaries, privileged daemons, IPC endpoints, file-format parsers. Memory safety + privilege boundaries. |
| `exploit-proof-rust` | Rust. Focuses the model on `unsafe`, FFI boundaries, serde deserialization, integer casts, `Send`/`Sync` mistakes, panics as DoS. |
| `exploit-proof-solidity` | Solidity / Vyper. Reentrancy, flash-loan oracle manipulation, access control across upgrades, silent casts. |
| `exploit-proof-web-go` | Go web services — net/http, gin, chi, echo, fiber, gRPC. Go-specific footguns (loop-var capture, nil-interface, concurrent map access). |
| `exploit-proof-web-java` | JVM web — Spring (MVC/WebFlux), Jakarta EE, Quarkus, Micronaut, Ktor. JPA raw queries, readObject, Jackson default-typing, JNDI, XXE. |
| `exploit-proof-web-js` | Node.js backends and JS/TS frontends (Express, Next.js, React, Vue, Angular). Template sinks, DOM sinks, dynamic `require`, shell out. |
| `exploit-proof-web-python` | Django / Flask / FastAPI / Starlette / Tornado / aiohttp. ORM query builders, template engines, `pickle.loads`, subprocess, missing authn/authz. |
| `nano-analyzer` | Terse attacker-first walkthrough adapted from [weareaisle/nano-analyzer](https://github.com/weareaisle/nano-analyzer). Five questions per function, show-your-work style. Pairs well with larger-context reasoning models. |

The `exploit-proof-*` language variants share the "concrete exploit or
it doesn't ship" gate from the base `exploit-proof` set but swap the
persona and the trace-to-sink list for language-specific hotspots. Pick
the variant that matches the repo's primary language; fall back to the
language-agnostic `exploit-proof` for polyglot codebases.

## Authoring a new set

Copy an existing directory and edit in place:

```bash
cp -r prompts/default prompts/my-set
# tweak system_message, analysis_sections, audit criteria, ...
codecrucible scan ./target --prompts-dir prompts/my-set
```

Required files: `security_analysis_base.yaml`, `analysis_sections.yaml`,
`feature_detection.yaml`, `audit.yaml`, `cwe_deep_analysis.yaml`. The loader
errors loudly if any of these are missing.

Things to keep intact when authoring:

- **Schema conformance.** The analyzer returns JSON matching
  `llm.SecurityAnalysisSchema`; the prompt must keep asking for it. Changing
  the shape means changing `internal/llm` as well.
- **`{repo_name}` / `{xml_content}` placeholders.** Templated in by
  `llm.PromptParams` — drop them and the scan target never reaches the model.
- **Audit cross-reference.** The audit expects analyzer findings to name a
  *source*, a *sink*, and the *absent control*. Prompts that produce
  free-form prose break the audit's ability to challenge individual
  findings.
- **Recall bias in the analyzer, precision bias in the audit.** This is the
  two-pass contract. A prompt set that pre-filters aggressively in the
  analyzer gives the audit nothing to remove and hurts overall recall.

## Prompt-set-aware flags

Nothing about per-phase flags, supplementary context, or model selection is
tied to a specific prompt set — they compose. A common pattern is a cheap
flash model for feature detection, the main thinking model for analysis
against a specialist set, and a smaller model for audit:

```bash
codecrucible scan ./target \
  --prompts-dir prompts/exploit-proof-web-go \
  --fd-provider google --fd-model gemini-3-flash \
  --model claude-opus-4-7 \
  --audit-model claude-sonnet-4-6
```
