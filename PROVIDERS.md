# Provider catalogs

Providers and their model catalogs live in [`internal/config/providers/`](internal/config/providers/).
The binary embeds every `.yaml` file in that directory. Adding a built-in service
that uses an existing protocol requires a YAML file and no Go registration.
Local provider files can add services or patch the bundled definitions without
rebuilding the binary.

## Add a local provider

Save a definition such as `providers/review-service.yaml`:

```yaml
schema_version: 1
name: review-service
protocol: openai-chat
base_url: https://review.example.com
require_model: true
warn_unpriced: true

auth:
  type: bearer
  api_key_env: REVIEW_SERVICE_API_KEY

request:
  path: /v1/chat/completions
  max_tokens_field: max_completion_tokens

discovery:
  format: openai-models
  path: /v1/models

models:
  - name: review-v1
    aliases: [reviewer]
    request_model: deployed-review-v1
    context_limit: 128000
    max_output_tokens: 8192
    tokenizer_encoding: cl100k_base
    supports_structured_output: true
    # Illustrative values: replace these with your deployment's verified rates.
    input_price_per_million: 1.0
    output_price_per_million: 4.0
```

Load it from `.codecrucible.yaml`:

```yaml
provider-files:
  - providers/review-service.yaml
provider: review-service
model: reviewer
```

Config-file paths are relative to that config file. Alternatively, pass
`--provider-file providers/review-service.yaml`; flag paths are relative to the
current directory. Repeat the flag for multiple files. When provided, the flag's
list replaces the config file's `provider-files` list.

Validate and inspect the catalog before scanning:

```bash
codecrucible validate-providers
codecrucible list-providers
codecrucible list-models --registered --provider review-service

# Provider-reported models require the service's credentials and network access.
codecrucible list-models --provider review-service
codecrucible scan ./target --provider review-service --model reviewer --dry-run
```

Set the API key in `REVIEW_SERVICE_API_KEY` when making real requests. Catalogs
store credential variable names, not credentials. Existing per-phase `api-key`,
`base-url`, headers, and model-parameter overrides still work.

## Patch a bundled provider

A file naming an existing provider only needs its identity and changed fields:

```yaml
schema_version: 1
name: anthropic
models:
  - name: claude-sonnet-5
    input_price_per_million: 1.5
    output_price_per_million: 7.5
```

This keeps the model's context window, output limit, tokenizer, and capabilities.
Files apply in order; later files win. Mappings merge field by field, and models
merge by case-insensitive `name` within their provider. Explicit `false`, `0`, and
empty strings override inherited values. Alias lists replace rather than merge;
`aliases: []` clears them. An empty `models: []` adds no patches and leaves the
existing models in place.

The legacy top-level `models:` configuration remains supported. Those entries
apply **after** provider files and retain their old behavior: a matching model
name replaces the entire entry, including its provider hint. They are isolated
to the current configuration load. Prefer provider files for partial overrides.

## Definition fields

| Field | Meaning |
| --- | --- |
| `schema_version` | Required; currently `1`. |
| `name` | Required provider identifier, using lowercase letters, digits, and hyphens. |
| `protocol` | `openai-chat`, `anthropic-messages`, or `databricks`. Controls serialization, response parsing, streaming, and retries. |
| `base_url` | Default HTTP(S) base URL. May contain a prefix path. Leave empty to require a runtime URL. |
| `auth.type` | `bearer`, `api-key` (`x-api-key` header), `optional-bearer`, or `none`. |
| `auth.api_key_env` | Environment variable containing the key. A per-phase key takes precedence. Overriding this field stops use of the provider's legacy key variable. |
| `headers` | Static HTTP header mapping, such as `anthropic-version`. Use `auth` for credentials. |
| `request.path` | Path appended to the base URL. Databricks additionally supports `{endpoint}`. |
| `request.max_tokens_field` | Optional `max_tokens` or `max_completion_tokens`. The latter also normalizes legacy `model-params.max_tokens` overrides. Model-level `use_max_completion_tokens` remains supported. |
| `discovery.format` | `openai-models`, `anthropic-models`, `ollama-tags`, `databricks`, or `none`. |
| `discovery.path` | Discovery path, appended to the same base URL; ignored for format `none`. |
| `default_model` | Optional model name in this provider's catalog, used when that provider is selected without a model. |
| `require_model` | Require an explicit model when this provider has no `default_model`. |
| `warn_unpriced` | Warn that cost reports and budget enforcement exclude a selected model with no configured rates. |
| `auto_detect_priority` | Positive integer enables credential-based auto-detection; lower numbers win. Zero (default) requires explicit selection or inference from a unique model. |
| `fallback` | Optional `claude-cli`, supported with `anthropic-messages`. Preserves Anthropic's local CLI authentication fallback. |
| `models` | Model entries using the existing `ModelConfig` fields, plus `aliases` and `request_model`. |

`request.path` is appended literally to the trimmed base URL; it does not replace
the URL's existing path. The bundled OpenAI and Cerebras paths include `/v1`;
Google's base URL already includes `/v1beta/openai`. Existing `--base-url`
conventions are preserved. Databricks retains its workspace host and serving
endpoint routing through `DATABRICKS_HOST`, `DATABRICKS_TOKEN`, and `--endpoint`.

New models without explicit limits use conservative defaults: 128,000 context
and 8,192 output tokens, with structured output disabled. Set verified deployment
limits, capabilities, and pricing before relying on them. Discovery reports model
availability; it does not establish model capabilities or contract pricing.

## Model identity and compatibility

Models are resolved within the selected provider, so identical model IDs can
have different limits and prices on different services. A bare model name that
matches multiple providers requires explicit `--provider` selection. Databricks
can still borrow public model profiles for its proxy deployments, preserving
legacy prefixed-name matching.

`aliases` explicitly map friendly names to their catalog model. Matching ignores
case and common separators. `request_model` sets the actual deployment ID sent to
the API; otherwise an alias sends its canonical catalog name. For compatibility,
non-exact profiles still support the existing longest substring match, preserving
the model ID the user supplied. `exact_match: true` disables aliases and substring
matching for that profile. Unknown models retain conservative defaults and do not
borrow another direct provider's capabilities or pricing.

A `model-params.model` override still takes precedence in the request body. It does
not change the selected catalog profile or its pricing assumptions. Scan artifacts
record the resolved provider protocol, request path, model, token-field policy,
and a fingerprint of static provider behavior without copying credentials or
header values.

Files are loaded explicitly, in a deterministic order, with no automatic network
updates or executable configuration. Validation rejects unknown fields, duplicate
models and conflicting aliases, unsupported protocol/auth/discovery formats,
invalid URLs, and invalid token limits or prices. Protocol changes that introduce
new serialization or streaming behavior still require a Go adapter.
