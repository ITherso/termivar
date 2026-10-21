# OpenAPI surface review

OpenAPI Surface Review V1 is an explicitly enabled native capability inside the
existing web assessment. It is compiled only with the non-default
`openapi-review` scanner and CLI feature and runs only when the operator passes
`--openapi-review` with explicit `--profile web-review`. Default builds and
default CLI help do not expose the option.

## Selection and transport

V1 selects at most one exact-origin document candidate deterministically. It
first considers bounded references committed by the root bootstrap whose final
basename is `openapi.json`, `openapi.yaml`, `openapi.yml`, `swagger.json`,
`swagger.yaml`, or `swagger.yml`; otherwise it uses the single fixed
`/openapi.json` fallback. The fallback is eligible only after explicit opt-in.
Candidate URLs with credentials, query strings, fragments, another origin, an
over-limit path, or unsupported schemes are rejected. Redirects remain disabled
and cannot retarget the review.

The native action `web.review.openapi.document-replay@1` sends one anonymous,
bodyless GET candidate and one exact replay through the parent assessment's
shared broker. The complete path costs at most two requests and one logical
active verification. It adds no client, authority, budget, cookie state,
credential source, retry path, or separately finalized report.

## Parsing and evidence

Both complete responses must be bounded JSON-compatible documents parsed by
the transport-neutral catalog. Supported documents are OpenAPI 3.0.x and 3.1.x
JSON. Their semantic document identities must agree across replay. YAML remains
unsupported in V1 and cannot create an item. Swagger/OpenAPI 2.0 is
metadata-only. External references are not fetched, and declared API operations
are never executed.

A complete correlated replay may project at most one
`api.openapi-contract-observed@1` item titled “OpenAPI contract observed.” Its
maximum disposition is `Informational` and its authority is `KnowledgeOnly`.
This records an observed contract surface, not endpoint reachability,
authorization behavior, sensitive-data exposure, exploitability, or a
vulnerability. Malformed, oversized, truncated, unsupported, redirected, or
replay-mismatched responses fail closed without an item.

## Selected value-free response privacy

When the binary also compiles `secret-exposure-review`, explicit
`--openapi-review --secret-exposure-review --profile web-review` selects the
existing value-free composition. OpenAPI's separately planned anonymous GET
candidate/replay bodies are not passive secret-detector inputs. The full bounded
semantic replay comparison remains private; equal counts are not an equality
oracle. The same broker, two-request/one-active ceiling and parent accounting
remain in force, with no extra request or budget.

Each received response needs exact committed opaque lineage. Public evidence
retains neither its whole-body hash nor the catalogue digest. The existing audit
retains `semantic_digest` as an explicitly present null, and a qualifying
informational item targets the coarse `assessment_subject`, not a
content-derived document identity. Different catalogues can therefore produce
the same coarse item identity: an unchanged Compare item is not proof of
cross-run document equality. Categorical audit outcomes/counts remain visible,
and feature-independent readers preserve strict current and historical input
contracts. With this privacy option absent, historical digest, document identity
and request behavior remain unchanged.

S04's existing entry-body privacy boundary also withholds body-derived discovery
hints. A custom document link available only inside that body is therefore not
re-parsed to select OpenAPI; the explicitly enabled `/openapi.json` fallback may
be selected instead. The controlled fallback fixture preserves its request trace,
but this is not a promise of identical document selection or generic coverage
between every option-off and privacy-selected run.

Selected REST, resource authorization or WordPress discovery still conflict with
secret-exposure review. Selecting both OpenAPI and SSRF-OAST also conflicts;
merely compiling SSRF-OAST does not. Preflight rejects those combinations before
secret acquisition, target traffic or output publication. See
[passive response secret-exposure review](passive-secret-exposure-review.md) for
the owned-fixture invocation, detector admission and privacy limitations.

## Current limitations

V1 does not parse YAML, convert Swagger 2.0, fetch external references, send
credentials, execute described methods, mutate parameters, upload content,
enumerate resources, test authorization, perform SSRF/OAST, or make
vulnerability claims. Catalog tags are metadata for future reviewed
capabilities and create no request obligation.

The separately enabled [REST read-only review](rest-readonly-review.md) is the
first consumer permitted to use this catalog for a network action. It still
requires explicit `--rest-review` in the same `web-review` invocation and only
receives a selection after this OpenAPI candidate/replay pair has committed an
identical semantic digest. It does not refetch the document or turn the full
catalog into actions.
