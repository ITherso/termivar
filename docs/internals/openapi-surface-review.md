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
