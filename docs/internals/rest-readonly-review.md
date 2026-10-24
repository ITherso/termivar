# REST read-only review

REST Read-Only Review V1 is an explicitly enabled native capability inside the
existing `WebAssessmentRuntime`. It is excluded from default scanner and CLI
features. The operator must compile `rest-review` and pass all of:

```text
termivar scan TARGET --profile web-review --openapi-review --rest-review
```

The CLI rejects `--rest-review` outside explicit `web-review` and rejects it
without the same-run `--openapi-review` option before network I/O. REST review
does not fetch another contract. It becomes eligible only after the current
assessment has committed a complete OpenAPI candidate and replay with the same
semantic document identity.

## Selection boundary

The replay-stable OpenAPI catalog may constrain selection; it does not grant
arbitrary execution authority. V1 deterministically selects at most one
operation. The operation must be an anonymous, bodyless, exact-origin `GET`
with no required path, query, header, or cookie parameter. It must require no
authentication, API key, OAuth context, cookie, request body, example/default
materialization, templated server expansion, or cross-origin server authority.

When several operations qualify, selection favors an exact-origin or relative
server, documented JSON-compatible success media, a non-deprecated operation,
the shortest canonical path, and finally stable operation identity. That
stable identity is a deterministic tie-breaker, never authority. The selected
target is retained internally as an opaque identity; reports do not publish
response values or bulk paths.

## Execution and evidence

The one native action sends exactly two requests on its complete path:

1. an anonymous, bodyless `GET` candidate;
2. an exact replay to the same canonical URL with a distinct scanner-owned leg
   identity.

The fixed leg identities are `rest-review:candidate` and
`rest-review:replay`. They stay correlated to one parent verification case so
the action remains one native capability and one completeness lifecycle.

Both requests use the parent assessment's exact-origin authority, shared
broker, `RuntimeBudget`, cancellation, deadline, response accounting, defense
evidence, registry, completeness lifecycle, and final report. Redirects and
implicit retries remain disabled. The action consumes at most one selected
operation, two requests, and one logical active verification.

For complete JSON-compatible responses, the existing raw-value-free API
comparison machinery evaluates `Status`, `Fields`, and value-sensitive
`Resources`. A positive observation requires two complete, non-truncated 2xx
responses with the same status and equivalent field/resource fingerprints,
plus exact operation correlation and reconciled accounting. A redirect,
authentication or authorization response, missing route, rate limit, defense
interference, server error, unsupported media, truncation, cancellation,
budget exhaustion, or replay mismatch produces no positive item.

The capability `api.rest-readonly-surface-observed@1` is titled “REST operation
surface observed.” Its maximum disposition is `Informational` and its authority
is `KnowledgeOnly`. It is reachability evidence for one safely selected read
surface, not a vulnerability, authorization, or sensitive-data claim.

## Explicit value-free privacy composition

When also compiled with `secret-exposure-review`, the same assessment may
explicitly select it without changing the REST operation selector:

```console
termivar scan http://127.0.0.1:<fixture-port>/ \
  --profile web-review --openapi-review --rest-review --secret-exposure-review \
  --report-dir assessment-rest-value-free
```

This example requires an already running owned fixture and its actual port.
The existing anonymous candidate/replay GETs are separately planned review
work, not inputs to the passive detector. They retain their two-request and
one-active parent allowance; the privacy composition adds no request or budget.
Full value-sensitive `Status`, `Fields` and `Resources` replay equality still
runs privately. A same-shape response with different scalar values is not a
stable replay merely because its counts agree.

In this selected mode, received responses use exact committed value-free
lineage instead of public body/view response digests. The catalogue-derived
operation and target identities are withheld: the existing audit omits
`selected_operation_identity`, and a qualifying informational item uses the
coarse `assessment_subject` target. The actual request URL remains private
transport/provenance data. This is not cross-run resource equality or a claim
that every private knowledge/Debug buffer is URL-free.

Strict central and feature-independent saved readers accept the omitted
operation identity only under a valid selected privacy audit. A historical
positive audit without privacy selection still requires its identity. No
schema or comparison authority is enlarged. Option-off digest, identity,
selection and request behavior remain unchanged. The ordinary S04 body-derived
discovery suppression still applies, so controlled fallback-fixture trace
equality is not a promise that every application has identical off/on
discovery. See [Passive response secret-exposure review](passive-secret-exposure-review.md).

## Deliberate exclusions

V1 materializes no parameter value, generates no request body, sends no
credential or cookie, and executes no write method. It does not enumerate
routes, mutate IDs, follow OpenAPI server URLs across origins, or chain the
selected operation into SQL, SSTI, XSS, authorization, SSRF, or upload review.
There is no `RestScanner`, `RestRuntime`, direct client, detached pass, or
REST-only report: the capability remains one bounded child in the single
assessment runtime.
