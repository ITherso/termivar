# GraphQL surface review

GraphQL Surface Review V1 is a non-default, anonymous protocol review for an
explicit `web-review` scan. Both `venom-scanner` and `venom-cli` use the
`graphql-review` feature, and the operator must also pass `--graphql-review`.
The feature is absent from default builds; a feature-enabled CLI rejects the
flag without an explicit `web-review` profile or with `baseline`.

This runtime does not change `decision-scan/v1`, the default scan, or the
transport-neutral API reasoner. It adds one separately authorized scanner child
that uses the existing request broker, `RuntimeBudget`, cancellation, exact
origin, and redirect-disabled policy.

## Authority and endpoint selection

V1 is anonymous only. Its requests do not read or replay authorization values,
cookies, or other credential sources, even when the independent
authorization-context comparison is enabled in the same assessment.

At most one endpoint is selected deterministically. Candidate evidence is
ranked from an exact `application/graphql-response+json` media type, an exact
`graphql` path segment, or an exact-origin discovered reference. Because the
operator explicitly enabled the review, `/graphql` may be used as the bounded
V1 runtime fallback. The closed selector models `/api/graphql` for a future
explicit fallback policy, but this runtime does not probe both conventional
paths. Cross-origin, credential-bearing, fragment-bearing, query-bearing,
redirect-derived, or oversized candidates are rejected.

## Fixed request protocol

The strategy is `web.review.graphql.introspection-pair@1`. It sends up to
three anonymous `POST` requests with bounded JSON bodies to the selected
endpoint:

1. A scanner-owned control operation requests only an aliased `__typename`.
2. A distinct candidate requests its aliased `__typename` and `__schema` root
   metadata: `queryType { name }`, `mutationType { name }`, and
   `subscriptionType { name }`.
3. A replay uses a distinct scanner-owned operation name and alias while
   requesting the same bounded root metadata.

Operation names and aliases follow the GraphQL Name grammar and are entirely
scanner-owned. The request plan has a hard maximum of one selected endpoint,
three requests, and one active verification. It sends no variables, fragments,
directives, application fields, mutations, subscriptions, batches, alias
fan-out, or full schema enumeration.

The candidate and replay have different request-body digests and both must be
broker-dispatched. Locally cached candidate evidence cannot satisfy replay.

## Response and evidence contract

The bounded classifier distinguishes an exact control envelope, an exact
schema-root introspection envelope, structured GraphQL errors, generic JSON,
HTML, unsupported media, malformed or ambiguous JSON, truncation, and other
incomplete states. Checked ceilings cover retained response bytes, JSON depth,
nodes, object members, arrays, strings, and error count.

A correlated control envelope may produce one **GraphQL surface observed**
item. Anonymous root introspection is reported only when both the candidate and
distinct replay contain the exact expected aliases and equivalent bounded
schema-root structure. Public evidence retains only whether query, mutation,
and subscription roots are present; it does not retain their names, raw request
bodies, raw response bodies, or GraphQL error messages.

Both item types are `Informational` under `KnowledgeOnly` authority.
Introspection availability may be intentional and is not a vulnerability,
authorization bypass, schema leak, or data-exposure conclusion. Restricted
introspection can retain the endpoint observation but not the introspection
item. Generic JSON, HTML, a replay mismatch, ambiguous structure, truncation,
or exhausted parser limits cannot become a completed positive result.

## Deliberately absent in V1

Only bounded schema-root introspection is executable. GET queries, JSON-array
batching, full schema enumeration, detailed-error review, field suggestions,
alias amplification, depth/complexity testing, persisted queries, multipart
uploads, subscriptions, mutation/CSRF review, and authenticated GraphQL review
remain metadata-only. Catalog breadth creates no request obligation.

V1 performs no mutation, application-record enumeration, authorization test,
denial-of-service probe, WebSocket connection, external callback, redirect
follow, or cross-origin request.

## Conformance evidence

Sanitized `security-assessment-fixture/v1` cases exercise exact control and
introspection envelopes, restricted introspection, malformed and partial
responses, parser-limit incompleteness, generic JSON, and GraphQL-like HTML.
Batch-shaped and GET-query cases remain metadata-only. These fixtures prove
deterministic contract conformance; they do not establish empirical scanner
accuracy or real-world GraphQL coverage. See the
[scanner conformance corpus](scanner-conformance-corpus.md).
