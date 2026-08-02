# ADR 0005: Share predicate vocabulary through venom-core

- Status: Accepted
- Date: 2026-08-02

## Context

Evidence producers and deterministic profiles previously reconstructed
`KnowledgePredicate` values from private string literals. The same HTTP
header, response, technology, and authentication concepts appeared in several
modules. A spelling or namespace change could therefore compile while causing
producers and consumers to stop matching.

The first JSON/GraphQL visibility profile also needs a stronger contract than
two independent observations. The rule engine evaluates all evidence for a
subject but does not establish that arbitrary UI, API, or principal records
refer to the same logical resource and authorized comparison. Joining those
records in a reasoning expression could manufacture a false authorization
boundary.

## Decision

Stable predicate descriptors and typed API comparison contracts live in
`venom-core`, inward of scanner execution and reasoning:

```text
PredicateDescriptor
    |
    +-- HttpEvidencePredicate
    +-- WebKnowledgePredicate
    +-- ApiEvidencePredicate
    +-- ApiKnowledgePredicate
```

`PredicateDescriptor` is a compile-time source descriptor that converts to the
existing owned `KnowledgePredicate`. It is not serialized itself, so persisted
predicates retain the established namespace-and-name wire representation.

The HTTP family provides fixed common predicates and an open response-header
constructor for names already validated and normalized by an HTTP producer.
Custom knowledge predicates remain supported; the vocabulary is not a closed
global registry.

API rules consume normalized HTTP evidence instead of substring matching raw
protocol values. The HTTP evidence boundary emits a validated lowercase
`http.response.media-type` essence, a Boolean
`http.response.media-type-json-compatible` classification, and bounded
non-empty `http.request.path-segment` observations. GraphQL media-type and
route rules use exact values from those contracts.

API visibility comparisons use `ApiVisibilityComparison`. The authorized host
must pair the same logical resource and opaque baseline/candidate contexts
before construction. The primary `to_observation()` path returns an
`ApiVisibilityObservation`: exactly one evidence record whose predicate
completely identifies surface, view pair, and difference/equivalence result,
plus one stable `api.visibility.resource-scope` relation to the host's opaque
resource `EntityId`. The evidence value identifies the comparison dimension,
and the relation cites that evidence as its sole provenance.

`KnowledgeBase::insert_evidence_with_relation()` preflights and writes both
records atomically and idempotently. It rejects a relation with different
provenance or a source other than the evidence subject, and neither half is
committed after a conflict. Destination entities may be registered later;
entity referential integrity remains eventual so independent producers are
not forced into one ingestion order.

The lower-level `to_evidence()` method is a detached path for advanced hosts.
Such a host must retain and persist an equivalent resource mapping itself.

The comparison subject and source correlation ID are derived from a
length-prefixed SHA-256 digest of the semantic identity: comparison ID,
surface, pair, result, dimension, baseline context, candidate context, and
resource scope. Opaque context and resource handles affect isolation without
exposing their raw values in emitted evidence. The evidence ID is derived from
that digest too, so replay cannot create independent Bayesian observations.

Observation time, producer provenance, and reliability are excluded from the
digest but remain immutable evidence fields. Reusing a semantic identity with
a different timestamp, component, or reliability therefore reuses the stable
evidence ID with different contents and is rejected as an identity conflict.
Zero reliability is rejected at construction; nonzero reliability is retained
as metadata. The current rule engine applies declared Bayesian likelihoods
without scaling them by that metadata.

Credentials, tokens, URLs, principal names, response values, and resource
names are forbidden comparison inputs.

`StandardApiReasoning` consumes this vocabulary as a transport-neutral profile.
It may infer response format, API surface, and reviewable visibility-boundary
hypotheses. It does not perform comparisons, network requests, planning,
verification, or vulnerability classification.

This contract assumes authorized evidence producers and knowledge-base write
authority. Shared predicate names and deterministic IDs are canonicalization
and replay controls, not cryptographic attestations. `ApiVisibilityComparison`
prevents accidental partial construction through its public API, but it cannot
stop a malicious writer from creating raw `Evidence` with a standard predicate.
Producer authentication and write authorization remain host responsibilities.

The digest creates a raw-value-free, pseudonymous identity, not a signature,
HMAC, producer attestation, or confidentiality guarantee. Predictable,
low-entropy handles may remain guessable through candidate testing and must not
be treated as secrets merely because their raw values are absent from evidence.

## Consequences

- Producers and reasoners refer to one source-level predicate identity.
- Existing serialized `KnowledgePredicate` data remains compatible.
- Dynamic normalized response headers and application-specific predicates
  remain possible.
- API rules depend on normalized media-type and path-segment evidence rather
  than raw `Content-Type` or URL substring matching.
- API comparison evidence cannot be assembled by combining unrelated UI, API,
  principal, resource, or turn records.
- Identical complete comparisons have stable subjects; changing any semantic
  identity field creates an isolated subject.
- Evidence and its resource-scope relation are stored as one atomic,
  idempotent bundle, preventing a half-written comparison claim.
- Destination entity registration remains eventually consistent with the
  already durable comparison-to-resource relation.
- Detached evidence production remains possible only when the host owns an
  equivalent durable resource mapping.
- Bounded aggregation in persisted rule definitions requires a reader that
  understands that wire field; hosts version rule payloads with the reasoning
  engine instead of loading them into pre-aggregation binaries.
- Reusing a semantic comparison identity with different immutable observation
  metadata fails explicitly instead of becoming another Bayesian observation.
- Nonzero reliability is auditable metadata but does not yet alter rule
  likelihoods.
- JSON representation evidence does not imply GraphQL.
- A visibility difference is a supported review hypothesis, not proof of IDOR,
  data exposure, or authorization bypass.
- The shared core gains typed names and validation but no HTTP client, parser,
  executor, planner, credential provider, or runtime policy.

Adding or changing a standard descriptor is now a public contract change and
requires producer, consumer, serialization, and documentation review.

## Alternatives considered

- Keep private predicate helper functions in each module: rejected because
  identical concepts could drift without a compiler error.
- Introduce a second serialized enum for every predicate: rejected because it
  would close extension families and require a storage migration.
- Infer visibility by joining independent UI and API observations: rejected
  because subject equality alone does not establish a common resource,
  principal pair, authorization, or collection turn.
- Put the vocabulary in `venom-scanner`: rejected because evidence producers
  and future reasoning crates need an inward, behavior-free contract.
- Treat standard predicate names as producer authentication: rejected because
  public identifiers cannot establish writer identity or authorization.
