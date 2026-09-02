# API reasoning internals

`StandardApiReasoning` is an opt-in, deterministic profile for JSON response
formats, GraphQL surface signals, and already-paired visibility comparisons.
It installs ontology definitions and Bayesian rules only. It performs no
network I/O and contains no planner, executor, credential, or verifier.

The separately feature-gated [GraphQL surface review](graphql-review.md) does
not move transport into this profile. Its scanner runtime owns endpoint
selection, up to three anonymous broker requests, bounded response
classification, replay, and informational projection; committed normalized
observations may then be consumed here like other HTTP/API evidence.

```text
HTTP evidence ----------------------+
                                    |
host-paired ApiVisibilityComparison +--> StandardApiReasoning
                                                 |
                                                 v
                                      Supported hypotheses
                                                 |
                                                 v
                                      host policy / later verifier
```

## Profile contents

The profile contains nine concepts, six axioms, and seven rules. Installation
preflights rules on a cloned registry and ontology definitions on prospective
state, so it is atomic and idempotent. It can be installed alongside
`StandardWebReasoning` in either order without sharing rule identities.

### Ontology

```text
json ----------------is_a----> api-response-format

json-http-api ----is_a----> api-interface ----is_a----> application-interface
graphql-api ------is_a----/

ui-api-visibility-boundary -------------------is_a----> visibility-boundary
authorization-context-visibility-boundary ----is_a----> visibility-boundary
```

The exact concepts are:

```text
application-interface
api-interface
api-response-format
json
json-http-api
graphql-api
visibility-boundary
ui-api-visibility-boundary
authorization-context-visibility-boundary
```

### Deterministic rules

| Rule ID | Input | Conclusion | Strength |
| --- | --- | --- | --- |
| `api.response.json.media-type` | `http.response.media-type-json-compatible = true` | `api.response-format = json` | Weak |
| `api.surface.graphql.response-media-type` | `http.response.media-type = application/graphql-response+json` | `api.surface.kind = graphql-api` | Strong |
| `api.surface.graphql.route` | `http.request.path-segment = graphql` | `api.surface.kind = graphql-api` | Weak |
| `api.surface.json.paired-comparison` | Atomic JSON visibility comparison, either result | `api.surface.kind = json-http-api` | Strong |
| `api.surface.graphql.paired-comparison` | Atomic GraphQL visibility comparison, either result | `api.surface.kind = graphql-api` | Strong |
| `api.visibility.ui-api.paired-difference` | Atomic JSON or GraphQL UI/API difference | `api.visibility.boundary = ui-api-visibility-boundary` | Weak |
| `api.visibility.authorization-context.paired-difference` | Atomic JSON or GraphQL authorization-context difference | `api.visibility.boundary = authorization-context-visibility-boundary` | Weak |

Rule conditions and Bayesian policy likelihoods use the shared typed
descriptors. The fixed values are deterministic reasoning weights, not
empirically calibrated real-world probabilities. Treat the resulting posterior
as a reproducible ranking signal until a labelled fixture corpus publishes
calibration metrics such as Brier score, reliability buckets, precision, and
recall.

The expression trace retains every candidate evidence ID that matched the
condition. Each API rule explicitly selects at most one deterministic Bayesian
contribution (`MaxContributions(1)`), preferring reliability, then observation
time, then stable evidence ID. The selected ID appears in the resulting belief
trail, so both the candidate set and posterior input remain explainable and
replayable. Other profiles keep the default `Independent` aggregation semantics
unless they opt into a bound themselves.

Persisted rule definitions that contain bounded aggregation must be loaded only
by an engine version that understands that field. The current reader rejects
unknown or misspelled likelihood fields, while a pre-aggregation binary cannot
retroactively enforce that guarantee. Deployments therefore version rule
payloads and reasoning-engine binaries together rather than downgrading a
bounded profile into an older reader.

## Conservative interpretation

JSON is a response representation, not a GraphQL detector. The HTTP producer
first validates and normalizes a media-type essence, then emits
`http.response.media-type-json-compatible = true` for `json` and `+json`
subtypes. That signal creates only the weak `api.response-format = json`
hypothesis. GraphQL requires the exact normalized
`application/graphql-response+json` media type, an exact `graphql` path-segment
signal, or an explicit host-paired GraphQL comparison. The reasoner does not
search raw `Content-Type` or URL strings.

An explicitly enabled GraphQL review adds stronger correlated protocol
evidence, but its conclusions remain conservative. A complete aliased
`__typename` control can establish an observed GraphQL surface. Anonymous
schema-root introspection is retained only after a distinct candidate and
replay both satisfy the bounded response contract. Neither observation is a
vulnerability or authorization claim, and the reasoner still cannot dispatch
the requests or raise either item above `Informational` / `KnowledgeOnly`.

A visibility difference is also not a vulnerability. UI/API differences may
be intentional product behavior, and authorization-context differences often
show that access control is working. The profile records a weak, supported
boundary hypothesis that deserves policy-aware review. It never emits IDOR,
data-leak, authorization-bypass, `Confirmed`, or `Rejected` claims.

An `Equivalent` comparison can still establish the declared API surface, but
it does not create a visibility-boundary hypothesis or a negative security
claim. Negative and confirmed lifecycle states belong to a future explicit
verifier operating under host authorization.

## Comparison isolation

Every `ApiVisibilityComparison` produces one evidence record on a pseudonymous
comparison subject. The digest includes the opaque comparison, context, and
resource-scope handles together with surface, pair, result, and dimension. This
prevents observations from different principals, resources, dimensions, or
turns from entering the same subject snapshot.

The digest excludes observation time, producer provenance, and reliability;
these are immutable evidence metadata rather than semantic comparison
identity. The deterministic evidence ID still makes exact replay strict. If a
producer recreates the same semantic identity with a different timestamp,
component, or reliability, insertion fails with an evidence identity conflict
instead of counting it as a second Bayesian observation.

The primary `to_observation()` path also returns a stable
`api.visibility.resource-scope` relation from that comparison subject to the
host-provided opaque resource `EntityId`. The relation is backed only by the
comparison evidence. Writing both records through
`KnowledgeBase::insert_evidence_with_relation()` is atomic and idempotent, so a
failed identity check cannot leave a detached comparison claim or a relation
without its observation.

The resource entity itself may be registered later. Knowledge-base entity
referential integrity is eventual by design so independent producers can write
in either order; the comparison-to-resource edge is queryable in the supplied
`KnowledgeBase` as soon as the bundle is accepted. Persisting it across process
failure remains a host responsibility.

`to_evidence()` is the detached, advanced alternative. A host using it must
retain and persist an equivalent resource mapping outside this bundle; the
reasoning profile cannot recover that association from the raw-value-free
evidence payload.

The profile never attempts an expression such as:

```text
UI record exists AND API record exists
```

Such an expression would be unsound because independent records do not prove a
shared principal or resource context. Only the atomic comparison predicates
can activate the visibility rules.

Both `ApiVisibilityComparison` conversion paths and
`HttpEvidencePolicy::with_reliability()` reject zero reliability. Any nonzero
reliability is retained on evidence for audit and future policy. The current
rule engine does not multiply or otherwise scale its fixed Bayesian likelihoods
by that metadata, so a lower nonzero reliability does not currently reduce the
rule's posterior contribution.

## Trust boundary

`StandardApiReasoning` assumes an authorized evidence-write boundary.
`ApiVisibilityComparison` validates the canonical host-paired contract, but
standard predicate names are public knowledge-base identifiers rather than
cryptographic attestations. A writer with direct knowledge-base access can
construct matching `Evidence` without using the comparison constructor.

The comparison digest is a pseudonymous deterministic identity, not an HMAC,
signature, or producer attestation. Low-entropy handles may be guessable even
when their raw values do not appear in evidence. It must not be treated as a
confidentiality or authentication mechanism.

Hosts must therefore authenticate producers and restrict write authority. The
profile guarantees deterministic interpretation of accepted evidence; it does
not prove who produced a record or whether a malicious writer described a real
comparison.

## Knowledge writes

Reasoning writes hypotheses, not facts. The comparison is already an immutable
observation, while surface and boundary interpretations remain Bayesian
claims. This avoids presenting a time- or context-dependent visibility result
as a permanent endpoint fact.

Installation writes only ontology definitions and rule definitions. Applying
the rule engine to a subject may write supported hypotheses, but it cannot
execute a request, choose an action, verify a result, or change a hypothesis to
`Confirmed` or `Rejected`.

## Evidence intake

Hosts may construct a comparison directly or use the bounded
`ApiVisibilityComparator` described in [API visibility evidence](api-evidence.md).
`ingest_api_visibility_observation` is the preferred host-facing write path: it
checks the expected resource, atomically stores the observation and relation,
then applies installed rules to the isolated comparison subject. Its typed
receipt distinguishes pre-commit rejection from post-commit reasoning failure.
The decision runner remains single-subject and is not used for paired ingress.

## Usage

```rust
use venom_scanner::{KnowledgeBase, RuleEngine, StandardApiReasoning};

let knowledge = KnowledgeBase::new();
let mut rules = RuleEngine::new();

StandardApiReasoning::new()?.install(&knowledge, &mut rules)?;
```

An authorized producer may then construct an `ApiVisibilityComparison`, call
`to_observation()`, and pass the bundle to
`ingest_api_visibility_observation`. That boundary atomically stores its
evidence and resource-scope relation before applying the rule engine to the
comparison subject. Supplying comparison inputs and deciding what subsequent
review is permitted remain host responsibilities.
