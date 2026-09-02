# Shared predicate vocabulary

Venom's evidence producers and deterministic reasoners share one typed
predicate vocabulary from `venom-core`. The vocabulary prevents a producer and
consumer from silently assigning different meanings to duplicated string
literals while retaining the existing `KnowledgePredicate` wire format.

## Descriptor contract

`PredicateDescriptor` is a static, validated description of a predicate. It
contains the namespace, name, and dotted diagnostic form and converts to the
canonical owned `KnowledgePredicate` through `into_knowledge()` or `Into`.

Descriptors deliberately do not implement Serde. Persisted evidence, facts,
hypotheses, expressions, and rules continue to encode predicates as:

```json
{
  "namespace": "http.response",
  "name": "status"
}
```

The vocabulary is therefore a source-level contract, not a second storage
schema. Custom `KnowledgePredicate` values remain supported.

## Predicate families

### `HttpEvidencePredicate`

This family describes raw observations made by HTTP evidence producers. Its
fixed descriptors cover request method and URL, response status and metadata,
bounded body observations, timing, cookie names, common response headers, and
normalized rate-limit signals.

API reasoning consumes normalized protocol observations instead of searching
raw header or URL strings:

| Predicate | Producer guarantee |
| --- | --- |
| `http.response.media-type` | One syntactically valid, lowercase media-type essence with parameters removed |
| `http.response.media-type-json-compatible` | Boolean indicating the validated `json` subtype or a `+json` structured suffix |
| `http.request.path-segment` | One bounded, non-empty URL path segment |

Invalid or ambiguous media types do not produce normalized media-type
evidence. The API profile compares these values exactly; it does not infer
GraphQL from a substring in raw `Content-Type` or request-URL evidence.
`HttpEvidencePolicy::with_reliability()` also rejects
`ConfidenceScore::NONE`: the current deterministic rules use configured
likelihoods and must not turn a zero-confidence producer signal into Bayesian
support.

The opt-in [GraphQL surface review](graphql-review.md) uses these same
normalized media/path observations when ranking one exact-origin endpoint. Its
operation correlation and bounded response-envelope classifier remain runtime
contracts rather than new stringly predicates. Generic JSON therefore still
cannot become GraphQL merely because the active review was enabled.

The response-header namespace remains open. Producers that validate and
lowercase a header name may use
`HttpEvidencePredicate::response_header(name)` instead of adding a constant for
every possible header. Common contracts such as `Content-Type`, `Server`,
`Allow`, `WWW-Authenticate`, and `X-Powered-By` have fixed descriptors.

### `WebKnowledgePredicate`

This family names conclusions produced by standard web reasoning:

```text
technology.web-server
technology.language
technology.framework
technology.ui-framework
authentication.mechanism
```

Evidence predicates and knowledge predicates are intentionally separate. For
example, `http.header.server` is an immutable observation, while
`technology.web-server` is an inferred claim.

### `ApiEvidencePredicate`

API visibility evidence is classified by one of eight atomic predicates:

| Surface | Compared views | Result | Dotted predicate |
| --- | --- | --- | --- |
| JSON HTTP | UI/API | Different | `api.visibility.json.ui-api.difference` |
| JSON HTTP | UI/API | Equivalent | `api.visibility.json.ui-api.equivalent` |
| JSON HTTP | Authorization contexts | Different | `api.visibility.json.authorization-context.difference` |
| JSON HTTP | Authorization contexts | Equivalent | `api.visibility.json.authorization-context.equivalent` |
| GraphQL | UI/API | Different | `api.visibility.graphql.ui-api.difference` |
| GraphQL | UI/API | Equivalent | `api.visibility.graphql.ui-api.equivalent` |
| GraphQL | Authorization contexts | Different | `api.visibility.graphql.authorization-context.difference` |
| GraphQL | Authorization contexts | Equivalent | `api.visibility.graphql.authorization-context.equivalent` |

`ApiEvidencePredicate::visibility(surface, pair, result)` selects the complete
classification without reconstructing a predicate string.

### `ApiKnowledgePredicate`

Standard API reasoning writes only these claim predicates:

| Predicate | Meaning |
| --- | --- |
| `api.response-format` | Observed representation, currently `json` |
| `api.surface.kind` | Inferred API family: `json-http-api` or `graphql-api` |
| `api.visibility.boundary` | Reviewable UI/API or authorization-context visibility boundary |

The typed values `ApiResponseFormat`, `ApiSurfaceKind`, and
`ApiVisibilityBoundaryKind` provide their stable values. A response format is
not an API-family conclusion: JSON content alone does not establish GraphQL or
even prove that a generic JSON response is an API.

## Atomic visibility comparisons

`ApiVisibilityComparison` represents one comparison already performed by an
authorized host component. It records:

- an opaque comparison ID;
- the JSON HTTP or GraphQL surface;
- UI/API or authorization-context pairing;
- `Different` or `Equivalent` result;
- resources, fields, or status dimension;
- opaque baseline, candidate, and resource-scope handles.
- the host observation timestamp used for exact replay.

The constructor rejects empty handles and bounds every opaque value to 256
bytes. These fields are handles, not storage for credentials, tokens, URLs,
principal names, response values, or resource names.

`to_observation()` is the normal bundled-storage path. It returns an
`ApiVisibilityObservation` containing exactly one immutable evidence record
and one stable evidence-backed graph relation. The result is encoded in the
evidence predicate, the measured dimension is its value, and its kind is
`api.visibility-comparison`.

The relation starts at the comparison subject, ends at the host's opaque
resource-scope `EntityId`, and uses the custom kind
`api.visibility.resource-scope`. Its deterministic
`api-comparison-scope:<digest>` identity and sole provenance ID are derived
from the same comparison evidence. `ApiVisibilityObservation::into_parts()`
returns those two records for storage.

A length-prefixed SHA-256 digest of the semantic identity fields becomes both
the `api-comparison:<digest>` subject and the source correlation ID, and the
same digest also produces deterministic evidence and relation IDs. Those
fields are comparison ID, surface, pair, result, dimension, baseline context,
candidate context, and resource scope.

Observation time, producer provenance, and reliability are deliberately not
part of that digest. Exact replay must nevertheless preserve them because they
remain part of the immutable `Evidence` record. Reconstructing the same
semantic identity with a different `observed_at_ms`, component, or reliability
reuses the deterministic evidence ID with different contents and the knowledge
base rejects it as an identity conflict. Changing a context, scope, surface,
result, or dimension instead creates a new semantic identity and isolated
subject.

`KnowledgeBase::insert_evidence_with_relation()` writes the observation bundle
atomically and idempotently. It requires the relation to originate at the
evidence subject and to cite exactly that evidence ID. Evidence and relation
identity conflicts are checked before either record or index changes, so the
knowledge base cannot retain an evidence-only or relation-only half after a
failed bundle write.

The destination `KnowledgeEntity` may be registered before or after this
bundle. Entity referential integrity is intentionally eventual because
independent discovery producers may write in either order. The graph edge is
present immediately in the supplied `KnowledgeBase`, so the comparison claim
still has a stable resource-scope association even while the destination entity
record has not yet arrived. Crash persistence remains a host responsibility.

`to_evidence()` remains an advanced detached path. It emits only the immutable
evidence; callers choosing it must persist an equivalent comparison-to-resource
mapping themselves. Integrations that need the built-in association should
prefer `to_observation()` and atomic knowledge-base bundle insertion, then
persist the result through their host-owned storage boundary.

Both conversion paths reject `ConfidenceScore::NONE`. A nonzero reliability is
preserved as source metadata on the emitted evidence and relation. The current
Bayesian rule engine applies the profile's declared likelihoods directly; it
does not scale them by `Evidence::reliability()`. Reliability-aware calibration
is a separate future policy, not an implied behavior of this vocabulary.

This one-record rule is a correctness boundary. The reasoning engine must not
join independent UI observations, API observations, or principal responses:
it has no authority to prove that they describe the same resource or
authorization context. The host must establish that equivalence before it
constructs `ApiVisibilityComparison`.

`venom-scanner::ApiVisibilityComparator` is an optional pure producer for hosts
that already hold two authorized `serde_json::Value` views. It canonicalizes
them under explicit hard ceilings and emits this same comparison contract. It
does not authorize, fetch, retain, or independently pair responses. See
[API visibility evidence](api-evidence.md).

## Trust boundary

Typed descriptors and `ApiVisibilityComparison` provide canonical names,
validation, raw-value-free evidence payloads, pseudonymous comparison
identity, and one-record comparison semantics. They are not cryptographic
attestations. Predicate names in the public knowledge base can be constructed
directly, so the system assumes that only authorized producers have
evidence-write authority.

The SHA-256 digest is not a signature or HMAC and does not authenticate its
inputs. It also is not a confidentiality boundary for predictable,
low-entropy handles: an observer may be able to test guesses. Hosts should use
suitably opaque, non-secret handles and must not treat the digest as proof of
producer identity or authorization.

A malicious or compromised writer could forge a standardized API predicate or
bypass the comparison constructor by creating `Evidence` directly. Hosts must
enforce producer identity, authorization, and write access outside this
vocabulary. Reasoning treats an accepted record as coming from that trusted
write boundary; it does not authenticate the observation merely because its
predicate has a standard name.

## Ownership boundary

The shared vocabulary lives in `venom-core` because both producers and
reasoners depend inward on it. It defines names, typed values, validation, and
raw-value-free comparison evidence. It does not contain an HTTP client, parser,
planner, verifier, credential provider, or execution policy.

GraphQL review keeps request dispatch and response classification in the
feature-gated scanner runtime. The predicate vocabulary neither selects an
endpoint nor authorizes a request.
