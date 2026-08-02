# API reference

Venom `0.9.0-alpha` is primarily a Rust library framework. The generated Rust API documentation is the source of truth for public types, traits, feature gates, and examples.

## Rust crates

| Crate | Purpose | Generated documentation |
| --- | --- | --- |
| `venom-core` | Transport-neutral events, findings, errors, configuration, models, and predicate vocabulary | [Open rustdoc](https://itherso.github.io/venom/rust/venom_core/) |
| `venom-scanner` | Scanner SDK, phase/plugin and execution contracts, deterministic reasoning profiles, and reports | [Open rustdoc](https://itherso.github.io/venom/rust/venom_scanner/) |
| `venom-api` | Experimental HTTP adapter | [Open rustdoc](https://itherso.github.io/venom/rust/venom_api/) |
| `venom-proxy` | HTTP/TLS proxy boundary | [Open rustdoc](https://itherso.github.io/venom/rust/venom_proxy/) |

The documentation workflow builds every public crate with all features and treats rustdoc warnings and broken intra-doc links as errors.

## Scanner SDK

Application authors should start with [`ScannerSdk`](https://itherso.github.io/venom/rust/venom_scanner/struct.ScannerSdk.html) and implement [`ScanPhase`](https://itherso.github.io/venom/rust/venom_scanner/trait.ScanPhase.html):

```rust
use venom_scanner::ScannerSdk;

let scanner = ScannerSdk::builder()
    // .phase(MyAuthorizedPhase)
    .build();
```

See [Scanner SDK](sdk.md) for a complete compiling phase and the generated starter project.

## Deterministic API reasoning

[`PredicateDescriptor`](https://itherso.github.io/venom/rust/venom_core/predicates/struct.PredicateDescriptor.html)
and the HTTP/API vocabulary in `venom-core` give evidence producers and
reasoning profiles one canonical predicate contract without replacing the open
`KnowledgePredicate` wire format.

[`StandardApiReasoning`](https://itherso.github.io/venom/rust/venom_scanner/api_reasoning/struct.StandardApiReasoning.html)
is an opt-in, transport-neutral profile. It produces explainable hypotheses for
JSON-compatible responses and GraphQL signals. The HTTP evidence boundary
normalizes a validated media-type essence, a JSON-compatible media-type flag,
and bounded URL path segments before the profile evaluates exact values. The
JSON rule has the stable identity `api.response.json.media-type`; it does not
search raw header or URL text.

A visibility-boundary hypothesis requires one host-created
[`ApiVisibilityComparison`](https://itherso.github.io/venom/rust/venom_core/predicates/struct.ApiVisibilityComparison.html)
that compares the same logical resource. Its recommended `to_observation()`
path returns an
[`ApiVisibilityObservation`](https://itherso.github.io/venom/rust/venom_core/predicates/struct.ApiVisibilityObservation.html)
containing the evidence and its stable, evidence-backed
`api.visibility.resource-scope` relation. Hosts can commit both records through
`KnowledgeBase::insert_evidence_with_relation`; identity and linkage conflicts
are checked before either record is written.

Hosts that start from authorized JSON values can use
[`ApiVisibilityComparator`](https://itherso.github.io/venom/rust/venom_scanner/api_evidence/struct.ApiVisibilityComparator.html)
to capture bounded, raw-value-free views and classify one explicit status,
field-shape, or resource-content dimension. The comparator never owns a network
client and retains signatures rather than response bodies. Its output remains
the core `ApiVisibilityComparison` contract.

For replayable projection and explanations, the additive profiled path accepts
an `ApiComparisonProfile` through `capture_profiled_view` and
`compare_profiled`. `ProfiledApiVisibilityComparison` keeps the legacy core
comparison nested inside an envelope containing comparator/canonicalization
versions, a content-derived projection-policy ID, the validated limits, and a
globally bounded `RedactedVisibilityDiff`. Selected and ignored path rules can
remove volatile fields; explicitly configured arrays can be canonicalized as
unordered. Explanations contain only domain-separated path, type, and scalar
value digests—never clear observed paths or raw response values.

[`ingest_api_visibility_observation`](https://itherso.github.io/venom/rust/venom_scanner/api_observation/fn.ingest_api_visibility_observation.html)
validates the caller's expected resource, atomically commits evidence plus its
scope relation, applies installed rules to the isolated comparison subject, and
returns typed commit/reasoning receipts. A post-commit reasoning failure carries
the observation commit receipt. Rule conclusions are themselves preflighted
and written as one hypothesis batch. Resource-oriented consumers can use
[`api_visibility_reviews_for_resource`](https://itherso.github.io/venom/rust/venom_scanner/api_observation/fn.api_visibility_reviews_for_resource.html)
without merging comparison subjects. Projection uses an explicit cursor query,
counts rejected relations against its scan budget, and enforces a compiled
per-page ceiling so a resource cannot trigger an unbounded clone or scan.
Producer components are capped at 256 bytes before ingestion commits; the
projection also checks that limit and the 1,024-byte boundary-rationale ceiling
while records are still borrowed from the knowledge store.
Each review exposes a computed `ApiVisibilityReviewDisposition`: equivalent
evidence is `NoDifferenceObserved`, a difference without the canonical standard
hypothesis is `UnresolvedDifference`, and only an exact weak/supported,
evidence-bound hypothesis is `AwaitHumanReview`. This disposition is not a
`DecisionLoopCommand`, is not serialized into the existing review wire shape,
and never declares broken access control or another vulnerability.
See [`ApiVisibilityReviewQuery`](https://itherso.github.io/venom/rust/venom_scanner/api_observation/struct.ApiVisibilityReviewQuery.html)
and [`ApiVisibilityReviewPage`](https://itherso.github.io/venom/rust/venom_scanner/api_observation/struct.ApiVisibilityReviewPage.html)
for cursor and page metadata. The legacy continuation is an opaque relation ID;
the host must keep it associated with the same resource. It is neither an
authenticated transport token nor a point-in-time snapshot under concurrent
inserts.

For host or transport boundaries, prefer
`api_visibility_reviews_for_resource_v2` with `ApiVisibilityReviewCursor`.
The v2 token binds its last relation to a domain-separated resource digest and
rejects accidental cross-resource reuse before the knowledge store is scanned.
It remains deterministic rather than authenticated: resource digests are
pseudonymous, may be dictionary-tested for low-entropy identifiers, and should
be wrapped in a host signature or MAC when exposed to an untrusted client.

Every policy likelihood in this API profile explicitly uses `MaxContributions(1)`
(constructed with `EvidenceAggregation::max_contributions(1)`), so repeated
matching observations do not keep increasing the posterior for the same
selector. This is local to the API profile. The rule engine and existing
profiles retain their default `Independent` contribution semantics.

The standard profile's fixed likelihoods are deterministic policy weights,
not empirically calibrated field probabilities. Until a labelled fixture
corpus publishes calibration metrics, consumers should present the posterior
as a ranking signal rather than a measured vulnerability probability.

The profile does not pair independent responses, perform network I/O, attest
producer truth, or verify a vulnerability; its visibility result is a review
signal.

The scanner test corpus contains deterministic golden comparisons for UI/API,
anonymous/authenticated, owner/unrelated-user, and read/write-capability
contexts. They exercise comparison, redacted explanation, ingestion, reasoning,
review disposition, and idempotent replay without issuing network requests.

Decision executors can report a typed `DecisionExecutionFailureKind` without
encoding policy or transport state in a string. Once the error crosses the
runner boundary, `DecisionExecutionFailureReceipt` preserves the exact request
context and resolved executor identity. Runner and standard-runtime errors
provide borrowed and consuming accessors for that receipt. These pre-commit
operational failures do not write evidence, synthesize verifier outcomes, or
penalize future planning through the Experience Store.

`RequestTimeout` is distinct from `TransportFailure`: the former means the
host-owned request/body deadline expired, while the latter covers other
network failures. Both remain neutral audit facts rather than verified target
outcomes.

After `analyze()` starts, an unexpected runtime error is wrapped in
`RunFailed`. Its `StandardWebDecisionFailureReceipt` retains the committed
bootstrap receipt, every earlier completed planning/outcome turn, and the
latest monotonic resource usage. Cause-specific accessors still expose the
current execution, evidence, or reasoning receipt. This is an in-process audit
boundary, not a persistence or crash-recovery guarantee.

The standard runtime's built-in HTTP executors share a host-owned request
broker. Request and active-verification counters advance only at the actual
dispatch boundary, while retained response chunks are charged immediately and
are not refunded by timeout, cancellation, or a later failure. Semantic action
attempts remain separate, so a cancelled scheduler delay does not masquerade
as network traffic. Broker limit denials are exposed through the run report's
structured limit and execution-failure receipts.

Hosts using `StandardWebDecisionRuntime` can opt into its passive API rules
with `enable_api_reasoning()`. The runtime reuses its existing normalized HTTP
evidence and exposes an optional installation receipt; it does not issue extra
requests or add API attack actions. An authorized host can also pass a typed
`ApiVisibilityObservation` to `runtime.ingest_api_visibility(...)`, then read a
bounded resource page with `runtime.api_visibility_reviews(...)`. These methods
preserve isolated comparison subjects and are neutral to request usage,
planning, experience, and decision-session state. They fail before any write
when API reasoning is disabled. `RuntimeApiVisibilityError` preserves a commit
receipt if reasoning fails after storage. Pairing, producer authentication,
authorization, and raw response handling remain host responsibilities.

The runnable
[`api_visibility_review`](https://github.com/ITherso/venom/blob/main/examples/api_visibility_review.rs)
example demonstrates the typed runtime workflow without performing network
I/O.

See [API visibility evidence](internals/api-evidence.md) for canonicalization
semantics, limits, receipts, replay behavior, and trust boundaries.

This reasoning surface is separate from the `venom-api` application transport.
Recognizing a GraphQL-shaped target does not expose or implement a GraphQL
server endpoint in Venom.

## Implemented HTTP surface

The current `venom-api` crate exposes one implemented route:

```http
GET /health

200 OK
Content-Type: text/plain

OK
```

`venom_api::router()` returns the Axum router containing this route. `venom_api::start_api()` is currently a startup hook and does **not** bind a listener. Authentication, scan-management endpoints, teams, exports, compliance endpoints, rate limits, webhooks, and GraphQL are not implemented contracts in this alpha release.

This explicit boundary prevents example payloads from being mistaken for shipped behavior. New HTTP endpoints require routing tests, request/response types, error semantics, authorization rules, and rustdoc examples before they are documented here.

## Stability

- Rust APIs are Preview during the `0.x` release line.
- Plugin compatibility follows the [Plugin API and SemVer policy](plugin-api-policy.md).
- Public enums and extensible records use non-exhaustive contracts where downstream exhaustive matching would restrict evolution.
- A stable HTTP API version has not been declared.

For release-level gaps and evidence, see [Repository health](repository-health.md).
