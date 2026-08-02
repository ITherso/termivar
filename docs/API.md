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

Every calibration in this API profile explicitly uses `MaxContributions(1)`
(constructed with `EvidenceAggregation::max_contributions(1)`), so repeated
matching observations do not keep increasing the posterior for the same
selector. This is local to the API profile. The rule engine and existing
profiles retain their default `Independent` contribution semantics.

The profile does not pair independent responses, perform network I/O, attest
producer truth, or verify a vulnerability; its visibility result is a review
signal.

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
