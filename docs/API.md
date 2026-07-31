# API reference

Venom `0.9.0-alpha` is primarily a Rust library framework. The generated Rust API documentation is the source of truth for public types, traits, feature gates, and examples.

## Rust crates

| Crate | Purpose | Generated documentation |
| --- | --- | --- |
| `venom-core` | Transport-neutral events, findings, errors, configuration, and models | [Open rustdoc](https://itherso.github.io/venom/rust/venom_core/) |
| `venom-scanner` | Scanner SDK, phase and plugin contracts, runner, events, and reports | [Open rustdoc](https://itherso.github.io/venom/rust/venom_scanner/) |
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
