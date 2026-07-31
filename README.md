# Venom

Venom is a modular Rust-based penetration testing framework focused on research and extensibility.

> Current release: **v0.9.0-alpha**. Venom is not production-ready. Use it only on systems you own or have explicit permission to test.

## Components

| Area | Status | Responsibility |
| --- | --- | --- |
| Core | Beta | Shared events, findings, configuration, models, and errors |
| Scanner | Beta | Runner, ordered phases, detection, and reporting |
| Plugins | Preview | Trait-based native extension API and registry |
| Distributed | Experimental | Worker, queue, and result aggregation APIs |
| Lua | Preview | Script execution boundary and lifecycle controls |
| Dashboard | Experimental | Scanner state projection and application views |
| Compliance | Preview | Optional audit and compliance models |

Lifecycle labels describe maturity, not completeness. Experimental and Preview APIs may change before a stable release.

## Architecture

```mermaid
flowchart TD
    Host["CLI / API / library host"] --> Runner
    Runner --> Pipeline["Scan Pipeline"]
    Pipeline --> Recon
    Pipeline --> Crawl
    Pipeline --> Directory
    Pipeline --> SQLi
    Pipeline --> XSS
    Pipeline --> SSRF
    Pipeline --> More["SSTI / LFI / XXE"]
    Pipeline --> Findings
    Plugins["Plugin Engine (Preview)"] --> Findings
    Runner --> Events["Event Bus"]
    Findings --> Reporter
    Events --> Observers["Dashboard / telemetry"]
```

The plugin engine is currently a parallel library extension path; merging it with the ordered phase pipeline is pre-stable work.

### Dependency direction

```mermaid
flowchart TD
    CLI[venom-cli] --> Scanner[venom-scanner]
    CLI --> API[venom-api]
    CLI --> Proxy[venom-proxy]
    API --> Scanner
    Scanner --> Core["venom-core<br/>Events / Findings / Errors / Models"]
    API --> Core
    Proxy --> Core
```

Dependencies point inward toward `venom-core`. Entry-point and product features must never become dependencies of lower-level crates. See [Architecture](docs/architecture.md) for module ownership, the editable Draw.io source, and the target product-layer split.

## Release readiness

| Check | Status | Evidence or gap |
| --- | --- | --- |
| Unit tests | Automated | Stable, beta, and nightly CI |
| Integration tests | Automated | Service-backed test job |
| Coverage | Automated | Tarpaulin report uploaded to Codecov |
| Compile time and binary size | Automated | Quality Metrics workflow artifact |
| Criterion microbenchmarks | Partial | Automated suite; endpoint baseline not published |
| Fuzzing | Partial | Parser targets exist; continuous campaign not operating |
| Mutation testing | Missing | Mutation score is not yet measured |
| External security audit | Missing | No independent audit has been completed |
| Performance report | Missing | Controlled CPU, RAM, throughput, and latency report pending |
| Stable API | Preview | Public contracts may change during alpha |

This table is intentionally conservative. Passing CI does not make the scanner production-ready.

## Quick start

Requirements: Rust stable, Git, and an authorized test target.

```bash
git clone https://github.com/ITherso/venom.git
cd venom
cargo test --workspace
cargo run -p venom-cli -- --help
```

Run an authorized scan:

```bash
cargo run -p venom-cli -- scan https://test.example
```

## Plugin SDK preview

Generate a standalone plugin starter with [`cargo-generate`](https://cargo-generate.github.io/cargo-generate/):

```bash
cargo install cargo-generate
cargo generate \
  --git https://github.com/ITherso/venom \
  --subfolder templates/venom-plugin \
  --name my-venom-plugin
```

The template implements `Plugin`, registers it in a test, and tracks Venom `main` during alpha. Pin a release tag or commit before publishing a third-party plugin. See [Plugin development](docs/plugin.md).

## Documentation

- [Architecture](docs/architecture.md)
- [Runner](docs/runner.md)
- [Scanner](docs/scanner.md)
- [Plugin development](docs/plugin.md)
- [Distributed execution](docs/distributed.md)
- [Lua](docs/lua.md)
- [Benchmarks and metrics](docs/benchmarks.md)
- [Security policy](SECURITY.md)
- [Documentation site](https://itherso.github.io/venom/)
- [Rust API documentation](https://itherso.github.io/venom/rust/venom_scanner/)

## Roadmap

- Converge native plugins and ordered scan phases behind one versioned execution contract.
- Move dashboard, distributed orchestration, and compliance into an optional product layer.
- Publish controlled performance, fuzzing, mutation, and independent audit results.

Roadmap items are intentions, not delivery guarantees. See [CHANGELOG.md](CHANGELOG.md) for shipped changes.

## Contributing

Read [Contributing](docs/CONTRIBUTING.md), keep dependencies pointed inward, and run formatting, clippy, and tests before opening a pull request. Report vulnerabilities privately according to [SECURITY.md](SECURITY.md).

Venom is licensed under the MIT License.
