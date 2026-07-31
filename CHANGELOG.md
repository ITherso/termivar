# Changelog

All notable changes to Venom are recorded here. Releases use the categories from [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and follow Semantic Versioning.

## [Unreleased]

### Added

- Focused architecture, runner, scanner, plugin, Lua, distributed, anomaly, benchmark, profiling, and fuzzing documentation.
- Editable Draw.io architecture and crate dependency diagrams.
- Criterion microbenchmark target and cargo-fuzz harnesses.
- A `cargo-generate` plugin starter with a CI smoke test.
- Automated compile-time, binary-size, peak-memory, and Criterion workflow artifacts.
- Published workspace API documentation and a conservative release-readiness matrix.
- A dedicated feature-lifecycle reference, repository map, design principles, project badges, and explicit MIT license file.
- Root contribution and conduct policies, architecture decision records, and a repository-health reference.
- A `ScannerSdk` composition API, generated scanner starter, and `cargo xtask` maintenance commands.
- CodeQL web analysis, cargo-deny policy, scheduled parser fuzzing, and Rust 1.88 MSRV enforcement.

### Changed

- Replaced the long-form promotional README with a concise project guide.
- Standardized the pre-release version as `0.9.0-alpha`.
- Replaced absolute completion claims with lifecycle labels such as Beta, Preview, and Experimental.
- Moved shared event and finding contracts into `venom-core` while preserving scanner re-exports.
- Documented the plugin system as a source-level preview instead of implying dynamic discovery.
- Moved the editable Draw.io architecture source directly under `docs/` for discoverability.
- Made plugin API compatibility explicit with version negotiation and non-exhaustive public types.
- Added publishable version requirements to internal crate dependencies and removed the unused, unmaintained `rustls-pemfile` dependency.

### Fixed

- CLI version output now derives from the Cargo package version.

### Security

- Expanded the responsible disclosure policy, supported-version table, response targets, CVE process, and researcher credit policy.

## [0.9.0-alpha] - Unreleased

### Added

- Multi-phase asynchronous scanner.
- CLI, API, and proxy workspace crates.
- Optional plugin, Lua, distributed, anomaly, compliance, monitoring, and threat-intelligence modules.
- Structured event, persistence, and reporting models.

### Changed

- Public APIs remain unstable during the alpha period.

### Fixed

- CI compatibility and artifact action updates made during release preparation.

### Security

- This alpha has not completed an independent security audit and is not production-ready.

[Unreleased]: https://github.com/ITherso/venom/compare/v0.9.0-alpha...HEAD
[0.9.0-alpha]: https://github.com/ITherso/venom/releases/tag/v0.9.0-alpha
