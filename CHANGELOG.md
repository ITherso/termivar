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
- A standard deterministic web runtime with request, wall-time, response-byte, active-verification, same-action, and no-progress budgets.
- Typed experience dispositions and an explicit confirmed-negative verifier outcome.
- Evidence write-set receipts, post-commit error recovery, and before/after decision-session transition summaries.
- A Cargo-metadata and Rust-AST architecture gate for workspace and reasoning-module boundaries.
- A shared transport-neutral HTTP/API predicate vocabulary with normalized media/path observations and atomic paired-visibility contracts.
- An opt-in deterministic JSON/GraphQL fingerprint profile that turns host-paired visibility differences into review hypotheses without declaring vulnerabilities.
- Opt-in passive JSON response-format and GraphQL surface reasoning in `StandardWebDecisionRuntime`, with an installation receipt and no additional requests, executors, payloads, or planner actions.
- A runtime-owned, fail-closed facade for authorized paired API visibility ingestion and bounded resource review without changing HTTP, planner, experience, or decision-session state.
- `ApiVisibilityObservation`, a stable evidence-backed resource-scope relation, and atomic `KnowledgeBase::insert_evidence_with_relation` storage.
- Per-calibration evidence aggregation with an explicit one-contribution policy for standard API rules.
- A bounded, deterministic API visibility comparator that retains signatures instead of raw JSON response values.
- Typed API observation commit/reasoning receipts and relation-ID-ordered resource-scoped visibility review projections.
- Cursor-bounded API visibility review pages with a compiled scan ceiling and rejected-edge accounting.
- Subject/ontology revisions, bounded stale-snapshot retries, and atomic verifier state transitions for reasoning turns.
- Typed post-reasoning planning receipts with snapshot revisions and before/after session transitions.
- Transport-neutral executor failure kinds and immutable pre-commit receipts carrying the exact case, action, stage, origin, delay, resource limits, executor, and diagnostic.
- A host-owned HTTP request broker with atomic dispatch, active-verification, and retained-response-byte accounting shared by every built-in standard-runtime executor.
- A pinned `venom-core` public API compatibility command and dedicated CI gate against the `v0.9.0-alpha` source baseline.
- A `ScanContext` construction ADR and migration guide for the next Scanner Preview release.
- A virtual-workspace layout gate that rejects uncompiled Rust source at the repository root.
- An additive API visibility comparator-v2 envelope with versioned projection profiles, volatile-path filtering, explicit unordered-array semantics, and bounded redacted path explanations.
- Explicit documentation that standard-profile Bayesian inputs are deterministic policy likelihoods until empirical calibration metrics are published.

### Changed

- Replaced the long-form promotional README with a concise project guide.
- Standardized the pre-release version as `0.9.0-alpha`.
- Replaced absolute completion claims with lifecycle labels such as Beta, Preview, and Experimental.
- Moved shared event and finding contracts into `venom-core` while preserving scanner re-exports.
- Documented the plugin system as a source-level preview instead of implying dynamic discovery.
- Moved the editable Draw.io architecture source directly under `docs/` for discoverability.
- Made plugin API compatibility explicit with version negotiation and non-exhaustive public types.
- Added publishable version requirements to internal crate dependencies and removed the unused, unmaintained `rustls-pemfile` dependency.
- Made the runtime bootstrap receipt optional so a fail-closed budget can stop before initial network evidence is committed.
- Limited learned suppression to verified negative conclusions; target blocks, policy blocks, transport failures, executor failures, and inconclusive checks remain neutral.
- Classified built-in HTTP applicability, policy, transport, and internal executor failures without parsing diagnostics or turning operational failures into verifier outcomes.
- Separated semantic action attempts from actual transport dispatches; retries, timeouts, redirects, partial bodies, and pre-dispatch failures now report their real resource use.
- Moved standard web action identities into a transport-neutral catalog so verification no longer depends on HTTP execution or the `scanning` feature.
- Replaced duplicated HTTP and web predicate literals with the canonical `venom-core` vocabulary.
- Made API fingerprinting consume normalized media-type and path-segment evidence; the JSON rule identity is `api.response.json.media-type`.
- Limited each standard API calibration to one matching contribution to reduce retry-driven posterior inflation; existing profiles retain the default independent-contribution behavior.
- Rejected zero-reliability HTTP evidence policies so fixed rule likelihoods cannot promote a no-confidence observation.
- Made rule-produced hypothesis writes batch-atomic and preserved verifier-owned terminal states under the same knowledge-base lock.
- Made planning-session changes error-atomic and snapshot-CAS guarded; planner, command-construction, and stale-knowledge failures no longer partially halt or advance a session.
- `ScanContext` now owns an evidence-driven `KnowledgeBase`, is non-exhaustive, and exposes reasoning state through `knowledge()`. This is an intentional Preview source transition from the v0.9 struct-literal contract; consumers must use constructors and the accessor. `venom-scanner` remains outside the blocking compatibility gate until the next Preview baseline.
- Removed the uncompiled pre-workspace monolith and its obsolete completion/deployment reports; Git history remains the migration archive.
- Made repository-size metrics count only tracked Rust files owned by workspace packages and moved warning denial from global environment overrides into explicit Clippy/release gates.
- Replaced stale testing, observability, and code-quality claims with documentation of the currently compiled contracts and CI evidence.
- Centralized canonical rule-hypothesis identity generation while preserving existing IDs byte-for-byte.

### Fixed

- CLI version output now derives from the Cargo package version.
- Standard web action execution and verification mappings now fail during profile construction instead of panicking at runtime.

### Security

- Expanded the responsible disclosure policy, supported-version table, response targets, CVE process, and researcher credit policy.
- Added hard depth, node, field, and canonical-byte ceilings for API visibility evidence preparation without weakening decision-runner subject isolation.
- Bounded relation identifiers, endpoints, custom kinds, provenance sets, review cursors, and page cloning; redacted deterministic visibility fingerprints and cursors from `Debug` output.
- Bounded API observation producer names and review explanations, validating borrowed records before projection clones them.
- Made request and retained-body charges non-refundable at the transport boundary, including partial reads and executor cancellation, and preserved structured audit receipts for broker limit denials.
- Bound profiled comparison identities to comparator, canonicalization, and projection-policy metadata; redacted legacy view handles from `Debug` output and kept raw JSON values and clear observed paths out of comparator-v2 reports.

## [0.9.0-alpha] - 2026-07-31

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
