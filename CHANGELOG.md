# Changelog

All notable changes to Venom are recorded here. Releases use the categories from [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and follow Semantic Versioning.

## [Unreleased]

### Added

- A security-hardened Phase 1 `semantic` entity extraction layer (`EntityExtractor`, `SemanticEntity`, `SemanticEntityType`, `AuthArtifactKind`). Converts raw scanner `Evidence` into strongly-typed, canonical semantic entities without mutating planner state or forcing intrinsic Plane properties onto entities. Includes strict redaction guarantees for sensitive header values (`[REDACTED]`) and auth credentials (SHA-256 fingerprinting with domain separation `venom:auth-artifact:v1:<kind>:<raw>`), `Domain` vs `IpAddress` separation, `v1` canonical entity identifiers, and order-independent `BTreeSet` attribute merging.

- A deterministic, public-API demonstration test (`defense_aware_planning_demo`) that shows the defense-aware planning arc end to end for one fixed scenario: the enforcement-off plan, the side-effect-free shadow delta with supporting evidence and stable explanation codes, and the enforcement-on plan with distinct `DefenseSuppressed` exclusions. It asserts the guarantees — disabled leaves the plan untouched, shadow and enforcement agree on what to suppress, and a suppressed action never becomes a plan step so it never reaches an executor — and renders a readable side-by-side summary.
- A default-off `defense::enforcement` layer (`DefensePlanningPolicy`, off by default) that lets observed defense change the real plan only when explicitly enabled. `defense_aware_plan` reuses the shadow layer to decide suppressions and applies them through a new, distinct `ExclusionReason::DefenseSuppressed` so defense suppression never conflates with adaptive/operator `PolicySuppressed`. While disabled it produces the planner's plan byte for byte; a defense-suppressed action never becomes a plan step, so it never reaches an executor. Defense still never adds an action or raises utility (graded numeric penalties are deferred).
- A side-effect-free `defense::shadow_planning` layer that computes a defense-aware shadow plan and an explainable delta against the current plan through the planner's read-only `plan_snapshot_with_suppressed` seam. It issues no request and mutates no planner, runtime, knowledge, or experience state, and never reorders the real plan. Defense evidence never adds an action or raises utility; it only allows, deprioritizes, or suppresses existing candidates via a single monotonic mapping keyed on `DefenseResponse` and a typed `DefenseInteractionClass` (no string matching). Recommendations reuse `defense::policy::recommend`, aggregated per resource with corroboration (a single standing block is downgraded), scoped to the exact resource, with a stable-coded delta referencing supporting evidence.
- A projection-only `defense::projection` adapter that turns observed defense state and control/candidate transitions into provenance-carrying `venom_core::Evidence` under the `defense.*` predicate namespace, deterministically and idempotently. It emits observations only — never a `Fact` or hypothesis, so a single block or a bare status never becomes a confirmed-WAF claim — and returns nothing for a non-response, so timeouts and connection failures are never learned as defense. Evidence ids are a versioned SHA-256 digest of the canonical projection identity (`defense/<sha256>`), so raw resource, receipt, correlation, and producer values stay in their provenance fields and never leak into an id. It selects no payload, issues no request, and does not touch the planner, executor, or runtime configuration.
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
- A host-owned HTTP request broker with atomic dispatch and active-verification accounting shared by every built-in standard-runtime executor.
- A pinned `venom-core` public API compatibility command and dedicated CI gate against the `v0.9.0-alpha` source baseline.
- A `ScanContext` construction ADR and migration guide for the next Scanner Preview release.
- A virtual-workspace layout gate that rejects uncompiled Rust source at the repository root.
- An additive, versioned API visibility comparator envelope with projection profiles, volatile-path filtering, explicit unordered-array semantics, and bounded redacted path explanations.
- Explicit documentation that standard-profile Bayesian inputs are deterministic policy likelihoods until empirical calibration metrics are published.
- Host-owned standard-runtime cancellation with a distinct terminal reason and an auditable receipt for evidence committed before verification was skipped.
- A versioned API review cursor that binds continuation state to a pseudonymous resource digest and rejects cross-resource reuse before scanning.
- A process-local runtime failure receipt that preserves committed bootstrap work, completed turns, and monotonic usage across later execution, accounting, reasoning, or verification errors.
- A transport-ownership ADR and architecture invariant that keeps raw network capabilities out of bounded standard-runtime consumers and tracks the explicit legacy phase I/O inventory.
- Planner-selected, versioned payload-strategy reference and derivation contracts with hard byte limits, redacted audit receipts, and fail-closed executor support negotiation; no production payload capability is enabled by this plumbing.
- A first native production payload strategy, `http.header.control-pair@1`, deriving a deterministic control/candidate pair for a single benign request header, plus a `standard_payload_strategies` registry builder and repeat/concurrency conformance tests.
- A second native production payload strategy, `api.authorization.context-pair@1`, deriving an anonymous (empty, header-omitting) control and an authorized candidate credential to measure the same resource's visibility difference; registered in `standard_payload_strategies` with repeat/concurrency conformance tests.
- An observation-only defensive-posture layer (the `defense` module) that fingerprints WAF and edge products with robust case-insensitive header, substring, and cookie matching, and projects a bounded, deterministic `DefenseState` (status class, challenge and rate-limit markers, product fingerprint, and overall posture) from one response. It selects no payload or evasion technique, and drops the brittle `Server: AmazonS3` → AWS WAF inference in favor of confidence-graded signals.
- A deterministic `DefenseTransition` that compares a control and a candidate `DefenseState` into typed defense-transition evidence (posture shift, newly-blocking/newly-rate-limited flags, status and fingerprint changes, and a `NoChange`/`DefenseEngaged`/`DefenseRelaxed`/`DefenseReconfigured` summary) for a planner to weigh; it makes no payload decision.
- A deterministic `defense::policy::recommend` escalation policy that maps observed defense evidence to a restrictiveness-ordered `DefenseResponse` (`Proceed`, `Observe`, `Backoff`, `Reconsider`, `Halt`), attributing a candidate-provoked block to the candidate request; it recommends only and selects no payload.
- Relocated the legacy WAF payload encoders and evasion enum into pure, behavior-equivalent `payload_strategies::encoding` and `payload_strategies::normalization` building blocks, correcting the `EvisionTechnique`/`WhespaceVariation` misspellings to `EvasionTechnique`/`WhitespaceVariation`. The corrected enum stays source- and serialization-compatible (a `From<waf::EvisionTechnique>` conversion and a serde alias for the old spelling), and `encode_into_artifact` routes encoded output through the bounded, redacted payload-artifact contract. Nothing is registered as a runtime strategy, so no scan behavior changes.
- A strategy-aware `HttpEvidenceExecutor` payload binding (`HttpHeaderPayloadBinding`) that resolves the planner-selected strategy, derives the stage-appropriate control or candidate artifact, applies it through validated `HttpProbe` header construction, and dispatches it over the host request broker; opt-in per executor, with no standard profile enabling it by default.
- A `StandardWebDecisionRuntimeBuilder::with_payload_binding` opt-in that attaches a payload binding to the bounded runtime's metered `http.evidence` executor, so derived control and candidate dispatches are charged through the runtime's request accounting like any other request.
- Cumulative request-body accounting at the host-owned broker boundary, including atomic concurrent-limit enforcement and rejection of unmetered bodies.
- Full transport-delivered response-chunk accounting while preserving a separately bounded retained evidence prefix.
- A comparator-v3 visibility-explanation disposition that distinguishes equivalence, bounded path summaries, and differences without representable path summaries while preserving explicit replay metadata.
- A host-triggered, single-use JSON authorization-context differential workflow that moves two broker-backed views through Comparator V3, atomic observation ingestion, and exact human-review projection without becoming a planner action or vulnerability verdict.
- Pinned golden API-authorization replay metadata and broker-backed runtime coverage for anonymous/member, owner/unrelated-user, and read/write-capability context pairs.
- Bounded, raw-target-free transport dispatch receipts with ordered per-attempt byte accounting and typed completion, failure, timeout, response-limit, and cancellation outcomes.
- A context-owned legacy discovery authority shared by crawler, optional directory, and parameter phases, with exact-origin redirect-disabled transport plus configurable depth, page, request, request-timeout, wall-time, cumulative-body, and per-response-body limits.

### Changed

- Made `venom scan` the default bounded deterministic runtime, retained `decision-scan` as a deprecated compatibility alias with the unchanged `decision-scan/v1` wire contract, and moved the historical mixed-authority heuristic runner behind the non-default `legacy-scanner` feature as acknowledged `legacy-scan`.
- Removed unsupported API and experimental proxy adapters from default CLI builds; their commands now require explicit `api-adapter` or `proxy-adapter` features, and the API adapter fails nonzero instead of implying that a listener started.
- Changed the repository container's default command to `venom --help`; it no longer starts an experimental network listener by default.
- Reframed the public README and linked onboarding, distribution, architecture, and profile guidance around the deterministic decision runtime, explicitly separating the opt-in legacy runner, unsupported adapters, and library-only surfaces.
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
- Moved unsafe-code and crate-documentation policy from global compiler flags into centrally inherited workspace lints.
- Classified per-request deadlines as `RequestTimeout` instead of conflating them with other transport failures.
- Made classic directory fuzzing an explicit `--legacy-directory-fuzz` CLI option instead of part of every historical ordered scan.
- Made every ordered CLI scan disclose that its unmigrated direct-I/O phases remain outside `StandardWebDecisionRuntime` and `RuntimeBudget`, keeping whole-run accounting `Unmetered` even though discovery phases two through four now have a separate bounded authority.
- Retained the legacy directory/parameter constructor shapes while adding explicit sequential constructors; positive compatibility concurrency values are conservatively narrowed to deterministic sequential dispatch, and the parameter constructor preserves zero as no request authority. Extended the alpha `ScannerError` enum as non-exhaustive before adding typed discovery cancellation, budget, policy, and state-limit failures.
- Advanced profiled API comparison metadata to v3; persisted v2 profiles are rejected instead of being silently reinterpreted after explanation semantics changed.
- Changed the alpha `RuntimeUsage.response_bytes` meaning from retained evidence bytes to complete response chunks delivered to the broker collector; a threshold-crossing chunk is charged, audited, and terminates the same turn.
- Enforced the Preview plugin registry's host-side enable flag, payload-size ceiling, and execution deadline without automatically retrying potentially side-effecting plugin calls.
- Canonicalized unordered-array path fingerprints once after capture instead of re-sorting a growing digest set for every element, preserving duplicate multiplicity and deterministic comparison semantics.
- Derived repository-size metric roots from locked Cargo metadata, consolidated release profile policy in the root manifest, and removed redundant development overrides; local parallelism now follows Cargo's host default.
- Replaced the stale CRA dashboard and unsupported enterprise/API claims with an explicitly disconnected `0.9.0-alpha` Vite preview, a locked zero-advisory dependency tree, and a real server-render smoke test.
- Made GitHub releases derive generated notes and prerelease/latest state from each tag instead of reusing the `v0.9.0-alpha` body and classification forever.

### Fixed

- CLI version output now derives from the Cargo package version.
- Standard web action execution and verification mappings now fail during profile construction instead of panicking at runtime.
- The architecture gate now owns and independently inspects explicitly registered nested production modules while continuing to reject undeclared helpers and includes.
- Made legacy payload pollution deterministic, UTF-8 reduction panic-free, and composite transformation hooks compositional.
- Prevented status-only API comparisons from emitting unrelated body-path explanations.
- Removed obsolete unregistered example sources and made the architecture gate reject top-level example `.rs` files that are not declared as Cargo targets.

### Security

- Expanded the responsible disclosure policy, supported-version table, response targets, CVE process, and researcher credit policy.
- Added hard depth, node, field, and canonical-byte ceilings for API visibility evidence preparation without weakening decision-runner subject isolation.
- Bounded relation identifiers, endpoints, custom kinds, provenance sets, review cursors, and page cloning; redacted deterministic visibility fingerprints and cursors from `Debug` output.
- Bounded API observation producer names and review explanations, validating borrowed records before projection clones them.
- Made request dispatch, buffered request-body, and delivered response-body charges non-refundable at the transport boundary, including partial reads and executor cancellation, and preserved structured audit receipts for broker limit denials.
- Bound profiled comparison identities to comparator, canonicalization, and projection-policy metadata; redacted legacy view handles from `Debug` output and kept raw JSON values and clear observed paths out of versioned reports.
- Made host cancellation preserve monotonic transport accounting and any post-commit, pre-verification evidence receipt without misreporting a wall-time or request-timeout limit.
- Rejected oversized plugin payloads before plugin code runs and cancelled in-process plugin futures when their configured deadline expires.
- Added strict, bounded cursor parsing and redacted cursor diagnostics while preserving the legacy in-process pagination wire contract.
- Added active multi-request and pre-socket retry budget regressions so nested dispatches cannot escape host accounting.
- Kept raw strategy seeds and derived artifacts out of serialization and debug output while retaining length, role, revision, and SHA-256 provenance.
- Isolated control and candidate connection pools while sharing one host-owned accounting authority; exact-target and context-header preflight, two active-verification leases, and monotonic partial/post-commit receipts prevent credential bleed and unaccounted paired transport.
- Replaced mutable or deprecated security-scanner actions with SHA/digest-pinned RustSec, cargo-deny, Trivy, CodeQL upload, Semgrep, and Codecov integrations; scans use least-privilege job tokens and audit the locked dependency graph without mutating it. Privileged release actions are SHA-pinned as well.
- Added bounded weekly Dependabot update queues for Cargo, the web preview, and GitHub Actions.
- Made legacy discovery state error-atomic, limited HTML extraction to complete `text/html` parser trees under a hard 64 KiB parse cap, retained POST/dialog form semantics without GET conversion, calibrated each eligible directory shape against two stable randomized nonexistent paths, and required reproducible four-leg parameter differentials. These remain `INFO` observations projected as `Unknown`, not findings.

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
