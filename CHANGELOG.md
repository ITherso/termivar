# Changelog

All notable changes to Termivar are recorded here. Releases use the categories from [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and follow Semantic Versioning.

## [Unreleased]

### Added

- Added a non-default SSRF OAST query review for one operator-authorized,
  structurally eligible query parameter. One `.invalid` control and two
  independently allocated HTTPS callback targets use exactly three anonymous,
  bodyless target GETs, one logical active verification, and at most twelve
  fixed provider-management requests. Only two correctly correlated callback
  observations can produce `NeedsReview` / `KnowledgeOnly` evidence; one-sided
  callbacks, timing, target status, and provider noise produce no item. The
  feature retains no raw target/provider traffic, remains outside
  `release-bundle`, and does not confirm SSRF or infer business impact.
- Added a non-default native OAST provider adapter that binds one explicitly
  self-hosted HTTPS management origin, one assessment and authority epoch,
  fixed register/allocate/poll/cleanup operations, and checked request, byte,
  poll, callback, and wall-time limits to a narrowing reservation of the
  parent assessment budget. Provider events are reduced into the existing
  raw-free correlation state machine. The adapter adds no CLI flag, target
  action or request, report, finding, release-bundle component, public provider,
  or SSRF conclusion.
- Added the unpublished `termivar-oast` auxiliary service and native protocol
  for an explicitly self-hosted, loopback-bound HTTP callback mailbox behind
  an operator-managed HTTPS reverse proxy. It uses high-entropy Bearer
  credentials, bounded in-memory raw-free events, fixed management routes, and
  explicit cleanup. Its server closure has no outbound client; a separately
  gated fixed-route HTTPS client and narrowing scanner authority provide the
  only reviewed management edge. Neither side adds a public provider, scanner
  action, target request, vulnerability claim, Interactsh compatibility,
  application-layer encryption, or `release-bundle` inclusion.
- Added a non-default, provider-neutral OAST correlation foundation with
  host-minted move-only tokens, exact verification-case binding, bounded
  caller-driven polling, DNS/HTTP event taxonomy, deterministic duplicate
  suppression, expiry/cancellation, and raw-value-free receipts. It performs
  no network I/O, registers no scanner action, emits no finding, and dispatches
  no SSRF or XXE payload.

### Changed

- Advanced the post-`v0.10.0-alpha.1` development line to
  `0.10.0-alpha.2`. A required provenance gate now rejects commits that keep a
  workspace version after its matching release tag.

### Fixed

- Exposed typed, redacted OpenAPI and REST review audits in JSON and text
  output so incomplete and ineligible reviews report their outcome, request
  and active-verification counts, replay state, and item-projection state
  without retaining response bodies or sensitive values.

## [0.10.0-alpha.1] - 2026-09-03

### Upgrade notes

- The current product name is Termivar, formerly Venom. The CLI binary changed
  from `venom` to `termivar`, the first-party package prefix changed from
  `venom-*` to `termivar-*`, and the Rust crate prefix changed from `venom_*`
  to `termivar_*`. No legacy `venom` binary alias is shipped.
- Active performance environment variables changed from `VENOM_PERF_*` to
  `TERMIVAR_PERF_*`, and the active cache/container identity changed from
  `.venom` to `.termivar`.
- Stable wire, schema, and digest identities may intentionally retain the
  former Venom name to preserve deterministic compatibility. Historical
  provenance likewise retains the name that was current when it was recorded.
- Integrators constructing scan state must follow the required
  [`ScanContext` migration guidance](docs/migrations/scan-context-construction.md).
  The complete product identity mapping and compatibility boundaries are in
  the [Venom-to-Termivar migration guide](docs/migrations/venom-to-termivar.md).

### Added

- Bounded HTML attribute source intelligence and quote-aware structural XSS
  review for ordinary, URI-bearing, and inline event-handler attributes. One
  source/DOM-cross-validated double-, single-, or unquoted anchor may select one
  non-executing inert boundary pair; exact host/sink boundary-and-tail evidence
  is `NeedsReview` only. Script context remains metadata-only, and no browser or
  JavaScript execution was added.
- A strict `venom.scan-profile/v1` product contract with exactly two CLI-wired
  built-ins: explicit single-resource `baseline` and opt-in exact-origin
  `web-review`. The origin assessment uses one shared runtime budget, metered
  redirect-disabled broker, cancellation authority, and authorization policy
  for deterministic bounded discovery and per-subject work, then composes
  bounded semantic extraction and defense observation/shadow planning.
- Value-free passive `web-review` evidence and typed `AssessmentItem`
  projection for HSTS, CSP, X-Content-Type-Options, Referrer-Policy,
  Permissions-Policy, and cookie-attribute review. Native passive items are
  `Informational` only. A closed native catalog now adds matched CORS and
  optional allowlisted navigation-query redirect/reflection review on the
  authorized starting resource through the same Standard runtime and shared
  broker without suppressing eligible standard actions. CORS requires a typed
  matched successful-status relationship, and redirect review recognizes only
  301/302/303/307/308. Exact policy relationships can produce only `NeedsReview`, benign
  reflection contexts remain `Informational`, redirects are never followed,
  and no native assessment capability can produce `Confirmed`. Stable item
  identity is root-only; non-root conditions become typed incompleteness rather
  than URL-derived fingerprints.
- An explicit exact-root `web-review` authorization-context option backed by
  the existing atomic API comparator. CLI credentials come only from a bounded
  environment, file, or stdin source; library hosts use a non-cloneable,
  redacted context type. Anonymous and authorized legs share the origin
  assessment authority. Equal visibility emits no item, a complete difference
  remains one atomic `NeedsReview` evidence reference, and incomplete or
  budget-limited collection suppresses later discovery instead of becoming
  empty success. The compiled active-verification default is six: four closed
  native-review requests plus the optional two-request API pair.
- An additive `venom-rendered-assessment/v1` JSON/CSV/HTML/Markdown surface for
  completed `web-review` runs, composed from runtime-owned truth through the
  existing 16 MiB bounded renderer. CLI `--report-format` selects the encoding;
  `--report-output` publishes a new, non-overwriting file through
  same-directory temporary-file and hard-link semantics. Incomplete or
  started-failed runs instead emit a redacted `web-assessment/v2` diagnostic,
  return nonzero, and create no report artifact.
- A focused Rust 1.88 runtime-smoke matrix on Ubuntu, Windows, and macOS for
  default CLI build/metadata, deterministic loopback scan behavior, atomic
  report paths, the core wire golden, exact-origin authority, and redirect
  no-follow behavior. This is a portability smoke layer, not platform
  certification or a duplicate all-feature matrix.
- Four separately tested current-head consumers under one dedicated lockfile
  for default `termivar-core`, deterministic assessment/reporting, the Legacy
  `ScannerSdk` facade, and evidence-only plugin API 0.2. Separate package
  invocations avoid feature unification; they prove same-revision source
  compilation only, not cross-version compatibility, a stable ABI, or external
  adoption.
- A deterministic endpoint-assessment evidence harness over the real
  `WebAssessmentRuntime`, with fixed harness-owned loopback workloads for 100
  and 1,000 endpoints plus 10,000 requests, strict
  `venom.endpoint-performance/v1` JSON/Markdown projection, an automatic
  contract job on relevant changes, and measurement gated by manual dispatch
  or an explicit same-repository PR label. The first controlled record captures
  three measured samples and intra-run variance for source commit `27321ef`;
  thresholds remain null and no repeatable accepted baseline, capacity claim,
  or SLA is established.
- Experimental opt-in host-library execution surfaces for bounded Lua 5.4
  source snapshots and deterministic process-local task/worker/result
  coordination. Neither surface has a repository CLI, scanner, plugin, or
  default-runtime caller.
- A security-hardened Phase 1 `semantic` entity extraction layer (`EntityExtractor`, `SemanticEntity`, `SemanticEntityType`, `AuthArtifactKind`). Converts raw scanner `Evidence` into strongly-typed, canonical semantic entities without mutating planner state or forcing intrinsic Plane properties onto entities. Includes strict redaction guarantees for sensitive header values (`[REDACTED]`) and auth credentials (SHA-256 fingerprinting with domain separation `venom:auth-artifact:v1:<kind>:<raw>`), `Domain` vs `IpAddress` separation, `v1` canonical entity identifiers, and order-independent `BTreeSet` attribute merging.

- A deterministic, public-API demonstration test (`defense_aware_planning_demo`) that shows the defense-aware planning arc end to end for one fixed scenario: the enforcement-off plan, the side-effect-free shadow delta with supporting evidence and stable explanation codes, and the enforcement-on plan with distinct `DefenseSuppressed` exclusions. It asserts the guarantees — disabled leaves the plan untouched, shadow and enforcement agree on what to suppress, and a suppressed action never becomes a plan step so it never reaches an executor — and renders a readable side-by-side summary.
- A default-off `defense::enforcement` layer (`DefensePlanningPolicy`, off by default) that lets observed defense change the real plan only when explicitly enabled. `defense_aware_plan` reuses the shadow layer to decide suppressions and applies them through a new, distinct `ExclusionReason::DefenseSuppressed` so defense suppression never conflates with adaptive/operator `PolicySuppressed`. While disabled it produces the planner's plan byte for byte; a defense-suppressed action never becomes a plan step, so it never reaches an executor. Defense still never adds an action or raises utility (graded numeric penalties are deferred).
- A side-effect-free `defense::shadow_planning` layer that computes a defense-aware shadow plan and an explainable delta against the current plan through the planner's read-only `plan_snapshot_with_suppressed` seam. It issues no request and mutates no planner, runtime, knowledge, or experience state, and never reorders the real plan. Defense evidence never adds an action or raises utility; it only allows, deprioritizes, or suppresses existing candidates via a single monotonic mapping keyed on `DefenseResponse` and a typed `DefenseInteractionClass` (no string matching). Recommendations reuse `defense::policy::recommend`, aggregated per resource with corroboration (a single standing block is downgraded), scoped to the exact resource, with a stable-coded delta referencing supporting evidence.
- A projection-only `defense::projection` adapter that turns observed defense state and control/candidate transitions into provenance-carrying `termivar_core::Evidence` under the `defense.*` predicate namespace, deterministically and idempotently. It emits observations only — never a `Fact` or hypothesis, so a single block or a bare status never becomes a confirmed-WAF claim — and returns nothing for a non-response, so timeouts and connection failures are never learned as defense. Evidence ids are a versioned SHA-256 digest of the canonical projection identity (`defense/<sha256>`), so raw resource, receipt, correlation, and producer values stay in their provenance fields and never leak into an id. It selects no payload, issues no request, and does not touch the planner, executor, or runtime configuration.
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
- A pinned `termivar-core` public API compatibility command and dedicated CI gate against the historical `venom-core` package at the `v0.9.0-alpha` source baseline.
- A `ScanContext` construction ADR and migration guide for the next Scanner Preview release.
- A virtual-workspace layout gate that rejects uncompiled Rust source at the repository root.
- An additive, versioned API visibility comparator envelope with projection profiles, volatile-path filtering, explicit unordered-array semantics, and bounded redacted path explanations.
- Explicit documentation that standard-profile Bayesian inputs are deterministic policy likelihoods until empirical calibration metrics are published.
- Host-owned standard-runtime cancellation with a distinct terminal reason and an auditable receipt for evidence committed before verification was skipped.
- A versioned API review cursor that binds continuation state to a pseudonymous resource digest and rejects cross-resource reuse before scanning.
- A process-local runtime failure receipt that preserves committed bootstrap work, completed turns, and monotonic usage across later execution, accounting, reasoning, or verification errors.
- A transport-ownership ADR and architecture invariant that keeps raw network capabilities out of bounded standard-runtime consumers and tracks the explicit legacy phase I/O inventory.
- Planner-selected, versioned payload-strategy reference and derivation contracts with hard byte limits, redacted audit receipts, and fail-closed executor support negotiation; no production payload capability is enabled by this plumbing.
- A first native built-in payload strategy, `http.header.control-pair@1`, deriving a deterministic control/candidate pair for a single benign request header, plus a `standard_payload_strategies` registry builder and repeat/concurrency conformance tests.
- A second native built-in payload strategy, `api.authorization.context-pair@1`, deriving an anonymous (empty, header-omitting) control and an authorized candidate credential to measure the same resource's visibility difference; registered in `standard_payload_strategies` with repeat/concurrency conformance tests.
- An observation-only defensive-posture layer (the `defense` module) that fingerprints WAF and edge products with robust case-insensitive header, substring, and cookie matching, and projects a bounded, deterministic `DefenseState` (status class, challenge and rate-limit markers, product fingerprint, and overall posture) from one response. It selects no payload or evasion technique, and drops the brittle `Server: AmazonS3` → AWS WAF inference in favor of confidence-graded signals.
- A deterministic `DefenseTransition` that compares a control and a candidate `DefenseState` into typed defense-transition evidence (posture shift, newly-blocking/newly-rate-limited flags, status and fingerprint changes, and a `NoChange`/`DefenseEngaged`/`DefenseRelaxed`/`DefenseReconfigured` summary) for a planner to weigh; it makes no payload decision.
- A deterministic `defense::policy::recommend` escalation policy that maps observed defense evidence to a restrictiveness-ordered `DefenseResponse` (`Proceed`, `Observe`, `Backoff`, `Reconsider`, `Halt`), attributing a candidate-provoked block to the candidate request; it recommends only and selects no payload.
- A strategy-aware `HttpEvidenceExecutor` payload binding (`HttpHeaderPayloadBinding`) that resolves the planner-selected strategy, derives the stage-appropriate control or candidate artifact, applies it through validated `HttpProbe` header construction, and dispatches it over the host request broker; opt-in per executor, with no standard profile enabling it by default.
- A `StandardWebDecisionRuntimeBuilder::with_payload_binding` opt-in that attaches a payload binding to the bounded runtime's metered `http.evidence` executor, so derived control and candidate dispatches are charged through the runtime's request accounting like any other request.
- Cumulative request-body accounting at the host-owned broker boundary, including atomic concurrent-limit enforcement and rejection of unmetered bodies.
- Full transport-delivered response-chunk accounting while preserving a separately bounded retained evidence prefix.
- A comparator-v3 visibility-explanation disposition that distinguishes equivalence, bounded path summaries, and differences without representable path summaries while preserving explicit replay metadata.
- A host-triggered, single-use JSON authorization-context differential workflow that moves two broker-backed views through Comparator V3, atomic observation ingestion, and exact human-review projection without becoming a planner action or vulnerability verdict.
- Pinned golden API-authorization replay metadata and broker-backed runtime coverage for anonymous/member, owner/unrelated-user, and read/write-capability context pairs.
- Bounded, raw-target-free transport dispatch receipts with ordered per-attempt byte accounting and typed completion, failure, timeout, response-limit, and cancellation outcomes.
- A context-owned legacy discovery authority shared by crawler, optional directory, and parameter phases, with exact-origin redirect-disabled transport plus configurable depth, page, request, request-timeout, wall-time, cumulative-body, and per-response-body limits.
- A distinct context-owned legacy verification authority for phases five through nine, with exact-origin bodyless transport, `Active`-stage accounting, disabled redirects/retries, and configurable request, timeout, wall-time, cumulative-body, and per-response-body limits.
- A fail-closed legacy verifier bridge that accepts only allowlisted, case-correlated, knowledge-only `NeedsReview` reports and rolls their public projection back when a phase errors, times out, panics, is cancelled, or exhausts its bounded transport authority.
- The initial Preview, opt-in host-library renderer for typed `RunReport`
  values, with format-safe encoding, an explicit document schema, a hard
  rendered-byte ceiling, typed failures, and no renderer-owned filesystem,
  persistence, CLI policy, or verdict authority. Its later explicit
  `web-review` composition is described above.

### Changed

- Renamed the current product, workspace packages, Rust crates, CLI binary,
  active performance environment variables, and cache/container identity from
  Venom to Termivar. Historical provenance and stable wire, schema, digest,
  evidence, and capability identities intentionally retain their existing
  values; no second CLI or scanner implementation was introduced.
- Preserved the no-profile `termivar scan` behavior and `decision-scan/v1` wire
  contract while making profile selection additive. Explicit `baseline` uses
  `web-assessment/v1`; completed `web-review` uses the central typed assessment
  renderer, and no explicit profile silently enables origin discovery.
- Extended the standalone `RunReport` renderer without removing it: builds with
  `scanning + reporting` can now compose only completed runtime-owned
  `WebAssessmentRunReport` truth into a typed report, while generic
  caller-supplied `RunReport` values remain the separate host-library API.
- Split responsibility-dense scanner facades into private domain modules for
  plugin execution, decision-loop and runner state, HTTP evidence, knowledge,
  rules, planning, API observation, Lua execution, and process-local
  coordination while
  preserving reviewed root facades, re-exports, feature closures, and runtime
  behavior. Architecture gates prevent those responsibilities from silently
  collapsing back into monolithic implementations.
- Switched the pinned repository coverage measurement from Linux's default
  Ptrace backend to Tarpaulin's explicit LLVM backend and versioned the evidence
  record as `venom.coverage.v2`, including a normalized line-state digest that
  makes same-count covered-line drift fail the baseline-acceptance seal.
- Replaced the Lua fail-closed registry scaffold and loose distributed models
  with exact private-module/root-facade APIs, independent feature closures, and
  architecture fingerprints/mutation checks. Lua now executes text-only chunks
  in fresh no-standard-library VMs; distributed commands use bounded ordered
  state, explicit logical time/revisions, fenced ownership, atomic retry and
  recovery, and bounded result retention.
- Advanced the remediated unreleased source line to the new pre-1.0 minor identity `0.10.0-alpha.1`, so its binaries cannot be confused with the behaviorally different historical `v0.9.0-alpha` artifacts.
- Removed the disconnected legacy adaptive response scorer and attack-shaped payload mutators; the default-built `adaptive` namespace now contains only the outcome-driven, declarative pipeline.
- Removed the false legacy WAF detector and attack-shaped evasion dispatcher. The remaining payload-encoding helper supports only explicit percent/hex byte encoding through the bounded, redacted `PayloadArtifact` contract.
- Quarantined unwired API/auth/dashboard/persistence/realtime models, the bounded report renderer, native plugins, Lua, distributed coordination, and the legacy scanner behind independent opt-in features; the default scanner feature closure is now only `core + scanning`, and optional dependencies follow those boundaries.
- Replaced the legacy `ScanFinding`-based report and synthetic risk/severity aggregation with a bounded renderer over the constructor-validated `RunReport` contract. It preserves stop classification codes without exposing private stop-reason detail, performs format encoding but no redaction, and requires callers to pre-redact projected target, authorized-origin, step/outcome action-identifier, and outcome-summary fields. The `reporting` feature now closes over `core` only; `VulnerabilityReport`, `risk_score`, `severity_stats`, and `phase_stats` are intentionally removed on this unreleased alpha line.
- Reduced default `termivar-core` to transport-neutral reasoning and run-report contracts. The complete historical configuration, error, event, raw finding, vulnerability, result, and HTTP facade remains available only through `legacy-contracts` so the pinned all-features compatibility gate stays strict without reintroducing those records into default builds.
- Replaced the false `AsyncMitmProxy`/certificate surface with an honestly named fixed-upstream TCP relay, removed unused HTTP/TLS dependencies, and made the CLI require an explicit validated upstream socket instead of silently choosing `127.0.0.1:80`.
- Removed the repository installer until a remediated release tag exists. The historical `v0.9.0-alpha` binaries predate the bounded default runtime and are not presented as an installation path for this source state.
- Made container publication an explicit manual action with commit-scoped development tags, removed unused PostgreSQL/Redis test services, and added CI checks for the inert non-root CLI image.
- Removed the historical root Compose stack and gated its return while deployment remains unsupported; the stack coupled the CLI to unused services, default credentials, disabled security, and nonexistent listener health semantics.
- Replaced the original loose `target`/`payload` plugin invocation and plugin-authored `ScanFinding` output with a host-owned bounded context and observation recorder. The Preview API line changes intentionally; plugin observations require host reasoning and verification before any finding projection.
- Removed the six substring-matching SQL, XSS, LFI, XXE, SSRF, and SSTI types from the production plugin namespace. Harmless INFO-only marker fixtures now exercise the trait boundary under `examples/plugin-fixtures/`, and stock profile scaffolds no longer name nonexistent detector plugins.
- Made `termivar scan` the default bounded deterministic runtime, retained `decision-scan` as a deprecated compatibility alias with the unchanged `decision-scan/v1` wire contract, and moved the historical mixed-authority heuristic runner behind the non-default `legacy-scanner` feature as acknowledged `legacy-scan`.
- Removed unsupported API and experimental proxy adapters from default CLI builds; their commands now require explicit `api-adapter` or `proxy-adapter` features, and the API adapter fails nonzero instead of implying that a listener started.
- Changed the repository container's default command to `termivar --help`; it no longer starts an experimental network listener by default.
- Reframed the public README and linked onboarding, distribution, architecture, and profile guidance around the deterministic decision runtime, explicitly separating the opt-in legacy runner, unsupported adapters, and library-only surfaces.
- Replaced the long-form promotional README with a concise project guide.
- Standardized the historical pre-release baseline as `0.9.0-alpha` before advancing the remediated source line.
- Replaced absolute completion claims with scoped lifecycle labels. Default
  `termivar-core` is a Stable candidate rather than a promise; deterministic APIs
  and plugin API 0.2 are Preview, `ScannerSdk` is Legacy, and Lua/distributed
  host surfaces are Experimental.
- Moved shared event and finding contracts into `termivar-core` while preserving scanner re-exports.
- Documented the plugin system as a source-level preview instead of implying dynamic discovery.
- Moved the editable Draw.io architecture source directly under `docs/` for discoverability.
- Made plugin API compatibility explicit with version negotiation and non-exhaustive public types.
- Added publishable version requirements to internal crate dependencies and removed the unused, unmaintained `rustls-pemfile` dependency.
- Made the runtime bootstrap receipt optional so a fail-closed budget can stop before initial network evidence is committed.
- Limited learned suppression to verified negative conclusions; target blocks, policy blocks, transport failures, executor failures, and inconclusive checks remain neutral.
- Classified built-in HTTP applicability, policy, transport, and internal executor failures without parsing diagnostics or turning operational failures into verifier outcomes.
- Separated semantic action attempts from actual transport dispatches; retries, timeouts, redirects, partial bodies, and pre-dispatch failures now report their real resource use.
- Moved standard web action identities into a transport-neutral catalog so verification no longer depends on HTTP execution or the `scanning` feature.
- Replaced duplicated HTTP and web predicate literals with the canonical `termivar-core` vocabulary.
- Made API fingerprinting consume normalized media-type and path-segment evidence; the JSON rule identity is `api.response.json.media-type`.
- Limited each standard API calibration to one matching contribution to reduce retry-driven posterior inflation; existing profiles retain the default independent-contribution behavior.
- Rejected zero-reliability HTTP evidence policies so fixed rule likelihoods cannot promote a no-confidence observation.
- Made rule-produced hypothesis writes batch-atomic and preserved verifier-owned terminal states under the same knowledge-base lock.
- Made planning-session changes error-atomic and snapshot-CAS guarded; planner, command-construction, and stale-knowledge failures no longer partially halt or advance a session.
- `ScanContext` now owns an evidence-driven `KnowledgeBase`, is non-exhaustive, and exposes reasoning state through `knowledge()`. This is an intentional Preview source transition from the v0.9 struct-literal contract; consumers must use constructors and the accessor. `termivar-scanner` remains outside the blocking compatibility gate until the next Preview baseline.
- Removed the uncompiled pre-workspace monolith and its obsolete completion/deployment reports; Git history remains the migration archive.
- Made repository-size metrics count only tracked Rust files owned by workspace packages and moved warning denial from global environment overrides into explicit Clippy/release gates.
- Replaced stale testing, observability, and code-quality claims with documentation of the currently compiled contracts and CI evidence.
- Centralized canonical rule-hypothesis identity generation while preserving existing IDs byte-for-byte.
- Moved unsafe-code and crate-documentation policy from global compiler flags into centrally inherited workspace lints.
- Classified per-request deadlines as `RequestTimeout` instead of conflating them with other transport failures.
- Made classic directory fuzzing an explicit `--legacy-directory-fuzz` CLI option instead of part of every historical ordered scan.
- Made every ordered CLI scan disclose that its discovery and active-verification authorities remain separate from `StandardWebDecisionRuntime` and `RuntimeBudget`; phase-one and custom extension direct I/O still keep whole-run accounting `Unmetered`.
- Replaced broad legacy exploit labels with bounded claim semantics: reproduced SQL diagnostics/timing, exact template arithmetic, and an opt-in benign local-file canary may require manual review; exact reflection stays unresolved, XXE stays inert, and OOB probe delivery records no callback conclusion by itself.
- Retained the legacy directory/parameter constructor shapes while adding explicit sequential constructors; positive compatibility concurrency values are conservatively narrowed to deterministic sequential dispatch, and the parameter constructor preserves zero as no request authority. Extended the alpha `ScannerError` enum as non-exhaustive before adding typed discovery cancellation, budget, policy, and state-limit failures.
- Advanced profiled API comparison metadata to v3; persisted v2 profiles are rejected instead of being silently reinterpreted after explanation semantics changed.
- Changed the alpha `RuntimeUsage.response_bytes` meaning from retained evidence bytes to complete response chunks delivered to the broker collector; a threshold-crossing chunk is charged, audited, and terminates the same turn.
- Enforced the Preview plugin registry's host-side enable flag, payload-size ceiling, and execution deadline without automatically retrying potentially side-effecting plugin calls.
- Canonicalized unordered-array path fingerprints once after capture instead of re-sorting a growing digest set for every element, preserving duplicate multiplicity and deterministic comparison semantics.
- Derived repository-size metric roots from locked Cargo metadata, consolidated release profile policy in the root manifest, and removed redundant development overrides; local parallelism now follows Cargo's host default.
- Replaced the stale CRA dashboard and unsupported enterprise/API claims with an explicitly disconnected `0.10.0-alpha.1` Vite preview, a locked zero-advisory dependency tree, and a real server-render smoke test.
- Made GitHub releases derive generated notes and prerelease/latest state from each tag instead of reusing the `v0.9.0-alpha` body and classification forever.
- Made tag publication fail closed until a testable release-metadata command finds a dated changelog section, exact release/comparison links, and a supported-version row for the tagged workspace version; immediately before checksums and create-once publication, the publisher force-refetches the remote tag and binds its peeled commit to the triggering build.

### Fixed

- CLI version output now derives from the Cargo package version.
- Standard web action execution and verification mappings now fail during profile construction instead of panicking at runtime.
- The architecture gate now owns and independently inspects explicitly registered nested production modules while continuing to reject undeclared helpers and includes.
- Made legacy payload pollution deterministic, UTF-8 reduction panic-free, and composite transformation hooks compositional.
- Prevented status-only API comparisons from emitting unrelated body-path explanations.
- Removed obsolete unregistered example sources and made the architecture gate reject top-level example `.rs` files that are not declared as Cargo targets.

### Security

- Hardened Lua registration against root escape, symlink and changed-source
  inputs; bounded VM memory, instructions, deadline, context, output, return,
  registry/concurrency/history state; and exposed only a private scalar host
  environment. These cooperative in-process controls do not hard-preempt
  parser/native work or provide process isolation, and source digests remain
  deterministic linkable metadata. Hardened distributed state with ordered
  collections, integer-only selection, hard capacity ceilings, explicit-time
  revision checks, private ownership snapshots, retry-backpressure preflight,
  and redacted opaque payload Debug output; structural tokens remain
  caller-epoch scoped rather than authenticated cross-instance capabilities.
- Made plugin registration reject duplicate IDs without replacing existing state, blocked unregistration and same-ID rebinding while an invocation is active, removed decorative retry policy, eliminated registration/execution-boundary panics, and placed plugin network access behind an exact-origin, cancellation-aware broker contract with context-validated capture caps, request/body accounting, opaque error details, and bounded redaction policy.
- Expanded the responsible disclosure policy, supported-version table, response targets, CVE process, and researcher credit policy.
- Added hard depth, node, field, and canonical-byte ceilings for API visibility evidence preparation without weakening decision-runner subject isolation.
- Bounded relation identifiers, endpoints, custom kinds, provenance sets, review cursors, and page cloning; redacted deterministic visibility fingerprints and cursors from `Debug` output.
- Bounded API observation producer names and review explanations, validating borrowed records before projection clones them.
- Made request dispatch, buffered request-body, and delivered response-body charges non-refundable at the transport boundary, including partial reads and executor cancellation, and preserved structured audit receipts for broker limit denials.
- Bound profiled comparison identities to comparator, canonicalization, and projection-policy metadata; redacted legacy view handles from `Debug` output and kept raw JSON values and clear observed paths out of versioned reports.
- Made host cancellation preserve monotonic transport accounting and any post-commit, pre-verification evidence receipt without misreporting a wall-time or request-timeout limit.
- Rejected oversized plugin payloads before plugin code runs and cooperatively cancelled yielding in-process plugin futures when their configured deadline expires; this is not CPU, memory, blocking-call, or process isolation.
- Added strict, bounded cursor parsing and redacted cursor diagnostics while preserving the legacy in-process pagination wire contract.
- Added active multi-request and pre-socket retry budget regressions so nested dispatches cannot escape host accounting.
- Kept raw strategy seeds and derived artifacts out of serialization and debug output while retaining length, role, revision, and SHA-256 provenance.
- Isolated control and candidate connection pools while sharing one host-owned accounting authority; exact-target and context-header preflight, two active-verification leases, and monotonic partial/post-commit receipts prevent credential bleed and unaccounted paired transport.
- Replaced mutable or deprecated security-scanner actions with SHA/digest-pinned RustSec, cargo-deny, Trivy, CodeQL upload, Semgrep, and Codecov integrations; scans use least-privilege job tokens and audit the locked dependency graph without mutating it. Privileged release actions are SHA-pinned as well.
- Added bounded weekly Dependabot update queues for Cargo, the web preview, and GitHub Actions.
- Made legacy discovery state error-atomic, limited HTML extraction to complete `text/html` parser trees under a hard 64 KiB parse cap, retained POST/dialog form semantics without GET conversion, calibrated each eligible directory shape against two stable randomized nonexistent paths, and required reproducible four-leg parameter differentials. These remain `INFO` observations projected as `Unknown`, not findings.
- Hardened the historical verification phases with negative baselines, reproducible controls, randomized probe ordering/operands, robust timing samples, exact nonce/canary replay, and local positive/negative fixtures. Removed default sensitive-file and cloud-metadata payloads; XXE dispatch remains disabled, and SSRF requires explicit OOB configuration while treating HTTP status only as a probe receipt.

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

[Unreleased]: https://github.com/ITherso/termivar/compare/v0.10.0-alpha.1...HEAD
[0.10.0-alpha.1]: https://github.com/ITherso/termivar/compare/v0.9.0-alpha...v0.10.0-alpha.1
[0.9.0-alpha]: https://github.com/ITherso/venom/releases/tag/v0.9.0-alpha
