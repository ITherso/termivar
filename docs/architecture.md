# Architecture

## OpenAPI surface review boundary

The separately non-default `openapi-review` feature requires explicit
`--openapi-review --profile web-review`. Its single native action remains in
the same `WebAssessmentRuntime`, exact-origin authority, redirect-disabled
client, broker, budget, evidence registry, and final report. It selects one
document at most and uses a bodyless GET candidate plus exact replay. The
transport-neutral catalog cannot grant execution authority, and described API
operations are not dispatched. See
[OpenAPI surface review](internals/openapi-surface-review.md).

The separately non-default `rest-review` feature requires explicit
`--profile web-review --openapi-review --rest-review`. It consumes only a
replay-stable OpenAPI catalog committed by that same assessment, selects at
most one anonymous bodyless exact-origin zero-input `GET`, and runs candidate
plus replay as two requests and one logical active verification through the
same `WebAssessmentRuntime`, broker, budget, exact-origin authority, evidence
registry, completeness lifecycle, and final report. It emits at most
`Informational` / `KnowledgeOnly`, executes no write, materializes no parameter
or body, uses no credential/cookie, and does not chain to SQL, SSTI, XSS,
authorization, SSRF, or upload review.

This document defines dependency direction and runtime ownership for the unreleased Termivar `0.10.0-alpha.1` source line. It is a design contract, not a production-readiness claim.

The editable diagrams.net source is [architecture.drawio](architecture.drawio). A presentation- and print-friendly export is available as [architecture.svg](images/architecture.svg).

![Termivar runtime and crate architecture](images/architecture.svg)

## Current workspace

| Crate | Responsibility | May depend on |
| --- | --- | --- |
| `termivar-core` | Default transport-neutral evidence, reasoning, ontology, outcome, predicate, and run-report contracts; the pre-quarantine facade is feature-gated | External libraries only |
| `termivar-scanner` | Phase/plugin traits, deterministic reasoning, runner, detection, opt-in bounded report rendering, and Experimental host-owned Lua/coordination execution | `termivar-core` |
| `termivar-exploit` | Preview, non-published exploit manifest/catalog plus disconnected non-default authorized orchestration contracts; only an in-memory lab fixture executes | `termivar-core` only where shared opaque identity/evidence contracts are required |
| `termivar-artifact` | Preview, non-published exact/wildcard buffer and bounded-reader signature observations; no path, network, process, exploit, or verdict authority | External libraries only |
| `termivar-proxy` | Experimental fixed-upstream TCP relay; no HTTP/TLS interception | External libraries only |
| `termivar-api` | Library health router and its local unsupported-listener error | External libraries only |
| `termivar-cli` | Composition root and command routing | `termivar-scanner` by default; `termivar-api`, `termivar-proxy`, and `termivar-artifact` only through explicit adapter features |

`xtask` is repository tooling rather than a runtime layer. It may orchestrate
workspace commands but application crates must not depend on it. Its
`scanner-salvage` and `waf-evasion-salvage` checks validate two strict,
separate historical source epochs against local Git objects and deterministic
generated reports. The first covers the deleted 38-file pre-workspace scanner
tree; the second covers 13 files and 39 components from the post-workspace
WAF/evasion quarantine wave. Neither check compiles or executes historical
source. The ledgers classify recovery candidates, superseded implementations,
and rejected behavior but create no application dependency, runtime
capability, execution authority, or claim authority.

The repository root is a virtual Cargo workspace and has no `src/` tree. Rust
source must live under a declared workspace package; otherwise it would be
excluded from build, test, documentation, release, and quality gates. The
architecture preflight rejects a virtual root containing `src/`. It also
rejects any top-level `.rs` file in the examples package that is not declared as
a Cargo target, so example source cannot silently fall outside compilation.

```mermaid
flowchart TD
    CLI[termivar-cli] --> Scanner[termivar-scanner]
    CLI -. "api-adapter" .-> API[termivar-api]
    CLI -. "proxy-adapter" .-> Proxy[termivar-proxy]
    CLI -. "artifact-adapter" .-> Artifact["termivar-artifact<br/>bounded observations"]
    Scanner --> Core["termivar-core<br/>Evidence / Reasoning / Outcomes / Reports"]
    Exploit["termivar-exploit<br/>Preview metadata + opt-in lab orchestration"] --> Core
```

`termivar-artifact` is a separate artifact-observation domain. Its library accepts
caller-supplied bytes or bounded readers and owns no filesystem path, network,
process, browser, or exploit authority. Only the CLI's non-default
`artifact-adapter` may open one explicitly selected local regular file for a
read-only scan; it performs no recursion and does not alter `termivar scan`.
Signature matches are deterministic observations, never malware verdicts,
vulnerabilities, or severity assignments. Repository signature discovery is an
explicit non-scanning `xtask artifact-catalog` operation.

`termivar-exploit` is an independent workspace domain rather than part of the
scanner product graph. `termivar-scanner`, `termivar-cli`, `termivar-api`, and
`termivar-proxy` do not depend on it. Its V1 default library accepts bounded
manifest bytes and performs deterministic validation and catalog queries. A
non-default Preview feature adds host-minted grants, sealed deterministic plans,
typed permits/receipts, and separate impact/cleanup lifecycle accounting. Only
an in-memory canary integration fixture exercises that API. The crate owns no
production target/network/process/browser/filesystem adapter, CLI command, or
authority derived from metadata. Source-linked implementations are cooperative
trusted code, not sandboxed third-party code. Repository-owned pack file
discovery belongs to `xtask`, not the library. The historical
`termivar_scanner::post_exploitation` metadata scaffold remains separately
quarantined behind `platform-models` and is not imported or expanded by this
domain.

The pre-quarantine `Config`, shared `Error`, lifecycle-event, `ScanFinding`, raw
HTTP, vulnerability, and scan-result records remain in `termivar-core` only behind
its non-default `legacy-contracts` feature for the pinned alpha compatibility
baseline. `termivar-scanner` forwards that feature only for `legacy-scanner` and
`platform-models`; the default decision runtime and the `reporting` feature
cannot import those records. The scanner owns behavior such as `EventBus`,
`ScanRunner`, `ScanPhase`, and `Plugin`. `ScanFinding` is a legacy phase
compatibility contract; the Preview plugin and reporting contracts do not
accept it.
`termivar-api` owns its small adapter error locally and has no workspace-crate
dependency.

No lower-level crate may depend on `termivar-cli` or `termivar-api`. A cycle between workspace crates is a release blocker.

## Runtime ownership

```mermaid
flowchart TD
    Host["CLI / library host"] --> LegacyRunner["Legacy runner · opt-in"]
    LegacyRunner --> Pipeline["Ordered legacy phase pipeline"]
    Pipeline --> Discovery["Bounded discovery authority<br/>phases 2–4"]
    Discovery --> Crawl
    Discovery --> Directory["Directory · explicit opt-in"]
    Discovery --> Parameters
    Pipeline --> Verification["Bounded Active verification authority<br/>phases 5–9"]
    Pipeline --> RawLegacy["Raw legacy client<br/>phase 1 / custom phases"]
    Discovery --> DiscoveryRecords["INFO discovery observations"]
    Verification --> ReviewRecords["Report projection<br/>Unknown or knowledge-only NeedsReview"]
    Verification --> KnowledgeReceipt["SSRF probe receipt<br/>knowledge only · no outcome"]
    RawLegacy --> LegacyRecords["Unverified compatibility records"]
    DiscoveryRecords --> RunReport["Typed run report · Unknown observations"]
    ReviewRecords --> RunReport
    LegacyRecords --> RunReport
    RunReport -. "explicit reporting host" .-> Renderer["Bounded renderer · Preview"]
    Renderer --> Document["Host-owned document<br/>no persistence or verdict authority"]
    PluginHost["Linked plugin host · Preview"] --> PluginContext["Host-owned PluginContext<br/>scope · budget · broker · redaction"]
    PluginContext --> PluginCode["Plugin trait implementation"]
    PluginCode --> PluginEvidence["Recorded observations"]
    PluginEvidence --> HostVerification["Host reasoning / verification"]
    LibraryHost["Explicit library host"] -. "lua" .-> Lua["Bounded Lua VM<br/>Experimental · in-process"]
    LibraryHost -. "distributed" .-> Coordinator["Bounded coordinator<br/>Experimental · process-local"]
    LegacyRunner --> Events["Event Bus"]
    Events -. "optional host projection" .-> Observers["Telemetry consumers"]
```

This diagram describes the legacy Surface-A orchestration boundary. Its
phase-two-to-four discovery and phase-five-to-nine verification envelopes do
not make whole-run accounting metered: phase one and host-defined custom phases
can retain raw direct-I/O authority. It also does
not imply that the deterministic Surface-B runtime projects verification
outcomes into findings, that a legacy `NeedsReview` outcome is a vulnerability
verdict, that the optional renderer persists a document, or that a dashboard
subscriber is composed by either CLI scan command.

The runner knows `ScanPhase`, not concrete phase implementations. The plugin
registry knows `Plugin`, not concrete plugin types. A linked host constructs the
execution request, the registry materializes the plugin context, and the host
retains authorization, transport, redaction, provenance, and verification
authority. Plugin observations do not automatically become
findings. An opt-in `PluginDecisionExecutor` can forward registry observations
through the deterministic runner when a host supplies the full execution
request; no stock CLI composes that bridge. Native plugin execution and the
ordered phase runner remain parallel paths, and neither CLI scan command loads
plugin crates dynamically.

## Scanner modules

Responsibility-dense scanner domains keep their established root source module
as a facade and place implementation ownership in private child modules. Eight
facades remain public modules; `lua_engine` and `distributed` remain private
modules with reviewed crate-root re-exports. Existing public module and
re-export paths remain compatible. This is a source-organization boundary, not
a second runtime or a capability change.

| Facade | Private responsibility modules |
| --- | --- |
| `plugin.rs` | metadata, host context, registry, execution, recorder, limits, and broker transport |
| `decision_loop.rs` | commands, state, transition policy, and receipts |
| `decision_runner.rs` | executor registry, execution, failures, and receipts |
| `http_evidence.rs` | policy, probes, response projection, form controls, passive review, request broker, and review response |
| `knowledge.rs` | store, snapshots, writes, relations, and indexes |
| `rules.rs` | expressions, registry, evaluation, and engine |
| `planner.rs` | model, policy, scoring, and selection |
| `api_observation.rs` | model, ingestion, query, review, and cursor |
| `lua_engine.rs` | source, registry, VM, execution, limits, and history |
| `distributed.rs` | model, limits, coordinator, queue, lease, worker, recovery, and results |

The historical `phases/`, `legacy_discovery.rs`, `runner.rs`, and
`event_bus.rs` remain opt-in through `legacy-scanner`. `reporting.rs` remains
the single bounded typed renderer. Optional detection, platform-model, ML,
monitoring, compliance, and threat-intelligence modules retain their separate
feature boundaries.

## Target product-layer split

Dashboard, distributed orchestration, compliance, and web application concerns should move outward once their contracts stabilize.

```mermaid
flowchart TD
    Product["Optional product layer<br/>Dashboard / Distributed / Compliance / Web"] --> App["CLI / application composition"]
    App --> Scanner[termivar-scanner]
    Scanner --> Core["termivar-core<br/>Evidence / Reasoning / Outcomes / Reports"]
```

This target supports separate open-source and commercial distributions without making `termivar-core` or `termivar-scanner` aware of product policy. No placeholder `termivar-enterprise` crate should be created until ownership, licensing, and stable interfaces are defined.

## Boundary rules

1. The CLI or application crate is the composition root.
2. The runner owns scheduling, timeout, cancellation, events, and aggregation, not detection logic.
3. Legacy phases implement their documented observation/verification contracts;
   plugins record observations through host policy and never own finding or
   transport authority.
4. The event bus carries immutable lifecycle facts; subscribers do not control execution through hidden callbacks.
5. The opt-in distributed contract owns bounded/versioned process-local records,
   explicit logical time, and ordered state transitions. Callers own any wire
   encoding, authenticated transport, persistence, coordinator epoch, and
   background execution; the public types intentionally define no serialization
   protocol.
6. The opt-in Lua contract snapshots approved-root text source and exposes only
   a private scalar context/output environment in a fresh no-standard-library
   VM. Its memory, instruction, deadline, and cancellation controls are
   cooperative in-process limits, not process isolation.
7. The opt-in report renderer consumes an immutable typed `RunReport`, performs
   no I/O or redaction, and neither mutates scanner state nor creates findings
   or verdicts. Hosts must pre-redact projected target, authorized-origin,
   action-identifier, and outcome-summary fields.

## Reasoning and runtime boundary

The decision engine remains inside `termivar-scanner` during alpha, but its module
direction is treated as an extraction boundary rather than an informal style
preference.

```mermaid
flowchart TD
    Runtime["Scanner runtime / HTTP / plugins"] --> PlanVerify["Planning / verification / domain profiles"]
    PlanVerify --> Contracts["Knowledge / rules / experience / semantic actions"]
    Contracts --> Core["termivar-core"]
```

| Protected layer | Modules | May import |
| --- | --- | --- |
| Evidence preparation | `api_evidence` | `termivar-core` plus bounded JSON/hash libraries; never network, runtime, planner, or knowledge state |
| Reasoning state | `experience`, `rules` | `termivar-core`; `rules` may also use `knowledge` |
| Payload derivation contract | `payload_strategy` | Bounded collections, serialization, and hashing only; never knowledge, runtime state, clocks, randomness, or transport |
| Planning and verification | `planner`, `verification` | `knowledge`, `rules`, `payload_strategy`, `termivar-core` |
| Semantic action, ingestion, and domain profiles | `web_actions`, `web_reasoning`, `api_reasoning`, `api_observation`, `web_planning`, `web_verification` | The lower rows above; never execution or HTTP modules |
| Execution and composition | `decision_runner`, `http_evidence`, `web_execution`, `web_runtime` | All inward contracts needed to perform and account for work |

Within the bounded standard runtime, `http_evidence/request_broker.rs` is the
sole owner of a raw HTTP client. Built-in bootstrap, planned, adaptive, retry,
and active-verification traffic must pass through its shared atomic accounting
authority. The architecture check rejects direct client or socket acquisition
from the surrounding decision/runtime modules. The standard runtime must call
the explicitly metered broker constructor; the architecture gate rejects a
switch to the named legacy unmetered constructor.

`WebAssessmentRuntime` is an orchestrator over that same Standard primitive,
not a second engine. Explicit `web-review` composes its root-scoped native
CORS and optional redirect/reflection actions into the authorized root's
existing Standard session without replacing its eligible standard actions.
Their executors receive the assessment broker, and
their actions are KnowledgeOnly. The closed response observer and committed
ledger can project only `Informational` or `NeedsReview`; action success cannot
authorize a confirmed finding. CORS additionally requires a typed matched
successful-status relationship, and redirect classification is the closed
301/302/303/307/308 set. Defense shadow/enforcement may retain or
suppress these already-planned differential reads but cannot add a native
action, refill the plan, increase intensity, or broaden scope.

Normalization resilience is a separate opt-in composition rather than a
responsibility of `defense`. Both the scanner/CLI
`normalization-resilience` feature and the explicit
`--normalization-resilience --profile web-review` runtime choice are required.
The feature consumes one already committed XSS parent control/canonical pair
only after a typed candidate-specific blocking transition. Fingerprints and
status codes do not authorize it. Metadata selection admits at most one
depth-one source-linked serializer: HTML scanner-token case for an HTML-text
parent, or one horizontal scanner-owned inter-token separator for an anchored
ordinary/URI/event-handler attribute parent. Percent decode-depth entries are
metadata-only.

The parent requests are reused rather than resent. A selected child has one
shared-authority bootstrap, transformed candidate, and distinct transformed
replay—three requests and one active verification through the existing broker.
Both transformed legs must avoid the canonical block and satisfy the same
existing inert DOM semantic verifier. Projection registers shared evidence once
and can emit only a defensive-normalization-gap `NeedsReview` item under
`KnowledgeOnly` authority. The boundary adds no `waf.rs`, generic dispatcher,
second client, redirect/origin expansion, request-shape mutation, rate-limit
evasion, browser/process/exploit dependency, or confirmed/product-specific
bypass claim. See
[Normalization-resilience review](internals/normalization-resilience.md).

The ordered legacy runner is separate. Its phases two through four share a
context-owned passive discovery authority that accepts exact-origin requests,
disables redirects, applies one configurable request/time/body envelope, and
commits typed discovery deltas atomically. Phases five through nine share a
second context-owned authority with its own `VerificationLimits`; it admits
bodyless exact-origin requests, disables redirects and retries, and accounts
them at the `Active` stage under a separate request/time/body envelope. Neither
authority composes `StandardWebDecisionRuntime` or extends its `RuntimeBudget`.

The architecture gate prevents built-in phases two through nine from
reacquiring a raw client or dispatching outside the authority assigned to their
phase class. The raw legacy client remains available to phase one and
host-defined custom `ScanPhase` extensions, so the whole ordered run remains
`Unmetered`. Within the active slice, only the SQL-behavior,
template-arithmetic, and explicitly configured local-file-canary action IDs may
cross a verifier-owned bridge, and only as case-correlated, knowledge-only
`NeedsReview` outcomes. Exact reflection has no browser verifier; XXE dispatch
is disabled; and configured SSRF OOB delivery records a probe receipt without a
callback conclusion.

`web_actions` owns stable semantic action and route identities. Planning,
verification, and execution are sibling consumers; an executor's HTTP method or
client policy never defines what the verifier is allowed to reason about.

`termivar-core::predicates` owns the canonical HTTP observations, web conclusions,
API conclusions, and atomic paired-visibility contract shared by producers and
reasoners. `api_reasoning` consumes those transport-neutral contracts to infer
JSON/GraphQL fingerprints and reviewable visibility boundaries. It performs no
requests, does not combine independent observations into a pair, and never
declares a vulnerability.

GraphQL surface review preserves that boundary. The non-default scanner/CLI
`graphql-review` feature and explicit `--graphql-review --profile web-review`
runtime choice create one anonymous scanner child; the reasoner does not create
it. The child deterministically selects at most one exact-origin endpoint and
uses the existing redirect-disabled broker and `RuntimeBudget` for an aliased
`__typename` control, bounded schema-root introspection candidate, and distinct
replay—up to three POST/JSON requests; the complete candidate/replay path uses
one active verification. Committed
typed protocol observations may feed existing API reasoning, but projections
remain `Informational` / `KnowledgeOnly`. There is no mutation, full schema
enumeration, authorization testing, depth/complexity probing, second client, or
WebSocket transport. See [GraphQL surface review](internals/graphql-review.md).

REST read-only review also preserves that boundary. The scanner/CLI
`rest-review` feature and explicit same-run `openapi-review` plus `web-review`
choice are required. Only a replay-stable catalog can constrain one anonymous,
bodyless, exact-origin `GET` with no required inputs. Candidate and replay are
two parent-broker requests and one active verification; a positive surface
observation requires stable successful JSON `Status`, `Fields`, and
value-sensitive `Resources`. It is `Informational` / `KnowledgeOnly` only.
There is no `RestScanner`, second runtime/client/broker/budget, detached pass,
write, credential, cookie, parameter/body materialization, or chaining to
another review family. See [REST read-only review](internals/rest-readonly-review.md).

Resource authorization review follows the same single-scanner rule. The
non-default scanner/CLI `authorization-review` feature and one explicit
`security.authorization-review-policy/v1` file add exactly one native action
to `WebAssessmentRuntime`. The operator supplies one exact-origin JSON `GET`
resource plus distinct primary and peer credentials through the existing
bounded env/file/stdin input boundary. The action uses the parent broker,
`RuntimeBudget`, exact-origin authority, cancellation, deadline, evidence
registry, completeness lifecycle, and final report for four ordered views:
primary candidate, peer candidate, primary replay, and peer replay. Those four
dispatches are one logical active verification: the lease is charged when the
primary replay begins, while the peer replay is passive-accounted in the same
active decision phase.

No separate authorization scanner, nested Standard runtime, direct client,
capability-owned authority or budget, detached pass, or independently finalized
report exists. The only principal-varying request material is the complete
`Authorization` header; requests are bodyless `GET`, carry no cookies, disable
redirects and retries, and never mutate or enumerate identifiers. Positive
projection requires both role replays and both cross-principal rounds to match
in `Status`, `Fields`, and value-sensitive `Resources`. At most one
`authorization.resource-cross-principal-equivalence@1` item can be emitted,
with `NeedsReview` disposition and `KnowledgeOnly` authority. It is not a
confirmed IDOR, BOLA, authorization bypass, or secure-negative result. The
existing exact-root authorization-context compatibility path retains its
public types, two-request accounting, evidence identity, and report shape. See
[Resource authorization differential review](internals/authorization-differential-review.md).

HTTP execution emits normalized protocol observations for API reasoning:
validated lowercase media-type essences, an explicit JSON-compatibility flag,
and bounded path segments. A host-paired comparison becomes an
`ApiVisibilityObservation` containing one pseudonymous evidence record and one
stable, evidence-backed `api.visibility.resource-scope` edge. The knowledge
base's `insert_evidence_with_relation` operation preflights and commits that
pair under one write lock, so an identity or linkage conflict cannot leave an
orphaned half of the bundle. This is storage consistency, not proof that a
producer's comparison is true.

`api_evidence` is the pure Evidence Engine boundary for paired JSON views. It
canonicalizes under explicit hard ceilings, retains only raw-value-free
signatures, and produces the transport-neutral comparison contract. The
`api_observation` ingress then validates the expected resource, commits the
evidence/relation pair, applies rules to the isolated comparison subject, and
returns an auditable receipt. It does not weaken the decision runner's rule that
executor evidence must match the outstanding case subject. Resource-scoped
review is a cursor-bounded relation projection, not an implicit cross-subject
planner input. Rejected relation shapes consume the page budget and a compiled
ceiling prevents unbounded projection work. Stored relation IDs, endpoints,
custom kinds, and provenance sets also have hard size ceilings; pagination
checks look-ahead on the borrowed index without cloning the next record.

Bayesian contribution aggregation remains an explicit rule-level choice.
`EvidenceCalibration::new` defaults to `Independent`, preserving the behavior
of existing profiles. Each standard API policy likelihood alone selects
`MaxContributions(1)`, limiting retry-driven posterior inflation for one
selector without changing other reasoning profiles.

A rule cycle evaluates every rule against one immutable subject snapshot and
preflights every matched hypothesis before committing the batch. Verifier-owned
`Confirmed` and `Rejected` states are preserved under that same write lock. A
late identity conflict therefore cannot commit only the earlier rule
conclusions or race a terminal verifier transition back to `Supported`.
Subject-local and ontology revisions provide a compare-and-swap boundary; a
stale cycle is re-evaluated under a fixed retry limit and then fails explicitly.
Verifier lifecycle transitions mutate only the latest stored state under the
knowledge lock, preserving concurrent belief and strength updates. Complete
verification reports carry the evaluated subject/ontology revisions; stale
reports are rejected, same-terminal replay is idempotent, and opposite terminal
transitions conflict instead of becoming last-writer-wins.

Planning prepares its session transition on a clone and swaps it only after
planner validation and command construction succeed. A final subject/ontology
revision check holds the knowledge read lock through that short swap, so a stale
plan cannot advance the session. Rule writes still precede planning and remain
append-only. A later planning failure therefore returns a typed reasoning
receipt with exact application write statuses and planner snapshot revisions
while leaving the replayable session unchanged.

Run the machine-enforced boundary locally:

```bash
cargo xtask architecture
```

The command rejects uncompiled source at the virtual workspace root and
undeclared top-level Rust sources in the examples package, validates workspace
dependencies and centrally inherited lint policy through locked Cargo metadata,
inspects protected production imports through the Rust AST, enforces
standard-runtime transport ownership, prevents migrated discovery and
verification phases from reacquiring direct I/O or crossing each other's
authority seam, freezes the remaining built-in legacy direct-I/O inventory,
verifies canonical `lib.rs` module and external-root wiring, and compiles
`termivar-scanner` with no default features. For Lua and distributed coordination,
it also pins independent raw feature closures, private modules and exact root
reexports, public symbol/constant inventories, private ownership snapshots,
ordered/integer-only state, absence of ambient filesystem/network/process/time
authority, exact VM construction and text/private-environment loading, and
source fingerprints with adversarial mutations. See
[ADR 0004](adr/0004-reasoning-runtime-boundary.md) and
[ADR 0012](adr/0012-account-delivered-transport-bytes.md), which supersedes
[ADR 0009](adr/0009-host-owned-transport-accounting.md). Planner-selected,
raw-value-free execution strategy references are specified by
[ADR 0010](adr/0010-planner-selected-payload-strategies.md). The scoped legacy
discovery migration is specified by
[ADR 0016](adr/0016-bound-legacy-discovery-authority.md); the separate active
verification authority and claim bridge are specified by
[ADR 0018](adr/0018-bound-legacy-verification-authority.md).
The host-owned, evidence-only plugin contract is specified by
[ADR 0019](adr/0019-host-own-plugin-execution.md). The two Experimental
host-execution contracts are specified by
[ADR 0022](adr/0022-bound-host-lua-and-distributed-execution.md). The additive
profiled assessment-reporting composition and CLI publication boundary are
specified by [ADR 0023](adr/0023-compose-profiled-assessment-reporting.md).
The pre-workspace component-level historical recovery inventory and its
no-runtime boundary are specified by
[ADR 0025](adr/0025-record-historical-scanner-salvage.md). The separate
post-workspace WAF/evasion quarantine inventory is specified by
[ADR 0027](adr/0027-record-post-workspace-waf-evasion-salvage.md); it does not
restore `waf.rs`, the retired adaptive modules, or a transformation dispatcher.
The ledger marks only the typed HTML token-case and inter-token-whitespace
concepts restored by normalization resilience; all blind, unsafe, and
misleading historical behavior retains its prior disposition.

For the ten responsibility-split domains above, the same gate also requires
the reviewed private child-module inventory, pins facade-resident authority,
rejects a responsibility collapsing back into a root facade or moving to a
sibling, rejects parent-facade glob imports, and checks allowed cross-domain
dependencies. These checks preserve the root source facade and its existing
public module or crate-root re-export paths while keeping authority ownership
explicit; they do not declare the Preview or Experimental APIs stable.

## Runtime evidence boundaries

The Rust `1.88.0` runtime-smoke matrix exercises the default CLI and a narrow
loopback-only contract set on Ubuntu, Windows, and macOS. Passing those jobs is
host-native smoke evidence, not platform certification or an all-features
release claim.

The `compat/current-head/` workspace uses one dedicated lockfile and four
separately tested packages for default core, deterministic assessment/reporting,
the Legacy `ScannerSdk` facade, and plugin API 0.2 against the same checkout.
They are same-revision source-shape evidence only: they establish neither
cross-version compatibility nor external adoption. See
[Public API compatibility status](public-api-compatibility.md).

The endpoint harness runs the real `WebAssessmentRuntime` only against its
hard-coded loopback fixture. Initial controlled evidence for source commit
`27321efbbf49cb2adbc72afb699d1b31ea407486` is retained from
[workflow run 33292247976](https://github.com/ITherso/venom/actions/runs/33292247976),
with [human-readable](reports/benchmarks/27321ef-endpoint-assessment.md) and
[machine-readable](reports/benchmarks/27321ef-endpoint-assessment.json)
records. One controlled run is not an SLA, capacity certification, accepted
repeatable baseline, or regression threshold.

## Dependency review

Before adding an edge, ask:

- Is the type transport-neutral and behavior-free enough for `termivar-core`?
- Can the behavior live behind an existing trait?
- Does any API, dashboard, database, or deployment type leak into scanner logic?
- Can the module be tested without starting the CLI, API, proxy, or web panel?

## Known alpha debt

- Native plugin execution is linked and in-process, with no sandbox, dynamic
  discovery, signing, or stable compatibility baseline. It remains separate
  from both CLI orchestration paths.
- The ordered phase runner still exposes a raw HTTP client to phase one and
  custom extensions and is not covered as a whole by
  `StandardWebDecisionRuntime` or `RuntimeBudget`. Phases two through four use a
  separate bounded passive discovery authority and phases five through nine a
  separate bounded active-verification authority; the directory phase still
  requires the explicit `--legacy-directory-fuzz` option.
- Dashboard, compliance, and the implemented Experimental distributed and Lua
  host APIs still live in `termivar-scanner`; neither execution API has a
  repository runtime caller, stable compatibility baseline, or production
  deployment contract.
- Several optional modules expose broad APIs that require stability review.
- `DecisionExecutionLimits` still names an HTTP response-body allowance in a
  generic executor request; it should become a transport-neutral resource
  allowance before extracting runner contracts.
