# Venom feature lifecycle

This document maps the current unreleased source state, whose package version is `0.10.0-alpha.1`. The published `v0.9.0-alpha` tag predates this remediation and is not the executable represented here. This map records what exists, how mature it is, and the most important limitation; it is not a completion score or a production-readiness claim.

A compiled module is not necessarily a runtime feature. The [runtime map](docs/internals/runtime-map.md) records whether each major surface participates in the default deterministic `venom scan`, the feature-gated `venom legacy-scan`, an opt-in library host, or no repository execution path.

## Lifecycle labels

| Label | Meaning |
| --- | --- |
| Stable candidate | Narrow public surface under compatibility review; not an accepted stable-version promise |
| Preview | Implemented for evaluation; contracts and behavior may change |
| Experimental | Research surface with limited validation and stability guarantees |
| Legacy | Maintained migration surface that is not the target runtime architecture |
| Unsupported | Code or an adapter exists, but no supported runnable product contract is offered |
| Planned | Direction is documented, but no shipped contract is promised |

## Foundation and executable surfaces

| Capability | Lifecycle | Current boundary |
| --- | --- | --- |
| Core contracts | Stable candidate | Default `venom-core` exposes transport-neutral evidence, reasoning, ontology, outcome, predicate, and run-report records; this inventory label is not an accepted stable baseline. Its pre-quarantine config, error, event, finding, HTTP, vulnerability, and result facade requires non-default `legacy-contracts` |
| Deterministic decision runtime | Preview | Bounded typed evidence, reasoning, planning, execution, verification, Experience, and continuation in `venom-scanner` |
| `venom scan` | Preview | With no profile, the conservative single-resource command and historically named `decision-scan/v1` JSON remain unchanged. Explicit `baseline` and `web-review` select strict `venom.scan-profile/v1` contracts without creating a second engine |
| Origin assessment runtime | Preview | Explicit `web-review` only: deterministic bounded exact-origin discovery, semantic extraction, defense observation/shadow planning, passive review, the closed native differential catalog, and an optional host-authorized root API context pair share one request/budget/cancellation/scope authority; redirects remain disabled and discovery never silently crosses origin |
| Typed assessment items | Preview | Product projection distinguishes `Informational`, `NeedsReview`, and verifier-authorized `Confirmed`. Passive review and parser-classified comment/text/ordinary-attribute reflection are informational; matched credentialed CORS, exact candidate-specific redirect, repeatable SQL/SSTI structural differentials, typed URI/style/handler/script/embedded-HTML reflection placement, and one atomic authorization-context visibility difference can be `NeedsReview` only. Eligible discovered resources reuse stable opaque non-secret subject identities, and no native web-review capability can produce `Confirmed` |
| Native low-risk web review | Preview | Explicit `web-review` only. Matched CORS, optional allowlisted redirect, one bounded scanner-marker reflection pair, one SQL quote-balance review, and one initial versioned SSTI arithmetic family run through the existing Standard runtime and shared broker. The bounded `html5ever` classifier plus fail-closed source passes provide typed attribute quote and JavaScript lexical anchors. V1 executes the HTML-text boundary, source/DOM-cross-validated ordinary, URI, or event-handler attribute boundaries, and exact single-/double-quoted or template-text JavaScript lexical boundaries. Positive script evidence requires exact ordered inert comment tokens outside the original string/template context on the same inline classic/module host with a clean control; expression, comment, and regex contexts remain metadata-only. Selection stays capped at one three-request child. Structural control is `NeedsReview` only—there is no JavaScript, event, navigation, browser execution, or XSS confirmation. Redirects are never followed, and no native action can confirm a vulnerability |
| `venom decision-scan` | Deprecated | Compatibility alias for `venom scan`; identical command definition and deterministic engine |
| `venom legacy-scan` | Legacy | Historical mixed-authority pipeline: phases 2–4 share bounded passive discovery and phases 5–9 share a separate bounded active-verification broker; phase one and custom phases may retain direct I/O, so the whole run is `Unmetered`; requires `legacy-scanner` plus explicit acknowledgement |
| Scanner SDK | Legacy | Historical application-defined phases composed through `ScannerSdk` and a generated starter; same-revision compilation does not make this facade a stable SDK baseline |
| HTTP API adapter | Unsupported | Absent by default; opt-in `api-adapter` exposes a command that fails nonzero because no listener is implemented |
| Proxy adapter | Experimental | Absent by default; opt-in `proxy-adapter` is a fixed-upstream TCP relay only, with no `CONNECT`, TLS termination, certificate generation, or HTTP inspection |

## Extensibility and analysis

| Capability | Lifecycle | Current boundary |
| --- | --- | --- |
| Native plugins | Preview | Source-level Rust trait and registry with a host-owned bounded `PluginContext`; plugins record observations rather than findings, no stock detector plugins ship, and there is no runtime crate discovery or stable ABI |
| Plugin starter | Preview | INFO-only trait-boundary fixture under `templates/venom-plugin`, rendered and tested in CI; it makes no security claim |
| Exploit foundation | Preview | Independent `venom-exploit` validates bounded manifests/catalogs and offers a disconnected non-default orchestration API with host-minted grants, deterministic plans, typed permits/receipts, and separate impact/cleanup truth. Only an in-memory canary test fixture executes; there is no real exploit, production adapter, scanner/CLI/API/proxy integration, automatic AssessmentItem transition, package authenticity, or sandbox |
| Bounded Lua execution | Experimental | Independent opt-in `lua` host-library API: approved-root source snapshots execute in fresh no-standard-library Lua 5.4 VMs under per-execution/registry limits; cooperative in-process controls are not process isolation, and no repository CLI, scanner, or plugin caller exists |
| Platform models | Experimental | Opt-in `platform-models` records, catalogs, and in-memory utilities; no API/auth/persistence/realtime execution path, and callers own collection capacity except where a type states a limit |
| Bounded report rendering | Preview | Standalone `reporting` still transforms host-pre-redacted typed `RunReport` values. With `scanning + reporting`, completed runtime-owned web-review truth is composed into typed assessment reports; the CLI uses the central renderer for JSON, CSV, HTML, and Markdown. Rendering has no I/O, persistence, risk synthesis, or verdict invention |
| Legacy discovery phases | Legacy | Crawler, opt-in directory discovery, and parameter discovery share exact-origin redirect-disabled request/time/body limits and atomic typed state; their `INFO` records project as `Unknown`, not findings |
| Legacy verification phases | Legacy | Phases 5–9 share separate exact-origin, bodyless, redirect- and retry-disabled request/time/body limits accounted at the `Active` stage; this authority is not the standard runtime's `RuntimeBudget` |
| Legacy verification claims | Legacy | Reproduced SQL diagnostics/timing, template arithmetic, and an explicitly configured benign local-file canary may project only knowledge-only `NeedsReview`; exact reflection remains `Unknown`, XXE is inert, and configured SSRF OOB delivery records a receipt without a callback conclusion |
| Legacy raw client | Legacy | Reconnaissance and host-defined custom phases may use direct I/O; this prevents whole-run request/body accounting even though built-in phases 2–9 use bounded authorities |
| Detection and deviation records | Experimental | Caller-supplied signal definitions, technique scores, and normalized deviation dimensions are validated or catalogued only; Venom does not calculate or classify them |
| External-model records | Experimental | Opt-in `ml` serializable records only; no training, clustering, classification, success estimation, or stage execution |
| Semantic extraction | Preview | Evidence-only, bounded library surface; composed after committed evidence only by explicit `web-review`, while the no-profile and `baseline` paths remain unchanged |
| Defense composition | Preview | Explicit `web-review` records observation and shadow planning. Enforcement is default off and can only suppress/narrow existing work when explicitly selected; it cannot add actions, raise intensity, or expand scope/budget |
| API predicate vocabulary | Preview | Canonical descriptors, normalized media/path observations, and resource-scope bundles in `venom-core` |
| JSON/GraphQL reasoning | Preview | Opt-in deterministic fingerprinting; paired differences remain review hypotheses, not vulnerability verification |
| API visibility evidence | Preview | Bounded raw-value-free comparison and atomic ingestion. An explicit exact-root `web-review` option accepts one complete Authorization value only from environment, a regular non-symlink file, stdin, or a library host; CLI credentialed review requires HTTPS except for numeric-IP loopback fixtures, and preflight failures precede the secret read. Anonymous and authorized legs share the assessment authority. Equal visibility emits no item, and a difference remains one atomic `NeedsReview` reference rather than invented leg evidence. Hosts remain responsible for authorization, stdin lifecycle, and context meaning |

## Scale and adjacent product surfaces

| Capability | Lifecycle | Current boundary |
| --- | --- | --- |
| Distributed coordination | Experimental | Independent opt-in `distributed` host-library state machines with bounded ordered task/worker/result state, explicit logical time/revisions, leases, retry/recovery, and deterministic replay for a fixed accepted command order; no transport, authentication, serialization, persistence, background execution, exactly-once, or multi-node control plane |
| Monitoring | Experimental | Opt-in caller-supplied profiles and comparisons; not telemetry collection or a performance SLA |
| Dashboard | Experimental | Disconnected web preview; not a scan-runtime component |
| Compliance | Experimental | Optional caller-supplied catalogs and reports; not a certification or audit result |
| Threat intelligence | Experimental | Optional feed/rule records and catalogs; no repository correlation or alert execution path |
| Scan profile contract | Preview | Exactly two named built-ins, `baseline` and `web-review`, are CLI-wired under strict `venom.scan-profile/v1`. Custom profile files and merge/override semantics are not implemented; historical aspirational profile samples are removed |

## Quality evidence

| Evidence | State | Notes |
| --- | --- | --- |
| Unit, integration, doc, security, and template tests | Automated | GitHub Actions also exercises architecture boundaries and Rust compatibility |
| Source coverage | Enforced, scoped | Pinned Tarpaulin's LLVM backend enforces the accepted exact ratio of 21,439/24,842 observed source lines on the aggregate and coverable changed lines; `venom.coverage.v2` evidence binds a normalized line-state digest, changed files and path/blob-stable omissions fail closed, and advisory Codecov upload remains best-effort |
| Rust compatibility | Automated | MSRV 1.88 plus stable, beta, and nightly |
| Cross-platform runtime smoke | Automated, scoped | Focused Rust 1.88 default-CLI, loopback, wire, origin, redirect, and report-path checks run on Ubuntu, Windows, and macOS; this is not platform certification or the full matrix |
| Public API compatibility | Automated, scoped | Blocking SemVer comparison covers `venom-core`; four separately resolved current-head consumers cover default core, deterministic assessment/reporting, the Legacy Scanner SDK facade, and plugin API 0.2 at the same revision only |
| Criterion and build metrics | Automated | Runner-local compile, binary, memory, and microbenchmark artifacts exist; they are not endpoint-capacity claims |
| Endpoint-scale performance | Initial controlled evidence | One fixed local-fixture workflow run covers 100/1,000 endpoints and 10,000 requests with three measured samples and intra-run variance; no repeatable accepted baseline, threshold, or SLA exists |
| Fuzzing | Scheduled and bounded | Four product-semantic and five parser targets; PR seed replay/compile plus scheduled/manual campaigns |
| Mutation testing | Scoped and evidenced | Selected semantic contracts have manual campaigns; no permanent farm or project-wide score |
| Independent security audit | Missing | No external audit has been completed |
| Workspace-wide stable public API | Missing | Default `venom-core` is a Stable candidate only; deterministic assessment/reporting and plugin API 0.2 are Preview, while `ScannerSdk` is Legacy. No accepted workspace-wide baseline or stable ABI is claimed |

See [Architecture](docs/architecture.md) for ownership rules, [Quality metrics](docs/quality-metrics.md) for measurement policy, [Repository health](docs/repository-health.md) for configured controls, and [Security](SECURITY.md) for responsible disclosure.
