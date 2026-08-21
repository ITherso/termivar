# Venom feature lifecycle

This document maps the current unreleased source state, whose package version is `0.10.0-alpha.1`. The published `v0.9.0-alpha` tag predates this remediation and is not the executable represented here. This map records what exists, how mature it is, and the most important limitation; it is not a completion score or a production-readiness claim.

A compiled module is not necessarily a runtime feature. The [runtime map](docs/internals/runtime-map.md) records whether each major surface participates in the default deterministic `venom scan`, the feature-gated `venom legacy-scan`, an opt-in library host, or no repository execution path.

## Lifecycle labels

| Label | Meaning |
| --- | --- |
| Beta | Usable in authorized research workflows, with pre-stable APIs |
| Preview | Implemented for evaluation; contracts and behavior may change |
| Experimental | Research surface with limited validation and stability guarantees |
| Legacy | Maintained migration surface that is not the target runtime architecture |
| Unsupported | Code or an adapter exists, but no supported runnable product contract is offered |
| Planned | Direction is documented, but no shipped contract is promised |

## Foundation and executable surfaces

| Capability | Lifecycle | Current boundary |
| --- | --- | --- |
| Core contracts | Beta | Default `venom-core` exposes transport-neutral evidence, reasoning, ontology, outcome, predicate, and run-report records; its pre-quarantine config, error, event, finding, HTTP, vulnerability, and result facade requires non-default `legacy-contracts` |
| Deterministic decision runtime | Preview | Bounded typed evidence, reasoning, planning, execution, verification, Experience, and continuation in `venom-scanner` |
| `venom scan` | Preview | Default bounded CLI profile over `StandardWebDecisionRuntime`; text, explain, and historically named `decision-scan/v1` JSON output |
| `venom decision-scan` | Deprecated | Compatibility alias for `venom scan`; identical command definition and deterministic engine |
| `venom legacy-scan` | Legacy | Historical mixed-authority pipeline: phases 2–4 share bounded passive discovery and phases 5–9 share a separate bounded active-verification broker; phase one and custom phases may retain direct I/O, so the whole run is `Unmetered`; requires `legacy-scanner` plus explicit acknowledgement |
| Scanner SDK | Preview | Application-defined phases composed through `ScannerSdk` and a generated starter |
| HTTP API adapter | Unsupported | Absent by default; opt-in `api-adapter` exposes a command that fails nonzero because no listener is implemented |
| Proxy adapter | Experimental | Absent by default; opt-in `proxy-adapter` is a fixed-upstream TCP relay only, with no `CONNECT`, TLS termination, certificate generation, or HTTP inspection |

## Extensibility and analysis

| Capability | Lifecycle | Current boundary |
| --- | --- | --- |
| Native plugins | Preview | Source-level Rust trait and registry with a host-owned bounded `PluginContext`; plugins record observations rather than findings, no stock detector plugins ship, and there is no runtime crate discovery or stable ABI |
| Plugin starter | Preview | INFO-only trait-boundary fixture under `templates/venom-plugin`, rendered and tested in CI; it makes no security claim |
| Bounded Lua execution | Experimental | Independent opt-in `lua` host-library API: approved-root source snapshots execute in fresh no-standard-library Lua 5.4 VMs under per-execution/registry limits; cooperative in-process controls are not process isolation, and no repository CLI, scanner, or plugin caller exists |
| Platform models | Experimental | Opt-in `platform-models` records, catalogs, and in-memory utilities; no API/auth/persistence/realtime execution path, and callers own collection capacity except where a type states a limit |
| Bounded run-report rendering | Preview | Opt-in `reporting` host-library API transforms typed `RunReport` values under a hard output ceiling; callers pre-redact projected fields, and the renderer has no repository/default CLI caller, I/O, persistence, redaction, risk/finding synthesis, or verdict authority |
| Legacy discovery phases | Legacy | Crawler, opt-in directory discovery, and parameter discovery share exact-origin redirect-disabled request/time/body limits and atomic typed state; their `INFO` records project as `Unknown`, not findings |
| Legacy verification phases | Legacy | Phases 5–9 share separate exact-origin, bodyless, redirect- and retry-disabled request/time/body limits accounted at the `Active` stage; this authority is not the standard runtime's `RuntimeBudget` |
| Legacy verification claims | Legacy | Reproduced SQL diagnostics/timing, template arithmetic, and an explicitly configured benign local-file canary may project only knowledge-only `NeedsReview`; exact reflection remains `Unknown`, XXE is inert, and configured SSRF OOB delivery records a receipt without a callback conclusion |
| Legacy raw client | Legacy | Reconnaissance and host-defined custom phases may use direct I/O; this prevents whole-run request/body accounting even though built-in phases 2–9 use bounded authorities |
| Detection and deviation records | Experimental | Caller-supplied signal definitions, technique scores, and normalized deviation dimensions are validated or catalogued only; Venom does not calculate or classify them |
| External-model records | Experimental | Opt-in `ml` serializable records only; no training, clustering, classification, success estimation, or stage execution |
| Semantic extraction | Preview | Evidence-only, bounded library surface; not automatically composed into either CLI scan command |
| API predicate vocabulary | Preview | Canonical descriptors, normalized media/path observations, and resource-scope bundles in `venom-core` |
| JSON/GraphQL reasoning | Preview | Opt-in deterministic fingerprinting; paired differences remain review hypotheses, not vulnerability verification |
| API visibility evidence | Preview | Bounded raw-value-free comparison and atomic ingestion; hosts remain responsible for authorization and pair construction |

## Scale and adjacent product surfaces

| Capability | Lifecycle | Current boundary |
| --- | --- | --- |
| Distributed coordination | Experimental | Independent opt-in `distributed` host-library state machines with bounded ordered task/worker/result state, explicit logical time/revisions, leases, retry/recovery, and deterministic replay for a fixed accepted command order; no transport, authentication, serialization, persistence, background execution, exactly-once, or multi-node control plane |
| Monitoring | Experimental | Opt-in caller-supplied profiles and comparisons; not telemetry collection or a performance SLA |
| Dashboard | Experimental | Disconnected web preview; not a scan-runtime component |
| Compliance | Experimental | Optional caller-supplied catalogs and reports; not a certification or audit result |
| Threat intelligence | Experimental | Optional feed/rule records and catalogs; no repository correlation or alert execution path |
| Scanning profile files | Experimental | Illustrative configuration samples; no CLI loader or active scan integration |

## Quality evidence

| Evidence | State | Notes |
| --- | --- | --- |
| Unit, integration, doc, security, and template tests | Automated | GitHub Actions also exercises architecture boundaries and Rust compatibility |
| Source coverage | Calibration automated | Pinned Tarpaulin emits Cobertura and deterministic repository-owned summaries; CI attempts a best-effort advisory Codecov upload whose tokenless availability is not enforced, changed-file presence fails closed, and no accepted numeric floor is committed yet |
| Rust compatibility | Automated | MSRV 1.88 plus stable, beta, and nightly |
| Public API compatibility | Automated, scoped | Blocking SemVer comparison covers `venom-core`, not every workspace crate |
| Criterion and build metrics | Automated | Runner-local artifacts exist; controlled endpoint-scale results remain missing |
| Fuzzing | Scheduled and bounded | Four product-semantic and five parser targets; PR seed replay/compile plus scheduled/manual campaigns |
| Mutation testing | Scoped and evidenced | Selected semantic contracts have manual campaigns; no permanent farm or project-wide score |
| Independent security audit | Missing | No external audit has been completed |
| Stable public API | Preview | Compatibility is not guaranteed before a stable release |

See [Architecture](docs/architecture.md) for ownership rules, [Quality metrics](docs/quality-metrics.md) for measurement policy, [Repository health](docs/repository-health.md) for configured controls, and [Security](SECURITY.md) for responsible disclosure.
