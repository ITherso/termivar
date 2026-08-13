# Venom feature lifecycle

This document is the capability map for Venom `0.9.0-alpha`. It records what exists, how mature it is, and the most important limitation. It is not a completion score or a production-readiness claim.

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
| Core contracts | Beta | Shared events, findings, configuration, models, errors, and predicate vocabulary in `venom-core` |
| Deterministic decision runtime | Preview | Bounded typed evidence, reasoning, planning, execution, verification, Experience, and continuation in `venom-scanner` |
| `venom scan` | Preview | Default bounded CLI profile over `StandardWebDecisionRuntime`; text, explain, and historically named `decision-scan/v1` JSON output |
| `venom decision-scan` | Deprecated | Compatibility alias for `venom scan`; identical command definition and deterministic engine |
| `venom legacy-scan` | Legacy | Historical mixed-authority pipeline: phases 2–4 share a bounded discovery broker, while phases 1 and 5–9 retain direct I/O outside `StandardWebDecisionRuntime` and `RuntimeBudget`; the whole run is `Unmetered` and requires `legacy-scanner` plus explicit acknowledgement |
| Scanner SDK | Preview | Application-defined phases composed through `ScannerSdk` and a generated starter |
| HTTP API adapter | Unsupported | Absent by default; opt-in `api-adapter` exposes a command that fails nonzero because no listener is implemented |
| Proxy adapter | Experimental | Absent by default; opt-in `proxy-adapter` is a fixed-upstream TCP relay only, with no `CONNECT`, TLS termination, certificate generation, or HTTP inspection |

## Extensibility and analysis

| Capability | Lifecycle | Current boundary |
| --- | --- | --- |
| Native plugins | Preview | Source-level Rust trait and registry; no runtime crate discovery or stable ABI; not merged into default `scan` |
| Plugin starter | Preview | `cargo-generate` template under `templates/venom-plugin`, rendered and tested in CI |
| Lua execution | Preview | Opt-in, host-owned script surface; not part of either CLI scan runtime |
| Legacy discovery phases | Legacy | Crawler, opt-in directory discovery, and parameter discovery share exact-origin redirect-disabled request/time/body limits and atomic typed state; their `INFO` records project as `Unknown`, not findings |
| Other legacy phases | Legacy | Recon, SQLi, XSS, SSTI, LFI/XXE, and SSRF heuristics retain raw direct I/O; directory discovery is a second explicit opt-in within the ordered runner |
| Anomaly detection | Experimental | Heuristic scoring requires manual validation and is not on a default scan path |
| Semantic extraction | Preview | Evidence-only, bounded library surface; not automatically composed into either CLI scan command |
| API predicate vocabulary | Preview | Canonical descriptors, normalized media/path observations, and resource-scope bundles in `venom-core` |
| JSON/GraphQL reasoning | Preview | Opt-in deterministic fingerprinting; paired differences remain review hypotheses, not vulnerability verification |
| API visibility evidence | Preview | Bounded raw-value-free comparison and atomic ingestion; hosts remain responsible for authorization and pair construction |

## Scale and adjacent product surfaces

| Capability | Lifecycle | Current boundary |
| --- | --- | --- |
| Distributed execution | Experimental | In-process worker, queue, and aggregation APIs; no durable multi-node control plane |
| Monitoring | Preview | Opt-in metrics and event projections; not a performance SLA |
| Dashboard | Experimental | Disconnected web preview; not a scan-runtime component |
| Compliance | Preview | Optional models; not a certification or audit result |
| Threat intelligence | Preview | Optional correlation surface with unstable provider contracts |
| Scanning profile files | Experimental | Illustrative configuration samples; no CLI loader or active scan integration |

## Quality evidence

| Evidence | State | Notes |
| --- | --- | --- |
| Unit, integration, doc, security, and template tests | Automated | GitHub Actions also exercises architecture boundaries and Rust compatibility |
| Source coverage | Automated | Tarpaulin output is uploaded to Codecov; no minimum percentage is claimed |
| Rust compatibility | Automated | MSRV 1.88 plus stable, beta, and nightly |
| Public API compatibility | Automated, scoped | Blocking SemVer comparison covers `venom-core`, not every workspace crate |
| Criterion and build metrics | Automated | Runner-local artifacts exist; controlled endpoint-scale results remain missing |
| Fuzzing | Scheduled and bounded | Four product-semantic and five parser targets; PR seed replay/compile plus scheduled/manual campaigns |
| Mutation testing | Scoped and evidenced | Selected semantic contracts have manual campaigns; no permanent farm or project-wide score |
| Independent security audit | Missing | No external audit has been completed |
| Stable public API | Preview | Compatibility is not guaranteed before a stable release |

See [Architecture](docs/architecture.md) for ownership rules, [Quality metrics](docs/quality-metrics.md) for measurement policy, [Repository health](docs/repository-health.md) for configured controls, and [Security](SECURITY.md) for responsible disclosure.
