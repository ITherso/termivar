# Venom feature lifecycle

This document is the capability map for Venom `0.9.0-alpha`. It records what exists, how mature it is, and the most important limitation. It is not a completion score or a production-readiness claim.

## Lifecycle labels

| Label | Meaning |
| --- | --- |
| Beta | Usable in authorized research workflows, with pre-stable APIs |
| Preview | Implemented for evaluation; contracts and behavior may change |
| Experimental | Research surface with limited validation and stability guarantees |
| Planned | Direction is documented, but no shipped contract is promised |

## Foundation

| Capability | Lifecycle | Current boundary |
| --- | --- | --- |
| Core contracts | Beta | Shared events, findings, configuration, models, and errors in `venom-core` |
| Scanner pipeline | Beta | Ordered phases, cancellation, aggregation, and reporting in `venom-scanner` |
| CLI | Beta | Composition root for scans, API hosting, and proxy commands |
| HTTP API | Beta | Application transport over core and scanner contracts |
| Proxy | Experimental | HTTP/TLS interception for explicitly authorized environments |

## Extensibility and analysis

| Capability | Lifecycle | Current boundary |
| --- | --- | --- |
| Native plugins | Preview | Source-level Rust trait and registry; no runtime crate discovery or stable ABI |
| Plugin starter | Preview | `cargo-generate` template under `templates/venom-plugin` |
| Lua execution | Preview | Script lifecycle and limits remain pre-stable |
| Anomaly detection | Experimental | Heuristic scoring requires manual validation |
| Detection phases | Beta | Recon, crawl, directory, SQLi, XSS, SSTI, LFI, XXE, and SSRF-oriented modules |

## Scale and product surfaces

| Capability | Lifecycle | Current boundary |
| --- | --- | --- |
| Distributed execution | Experimental | Worker, queue, and aggregation APIs may change |
| Monitoring | Preview | Runtime metrics and event projections are not a performance SLA |
| Dashboard | Experimental | Web application remains an outward product concern |
| Compliance | Preview | Optional models; not a certification or audit result |
| Threat intelligence | Preview | Optional correlation surface with unstable provider contracts |

## Quality evidence

| Evidence | State | Notes |
| --- | --- | --- |
| Unit, integration, and doc tests | Automated | GitHub Actions runs tests plus stable, beta, and nightly compatibility checks |
| Source coverage | Automated | Tarpaulin output is uploaded to Codecov |
| Criterion microbenchmarks | Automated | Artifacts are produced; historical reports are not yet published |
| Compile time, binary size, and peak memory | Automated | Runner-local regression signals are stored as workflow artifacts |
| Fuzzing | Partial | Parser targets exist; a continuous bounded campaign is pending |
| Mutation score | Missing | No automated mutation baseline has been published |
| Independent security audit | Missing | No external audit has been completed |
| Stable public API | Preview | Compatibility is not guaranteed before a stable release |

See [Architecture](docs/architecture.md) for ownership rules, [Quality metrics](docs/quality-metrics.md) for measurement policy, and [Security](SECURITY.md) for responsible disclosure.
