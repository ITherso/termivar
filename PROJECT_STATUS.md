# Project Status

The latest tagged Venom release is **v0.9.0-alpha**; `main` targets the next Preview release. Venom is a modular Rust-based penetration testing framework focused on research and extensibility, and it is not production-ready.

## Why alpha

- The Scanner SDK and plugin API are public and usable, but their contracts may still change before v1.
- `ScanContext` now has an accepted non-exhaustive, constructor-owned policy, but the intentional transition from the tagged struct-literal contract still needs a new Preview release and post-transition scanner baseline.
- The distributed worker pool is an in-process scheduling preview, not a durable multi-node control plane.
- Criterion and fuzz baselines exist, but endpoint-scale CPU, memory, latency, and throughput evidence is incomplete.
- No independent security audit has been completed.
- Upgrade compatibility, long-term support, and operational service-level objectives are not defined.
- External adopter and contributor feedback is still limited.

## v1 release gates

| Gate | Current evidence | Exit criterion | Tracking | Target milestone |
| --- | --- | --- | --- | --- |
| Stable SDK and plugin contracts | Pinned `venom-core` patch gate plus Scanner construction ADR and migration; post-transition scanner baseline pending | Public contracts documented, baselined, and protected by compatibility tests | [#4](https://github.com/ITherso/venom/issues/4) | v1.0 |
| Reproducible performance report | Criterion microbaseline | Publish controlled 100/1,000 endpoint and 10,000-request CPU, RAM, latency, and throughput results | [#5](https://github.com/ITherso/venom/issues/5) | v1.0 |
| Fuzzing maturity | Scheduled bounded campaigns and committed baseline | Expand corpus/coverage, retain crash artifacts, and document a repeatable triage path | Backlog | v1.0 |
| Security readiness | CodeQL, `cargo audit`, `cargo deny`, private reporting policy | Close audit-readiness gaps and publish the scope/outcome of an independent review | [#6](https://github.com/ITherso/venom/issues/6) | v1.0 |
| Distributed semantics | In-memory queue, worker scoring, retry, heartbeat primitives | Define durability, leases, retry ownership, failure recovery, and transport boundaries | [#7](https://github.com/ITherso/venom/issues/7) | v1.1 |
| Adoption evidence | Examples, generated starters, and a scoped first issue | Validate the 10-minute path with at least one external adopter or contributor | [#3](https://github.com/ITherso/venom/issues/3) | v1.0 |
| Upgrade lifecycle | Pre-stable plugin policy | Define supported release lines, deprecation windows, and migration requirements | [#8](https://github.com/ITherso/venom/issues/8) | v1.0 |

## Active blockers

The following conditions block a stable v1.0 claim:

1. Scanner SDK and plugin contracts still lack an accepted stable baseline and compatibility window; the core-only gate does not close this blocker ([#4](https://github.com/ITherso/venom/issues/4)).
2. No controlled endpoint-scale performance report ([#5](https://github.com/ITherso/venom/issues/5)).
3. No independent security assessment ([#6](https://github.com/ITherso/venom/issues/6)).
4. Insufficient external adoption evidence for the SDK and plugin workflow ([#3](https://github.com/ITherso/venom/issues/3)).
5. No documented upgrade and deprecation lifecycle for stable consumers ([#8](https://github.com/ITherso/venom/issues/8)).

Distributed multi-node production readiness is tracked separately for v1.1 and does not block a focused single-node v1.0 SDK release if its Preview status remains explicit.

## Evidence

- [v0.9.0-alpha release](https://github.com/ITherso/venom/releases/tag/v0.9.0-alpha)
- [Feature lifecycle](FEATURES.md)
- [Repository health](docs/repository-health.md)
- [Benchmark evidence](docs/benchmarks.md)
- [Fuzzing evidence](docs/fuzzing.md)
- [Plugin API policy](docs/plugin-api-policy.md)
- [Security policy](SECURITY.md)

Milestones and the [Venom Roadmap project](https://github.com/users/ITherso/projects/1) are the operational source of truth for planned work. This document defines release gates; it is not a delivery guarantee.
