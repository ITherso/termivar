# Project Status

The latest published release is the experimental **v0.10.0-alpha.1** prerelease. Current `main` is the unreleased `0.10.0-alpha.2` development line; the published binaries do not include its later changes. The historical **v0.9.0-alpha** release under the former Venom name predates the remediated runtime. Termivar is an experimental Rust security-testing project centered on a bounded deterministic decision runtime, and it is not production-ready.

## Why alpha

- Default `termivar-core` is a Stable candidate, not a stable-version promise.
  The deterministic assessment/reporting APIs and evidence-only plugin API 0.2
  remain Preview, while `ScannerSdk` is a Legacy facade. Four separately
  resolved current-head consumers prove only same-revision compilation; they
  do not select a v1 baseline, promise a stable ABI, or demonstrate external
  adoption. Plugins are linked, in-process extensions that receive a
  host-owned bounded context and record observations; Termivar ships no stock
  detector plugins, and plugin output is not an automatic finding.
- The default `termivar scan` command exercises the conservative deterministic single-resource runtime; its operational outcomes are not findings or vulnerability verdicts. Explicit `web-review` adds bounded exact-origin discovery plus passive and matched low-risk review under the same host-owned authority. A separately explicit, exact-root authorization-context pair reads secret material only from an environment variable, file, stdin, or a library host; it retains one atomic comparison and can produce at most `NeedsReview`. Native actions remain KnowledgeOnly. The historical heuristic runner is separately feature-gated and requires explicit acknowledgement. Its phases 2–4 share bounded passive discovery and phases 5–9 share a distinct bounded active-verification authority. Phase one and custom extensions can still perform raw I/O, so whole-run accounting remains `Unmetered`; the narrower phase-5-to-9 authority must not be mistaken for `RuntimeBudget` coverage.
- The non-exhaustive, constructor-owned `ScanContext` transition is included in `v0.10.0-alpha.1`; an accepted post-transition scanner compatibility baseline remains outstanding. This intentional change from the former tagged struct-literal contract is not a patch-compatibility claim.
- Lua execution and distributed coordination are implemented Experimental,
  opt-in host-library contracts with no repository runtime caller. Lua provides
  cooperative in-process VM limits rather than process isolation; distributed
  state is process-local and deterministic only for a fixed accepted command
  order, with no transport, persistence, or multi-node control plane.
- Criterion and fuzz baselines exist, and one controlled endpoint workflow run
  records the fixed 100/1,000-endpoint and 10,000-request workloads with three
  measured samples. That record establishes intra-run variance only; a
  repeatable accepted performance baseline and inter-run variance remain
  incomplete.
- No independent security audit has been completed.
- Upgrade compatibility, long-term support, and operational service-level objectives are not defined.
- External adopter and contributor feedback is still limited.

## v1 release gates

| Gate | Current evidence | Exit criterion | Tracking | Target milestone |
| --- | --- | --- | --- | --- |
| Stable SDK and plugin contracts | Pinned `termivar-core` patch gate, Scanner construction ADR/migration, and four same-revision current-head consumer fixtures; no accepted Scanner/plugin cross-version baseline | Public contracts documented, baselined across accepted versions, and protected by compatibility and deprecation policy | [#4](https://github.com/ITherso/termivar/issues/4) | v1.0 |
| Repeatable performance baseline | Historical Criterion microbaseline plus one controlled endpoint workflow run with intra-run variance; thresholds remain null | Repeat comparable 100/1,000-endpoint and 10,000-request CPU, RAM, latency, and throughput runs on a pinned hardware class and review inter-run variance before accepting a baseline | [#5](https://github.com/ITherso/termivar/issues/5) | v1.0 |
| Fuzzing maturity | Scheduled bounded campaigns and committed baseline | Expand corpus/coverage, retain crash artifacts, and document a repeatable triage path | Backlog | v1.0 |
| Security readiness | CodeQL, `cargo audit`, `cargo deny`, private reporting policy | Close audit-readiness gaps and publish the scope/outcome of an independent review | [#6](https://github.com/ITherso/termivar/issues/6) | v1.0 |
| Distributed deployment semantics | Bounded process-local coordinator with explicit revisions/time, fenced leases, fixed retry/recovery policy, and bounded result retention | Define authenticated transport and wire compatibility, durability/restart reconciliation, coordinator epochs, background operation, and production evidence | [#7](https://github.com/ITherso/termivar/issues/7) | v1.1 |
| Adoption evidence | Examples and generated starters are internal evidence only | Validate a version-pinned integration with at least one independent downstream user or project, including compatibility feedback and a documented external result | [#63](https://github.com/ITherso/termivar/issues/63) | v1.0 |
| Upgrade lifecycle | Pre-stable plugin policy | Define supported release lines, deprecation windows, and migration requirements | [#8](https://github.com/ITherso/termivar/issues/8) | v1.0 |

## Active blockers

The following conditions block a stable v1.0 claim:

1. Scanner SDK and plugin contracts still lack an accepted stable baseline and compatibility window; the core-only gate does not close this blocker ([#4](https://github.com/ITherso/termivar/issues/4)).
2. Only one controlled endpoint-scale workflow record exists; there is no
   repeatable accepted baseline or reviewed inter-run variance
   ([#5](https://github.com/ITherso/termivar/issues/5)).
3. No independent security assessment ([#6](https://github.com/ITherso/termivar/issues/6)).
4. Insufficient independent external adoption evidence for a version-pinned SDK or plugin integration ([#63](https://github.com/ITherso/termivar/issues/63)).
5. No documented upgrade and deprecation lifecycle for stable consumers ([#8](https://github.com/ITherso/termivar/issues/8)).

Distributed multi-node production readiness is tracked separately for v1.1 and does not block a focused single-node v1.0 SDK release if its Experimental, in-process-only status remains explicit.

## Evidence

- [Published v0.10.0-alpha.1 prerelease](https://github.com/ITherso/termivar/releases/tag/v0.10.0-alpha.1)
- [Historical former-name v0.9.0-alpha release](https://github.com/ITherso/venom/releases/tag/v0.9.0-alpha)
- [Feature lifecycle](FEATURES.md)
- [Repository health](docs/repository-health.md)
- [Benchmark evidence](docs/benchmarks.md)
- [Initial endpoint-assessment evidence](docs/reports/benchmarks/27321ef-endpoint-assessment.md)
- [Fuzzing evidence](docs/fuzzing.md)
- [Public API compatibility status](docs/public-api-compatibility.md)
- [Plugin API policy](docs/plugin-api-policy.md)
- [Security policy](SECURITY.md)
- [Runtime-truth remediation closure](docs/audits/runtime-truth-remediation-closure.md)

Milestones and the [Termivar Roadmap project](https://github.com/users/ITherso/projects/1) are the operational source of truth for planned work. This document defines release gates; it is not a delivery guarantee.
