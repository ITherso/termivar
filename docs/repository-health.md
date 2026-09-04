# Repository health

This page records configured repository controls and known gaps. A workflow
definition is tooling evidence, not proof that an arbitrary commit passed, and
no repository control establishes production readiness, legal compliance, or
independent security assurance.

| Control | State | Enforcement or gap |
| --- | --- | --- |
| CodeQL | Configured for JavaScript/TypeScript | Advanced setup analyzes `web/` on relevant changes, a weekly schedule, and manual dispatch; it does not analyze Rust |
| `cargo-audit` | Configured in security CI | One repository-owned runner builds exact `cargo-audit` 0.22.2 with Rust 1.88.0 and the tool's packaged lockfile, verifies that executable, then checks the committed workspace lockfile against the current RustSec advisory database without rewriting it |
| `cargo-deny` | Configured in security CI | The pinned action checks advisories, licenses, bans, and dependency sources against repository policy |
| Trivy | Configured in security CI | SHA-pinned `trivy-action` v0.36.0 runs Trivy v0.70.0 against the repository filesystem for vulnerability, secret, and misconfiguration findings at the declared severity policy |
| Semgrep CE | Configured in security CI | A digest-pinned Semgrep CE image runs declared community rules with metrics disabled |
| Dependabot | Configured | Weekly Cargo, npm, and GitHub Actions update proposals are defined; configuration does not guarantee that an update exists, is safe, or has been merged |
| `cargo-fuzz` | Scheduled and bounded | Four product-semantic and five parser targets replay reviewed seeds and compile on relevant PRs, then run bounded scheduled/manual campaigns; the older [committed parser baseline](reports/fuzzing/7515b79.md) remains evidence only for its recorded commit |
| `cargo-mutants` | Scoped and manual | Selected policy, planner/runtime, and extraction contracts have evidenced review campaigns; no mutation workflow, workspace-wide baseline, or aggregate score is committed |
| Source coverage | Enforced, scoped | Rust `1.88.0` and the explicit LLVM backend of `cargo-tarpaulin 0.37.2` enforce the accepted exact 21,439/24,842 aggregate and changed-line ratio for tracked Rust files under `crates/*/src/**` and `xtask/src/**`; `venom.coverage.v2` binds a normalized line-state digest, changed-file presence is fail-closed, and advisory Codecov upload remains best-effort |
| MSRV | Configured in CI | Workspace packages declare Rust `1.88`; the compatibility matrix also exercises stable, beta, and nightly |
| Cross-platform runtime smoke | Configured in CI | A focused Rust `1.88.0` matrix builds the default CLI and exercises CLI metadata, one deterministic loopback scan, atomic report paths, core wire stability, exact-origin authority, and redirect observation on Ubuntu, Windows, and macOS; it is not platform certification, all-features evidence, or a release-readiness claim |
| SemVer | Configured for `termivar-core` | `cargo xtask semver` compares the all-features core API with the recorded former-name `v0.9.0-alpha` baseline using a patch-compatibility threshold |
| Current-head downstream consumers | Configured in CI | One dedicated lockfile supports four separate package tests for default core, deterministic assessment/reporting, the Legacy Scanner SDK facade, and plugin API 0.2 against the same checkout; this is not cross-version or external-adoption evidence |
| Endpoint-scale evidence | Initial controlled record | The loopback-only real-runtime harness recorded fixed 100-endpoint, 1,000-endpoint, and 10,000-request workloads for source `27321ef` in workflow run `33292247976`; this is not an accepted repeatable baseline, SLA, capacity claim, or regression threshold |
| Architecture boundaries | Configured in CI | `cargo xtask architecture` checks virtual-root source, workspace edges, protected imports, transport-free reasoning, and responsibility ownership behind ten modular root source facades |

## Release evidence

The release workflow defines formatting, architecture, Clippy, workspace-test,
dependency-policy, and cross-platform build gates. `cargo xtask release` runs a
local preflight without tagging or publishing. A release claim must identify
the exact commit and retain the corresponding GitHub Actions result; the
existence of either command is not evidence that it passed.

The separate Tests-workflow runtime-smoke matrix adds host-native execution on
Ubuntu, Windows, and macOS. It uses deterministic loopback fixtures and a small
set of path, scope, redirect, and wire-format checks; it does not replace the
release workflow's artifact builds or establish broad platform support by
configuration alone.

The initial endpoint-scale record is tied to source commit
`27321efbbf49cb2adbc72afb699d1b31ea407486` and
[workflow run 33292247976](https://github.com/ITherso/venom/actions/runs/33292247976).
Its [Markdown](reports/benchmarks/27321ef-endpoint-assessment.md) and
[validated JSON](reports/benchmarks/27321ef-endpoint-assessment.json) retain the
runner, workload, request-accounting, and variance metadata. One controlled
run does not establish an accepted repeatable baseline or a release performance
threshold.

## Public API compatibility scope

The configured `Public API Compatibility` CI job runs
`cargo-semver-checks 0.50.0` through `cargo xtask semver`. It compares only
the current `termivar-core`, with all features enabled, against the historical
`venom-core` package at commit
`9f65c661028af2d7129caeee640f9b6185c357ca`, the commit referenced by the
annotated `v0.9.0-alpha` tag. The explicit patch comparison mode makes a
detected breaking change fail even though the unreleased workspace has moved
to the distinct `0.10.0-alpha.2` development line.

The all-features comparison deliberately enables core's non-default
`legacy-contracts` feature. That feature preserves the historical configuration,
error, event, raw finding, vulnerability, and HTTP records solely for the pinned
`v0.9.0-alpha` API check; passing the check does not place those records in the
default core crate or the default product runtime.

This is deliberately a core-contract gate, not a workspace-wide stability
claim. [ADR 0007](adr/0007-scan-context-construction-boundary.md) makes
`ScanContext` constructor-owned, non-exhaustive, and responsible for a private
knowledge base. That transition is intentionally source-incompatible with the
tagged `v0.9.0-alpha` struct-literal contract. `termivar-scanner` therefore remains
Preview and outside the blocking job until the next Preview release provides
an immutable post-transition baseline. The CLI, API, and proxy crates are not
covered by this check.

The SemVer command remains separate from `cargo xtask release`; CI installs the
declared analysis-tool version and runs the compatibility job independently.

The `compat/current-head/` workspace uses one dedicated lockfile and separate
package invocations to add downstream-shaped compile evidence for four isolated
feature closures. Its path dependencies all resolve to the same checkout, so a
pass catches current-revision API drift but does not establish compatibility
with a published release, a Rust ABI, a deprecation window, or external
adoption. The lifecycle inventory and exact boundaries are recorded in [Public
API compatibility status](public-api-compatibility.md).

## Workflow supply-chain posture

The security workflow uses top-level read-only repository permissions and
grants narrower job-level write permissions only where SARIF publication
requires them. RustSec audit execution is repository-owned: the executable is
version-pinned, compiled with Rust 1.88.0 using its upstream packaged lockfile,
and shared by test, security, and release gates. The advisory database remains
live rather than vendored or frozen. `cargo-deny` remains a separate
commit-SHA-pinned policy action; application dependencies are not modified to
repair CI-tool dependency drift. The Trivy action is commit-SHA pinned and the
Semgrep CE container is image-digest pinned. Trivy's action version and scanner
version are separate and both are declared.

This hardening reduces mutable-reference risk but does not eliminate workflow
supply-chain risk. Workflow actions are full-SHA pinned and container jobs are
digest-pinned by architecture policy; hosted runners and downloaded toolchains
remain external dependencies, and Dependabot proposals still require review.

## Open gaps

- CodeQL covers JavaScript/TypeScript only and does not replace Rust-specific dependency, Clippy, fuzz, or review controls.
- The security workflow configuration does not establish that its latest run passed; consult the result for the exact commit under review.
- Trivy, Semgrep, Cargo Audit, and cargo-deny are scoped automated tools and can produce false positives and false negatives.
- Fuzzing is time-bounded and does not prove parser safety.
- Scoped mutation campaigns do not establish project-wide mutation adequacy; survivor classification remains a review responsibility.
- Coverage is a scoped regression signal, not proof that the tests are adequate or that uncovered behavior is safe.
- Scanner construction policy and same-revision downstream fixtures are documented, but Scanner SDK and plugin contracts still lack an accepted post-transition compatibility baseline and cross-version evidence.
- Automated API linting and current-head compilation do not prove released-version Rust source compatibility; public-API review remains required.
- No independent downstream adoption has been documented; repository-authored fixtures and demonstrations do not count as external adoption.
- No independent security audit, penetration-test report, or compliance certification has been completed.
- Initial controlled endpoint evidence exists, but no repeatable accepted performance baseline, SLA, capacity certification, or regression threshold has been established.
- A supported API listener, TLS-intercepting MITM proxy, and durable distributed control plane remain absent. The process-local coordinator is Experimental and does not fill that product gap.
