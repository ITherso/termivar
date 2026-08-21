# Repository health

This page records configured repository controls and known gaps. A workflow
definition is tooling evidence, not proof that an arbitrary commit passed, and
no repository control establishes production readiness, legal compliance, or
independent security assurance.

| Control | State | Enforcement or gap |
| --- | --- | --- |
| CodeQL | Configured for JavaScript/TypeScript | Advanced setup analyzes `web/` on relevant changes, a weekly schedule, and manual dispatch; it does not analyze Rust |
| `cargo-audit` | Configured in security CI | The RustSec action audits the committed Cargo dependency resolution without rewriting the lockfile |
| `cargo-deny` | Configured in security CI | The pinned action checks advisories, licenses, bans, and dependency sources against repository policy |
| Trivy | Configured in security CI | SHA-pinned `trivy-action` v0.36.0 runs Trivy v0.70.0 against the repository filesystem for vulnerability, secret, and misconfiguration findings at the declared severity policy |
| Semgrep CE | Configured in security CI | A digest-pinned Semgrep CE image runs declared community rules with metrics disabled |
| Dependabot | Configured | Weekly Cargo, npm, and GitHub Actions update proposals are defined; configuration does not guarantee that an update exists, is safe, or has been merged |
| `cargo-fuzz` | Scheduled and bounded | Four product-semantic and five parser targets replay reviewed seeds and compile on relevant PRs, then run bounded scheduled/manual campaigns; the older [committed parser baseline](reports/fuzzing/7515b79.md) remains evidence only for its recorded commit |
| `cargo-mutants` | Scoped and manual | Selected policy, planner/runtime, and extraction contracts have evidenced review campaigns; no mutation workflow, workspace-wide baseline, or aggregate score is committed |
| Source coverage | Calibration configured | Rust `1.88.0` and the explicit LLVM backend of `cargo-tarpaulin 0.37.2` produce Cobertura plus `venom.coverage.v2` JSON/Markdown evidence and a normalized line-state digest for tracked Rust files under `crates/*/src/**` and `xtask/src/**`; changed-file presence is fail-closed, Codecov upload is best-effort and tokenless availability is not enforced, and no accepted numeric floor is committed yet |
| MSRV | Configured in CI | Workspace packages declare Rust `1.88`; the compatibility matrix also exercises stable, beta, and nightly |
| SemVer | Configured for `venom-core` | `cargo xtask semver` compares the all-features core API with the recorded `v0.9.0-alpha` baseline using a patch-compatibility threshold |
| Architecture boundaries | Configured in CI | `cargo xtask architecture` checks virtual-root source, workspace edges, protected imports, and the transport-free reasoning build |

## Release evidence

The release workflow defines formatting, architecture, Clippy, workspace-test,
dependency-policy, and cross-platform build gates. `cargo xtask release` runs a
local preflight without tagging or publishing. A release claim must identify
the exact commit and retain the corresponding GitHub Actions result; the
existence of either command is not evidence that it passed.

## Public API compatibility scope

The configured `Public API Compatibility` CI job runs
`cargo-semver-checks 0.50.0` through `cargo xtask semver`. It compares only
`venom-core`, with all features enabled, against commit
`9f65c661028af2d7129caeee640f9b6185c357ca`, the commit referenced by the
annotated `v0.9.0-alpha` tag. The explicit patch comparison mode makes a
detected breaking change fail even though the unreleased workspace has moved
to the distinct `0.10.0-alpha.1` pre-1.0 minor line.

The all-features comparison deliberately enables core's non-default
`legacy-contracts` feature. That feature preserves the historical configuration,
error, event, raw finding, vulnerability, and HTTP records solely for the pinned
`v0.9.0-alpha` API check; passing the check does not place those records in the
default core crate or the default product runtime.

This is deliberately a core-contract gate, not a workspace-wide stability
claim. [ADR 0007](adr/0007-scan-context-construction-boundary.md) makes
`ScanContext` constructor-owned, non-exhaustive, and responsible for a private
knowledge base. That transition is intentionally source-incompatible with the
tagged `v0.9.0-alpha` struct-literal contract. `venom-scanner` therefore remains
Preview and outside the blocking job until the next Preview release provides
an immutable post-transition baseline. The CLI, API, and proxy crates are not
covered by this check.

The SemVer command remains separate from `cargo xtask release`; CI installs the
declared analysis-tool version and runs the compatibility job independently.

## Workflow supply-chain posture

The security workflow uses top-level read-only repository permissions and
grants narrower job-level write permissions only where check, issue, or SARIF
publication requires them. Its Rust dependency actions and Trivy action are
commit-SHA pinned; the Semgrep CE container is image-digest pinned. Trivy's
action version and scanner version are separate and both are declared.

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
- Coverage calibration has no accepted numeric threshold yet; its artifact is evidence for reviewing the first baseline, not proof that a project or patch percentage floor was enforced.
- Scanner construction policy is documented, but Scanner SDK and plugin contracts still lack an accepted post-transition compatibility baseline.
- Automated API linting does not prove complete Rust source compatibility; public-API review and downstream compile fixtures remain required.
- No independent security audit, penetration-test report, compliance certification, or controlled end-to-end performance report has been completed.
