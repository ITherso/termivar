# Repository health

This page records enforced repository controls and known gaps. A configured tool is not evidence of production readiness or an independent security audit.

| Control | State | Enforcement or gap |
| --- | --- | --- |
| CodeQL | Automated for JavaScript/TypeScript | Advanced setup scans `web/`; Rust remains covered by Rust-native and language-agnostic controls |
| `cargo-deny` | Required | CI checks advisories, licenses, duplicate-policy warnings, and dependency sources |
| `cargo-audit` | Required | Test and security workflows fail on RustSec advisories |
| `cargo-fuzz` | Scheduled + evidenced | Five parser targets run in bounded weekly campaigns; the [first committed baseline](reports/fuzzing/7515b79.md) records 32,500,714 executions and no observed crash |
| MSRV | Required | Workspace packages declare Rust `1.88`; CI builds that toolchain plus stable, beta, and nightly |
| SemVer | Required for `venom-core` | `cargo xtask semver` checks the all-features public API against the immutable `v0.9.0-alpha` commit with a patch-compatibility threshold |
| Architecture boundaries | Required | `cargo xtask architecture` validates workspace edges, protected module imports, and the no-default-features reasoning build |

## Release evidence

A release candidate must pass formatting, architecture boundaries, Clippy, workspace tests, dependency policy, security scans, documentation, and release compilation. `cargo xtask release` runs the local preflight; GitHub Actions remains the authoritative cross-platform result.

## Public API compatibility scope

The required `Public API Compatibility` CI job runs
`cargo-semver-checks 0.50.0` through `cargo xtask semver`. It compares only
`venom-core`, with all features enabled, against commit
`9f65c661028af2d7129caeee640f9b6185c357ca`, the commit referenced by the
annotated `v0.9.0-alpha` tag. The explicit patch release type makes a detected
breaking change fail even while the workspace remains on the same alpha
version.

This is deliberately a core-contract gate, not a workspace-wide stability
claim. [ADR 0007](adr/0007-scan-context-construction-boundary.md) makes
`ScanContext` constructor-owned, non-exhaustive, and responsible for a private
knowledge base. That transition is intentionally source-incompatible with the
tagged `v0.9.0-alpha` struct-literal contract. `venom-scanner` therefore remains
Preview and outside the blocking job until the next Preview release provides
an immutable post-transition baseline. The CLI, API, and proxy crates are not
covered by this check.

The SemVer command remains separate from `cargo xtask release`; CI installs the
pinned analysis tool and runs the compatibility job independently.

## Open gaps

- CodeQL does not replace Rust-specific dependency, Clippy, fuzz, or review controls.
- Fuzzing is time-bounded and does not prove parser safety.
- Scanner construction policy is documented, but Scanner SDK and plugin contracts still lack an accepted post-transition compatibility baseline.
- Automated API linting does not prove complete Rust source compatibility; public-API review and downstream compile fixtures remain required.
- No independent security audit or controlled end-to-end performance report has been completed.
