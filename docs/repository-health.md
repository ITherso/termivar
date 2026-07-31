# Repository health

This page records enforced repository controls and known gaps. A configured tool is not evidence of production readiness or an independent security audit.

| Control | State | Enforcement or gap |
| --- | --- | --- |
| CodeQL | Automated for JavaScript/TypeScript | Advanced setup scans `web/`; Rust remains covered by Rust-native and language-agnostic controls |
| `cargo-deny` | Required | CI checks advisories, licenses, duplicate-policy warnings, and dependency sources |
| `cargo-audit` | Required | Test and security workflows fail on RustSec advisories |
| `cargo-fuzz` | Scheduled + evidenced | Five parser targets run in bounded weekly campaigns; the [first committed baseline](reports/fuzzing/7515b79.md) records 32,500,714 executions and no observed crash |
| MSRV | Required | Workspace packages declare Rust `1.88`; CI builds that toolchain plus stable, beta, and nightly |
| SemVer | Documented | Plugin preview policy is enforced at registration; automated public-API baselines start after the first release |

## Release evidence

A release candidate must pass formatting, Clippy, workspace tests, dependency policy, security scans, documentation, and release compilation. `cargo xtask release` runs the local preflight; GitHub Actions remains the authoritative cross-platform result.

## Open gaps

- CodeQL does not replace Rust-specific dependency, Clippy, fuzz, or review controls.
- Fuzzing is time-bounded and does not prove parser safety.
- SemVer automation needs a released baseline before `cargo-semver-checks` can compare public APIs.
- No independent security audit or controlled end-to-end performance report has been completed.
