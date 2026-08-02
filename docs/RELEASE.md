# Release process

Venom follows Semantic Versioning. Pre-release identifiers such as `-alpha`
communicate stability; they are part of the version, not a separate status
string.

## Release gate

- workspace version and CLI output agree;
- changelog entry is complete;
- architecture, formatting, lint, unit, integration, security, and compatibility checks pass;
- the pinned `venom-core` public API compatibility job passes;
- every published crate either passes its blocking compatibility baseline or
  carries an explicitly documented pre-v1 break, version transition, and
  upgrade note;
- benchmark results are reproducible and do not contain unsupported claims;
- security advisories and dependency findings are triaged;
- supported-version table is current;
- tag, release title, and artifacts use the same version.

`cargo xtask release` runs the local architecture, formatting, lint, workspace
test, and release-build preflight. CI adds dependency policy, security,
documentation, compatibility, and the four-platform build matrix on `main`
without publishing a release.

Public API compatibility is intentionally a separate command and is not folded
into the local release preflight:

```sh
rustup toolchain install 1.93.0
cargo +1.93.0 install cargo-semver-checks --version 0.50.0 --locked
cargo +1.93.0 xtask semver
```

The command requires exactly `cargo-semver-checks 0.50.0` and checks only
`venom-core` against the immutable `v0.9.0-alpha` source commit. CI pins Rust
1.93.0 for the analysis job. See
[Repository health](repository-health.md#public-api-compatibility-scope) for
the current scope and the documented scanner exception.

Before publishing the current scanner shape, the release must treat
`ScanContext::knowledge` as an incompatible pre-v1 transition, include an
upgrade note for struct-literal users, and establish the next scanner baseline.

## Release notes template

```markdown
# Venom vX.Y.Z

## Added

## Changed

## Fixed

## Security

## Upgrade notes

## Verification
```

Omit an empty category rather than adding filler. Security fixes should link to
the published advisory after coordinated disclosure. Checksums and provenance
should accompany downloadable artifacts.

## Alpha release

For `0.9.0-alpha`, do not use "production-ready", completion percentages, or
unverified performance numbers. Clearly identify unstable APIs, disabled legacy
fixtures, and the absence of an independent audit.

The `v0.9.0-alpha` GitHub Release contains uniquely named archives for Linux
x86_64, macOS x86_64, macOS arm64, and Windows x86_64. The workflow publishes a
sorted `SHA256SUMS` file and GitHub build-provenance attestations for the archives.
Crates.io publishing is deliberately separate until the public crate API and
registry credentials are ready.
