# Release process

Termivar follows Semantic Versioning. Pre-release identifiers such as `-alpha`
communicate stability; they are part of the version, not a separate status
string.

## Release gate

- workspace version and CLI output agree;
- changelog entry is reviewed and complete;
- architecture, formatting, lint, unit, integration, security, and compatibility checks pass;
- the pinned `termivar-core` public API compatibility job passes;
- every published crate either passes its blocking compatibility baseline or
  carries an explicitly documented pre-v1 break, version transition, and
  upgrade note;
- benchmark results are reproducible and do not contain unsupported claims;
- security advisories and dependency findings are triaged;
- supported-version table is current;
- the annotated tag resolves to reviewed `main`; immediately before checksums
  and publication, CI force-refetches it and requires its peeled commit to equal
  the triggering build commit; tag, release title, and artifacts use the same
  version;
- no GitHub Release already exists for the tag; the workflow creates each
  release once and refuses asset replacement.

`cargo xtask release` runs the local architecture, canonical Rust `1.88.0`
rustfmt, lint, workspace test, and release-build preflight. The formatting
contract is `cargo +1.88.0 fmt --all -- --check`; compiler compatibility is
tested separately on stable, beta, nightly, and the MSRV. CI adds dependency
policy, security, documentation, compatibility, and the four-platform build
matrix on `main` without publishing a release. On a version tag, CI
additionally runs `cargo xtask release-metadata <version>` and refuses
publication until the version has a dated changelog section, release/comparison
links, and a current
supported-version row. Human review remains responsible for the completeness
and accuracy of the prose. Release binaries use the exact MSRV toolchain
rather than a floating `stable` channel. An annotated version tag can publish
only after every release job succeeds. The publisher then refetches the remote
tag, rechecks its object type and peeled commit, generates checksums, and invokes
the create-once release command in one fail-closed step; it also fails if that
tag already has a GitHub Release.

Public API compatibility is intentionally a separate command and is not folded
into the local release preflight:

```sh
rustup toolchain install 1.93.0
cargo +1.93.0 install cargo-semver-checks --version 0.50.0 --locked
cargo +1.93.0 xtask semver
```

The command requires exactly `cargo-semver-checks 0.50.0` and checks only the
current `termivar-core` API against the historical `venom-core` package at the
immutable `v0.9.0-alpha` source commit. CI pins Rust
1.93.0 for the analysis job. See
[Repository health](repository-health.md#public-api-compatibility-scope) for
the current scope and the documented scanner exception.

The experimental [`v0.10.0-alpha.2` prerelease](https://github.com/ITherso/termivar/releases/tag/v0.10.0-alpha.2)
is published as release ID `383577232`. Annotated tag object
`c2c749c410b274c6719c586087e5d32f222ec8a2` peels to
`284a21a83191075615f2086ec935c6f3bf07c2bf`; the release contains four native
archives and a 478-byte `SHA256SUMS` whose SHA-256 is
`9117984e31523aa4bfc751a182423efd2af0f1581883750fe4f3f2abf11d7499`.
Current `main` uses the unreleased `0.10.0-alpha.3` development identity so
later source cannot be confused with those published bytes.

Alpha.2 followed the process above: prepared metadata and native packaged
acceptance were reviewed on the exact candidate, the annotated tag was created
from that commit, and the create-once workflow revalidated and published it.
The checked-in alpha.2 release note remains the publication-note source; its
normalized text matches the published release body rather than being rewritten
after release. Future releases must repeat the same candidate, tag, and
create-once checks. Main-run archives remain temporary workflow evidence and
are not tag-labelled release assets or published checksums.

Do not baseline the scanner against mutable `main` or describe the current
transition as patch-compatible with `v0.9.0-alpha`.

## Release notes template

```markdown
# Termivar vX.Y.Z

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

The historical `v0.9.0-alpha` GitHub Release contains uniquely named archives for Linux
x86_64, macOS x86_64, macOS arm64, and Windows x86_64. The workflow publishes a
sorted `SHA256SUMS` file and GitHub build-provenance attestations for the archives.
Those binaries predate the remediated runtime on `main` and are not the current
source contract's installation path.
Crates.io publishing is deliberately separate until the public crate API and
registry credentials are ready.
