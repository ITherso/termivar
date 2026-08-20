# Release process

Venom follows Semantic Versioning. Pre-release identifiers such as `-alpha`
communicate stability; they are part of the version, not a separate status
string.

## Release gate

- workspace version and CLI output agree;
- changelog entry is reviewed and complete;
- architecture, formatting, lint, unit, integration, security, and compatibility checks pass;
- the pinned `venom-core` public API compatibility job passes;
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

`cargo xtask release` runs the local architecture, formatting, lint, workspace
test, and release-build preflight. CI adds dependency policy, security,
documentation, compatibility, and the four-platform build matrix on `main`
without publishing a release. On a version tag, CI additionally runs
`cargo xtask release-metadata <version>` and refuses publication until the
version has a dated changelog section, release/comparison links, and a current
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

The command requires exactly `cargo-semver-checks 0.50.0` and checks only
`venom-core` against the immutable `v0.9.0-alpha` source commit. CI pins Rust
1.93.0 for the analysis job. See
[Repository health](repository-health.md#public-api-compatibility-scope) for
the current scope and the documented scanner exception.

The current scanner shape has selected the new pre-1.0 minor source identity
`0.10.0-alpha.1`. Before publishing it:

1. move its reviewed changes from `Unreleased` into a dated
   `0.10.0-alpha.1` section;
2. list the `ScanContext` construction transition under Upgrade notes and link
   the [migration guide](migrations/scan-context-construction.md);
3. create the release and annotated tag only after every release check passes;
4. resolve that tag to its immutable peeled commit; and
5. add the blocking `venom-scanner` baseline in a later change.

Do not baseline the scanner against mutable `main` or describe the current
transition as patch-compatible with `v0.9.0-alpha`.

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

The historical `v0.9.0-alpha` GitHub Release contains uniquely named archives for Linux
x86_64, macOS x86_64, macOS arm64, and Windows x86_64. The workflow publishes a
sorted `SHA256SUMS` file and GitHub build-provenance attestations for the archives.
Those binaries predate the remediated runtime on `main` and are not the current
source contract's installation path.
Crates.io publishing is deliberately separate until the public crate API and
registry credentials are ready.
