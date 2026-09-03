# Contributing

The canonical contribution policy lives in the repository-root [CONTRIBUTING.md](https://github.com/ITherso/termivar/blob/main/CONTRIBUTING.md). It defines coding style, rustfmt and Clippy expectations, branch and commit naming, the pull-request checklist, architecture review, and licensing.

## Local verification

```bash
cargo +1.88.0 fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo xtask docs
```

Termivar pins repository formatting to Rust `1.88.0` rustfmt. Stable, beta,
nightly, and MSRV compiler compatibility remain separate CI contracts.

Changes to a public contract must document compatibility impact. Changes to dependency direction, execution ownership, or component boundaries must update an existing [architecture decision record](adr/README.md) or add a new one.

Security vulnerabilities must be reported privately according to the [security policy](https://github.com/ITherso/termivar/blob/main/SECURITY.md).
