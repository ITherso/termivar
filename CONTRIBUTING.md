# Contributing to Venom

Venom welcomes focused changes that preserve its crate boundaries and authorized-security-testing purpose. By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

Required: Git and Rust `1.88` or newer. Docker is optional for service-backed integration tests.

```bash
git clone https://github.com/ITherso/venom.git
cd venom
cargo test --workspace
```

The repository exposes common maintenance commands through `cargo xtask`:

```bash
cargo xtask docs
cargo xtask benchmark
cargo xtask release
cargo xtask generate scanner my-scanner
cargo xtask generate plugin my-plugin
```

The generate commands require `cargo-generate` (`cargo install cargo-generate`).

## Coding style

- Prefer safe Rust. Any `unsafe` block requires a `SAFETY:` rationale, isolation, and focused tests.
- Keep dependencies directed toward `venom-core`; entry-point and product crates must not leak into lower layers.
- Keep runner, phase, plugin, event, report, and transport responsibilities separate.
- Use async I/O on runtime paths and never block a Tokio worker thread.
- Return structured errors and findings; do not hide failures in logging alone.
- Document public contracts with a compiling example when practical.

Before opening a pull request, run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features
cargo test --workspace --all-features
```

Formatting is defined by `rustfmt.toml`; lint behavior is defined by `clippy.toml` and CI. Do not hand-format around these tools.

## Branch naming

Use a short lowercase description:

- `feature/plugin-capabilities`
- `fix/event-ordering`
- `docs/scanner-sdk`
- `chore/dependency-policy`

Avoid personal names, ticket-only branch names, and broad branches such as `changes`.

## Commit style

Use an imperative Conventional Commit subject, optionally with a scope:

```text
feat(sdk): add custom scanner builder
fix(plugin): reject incompatible API versions
docs(adr): record event bus ownership
chore(ci): enforce the declared MSRV
```

Keep commits reviewable and do not mix refactors with unrelated behavior changes. Explain the reason and compatibility impact in the commit body when the subject is insufficient.

## Pull request checklist

- [ ] The change is focused and the description explains why it is needed.
- [ ] `cargo fmt`, Clippy, and relevant tests pass.
- [ ] New behavior has unit, integration, or doc-test coverage.
- [ ] Public API changes follow [the SemVer policy](docs/plugin-api-policy.md).
- [ ] Architecture changes update or add an [ADR](docs/adr/README.md).
- [ ] User-facing changes update documentation and `CHANGELOG.md`.
- [ ] New dependencies pass `cargo audit` and `cargo deny` policy.
- [ ] Security-testing examples use targets the contributor owns or is authorized to test.
- [ ] No secrets, credentials, private targets, or real customer data are included.

## Security reports

Do not open a public issue for a vulnerability. Follow [SECURITY.md](SECURITY.md).

## License

Venom is licensed under the [MIT License](LICENSE). Unless stated otherwise, contributions submitted to this repository are accepted under the same terms.
