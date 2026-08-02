# Code quality

Venom treats quality claims as release evidence, not marketing language. Passing
CI means that the declared checks passed for one commit; it does not make the
alpha production-ready or prove that a scanner result is correct.

## Source ownership

```text
crates/
├─ venom-core/src/          transport-neutral contracts and types
├─ venom-scanner/src/       runtime, reasoning, phases, and plugins
├─ venom-proxy/src/         HTTP/TLS proxy boundary
├─ venom-api/src/           application transport
└─ venom-cli/src/           composition root
examples/src/               compiled SDK examples
xtask/src/                  repository maintenance commands
```

The root `Cargo.toml` is a virtual workspace manifest and must not have `src/`.
Rust code belongs to a declared package so it cannot be silently excluded from
build, test, documentation, release, or quality gates. `cargo xtask
architecture` enforces this rule and the allowed crate dependency graph.

## Rust conventions

- Follow standard Rust naming: `snake_case` functions/modules,
  `PascalCase` types/traits, and `SCREAMING_SNAKE_CASE` constants.
- Prefer small, explicit modules with narrow public surfaces.
- Keep transport, planning, verification, rules, and persistence concerns on
  their documented side of the architecture boundary.
- Return structured errors. Logs are diagnostic and must not be the only record
  of a failed state transition.
- Use checked arithmetic and explicit ceilings at attacker-controlled or
  untrusted input boundaries.
- Avoid secret-bearing `Debug` output. Opaque IDs and redacted summaries are
  preferable to raw headers, response values, tokens, or customer identifiers.

The workspace compiler configuration denies unsafe code and enables selected
rustdoc warnings. Platform configuration is compiler-owned; the repository does
not inject values such as `CARGO_CFG_UNIX`. Warning-free Clippy is enforced by
release and CI commands rather than a global `RUSTFLAGS` environment override.

## Required local checks

Before submitting a change, run:

```bash
cargo fmt --all -- --check
cargo xtask architecture
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features --locked
```

`cargo xtask release` runs the maintained local preflight and builds the release
CLI. GitHub Actions remains authoritative for the cross-platform result.

Use a narrower command while iterating, but do not substitute it for the
relevant workspace gate:

```bash
cargo test -p venom-core
cargo test -p venom-scanner --no-default-features --lib --locked
cargo test -p venom-scanner --all-features runtime_budget
```

See [Testing](TESTING.md) for service-backed tests, deterministic reasoning
fixtures, fuzzing, coverage, and runtime-accounting expectations.

## Public API documentation

Public contracts should explain invariants, failure behavior, resource limits,
and compatibility status. Add a compiling example when it clarifies normal
usage:

````rust
/// Creates a bounded value after validating its public invariant.
///
/// # Errors
///
/// Returns [`ValueError`] when `input` exceeds the documented ceiling.
///
/// # Examples
///
/// ```
/// # use example_crate::BoundedValue;
/// let value = BoundedValue::new("example")?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
# pub struct BoundedValue;
# pub struct ValueError;
````

Run `cargo test --workspace --doc --locked` for examples and `cargo xtask docs`
for Rust API documentation plus the strict MkDocs build. Do not publish an API
snippet for a type that is not exported by a compiled workspace crate.

## Architecture-sensitive changes

Changes to the following areas need focused boundary tests and an architecture
review:

- workspace dependency direction;
- reasoning or planner imports;
- network ownership and runtime resource accounting;
- evidence identity, canonicalization, or replay semantics;
- plugin and scanner SDK public contracts;
- cancellation, partial commit, and audit receipts.

Record a durable design decision in an [ADR](adr/README.md) when the reason for
the boundary would otherwise be lost.

## Dependency and security checks

CI runs Cargo Audit, cargo-deny, CodeQL, Semgrep, and filesystem/container
scanning in separate workflows. A new dependency needs a concrete purpose,
compatible license, maintained release line, and review of its default
features. Security-sensitive changes also need negative tests for denied,
malformed, oversized, and partially failed inputs.

Do not report vulnerabilities in a public issue. Follow the private process in
the repository [Security Policy](https://github.com/ITherso/venom/blob/main/SECURITY.md).

## Metrics

The Quality Metrics workflow records compile time, release binary size, peak
runner memory, and Criterion artifacts. The repository metrics script counts
only tracked Rust files owned by workspace packages. Neither source-line count
nor test count is a quality score.

Coverage, benchmark, and fuzz results must include the commit, toolchain,
configuration, bounded workload, and artifact provenance. See [Quality
metrics](quality-metrics.md), [Benchmarks](benchmarks.md), and
[Fuzzing](fuzzing.md).

## Review checklist

- The change has one observable purpose and no unrelated refactor.
- New behavior has a regression test, including the relevant failure path.
- Public API and serialized-shape changes state their SemVer impact.
- Resource usage is bounded at the owning layer, not inferred from logs or
  semantic actions.
- Documentation describes compiled behavior and does not use completion
  percentages or unsupported production claims.
- No secrets, credentials, private targets, generated build output, or customer
  data are included.
- The architecture, formatting, Clippy, and relevant test gates pass.

Current release blockers and missing evidence are tracked in
[`PROJECT_STATUS.md`](https://github.com/ITherso/venom/blob/main/PROJECT_STATUS.md).
