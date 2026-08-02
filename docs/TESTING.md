# Testing

Venom tests the declared Cargo workspace. The repository root is a virtual
manifest and intentionally contains no Rust target of its own. Test counts are
not hand-maintained in documentation; CI results and coverage artifacts are the
source of truth.

## Test layout

| Layer | Location or command | Purpose |
| --- | --- | --- |
| Unit and contract tests | `crates/*/src/` | Local invariants, public contracts, and deterministic reasoning |
| Scanner integration tests | `crates/venom-scanner/tests/` | Feature combinations and cross-module behavior |
| Architecture policy | `cargo xtask architecture` | Workspace edges, virtual-root layout, protected imports, and transport-free compilation |
| SDK examples | `examples/` | Compiling consumer-facing usage |
| Template smoke tests | `templates/` in CI | Generated scanner and plugin projects compile independently |
| Benchmarks | `crates/venom-scanner/benches/` | Criterion regression signals |
| Fuzz targets | `fuzz/` | Bounded parser campaigns outside the main workspace |
| Dashboard tests | `web/` | Frontend unit, build, and separately configured browser checks |

## Local commands

Run the normal workspace suite:

```bash
cargo test --workspace --all-features --locked
```

Run the checks most likely to catch an architectural regression:

```bash
cargo xtask architecture
cargo test -p venom-scanner --no-default-features --lib --locked
```

Focus on one package or one test name while iterating:

```bash
cargo test -p venom-core
cargo test -p venom-scanner --all-features runtime_budget
cargo test -p venom-scanner --test integration_tests
```

Public examples must compile as documentation tests where applicable:

```bash
cargo test --workspace --doc --locked
```

The full local release preflight also runs formatting, Clippy, workspace tests,
the architecture gate, and a release CLI build:

```bash
cargo xtask release
```

## Service-backed tests

The GitHub integration-test job starts PostgreSQL 15 and Redis 7, then runs the
all-feature integration suite with explicit local connection strings. To
reproduce that job, start disposable local services and set:

```bash
export DATABASE_URL=postgres://test:test@localhost:5432/venom_test
export REDIS_URL=redis://localhost:6379
cargo test --workspace --all-features --tests --locked
```

Never point automated tests at a public or customer system. Network behavior
must use loopback fixtures with deterministic responses and bounded timeouts.

## Reasoning and runtime regressions

Reasoning tests should assert the complete causal chain that matters to the
contract, not only a final score:

- normalized evidence and provenance;
- fact or hypothesis transitions;
- selected or rejected plan;
- transport budget usage;
- verification outcome and audit receipt;
- session and Experience Store transitions.

Use fixed evidence, clocks, identifiers, and policies. The same fixture and
configuration must produce the same comparison, explanation, plan, and
outcome. Tests that exercise HTTP must keep request count, retained response
bytes, redirects, retries, cancellation, and partial failures observable at the
host-owned transport boundary.

## Security and compatibility

Security checks are separate from functional tests:

```bash
cargo audit
cargo deny check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

CI checks the declared MSRV (`1.88.0`), stable, beta, and nightly. Stable and
MSRV failures are release blockers. Beta and nightly expose upcoming compiler
changes; investigate failures before deciding whether an upstream regression
is involved.

The scheduled fuzz workflow runs bounded HTTP, JSON, YAML, XML, and text parser
campaigns. See [Fuzzing](fuzzing.md) for reproduction and artifact policy.

## Coverage and performance

The Tests workflow uploads Rust coverage to Codecov. Coverage is a navigation
signal, not proof of correctness; new behavior still needs assertions for
failure paths and boundary conditions.

Criterion output, compile time, binary size, and peak runner memory are
published as workflow artifacts. See [Quality metrics](quality-metrics.md) and
[Benchmarks](benchmarks.md). Do not copy runner-local values into the README as
capacity claims.

## Before a pull request

At minimum:

```bash
cargo fmt --all -- --check
cargo xtask architecture
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features --locked
```

Add the narrowest regression test that would fail without the change. If a
public contract or dependency boundary changes, update the relevant API guide
or architecture decision record in the same pull request.
