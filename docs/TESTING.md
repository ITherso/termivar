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
| Architecture policy | `cargo xtask architecture` | Workspace edges, virtual-root and example-target ownership, protected imports, and transport-free compilation |
| SDK examples | `examples/` | Compiling consumer-facing usage |
| Template smoke tests | `templates/` in CI | Generated scanner and plugin projects compile independently |
| Benchmarks | `crates/venom-scanner/benches/` | Criterion regression signals |
| Fuzz targets | `fuzz/` | Bounded parser campaigns outside the main workspace |
| Dashboard tests | `web/` | Server-render smoke, typecheck, lint, and production-build checks; no browser interaction or accessibility suite is currently configured |

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
cargo test --locked -p venom-scanner --no-default-features --features legacy-scanner --test integration_tests
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

## Integration tests

The GitHub integration-test job runs the all-feature suite without PostgreSQL or
Redis. The current tests use in-memory state and loopback fixtures; provisioning
unused services would imply a runtime dependency that does not exist. Reproduce
the job with:

```bash
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
outcome. Tests that exercise HTTP must keep request count, buffered request-body
bytes, complete transport-delivered response chunks, retained evidence bytes,
redirects, retries, cancellation, and partial failures observable at the
host-owned transport boundary. A response-threshold crossing must halt the same
turn while preserving any committed evidence receipt.

Native authorization-context differential regression coverage must use
loopback only and assert the whole paired boundary:

- preflight rejects method, exact-target, non-context-header, credential, and
  insecure non-loopback transport mismatches before opening a socket;
- control and candidate credentials remain isolated, including connection-pool
  and response-cookie state, while both requests charge the same broker budget;
- both legs consume active-verification and total-request leases, so a limit of
  one prevents the candidate dispatch;
- redirects are charged but never followed, and implicit retries never create
  an unaccounted request;
- partial bodies, timeouts, cancellation, malformed/non-JSON responses, `429`,
  server errors, and response-byte crossings never emit a comparison;
- a completed control receipt and all delivered bytes remain auditable when the
  candidate or a later stage fails;
- dispatch receipts remain ordered and raw-target-free, distinguish completed,
  timeout, response-limit, transport-failure, and cancelled exits, and report
  retention omissions explicitly;
- the same complete fixture and V3 profile produce the same comparison and
  redacted explanation; fixture-pinned policy, subject, path, and serialized
  envelope digests make an accidental algorithm/version drift fail even when
  the current implementation remains internally self-consistent;
- anonymous/authenticated, owner/unrelated-user, and read/write-capability
  authorization fixtures all traverse the real two-request broker path, not
  only the transport-neutral comparator;
- a difference ends only in a weak, supported `AwaitHumanReview` boundary and
  never a vulnerability finding, Experience write, or decision-loop success;
- serialized and debug reports contain no credential values, raw JSON values,
  or clear diff paths; debug output also redacts deterministic digests, while
  serialized digests remain explicitly pseudonymous audit metadata.

Tests for post-comparison cancellation and post-commit reasoning/projection
failure must assert which of the comparison, observation receipt, and exact
review remains available. These receipts describe in-process append-only state;
they are not rollback or crash-durability claims.

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

The scheduled fuzz workflow runs bounded Venom HTML/declarative-semantic targets
plus HTTP, JSON, YAML, XML, and text dependency-parser campaigns. See
[Fuzzing](fuzzing.md) for reproduction and artifact policy.

## Coverage and performance

The Tests workflow builds `cargo-tarpaulin 0.37.2` with pinned installer Rust
`1.91.0`, then explicitly measures with the project's Rust `1.88.0`, its
`llvm-tools-preview` component, and Tarpaulin's LLVM backend. The fixed
scope is tracked Rust files under `crates/*/src/**` and `xtask/src/**` with the
all-feature workspace build. It uploads Cobertura plus deterministic JSON and
Markdown summaries as the `coverage-evidence` artifact. It also attempts a
best-effort advisory Codecov upload, but tokenless availability is not required
or enforced. The policy checker's own standard-library regression tests run
before measurement.

This source state intentionally runs the checker in calibration mode because no
accepted numeric baseline is committed. Calibration still rejects malformed or
escaping paths. Every changed in-scope file has a patch row; a file absent from
Cobertura may pass calibration only when it is explicit in the current omission
inventory, with its actual changed-line count and zero observed covered and
coverable counts. Those zeroes describe instrumentation output, not the absence
of executable source. The full omission inventory must equal the exact reviewed
nine-path bootstrap list in [Coverage evidence](reports/coverage/README.md).
Calibration does not invent a percentage floor. After a reviewed baseline is
committed and calibration is removed, normal mode prevents aggregate regression
and requires coverable changed lines on pull requests and branch pushes to meet
the accepted aggregate ratio. An accepted omission is excluded from the patch
denominator only while its path and source blob remain frozen to the applicable
floor record; changed content must become measured. A new omission fails closed,
as does disappearance from Cobertura of a source measured in that baseline and
still present at HEAD. A missing/null event base fails closed; a patch with zero
observed coverable changed lines is N/A. Exact integer counts are authoritative;
rounded percentages are display-only. Evidence schema `venom.coverage.v2` also
binds the normalized boolean state of every observed source line. First and
replacement baseline records must match the current aggregate, per-file,
line-state digest, and omission measurement exactly.
Actual Rust `tarpaulin` and `tarpaulin_*` cfg tokens,
`coverage(off)`, and legacy `no_coverage` attributes are forbidden in the
tracked production-source scope so instrumentation-specific conditionals cannot
turn changed code into an N/A patch; comments and string literals that merely
describe them are ignored. `--ignore-config`, an exact workflow-level env, the
reviewed alias-only Cargo config, and the custom-build ban close
repository-controlled instrumentation overrides.

A first or replacement baseline must come from a dedicated follow-up to its
recorded source commit. Outside coverage truth docs and the exact first-time
workflow flip, tracked source, manifests, lockfile, checker, fixtures, and build
inputs must remain unchanged. Baseline acceptance must preserve the evidence
source commit through a merge commit or fast-forward; squash/rebase history must
regenerate evidence for the rewritten commit.

Run the checker tests with:

```bash
python3 -m unittest discover -s scripts/tests -p 'test_coverage_gate.py'
```

See [Coverage evidence](reports/coverage/README.md) for the command, schema,
provenance requirements, baseline acceptance sequence, and current calibration
limit. Coverage is a navigation signal, not proof of correctness; new behavior
still needs assertions for failure paths and boundary conditions.

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
