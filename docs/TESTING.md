# Testing

Termivar tests the declared Cargo workspace. The repository root is a virtual
manifest and intentionally contains no Rust target of its own. Test counts are
not hand-maintained in documentation; CI results and coverage artifacts are the
source of truth.

## Test layout

| Layer | Location or command | Purpose |
| --- | --- | --- |
| Unit and contract tests | `crates/*/src/` | Local invariants, public contracts, and deterministic reasoning |
| Scanner integration tests | `crates/termivar-scanner/tests/` | Feature combinations and cross-module behavior |
| Architecture policy | `cargo xtask architecture` | Workspace edges, virtual-root and example-target ownership, protected imports, transport-free compilation, and modular-facade responsibility ownership |
| SDK examples | `examples/` | Compiling consumer-facing usage |
| Template smoke tests | `templates/` in CI | Generated scanner and plugin projects compile independently |
| Current-head consumers | `compat/current-head/` | One dedicated lockfile with separate package tests for core, deterministic assessment/reporting, Legacy `ScannerSdk`, and plugin API 0.2 |
| Benchmarks | `crates/termivar-scanner/benches/` | Criterion regression signals |
| Endpoint evidence | `endpoint_assessment` bench plus `scripts/run-endpoint-performance.sh` | Real-runtime, loopback-only fixed workloads with strict JSON/Markdown evidence |
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
cargo test -p termivar-scanner --no-default-features --lib --locked
```

Focus on one package or one test name while iterating:

```bash
cargo test -p termivar-core
cargo test -p termivar-scanner --all-features runtime_budget
cargo test --locked -p termivar-scanner --no-default-features --features legacy-scanner --test integration_tests
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

## Cross-platform runtime smoke

The Tests workflow has a small `Runtime Smoke` matrix on `ubuntu-latest`,
`windows-latest`, and `macos-latest`, all using the declared Rust `1.88.0`
toolchain. Each runner builds the default `termivar-cli`, executes the built
binary with `--version` and `--help`, and runs the real process-level default
scan against a deterministic `127.0.0.1` fixture. It also exercises atomic
`--report-output` create/no-clobber behavior through an explicitly selected
`web-review` profile, the transport-neutral core RunReport wire golden, and
focused scanner exact-origin and redirect-no-follow contracts.

This matrix is intentionally a runtime portability smoke layer, not a second
copy of the all-features, Clippy, coverage, security, fuzz, or release-artifact
matrices. It tests only host-native builds and temporary-path behavior on the
three hosted operating systems. It is not platform certification or a claim
that every feature is supported equally on each OS. All sockets opened by these
tests bind to loopback; the job never scans a public target.

## Current-head downstream compile fixtures

The `Downstream Current-Head Compile` job tests four separately resolved
feature closures from `compat/current-head/`: default `termivar-core`, the
deterministic assessment/reporting Preview, the Legacy `ScannerSdk` facade,
and plugin API 0.2. Run the packages independently so Cargo cannot unify their
features and make a narrower consumer appear to compile against a broader
surface.

These fixtures use path dependencies into the same checkout. They detect
accidental source drift at that revision, but do not compare released
versions, select a v1 baseline, promise a stable ABI, or count as independent
adoption. The exact lifecycle inventory and reproduction commands are in
[Public API compatibility status](public-api-compatibility.md).

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

Assessment/CLI composition tests must additionally prove that the optional
root context pair uses the origin assessment's existing authority, consumes two
active leases, emits no item for equivalent visibility, and projects a
difference through one atomic evidence reference with empty synthetic
control/candidate lists. A one-active-verification limit must prevent the
candidate leg, suppress later discovery, and return typed incompleteness. Env,
file, and stdin sources must be exercised without allowing the credential,
source identifier, file path, raw JSON, or private diagnostics into stdout,
stderr, debug text, or any renderer.

Native `web-review` CORS/redirect/reflection regression coverage also uses
loopback only and must assert the complete product boundary:

- omitting `web-review` dispatches no Origin or query mutation;
- bootstrap and every control/candidate leg share one exact-origin broker,
  request budget, cancellation token, and deadline;
- the deterministic external destination is carried only as same-origin input,
  and redirect following remains disabled;
- reflected Origin without the credential policy and a generic 3xx produce no
  CORS or redirect review item;
- CORS status-divergent/error-only pairs and redirect statuses outside the
  closed 301/302/303/307/308 set produce no review item;
- eligible standard and native actions remain additive while sharing one
  reconciled request budget;
- control/candidate evidence is case-correlated, disjoint, committed, and
  replayed before an item is projected;
- ordinary exact HTML reflection is `Informational`, dangerous-context
  reflection is at most `NeedsReview`, and no reflection is `Confirmed` XSS;
- budget exhaustion, a missing/cross-case pair, or incomplete bounded HTML
  reflection analysis is typed incompleteness, never empty success; and
- JSON, CSV, HTML, and Markdown keep `NeedsReview`/`Differential` visibly
  distinct from `Informational`/`Observation` without exposing candidate
  values or raw response material.

## Security and compatibility

Security checks are separate from functional tests:

```bash
cargo audit
cargo deny check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

CI checks the declared MSRV (`1.88.0`), stable, beta, and nightly. Stable and
MSRV failures are release blockers. Beta and nightly expose upcoming compiler
changes; investigate failures before deciding whether an upstream regression
is involved.

The scheduled fuzz workflow runs bounded Termivar HTML/declarative-semantic targets
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

The checker enforces the accepted LLVM baseline of exactly 21,439 covered of
24,842 observed coverable source lines. Aggregate coverage and coverable changed
lines on pull requests and branch pushes must each meet that integer ratio.
Every changed in-scope file has a patch row. The accepted record preserves the
exact reviewed nine-path omission inventory from
[Coverage evidence](reports/coverage/README.md); its zeroes describe
instrumentation output, not the absence of executable source. An accepted
omission is excluded from the patch denominator only while its path and source
blob remain frozen to the applicable
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
provenance requirements, accepted record, and replacement sequence. Coverage is
a navigation signal, not proof of correctness; new behavior
still needs assertions for failure paths and boundary conditions.

Criterion output, compile time, binary size, and peak runner memory are
published as workflow artifacts. See [Quality metrics](quality-metrics.md).

The endpoint-scale harness is a separate `harness = false` benchmark binary
that runs the real `WebAssessmentRuntime` against only its hard-coded
`127.0.0.1` fixture. It accepts fixed workload names rather than a target URL:
100 endpoints, 1,000 endpoints, or a 10,000-request batch. The final batch is
ten independent origin assessments, each with its own 1,000-request authority;
it must not be described as one global budget. The harness fails unless
endpoint execution, broker receipts, request counts, response bytes, active
verification use, and completion state reconcile.

Run the canonical Linux wrapper from a clean checkout:

```bash
bash scripts/run-endpoint-performance.sh \
  --workload all \
  --warmups 1 \
  --samples 3 \
  --output-dir target/endpoint-performance
```

Warmups and samples are hard-bounded. After the Cargo build, the wrapper clears
HTTP(S)/ALL proxy variables and pins `NO_PROXY`; the benchmark binary separately
rejects a proxy-bearing environment before opening its fixture. Output uses the
strict `venom.endpoint-performance/v1` JSON schema plus a Markdown projection.
Initial
controlled evidence for source commit
`27321efbbf49cb2adbc72afb699d1b31ea407486` was produced by
[workflow run 33292247976](https://github.com/ITherso/venom/actions/runs/33292247976)
and is retained as [Markdown](reports/benchmarks/27321ef-endpoint-assessment.md)
and [JSON](reports/benchmarks/27321ef-endpoint-assessment.json). This is one
runner-local measurement set with a fixed one-millisecond fixture delay. It is
not an SLA, capacity limit, concurrency result, accepted repeatable baseline,
or regression threshold; `thresholds` remains `null`. See
[Benchmarks](benchmarks.md) for full provenance and limitations. Do not copy
runner-local values into the README as capacity claims.

## Before a pull request

At minimum:

```bash
cargo +1.88.0 fmt --all -- --check
cargo xtask architecture
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```

Add the narrowest regression test that would fail without the change. If a
public contract or dependency boundary changes, update the relevant API guide
or architecture decision record in the same pull request.
