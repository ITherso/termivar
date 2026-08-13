# Runtime truth remediation audit

This audit records the executable baseline for the remediation that makes the
deterministic runtime Venom's primary scanner product. It is an implementation
input, not a claim that the listed problems are already fixed.

## Baseline

- Expected baseline: `bfdd8276329a858041e61458ea36cb66b0e4487c`.
- Audited HEAD: `9e7b1d0430935165ceb23de44b386365b965785d`.
- Worktree at audit start: clean.
- Newer work preserved: three compatible commits implementing and documenting
  fail-closed derived-evidence lineage (`0e4e073`, `6aad1ed`, `9e7b1d0`).
- Workspace members: `venom-core`, `venom-scanner`, `venom-cli`, `venom-api`,
  `venom-proxy`, `venom-examples`, and `xtask`.

No audit or test command contacted a public target. Executable characterizations
used loopback listeners only.

## Confirmed executable surfaces

| Surface | Current caller | Executable truth before remediation |
| --- | --- | --- |
| `venom scan` | `crates/venom-cli/src/main.rs` | Direct-I/O ordered legacy phases. It does not use `StandardWebDecisionRuntime` or `RuntimeBudget`. |
| `venom decision-scan` | `crates/venom-cli/src/decision_scan.rs` | The only production CLI caller of the bounded deterministic web runtime. |
| Scanner SDK | Library hosts and generated template | Composes the legacy `ScanRunner`; phase failure information is not represented in its public report. |
| `venom api` | CLI adapter | Calls an unsupported stub that binds no listener, yet returns success. The library router contains only `GET /health`. |
| `venom proxy` | CLI adapter and Docker default | Experimental fixed-upstream TCP relay, not an HTTP/TLS MITM proxy. |
| Plugin registry | Opt-in library hosts | Executes host-provided plugins; no stock CLI consumer. |

The default CLI unconditionally compiles `venom-api`, `venom-proxy`, `reqwest`,
and the scanner's default features. The scanner defaults are
`core + scanning + detection`; `scanning` combines the deterministic runtime,
legacy phases/runner/SDK, and unrelated platform models.

## Public but unwired surfaces

- `reporting`, `dashboard`, `persistence`, `realtime`, `post_exploitation`, and
  WAF compatibility types are default-compiled but have no production caller.
- `advanced_detection` and `anomaly` are default-compiled through `detection`
  but do not participate in either CLI scan path.
- `semantic` and `defense` have tested host contracts but are not composed into
  the standard runtime automatically.
- `distributed` is an opt-in in-memory scaffold with no runtime caller.
- Lua is bundled with `plugins`, but its validated script path is not the source
  that the current executor evaluates.
- The six built-in plugin "scanners" are marker fixtures that can manufacture
  high/critical `ScanFinding` values from input strings without validating a
  target response.

## Default-compiled scaffolds and boundary defects

- `venom-scanner --no-default-features` still compiles substantial API, auth,
  configuration, cache, event, and model surfaces; `mlua` is unconditional.
- The default CLI exposes unsupported API and experimental proxy commands.
- API accepts an address, prints a startup message, binds nothing, and exits 0.
- Proxy address parsing uses `split(':')`; malformed and bracketed IPv6 inputs
  can silently exit 0 without starting a relay.
- `ScanRunner` logs phase errors/timeouts and returns a bare partial vector.
- CLI `scan_task.await.unwrap_or_default()` turns task failure into an empty
  successful result and prints `Found N vulnerabilities`.
- Plugin duplicate IDs replace three maps independently; `retry_count` is
  decorative; timestamp acquisition unwraps; plugins receive loose strings and
  return findings directly.
- Distributed dequeue removes the task record, assignment does not implement an
  atomic queued-to-assigned transition, retry does not requeue, and completion
  is not idempotent. Its tests are compile-disabled.
- Lua tests are compile-disabled; timeout drops an awaiting future but does not
  cooperatively stop Lua execution.

## Confirmed false-positive risks

Loopback characterizations prove that the legacy default path can report:

- 90 hidden parameters against an application that ignores every unknown query
  parameter and always returns the same HTTP 200 response;
- directory findings on wildcard/soft-404 routers because no randomized
  nonexistent-path control exists;
- SQL injection from one HTTP 500, a generic `Syntax error` string, or one
  delayed response;
- confirmed reflected XSS from inert plain-text reflection;
- critical SSTI when a static page merely contains `49`;
- LFI when a baseline page contains `localhost`;
- XXE when a static response already contains a file-like marker;
- SSRF/internal reachability from ordinary 401/403 responses or uncorrelated
  response text.

The crawler performs one root request, uses regex HTML extraction, ignores
relative URLs and form semantics, and does not bound response bodies. Parameter
discovery has no baseline, negative control, or reproducibility check. Several
legacy detector phases include cloud-metadata and sensitive-file payloads; these
must remain outside the default runtime and be removed or semantically narrowed.

## Packaging and distribution contradictions

- The Docker image exposes port 8080, installs a fake TCP healthcheck, and starts
  the experimental proxy by default.
- The root Compose file advertises a deployment composed of unused PostgreSQL,
  Redis, Prometheus, Grafana, Elasticsearch, and Kibana services, contains
  default credentials/security-disabled services, and references absent files.
- The container workflow provisions unused services and publishes an unsupported
  image on ordinary branch pushes.
- `install.sh` advertises package-manager, crates.io, and GHCR channels that do
  not exist, constructs the wrong release asset names, and performs no checksum
  verification.
- Legacy reporting inserts target-controlled strings into HTML and CSV without
  contextual escaping, spreadsheet-formula neutralization, uniform redaction,
  or evidence length limits.

## Baseline verification commands

| Command | Baseline result |
| --- | --- |
| `git rev-parse HEAD` | `9e7b1d0430935165ceb23de44b386365b965785d` |
| `git status --short` | clean |
| `cargo metadata --locked --no-deps --format-version 1` | PASS; seven workspace members inventoried |
| `cargo run --locked -p venom-cli -- --help` | PASS; exposed `scan`, `decision-scan`, `api`, `proxy` |
| `cargo run --locked -p venom-cli -- decision-scan --help` | PASS |
| `cargo run --locked -p venom-cli -- scan --help` | PASS |
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | PASS |
| `cargo test --locked -p venom-scanner --no-default-features --lib` | PASS, 450 tests; two expected dead-code warnings in this feature slice |
| `cargo test --locked -p venom-scanner --no-default-features --features scanning --lib` | PASS, 802 tests |
| `cargo test --locked -p venom-scanner --no-default-features --features plugins --lib` | PASS, 489 tests; current unsafe fixture semantics are encoded by tests |
| `cargo test --locked -p venom-scanner --no-default-features --features distributed --lib` | PASS, 802 unrelated/scanning tests; distributed tests themselves are disabled |
| `cargo test --locked -p venom-cli` | PASS, 37 unit + 3 integration tests |
| `cargo build --locked --release -p venom-cli` | PASS |
| `cargo run --locked -p xtask -- architecture` | BLOCKED before execution by Windows Application Control (`os error 4551`); no bypass attempted |
| `cargo test --workspace --all-features --locked` | Local host attempt did not complete: all-feature rustdoc test processes stalled under Windows policy; narrower package/feature gates above executed. Remote clean CI is required for this portion. |

Docker is not installed on the audit host, so no local container build was
claimed. Existing tests and audit probes used only deterministic in-process or
loopback fixtures.

## Remediation order

1. Make deterministic `scan` canonical; move the direct-I/O pipeline behind an
   acknowledged non-default `legacy-scanner` feature; hide unsupported adapters.
2. Replace the bare stringly run boundary with explicit complete/partial/
   cancelled/failed typed reports.
3. Build bounded same-origin discovery with negative controls before considering
   any low-risk verifier expansion.
4. Quarantine or correct every legacy detector, plugin fixture, platform model,
   distribution artifact, and reporting path before it can be mistaken for a
   supported product surface.
5. Keep Lua and distributed opt-in and experimental until their execution and
   state-machine contracts are real and their tests are active.
