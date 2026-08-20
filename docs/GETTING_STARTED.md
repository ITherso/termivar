# Getting started

This unreleased source state (package version `0.10.0-alpha.1`) is an experimental
Rust security-testing project. The historical `v0.9.0-alpha` tag predates the
bounded default runtime documented here. Build a reviewed, pinned
commit; it is not production-ready and must be run only against systems you own
or are explicitly authorized to test.

This guide covers the default deterministic CLI and the separately compiled historical runner. It does not describe a dashboard, API service, TLS-intercepting proxy, team service, or cloud control plane because those are not supported runtime products today.

## Prerequisites

- Rust 1.88 or newer ([rustup](https://rustup.rs/))
- Git
- An authorized, reachable HTTP(S) origin

Docker is optional. PostgreSQL, Redis, Node.js, and a browser are not required to build or run the CLI scan commands.

## Build from source

```bash
git clone https://github.com/ITherso/venom.git
cd venom
REVIEWED_COMMIT="REPLACE_WITH_THE_REVIEWED_FULL_COMMIT_SHA"
test "$REVIEWED_COMMIT" != "REPLACE_WITH_THE_REVIEWED_FULL_COMMIT_SHA"
git checkout --detach "$REVIEWED_COMMIT"
test "$(git rev-parse HEAD)" = "$REVIEWED_COMMIT"
cargo build --locked -p venom-cli
cargo run -p venom-cli --locked -- --help
```

The root manifest is a virtual workspace. The CLI package is `venom-cli`; its binary is named `venom`.

## Run the deterministic runtime

`scan` is the current deterministic Surface-B preview and the default product command:

```bash
cargo run -p venom-cli --locked -- scan https://authorized.example.test
```

`example.test` is a reserved placeholder and will not normally resolve. Replace it with an exact origin you own or have explicit permission to assess.

The command:

- bootstraps bounded HTTP evidence for one authorized origin;
- reasons over typed evidence and subject-scoped hypotheses;
- selects eligible actions using deterministic utility, cost, risk, requirements, prerequisites, and suppression policy;
- executes built-in requests through one redirect-disabled, metered broker;
- applies passive or active verification under the action's claim policy;
- stops under fixed request, byte, wall-time, action-attempt, and no-progress limits.

It emits operational decisions and outcomes, not deterministic-runtime findings or vulnerability declarations.

### Explain mode

```bash
cargo run -p venom-cli --locked -- scan https://authorized.example.test --explain
```

The expanded text includes hypotheses, selected and excluded actions, dispatches, outcomes, and terminal reasoning.

### JSON diagnostics

```bash
cargo run -p venom-cli --locked -- scan https://authorized.example.test --format json
```

The JSON document retains the historically named schema [`decision-scan/v1`](internals/decision-scan-json-v1.md). It already carries full diagnostics, so `--format json` and `--explain` cannot be combined. `decision-scan` remains a deprecated, discoverable command alias for `scan`; it runs the same implementation and produces identical stdout and stderr.

### Safe local smoke target

For a network-isolated smoke run, serve a temporary directory on loopback in one terminal:

```bash
python3 -m http.server 8088 --bind 127.0.0.1
```

Then run Venom in another terminal:

```bash
cargo run -p venom-cli --locked -- scan http://127.0.0.1:8088
```

This proves command wiring and output shape; it is not a meaningful security assessment.

## Legacy ordered scanner

The historical ordered runner is not present in a default build. To use it, compile the explicit feature and acknowledge its heuristic claim boundary:

```bash
cargo run -p venom-cli --locked --features legacy-scanner -- legacy-scan \
  https://authorized.example.test --acknowledge-legacy-heuristics
```

It runs the historical phase pipeline. Its crawler, wordlist-based directory
discovery, and parameter discovery share an exact-origin, redirect-disabled
authority with configurable finite depth, page, request, request-timeout,
wall-time, cumulative-body, and per-response-body limits. Those phases stage
typed endpoint/form state atomically. Directory discovery calibrates two
stable randomized nonexistent-path controls for each eligible path shape;
parameter discovery requires a
baseline/control/candidate/identical-replay differential. Their records are
informational observations, not vulnerability confirmation.

Wordlist-based directory discovery is still off within this opt-in runtime. The
additional `--legacy-directory-fuzz` option enables it; use it only when target
authorization and expected load are clear. Phases five through nine use a
second exact-origin, redirect- and retry-disabled authority with finite
`VerificationLimits`. Reproduced SQL behavior and template arithmetic can
project only knowledge-only `NeedsReview`; exact reflection remains `Unknown`.
The CLI's phase-eight and phase-nine defaults are inert. SDK hosts can opt into
a benign local-file canary or OOB URL delivery, but XXE remains disabled and a
probe response is not callback evidence.

Phase one and custom extensions can still perform direct network I/O outside
both scoped authorities and `RuntimeBudget`, so the CLI reports the whole run
as `Unmetered` and prints that warning before execution. Raw phase prose and
evidence details are withheld at the public boundary. See
[ADR 0016](adr/0016-bound-legacy-discovery-authority.md) and
[ADR 0018](adr/0018-bound-legacy-verification-authority.md).

`scan` and its `decision-scan` alias are the same deterministic engine. `legacy-scan` is a different engine; its results, accounting, and claim semantics must not be compared as though it were an output mode of `scan`.

## Understanding deterministic output

| Term | Meaning |
| --- | --- |
| Observed | Present in bounded typed evidence |
| Supported | Deterministic reasoning supports a hypothesis |
| Confirmed | A verifier-authorized transition occurred |
| Success | The action objective completed; confirmation may still be forbidden |
| NeedsReview / Unknown | Evidence does not authorize a terminal claim |

For example, collecting PHP-style form-control names or Sanctum-compatible cookie names is KnowledgeOnly. The action can succeed while its motivating technology hypothesis remains Supported rather than Confirmed.

## Optional CLI adapters

Default builds expose neither `api` nor `proxy`. They can be compiled as explicit adapters, but they are not scan alternatives:

- `cargo run -p venom-cli --locked --features api-adapter -- api --addr 127.0.0.1:8080` is unsupported and exits nonzero: the library has a health router, but no listener is implemented.
- `cargo run -p venom-cli --locked --features proxy-adapter -- proxy --addr 127.0.0.1:8081 --upstream 127.0.0.1:9081` starts an experimental TCP relay to the explicitly selected upstream. It does not implement HTTP `CONNECT`, TLS termination, generated certificates, or request inspection.

The dashboard, distributed scheduler, monitoring, compliance, profile, and Lua modules are disconnected, opt-in, host-owned, or experimental. See the [runtime map](internals/runtime-map.md) before treating any module as executable product behavior.

## Validate a checkout

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo xtask architecture
cargo xtask docs
```

The last command requires the documentation dependencies from `requirements-docs.txt`.

## Extend Venom

The Scanner SDK and native plugin starters are Preview and compile in CI:

```bash
cargo install cargo-generate
cargo xtask generate scanner my-scanner
cargo xtask generate plugin my-venom-plugin
```

They are source-level, opt-in library integrations, not runtime-loaded
extensions for the default deterministic `scan`. Venom ships no stock detector
plugins; the generated plugin records an INFO-only trait-boundary observation
through host-owned policy and makes no security claim. Read the
[Scanner SDK](sdk.md), [plugin guide](plugin.md), and
[plugin API policy](plugin-api-policy.md) before depending on pre-stable
contracts.

## Next steps

- [Root project overview](https://github.com/ITherso/venom#readme)
- [Runtime map](internals/runtime-map.md)
- [Architecture](architecture.md)
- [Decision runner](internals/decision-runner.md)
- [Web execution](internals/web-execution.md)
- [Web verification](internals/web-verification.md)
- [Feature lifecycle](https://github.com/ITherso/venom/blob/main/FEATURES.md)
- [Project status](https://github.com/ITherso/venom/blob/main/PROJECT_STATUS.md)
- [Security policy](https://github.com/ITherso/venom/blob/main/SECURITY.md)
