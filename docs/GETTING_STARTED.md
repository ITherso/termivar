# Getting started

Venom `0.9.0-alpha` is an experimental Rust security-testing project. It is not production-ready. Run it only against systems you own or are explicitly authorized to test.

This guide covers the two real CLI scan surfaces. It does not describe a dashboard, API service, TLS-intercepting proxy, team service, or cloud control plane because those are not supported runtime products today.

## Prerequisites

- Rust 1.88 or newer ([rustup](https://rustup.rs/))
- Git
- An authorized, reachable HTTP(S) origin

Docker is optional. PostgreSQL, Redis, Node.js, and a browser are not required to build or run the CLI scan commands.

## Build from source

```bash
git clone https://github.com/ITherso/venom.git
cd venom
cargo build --locked -p venom-cli
cargo run -p venom-cli --locked -- --help
```

The root manifest is a virtual workspace. The CLI package is `venom-cli`; its binary is named `venom`.

## Preview the deterministic runtime

`decision-scan` is the current deterministic Surface-B preview:

```bash
cargo run -p venom-cli --locked -- decision-scan https://authorized.example.test
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
cargo run -p venom-cli --locked -- decision-scan https://authorized.example.test --explain
```

The expanded text includes hypotheses, selected and excluded actions, dispatches, outcomes, and terminal reasoning.

### JSON diagnostics

```bash
cargo run -p venom-cli --locked -- decision-scan https://authorized.example.test --format json
```

The JSON document uses schema [`decision-scan/v1`](internals/decision-scan-json-v1.md). It already carries full diagnostics, so `--format json` and `--explain` cannot be combined.

### Safe local smoke target

For a network-isolated smoke run, serve a temporary directory on loopback in one terminal:

```bash
python3 -m http.server 8088 --bind 127.0.0.1
```

Then run Venom in another terminal:

```bash
cargo run -p venom-cli --locked -- decision-scan http://127.0.0.1:8088
```

This proves command wiring and output shape; it is not a meaningful security assessment.

## Legacy ordered scanner

`venom scan` remains available as a migration surface:

```bash
cargo run -p venom-cli --locked -- scan https://authorized.example.test
```

It runs the ordered legacy phase pipeline and legacy finding aggregation. It performs direct network I/O outside `StandardWebDecisionRuntime` and `RuntimeBudget`, and the CLI prints that warning before execution.

Wordlist-based directory brute forcing is off by default. The explicit `--legacy-directory-fuzz` option enables that additional direct-I/O phase; use it only when the target authorization and expected load are clear.

`scan` and `decision-scan` are different engines. Results, accounting, and claim semantics must not be compared as though one were an output mode of the other.

## Understanding deterministic output

| Term | Meaning |
| --- | --- |
| Observed | Present in bounded typed evidence |
| Supported | Deterministic reasoning supports a hypothesis |
| Confirmed | A verifier-authorized transition occurred |
| Success | The action objective completed; confirmation may still be forbidden |
| NeedsReview / Unknown | Evidence does not authorize a terminal claim |

For example, collecting PHP-style form-control names or Sanctum-compatible cookie names is KnowledgeOnly. The action can succeed while its motivating technology hypothesis remains Supported rather than Confirmed.

## Other CLI adapters

The binary exposes `api` and `proxy` subcommands, but they are not scan alternatives:

- `venom api` is unsupported: the library has a health router, but the CLI adapter does not bind a listener.
- `venom proxy` is an experimental fixed-upstream TCP relay. It does not implement HTTP `CONNECT`, TLS termination, generated certificates, or request inspection.

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

They are source-level library integrations, not runtime-loaded extensions for `decision-scan`. Read the [Scanner SDK](sdk.md), [plugin guide](plugin.md), and [plugin API policy](plugin-api-policy.md) before depending on pre-stable contracts.

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
