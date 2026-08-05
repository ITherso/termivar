# Runtime map (what actually runs)

> Snapshot: `main` at commit `0208b38`. This page describes the **executable
> truth** of the repository today, not aspirations. Where a capability is not
> wired into a runnable path, it is labelled as such. Release line `0.9.0-alpha`
> is not production-ready.

Venom has **three distinct runtime surfaces**. They are separate on purpose; a
capability existing in one surface does not mean it runs in another. The single
`venom` binary also exposes separate adapter subcommands (`api`, `proxy`) that are
not part of the scan runtime.

## A. Default CLI scan runtime (legacy direct I/O)

`venom scan <target>` runs an ordered phase pipeline built directly on a
`reqwest` client. It is **legacy direct I/O** and does **not** go through
`StandardWebDecisionRuntime` or `RuntimeBudget`; the CLI prints this warning
before running (`LEGACY_SCAN_RUNTIME_WARNING` in `crates/venom-cli/src/main.rs`).

```text
venom scan
  -> ScanContext
      -> ScanRunner
          -> ordered phases/*
```

The phase sequence the CLI composes for the scan, in order (the directory phase is
shown conditionally — it is registered only with the opt-in
`--legacy-directory-fuzz` flag):

1. `ReconPhase`
2. `CrawlPhase`
3. `DirectoryFuzzer` — **conditional**, only with `--legacy-directory-fuzz`
4. `ParameterDiscoverer`
5. `SqliScanner`
6. `XssScanner`
7. `SstiScanner`
8. `LfiXxeScanner`
9. `SsrfScanner`

This is the only **scan runtime** executed by `venom scan`. The same binary also
exposes the separate `api` and `proxy` adapter commands described under surface C;
they do not run the scan pipeline and `venom scan` does not consult the
deterministic decision runtime below.

`ScanContext` instantiates and privately owns a `KnowledgeBase`, but the current
legacy phases do **not** consume it — construction and ownership are not the same
as active use. Surface B, by contrast, actively uses `KnowledgeBase` as
deterministic reasoning/runtime state.

## B. Deterministic decision runtime

`StandardWebDecisionRuntime` is a separate, budget-bounded runtime. It exists and
is exercised by tests and the `decision_scan` example / library hosts, but it is
**not** the path the default `venom scan` command takes.

```text
decision_scan example / library host
  -> StandardWebDecisionRuntime
      -> RuntimeBudget
          -> Evidence
          -> Knowledge
          -> Rules
          -> Planner
          -> Executor (HttpEvidenceExecutor, metered broker)
          -> Verification
```

Modules composed into this runtime are compiled under the default feature set
(`core`, `scanning`) but are not invoked by the default CLI scan: `web_runtime`,
`web_decision`, `web_reasoning`, `web_planning`, `web_execution`,
`web_verification`, `decision_loop`, `decision_runner`, `runtime_budget`,
`http_evidence`, `planner`, `rules`, `knowledge`, `experience`, `verification`,
`adaptive`, and the `api_*` reasoning/evidence modules.

Two implemented-and-tested surfaces are **host-owned** and are *not* automatically
composed into `StandardWebDecisionRuntime` — a host must call them explicitly:

- **Semantic Phase 1.5** (`semantic`: `EntityExtractor`, the producer contract,
  the golden corpus). Consumes `Evidence` only; not wired into the default
  `venom scan` runtime.
- **Defense** (`defense`: projection / shadow / enforcement). The API is
  implemented and tested. `StandardWebDecisionRuntime` does **not** compose it;
  `tests/defense_aware_planning_demo.rs` exercises it, and no production runtime
  caller exists in the repository. External hosts may integrate projection, shadow
  planning, and enforcement explicitly.

## C. Platform shell

The table below classifies the **runtime-critical module groups** along
independent axes — build availability, execution participation, whether the
default `venom scan` path uses it, and support status — because these are not
mutually exclusive (a module can be both opt-in and experimental, and some
modules participate in more than one surface). This table groups the
runtime-critical modules; every top-level public module additionally carries a
source-level `//! ## Runtime scope` banner in its module root, using the same four
axes.

| Module / group | Build availability | Execution participation | Default `venom scan` | Support status |
| --- | --- | --- | --- | --- |
| `phases/*`, `runner`, `context` | default | Surface A | yes (directory phase conditional) | legacy alpha runtime |
| Deterministic stack (`web_runtime`, `decision_runner`, `runtime_budget`, `http_evidence`, `planner`, `rules`, `knowledge`, `experience`, `verification`, `adaptive`, `web_*`, `api_*`) | default | Surface B (composed) | no | implemented and tested |
| `semantic` (Phase 1.5) | default | library / test only (host-owned) | no | implemented and tested; not wired into the default CLI runtime |
| `defense` (projection / shadow / enforcement) | default | host / test only (explicit API) | no | implemented and tested; **not composed into `StandardWebDecisionRuntime`** |
| `advanced_detection`, `anomaly` | default (`detection`) | none on the default scan path | no | compiled, not executed by the default CLI |
| `post_exploitation`, `persistence`, `reporting`, `realtime`, `dashboard`, `waf`, `sdk` | default (`scanning`) | none on the default scan path | no | compiled, not executed by the default CLI |
| `ml` | opt-in (`ml`) | none on any default path | no | experimental |
| `distributed` | opt-in (`distributed`) | none on any default path | no | experimental / scaffold |
| `monitoring` | opt-in (`monitoring`) | none on any default path | no | experimental / scaffold |
| `compliance` | opt-in (`compliance`) | none on any default path | no | experimental / scaffold |
| `threat_intelligence` | opt-in (`threat-intel`) | none on any default path | no | experimental / scaffold |
| `plugin`, `plugins`, `lua_engine` | opt-in (`plugins`) | host-owned | no | opt-in extension surface |
| `venom-api` (`venom api`) | separate workspace crate | explicit CLI hook | no | **unsupported listener** — `start_api` does not bind; `router` exposes only `GET /health` as a library value |
| `venom-proxy` (`venom proxy`) | separate workspace crate | explicit CLI adapter | no | **experimental fixed-upstream TCP relay** (see below) |
| Deployment (Helm / Terraform / Kubernetes) | absent | none | no | unsupported — removed as non-deployable; see the [deployment blueprint](../experimental/deployment-blueprint.md) |

Always-compiled support modules not listed above (for example `api_gateway`,
`auth`, `cache`, `config`, `config_loader`, `contracts`, `event_bus`, `logging`,
`metrics`, `error`, `payload_strategy`) are library plumbing for the surfaces
above; each carries its own source-level runtime-scope banner in its module root.

### The proxy is a TCP relay, not a MITM proxy

`venom proxy` starts `venom-proxy::AsyncMitmProxy`. Despite the type name, the
current connection handler is an **experimental fixed-upstream bidirectional TCP
relay**: it accepts a client connection, opens a TCP connection to a hard-coded
upstream (`127.0.0.1:80`), and copies bytes in both directions. It does **not**
parse `CONNECT`, terminate TLS, present generated certificates, or inspect/modify
HTTP. The `CertCache` type exists but is **not used** by the connection path.
`AsyncMitmProxy` is a legacy/aspirational type name; it is not a statement that
TLS interception is implemented.

## Not implemented

The following are **not** implemented and must not be described as if they were:
a Relation Engine, Planes, a Knowledge Graph, a Machine Scanner, a bound API
listener, a supported/configurable MITM proxy, and any cloud deployment. (The
`knowledge` module is an evidence/hypothesis store, not a "Knowledge Graph".)

## How to reproduce the module inventory

The module set and feature gates above come from
`crates/venom-scanner/src/lib.rs` and `crates/venom-scanner/Cargo.toml`. Any
numeric counts are intentionally omitted here; if a count is needed, generate it
against a named snapshot commit with an explicit command rather than quoting a
static number that will drift.
