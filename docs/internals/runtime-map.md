# Runtime map (what actually runs)

> This page describes the executable truth of the current main-line source, not
> aspirations. A compiled module is not necessarily part of a product runtime.
> Release line `0.9.0-alpha` is not production-ready.

Venom has one default scan runtime, one separately compiled historical runner,
and optional host/adapter surfaces. A capability in one surface does not silently
participate in another.

## Default deterministic scan runtime (Surface B)

`venom scan <target>` is the canonical CLI path. It composes
`StandardWebDecisionRuntime` with a fixed conservative profile and routes every
built-in request through the runtime-owned, redirect-disabled, metered broker.
`venom decision-scan` is a deprecated Clap alias for the same command variant and
implementation; it is not a second engine.

```text
venom scan <target>  (or deprecated decision-scan alias)
  -> StandardWebDecisionRuntime
      -> RuntimeBudget
          -> Evidence
          -> Knowledge and deterministic rules
          -> Planner
          -> Executor registry and metered broker
          -> Passive / active verification
          -> Experience and bounded continuation
```

The CLI profile permits at most 16 total dispatches, 60 seconds of wall time, a
1 MiB cumulative delivered response-body threshold, a per-probe buffered-body
limit of 256 KiB inherited from `HttpEvidencePolicy`, and an 8,192-character text
sample. It uses planning budget 100, risk limit 40, and at most eight semantic
action cycles. API reasoning, payload binding, semantic extraction, and defense
composition remain absent unless a library host explicitly opts into their
separate APIs.

Text summary, `--explain`, and `--format json` are renderings of the same typed
runtime report. The JSON contract keeps its historical
[`decision-scan/v1`](decision-scan-json-v1.md) name; the command rename does not
reinterpret or fork that wire contract. Runtime outcomes are operational
decisions and verifier results, not Surface-B findings or vulnerability verdicts.

The deterministic modules are compiled through the scanner crate's default
`core` + `scanning` features: `web_runtime`, `web_decision`, `web_reasoning`,
`web_planning`, `web_execution`, `web_verification`, `decision_loop`,
`decision_runner`, `runtime_budget`, `http_evidence`, `planner`, `rules`,
`knowledge`, `experience`, `verification`, and `adaptive`.

Two implemented-and-tested surfaces are host-owned and are not automatically
composed into the default runtime:

- **Semantic extraction** (`semantic`) consumes evidence through a bounded
  library API; `venom scan` does not call it.
- **Defense projection / shadow / enforcement** (`defense`) is an explicit
  library API. `StandardWebDecisionRuntime` does not compose it, and no
  production runtime caller exists in the repository.

## Historical direct-I/O runner (Surface A)

The ordered context, runner, Scanner SDK, and phase modules are absent from the
default scanner and CLI feature sets. A host must compile
`venom-cli/legacy-scanner`, invoke `legacy-scan`, and pass the required
`--acknowledge-legacy-heuristics` flag:

```text
cargo run -p venom-cli --locked --features legacy-scanner -- legacy-scan \
  <authorized-target> --acknowledge-legacy-heuristics
    -> ScanContext
        -> ScanRunner
            -> historical phases/*
```

The phase sequence is:

1. `ReconPhase`
2. `CrawlPhase`
3. `DirectoryFuzzer` — only with the additional
   `--legacy-directory-fuzz` opt-in
4. `ParameterDiscoverer`
5. `SqliScanner`
6. `XssScanner`
7. `SstiScanner`
8. `LfiXxeScanner`
9. `SsrfScanner`

These phases use a shared `reqwest` client directly and do not consume
`RuntimeBudget`. The CLI therefore treats their results as partial heuristic
observations, suppresses untyped phase prose and details, and never presents
them as verifier-backed vulnerability confirmations. `ScanContext` owns a
`KnowledgeBase`, but the historical phases do not consume it; ownership is not
execution participation.

## Optional adapters and platform shell (Surface C)

Default `venom-cli` features are empty, so the binary exposes neither `api` nor
`proxy` unless explicitly compiled:

- `api-adapter` adds `venom api`. The command returns a typed nonzero error
  because `venom-api::start_api` does not bind. The library's `router()` value
  contains only `GET /health` for an application-owned host.
- `proxy-adapter` adds `venom proxy`. It starts the experimental
  fixed-upstream TCP relay described below.

The following matrix separates build availability from actual execution:

| Module / group | Build availability | Execution participation | Default `venom scan` | Support status |
| --- | --- | --- | --- | --- |
| Deterministic stack (`web_runtime`, `decision_runner`, `runtime_budget`, `http_evidence`, `planner`, `rules`, `knowledge`, `experience`, `verification`, `adaptive`, `web_*`, `api_*`) | scanner default (`core`, `scanning`) | Surface B (composed, except opt-in API reasoning) | yes | implemented and tested Preview |
| `semantic` | scanner default | library / test only, host-owned | no | implemented and tested Preview |
| `defense` | scanner default | library / test only, host-owned | no | implemented and tested; not composed into `StandardWebDecisionRuntime` |
| `phases/*`, `runner`, `context`, `sdk` | opt-in (`legacy-scanner`) | Surface A | no | historical alpha runtime / SDK |
| `advanced_detection`, `anomaly` | opt-in (`detection`) | no repository product caller | no | Experimental |
| `post_exploitation`, `persistence`, `reporting`, `realtime`, `dashboard`, `waf` | scanner default (`scanning`) | no default command caller | no | compiled library/scaffold surfaces |
| `ml` | opt-in (`ml`) | no default path | no | Experimental |
| `distributed` | opt-in (`distributed`) | no default path | no | Experimental / scaffold |
| `monitoring` | opt-in (`monitoring`) | no default path | no | Experimental / scaffold |
| `compliance` | opt-in (`compliance`) | no default path | no | Experimental / scaffold |
| `threat_intelligence` | opt-in (`threat-intel`) | no default path | no | Experimental / scaffold |
| `plugin`, `plugins`, `lua_engine` | opt-in (`plugins`) | host-owned | no | source-level extension Preview |
| `venom-api` / `venom api` | CLI opt-in (`api-adapter`) | command fails closed; router is host-owned | no | unsupported listener |
| `venom-proxy` / `venom proxy` | CLI opt-in (`proxy-adapter`) | explicit adapter | no | Experimental fixed-upstream TCP relay |
| Deployment (Helm / Terraform / Kubernetes) | absent | none | no | unsupported; see the [deployment blueprint](../experimental/deployment-blueprint.md) |

Always-compiled support modules not listed separately (for example
`api_gateway`, `auth`, `cache`, `config`, `config_loader`, `event_bus`, `logging`,
`metrics`, and `payload_strategy`) are library plumbing. Compilation does not
mean a default command calls them.

### The proxy is a TCP relay, not a MITM proxy

With `proxy-adapter`, `venom proxy` starts
`venom-proxy::AsyncMitmProxy`. Despite the legacy type name, the current handler
accepts a client TCP connection, opens a connection to fixed upstream
`127.0.0.1:80`, and copies bytes in both directions. It does not parse
`CONNECT`, terminate TLS, present generated certificates, or inspect/modify HTTP.
`CertCache` is not used by the connection path.

## Not implemented

The following must not be described as shipped product behavior: a Relation
Engine, Planes, a Knowledge Graph, a Machine Scanner, a bound API listener, a
supported/configurable MITM proxy, or cloud deployment. The `knowledge` module
is an evidence/hypothesis store, not a knowledge graph.

## How to reproduce the inventory

The feature and module inventory comes from
`crates/venom-scanner/Cargo.toml`, `crates/venom-scanner/src/lib.rs`,
`crates/venom-cli/Cargo.toml`, and `crates/venom-cli/src/main.rs`. Numeric module
counts are intentionally omitted because they drift; generate any count against
a named commit with an explicit command.
