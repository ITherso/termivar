# Runtime map (what actually runs)

> Snapshot: `main` at commit `0208b38`. This page describes the **executable
> truth** of the repository today, not aspirations. Where a capability is not
> wired into a runnable path, it is labelled as such. Release line `0.9.0-alpha`
> is not production-ready.

Venom has **three distinct runtime surfaces**. They are separate on purpose; a
capability existing in one surface does not mean it runs in another.

## A. Default CLI runtime (legacy direct I/O)

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

The phases registered by default (`crates/venom-cli/src/main.rs`), in order:

1. `ReconPhase`
2. `CrawlPhase`
3. `DirectoryFuzzer` — **only** when `--legacy-directory-fuzz` is passed
4. `ParameterDiscoverer`
5. `SqliScanner`
6. `XssScanner`
7. `SstiScanner`
8. `LfiXxeScanner`
9. `SsrfScanner`

This is the only surface that runs when a user invokes the default binary. It
does not consult the deterministic decision runtime below.

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

Modules implementing this surface are compiled under the default feature set
(`core`, `scanning`) but are not invoked by the default CLI scan: `web_runtime`,
`web_decision`, `web_reasoning`, `web_planning`, `web_execution`,
`web_verification`, `decision_loop`, `decision_runner`, `runtime_budget`,
`http_evidence`, `planner`, `rules`, `knowledge`, `experience`, `verification`,
`defense`, `payload_strategies`, and the `api_*` reasoning/evidence modules.

**Semantic Phase 1.5** (`semantic` module: `EntityExtractor`, the producer
contract, and the golden corpus) is implemented and tested, but it is **not yet
wired into the default `venom scan` runtime**. It consumes `Evidence` only.

## C. Platform shell

The remaining modules form a "platform shell" around the two runtimes. Each is
classified by what actually happens today, using two axes: the default feature
set is `["core", "scanning", "detection"]`, and the default execution path is the
`venom scan` phase pipeline in surface A.

| Surface / module | Classification |
| --- | --- |
| `phases/*` (Recon, Crawl, ParameterDiscoverer, Sqli, Xss, Ssti, LfiXxe, Ssrf) | Compiled under default; **executed by the default CLI scan** |
| `phases::DirectoryFuzzer` | Compiled under default; executed **only** with the opt-in `--legacy-directory-fuzz` flag |
| Decision-runtime stack (`web_runtime`, `decision_runner`, `runtime_budget`, `http_evidence`, `planner`, `rules`, `knowledge`, `verification`, `defense`, …) | Compiled under default; **not executed by the default CLI scan** (drives surface B and library hosts) |
| `semantic` (Phase 1.5) | Compiled under default; **implemented and tested, not wired into the default CLI runtime** |
| `advanced_detection`, `anomaly` | Compiled under default (`detection`); not on the default CLI scan path |
| `post_exploitation`, `persistence`, `reporting`, `realtime`, `dashboard`, `waf`, `adaptive`, `sdk` | Compiled under default (`scanning`); not on the default CLI scan path |
| `ml` | **Opt-in feature** (`ml`); not in the default feature set |
| `distributed` | **Opt-in feature** (`distributed`) |
| `monitoring` | **Opt-in feature** (`monitoring`) |
| `compliance` | **Opt-in feature** (`compliance`) |
| `threat_intelligence` | **Opt-in feature** (`threat-intel`) |
| `plugin`, `plugins`, `lua_engine` | **Opt-in feature** (`plugins`) |
| `venom api` CLI / `venom-api` listener | **Unsupported**: `start_api` is a startup hook that does **not** bind a network listener; the `router` exposes only `GET /health` as a library value |
| `venom proxy` CLI / `venom-proxy` | **Experimental**: binds an `AsyncMitmProxy`, but the interception API is unstable and the upstream (`127.0.0.1:80`) is hard-coded — not a supported, configurable MITM proxy |
| Deployment (Helm / Terraform / Kubernetes) | **Unsupported** — removed as non-deployable; see the [deployment blueprint](../experimental/deployment-blueprint.md) |

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
