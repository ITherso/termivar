# Runtime map (what actually runs)

> This page describes the executable truth of the current main-line source, not
> aspirations. A compiled module is not necessarily part of a product runtime.
> This unreleased source state uses package version `0.10.0-alpha.1`; the published
> `v0.9.0-alpha` tag predates this runtime map. Neither is production-ready.

The historical audit and its final dispositions are kept separately in the
[runtime-truth remediation closure](../audits/runtime-truth-remediation-closure.md).

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

Among the implemented-and-tested host-owned APIs, these four
decision/runtime-adjacent surfaces are not automatically composed into the
default runtime:

- **Semantic extraction** (`semantic`) consumes evidence through a bounded
  library API; `venom scan` does not call it.
- **Defense projection / shadow / enforcement** (`defense`) is an explicit
  library API. `StandardWebDecisionRuntime` does not compose it, and no
  production runtime caller exists in the repository.
- **Lua execution** (`lua`, opt-in) is a bounded registry and fresh-VM executor
  for an explicit library host. It uses cooperative in-process controls, not
  process isolation, with no
  CLI, scanner-phase, or plugin caller.
- **Distributed coordination** (`distributed`, opt-in) is a bounded,
  deterministic process-local task/worker/result state machine for an explicit
  library host. It is not a transport service or multi-node control plane.

## Historical mixed-authority runner (Surface A)

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
5. `SqliScanner` — bounded SQL-behavior differentials
6. `XssScanner` — bounded exact-reflection observation
7. `SstiScanner` — bounded template-arithmetic differential
8. `LfiXxeScanner` — inert by default; SDK-only benign file-canary opt-in,
   with XXE dispatch quarantined
9. `SsrfScanner` — inert by default; SDK-only OOB delivery opt-in records probe
   receipts without collecting callbacks

The whole ordered run remains `Unmetered`: phase one and host-defined custom
phases can retain the raw legacy `reqwest` client. The run report therefore
cannot derive complete request or body usage even though built-in phases two
through nine use scoped bounded transport authorities. Neither authority is the
standard runtime's `RuntimeBudget`.

Phases two through four are one deliberately narrow migration boundary. They
share a context-owned passive, exact-origin, redirect-disabled request
authority with finite configurable limits for crawl depth, scheduled pages,
total requests, per-request timeout, shared wall time, cumulative delivered
response-body bytes, and retained bytes per response.

The bounded discovery slice has these semantics:

- Phase two performs deterministic breadth-first traversal, parses only
  non-truncated `text/html` bodies no larger than 64 KiB, and commits canonically ordered endpoints, visits,
  and typed forms atomically. Form ownership covers parser-tree descendants;
  POST and dialog forms are recorded with named controls but are never
  flattened into GET requests.
- Optional phase three calibrates two stable randomized nonexistent-path
  responses for each eligible depth/trailing-slash/extension shape before
  recording a materially distinct endpoint. Candidates equivalent to the
  normalized wildcard/soft-404 or redirect controls are suppressed. HTTP 401/403
  can remain endpoint observations, not authentication findings.
- Phase four uses baseline, randomized unknown-parameter, candidate, and
  identical-replay legs. A parameter is recorded only when the candidate is
  reproducible and differs materially from both controls.
- A transport, cancellation, limit, state-validation, or comparison-batch failure
  publishes no partial discovery delta.

Discovery records are informational observations. The CLI suppresses raw phase
prose/evidence and projects any compatibility records as `Unknown`; neither
successful transport nor a differential is a verifier-backed finding or
vulnerability verdict. See
[ADR 0016](../adr/0016-bound-legacy-discovery-authority.md).

Phases five through nine form a second migration boundary. They share a
distinct context-owned, exact-origin, redirect- and retry-disabled authority
with a finite `VerificationLimits` envelope for total requests, per-request
timeout, shared wall time, cumulative delivered response-body bytes, and
retained bytes per response. Requests are bodyless and charged at the `Active`
stage inside this authority; they do not consume or reset the passive discovery
envelope.

The active slice has these claim semantics:

- Phase five requires a negative baseline, a randomized control, an exact
  diagnostic replay, or repeated control/test timing samples with alternating
  order and robust median/MAD thresholds. Accepted SQL-behavior categories can
  project only knowledge-only `NeedsReview`.
- Phase six requires reproducible byte-exact reflection of a benign nonce and
  records response content type and a bounded context classification. A nonce
  already present in the baseline, a truncated response, an encoded-only value,
  or inconsistent replay is rejected. With no browser-execution verifier, the
  public result remains `Unknown` even for an HTML script or attribute context.
- Phase seven uses randomized arithmetic operands, a syntactically similar
  non-evaluating control, an exact expected result, and exact replay. An
  accepted differential can project only knowledge-only `NeedsReview`; it does
  not identify a template engine or code execution.
- Phase eight dispatches nothing by default. An SDK host can explicitly provide
  two independent version-four UUIDs for a benign canary file name and expected
  contents on an authorized fixture. Baseline and randomized missing-file
  controls must be negative, and two candidate replays must contain the exact
  marker before a knowledge-only `NeedsReview` outcome is eligible. XXE remains
  inert even when the compatibility OOB string is set.
- Phase nine dispatches nothing by default. An SDK host may configure a
  validated bare DNS OOB domain; Venom then delivers a nonce-bearing callback
  URL only through already observed parameters at the authorized origin and
  records the target request's status as typed probe evidence. It has no
  callback collector or verifier, so HTTP 200, 401, or 403 produces no SSRF
  conclusion. No localhost, cloud-metadata, or other sensitive default payload
  is compiled into this phase.

Only allowlisted phase-five, phase-seven, and opt-in phase-eight action IDs can
cross the context's verifier bridge. Reports must be active, origin-scoped,
case-correlated, knowledge-only `NeedsReview` outcomes backed by evidence in the
same `KnowledgeBase`; raw phase strings never gain that authority. The runner
checkpoints this typed ledger per phase and discards the phase's public
projection on error, panic, timeout, cancellation, or bounded-transport
exhaustion. See
[ADR 0018](../adr/0018-bound-legacy-verification-authority.md).

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
| Deterministic stack (`web_runtime`, `decision_runner`, `runtime_budget`, `http_evidence`, `planner`, `rules`, `knowledge`, `experience`, `verification`, `adaptive`, `web_*`, `api_evidence`, `api_observation`, `api_reasoning`) | scanner default (`core`, `scanning`) | Surface B (composed, except opt-in API reasoning) | yes | implemented and tested Preview |
| `semantic` | scanner default | library / test only, host-owned | no | implemented and tested Preview |
| `defense` | scanner default | library / test only, host-owned | no | implemented and tested; not composed into `StandardWebDecisionRuntime` |
| `phases/*`, `legacy_discovery`, `runner`, `context`, `sdk` | opt-in (`legacy-scanner`) | Surface A; phases 2–4 use bounded passive discovery, phases 5–9 use separate bounded active verification, and phase-one/custom raw I/O remains possible | no | historical alpha runtime / SDK; whole-run accounting remains `Unmetered` |
| `advanced_detection`, `anomaly` | opt-in (`detection`) | no repository product caller; validated/catalogued caller records plus text matching only | no | Experimental; no deviation computation, response classification, or finding production |
| `api`, `api_gateway`, `auth`, `cache`, `config`, `config_loader`, `metrics`, `post_exploitation`, `persistence`, `realtime`, `dashboard` | opt-in (`platform-models`) | no repository product caller | no | Experimental records, catalogs, and in-memory utilities; no API/auth/persistence/realtime execution path, and caller-owned collections are not uniformly capacity-bounded |
| `reporting` | opt-in (`reporting`) | source-level host library only; consumes typed `RunReport` with caller-pre-redacted projected text fields | no | Preview bounded renderer; performs encoding but no redaction, I/O, persistence, finding/risk synthesis, verdict authority, or repository caller; see the [reporting guide](../reporting.md) |
| `ml` | opt-in (`ml`) | external-model records only; no repository computation or execution | no | Experimental data-model scaffold |
| `distributed` | opt-in (`distributed`) | explicit host-owned process-local coordinator/result APIs; no repository product/runtime caller | no | implemented and tested Experimental; bounded ordered state, explicit logical time/revisions, leases, retry/recovery, and fixed-command-order determinism; no transport, authentication, serialization, persistence, background work, exactly-once, or multi-node service |
| `monitoring` | opt-in (`monitoring`) | no default path | no | Experimental / scaffold |
| `compliance` | opt-in (`compliance`) | no default path | no | Experimental / scaffold |
| `threat_intelligence` | opt-in (`threat-intel`) | no default path | no | Experimental / scaffold |
| `plugin` | opt-in (`plugins`) | host-owned; `PluginDecisionExecutor` can forward registry observations when a host supplies the execution request | no | source-level extension Preview; no stock detector plugins or dynamic loading |
| `lua_engine` | opt-in (`lua`) | explicit host-owned approved-root registry/executor; no repository product/runtime caller | no | implemented and tested Experimental; fresh text-only no-standard-library Lua 5.4 VMs with cooperative per-execution/registry limits, not process isolation |
| `venom-api` / `venom api` | CLI opt-in (`api-adapter`) | command fails closed; router is host-owned | no | unsupported listener |
| `venom-proxy` / `venom proxy` | CLI opt-in (`proxy-adapter`) | explicit adapter | no | Experimental fixed-upstream TCP relay |
| Deployment (Compose / Helm / Terraform / Kubernetes) | absent | none | no | unsupported; see the [deployment blueprint](../experimental/deployment-blueprint.md) |

The default scanner feature closure is exactly `core` plus `scanning`.
`LuaEngineConfig` is a small shared support type reachable through either
`platform-models` or `lua`; the broader `config` module remains platform-only.
The raw `lua` closure is exactly `core`, optional `mlua`, and optional Tokio;
`mlua` disables defaults and enables only vendored Lua 5.4. The raw
`distributed` closure is empty. `event_bus` and `logging` are historical
`legacy-scanner` host utilities. The architecture gate checks private opt-in
module declarations, exact root facades and dependency closures, production
API/source fingerprints, and authority constraints, and prevents a broad
default feature from silently restoring either host surface.

### The proxy is a TCP relay, not a MITM proxy

With `proxy-adapter`, `venom proxy --addr <LISTEN> --upstream <UPSTREAM>` starts
`venom-proxy::FixedUpstreamTcpRelay`. Both socket addresses are explicit; there
is no implicit destination. The handler accepts a client TCP connection, opens
the configured upstream connection, and copies bytes in both directions. It
does not parse `CONNECT`, terminate TLS, generate/present certificates, or
inspect/modify HTTP.

## Not implemented

The following must not be described as shipped product behavior: a Relation
Engine, Planes, a Knowledge Graph, a Machine Scanner, a bound API listener, a
supported/configurable MITM proxy, a Lua process-isolation service, a
distributed transport/control plane, or cloud deployment. The `knowledge`
module is an evidence/hypothesis store, not a knowledge graph.

## How to reproduce the inventory

The feature and module inventory comes from
`crates/venom-scanner/Cargo.toml`, `crates/venom-scanner/src/lib.rs`,
`crates/venom-cli/Cargo.toml`, and `crates/venom-cli/src/main.rs`. Numeric module
counts are intentionally omitted because they drift; generate any count against
a named commit with an explicit command.
