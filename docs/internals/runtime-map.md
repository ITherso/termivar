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

The separate, non-published `venom-exploit` workspace crate remains outside all
product runtimes. Its default Preview surface owns bounded
`venom.exploit-manifest/v1` metadata, deterministic catalog selection,
applicability/risk declarations, authorization requirements, and lifecycle
vocabulary. Its non-default `orchestration` feature adds an explicit host
library for deterministic planning, host-minted non-deserializable grants,
sealed source-linked implementation bindings, narrow step permits, validated
receipts, impact/cleanup accounting, and `venom.exploit-run/v1` reports. Only a
wholly in-memory `venom-canary` integration fixture exercises that surface.
There is no production target, network, process, browser, filesystem, or
external-callback adapter; no scanner/CLI/API/proxy dependency edge; and no
route from an `AssessmentItem` to an exploit. Repository pack validation is an
explicit `xtask` operation and does not participate in `venom scan`.

The [historical scanner salvage ledger](../history/historical-scanner-salvage.md)
is repository evidence, not runtime authority. The explicit `xtask
scanner-salvage` check reads only the strict ledger, generated report, and local
Git objects for the deleted 38-file tree. Only the historical detector's
byte-pattern component is now marked `Restored` by the separate
`venom-artifact` domain. Its unsafe mmap adapter, fabricated request-path
finding logic, and unsupported optimization claims remain rejected.

`venom-artifact` is not part of either scan runtime. Its Preview library scans
bounded caller-supplied byte slices or `Read` streams and emits exact/wildcard
match observations with deterministic offsets and completion truth. The
non-default CLI `artifact-adapter` owns the only repository file-access edge:
one explicitly selected local regular file, read-only, without recursion,
globbing, process acquisition, network I/O, execution, or file writes. No
signature observation triggers exploit orchestration or becomes a malware or
vulnerability verdict.

## Default deterministic scan runtime (Surface B)

`venom scan <target>` is the canonical CLI path. With no explicit profile, it
composes `StandardWebDecisionRuntime` with the unchanged conservative
single-resource policy and routes every built-in request through its
runtime-owned, redirect-disabled, metered broker. `venom decision-scan` is a
deprecated Clap alias for the same command variant and implementation; it is
not a second engine.

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

venom scan <target> --profile baseline
  -> the same StandardWebDecisionRuntime primitive
  -> additive web-assessment/v1 profile audit

venom scan <target> --profile web-review
  -> WebAssessmentRuntime
      -> one RuntimeBudget / request broker / cancellation / exact-origin policy
      -> stable bounded discovery
      -> StandardWebDecisionRuntime subject work under that shared authority
      -> bounded semantic extraction
      -> defense observation and shadow planning
      -> passive header/cookie assessment projection
      -> root-scoped matched CORS and optional redirect review
      -> one bounded root-or-discovered parser-driven reflection-context pair
      -> one DOM reflection parse + bounded attribute/JavaScript source-anchor passes
      -> at most one assessment-wide evidence-capable XSS structural family
      -> one bounded root-or-discovered SQL structural review with exact replay
      -> one bounded root-or-discovered SSTI arithmetic review with independent replay
      -> optional exact-root anonymous/authorized API visibility pair
      -> central bounded assessment renderer on complete execution
```

The no-profile and explicit `baseline` single-resource policy permits at most 16 total dispatches, 60 seconds of wall time, a
1 MiB cumulative delivered response-body threshold, a per-probe buffered-body
limit of 256 KiB inherited from `HttpEvidencePolicy`, and an 8,192-character text
sample. It uses planning budget 100, risk limit 40, and at most eight semantic
action cycles. API reasoning and payload binding remain absent unless a library
host explicitly opts into their separate APIs.

The strict `venom.scan-profile/v1` schema exposes exactly `baseline` and
`web-review`. Custom profile files, raw transport settings, arbitrary origins,
unbounded concurrency, and deep-merge/override semantics are not supported.
`web-review` applies compiled absolute ceilings and checked profile limits for
subjects, discovery depth, references per document, URL retention, forms,
controls, query-parameter names, total requests, body bytes, wall time, and
active verification count. Every limit fails closed.

Origin discovery is deterministic and bounded. It canonicalizes eligible
absolute, root-relative, relative, and form-action references, removes
fragments and duplicate representations, follows only safe GET/HEAD candidates,
and never silently crosses the authorized exact origin. Forms retain action,
method, and control names only—not values, credentials, CSRF values, or cookie
contents. Discovered subjects and semantic entities are typed knowledge with
provenance, not vulnerability findings.

Committed response evidence is projected into bounded semantic entities and
defense observations. Defense shadow planning is audit-only. Enforcement is
off by default; explicit `--enforce-defense` can only narrow or suppress
already-authorized actions and cannot add actions, increase intensity, or
expand scope/budget.

Passive `web-review` observes HSTS, CSP, X-Content-Type-Options,
Referrer-Policy, Permissions-Policy, and value-free cookie metadata. Its closed
native differential catalog is composed into the authorized root's existing
Standard runtime session, so bootstrap and pair legs share the same broker and
global budget without suppressing eligible standard actions. CORS always uses
a matched no-Origin/candidate pair and requires successful status classes on
both legs. The redirect action exists only when the starting URL supplied a
recognized navigation parameter name; its original value is discarded. Only
301/302/303/307/308 are treated as redirect statuses, and redirects are not
followed. A distinct two-request reflection pair uses a scanner-owned inert
marker and one bounded `html5ever` parse for supported `text/html`. Comment,
ordinary text, and ordinary attribute placement are `Informational`; typed
URI-bearing, style, inline-handler, script-element, and embedded-HTML attribute
placement is at most `NeedsReview`. Quote mode and JavaScript lexical context
are supplied only by their bounded source analyzers and cross-checked with the
DOM; CSS context is not inferred. Exact credentialed CORS and candidate-specific
redirect relationships are also at most `NeedsReview`. Every
native action is KnowledgeOnly, and no native assessment capability can
produce a `Confirmed` item.
For XSS structural selection, one fail-closed linear source pass retains only
an exact normalized host/sink and double-, single-, or unquoted mode, then
cross-checks that anchor against `html5ever`. HTML-text evidence requires the
exact inert scanner node. Ordinary, URI, and event-handler attribute evidence
requires exact inert boundary and tail attributes on that same anchored HTML
host/sink and a clean matched control. A separate bounded, non-evaluating pass
classifies one unique marker on one supported inline classic/module script host.
Single-quoted string, double-quoted string, and template-literal-text families
require exact ordered scanner-owned boundary/tail block-comment tokens outside
the original string/template context on that same host, with neither token in
control. Expression/code, template-expression, line/block-comment, and regex
contexts remain metadata-only. Selection precedes payload materialization and
admits one family, preserving one child bootstrap plus control/candidate—the
three-request ceiling—regardless of catalog size; metadata growth does not add
per-family HTML/JavaScript parses or requests. Lexical boundary evidence remains
KnowledgeOnly and can project at most `NeedsReview`; no JavaScript or browser is
executed.
At most one deterministic query name across the assessment receives SQL
structural review. Two independent matched quote-balance pairs must reproduce
both a status-class and normalized body-structure change. Error text and
latency are not classification inputs; incomplete or inconsistent replay emits
no claim and incomplete collection remains typed incomplete.

The optional authorization-context slice consumes a host-supplied complete
header value only after explicit profile/root validation. It builds a separate
Standard child runtime with the assessment's existing shared authority, then
executes the existing atomic API comparator once. Both legs are active, use
separate principal-isolating connection pools, and share total-request,
response-byte, active-verification, cancellation, deadline, and exact-origin
limits. The compiled default active ceiling is six: four for the closed native
catalog and two for this pair. Equivalent visibility emits no item; a complete
difference is one opaque atomic evidence reference with maximum disposition
`NeedsReview`. Partial collection or a lower exhausted limit is typed
incomplete and cannot be reported as empty success.

The stable item-identity authority preserves `authorized-root@1` for the exact
origin root and registers eligible discovered exact-origin subjects with an
opaque `discovered-resource@1` digest over canonical structure. The identity
contains no query values or readable path material and grants no request
authority. Unsafe subjects and non-root starting targets remain typed
incompleteness and cannot be composed as completed assessment reports.

On the no-profile compatibility path, text summary, `--explain`, and
`--format json` are renderings of the same typed runtime report. The JSON contract keeps its historical
[`decision-scan/v1`](decision-scan-json-v1.md) name; the command rename does not
reinterpret or fork that wire contract. Runtime outcomes are operational
decisions and verifier results, not Surface-B findings or vulnerability verdicts.

Explicit `baseline` uses `web-assessment/v1`. A completed `web-review` uses the
central renderer's `venom-rendered-assessment/v1` schema in JSON, CSV, HTML, or
Markdown; absent `--report-format`, text maps to Markdown and `--format json`
maps to JSON. Incomplete or started-failed origin work emits a redacted
`web-assessment/v2` diagnostic audit to stdout, marks assessment items
unavailable, exits nonzero, and creates no report artifact. `--report-output`
uses exclusive same-directory temporary creation plus hard-link publication,
never overwrites, and fails nonzero where those filesystem semantics are not
available; directory-metadata crash durability is best effort.

The deterministic modules are compiled through the scanner crate's default
`core` + `scanning` features: `web_runtime`, `web_decision`, `web_reasoning`,
`web_planning`, `web_execution`, `web_verification`, `decision_loop`,
`decision_runner`, `runtime_budget`, `http_evidence`, `planner`, `rules`,
`knowledge`, `experience`, `verification`, and `adaptive`.

Internal responsibility splits do not create additional engines. The root
source facades for `plugin`, `decision_loop`, `decision_runner`,
`http_evidence`, `knowledge`, `rules`, `planner`, and `api_observation` remain
public modules. `lua_engine` and `distributed` remain private modules with
reviewed crate-root re-exports. Private child modules own narrower
metadata/context/execution, state/policy/receipt, policy/probe/response,
store/write/query, and coordinator/lease responsibilities.
The architecture gate pins the reviewed child inventory, facade-resident
authority, and allowed cross-domain dependencies so these domains cannot
silently collapse back into responsibility-dense root files.

Composition is selection-specific:

- **Semantic extraction** (`semantic`) consumes evidence through a bounded
  library API. It remains absent from no-profile and `baseline`, but explicit
  `web-review` composes it only after evidence has been committed.
- **Defense projection / shadow / enforcement** (`defense`) is an explicit
  library API. `StandardWebDecisionRuntime` alone does not compose it;
  `WebAssessmentRuntime` records observation/shadow planning, with enforcement
  separately opt-in and monotonic.
- **Lua execution** (`lua`, opt-in) is a bounded registry and fresh-VM executor
  for an explicit library host. It uses cooperative in-process controls, not
  process isolation, with no
  CLI, scanner-phase, or plugin caller.
- **Distributed coordination** (`distributed`, opt-in) is a bounded,
  deterministic process-local task/worker/result state machine for an explicit
  library host. It is not a transport service or multi-node control plane.
- **Exploit foundation** (`venom-exploit`, independent Preview crate) validates
  host-supplied bounded metadata and repository-owned lab manifests. Its
  non-default orchestration API requires an exact host-minted grant before a
  prepared plan can produce step permits. Catalog membership, applicability,
  maturity, a prepared plan, and implementation presence grant no execution
  authority. Attempt, trigger, impact, cleanup, and cleanup verification remain
  distinct facts. Source-linked implementations are cooperative trusted code,
  not sandboxed code. No stock runtime or CLI consumes this API; the only
  executor is an in-memory integration-test fixture.

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
| Deterministic stack (`web_runtime`, `decision_runner`, `runtime_budget`, `http_evidence`, `planner`, `rules`, `knowledge`, `experience`, `verification`, `adaptive`, `web_*`, `api_evidence`, `api_observation`, `api_reasoning`) | scanner default (`core`, `scanning`) | Surface B; no-profile/`baseline` use the single-resource primitive, explicit `web-review` adds the origin orchestrator; API reasoning remains host opt-in | yes, profile-dependent | implemented and tested Preview |
| `semantic` | scanner default | host library and explicit `web-review` post-commit composition | `web-review` only | implemented and tested Preview |
| `defense` | scanner default | host library and explicit `web-review` observation/shadow; enforcement requires `--enforce-defense` | `web-review` only | implemented and tested Preview; cannot add or intensify actions |
| `phases/*`, `legacy_discovery`, `runner`, `context`, `sdk` | opt-in (`legacy-scanner`) | Surface A; phases 2–4 use bounded passive discovery, phases 5–9 use separate bounded active verification, and phase-one/custom raw I/O remains possible | no | Legacy runtime / `ScannerSdk` facade; whole-run accounting remains `Unmetered` |
| `advanced_detection`, `anomaly` | opt-in (`detection`) | no repository product caller; validated/catalogued caller records plus text matching only | no | Experimental; no deviation computation, response classification, or finding production |
| `api`, `api_gateway`, `auth`, `cache`, `config`, `config_loader`, `metrics`, `post_exploitation`, `persistence`, `realtime`, `dashboard` | opt-in (`platform-models`) | no repository product caller | no | Experimental records, catalogs, and in-memory utilities; no API/auth/persistence/realtime execution path, and caller-owned collections are not uniformly capacity-bounded |
| `reporting` | opt-in at scanner boundary; enabled by normal CLI dependency | standalone host `RunReport` rendering and, with `scanning`, typed completed-assessment composition/rendering | completed explicit `web-review` only | Preview bounded renderer; no I/O, persistence, risk synthesis, or verdict invention; see the [reporting guide](../reporting.md) |
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

The default scanner crate feature closure is exactly `core` plus `scanning`.
The normal CLI dependency additionally enables `reporting` for the explicit
completed `web-review` path; this does not alter no-profile execution or its
wire contract.
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

Runtime validation has deliberately narrower evidence boundaries than this
inventory. Rust `1.88.0` smoke jobs exercise loopback CLI/path/scope contracts
on Ubuntu, Windows, and macOS, but do not certify those platforms or duplicate
the all-features matrix. The `compat/current-head/` workspace uses one dedicated
lockfile and separate package tests for default core, deterministic
assessment/reporting, the Legacy `ScannerSdk` facade, and plugin API 0.2 against
the same checkout; they are not cross-version compatibility or
external-adoption evidence.

The loopback-only endpoint harness has one initial controlled record for source
commit `27321efbbf49cb2adbc72afb699d1b31ea407486` from
[workflow run 33292247976](https://github.com/ITherso/venom/actions/runs/33292247976):
[Markdown](../reports/benchmarks/27321ef-endpoint-assessment.md) and
[JSON](../reports/benchmarks/27321ef-endpoint-assessment.json). It exercises
100 endpoints, 1,000 endpoints, and a 10,000-request batch using the real
`WebAssessmentRuntime`. The batch is ten independent origin authorities, not
one global assessment. This evidence is not an SLA, an accepted repeatable
baseline, or a regression threshold.
