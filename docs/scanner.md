# Scanner

`venom-scanner` contains the default deterministic evidence/reasoning/runtime stack plus feature-gated historical scan contracts, optional analysis modules, plugins, events, persistence models, and bounded report rendering.

## Default deterministic runtime

Default builds expose one `venom scan` product with three deliberately distinct
selection states:

- With no `--profile`, `StandardWebDecisionRuntime` keeps the conservative
  single-resource behavior, text/`--explain` output, and the existing
  `decision-scan/v1` JSON contract.
- `--profile baseline` explicitly selects the strict
  `venom.scan-profile/v1` single-resource contract and emits the additive
  `web-assessment/v1` profile audit.
- `--profile web-review` composes the same single-resource primitive inside a
  bounded exact-origin assessment. Deterministic discovery, semantic
  extraction, defense observation/shadow planning, passive header/cookie
  review, and the closed native differential catalog share one runtime-owned
  `RuntimeBudget`, request-accounting broker, cancellation authority, and
  exact-origin policy. Redirects remain disabled.

The exact-origin runtime uses stable bounded discovery and retains canonical
subjects, form actions/methods, form-control names, candidate query-parameter
names, and typed provenance. It does not retain form values or cookie values,
and a discovered resource is knowledge rather than a vulnerability result.
Cross-origin references are rejected rather than becoming new authority.

Passive review observes HSTS, CSP, X-Content-Type-Options, Referrer-Policy,
Permissions-Policy, and value-free cookie metadata. These capabilities project
only `Informational` `AssessmentItem` values. The product claim ladder permits
an observation to become `Informational`, a matched differential to become
`NeedsReview`, and only a verifier-authorized, case-correlated transition under
a confirming claim policy to become `Confirmed`.

Native low-risk review is enabled only by `web-review` and runs on the
authorized starting resource inside the same `StandardWebDecisionRuntime`
session used for its bootstrap. It uses matched CORS control/candidate requests
and, only for a recognized navigation parameter already named by the starting
URL, a matched redirect/reflection query pair. The supplied query value is
discarded. At most one deterministic discovered parameter is also reviewed by
two independent matched SQL quote-balance pairs. The mutation contains no
operator, comment, statement separator, function, or delay syntax. An item
requires the same candidate-specific status-class and normalized body-structure
difference in both pairs; text and latency are not signals. Native actions do
not suppress otherwise eligible standard actions.
A reflected Origin without the complete credential policy or without two
successful-status legs is insufficient. Redirect review accepts only
301/302/303/307/308, and redirects are not followed. Non-dangerous exact
reflection is `Informational`; dangerous-context reflection, credentialed
candidate-specific CORS, and an exact candidate-specific external redirect are
at most `NeedsReview`; the repeatable SQL structural relationship is also at
most `NeedsReview`. Every native action is KnowledgeOnly, and no native
assessment capability can produce a `Confirmed` item.
An explicitly non-HTML response makes reflection review not applicable. A
truncated body, invalid UTF-8, or exhausted DOM/occurrence ceiling instead makes
the selected differential review typed incomplete; it is never reported as an
empty successful assessment.

An explicit root authorization context adds one anonymous/authorized JSON
visibility pair without creating another scanner engine or authority. Library
hosts pass `WebAssessmentRootAuthorizationContext`; the CLI accepts the
complete header value only via `--auth-env`, `--auth-file`, or `--auth-stdin`.
There is no raw credential argument. The option requires `web-review` at the
exact origin root and HTTPS; numeric-IP loopback HTTP is reserved for local
fixtures. A file source must be a regular, non-symlink file. Standard-input
loading waits for EOF and is intentionally controlled by the invoking host.
Profile, target, transport, and obvious report-output failures are resolved
before credential material is read. Both active legs use the same assessment
broker, budget, cancellation token, deadline, and redirect-disabled policy. Equal visibility
produces no item. A complete difference is projected as one atomic comparison
evidence reference and at most `NeedsReview`; it is not decomposed into fake
control/candidate evidence and does not prove an authorization vulnerability.
Incomplete collection stops later discovery and makes the run typed
incomplete. The compiled web-review default reserves six active-verification
slots for the closed four-request native catalog plus this optional two-request
pair; any lower host-selected ceiling still fails closed.

Stable item identity preserves `authorized-root@1` for the exact origin root
and assigns eligible discovered exact-origin subjects a deterministic opaque
`discovered-resource@1` identity. Its digest preimage uses only the stable
scope, method, canonical resource structure, and sorted unique query names;
query values and readable path material are never public identity metadata. A
non-root starting target remains typed incompleteness.

Defense enforcement remains off unless `--enforce-defense` is supplied with
`web-review`. Observation and shadow planning are always non-authoritative;
enabled enforcement can only narrow or suppress existing authorized work. It
cannot add an action, expand exact-origin authority or budgets, or increase
intensity.

## Internal domain facades

The scanner's responsibility-dense domains are split behind their existing
root source facades. `plugin`, `decision_loop`, `decision_runner`,
`http_evidence`, `knowledge`, `rules`, `planner`, and `api_observation` remain
public modules; `lua_engine` and `distributed` remain private modules with
reviewed crate-root re-exports. Private child modules own narrower model,
policy, registry, execution, receipt, storage, query, VM, and coordination
responsibilities. This organization does not add a scanner engine or change any
capability semantics.

`cargo xtask architecture` binds the reviewed child-module inventory, keeps
authority-defining symbols in their facade, rejects responsibility moving back
into the facade or across siblings, and checks allowed cross-domain imports.
Lifecycle remains unchanged: the deterministic assessment and plugin API 0.2
surfaces are Preview, `ScannerSdk` is a Legacy facade, and Lua/distributed host
surfaces are Experimental.

## Historical ordered pipeline

The ordered runner, scanner SDK, context, and phases require the non-default
`legacy-scanner` feature. The CLI exposes them only as `legacy-scan`, and only
after `--acknowledge-legacy-heuristics`. It registers reconnaissance, crawling,
parameter discovery, SQL-behavior observation, reflection observation,
template-arithmetic observation, an inert-by-default file-canary/XXE phase, and
an inert-by-default OOB delivery phase;
`DirectoryFuzzer` requires the additional `--legacy-directory-fuzz` opt-in.

This is currently a mixed-authority pipeline:

- Crawler, optional directory discovery, and parameter discovery (phases two
  through four) share a context-owned exact-origin, redirect-disabled broker.
  `DiscoveryLimits` configures finite crawl-depth, page, request,
  per-request-timeout, wall-time, cumulative-body, and per-response-body
  ceilings across those phases.
- The crawler uses deterministic breadth-first traversal and an HTML5 parser
  only for complete `text/html` bodies no larger than 64 KiB. Its typed forms retain action, method,
  and named parser-tree-descendant controls. POST and dialog forms are recorded,
  never requested as GET.
- Directory discovery compares candidates to two stable randomized
  nonexistent-path controls in the same parent namespace and with the same
  trailing-slash and extension shape. Parameter discovery requires a
  reproducible four-leg differential:
  baseline, randomized unknown parameter, candidate, and identical replay.
  Both produce `INFO` observations, not vulnerability conclusions.
- Discovery endpoints, visits, and forms are staged and committed atomically;
  a failed or budget-exhausted batch does not publish partial state.
- Phases five through nine share a second context-owned exact-origin broker.
  `VerificationLimits` configures its finite request, per-request-timeout,
  wall-time, cumulative-body, and per-response-body ceilings. Requests are
  bodyless, redirects and retries are disabled, and broker accounting uses the
  `Active` stage. The default shared request ceiling is 96; phase-local
  ceilings (20/18/16/16/16) prevent one built-in phase from consuming the full
  envelope. This is a separate migration authority, not the standard runtime's
  `RuntimeBudget`.
- Reproduced SQL diagnostics and robust timing differentials, exact replayed
  template arithmetic, and an SDK host's explicitly configured benign
  local-file canary may project only verifier-owned, knowledge-only
  `NeedsReview`. Exact nonce reflection remains `Unknown` because there is no
  browser-execution verifier. The default phase-eight path dispatches neither
  LFI nor XXE probes; an OOB string does not enable XXE. Phase nine is inert by
  default, and explicit OOB delivery records a nonce-bearing request receipt,
  not callback evidence. No cloud-metadata or sensitive-file destination is a
  default probe.
- Reconnaissance and host-defined custom phases can still use the raw legacy
  client outside both bounded authorities and `RuntimeBudget`. Consequently the
  complete ordered run is reported as `Unmetered` even though built-in phases
  two through nine have scoped limits.

The CLI emits typed completion state and suppresses phase prose/evidence. Raw
compatibility records project only as informational `Unknown` observations;
the allowlisted phase-five, phase-seven, and opt-in phase-eight bridge can
instead publish the verifier-scoped `NeedsReview` outcomes described above.
See the [runtime map](internals/runtime-map.md),
[ADR 0016](adr/0016-bound-legacy-discovery-authority.md), and
[ADR 0018](adr/0018-bound-legacy-verification-authority.md).

Each phase implements:

```rust
#[async_trait]
pub trait ScanPhase: Send + Sync {
    fn phase_number(&self) -> u8;
    fn name(&self) -> &'static str;
    async fn execute(&self, ctx: &ScanContext) -> Result<Vec<ScanFinding>>;
}
```

## Reporting host contract

The independent `reporting` feature exposes a bounded, deterministic renderer
for an already constructed `RunReport`. In its standalone `reporting` feature
closure it still enables only `core`, performs no I/O, and requires the host to
pre-redact `target`, `authorized_origin`, step/outcome `action_id`, and outcome
`redacted_summary` values.

When both `scanning` and `reporting` are enabled, the same `ReportGenerator`
also consumes a completed runtime-owned `WebAssessmentRunReport` plus its
validated profile, internally mints the generic run envelope, and renders a
typed `AssessmentRunReport`. The default CLI enables this combination and uses
it for completed `web-review` JSON, CSV, HTML, and Markdown output under the
same 16 MiB ceiling. Assessment summaries and opaque references are already
redacted before they reach the renderer. The renderer does not create items,
upgrade dispositions, synthesize severity/risk, persist files, or acquire
verdict authority. See [Bounded report rendering](reporting.md), [ADR
0021](adr/0021-render-bounded-run-reports.md), and [ADR
0023](adr/0023-compose-profiled-assessment-reporting.md).

## Endpoint-scale evidence

The endpoint harness exercises the real `WebAssessmentRuntime` only against a
hard-coded `127.0.0.1` fixture. Its fixed workloads cover 100 endpoints, 1,000
endpoints, and 10,000 requests. The last workload is a batch of ten independent
998-subject origin assessments, each with its own broker, budget, cancellation,
and deadline; it is not one 10,000-request authority.

Initial controlled evidence for source commit
`27321efbbf49cb2adbc72afb699d1b31ea407486` is retained from
[workflow run 33292247976](https://github.com/ITherso/venom/actions/runs/33292247976)
as [Markdown](reports/benchmarks/27321ef-endpoint-assessment.md) and
[validated JSON](reports/benchmarks/27321ef-endpoint-assessment.json). These
runner-local observations are not an SLA, capacity limit, concurrency result,
accepted repeatable baseline, or regression threshold. See
[Benchmarks](benchmarks.md) for the authority model and reproduction contract.

## Experimental host execution contracts

The independent `lua` feature closes over `core`, Tokio, and a vendored Lua 5.4
build with no default `mlua` features. It implements approved-root source
snapshot registration and fresh, no-standard-library, text-only VMs with
bounded context/output/return/history and cooperative memory, instruction,
deadline, cancellation, and concurrency controls. These controls are not
process isolation or an OS sandbox; no CLI, scanner phase, or plugin path calls
them. See [Lua execution](lua.md).

The `distributed` feature has an empty raw feature closure and implements bounded ordered
task/worker/result state machines with caller-supplied logical time, expected
revisions, fenced leases, fixed retry/recovery policy, and deterministic output
for a fixed accepted command order. It has no transport, authentication,
serialization, persistence, ambient clock, background work, exactly-once, or
multi-node contract. See [Distributed coordination](distributed.md).

## Feature flags

| Feature | Purpose | Maturity |
| --- | --- | --- |
| `core` | Transport-neutral evidence, knowledge, planning, and verification contracts | Preview |
| `scanning` | Deterministic evidence, reasoning, planning, execution, verification, and bounded runtime | Preview |
| `legacy-scanner` | Historical ordered runner, context, phases, and Scanner SDK; separate bounded discovery and active-verification slices within an otherwise unmetered run | Legacy |
| `platform-models` | Unwired API/auth/dashboard/persistence/post-exploitation/realtime library models | Experimental |
| `reporting` | Bounded generic `RunReport` renderer; with `scanning`, also the central typed assessment renderer used by completed CLI `web-review` runs. No renderer-owned I/O, persistence, or verdict generation | Preview |
| `detection` | Signal-definition validation, caller-scored technique catalogs, neutral deviation records, and text matching; no scoring or classification | Experimental |
| `plugins` | Evidence-only native plugin registry; no stock detector plugins | Preview |
| `lua` | Implemented bounded host-library Lua execution; cooperative in-process controls, no process isolation or repository product/runtime caller | Experimental |
| `distributed` | Implemented deterministic bounded in-process coordination; no transport, persistence, or multi-node runtime | Experimental |
| `ml` | Serializable external-model records; no learning, clustering, classification, or execution | Experimental |
| `monitoring` | Caller-supplied performance records and comparisons; no telemetry collector | Experimental |
| `compliance` | Caller-supplied audit/catalog records; no compliance determination | Experimental |
| `threat-intel` | Caller-supplied feed/rule records and catalogs; no correlation or alert engine | Experimental |
| `full` / `research` | Historical all-opt-in compatibility aggregates; not supported product tiers | Experimental |
| `enterprise` | Historical aggregate excluding `threat-intel`; not an enterprise package | Experimental |

The scanner crate's default build enables exactly `core` and `scanning`.
Detection, the historical runner, platform models, the bounded report renderer,
host execution surfaces, and the other feature-flagged modules listed above
require explicit opt-in at that crate boundary. The CLI's normal dependency
selects `scanning + reporting` so an explicit completed `web-review` can use the
central assessment renderer; omitting `--profile` still preserves the old
runtime and wire behavior. CI compiles these feature groups independently, and
the architecture gate binds their private module declarations, exact root
facades, dependency closures, and authority constraints to the expected Cargo
features. See the [runtime map](internals/runtime-map.md).

## Adding a phase

1. Implement `ScanPhase` in `src/phases/`.
2. Keep CLI types out of the implementation. A built-in phase must use its
   assigned context-owned transport authority; an external custom phase that
   uses the compatibility client keeps the whole run explicitly `Unmetered`.
3. Return internal compatibility records; do not render or claim findings in
   the phase. The typed SDK boundary projects raw records only as unresolved
   observations. New verifier-backed projections require an explicit,
   allowlisted case and claim policy rather than a severity string.
4. Cover network failures, cancellation, and false-positive boundaries.
5. Register the phase in the composition root only after its ordering is explicit.

## Safety

Phases can send traffic that affects a target. Use bounded concurrency, timeouts, and conservative defaults. Tests that require external targets must use controlled fixtures and must not run against public services.
