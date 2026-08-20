# Scanner

`venom-scanner` contains the default deterministic evidence/reasoning/runtime stack plus feature-gated historical scan contracts, optional analysis modules, plugins, events, persistence models, and bounded report rendering.

## Default deterministic runtime

Default builds expose `venom scan`, which composes `StandardWebDecisionRuntime` with a fixed bounded profile. Its network actions use the runtime's redirect-disabled metered broker, and its output consists of operational decisions and verifier outcomes rather than findings.

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
for an already constructed `RunReport`. It enables only `core`, performs no I/O,
and has no repository or default CLI caller. It preserves typed run status,
stop classification code, accounting, and steps, and emits a privacy-minimized
outcome projection without serializing fingerprints/private provenance or
calculating risk, severity, findings, or vulnerability verdicts. Format
encoding is not redaction: a host must
pre-redact `target`, `authorized_origin`, step/outcome `action_id`, and outcome
`redacted_summary` values. See [Bounded run-report rendering](reporting.md) and [ADR
0021](adr/0021-render-bounded-run-reports.md).

## Feature flags

| Feature | Purpose | Maturity |
| --- | --- | --- |
| `core` | Transport-neutral evidence, knowledge, planning, and verification contracts | Preview |
| `scanning` | Deterministic evidence, reasoning, planning, execution, verification, and bounded runtime | Preview |
| `legacy-scanner` | Historical ordered runner, context, phases, and Scanner SDK; separate bounded discovery and active-verification slices within an otherwise unmetered run | Legacy |
| `platform-models` | Unwired API/auth/dashboard/persistence/post-exploitation/realtime library models | Experimental |
| `reporting` | Bounded host-library renderer for typed `RunReport`; caller-owned pre-redaction, no I/O, persistence, CLI caller, or verdict generation | Preview |
| `detection` | Signal-definition validation, caller-scored technique catalogs, neutral deviation records, and text matching; no scoring or classification | Experimental |
| `plugins` | Evidence-only native plugin registry; no stock detector plugins | Preview |
| `lua` | Independent registry scaffold; source execution fails closed | Experimental |
| `distributed` | In-process queue/worker models; no remote or durable coordination | Experimental |
| `ml` | Serializable external-model records; no learning, clustering, classification, or execution | Experimental |
| `monitoring` | Caller-supplied performance records and comparisons; no telemetry collector | Experimental |
| `compliance` | Caller-supplied audit/catalog records; no compliance determination | Experimental |
| `threat-intel` | Caller-supplied feed/rule records and catalogs; no correlation or alert engine | Experimental |
| `full` / `research` | Historical all-opt-in compatibility aggregates; not supported product tiers | Experimental |
| `enterprise` | Historical aggregate excluding `threat-intel`; not an enterprise package | Experimental |

Default builds enable exactly `core` and `scanning`. Detection, the historical
runner, platform models, the bounded report renderer, extension runtimes, and the other
feature-flagged surfaces listed above require explicit opt-in. CI compiles the
quarantined feature groups independently, and the architecture gate binds their
module declarations to the expected Cargo features. See the
[runtime map](internals/runtime-map.md).

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
