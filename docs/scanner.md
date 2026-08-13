# Scanner

`venom-scanner` contains the default deterministic evidence/reasoning/runtime stack plus feature-gated historical scan contracts, optional analysis modules, plugins, events, persistence, and reports.

## Default deterministic runtime

Default builds expose `venom scan`, which composes `StandardWebDecisionRuntime` with a fixed bounded profile. Its network actions use the runtime's redirect-disabled metered broker, and its output consists of operational decisions and verifier outcomes rather than findings.

## Historical ordered pipeline

The ordered runner, scanner SDK, context, and phases require the non-default
`legacy-scanner` feature. The CLI exposes them only as `legacy-scan`, and only
after `--acknowledge-legacy-heuristics`. It registers reconnaissance, crawling,
parameter discovery, SQL injection, XSS, SSTI, LFI/XXE, and SSRF phases;
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
- Reconnaissance and phases five through nine still use the raw legacy client
  outside `StandardWebDecisionRuntime` and `RuntimeBudget`. Consequently the
  complete ordered run is reported as `Unmetered` even though its discovery
  slice is bounded.

The CLI emits typed completion state, suppresses phase prose/evidence, and
projects compatibility records only as informational `Unknown` observations.
See the [runtime map](internals/runtime-map.md) and
[ADR 0016](adr/0016-bound-legacy-discovery-authority.md).

Each phase implements:

```rust
#[async_trait]
pub trait ScanPhase: Send + Sync {
    fn phase_number(&self) -> u8;
    fn name(&self) -> &'static str;
    async fn execute(&self, ctx: &ScanContext) -> Result<Vec<ScanFinding>>;
}
```

## Feature flags

| Feature | Purpose | Maturity |
| --- | --- | --- |
| `scanning` | Deterministic evidence, reasoning, planning, execution, verification, and bounded runtime | Preview |
| `legacy-scanner` | Historical ordered runner, context, phases, and Scanner SDK; bounded discovery phases within an otherwise unmetered run | Legacy |
| `detection` | Advanced and anomaly detection | Experimental |
| `plugins` | Native plugin registry and Lua engine | Preview |
| `distributed` | Queues, workers, and aggregation | Experimental |
| `ml` | Pattern learning models | Experimental |
| `monitoring` | Performance models | Preview |
| `compliance` | Audit and compliance models | Preview |
| `threat-intel` | Feed and correlation models | Preview |
| `full` / `research` | All optional capabilities | Experimental |

Default builds enable `core` and `scanning`. Detection, the historical runner,
and the other feature-flagged surfaces listed above require explicit opt-in;
some library/scaffold modules still compile under `scanning` without being called
by the default command. See the [runtime map](internals/runtime-map.md).

## Adding a phase

1. Implement `ScanPhase` in `src/phases/`.
2. Keep transport and CLI types out of the implementation.
3. Return internal compatibility records; do not render or claim findings in
   the phase. The typed SDK boundary projects these records only as unresolved
   observations.
4. Cover network failures, cancellation, and false-positive boundaries.
5. Register the phase in the composition root only after its ordering is explicit.

## Safety

Phases can send traffic that affects a target. Use bounded concurrency, timeouts, and conservative defaults. Tests that require external targets must use controlled fixtures and must not run against public services.
