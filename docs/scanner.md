# Scanner

`venom-scanner` contains scan contracts, the ordered runner, detection phases, optional analysis modules, plugins, events, persistence, and reports.

## Default pipeline

The CLI currently registers reconnaissance, crawling, directory fuzzing, parameter discovery, SQL injection, XSS, SSTI, LFI/XXE, and SSRF phases.

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
| `scanning` | Runner, phases, adaptive behavior, reporting | Beta |
| `detection` | Advanced and anomaly detection | Experimental |
| `plugins` | Native plugin registry and Lua engine | Preview |
| `distributed` | Queues, workers, and aggregation | Experimental |
| `ml` | Pattern learning models | Experimental |
| `monitoring` | Performance models | Preview |
| `compliance` | Audit and compliance models | Preview |
| `threat-intel` | Feed and correlation models | Preview |
| `full` / `research` | All optional capabilities | Experimental |

Default builds enable `core`, `scanning`, and `detection`.

## Adding a phase

1. Implement `ScanPhase` in `src/phases/`.
2. Keep transport and CLI types out of the implementation.
3. Return structured findings; do not render reports in the phase.
4. Cover network failures, cancellation, and false-positive boundaries.
5. Register the phase in the composition root only after its ordering is explicit.

## Safety

Phases can send traffic that affects a target. Use bounded concurrency, timeouts, and conservative defaults. Tests that require external targets must use controlled fixtures and must not run against public services.
