# Runner

`ScanRunner` is the orchestration boundary for ordered scan phases. It is intentionally responsible for control flow, not vulnerability-specific logic.

## Responsibilities

- register `ScanPhase` trait objects;
- order phases by `phase_number()`;
- enforce per-phase timeouts;
- observe cancellation;
- publish phase lifecycle events;
- aggregate `ScanFinding` values;
- return partial results when a phase fails.

## Execution sequence

```text
register phases
      ↓
sort by phase number
      ↓
check cancellation
      ↓
publish PhaseStarted
      ↓
ScanPhase::execute(context)
      ↓
publish PhaseCompleted or PhaseFailed
      ↓
aggregate findings
```

## Contract boundary

The runner may call methods defined by `ScanPhase`; it must not match on concrete phase types or inspect detector internals. Plugins should be integrated through an adapter implementing a common execution contract rather than by adding plugin-specific branching to the runner.

## Failure behavior

Phase errors and timeouts are logged and emitted as events. They do not panic the process. Cancellation stops subsequent phases and returns findings collected so far.

## Testing expectations

Runner tests should use small fake phases to cover ordering, timeout, cancellation, failure isolation, and finding aggregation. Network behavior belongs in phase tests.
