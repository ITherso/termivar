# Runner

`ScanRunner` is the orchestration boundary for ordered scan phases. It is intentionally responsible for control flow, not vulnerability-specific logic.

## Responsibilities

- register `ScanPhase` trait objects;
- order phases by `(phase_number(), name())`;
- enforce per-phase timeouts;
- observe cancellation;
- publish phase lifecycle events;
- convert raw `ScanFinding` values at a claim-safe compatibility boundary;
- return typed completion, failure, timeout, cancellation, and skip state.

## Execution sequence

```text
register phases
      ↓
sort by phase number, then name
      ↓
reject duplicate number/name identities
      ↓
validate bounded report envelope
      ↓
check cancellation
      ↓
publish PhaseStarted
      ↓
ScanPhase::execute(context)
      ↓
publish PhaseCompleted or PhaseFailed
      ↓
build typed run report
```

## Contract boundary

The runner may call methods defined by `ScanPhase`; it must not match on concrete phase types or inspect detector internals. Plugins should be integrated through an adapter implementing a common execution contract rather than by adding plugin-specific branching to the runner.

## Failure behavior

Phase errors, panics while polling phase execution, and timeouts are emitted as typed failed/timed-out
steps. They do not become empty success. Cancellation drops the structurally
owned `ScanPhase::execute` future, marks subsequent phases skipped, and returns
a `Cancelled` report. Exhaustion of the shared phase-two-to-four discovery
authority records `BudgetExhausted`, skips dependent later phases, and returns
an incomplete report rather than continuing into unmetered work. Dropping the
caller's run future follows the same owned
drop path instead of detaching phase execution. A phase must structurally
own any child tasks it starts so dropping `execute` aborts them; detached tasks
are outside the runner's control
and violate the phase contract. Panic isolation catches only panics that unwind
while polling `execute`, not `panic = "abort"` builds or detached work.
Because this historical runner does not own all of its phases' transport,
request and body-byte accounting is explicitly `Unmetered`; elapsed wall time
is merely observed. The separate bounded authority used by discovery phases two
through four cannot account for raw I/O in custom phases or phases one and five
through nine.

## Testing expectations

Runner tests should use small fake phases to cover ordering, timeout, cancellation, failure isolation, and finding aggregation. Network behavior belongs in phase tests.
