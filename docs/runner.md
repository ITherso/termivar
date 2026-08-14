# Runner

`ScanRunner` is the orchestration boundary for ordered scan phases. It is intentionally responsible for control flow, not vulnerability-specific logic.

## Responsibilities

- register `ScanPhase` trait objects;
- order phases by `(phase_number(), name())`;
- enforce per-phase timeouts;
- observe cancellation;
- publish phase lifecycle events;
- convert raw `ScanFinding` values at a claim-safe compatibility boundary;
- accept only allowlisted verifier-owned, knowledge-only `NeedsReview` outcomes
  from corrected built-in phases;
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
accept verifier outcome ledger or sanitize raw records
      ↓
publish PhaseCompleted or PhaseFailed
      ↓
build typed run report
```

## Contract boundary

The runner may call methods defined by `ScanPhase`; it must not match on
concrete phase types or inspect detector internals. Native plugins remain
outside this ordered runner. The deterministic decision runner can instead
adapt one registered plugin through `PluginDecisionExecutor` and a host-owned
`PluginExecutionRequestProvider`; that bridge forwards observation evidence and
does not convert successful plugin execution into a finding.

## Failure behavior

Phase errors, panics while polling phase execution, and timeouts are emitted as typed failed/timed-out
steps. They do not become empty success. Cancellation drops the structurally
owned `ScanPhase::execute` future, marks subsequent phases skipped, and returns
a `Cancelled` report. Exhaustion of either the phase-two-to-four discovery
authority or the separate phase-five-to-nine active-verification authority
records `BudgetExhausted`, skips dependent later phases, and returns an
incomplete report rather than continuing into other legacy work. Dropping the
caller's run future follows the same owned
drop path instead of detaching phase execution. A phase must structurally
own any child tasks it starts so dropping `execute` aborts them; detached tasks
are outside the runner's control
and violate the phase contract. Panic isolation catches only panics that unwind
while polling `execute`, not `panic = "abort"` builds or detached work.
Because this historical runner does not own all of its phases' transport,
request and body-byte accounting is explicitly `Unmetered`; elapsed wall time
is merely observed. The distinct bounded authorities used by discovery phases
two through four and active-verification phases five through nine cannot account
for raw I/O in phase one or custom phases, and neither is the standard
runtime's `RuntimeBudget`.

The runner checkpoints the verifier-outcome ledger before each phase. A normal
completion publishes any new typed outcomes and suppresses the same phase's raw
compatibility aggregate; a failure, panic, timeout, cancellation, or bounded
transport exhaustion rolls that public ledger slice back. The bridge accepts
only active, case-correlated, knowledge-only `NeedsReview` reports from the
allowlisted SQL-behavior, template-arithmetic, and local-file-canary actions.
All other raw phase records remain informational `Unknown`.

## Testing expectations

Runner tests should use small fake phases to cover ordering, timeout,
cancellation, failure isolation, raw-record sanitization, and typed-outcome
rollback. Network and claim-specific control behavior belongs in phase tests
against local fixtures.
