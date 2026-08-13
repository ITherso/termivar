# Runner internals

`ScanRunner` owns execution policy for `ScanPhase` trait objects. Registering a
phase inserts it into a list sorted by `(phase_number, name)`; running the
pipeline executes that list sequentially.

## Phase lifecycle

Before any phase can publish telemetry or run, the runner validates the bounded
public report envelope and observes a pre-existing cancellation signal. For
each phase that remains eligible, the runner:

1. rechecks the shared cancellation token;
2. writes structured and human-readable start telemetry;
3. publishes `PhaseStarted`;
4. races `ScanPhase::execute` against cancellation and the configured timeout;
5. publishes `PhaseCompleted` or `PhaseFailed`;
6. accepts new allowlisted verifier-owned `NeedsReview` outcomes after a normal
   phase completion, otherwise converts successful raw phase records into a
   zero-confidence `Unknown` aggregate with no fabricated evidence identity;
7. records one typed step status for every registered phase.

Ordinary phase errors, panics while polling phase execution, and timeouts do not
stop later phases, but they make the run `Partial` or `Failed`; they can no
longer become an empty successful result. A typed `BudgetExhausted` step from
either bounded legacy authority stops the dependent remainder of the ordered
pipeline and records those later phases as `Skipped`, preventing other legacy
work from continuing after that authority is depleted.
Cancellation stops the loop. The active `ScanPhase::execute` future is dropped
before the runner returns, and later phases are represented as `Skipped`.
Dropping the caller's `run_pipeline` future follows the same structurally owned
drop path instead of detaching phase execution. The runner cannot reclaim work
that a phase detaches: phase
implementations must keep child tasks structurally owned and ensure dropping
their `execute` future aborts that work. The built-in concurrent legacy phases
use drop-aborting task sets for this reason.

## Ownership

The runner owns ordering, timeout, cancellation, lifecycle events, and
aggregation for the owned `execute` future. A phase owns detection behavior and
all child work it starts, and may use only the shared `ScanContext` contract.
Third-party phases must not detach tasks that can outlive `execute`. The runner
must never inspect a concrete phase or plugin type.

`ScannerSdk` is the public composition layer above the runner. It creates the
context, HTTP client, telemetry channel, cancellation token, and event bus, then
returns the shared `venom_core::RunReport` contract.

## Current constraints

- Execution is sequential; there is no dependency graph or parallel phase scheduling.
- Duplicate phase numbers are ordered by the stable phase name. Two
  implementations with the same number and name are rejected before any phase
  event, state mutation, or I/O so report identity cannot depend on insertion order.
- Discovery phases two through four share a bounded passive HTTP authority;
  phases five through nine share a distinct bounded authority accounted at the
  `Active` stage. Both enforce exact-origin, bodyless, redirect-disabled
  transport with separate request/time/body envelopes. Phase one and custom
  phases can still perform raw direct I/O. Whole-run request and body-byte
  accounting is therefore `Unmetered`, never a fabricated zero; elapsed wall
  time is recorded only as observed.
- Raw phase descriptions, claimed severity, and evidence do not cross the
  public report boundary. The report retains a stable fingerprint, trusted
  phase action identity, an informational/unassessed severity, fixed rationale,
  and a bounded redacted summary. A non-informational impact rating requires a
  separate verifier-backed projection policy; an action `Success` alone is not
  enough.
- Corrected built-in phases have a narrower typed seam. The context accepts
  only allowlisted SQL-behavior, template-arithmetic, and local-file-canary
  reports that are active, case-correlated, knowledge-only, origin-scoped, and
  `NeedsReview`. The runner checkpoints that ledger per phase, publishes it
  only after normal completion, suppresses a duplicate raw aggregate, and
  rolls the ledger slice back on error, panic, timeout, cancellation, or
  transport-budget exhaustion. XSS reflection has no such verifier and remains
  `Unknown`; SSRF probe receipts remain knowledge evidence without an outcome.
- Panic isolation catches panics that unwind while polling `ScanPhase::execute`;
  it is not
  a process-crash boundary and cannot recover from `panic = "abort"` or from
  detached child tasks.

Changes to these semantics require focused ordering, timeout, cancellation, failure-isolation, and partial-result tests.
