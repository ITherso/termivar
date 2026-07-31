# Runner internals

`ScanRunner` owns execution policy for `ScanPhase` trait objects. Registering a phase inserts it into a list sorted by `phase_number`; running the pipeline executes that list sequentially.

## Phase lifecycle

For each phase, the runner:

1. checks the shared cancellation token;
2. writes structured and human-readable start telemetry;
3. publishes `PhaseStarted`;
4. races `ScanPhase::execute` against cancellation and the configured timeout;
5. publishes `PhaseCompleted` or `PhaseFailed`;
6. appends successful findings in phase order.

Errors and timeouts do not stop later phases. Cancellation stops the loop. In every case, findings from previously completed phases are returned as partial results.

## Ownership

The runner owns ordering, timeout, cancellation, lifecycle events, and aggregation. A phase owns detection behavior and may use only the shared `ScanContext` contract. The runner must never inspect a concrete phase or plugin type.

`ScannerSdk` is the public composition layer above the runner. It creates the context, HTTP client, telemetry channel, cancellation token, and event bus, then returns a `ScanReport`.

## Current constraints

- Execution is sequential; there is no dependency graph or parallel phase scheduling.
- Duplicate phase numbers are allowed and retain no documented tie-break guarantee.
- Errors are normalized into log/event strings and are not returned in `ScanReport` as structured phase outcomes.
- The SDK creates a new cancellation token for each scan and does not yet expose cancellation to its caller.

Changes to these semantics require focused ordering, timeout, cancellation, failure-isolation, and partial-result tests.
