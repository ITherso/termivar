# ADR 0009: Make the standard runtime own transport accounting

- Status: Accepted
- Date: 2026-08-02
- Extends: ADR 0004
- Response-byte semantics amended by: ADR 0012

## Context

Counting semantic actions is not a resource boundary. One executor can issue
multiple requests, redirects and retries can multiply traffic, and a response
can consume bytes before evidence is committed. Accounting inferred later from
successful evidence therefore lets transport work escape the runtime budget.

The standard decision runtime also needs to distinguish its complete wall
deadline from an individual request timeout and to preserve audit history when
transport, accounting, reasoning, or verification fails after earlier work was
committed.

## Decision

The bounded `StandardWebDecisionRuntime` owns one shared HTTP request broker and
one atomic accounting authority:

1. Every built-in HTTP dispatch acquires a non-refundable broker lease at the
   transport boundary. Bootstrap, passive, adaptive, retry, and active requests
   compete for the same total-request budget.
2. Active-verification dispatches also consume the separate active budget.
3. Complete response-body chunks delivered to the collector are charged before
   their bounded prefix is retained. Partial bytes remain charged when a later
   read times out, fails, or is cancelled (see ADR 0012).
4. Automatic redirect following and implicit client retries are disabled. A
   semantic retry must re-enter the broker and acquire another lease.
5. Policy validation and request construction happen before acquiring a lease;
   a refused socket dispatch is accounted, while a pre-dispatch policy failure
   is not.
6. Request timeouts have a typed failure classification distinct from other
   transport failures and the outer wall deadline.
7. An unexpected error after `analyze()` starts carries a process-local failure
   receipt with committed bootstrap work, completed turns, and monotonic usage.
   Cause-specific execution, evidence, and reasoning receipts remain available.
8. The architecture check prevents bounded runtime modules from acquiring a raw
   network client. The broker is the sole transport owner for this profile.
9. Every acquired lease closes into a bounded, raw-target-free, ordered
   dispatch receipt. Unclassified future drops are recorded as cancellation;
   denied pre-dispatch leases create no receipt.

## Consequences

- A multi-request executor, retry, or active verifier cannot exceed the shared
  runtime envelope even when no evidence is ultimately committed.
- Budget denial happens before the refused dispatch and remains explainable
  through typed limit and execution receipts.
- `max_response_bytes` means cumulative response-body bytes delivered to the
  collector, including the single chunk that can cross the threshold. Headers,
  framing, and unread bytes after collection stops are not a bandwidth meter.
- A later denial or failure cannot erase earlier wire-attempt receipts. Their
  hard retention ceiling and omitted count keep the audit bounded and honest.
- The ordered legacy phase runner and manually assembled executor/plugin
  adapters are separate surfaces and do not inherit this guarantee. Their
  existing direct-I/O inventory is frozen by architecture policy while a future
  migration is designed.
- Failure receipts are in-process audit objects, not durable transactions or
  crash-recovery logs.

## Alternatives considered

- Trust executor-supplied request and byte counts: rejected because a safety
  boundary cannot depend on voluntary or perfectly accurate receipts.
- Infer usage from evidence after execution: rejected because failures and
  partial responses can perform unaccounted work.
- Treat one semantic action as one request: rejected because executors, retries,
  and verification may legitimately require more than one dispatch.
- Retrofit the public legacy `ScanContext.client` in this change: rejected
  because custom phases can retain and use that raw capability; claiming an
  enforced budget would require a deliberate API migration.
