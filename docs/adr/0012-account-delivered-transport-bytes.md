# ADR 0012: Account delivered transport bytes

- Status: Accepted
- Date: 2026-08-02
- Supersedes: ADR 0009

## Context

ADR 0009 moved request counts and retained response bytes into a host-owned
broker. Retained-byte accounting still allowed bytes already delivered in a
transport chunk to disappear from usage, and request bodies were not charged.
Evidence cannot be the accounting authority because execution may fail before
evidence is emitted or after evidence is committed.

`reqwest` exposes response bodies as chunks whose size is not known until the
chunk is delivered to the collector. A hard zero-overrun wire-byte ceiling is
therefore not enforceable at this abstraction boundary. The runtime must record
the complete delivered chunk, stop further reads, and expose the crossing as a
typed terminal condition instead of hiding it.

## Decision

1. The standard runtime constructs only a metered `HttpRequestBroker`; its
   bootstrap, planned, adaptive, retry, and active executors share one
   accounting authority.
2. A buffered request body is measured and charged atomically with its request
   reservation immediately before dispatch. Opaque or streaming bodies fail
   closed before dispatch.
3. Metered response collectors share one host-owned asynchronous read gate.
   Before each read, the collector checks the remaining session and per-request
   retention allowances.
4. A delivered chunk is recorded in full before only its bounded prefix is
   retained. The broker then stops immediately when that chunk crosses either
   allowance. The global read gate limits transport-threshold overrun to one
   delivered chunk across concurrent collectors.
5. A response-byte threshold crossing halts the same runtime turn with a typed
   `ResponseBytes` limit. Evidence committed before that check remains available
   as bootstrap or `unverified_evidence`; verification and Experience updates do
   not run.
6. `RuntimeUsage.response_bytes` now means response-body bytes delivered to the
   broker collector, not only bytes retained in evidence. This alpha wire field
   keeps its name for source compatibility; replay consumers must treat the
   semantic change as a migration.
7. Automatic redirects and implicit client retries remain disabled. A redirect
   response consumes its originating request; a semantic retry must acquire a
   fresh request and request-body lease.

## Consequences

- No collector starts another body read after the response threshold is full.
- Retained evidence bytes never exceed the remaining session or per-response
  allowance. Delivered usage may exceed the configured threshold by the single
  chunk that revealed the crossing, and that overrun is both charged and
  terminal.
- Request count, request-body bytes, active verification count, and retained
  response bytes remain atomically bounded before their respective side effect.
- Headers, framing, and bytes not read after collection stops are outside the
  response-body metric.
- Standalone legacy constructors remain explicitly unmetered for compatibility
  and are not part of the bounded runtime guarantee.

## Alternatives considered

- Charge only the retained prefix: rejected because delivered bytes would again
  disappear from audit accounting.
- Trust executor-supplied receipts: rejected because a safety boundary cannot
  depend on voluntary post-execution reporting.
- Continue reading after the threshold solely to count discarded bytes:
  rejected because accounting must stop resource use rather than create it.
- Add a new HTTP stack to control wire read sizes: rejected for this change;
  the existing broker can provide a deterministic, bounded collection contract
  without another dependency or architectural layer.
