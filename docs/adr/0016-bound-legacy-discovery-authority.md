# ADR 0016: Bound legacy discovery behind a shared authority

- Status: Accepted
- Date: 2026-08-13
- Relates to: ADR 0009, ADR 0012, ADR 0015, and ADR 0017

## Context

The opt-in ordered runner is a historical compatibility surface, not the
standard decision runtime. Its crawler, directory discovery, and parameter
discovery nevertheless shared the same risks: unconstrained requests, ad hoc
URL handling, partial shared-state writes after a failed batch, and heuristic
responses that could be mistaken for vulnerability confirmation.

Moving only these discovery phases does not make the complete ordered runner
metered. Reconnaissance and phases five through nine still retain the public
legacy `ScanContext.client` capability and can perform direct I/O outside
`StandardWebDecisionRuntime` and `RuntimeBudget`.

## Decision

The legacy crawler (phase two), opt-in directory discovery (phase three), and
parameter discovery (phase four) share one context-owned discovery authority:

1. The authority accepts only HTTP(S) URLs on the target's exact normalized
   origin, rejects URL credentials, disables automatic redirects and implicit
   retries, and exposes a bounded response rather than raw `reqwest` state.
2. One configurable `DiscoveryLimits` envelope bounds link depth, scheduled
   pages, total requests, per-request timeout, shared discovery wall time,
   cumulative delivered response-body threshold, and the retained body for
   each response. As in ADR 0009, one threshold-crossing delivered chunk may be
   charged before further reads/dispatches stop; retained response data remains
   capped. The default limits are finite and a limit denial fails before
   further discovery state is committed.
3. Discovery state is typed, canonically ordered, size-bounded, snapshotted for
   consumers, and committed from a staged delta as one transition. A failed
   crawl or comparison batch cannot publish a partial endpoint/form update.
4. The crawler performs deterministic breadth-first traversal and parses only
   non-truncated `text/html` responses no larger than a hard 64 KiB derivation
   cap with an HTML5 parser. Forms retain their
   canonical action, GET/POST/dialog method, and named descendant controls.
   This is parser-tree-descendant ownership, not complete HTML form-owner
   association. POST and dialog forms are recorded but never converted to GET
   requests.
5. Directory discovery first requests two randomized nonexistent paths for
   every eligible candidate shape (safe parent namespace, trailing slash, and extension). A
   shape is probed only when both bounded control responses are usable and
   normalize identically. A candidate becomes an informational endpoint
   observation only when its normalized bounded response is materially
   distinct from that stable calibration. Query-bearing, dot-prefixed, and
   structurally unsafe candidates fail closed rather than widening control
   traffic.
6. Parameter discovery compares four legs for each candidate: baseline,
   randomized unknown-parameter control, candidate, and identical candidate
   replay. It records a parameter only when the candidate is reproducible and
   differs materially from both controls. Truncation and pre-existing probe
   markers fail closed.
7. Phase records remain `INFO` observations. The typed ordered-run report
   projects compatibility records as `Unknown`; none of these discovery
   transitions is a verifier-backed finding or vulnerability verdict.

## Consequences

- Discovery phases two through four cannot dispatch after their shared request,
  time, or cumulative-body threshold is exhausted; page, depth, origin,
  per-response retention, URL, endpoint, parameter, form, and control state are
  hard-capped.
- Same-origin enforcement is request scope, not authorization. The operator
  still controls whether the target and expected traffic are permitted.
- Random probe values prevent fixed-control collisions and are scrubbed from
  comparison signatures and public observations. Canonically ordered state
  keeps snapshots independent of insertion order.
- The entire ordered run remains `Unmetered` because phases one and five through
  nine retain direct-I/O authority. The discovery authority is not
  `StandardWebDecisionRuntime`, and its limits are not the whole-run
  `RuntimeBudget`.
- The architecture gate removes phases two through four from the allowed direct
  `.send()` inventory, rejects raw-client/state/broker reacquisition in those
  consumers, and retains an explicit direct-I/O inventory for unmigrated phases.
- Public `ScanContext` legacy state remains available for pre-stable host
  compatibility; validated host-seeded entries may be read into discovery
  snapshots, but only the typed authority can perform phase-two-to-four
  transport.

## Alternatives considered

- Report the whole legacy run as metered: rejected because raw client authority
  remains in other phases.
- Reuse `StandardWebDecisionRuntime` or its complete `RuntimeBudget`: rejected
  because this is a scoped migration boundary for a different orchestration
  surface, not composition into the deterministic decision loop.
- Keep phase-local clients and counters: rejected because separate limits do not
  provide one non-refundable authority across crawler, directory, and parameter
  requests.
- Treat status codes, reflection, or a successful request as a finding:
  rejected because discovery observations do not verify a security claim.
