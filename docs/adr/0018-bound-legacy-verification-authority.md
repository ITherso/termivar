# ADR 0018: Bound legacy verification behind a separate active authority

- Status: Accepted
- Date: 2026-08-14
- Supersedes: ADR 0016's phase-five-to-nine direct-I/O inventory
- Retains: ADR 0016's discovery authority and whole-run accounting decision
- Relates to: ADR 0009, ADR 0012, and ADR 0017

## Context

ADR 0016 moved legacy discovery phases two through four behind one bounded
authority while accurately recording that phases five through nine still used
the raw compatibility client. Those later phases mixed transport success with
broad security labels, and several probes lacked the controls required to
separate a target-specific response from baseline text, generic error pages,
network jitter, encoding, or a request-delivery receipt.

The ordered runner remains a historical compatibility surface. Improving its
built-in verification phases must not imply that it has joined
`StandardWebDecisionRuntime`, that its whole-run resource use is metered, or
that a successful request is a vulnerability verdict.

## Decision

1. Built-in phases five through nine share one context-owned
   `LegacyVerificationAuthority`, separate from the passive discovery
   authority. It accepts only bodyless HTTP(S) requests at the target's exact
   normalized origin, rejects URL credentials, disables automatic redirects
   and retries, and accounts dispatches at the `Active` stage.
2. A configurable `VerificationLimits` envelope bounds total requests,
   per-request timeout, shared monotonic wall time, cumulative delivered
   response-body bytes, and retained bytes per response. Its finite budget
   cannot be reset during a run and cannot consume or replenish the discovery
   envelope. The default shared request ceiling is 96. The five built-in
   consumers also retain phase-local ceilings of 20, 18, 16, 16, and 16
   requests respectively, so one early phase cannot consume the authority
   intended for every later built-in.
3. SQL behavior uses negative baselines and randomized controls. A diagnostic
   must be absent from baseline/control and reproduced by the candidate. Timing
   uses repeated control/test pairs, alternating randomized order, median and
   median-absolute-deviation thresholds, and a bounded request ceiling. Either
   accepted category is only eligible for `NeedsReview`.
4. XSS-named compatibility code is an exact-reflection observer. It sends a
   benign nonce, requires a negative baseline and consistent exact replay, and
   records media type plus a bounded syntactic context. Without browser
   execution evidence it remains `Unknown`, including in script or attribute
   text.
5. Template arithmetic uses randomized operands, an exact expected result, a
   syntactically similar non-evaluating control, a negative baseline, and exact
   replay. An accepted differential is only eligible for `NeedsReview`; it does
   not identify an engine, sandbox escape, or code execution.
6. LFI/XXE is inert by default. An SDK host may explicitly configure a benign,
   scan-specific local-file canary on an authorized fixture using independent
   random identifiers for the file name and expected content. A negative
   baseline, randomized missing-file control, and two exact positive replays
   are required before `NeedsReview` is eligible. The compatibility OOB string
   never dispatches XXE traffic because no trusted callback verifier exists.
7. SSRF is inert by default. With an explicitly configured, validated bare DNS
   OOB domain, the phase may deliver a nonce-bearing callback URL through an
   already observed parameter at the authorized origin. It records only the
   target request's status as typed probe evidence. It does not collect
   callbacks, and HTTP 200, 401, or 403 cannot establish an SSRF conclusion.
   No localhost, cloud-metadata, or sensitive-file probe is compiled as a
   default.
8. A separate context bridge accepts typed public outcomes only from the
   allowlisted SQL-behavior, template-arithmetic, and local-file-canary action
   IDs. Each report must be verifier-produced at the `Active` stage,
   origin-scoped, case-correlated, backed by evidence in the same
   `KnowledgeBase`, marked `NeedsReview`, and configured as knowledge-only so
   it cannot transition a hypothesis. Raw descriptions and severity strings
   never gain this authority.
9. `ScanRunner` checkpoints the typed outcome ledger around each phase. A
   normal return may publish the new verifier outcomes and suppress the same
   phase's raw aggregate. Error, panic, timeout, cancellation, or authority
   exhaustion discards that phase's pending public outcome projection.

## Consequences

- Built-in phases two through nine no longer use the public raw client, and the
  architecture gate rejects raw-client reacquisition, direct dispatch, and
  crossing between the passive and active authority seams.
- The two scoped authorities do not make the complete ordered runner metered.
  Phase one and host-defined custom `ScanPhase` extensions can still use raw
  direct I/O, so request and body accounting for a legacy run remains
  `Unmetered`; elapsed wall time remains observed.
- `LegacyVerificationAuthority` is not `StandardWebDecisionRuntime`, and
  `VerificationLimits` is not the standard runtime's `RuntimeBudget`.
- Same-origin is request scope, not authorization. The operator or SDK host
  remains responsible for permission to send every probe, provision a canary,
  and use an OOB callback domain.
- SQL timing, reflection, template arithmetic, local-file canary observation,
  request delivery, and callback receipt are distinct facts. The first three
  eligible differential categories and the explicit canary stop at
  `NeedsReview`; reflection stops at `Unknown`; SSRF has no verifier outcome.

## Alternatives considered

- **Reuse the passive discovery envelope.** Rejected because active probe
  traffic needs a distinct policy, stage, and budget that cannot consume or
  reset discovery work.
- **Move the phases directly into `StandardWebDecisionRuntime`.** Rejected for
  this focused migration because the historical ordered runner has different
  orchestration, output, and extension contracts.
- **Promote every positive heuristic record to a typed outcome.** Rejected
  because raw strings, HTTP status, exact reflection, and request delivery do
  not supply verifier authority.
- **Keep default local-file, XXE, localhost, or cloud-metadata probes.** Rejected
  because safe defaults require inert behavior or an explicit benign fixture
  and a trustworthy receipt boundary.
