# Defense observation

The `defense` module is an **observation-only** layer. It turns raw response
signals into a typed, bounded picture of a target's defensive behavior. It never
selects a payload or an evasion technique — that decision belongs to the planner,
which consumes these observations. Keeping detection and payload selection in
separate modules means a change to a defensive fingerprint can never silently
change attack behavior.

The legacy `waf` utility remains for backward compatibility. New work should
build on this layer; payload derivation lives in `payload_strategies`.

## Fingerprinting

`defense::fingerprint` infers the most likely defensive product from response
signals. Matching is deliberately robust:

- header **names** are matched case-insensitively;
- header and body **values** are matched by case-insensitive substring, not exact
  equality, so a brittle `"Server: cloudflare"` equality check is replaced by a
  `server` value containing `cloudflare`;
- `set-cookie` signatures match any cookie value, so session-cookie tells (for
  example `BIGipServer*`, `incap_ses*`) are detected regardless of the rest of
  the header.

Each match carries a `FingerprintConfidence` of `Weak`, `Probable`, or `Strong`,
and the strongest match wins deterministically. AWS signals are intentionally
conservative: an Amazon request id or S3 server banner indicates Amazon
infrastructure, not necessarily a WAF, so the brittle legacy `Server: AmazonS3`
→ AWS WAF inference is dropped in favor of confidence-graded signals. The body is
scanned only up to a fixed byte ceiling, so a large response cannot turn one
observation into unbounded work.

## Defense state

`DefenseState::observe(status, headers, body)` projects one response into a
bounded, deterministic observation:

- `DefenseStatusSignal` — a coarse status class (`Forbidden`, `NotAcceptable`,
  `Teapot`, `RateLimited`, `ServerError`, or `Normal`);
- challenge markers found in the (bounded) body prefix;
- rate-limit signals, from a `429` status or rate-limit accounting headers;
- an optional product fingerprint;
- an overall `DefensePosture` of `Open`, `Suspected`, or `Blocking`.

Posture derivation is conservative and separates deliberate blocks from ambiguous
conditions: a `403`/`406`/`418` status or a challenge body is `Blocking`; rate
limiting or a product fingerprint alone is only `Suspected`; a `5xx` on its own is
not treated as a block. The observation makes no payload or escalation decision;
it is the evidence a planner would weigh before choosing a strategy.

## Defense transitions

`DefenseTransition::between(control, candidate)` is the deterministic difference
between two observations of the same target — typically a baseline (control)
response and a response to a strategy-derived candidate request. It reports:

- a `PostureShift` of `Escalated`, `Deescalated`, or `Unchanged`, derived from
  the ordered postures;
- whether the candidate became newly blocking or newly rate limited;
- whether the coarse status class or the fingerprinted product changed;
- a `DefenseTransitionKind` summary of `NoChange`, `DefenseEngaged`,
  `DefenseRelaxed`, or `DefenseReconfigured` (same posture level, different
  signals).

A transition is evidence, not a decision. It is the signal a planner would weigh
to decide whether to escalate to a different payload strategy, back off, or
re-fingerprint — the escalation policy itself is a separate, later step.

## Escalation policy

`defense::policy::recommend(state, transition)` is the single place that turns
observation into a recommendation. It maps a `DefenseState` and an optional
`DefenseTransition` into a `DefenseResponse`:

- `Proceed` — no defensive reaction;
- `Observe` — defensive infrastructure present but not blocking;
- `Backoff` — rate limiting is in effect;
- `Reconsider` — the candidate provoked a block the control did not, so the block
  is attributed to the candidate request and the planner should change strategy;
- `Halt` — a standing hard block or challenge.

`DefenseResponse` is ordered by restrictiveness, so a caller weighing several
observations can take the maximum. The policy recommends but never acts: it
selects no payload and issues no request. Wiring the recommendation into planner
strategy selection is the next, separate step.

## Evidence projection

`defense::projection` adapts the observation contracts above into immutable
`venom_core::Evidence` a knowledge store can retain with full provenance. It is
strictly projection-only:

- `project_defense_state` / `project_defense_transition` return `Vec<Evidence>`;
  `project_outcome` handles an `ObservedOutcome`, returning an empty vector for
  `NoResponse` so a timeout or connection failure is **never** learned as a
  defensive signal.
- It emits **observations only** — never a `Fact` or hypothesis — so a single
  block never becomes a "confirmed WAF" claim, and a bare block with no matching
  fingerprint yields no product predicate.
- Predicates are namespaced under `defense.*` — for example
  `defense.posture.blocking`, `defense.status.blocked`,
  `defense.challenge.present`, `defense.rate_limit.observed`,
  `defense.fingerprint.cloudflare`, and `defense.transition.engaged`.
- Each record carries its producer (`EvidenceSource` component), the resource
  (`subject`), the case/action correlation, the observation sequence and
  supporting response receipt (folded into a deterministic evidence id), and —
  for a fingerprint — the fingerprint confidence as the record reliability.
- Identity and timestamp come from a caller-supplied
  `DefenseObservationContext`, so the projection is a pure, deterministic,
  idempotent function. It reads no clock or randomness, selects no payload,
  issues no request, and touches neither the planner nor the executor.

Callers ingest the result through the existing
`KnowledgeBase::insert_evidence_batch`. Reading these predicates during planning
is a separate, later step behind a default-off flag.

## Boundaries

`DefenseState::observe` is a pure function of its inputs: identical
`(status, headers, body)` always yield an equal `DefenseState`. The module reads
no clock, randomness, knowledge, or transport, and issues no request. It is the
observation half of the split the WAF sprint introduces; escalation policy and a
planner that selects a payload strategy from this evidence are separate, later
steps.
