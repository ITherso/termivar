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

## Boundaries

`DefenseState::observe` is a pure function of its inputs: identical
`(status, headers, body)` always yield an equal `DefenseState`. The module reads
no clock, randomness, knowledge, or transport, and issues no request. It is the
observation half of the split the WAF sprint introduces; escalation policy and a
planner that selects a payload strategy from this evidence are separate, later
steps.
