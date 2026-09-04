# OAST correlation foundation

OAST Correlation Foundation V1 is a non-default, provider-neutral library
contract behind the `termivar-scanner` feature `oast-correlation`. It gives a
host a bounded way to correlate DNS or HTTP interaction events with one exact
assessment verification case. It performs no network I/O and is not a scanner
action.

## Authority and identity

The host supplies a fresh 32-byte cryptographically random token. Termivar
rejects the all-zero value, consumes the token by move, redacts it from
`Debug`, and exposes neither the bytes nor a reusable token digest. The host is
responsible for entropy; the contract cannot prove how the bytes were minted.

Registration binds the token-derived public correlation identity to one
authority epoch, one complete `VerificationCase`, its exact subject/resource,
the permitted DNS and/or HTTP protocol set, and an issued-at/expiry interval.
The binding includes action, case, hypothesis, optional payload-strategy, and
hypothesis-transition semantics. Each case, subject, action, and hypothesis
identity is rejected above 256 UTF-8 bytes before hashing or cloning. A handle
does not widen network authority, and a consumed token cannot be registered
again during the authority lifetime.

The private token-reuse fingerprint, binding identity, and correlation identity
use separate versioned SHA-256 domains and length-framed inputs. They are
deterministic pseudonymous identities, not confidentiality mechanisms. Event
keys are separate fixed-width opaque values supplied by the host. The secret
token itself never enters a receipt, report, stable item identity, log,
serialized model, or error.

## Bounded polling lifecycle

Limits are explicit and checked: registrations per authority, polls per
registration, events per poll, unique events per registration, and token TTL.
There is no unbounded or implicitly granting default.

The pure lifecycle is:

1. register one host-minted token against one exact case and protocol set;
2. begin one poll using caller-supplied monotonic time;
3. charge the poll budget before returning a move-only permit;
4. let a future host adapter perform provider I/O outside this contract;
5. stage one bounded batch of already reduced events and consume the permit to
   complete it; or
6. cancel or expire the registration explicitly.

Only one poll may be in flight for a registration. Dropping a permit does not
refund its charge. Permit issuance checks the exact assessment and complete
verification case; event staging checks correlation and protocol grants; and
consuming completion rechecks lifecycle time, canonicalizes the batch, and
validates duplicate and capacity semantics before committing atomically. The
token is consumed and zeroed at registration rather than retained as a polling
credential. A stale, foreign, replayed, mismatched, cancelled, or expired
operation fails closed.

## Event and receipt privacy

An event contains only a fixed opaque event key and the typed protocol class
`DNS` or `HTTP`. It cannot contain a queried name, URL, path, address, header,
body, provider payload, credential, or provider timestamp. Reusing one event
key under the same protocol family is suppressed deterministically even when a
provider reports different reduced metadata; reusing it across DNS and HTTP is
a conflict and rejects the batch. Canonical ordering makes equivalent input
batches produce identical typed, raw-value-free receipts.

Receipts describe correlation and binding identities, protocol counts,
accepted/duplicate counts, polling state, expiry, and cancellation without
implementing `Serialize` or retaining raw callback material. They are audit
contracts only. V1 creates no `Evidence`, `Outcome`, `AssessmentItem`, severity,
or vulnerability conclusion.

## Native provider adapter boundary

The separately gated `oast-native-provider` host-library adapter may feed the
correlation authority only after reducing a bounded response from one exact
self-hosted provider origin. It must use the existing registration and poll
permits; provider events cannot become correlation events by bypassing the
state machine. Provider session, callback, and event identifiers remain
private, while replay suppression and exact verification-case binding remain
owned here.

See [Native OAST provider authority](native-oast-provider-authority.md) for the
fixed HTTPS operations and narrowing parent-budget contract.

## Deliberate exclusions

The provider-neutral foundation itself has no callback service URL, provider
session, HTTP/DNS listener, CLI flag, report field, `WebAssessmentRuntime`
action, background task, clock, random generator, persistence, SSRF/XXE
payload, or target request. Enabling `oast-correlation` alone remains
transport-free. The separate native adapter is not enabled by that feature and
does not prove SSRF.

The separately gated [SSRF OAST query review](ssrf-oast-query-review.md)
provides that target authority for one exact eligible query occurrence. It
still consumes this foundation through exact case binding and requires two
independent fresh callback identities; enabling this foundation alone remains
transport-free and cannot produce an item.
Provider configuration cannot become target-execution authority, and a
callback observation remains distinct from a vulnerability verdict.
