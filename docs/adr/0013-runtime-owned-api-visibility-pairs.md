# ADR 0013: Run authorized API visibility pairs as a runtime-owned workflow

- Status: Accepted
- Date: 2026-08-03
- Extends: ADR 0006, ADR 0011, and ADR 0012

## Context

ADR 0006 established a transport-free boundary for ingesting a comparison that
an authorized host had already produced. Venom still lacked a native path that
could collect both views while enforcing the standard runtime's request,
response-byte, active-verification, cancellation, and wall-time budgets.

Putting this operation behind a normal `DecisionActionExecutor` would weaken an
existing invariant. Executor evidence belongs to the outstanding endpoint case,
whereas a paired visibility observation belongs to an isolated
`api-comparison:*` subject and reaches its logical resource through one
evidence-backed relation. It would also let the planner initiate requests that
carry two authorization contexts without a distinct host authorization step.

The two requests may contain credentials and may encounter connection-bound
server state. They therefore need separate connection pools without splitting
the runtime's accounting authority. A partial pair must remain auditable but
must never be interpreted as a visibility comparison.

## Decision

1. `StandardWebDecisionRuntime::run_api_visibility_pair` is an explicit,
   host-triggered, single-use workflow. It is not a planner-selected action,
   payload capability, `DecisionLoopCommand`, or general-purpose fuzzer. Once
   pre-I/O configuration and target checks succeed, it consumes the runtime's
   execution right even if collection later stops.
2. The first native slice accepts only an authorization-context pair over JSON
   HTTP. Both legs use `GET` and the exact runtime target, including scheme,
   authority, path, and query. Authenticated transport requires HTTPS except
   for an exact loopback fixture target.
3. The host explicitly declares the bounded set of context-owned credential
   and supporting anti-CSRF header names. At least one primary credential header
   must differ. All non-context headers must be identical, and method, target,
   body shape, and request-representation headers cannot vary through this
   contract.
4. Control and candidate use separate redirect-disabled, implicit-retry-disabled
   connection pools. Both pools retain the same immutable HTTP policy and the
   same host-owned broker accounting authority. Each leg is charged as an
   active verification, so total-request, active-verification, request-body,
   transport-delivered response-byte, cancellation, timeout, and wall-time
   limits apply at the transport boundary.
5. Only two complete, non-truncated, JSON-compatible responses reach the
   comparator. Rate-limited and server-error responses, malformed JSON, policy
   denials, transport failures, cancellation, and budget exhaustion produce an
   inconclusive or operational stop rather than a comparison. Redirect
   responses are not followed and automatic retries are not attempted.
6. A complete pair is reduced through Comparator V3. Raw response bodies and
   credential values remain transient; reports retain bounded, raw-value-free
   leg receipts, pseudonymous digests, resource usage, the versioned comparison
   envelope, and—when reached—the observation and exact review projection.
7. Observation ingestion atomically commits comparison evidence and its sole
   resource-scope relation, then applies deterministic API reasoning to the
   isolated comparison subject. A difference may produce only the canonical
   weak, supported boundary hypothesis and `AwaitHumanReview`. It never becomes
   a vulnerability verdict, a successful attack outcome, an Experience update,
   or an endpoint decision-loop transition.
8. Audit state is monotonic. A stop before both legs complete retains usage and
   any completed-leg receipt but emits no comparison. A cancellation or limit
   after comparison may retain that comparison; a stop after ingestion may also
   retain the committed observation and review. A later reasoning or projection
   error exposes the transport audit, comparison, and available commit receipt
   rather than implying rollback. These are in-process receipts, not crash
   durability acknowledgements.

## Consequences

- Venom gains one runtime-native differential slice without turning credentials
  into planner data or weakening the runner's one-case/one-subject rule.
- The host must explicitly authorize and label both contexts, assert that they
  represent the same logical resource, and provide non-secret opaque handles.
  Venom validates request shape but cannot attest those claims.
- A usable pair requires capacity for two total requests and two active
  verifications. Separate connection pools intentionally trade connection reuse
  for principal isolation while sharing one budget.
- The same runtime instance cannot subsequently run `analyze()` or another
  paired workflow. A host that needs both creates separate bounded runtimes.
- Existing transport-free ingestion remains available for hosts that collect
  responses elsewhere. This decision adds a narrower native collector; it does
  not replace the ingestion contract.
- Deterministic digests are pseudonymous and may be dictionary-tested. They are
  replay and audit metadata, not secret-protection tokens or attestations.

## Alternatives considered

- Model the pair as one planner-selected executor action: rejected because it
  would conflate host authorization with planner policy and violate comparison-
  subject isolation.
- Mark control passive and candidate active: rejected because both requests
  carry an authorization context and participate in one active comparison.
- Reuse one connection pool for both principals: rejected because cookies or
  other connection-bound server state could contaminate the candidate leg.
- Compare or reason over a single completed leg: rejected because a visibility
  boundary requires an atomic paired observation.
- Automatically follow redirects or retry failed legs: rejected because every
  additional request needs an explicit broker lease and can change the resource
  being compared.
