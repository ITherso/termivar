# Standard web decision runtime

## Optional OpenAPI document replay

When both the non-default `openapi-review` feature and explicit runtime option
are present, the parent web assessment installs
`web.review.openapi.document-replay@1` as one native action. It owns no nested
runtime or client: selection, the anonymous bodyless GET candidate, exact
replay, evidence, and projection reuse the parent exact-origin authority,
redirect-disabled broker, budget, cancellation, completeness lifecycle, and
final report. At most one document is selected; the complete action costs two
requests and one logical active verification. A semantic replay mismatch or any
unsupported, malformed, incomplete, truncated, redirected, or over-limit
response produces no item.

`StandardWebDecisionRuntime` is the host-facing composition API for one authorized HTTP target. It owns the standard knowledge base, decision loop, executor registry, experience store, and session so a caller does not have to wire those components manually.

```text
authorized target + HTTP policy
              |
              v
 StandardWebDecisionRuntime
              |
              +--> RequestBroker ---> bootstrap GET ---> immutable Evidence
              |                           |
              |                           v
              +--------------------> reasoning + planning
                                          |
                                          v
                                executable action only
                                          |
                                          v
                              evidence + verification
                                          |
                                          v
                                  terminal command
```

## Build and run

```rust
let policy = HttpEvidencePolicy::for_origin(target.clone())?
    .with_body_capture(HttpBodyCapture::TextSample { max_chars: 8_192 })?;
let cancellation = tokio_util::sync::CancellationToken::new();

let mut runtime = StandardWebDecisionRuntime::builder(target)
    .http_policy(policy)
    .cancellation_token(cancellation.clone())
    .enable_api_reasoning()
    .business_value(80)
    .planning_budget(100)
    .risk_limit(40)
    .max_action_cycles(8)
    .max_total_requests(32)
    .max_wall_time(std::time::Duration::from_secs(120))
    .max_response_bytes(2 * 1024 * 1024)
    .build()?;

let report = runtime.analyze().await?;
```

The host may retain the token clone and cancel it for a user stop, scope
change, incident response, or shutdown. Host cancellation is reported as
`Halt { reason: CancelledByHost }`; it is distinct from the complete-runtime
wall deadline and from an individual request timeout.

The runnable [`decision_scan`](https://github.com/ITherso/venom/blob/main/examples/decision_scan.rs) example accepts an explicitly supplied target URL and prints the selected actions, verified outcomes, terminal command, and learned experience count.

## Defaults and policy ownership

Without overrides, the builder creates a policy restricted to the target's exact origin and uses these deterministic decision defaults:

| Setting | Default |
| --- | ---: |
| Business value | 80% |
| Planner action-cost budget | 100 |
| Maximum action risk | 40% |
| Passive action cycles | 8 |
| Suppression-eligible verified negatives | 10 |
| Passive API response/surface reasoning | Disabled |
| Total HTTP requests | 32 |
| Complete runtime wall time | 120 seconds |
| Transport-delivered response-body bytes across the session | 2 MiB |
| Buffered request-body bytes across the session | 256 KiB |
| Active verification requests | 4 |
| Attempts for one semantic action | 3 |
| Consecutive no-progress execution turns | 4 |

The HTTP policy remains authoritative for origins, timeout, body buffering, text sampling, captured headers, and evidence reliability. Redirects are not followed. The runtime performs one bootstrap `GET`, then only the discovery methods owned by installed semantic executors.

`planning_budget` is expressed in planner action-cost units; it is not a raw HTTP-request count. `max_action_cycles` remains the decision loop's passive-action guard. `RuntimeBudget` is the outer operational envelope and includes bootstrap, planned, adaptive, retry, and active-verification requests.

All runtime dimensions accept zero as a deliberate fail-closed value. A zero request, wall-time, response-byte, or same-action budget prevents bootstrap I/O. A zero request-body budget permits bodyless discovery but refuses the first non-empty body before dispatch. A zero active-verification budget still permits passive work but refuses the first active probe.

## Optional API response and surface reasoning

`enable_api_reasoning()` installs `StandardApiReasoning` into the runtime's
existing rule engine. It is disabled by default, and
`api_reasoning_installation()` returns the installation receipt only when the
builder enabled it.

The option evaluates normalized evidence already emitted by the HTTP executor.
Generic JSON produces only a JSON response-format hypothesis. An exact GraphQL
response media type produces a strong GraphQL surface hypothesis, while a
normalized `graphql` path segment remains weak. Enabling it creates no request,
executor, payload, active verification, or planner action, so the runtime's
configured limits and request reservations remain unchanged. The additional
deterministic rule evaluation still runs under the same wall-time deadline.

### Authorized paired-visibility workflows

#### Transport-free ingestion

The runtime can also own the storage, reasoning, and review side of an
authorized paired-visibility workflow. The host still pairs the two contexts
and creates a typed `ApiVisibilityObservation`; the runtime never accepts raw
response bodies, credentials, headers, URLs, or principal names through this
boundary.

```rust
let receipt = runtime.ingest_api_visibility(observation, &resource)?;
let query = ApiVisibilityReviewQuery::new(32)?;
let page = runtime.api_visibility_reviews(&resource, &query)?;
```

Both methods require `.enable_api_reasoning()`. A disabled runtime returns
`RuntimeApiVisibilityError::ApiReasoningDisabled` before writing anything.
Successful ingestion preserves the observation's isolated comparison subject
and its evidence-backed resource relation; it never rewrites comparison
evidence onto the runtime endpoint subject.

Ingress is neutral to HTTP request accounting, the decision session,
experience, planning, and executor selection. It may be performed before or
after `analyze()` and does not make the paired hypothesis eligible for the
endpoint planner. Exact replay remains idempotent. If reasoning fails after
the observation commits, `RuntimeApiVisibilityError::committed_observation()`
exposes the commit receipt rather than implying rollback. Producer
authentication, authorization of both compared contexts, same-resource
pairing, and persistence remain host responsibilities.

#### Native authorization-context pair

`run_api_visibility_pair` is the first runtime-native collection path for this
model. It is an explicit host call, not a planner-selected capability. The host
provides two context-bound `GET` probes for the exact runtime target, identifies
their shared logical resource, and declares which bounded credential or
supporting anti-CSRF header names belong to the authorization context. The
request constructor rejects a method, URL, non-context header, or primary
credential equivalence before I/O. Credentials require HTTPS except on an exact
loopback fixture target.

```rust
let report = runtime.run_api_visibility_pair(request).await?;

match report.disposition() {
    ApiVisibilityDifferentialDisposition::AwaitHumanReview => {
        // Present the weak, evidence-backed boundary to an authorized reviewer.
    }
    ApiVisibilityDifferentialDisposition::NoDifferenceObserved
    | ApiVisibilityDifferentialDisposition::UnresolvedDifference
    | ApiVisibilityDifferentialDisposition::Inconclusive
    | ApiVisibilityDifferentialDisposition::CancelledByHost
    | ApiVisibilityDifferentialDisposition::RuntimeBudgetLimit => {}
    _ => {}
}
```

Control and candidate use separate connection pools so connection-bound state
cannot cross principal contexts. They still share the runtime's HTTP policy and
host-owned accounting authority. Both dispatches are `Active`, require separate
total-request and active-verification leases, and charge request bodies and all
transport-delivered response chunks at the broker boundary. Redirect following
and implicit retries remain disabled.

Only two complete, non-truncated JSON-compatible responses continue to
Comparator V3. The runtime then creates the isolated comparison observation,
atomically commits its evidence and resource relation, applies standard API
reasoning, and reads the exact committed review. A difference can produce only
a weak, supported boundary hypothesis with `AwaitHumanReview`; it never becomes
a vulnerability verdict, endpoint decision-loop command, planner success, or
Experience update.

The operation is single-use. Once its pre-I/O configuration and target checks
pass, the same runtime cannot later run `analyze()` or another pair. Incomplete
legs produce no comparison, but their charged usage and any completed-leg
receipt remain in `ApiVisibilityDifferentialAudit`. Its `transport()` audit
also preserves every acquired control/candidate dispatch and typed terminal
outcome, including a partially received timeout or cancelled in-flight leg. A late cancellation or
limit may retain a completed V3 comparison and, if ingestion already happened,
the observation and review. Post-commit errors expose the same audit plus the
available comparison and commit receipt; they do not imply rollback or disk
durability. See [ADR 0013](../adr/0013-runtime-owned-api-visibility-pairs.md).

The opt-in origin assessment composes this workflow for the exact root only.
`WebAssessmentRootAuthorizationContext` consumes one bounded complete
`Authorization` value, builds a distinct Standard child with the assessment's
existing `SharedWebRuntimeAuthority`, and runs the anonymous/authorized pair
after root work but before discovery admission. It does not mint another broker
or budget. A canonical `AwaitHumanReview` result is projected as one atomic
comparison evidence reference; the assessment does not invent separate
control/candidate evidence records. Equivalence emits no item. Incomplete
collection, cancellation, or limit exhaustion halts later discovery and keeps
the assessment incomplete. The capability has no verifier transition and can
never produce `Confirmed`.

#### Resource authorization differential

The non-default `authorization-review` feature composes one policy-selected
resource comparison as the native action
`web.review.authorization.resource-differential` inside the existing
`WebAssessmentRuntime`. It does not invoke `run_api_visibility_pair`, create a
second Standard runtime, or finalize a detached report. The feature-enabled
builder accepts one validated `security.authorization-review-policy/v1` value
and one move-only primary/peer principal pair; the CLI supplies those values
only after profile, policy-file, transport, source-conflict, and report-output
preflight.

The action dispatches primary candidate, peer candidate, primary replay, and
peer replay against the same exact resource. All four bodyless `GET` legs use
the parent redirect-disabled request broker, exact-origin authority,
`RuntimeBudget`, response accounting, cancellation, and deadline, while the
broker isolates principal connection state. The only principal-varying header
is `Authorization`; there is no cookie, request body, arbitrary header, method
change, identifier mutation, or implicit retry. The child is capped at one
resource, four requests, and one logical active verification: the passive
stage collects both candidate views, then the active decision phase charges
its sole logical active-verification lease when the primary replay begins. The
peer replay is passive-accounted within that same phase, through the same
registered action and executor.

Complete JSON responses are reduced immediately through the shared API
comparison foundation. A positive item requires independent primary and peer
stability and both cross-principal rounds to match across `Status`, `Fields`,
and value-sensitive `Resources`. The committed observer/ledger truth and all
request/accounting receipts must reconcile before the common projection can
emit one `authorization.resource-cross-principal-equivalence@1` item. Its
maximum is `NeedsReview` / `KnowledgeOnly`. Redirect, defense or rate-limit
interference, unsupported media, malformed or truncated JSON, cancellation,
budget exhaustion, or any missing lifecycle entry fails closed and cannot
produce a completed item set.

The resulting redaction-safe audit is part of the same composed assessment
report. It exposes typed outcome and bounded accounting only—not credentials or
credential digests/sources, raw URLs or query values, the clear resource
handle, JSON Pointer text, scalar values, bodies, or raw errors. The existing
two-leg exact-root authorization-context compatibility workflow remains
unchanged and cannot be enabled in the same V1 run.

## Runtime safety envelope

The runtime checks limits in a stable order before execution: wall time; advisory broker preflight for total requests, remaining response bytes, and active verifications; then attempts for the semantic action. Only the semantic attempt is reserved before an optional scheduler delay. A delay cancellation therefore consumes an action attempt but not a request. The shared host-owned request broker repeats the resource checks atomically, charges the exact buffered request-body length, and records the request immediately before `reqwest::Client::execute`, so a transport error or timeout after dispatch remains charged. An opaque request body whose length cannot be measured is rejected before dispatch.

The wall deadline starts at the beginning of `analyze()` and covers bootstrap, reasoning, scheduler delay, network I/O, verification, and state transitions. Awaited delays and requests are cancelled at the monotonic deadline. Synchronous reasoning cannot be interrupted mid-function, so the runtime checks the deadline again immediately after it returns.

Host cancellation is checked before bootstrap, at deterministic planning
boundaries, and while bootstrap or action execution is awaited. The runtime
uses a deliberately biased wait order: a ready execution result wins first so
a just-produced commit receipt is not discarded; an explicit host cancellation
wins over a simultaneously ready wall deadline because it is the more specific
stop reason. Cancellation after evidence commit but before verification keeps
that receipt in `unverified_evidence()` and does not synthesize an outcome.

`RuntimeBudget::max_request_body_bytes` is the session-wide total of buffered request bodies accepted by broker leases. The charge and request reservation happen under the same accounting lock before network dispatch, so concurrent capability executors cannot oversubscribe the allowance. Headers, URLs, and wire framing are excluded.

`HttpEvidencePolicy::max_body_bytes` remains a per-response retention ceiling. `RuntimeBudget::max_response_bytes` is the session-wide threshold for response-body bytes delivered to broker collection. Metered collectors share one response-read gate and recheck the remaining allowance before every read. Every complete received chunk is charged before its bounded prefix is exposed to the executor. The one serialized chunk that reveals a crossing can make usage exceed the threshold; retention stays capped, no collector starts another body read, and the same turn terminates with a typed `ResponseBytes` limit. Evidence already committed by that turn remains in bootstrap or `unverified_evidence`, before verification or Experience updates. Bytes also remain charged when a later read fails, times out, or is cancelled. Content-Length, headers, framing, and unread bytes after collection stops are excluded.

All built-in HTTP executors installed by `StandardWebDecisionRuntime` share one broker, one redirect-disabled and implicit-retry-disabled client, and one accounting authority. Bootstrap, planned, adaptive, retry, and active-verification dispatches therefore compete for the same atomic envelope. Redirect responses consume the request that produced them but are not followed. Semantic retries re-enter the broker and acquire a fresh lease. Low-level callers that construct and run an arbitrary `DecisionActionExecutor` outside this standard runtime remain responsible for their own transport policy and accounting.

No-progress accounting ignores raw evidence IDs, timing changes, retry case IDs, and experience inserts. A completed execution turn resets the counter only when it inserts or updates a hypothesis, escalates passive verification to an active probe, or reaches a terminal Success/FalsePositive/ConfirmedNegative result. A knowledge-only Success therefore still records objective progress even though it transitions no hypothesis. When the configured count is reached, the next command is not dispatched.

Expected exhaustion is an auditable result rather than an execution error. The report ends with `Halt { reason: RuntimeBudgetLimit }`, exposes the structured dimension through `limit_exceeded()`, and carries final broker counters through `usage()`. If the broker refuses a later dispatch inside an already-started executor, `execution_failure()` also preserves the exact request, executor, stage, origin, limits, and structured runtime limit. If a natural `Complete`, `AwaitHumanReview`, or policy `Halt` is reached on the same completed turn, that domain terminal takes precedence.

Both successful reports and post-start failure receipts expose
`transport()`. This bounded, raw-target-free audit orders broker leases by
dispatch sequence and distinguishes completion, transport failure,
per-request timeout, response-budget reach, and caller cancellation. A denied
lease is absent because it opened no dispatch; earlier receipts remain present
when a later request, accounting check, verification, or state transition
fails. The hard retention ceiling is explicit through
`omitted_receipt_count()` rather than silently presenting a partial audit as
complete.

## Executable-plan boundary

The standard planner currently declares nine semantic actions while the built-in discovery profile implements eight. The runtime compares planner executor identities with the installed registry before each planning cycle. Actions without an executor are supplied as host policy suppressions, remain visible as `PolicySuppressed` exclusions, and are never handed to the runner.

This prevents a discovered Laravel input hypothesis from becoming an `UnknownExecutor` runtime failure. A future audited executor can remove its action from that suppression set simply by becoming part of the installed profile.

## Lifecycle and audit

A runtime instance is single-use. The started flag is retained even if a network or verification error occurs, because evidence may already have been committed under deterministic case identities. Create a new runtime for a new session.

When an executor reports a failure before evidence commit, `StandardWebDecisionRuntimeError::execution_failure()` forwards the runner's typed receipt. Built-in HTTP failures are classified from error variants rather than diagnostic text: unsupported subjects are not applicable, authorization/scope refusals and unmetered request bodies are policy blocks, an expired host request/body deadline is a request timeout, other network failures are transport failures, and internal construction/model failures remain executor failures. Transport dispatch, request-body accounting, and received-byte accounting remain monotonic, but provider or policy failures before dispatch consume only the semantic attempt. None of these operational classifications creates a synthetic verifier outcome or changes Experience suppression state.

After `analyze()` marks the runtime started, unexpected failures are wrapped in
`RunFailed`. `failure_receipt()` exposes the committed bootstrap receipt,
completed planning/outcome turns, and the latest monotonic usage snapshot from
before the failing boundary. The nested source remains typed, so
`execution_failure()`, `committed_evidence()`, and `committed_reasoning()` keep
forwarding the current boundary's receipt. This envelope is process-local; it
does not claim disk durability or crash recovery.

`StandardWebDecisionRunReport` retains:

- the optional bootstrap evidence receipt (absent when a limit stops bootstrap);
- each reasoning/planning report;
- every executor evidence receipt and outcome report;
- evidence committed immediately before cancellation, exposed separately as
  `unverified_evidence()` because no verifier outcome exists;
- the final `Complete`, `AwaitHumanReview`, or `Halt` command;
- final resource usage and an optional structured limit record;
- bounded, ordered per-dispatch transport receipts and an explicit omitted count;
- an optional execution-failure receipt when the broker refused an in-executor dispatch.

The knowledge base, experience store, and replayable session remain inspectable after execution. A host can also consume the runtime with `into_experience()` and pass that store into a later builder through `experience_store()`.

## Turn commit semantics

Runtime request dispatches, request-body bytes, and transport-delivered response bytes are monotonic and are never rolled back. Executor evidence is provenance-validated as a complete batch and then committed atomically to the knowledge base. Verification, hypothesis transition, experience, and session transition happen after that evidence commit. If one of those later synchronous stages fails, the evidence remains append-only while the runtime returns an error and stays single-use. `StandardWebDecisionRuntimeError::committed_evidence()` exposes the failed turn's committed in-process receipt, including response-telemetry validation failures, and the consuming getter transfers it without another evidence clone.

A successful outcome report exposes a runtime-only, lightweight before/after session transition summary alongside its verification, hypothesis write, and experience write. The summary is not a full session replay snapshot and is omitted from the report's existing serialized shape. Candidate experience and session state are assigned only after every fallible outcome step succeeds. This is an explicit error-atomic partial-turn boundary, not a rollback or crash-atomic transaction guarantee.

Planning turns use the same candidate-session rule. Planner validation and case construction must finish before the runtime advances or halts the real session, and a final read-locked revision check rejects a plan made stale by concurrent knowledge writes. A successful planning report exposes its runtime-only before/after transition. Reasoning still commits before planning. When those rule writes changed knowledge and planning then fails, `StandardWebDecisionRuntimeError::committed_reasoning()` exposes the exact application/write statuses plus the subject/ontology revisions of the planner snapshot; the session remains unchanged. This is an explicit post-commit receipt, not rollback of immutable reasoning history or a durability claim.

The hypothesis transition uses the `VerificationReport` revision token. A
concurrent evidence, hypothesis, or ontology write makes the report stale and
aborts the candidate experience/session commit. Same-terminal replay remains
idempotent, while opposite terminal transitions fail explicitly.

A budget stop is different: it occurs before the refused transport dispatch and moves any outstanding decision session to `Halted { reason: RuntimeBudgetLimit }`. A dispatch or partial body already charged before a later failure remains visible in `usage()`. Evidence and outcome receipts from earlier completed turns remain available in the report, while an in-executor broker refusal has its own failure receipt.
