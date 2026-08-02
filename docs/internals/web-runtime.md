# Standard web decision runtime

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

let mut runtime = StandardWebDecisionRuntime::builder(target)
    .http_policy(policy)
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
| Buffered response bytes across the session | 2 MiB |
| Active verification requests | 4 |
| Attempts for one semantic action | 3 |
| Consecutive no-progress execution turns | 4 |

The HTTP policy remains authoritative for origins, timeout, body buffering, text sampling, captured headers, and evidence reliability. Redirects are not followed. The runtime performs one bootstrap `GET`, then only the discovery methods owned by installed semantic executors.

`planning_budget` is expressed in planner action-cost units; it is not a raw HTTP-request count. `max_action_cycles` remains the decision loop's passive-action guard. `RuntimeBudget` is the outer operational envelope and includes bootstrap, planned, adaptive, retry, and active-verification requests.

All runtime dimensions accept zero as a deliberate fail-closed value. A zero request, wall-time, response-byte, or same-action budget prevents bootstrap I/O. A zero active-verification budget still permits passive work but refuses the first active probe.

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

### Authorized paired-visibility ingress

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

## Runtime safety envelope

The runtime checks limits in a stable order before execution: wall time; advisory broker preflight for total requests, remaining response bytes, and active verifications; then attempts for the semantic action. Only the semantic attempt is reserved before an optional scheduler delay. A delay cancellation therefore consumes an action attempt but not a request. The shared host-owned request broker repeats the resource checks atomically and records the request immediately before `reqwest::Client::execute`, so a transport error or timeout after dispatch remains charged.

The wall deadline starts at the beginning of `analyze()` and covers bootstrap, reasoning, scheduler delay, network I/O, verification, and state transitions. Awaited delays and requests are cancelled at the monotonic deadline. Synchronous reasoning cannot be interrupted mid-function, so the runtime checks the deadline again immediately after it returns.

`HttpEvidencePolicy::max_body_bytes` remains a per-response ceiling. `RuntimeBudget::max_response_bytes` is the session-wide total of response-body bytes retained by broker leases. Every retained chunk is charged before it is exposed to the executor. Bytes remain charged when a later chunk fails, the request times out, or the outer wall deadline cancels collection; accounting is no longer inferred from successful evidence. The collector uses the smallest of the remaining session allowance, its per-execution allowance, and its per-response policy. Content-Length, discarded bytes beyond those bounds, and wire overhead are not charged as retained body bytes.

All built-in HTTP executors installed by `StandardWebDecisionRuntime` share one broker, one redirect-disabled and implicit-retry-disabled client, and one accounting authority. Bootstrap, planned, adaptive, retry, and active-verification dispatches therefore compete for the same atomic envelope. Redirect responses consume the request that produced them but are not followed. Semantic retries re-enter the broker and acquire a fresh lease. Low-level callers that construct and run an arbitrary `DecisionActionExecutor` outside this standard runtime remain responsible for their own transport policy and accounting.

No-progress accounting ignores raw evidence IDs, timing changes, retry case IDs, and experience inserts. A completed execution turn resets the counter only when it inserts or updates a hypothesis, escalates passive verification to an active probe, or reaches a conclusive Success/FalsePositive/ConfirmedNegative result. When the configured count is reached, the next command is not dispatched.

Expected exhaustion is an auditable result rather than an execution error. The report ends with `Halt { reason: RuntimeBudgetLimit }`, exposes the structured dimension through `limit_exceeded()`, and carries final broker counters through `usage()`. If the broker refuses a later dispatch inside an already-started executor, `execution_failure()` also preserves the exact request, executor, stage, origin, limits, and structured runtime limit. If a natural `Complete`, `AwaitHumanReview`, or policy `Halt` is reached on the same completed turn, that domain terminal takes precedence.

## Executable-plan boundary

The standard planner currently declares nine semantic actions while the built-in discovery profile implements five. The runtime compares planner executor identities with the installed registry before each planning cycle. Actions without an executor are supplied as host policy suppressions, remain visible as `PolicySuppressed` exclusions, and are never handed to the runner.

This prevents a discovered nginx, Apache, PHP, or Laravel input hypothesis from becoming an `UnknownExecutor` runtime failure. A future audited executor can remove its action from that suppression set simply by becoming part of the installed profile.

## Lifecycle and audit

A runtime instance is single-use. The started flag is retained even if a network or verification error occurs, because evidence may already have been committed under deterministic case identities. Create a new runtime for a new session.

When an executor reports a failure before evidence commit, `StandardWebDecisionRuntimeError::execution_failure()` forwards the runner's typed receipt. Built-in HTTP failures are classified from error variants rather than diagnostic text: unsupported subjects are not applicable, authorization/scope refusals are policy blocks, request and timeout failures are transport failures, and internal construction/model failures remain executor failures. Transport dispatch and retained-byte accounting remain monotonic, but provider or policy failures before dispatch consume only the semantic attempt. None of these operational classifications creates a synthetic verifier outcome or changes Experience suppression state.

`StandardWebDecisionRunReport` retains:

- the optional bootstrap evidence receipt (absent when a limit stops bootstrap);
- each reasoning/planning report;
- every executor evidence receipt and outcome report;
- the final `Complete`, `AwaitHumanReview`, or `Halt` command;
- final resource usage and an optional structured limit record;
- an optional execution-failure receipt when the broker refused an in-executor dispatch.

The knowledge base, experience store, and replayable session remain inspectable after execution. A host can also consume the runtime with `into_experience()` and pass that store into a later builder through `experience_store()`.

## Turn commit semantics

Runtime request dispatches and retained response bytes are monotonic and are never rolled back. Executor evidence is provenance-validated as a complete batch and then committed atomically to the knowledge base. Verification, hypothesis transition, experience, and session transition happen after that evidence commit. If one of those later synchronous stages fails, the evidence remains append-only while the runtime returns an error and stays single-use. `StandardWebDecisionRuntimeError::committed_evidence()` exposes the failed turn's durable receipt, including response-telemetry validation failures, and the consuming getter transfers it without another evidence clone.

A successful outcome report exposes a runtime-only, lightweight before/after session transition summary alongside its verification, hypothesis write, and experience write. The summary is not a full session replay snapshot and is omitted from the report's existing serialized shape. Candidate experience and session state are assigned only after every fallible outcome step succeeds. This is an explicit error-atomic partial-turn boundary, not a rollback or crash-atomic transaction guarantee.

Planning turns use the same candidate-session rule. Planner validation and case construction must finish before the runtime advances or halts the real session, and a final read-locked revision check rejects a plan made stale by concurrent knowledge writes. A successful planning report exposes its runtime-only before/after transition. Reasoning still commits before planning. When those rule writes changed knowledge and planning then fails, `StandardWebDecisionRuntimeError::committed_reasoning()` exposes the exact application/write statuses plus the subject/ontology revisions of the planner snapshot; the session remains unchanged. This is an explicit post-commit receipt, not rollback of immutable reasoning history or a durability claim.

The hypothesis transition uses the `VerificationReport` revision token. A
concurrent evidence, hypothesis, or ontology write makes the report stale and
aborts the candidate experience/session commit. Same-terminal replay remains
idempotent, while opposite terminal transitions fail explicitly.

A budget stop is different: it occurs before the refused transport dispatch and moves any outstanding decision session to `Halted { reason: RuntimeBudgetLimit }`. A dispatch or partial body already charged before a later failure remains visible in `usage()`. Evidence and outcome receipts from earlier completed turns remain available in the report, while an in-executor broker refusal has its own failure receipt.
