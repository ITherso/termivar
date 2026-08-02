# Standard web decision runtime

`StandardWebDecisionRuntime` is the host-facing composition API for one authorized HTTP target. It owns the standard knowledge base, decision loop, executor registry, experience store, and session so a caller does not have to wire those components manually.

```text
authorized target + HTTP policy
              |
              v
 StandardWebDecisionRuntime
              |
              +--> bootstrap GET ---> immutable Evidence
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
| Total HTTP requests | 32 |
| Complete runtime wall time | 120 seconds |
| Buffered response bytes across the session | 2 MiB |
| Active verification requests | 4 |
| Attempts for one semantic action | 3 |
| Consecutive no-progress execution turns | 4 |

The HTTP policy remains authoritative for origins, timeout, body buffering, text sampling, captured headers, and evidence reliability. Redirects are not followed. The runtime performs one bootstrap `GET`, then only the discovery methods owned by installed semantic executors.

`planning_budget` is expressed in planner action-cost units; it is not a raw HTTP-request count. `max_action_cycles` remains the decision loop's passive-action guard. `RuntimeBudget` is the outer operational envelope and includes bootstrap, planned, adaptive, retry, and active-verification requests.

All runtime dimensions accept zero as a deliberate fail-closed value. A zero request, wall-time, response-byte, or same-action budget prevents bootstrap I/O. A zero active-verification budget still permits passive work but refuses the first active probe.

## Runtime safety envelope

The runtime checks limits in a stable order before every side effect: wall time, total requests, remaining response bytes, active verifications, then attempts for the semantic action. Request and action counters are reserved before any optional scheduler delay and executor work, so a delay cancellation, transport error, or timeout still consumes an attempt even when no socket request reaches the target.

The wall deadline starts at the beginning of `analyze()` and covers bootstrap, reasoning, scheduler delay, network I/O, verification, and state transitions. Awaited delays and requests are cancelled at the monotonic deadline. Synchronous reasoning cannot be interrupted mid-function, so the runtime checks the deadline again immediately after it returns.

`HttpEvidencePolicy::max_body_bytes` remains a per-response ceiling. `RuntimeBudget::max_response_bytes` is the session-wide total of response-body bytes buffered into evidence. Before each request, the runtime passes the remaining session allowance to the HTTP executor; the collector uses the smaller of that allowance and its per-response policy. Content-Length and wire overhead are not charged as body bytes.

No-progress accounting ignores raw evidence IDs, timing changes, retry case IDs, and experience inserts. A completed execution turn resets the counter only when it inserts or updates a hypothesis, escalates passive verification to an active probe, or reaches a conclusive Success/FalsePositive/ConfirmedNegative result. When the configured count is reached, the next command is not dispatched.

Expected exhaustion is an auditable result rather than an execution error. The report ends with `Halt { reason: RuntimeBudgetLimit }`, exposes the structured dimension through `limit_exceeded()`, and carries final counters through `usage()`. If a natural `Complete`, `AwaitHumanReview`, or policy `Halt` is reached on the same completed turn, that domain terminal takes precedence.

## Executable-plan boundary

The standard planner currently declares nine semantic actions while the built-in discovery profile implements five. The runtime compares planner executor identities with the installed registry before each planning cycle. Actions without an executor are supplied as host policy suppressions, remain visible as `PolicySuppressed` exclusions, and are never handed to the runner.

This prevents a discovered nginx, Apache, PHP, or Laravel input hypothesis from becoming an `UnknownExecutor` runtime failure. A future audited executor can remove its action from that suppression set simply by becoming part of the installed profile.

## Lifecycle and audit

A runtime instance is single-use. The started flag is retained even if a network or verification error occurs, because evidence may already have been committed under deterministic case identities. Create a new runtime for a new session.

`StandardWebDecisionRunReport` retains:

- the optional bootstrap evidence receipt (absent when a limit stops bootstrap);
- each reasoning/planning report;
- every executor evidence receipt and outcome report;
- the final `Complete`, `AwaitHumanReview`, or `Halt` command.
- final resource usage and an optional structured limit record.

The knowledge base, experience store, and replayable session remain inspectable after execution. A host can also consume the runtime with `into_experience()` and pass that store into a later builder through `experience_store()`.

## Turn commit semantics

Runtime request reservations are monotonic and are never rolled back. Executor evidence is provenance-validated as a complete batch and then committed atomically to the knowledge base. Verification, hypothesis transition, experience, and session transition happen after that evidence commit. If one of those later synchronous stages fails, the evidence remains append-only while the runtime returns an error and stays single-use. `StandardWebDecisionRuntimeError::committed_evidence()` exposes the failed turn's durable receipt, including response-telemetry validation failures, and the consuming getter transfers it without another evidence clone.

A successful outcome report exposes a runtime-only, lightweight before/after session transition summary alongside its verification, hypothesis write, and experience write. The summary is not a full session replay snapshot and is omitted from the report's existing serialized shape. Candidate experience and session state are assigned only after every fallible outcome step succeeds. This is an explicit error-atomic partial-turn boundary, not a rollback or crash-atomic transaction guarantee.

A budget stop is different: it occurs before the refused side effect and moves any outstanding decision session to `Halted { reason: RuntimeBudgetLimit }`. Evidence and outcome receipts from earlier completed turns remain available in the report.
