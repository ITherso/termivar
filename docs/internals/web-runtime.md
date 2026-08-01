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
| Consecutive failures before suppression | 10 |

The HTTP policy remains authoritative for origins, timeout, body buffering, text sampling, captured headers, and evidence reliability. Redirects are not followed. The runtime performs one bootstrap `GET`, then only the discovery methods owned by installed semantic executors.

`planning_budget` is expressed in planner action-cost units; it is not a raw HTTP-request count. `max_action_cycles` bounds passive actions. Active verification remains bounded independently by the decision and adaptation limits.

## Executable-plan boundary

The standard planner currently declares nine semantic actions while the built-in discovery profile implements five. The runtime compares planner executor identities with the installed registry before each planning cycle. Actions without an executor are supplied as host policy suppressions, remain visible as `PolicySuppressed` exclusions, and are never handed to the runner.

This prevents a discovered nginx, Apache, PHP, or Laravel input hypothesis from becoming an `UnknownExecutor` runtime failure. A future audited executor can remove its action from that suppression set simply by becoming part of the installed profile.

## Lifecycle and audit

A runtime instance is single-use. The started flag is retained even if a network or verification error occurs, because evidence may already have been committed under deterministic case identities. Create a new runtime for a new session.

`StandardWebDecisionRunReport` retains:

- the bootstrap evidence receipt;
- each reasoning/planning report;
- every executor evidence receipt and outcome report;
- the final `Complete`, `AwaitHumanReview`, or `Halt` command.

The knowledge base, experience store, and replayable session remain inspectable after execution. A host can also consume the runtime with `into_experience()` and pass that store into a later builder through `experience_store()`.
