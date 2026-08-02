# Web execution internals

`StandardWebDiscoveryExecutorProfile` connects selected semantic web actions to the decision runner without weakening the HTTP evidence boundary. It is opt-in and requires an explicit `HttpEvidencePolicy` from the host.

```text
AttackPlan
    |
    v
DecisionLoopCommand
    |
    v
DecisionExecutorRegistry
    |
    +--> web.probe.laravel-routes ------> OPTIONS
    +--> web.probe.livewire-components -> GET
    +--> web.probe.sanctum-auth --------> HEAD
    +--> web.probe.http-basic-auth -----> HEAD
    +--> web.probe.http-bearer-auth ----> HEAD
    |
    v
HttpEvidenceExecutor
    |
    v
provenance-validated Evidence
```

## Safety boundary

The built-in profile is discovery-only. It does not submit credentials, inject payloads, follow redirects, mutate server state intentionally, or navigate outside the policy's authorized origins.

An action may carry a versioned `PayloadStrategyRef` for a future native
capability. The resolved executor must explicitly support that exact revision;
the runner rejects unsupported references before invoking it. Raw seed and
artifact types do not implement serialization and have redacted debug output,
so the framework does not copy their values into planner or audit records. A
custom executor remains responsible for never copying `as_bytes()` into
evidence or errors. A serializable receipt contains only role, length, digest,
and strategy provenance.

All five executors inherit the same host-owned controls:

- exact origin allowlist;
- total request and body-read timeout;
- maximum retained response size plus transport-delivered byte accounting;
- response-header allowlist;
- optional bounded text sampling;
- source reliability.

The Laravel route action currently observes the method boundary of the subject endpoint with `OPTIONS`; it is a safe seed for later route discovery, not a crawler. Livewire uses `GET` so an explicitly enabled bounded text sample can expose component markers. Authentication actions use credential-free `HEAD` and retain status plus allowed headers such as `WWW-Authenticate`.

## Registry installation

```rust
let policy = HttpEvidencePolicy::for_origin(target)?;
let profile = StandardWebDiscoveryExecutorProfile::new(policy)?;
let mut registry = DecisionExecutorRegistry::new();

profile.install(&mut registry)?;
let runner = DecisionRunnerAdapter::new(registry);
```

Installation clones and preflights the registry, then replaces it only after every executor and route succeeds. Both passive and active routes are installed. Reinstallation is idempotent.

A pre-existing executor with a standard identity is treated as a deliberate host override and is never replaced. A conflicting action route rejects the complete installation, preserving the original registry.

Hosts using the complete built-in stack can install reasoning, planning, execution, and verification through the transactional [standard web decision profile](web-decision.md).

## Evidence and verification

Each semantic executor has its own source component ID. The decision runner rejects a complete result batch unless every observation:

1. describes the verification case subject;
2. names the resolved semantic executor as its source component;
3. carries the case ID as its correlation ID.

The profile emits observations only. Classification, passive verification, active verification, outcomes, experience, and replanning remain owned by their existing layers.

The opt-in [standard web verification profile](web-verification.md) consumes these observations using action- and case-scoped rules. Keeping it separate ensures the executor never interprets its own response as success or failure.

## Intentionally unsupported actions

Nginx/Apache configuration analysis, PHP input discovery, and Laravel input analysis do not yet have built-in executors. Their planner identities remain stable, so hosts may register audited implementations without changing reasoning or planning policy.
