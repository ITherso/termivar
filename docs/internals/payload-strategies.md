# Payload strategy boundary

Venom does not make the planner a payload generator. The planner selects a
semantic action and, when required, an exact strategy ID and revision. A native
capability executor is the only component that may resolve that reference and
derive one bounded artifact.

> Current maturity: this release ships the reference, derivation, propagation,
> and exact-support negotiation contracts, the first two native built-in
> strategies (`http.header.control-pair@1` and
> `api.authorization.context-pair@1`), the `standard_payload_strategies` registry
> builder, and a strategy-aware `HttpEvidenceExecutor` that resolves the bound
> reference, derives one control or candidate artifact per turn, and dispatches
> it through the host request broker. No standard profile enables a payload
> binding by default, so normal runtime execution dispatches no payload
> artifacts unless a host explicitly opts in with
> `HttpEvidenceExecutor::with_payload_binding`.

## Registered built-in strategies

### `http.header.control-pair@1`

The first native strategy derives a matched control/candidate pair for a single
benign request header (`accept` in this revision). The control leg is a
conventional, seed-independent baseline (`*/*`); the candidate leg is that
baseline plus one controlled, seed-derived variation (`*/*, <seed>`). Both legs
require a non-empty, header-safe seed and fail closed (`DerivationFailed`)
otherwise. The strategy emits only visible ASCII and spaces and never introduces
control characters, so a derived value is always a valid header value and cannot
perform header injection or request splitting at the derivation boundary. It is
deliberately the lowest-risk first strategy: it measures whether a target
responds differently to exactly one controlled header change, and derivation
remains a pure function of `(role, seed, limits)`.

### `api.authorization.context-pair@1`

The second native strategy varies only the authorization context of an otherwise
identical request (header `authorization`), so an executor can measure how the
same resource's visibility differs between an anonymous and an authorized
principal. The control leg derives an **empty** artifact, which instructs the
executor to omit the header entirely (the anonymous context). The candidate leg
derives the seed verbatim — the complete authorization header value the host
wants to test, for example `Bearer <token>`. Both legs require a non-empty,
header-safe seed and fail closed (`DerivationFailed`) otherwise, and the strategy
never introduces control characters, so a derived credential is always a valid
header value.

## Executor wiring

`HttpHeaderPayloadBinding` binds a registry, a strategy reference, a seed, byte
limits, and a target request header. `HttpEvidenceExecutor::with_payload_binding`
attaches one binding to the standard HTTP evidence executor. Once bound, the
executor:

1. advertises exact support for the bound reference through
   `supports_payload_strategy`, so the decision runner fails closed if a case
   selects an unsupported strategy;
2. on a selected turn, derives the stage-appropriate artifact (`Control` for a
   passive turn, `Candidate` for an active verification turn) from the registry;
3. applies the derived bytes as the bound header value through
   `HttpProbe::with_header`, which re-runs forbidden-header and value validation
   (an empty artifact omits the header, representing an anonymous context);
4. dispatches the request through the host-owned request broker, so every
   strategy-materialized request is charged like any other.

Actions that do not select the bound reference are dispatched unchanged, so one
executor can serve both plain discovery and strategy-driven differential turns.
A host opts in explicitly; no standard profile installs a binding by default.

Inside the bounded standard runtime, `StandardWebDecisionRuntimeBuilder::with_payload_binding`
attaches a binding to the runtime's `http.evidence` executor, which shares the
runtime's metered request broker. Every artifact that binding derives and
dispatches is therefore charged through the runtime's request accounting exactly
like any other request, satisfying the transport requirement above.

```text
Evidence -> Hypothesis -> AttackAction
                            |
                            v
                 PayloadStrategyRef (ID + revision)
                            |
                            v
                  DecisionExecutionRequest
                            |
                            v
                 Native capability executor
                            |
                    PayloadStrategy
                            |
              one Control or Candidate artifact
                            |
                            v
              host-owned accounting broker
```

## Contract

`PayloadStrategy::derive_one` is deliberately synchronous and pure. The same
strategy reference, role, seed, and limits must yield the same bytes and digest.
The contract module cannot import clocks, randomness, knowledge state, runtime
state, or transport clients; `cargo xtask architecture` enforces this boundary.
Implementations may live in capability modules, so determinism is also a
trusted implementation invariant. Every native implementation must add and
pass repeat/concurrency conformance tests before registration in a standard
profile.

A conforming native executor must produce one artifact per turn:

- passive evidence collection requests a `Control` artifact;
- explicit active verification requests a `Candidate` artifact.

`HttpEvidenceExecutor` is the first such executor (see below).
This aligns differential work with the existing evidence transaction boundary.
A committed control observation stays auditable if the candidate is later
blocked by policy, exceeds a budget, times out, or fails verification.

## Limits and redaction

The default seed and output ceiling is 4 KiB and the compiled hard ceiling is
64 KiB. A zero limit is valid and fails closed. Strategy output is validated a
second time by `PayloadStrategyRegistry`.

`PayloadSeed` and `PayloadArtifact` are intentionally not serializable. Their
debug representations show only `<redacted>`, byte length, and digest. Use
`PayloadArtifact::receipt()` for audit output; it contains:

- strategy ID and revision;
- control/candidate role;
- byte length;
- SHA-256 digest.

It never contains the raw seed or derived bytes.

The digest provides replay provenance, not confidentiality. Small or
predictable payloads can be recovered with a dictionary attack against an
unkeyed SHA-256 value. Treat receipts as pseudonymous security telemetry and do
not publish them when the underlying payload space is sensitive.

## Transport requirement

Resolving a strategy does not authorize network I/O. A native executor must use
the host-owned request broker. The broker atomically charges request count,
buffered request-body bytes, active verification, and transport-delivered
response-body bytes while bounding the retained prefix.
Opaque streaming bodies whose length cannot be charged are rejected before
dispatch.

Plugin execution and the ordered legacy runner do not accept planner-selected
payload-strategy actions. Their separate bounded authorities therefore cannot be
used to bypass this artifact boundary.

## Encoding and normalization primitives

`payload_strategies::encoding` contains only neutral byte encodings: ASCII URL
percent encoding and lowercase hexadecimal encoding. The old WAF detector and
attack-shaped evasion dispatcher (comment injection, parameter pollution, HTTP
splitting, case/whitespace mutation, and double encoding) were removed.

`PayloadEncoding` is selected explicitly by a host. `encode_into_artifact`
routes its output through `PayloadArtifact`, so encoded bytes inherit the same
per-turn byte bound and raw-value redaction as any other artifact. No encoding
helper is registered as a runtime strategy or allowed to issue a request.

## Differential analysis

Payload derivation and response comparison are separate responsibilities. JSON
visibility differences use `ApiVisibilityComparator` and its versioned profiled
envelope. An empty path summary is not treated as equivalence: status-only or
structural differences can be classified as
`DifferenceWithoutPathSummary`. Visibility differences remain review signals,
not automatic vulnerability verdicts.
