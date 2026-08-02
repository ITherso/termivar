# ADR 0010: Select payload strategies without moving payloads into planning

- Status: Accepted
- Date: 2026-08-02
- Extends: ADR 0004 and ADR 0009

## Context

The legacy adaptive payload transformers are disconnected from deterministic
reasoning and the utility planner. Passing raw payloads through planner plans,
decision commands, or audit receipts would couple policy to execution and risk
leaking sensitive material. Allowing an executor to choose an unrecorded
strategy would make replay and verification ambiguous.

Differential execution also has a transaction boundary. The current runner
commits one executor evidence batch at a time. A capability that performs a
large control/candidate batch can lose the earlier observations when a later
request fails before the executor returns.

## Decision

1. `AttackAction` may carry an optional, validated `PayloadStrategyRef`
   containing only a stable ID and positive revision.
2. The planner selects that opaque reference with the action and propagates it
   through `PlanStep`, `VerificationCase`, and `DecisionExecutionRequest`.
   Planning never imports payload bytes, transformers, HTTP, or a knowledge
   store.
3. An executor must explicitly report support for the exact selected strategy
   revision. A legacy executor fails before execution rather than silently
   ignoring strategy semantics.
4. `PayloadStrategy` is a pure synchronous contract. Given the same reference,
   role, seed, and limits it must derive the same artifact. Architecture checks
   prohibit clocks, randomness, runtime state, knowledge access, and transport
   dependencies in the contract module. Implementations outside that module
   remain trusted code and require repeat/concurrency conformance tests.
5. A conforming native strategy executor must derive one bounded artifact per
   execution turn. Passive collection uses a control role; explicit active
   verification uses a candidate role. This keeps request accounting and
   evidence commits aligned with the existing turn boundary.
6. Raw seeds and artifacts implement redacted debug output and are not
   serializable. Audit output contains only strategy provenance, role, byte
   length, and SHA-256 digest.
7. A native capability executor may dispatch an artifact only through the
   host-owned broker. Request-body length is charged atomically with the broker
   lease before the request reaches the network.
8. This change ships the contracts, propagation, and fail-closed support
   negotiation only. No standard profile registers a strategy-aware production
   executor yet; role mapping and single-artifact enforcement become executable
   guarantees when that first native capability is installed.

## Consequences

- The reasoning engine can select what is worth testing without becoming a
  payload generator or transport owner.
- Strategy revisions are replayable and an unsupported selection fails closed.
- The outstanding case pins its selected revision; reconfiguring the planner
  cannot change a later active, retry, completion, or review transition.
- Control evidence can remain committed and auditable if a later candidate
  request is denied, times out, or fails verification.
- The existing API visibility comparator remains the differential analysis
  primitive; this decision does not create a duplicate comparator or claim a
  vulnerability from a visibility difference.
- The legacy `DirectoryFuzzer` and adaptive transformers do not automatically
  become decision capabilities. Directory fuzzing is an explicit legacy CLI
  option while migration remains incomplete.
- Artifact digests are pseudonymous replay metadata, not secret-safe keyed
  commitments; small payload spaces remain dictionary-testable.

## Alternatives considered

- Put raw payloads in `AttackAction` or `DecisionLoopCommand`: rejected because
  it leaks execution details into policy, serialization, and audit surfaces.
- Let each executor choose an unversioned strategy: rejected because identical
  plans could produce different behavior without explanation.
- Add a new `Capability` orchestration layer: rejected because action IDs and
  executor routes already form the semantic capability boundary.
- Execute all differential variants in one executor call: deferred until a
  durable partial-evidence protocol exists; one artifact per turn preserves the
  current append-only evidence semantics.
