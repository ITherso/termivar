# Standard web decision profile

`StandardWebDecisionProfile` is the one-shot host boundary for Venom's deterministic web decision stack. It composes the standard reasoning, planning, discovery execution, and verification profiles without merging their responsibilities.

```text
immutable HTTP evidence
          |
          v
 StandardWebReasoning -----> hypotheses
                                  |
                                  v
 StandardWebAttackProfile ---> AttackPlan
                                  |
                                  v
 StandardWebDiscoveryExecutorProfile
                                  |
                                  v
 StandardWebVerificationProfile ---> Outcome
```

The profile is opt-in. Construction requires a host-owned `HttpEvidencePolicy`, so network scope, timeouts, response limits, allowed headers, and text sampling remain explicit policy decisions.

## Installation

```rust
let profile = StandardWebDecisionProfile::new(
    HttpEvidencePolicy::for_origin(target)?,
)?;

let report = profile.install(
    &knowledge,
    &mut decision_loop,
    &mut executors,
)?;
```

The returned `StandardWebDecisionInstallReport` keeps the write report for each layer separate. Hosts can audit ontology concepts and axioms, inference rules, planner actions, executors, routes, and verifier rules without depending on hidden aggregate counts.

Reinstallation is idempotent. Existing definitions with identical semantics produce zero writes. A reused identity with different semantics is a conflict.

## Commit boundary

Installation uses a prepare-then-commit sequence:

1. clone the decision loop and executor registry;
2. preflight planner actions, verifier rules, executors, and routes on those clones;
3. preflight reasoning rules on a cloned rule engine;
4. clone, validate, and replace the ontology while holding one knowledge-base write lock;
5. replace the prepared decision loop and executor registry with infallible assignments.

If any preflight fails, the caller's decision loop, registry, and ontology remain unchanged. Ontology concepts and axioms are also installed as one batch, so a late axiom conflict cannot leave earlier concepts committed.

This is a setup transaction, not a runtime transaction. It does not roll back evidence or outcomes created after a decision session starts.

## Layer boundaries

- reasoning observes stored evidence and emits hypotheses; it performs no I/O;
- planning ranks eligible actions; it does not execute them;
- execution collects bounded observations; it never classifies its own result;
- verification evaluates case-correlated evidence and emits an outcome;
- the host retains authorization, policy, persistence, and session lifecycle ownership.

The individual profiles remain public for specialized hosts. Use the composite profile when the standard stack should be installed as one reviewed unit; use the individual profiles when a host deliberately replaces a layer.
