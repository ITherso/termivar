# Decision runner internals

`DecisionLoop` is deterministic policy; `DecisionRunnerAdapter` is the side-effect boundary that executes its commands. Keeping those responsibilities separate makes the same evidence and session state replay to the same decision without requiring a network or plugin runtime in reasoning tests.

## Command flow

```text
DecisionLoopCommand
        |
        v
DecisionRunnerAdapter -----> DecisionExecutorRegistry
        |                              |
        |                              v
        |                    DecisionActionExecutor
        |                              |
        |                              v
        |                         Vec<Evidence>
        |                              |
        +---- validate provenance <----+
        |
        v
KnowledgeBase::insert_evidence_batch
        |
        v
PassiveVerifier / ActiveVerifier
        |
        v
DecisionOutcomeReport
```

The adapter accepts only commands emitted by the decision loop. It never selects an attack, changes utility, evaluates a rule, or invents a retry.

## Executor resolution

Planner commands may name an executor directly. Adaptive actions and active probes carry only an action ID, so the registry resolves a stage-specific route. Separate passive and active routes let verification use a stricter probe without coupling planner policy to a concrete plugin.

Duplicate executor IDs and ambiguous action routes are rejected. Missing routes fail before delay or executor work begins.

## Evidence boundary

An executor returns native `Evidence`, not findings or decisions. Before any write, every item must satisfy three provenance invariants:

1. the evidence subject equals the verification case subject;
2. the source component equals the resolved executor ID;
3. the source correlation ID equals the verification case ID.

`KnowledgeBase::insert_evidence_batch` preflights identities under one write lock. A conflict rejects the whole batch, while exact repeats remain idempotent. Active execution captures a subject snapshot immediately before the probe and another after the batch commit.

Verifier rules may additionally opt into an action identity and current-case evidence correlation. This is required when a long-lived subject snapshot can contain responses from multiple semantic actions or retries; unrelated and historical observations remain visible to the knowledge base but cannot win that scoped verification rule.

## Legacy plugin bridge

`PluginDecisionExecutor` adapts the Preview `PluginRegistry` contract to native evidence. A host-owned `PluginInputProvider` maps a decision request to the legacy `target` and `payload` strings; the adapter does not assume an action ID is a payload. Successful `ScanFinding` values become correlated `plugin.finding` evidence. Plugin failures remain executor failures and do not enter the knowledge base.

The bridge is a migration boundary. New reasoning-aware extensions should implement `DecisionActionExecutor` directly so they can emit typed evidence without the lossy `ScanFinding` conversion.

## Failure semantics

- A stale command/session mismatch is rejected before executor work.
- Executor and provenance failures leave knowledge unchanged.
- Evidence identity conflicts reject the complete batch.
- Once valid observations are committed, they remain immutable even if later verification or adaptive evaluation fails; observations are facts about execution, not a transaction over decision policy.
- Terminal commands perform no executor work and are returned to the host unchanged.
