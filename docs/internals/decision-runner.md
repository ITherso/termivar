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

`DecisionEvidenceReceipt` retains the exact evidence emitted by that execution in addition to the write results and verification snapshots. Its `write_set()` iterator pairs each observation with its input-order `KnowledgeWrite`, making the atomic commit set explicit. This matters for active verification, where passive and active requests intentionally reuse one case correlation ID: resource accounting reads the exact batch rather than double-counting the cumulative subject snapshot.

The host may attach `DecisionExecutionLimits` to reduce executor resource use. Unrestricted requests preserve the existing serialized request shape. The runner exposes execution/commit and decision resumption as separate internal stages so a runtime can account for a committed receipt before verification or experience transition begins.

Verifier rules may additionally opt into an action identity and current-case evidence correlation. This is required when a long-lived subject snapshot can contain responses from multiple semantic actions or retries; unrelated and historical observations remain visible to the knowledge base but cannot win that scoped verification rule.

## Legacy plugin bridge

`PluginDecisionExecutor` adapts the Preview `PluginRegistry` contract to native evidence. A host-owned `PluginInputProvider` maps a decision request to the legacy `target` and `payload` strings; the adapter does not assume an action ID is a payload. Successful `ScanFinding` values become correlated `plugin.finding` evidence. Plugin failures remain executor failures and do not enter the knowledge base.

The bridge is a migration boundary. New reasoning-aware extensions should implement `DecisionActionExecutor` directly so they can emit typed evidence without the lossy `ScanFinding` conversion.

## Failure semantics

- A stale command/session mismatch is rejected before executor work.
- Executor and provenance failures leave knowledge unchanged.
- Evidence identity conflicts reject the complete batch.
- Once valid observations are committed, they remain immutable even if later verification or adaptive evaluation fails; observations are facts about execution, not a transaction over decision policy. `DecisionRunnerError::committed_evidence()` exposes that durable receipt, and `into_committed_evidence()` transfers it without cloning.
- A successful `DecisionOutcomeReport` is the outcome phase's completion receipt. Its verification, hypothesis write, experience write, and runtime-only `DecisionSessionTransition` describe the state changes applied after evidence storage. The lightweight transition summary is intentionally omitted from the report's existing serialized shape; a future persisted audit format will be explicit and versioned.
- The outcome phase uses candidate experience and session state. On a normal returned error, hypothesis, experience, and session changes are not committed. This is error-atomic, not a claim of crash-atomic persistence.
- Planning also prepares every session mutation on a candidate clone. A planner or case-construction error therefore leaves the replayable session unchanged, including the action-cycle-limit path. Before the swap, the loop validates the subject/ontology revisions and holds the knowledge read lock through the short session commit. Concurrent knowledge writes therefore produce `StalePlanningSnapshot` instead of scheduling an action from stale hypotheses. Successful `DecisionPlanningReport` values expose the before/after `DecisionSessionTransition` without changing their existing serialized shape.
- Rule application intentionally precedes utility planning. If it inserts or updates hypotheses and a later planning step fails, those in-memory knowledge writes remain committed. `DecisionLoopError::committed_reasoning()` returns a `DecisionReasoningCommitReceipt` containing the exact application/write statuses and the subject/ontology revisions of the attempted planner snapshot. Rule evaluations remain pre-commit candidates; consumers should query current knowledge when verifier-owned terminal-state preservation matters. `DecisionRunnerError` forwards the same receipt; absence means that failed planning did not change reasoning state.
- Terminal commands perform no executor work and are returned to the host unchanged.
