# Internals

These notes explain the implementation boundaries that contributors most often need before changing execution code. They describe the current alpha behavior, including limitations; they are not promises of a stable internal API.

## Map

```text
ScannerSdk
    |
    v
ScanRunner -----> EventBus
    |
    v
ScanPhase

Plugin host ----> host-created request ----> PluginRegistry
                                               |
                                               v
                                  invocation PluginContext ----> Plugin::execute
                                      |                           |
                                      v                           v
                               bounded broker             evidence recorder

DecisionLoop ---> DecisionRunnerAdapter ---> DecisionActionExecutor
                         |
                         v
                   KnowledgeBase

HTTP target ---> StandardWebDecisionRuntime
                         |
                         v
                HttpEvidenceExecutor ---> typed Evidence
                                            |
                                            v
                              StandardWebDecisionProfile
                                            |
                                            v
                              StandardWebReasoning ---> Hypotheses
                                                           |
                                                           v
                                             StandardWebAttackProfile
                                                           |
                                                           v
                                                   AttackPlan
                                                           |
                                                           v
                                    StandardWebDiscoveryExecutorProfile
                                                           |
                                                           v
                                           HttpEvidenceExecutor
                                                           |
                                                           v
                                       StandardWebVerificationProfile
                                                           |
                                                           v
                                                        Outcome

Authorized JSON pair --> ApiVisibilityComparator --> comparison observation
                                                        |
                                                        v
                                              KnowledgeBase + relation
                                                        |
                                                        v
                                             StandardApiReasoning
                                                        |
                                                        v
                                           resource review projection

Explicit host --> TaskQueue <--> WorkerPool --> WorkerNode
      |              |
      |              `--> CompletionReceipt --> ResultAggregator
      `--> LuaScriptRegistry --> fresh bounded Lua VM

Bounded manifest bytes --> venom-exploit validation --> sealed metadata catalog
                                                        (no execution runtime)
```

- [Scheduler](scheduler.md): explicit-time revisioned queue/worker assignment,
  logical ownership, retry/recovery, and bounded result-retention boundaries.
- [Lua execution](../lua.md): approved-root source snapshots, private VM host
  API, cooperative budgets/cancellation, and receipt/provenance limits.
- [Event bus](event-bus.md): synchronous publication, subscriptions, history, and correlation.
- [Runner](runner.md): ordered phase execution, timeouts, cancellation, and partial results.
- [Decision runner](decision-runner.md): command execution, executor routing, evidence provenance, and verifier handoff.
- [Declarative policy wire contracts](declarative-policy-wire.md): fail-closed semantic fields, compatibility guards, and host loader limits.
- [HTTP evidence executor](http-evidence.md): scope policy, bounded collection, typed observations, and rate-limit normalization.
- [Scanner conformance corpus](scanner-conformance-corpus.md): strict repository-only sanitized request/response cases, deterministic validation, and the boundary between contract checks and empirical accuracy.
- [API predicate vocabulary](api-predicates.md): canonical and normalized HTTP/API predicates plus atomic evidence/resource-scope observation bundles.
- [API visibility evidence](api-evidence.md): bounded JSON comparison, broker-backed authorization-context pairs, atomic ingestion receipts, and resource-scoped review projections.
- [Authorization differential review foundation](authorization-differential-review.md): strict primary-only policy, move-only principal roles, four raw-value-free JSON views, replay stability, and transport-free outcome classification.
- [API reasoning](api-reasoning.md): deterministic JSON/GraphQL fingerprinting, capped API evidence contributions, and review-only visibility-boundary hypotheses.
- [GraphQL surface review](graphql-review.md): explicit anonymous opt-in, deterministic one-endpoint selection, bounded three-request introspection/replay, and informational claim authority.
- [Standard web decision profile](web-decision.md): one-shot composition, installation transaction, and layer boundaries.
- [Standard web decision runtime](web-runtime.md): target builder, bootstrap evidence, executable-plan filtering, resource budgets, and complete session driving.
- [Web reasoning](web-reasoning.md): standard ontology, explainable fingerprint rules, and Bayesian weak/strong hypotheses.
- [Web planning](web-planning.md): hypothesis-gated actions, utility ranking, policy exclusions, and executor contracts.
- [Payload strategies](payload-strategies.md): planner-selected revisions, deterministic derivation contract, redaction, and transport requirements.
- [Normalization-resilience review](normalization-resilience.md): explicit opt-in, candidate-specific defense eligibility, typed depth-one HTML transforms, replay, and conservative claim authority.
- [Web execution](web-execution.md): semantic executor installation, discovery-only HTTP methods, and scope controls.
- [Web verification](web-verification.md): action/case isolation, passive/active rules, and conservative outcomes.
- [Plugin registry](plugin-registry.md): host-owned scope, request/evidence budgets, redaction, validation, execution, and accounting.
- [Semantic producer contract](semantic-producer-contract.md): production evidence vocabulary compatibility for semantic entity extraction and explicit deferred gaps.
- [ADR 0024](../adr/0024-separate-exploit-manifest-catalog.md): separate
  bounded exploit metadata/catalog contracts from the quarantined historical
  scanner scaffold and from future execution authority.

Cross-boundary changes should start in [Architecture Decisions](../adr/README.md). Public contract changes must also follow the [Plugin API policy](../plugin-api-policy.md).
