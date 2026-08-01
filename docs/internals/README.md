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

Plugin host ----> PluginRegistry ----> Plugin::execute

DecisionLoop ---> DecisionRunnerAdapter ---> DecisionActionExecutor
                         |
                         v
                   KnowledgeBase

HTTP target ---> HttpEvidenceExecutor ---> typed Evidence
                                            |
                                            v
                              StandardWebReasoning ---> Hypotheses
                                                           |
                                                           v
                                             StandardWebAttackProfile
                                                           |
                                                           v
                                                   AttackPlan

Task producer --> TaskQueue --> WorkerPool --> WorkerNode
```

- [Scheduler](scheduler.md): queue, worker scoring, assignment, retry, and heartbeat boundaries.
- [Event bus](event-bus.md): synchronous publication, subscriptions, history, and correlation.
- [Runner](runner.md): ordered phase execution, timeouts, cancellation, and partial results.
- [Decision runner](decision-runner.md): command execution, executor routing, evidence provenance, and verifier handoff.
- [HTTP evidence executor](http-evidence.md): scope policy, bounded collection, typed observations, and rate-limit normalization.
- [Web reasoning](web-reasoning.md): standard ontology, explainable fingerprint rules, and Bayesian weak/strong hypotheses.
- [Web planning](web-planning.md): hypothesis-gated actions, utility ranking, policy exclusions, and executor contracts.
- [Plugin registry](plugin-registry.md): validation, compatibility, lookup, execution, and accounting.

Cross-boundary changes should start in [Architecture Decisions](../adr/README.md). Public contract changes must also follow the [Plugin API policy](../plugin-api-policy.md).
