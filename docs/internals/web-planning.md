# Web planning internals

`StandardWebAttackProfile` maps supported web hypotheses to executor-routable actions. It is an opt-in planner profile: it ranks candidates and emits commands but never performs network I/O.

```text
HTTP Evidence
     |
     v
StandardWebReasoning
     |
     v
Weak / Strong Hypotheses
     |
     v
StandardWebAttackProfile
     |
     +--> requirements expression
     +--> posterior / strength threshold
     +--> gain, cost, risk, business value
     +--> dependency closure
     |
     v
AttackPlan ---> DecisionLoopCommand::ExecuteAction ---> registered executor
```

## Action catalog

The standard profile currently declares nine semantic actions.

| Hypothesis | Action | Required strength | Minimum posterior |
| --- | --- | --- | --- |
| nginx web server | configuration discovery | Any | 70% |
| Apache HTTP Server | configuration discovery | Any | 70% |
| PHP runtime | input discovery | Any | 70% |
| Laravel framework | route discovery | Strong | 80% |
| Laravel framework | input analysis | Strong | 80% |
| Livewire UI framework | component discovery | Any | 60% |
| Sanctum authentication | auth-boundary analysis | Any | 50% |
| HTTP Basic | auth-boundary analysis | Strong | 90% |
| HTTP Bearer | auth-boundary analysis | Strong | 90% |

Laravel input analysis depends on Laravel route discovery. The planner can rank input analysis first by utility, but its dependency closure always places route discovery earlier in the emitted plan.

The lower Sanctum threshold does not imply verification. The underlying cookie-based hypothesis remains weak, and the action carries higher operational risk so conservative planning contexts exclude it automatically.

## Executor boundary

Every `StandardWebActionKind` exposes a stable planner action ID and executor ID. A host must register a matching `DecisionActionExecutor` before handing the command to `DecisionRunnerAdapter`.

```rust
for kind in StandardWebActionKind::all() {
    println!("{} -> {}", kind.action_id(), kind.executor_id());
}
```

This profile does not silently map semantic actions to generic exploit plugins. Route discovery, component discovery, and authentication analysis remain isolated executor contracts that a host can implement with its own scope, rate, and authorization policy.

The opt-in [standard web discovery executor profile](web-execution.md) now supplies bounded built-in implementations for Laravel route boundaries, Livewire component discovery, and Sanctum/HTTP authentication boundaries. Configuration and input-analysis executors remain host-owned.

## Installation

Reasoning and planning are installed independently into the decision loop.

```rust
let knowledge = KnowledgeBase::new();
let mut decision_loop = DecisionLoop::new(config);

StandardWebReasoning::new()?
    .install(&knowledge, decision_loop.rules_mut())?;
StandardWebAttackProfile::new()?
    .install(decision_loop.planner_mut())?;
```

Both installations are idempotent and preflight identity conflicts against cloned registries before replacing planner state.

## Explainability and policy

Each selected `PlanStep` retains:

- the requirements expression trace;
- the hypothesis supplying confidence;
- gain, posterior, business value, cost, and risk;
- the calculated fixed-point utility;
- prerequisite action identities;
- the executor identity.

Rejected actions preserve an explicit reason such as unmet requirements, insufficient hypothesis strength, risk limit, dependency failure, budget exhaustion, or policy suppression.
