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
     |
     +--> optional versioned strategy reference (never raw payload bytes)
```

## Action catalog

The standard profile currently declares nine semantic actions.
Their stable identities live in the transport-neutral `web_actions` catalog;
planning assigns utility while execution separately binds supported identities
to concrete probes.

| Hypothesis | Action | Required strength | Minimum posterior | Verification target |
| --- | --- | --- | --- | --- |
| nginx web server | configuration discovery | Any | 70% | Motivation |
| Apache HTTP Server | configuration discovery | Any | 70% | Motivation |
| PHP runtime | input discovery | Any | 70% | KnowledgeOnly |
| Laravel framework | route discovery | Strong | 80% | Motivation |
| Laravel framework | input analysis | Strong | 80% | Motivation |
| Livewire UI framework | component discovery | Any | 60% | Motivation |
| Sanctum authentication | auth-boundary analysis | Any | 50% | Motivation |
| HTTP Basic | auth-boundary analysis | Strong | 90% | Motivation |
| HTTP Bearer | auth-boundary analysis | Strong | 90% | Motivation |

Laravel input analysis depends on Laravel route discovery. The planner can rank input analysis first by utility, but its dependency closure always places route discovery earlier in the emitted plan.

The lower Sanctum threshold does not imply verification. The underlying cookie-based hypothesis remains weak, and the action carries higher operational risk so conservative planning contexts exclude it automatically.

PHP input discovery is deliberately `KnowledgeOnly`. The PHP hypothesis still
motivates and supplies confidence for the action, but finding a named HTML form
control proves only that the discovery objective succeeded; it does not prove
that PHP produced the control and therefore cannot confirm or reject PHP.

## Executor boundary

Every `StandardWebActionKind` exposes a stable planner action ID and executor ID. A host must register a matching `DecisionActionExecutor` before handing the command to `DecisionRunnerAdapter`.

```rust
for kind in StandardWebActionKind::all() {
    println!("{} -> {}", kind.action_id(), kind.executor_id());
}
```

This profile does not silently map semantic actions to generic exploit plugins. Route discovery, component discovery, and authentication analysis remain isolated executor contracts that a host can implement with its own scope, rate, and authorization policy.

The opt-in [standard web discovery executor profile](web-execution.md) supplies bounded built-in implementations for eight actions, including nginx/Apache configuration discovery, PHP input discovery, Laravel route boundaries, Livewire component discovery, and Sanctum/HTTP authentication boundaries. Laravel input analysis remains host-owned.

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
- the separately resolved verification target (`Motivation`, `Distinct`, or
  `KnowledgeOnly`) in the in-process plan; the existing serialized plan shape
  intentionally omits this additive field for wire compatibility;
- gain, posterior, business value, cost, and risk;
- the calculated fixed-point utility;
- prerequisite action identities;
- the executor identity;
- the optional exact payload strategy ID and revision selected with the action.

The planner treats the strategy reference as declarative action identity. It
does not resolve a transformer, derive bytes, read runtime state, or know HTTP.
Changing only the strategy revision changes action semantics and therefore
conflicts with an existing registration under the same action ID.

Rejected actions preserve an explicit reason such as unmet requirements, insufficient hypothesis strength, risk limit, dependency failure, budget exhaustion, or policy suppression.
