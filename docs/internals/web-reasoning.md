# Web reasoning internals

`StandardWebReasoning` is an opt-in bridge from immutable HTTP observations to Bayesian technology and authentication hypotheses. It performs no requests and never marks a claim confirmed or rejected.

```text
HttpEvidenceExecutor
        |
        v
typed Evidence -------> Standard web ontology
        |                         |
        v                         v
Expression trace -----> Bayesian policy likelihood
                                  |
                                  v
                    Weak / Strong Hypothesis
                                  |
                                  v
                         Planner / Verifier
```

## Standard ontology

The profile defines categories for technology, server software, programming languages, web frameworks, UI frameworks, and authentication mechanisms. Product concepts include nginx, Apache HTTP Server, PHP, Laravel, Livewire, Sanctum, HTTP Basic, and HTTP Bearer.

Relationships retain domain meaning. For example:

```text
laravel  --is_a----------> web-framework --is_a--> technology
laravel  --implemented_in-> php
livewire --depends_on----> laravel
sanctum  --depends_on----> laravel
```

Installation preflights ontology and rule identities on owned clones, then registers them idempotently. The default `DecisionLoop` remains empty so hosts explicitly choose the domain profile they trust.

## Fingerprint rules

Rules use ASCII case-insensitive substring matching for protocol and product tokens while preserving the exact contributing evidence IDs in their expression traces.

| Observation | Conclusion | Strength |
| --- | --- | --- |
| `Server` contains nginx or Apache | web-server hypothesis | Weak |
| `X-Powered-By` contains PHP | language=php | Weak |
| `X-Powered-By` names Laravel, or Laravel session plus XSRF cookies | framework=laravel | Strong |
| Bounded body sample contains a Livewire DOM marker | ui-framework=livewire | Weak |
| Laravel session plus XSRF cookies | authentication=sanctum | Weak |
| `WWW-Authenticate` advertises Basic or Bearer | authentication mechanism | Strong |

The Sanctum conclusion deliberately remains weak because the cookie pair is compatible with Sanctum but is not exclusive proof. An isolated XSRF cookie produces no Laravel or Sanctum claim.

## Bayesian behavior

Each rule declares a prior and deterministic `P(E|H)` / `P(E|not H)` policy likelihood. These fixed weights have not yet been calibrated against a labelled field corpus, so the posterior is a reproducible ranking signal rather than a measured real-world frequency. The fixed-point implementation produces the same result on every platform. A hypothesis records the contributing evidence and rationale, making every planner input explainable.

Only passive or active verifiers may move a hypothesis to `Confirmed` or `Rejected`. Re-running reasoning cannot reverse a verifier-owned state.

## Usage

```rust
let knowledge = KnowledgeBase::new();
let mut decision_loop = DecisionLoop::new(config);

StandardWebReasoning::new()?
    .install(&knowledge, decision_loop.rules_mut())?;
```

Evidence can then be inserted in atomic batches. The next decision-loop reasoning turn evaluates the standard rules before planning.

The resulting hypotheses can be connected to the opt-in [standard web attack profile](web-planning.md).
