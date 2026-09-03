# Web verification internals

`StandardWebVerificationProfile` maps evidence from the built-in semantic web executors to deterministic outcomes. It installs ten passive and ten active rules into `VerificationPipeline`.

The verifier consumes discovery capability identities from the transport-neutral
`web_actions` catalog. It does not import `web_execution`, an HTTP client, or a
runner, and the profile remains available when `termivar-scanner` is built without
the `scanning` feature.

```text
semantic HTTP evidence
          |
          v
 action scope == VerificationCase.action_id
          |
          v
 source correlation == VerificationCase.id
          |
          v
 passive / active expression
          |
          v
 Success | Blocked | Unknown | NeedsReview
```

## Outcome policy

| Action | Evidence from the current case | Outcome |
| --- | --- | --- |
| Laravel route boundary | `Allow` exists | `NeedsReview` |
| PHP input discovery | bounded HTML sample contains a named HTML-namespace form control | `Success` |
| Livewire component discovery | bounded body sample contains `wire:id=` or `wire:snapshot=` | `Success` |
| Sanctum-compatible cookie boundary | both `laravel_session` and `XSRF-TOKEN` cookie names | `Success` |
| HTTP Basic auth boundary | `WWW-Authenticate` contains `Basic` | `Success` |
| HTTP Bearer auth boundary | `WWW-Authenticate` contains `Bearer` | `Success` |
| Any built-in discovery action | status is `401`, `403`, or `429` without a higher-priority semantic signal | `Blocked` |

An explicit authentication challenge outranks the generic `401` blocked rule. This records the advertised authentication mechanism instead of treating its expected challenge as a failed probe.

The Laravel `Allow` signal is deliberately non-conclusive. It proves that the endpoint advertised a method boundary, not that Laravel produced it. Missing markers produce the canonical evidence-free `Unknown`; absence alone never becomes `FalsePositive`.

Outcome status and hypothesis transition are separate contracts. PHP input
discovery and Sanctum-compatible cookie observation are `KnowledgeOnly`. A named
form control or a current-case Laravel session/XSRF cookie pair yields
action-level `Success` and completes its discovery objective, while the
motivating PHP or Sanctum hypothesis remains `Supported`. The cookie pair is
compatible with Sanctum SPA authentication but also follows an ordinary Laravel
session/CSRF cookie-name convention, so it is not proof that Sanctum is installed
or active. Directly coupled actions retain the default `Motivation` target, so
their transition-authorized Success can confirm the selected hypothesis.

## Isolation

Every standard rule is restricted in two dimensions:

1. its action scope must equal `VerificationCase.action_id`;
2. raw evidence must carry `VerificationCase.id` as its source correlation ID.

The first boundary prevents a Basic rule from confirming a Bearer case. The second prevents a historical `403`, marker, or challenge from being combined with a new execution. Case-correlated rules are rejected during construction unless their complete expression uses the raw evidence layer only.

Action matching is retained in every `VerificationRuleEvaluation`, so an audit trail distinguishes “condition did not match” from “condition matched evidence but belonged to another action.”

## Active freshness

Active verification keeps the existing monotonic snapshot rule. A matching expression is eligible only when it cites at least one evidence ID absent from the passive baseline. Reusing a stale marker with the same case correlation therefore remains `Unknown`; a fresh active observation can produce a terminal result, which becomes hypothesis-conclusive only when the case authorizes a transition.

## Commit concurrency

Each `VerificationReport` carries a runtime-only commit token for the subject
and ontology revisions it evaluated. `VerificationReport::apply` compares that
token under the knowledge-base write lock before changing hypothesis state. If
new rule-visible knowledge arrived in between, the transition fails stale
instead of confirming or rejecting a newer evaluation. Replaying the same
terminal state is idempotent; attempting to reverse `Confirmed` and `Rejected`
is an explicit conflict rather than last-writer-wins.

The lower-level `apply_outcome` compatibility function has neither a snapshot
token nor the case-level transition policy. It is restricted to callers that
have already established transition authorization and cannot detect intervening
recalibration; production decision turns apply the complete report.

## Installation

```rust
let mut decision_loop = DecisionLoop::new(config);

StandardWebVerificationProfile::new()?
    .install(decision_loop.verification_mut())?;
```

Installation preflights a cloned pipeline and replaces the original only after every rule succeeds. Reinstallation is idempotent, while a reused rule ID with different semantics rejects the complete update.
