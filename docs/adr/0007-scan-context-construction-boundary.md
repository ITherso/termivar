# ADR 0007: Make ScanContext constructor-owned and non-exhaustive

- Status: Accepted
- Date: 2026-08-02

## Context

The tagged `v0.9.0-alpha` scanner contract exposed every `ScanContext` field,
so downstream crates could construct it with a struct literal. Adding the
evidence-driven knowledge base then required every such literal to initialize a
new runtime-owned field. The scanner context will continue to acquire runtime
state as reasoning, cancellation, budgets, and observability evolve.

Extensions need to borrow scan state, but they should not define how the
runtime assembles or replaces that state.

## Decision

`ScanContext` is non-exhaustive and is created through `new`, `with_timeout`,
`with_cancellation`, or `with_event_bus`. Extensions may use documented public
handles and methods, but they must not depend on struct literals or update
syntax.

The context owns its `KnowledgeBase`. The field is private and exposed as a
shared borrow through `knowledge()`. No setter or mutable reference is exposed:
the knowledge base already provides synchronized write operations through a
shared reference, and replacing the base would split one scan's evidence
identity.

This construction change is an intentional Scanner Preview incompatibility
with `v0.9.0-alpha`; it is not presented as a patch-compatible fix. It must ship
on a new pre-1.0 minor line with an upgrade note. A blocking
`venom-scanner` compatibility baseline will be added only after that Preview
release exists, using the annotated tag's immutable peeled commit.

## Consequences

- Future context fields can be added without changing downstream initializers.
- Phases and plugins share one runtime-owned knowledge identity across context
  clones.
- Consumers tracking `main` must replace direct `context.knowledge` access with
  `context.knowledge()`.
- Consumers migrating from `v0.9.0-alpha` must replace struct literals with a
  named constructor.
- `#[non_exhaustive]` protects future field additions, but it does not make
  removal, privatization, or type changes of existing public fields
  source-compatible.
- The stable SDK release blocker remains open until a post-transition scanner
  baseline and compatibility window exist.

## Alternatives considered

- Preserve public struct literals: rejected because every runtime-state field
  would remain a downstream source break.
- Make every existing field private immediately: deferred because that would
  expand the current Preview migration without an accessor design for each
  field.
- Introduce a second context type: rejected because it would duplicate shared
  state and force adapters throughout the runner and phase contracts.
