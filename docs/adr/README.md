# Architecture decision records

Architecture decision records (ADRs) preserve why a durable technical choice was made. They complement the current-state [architecture guide](../architecture.md), which describes what exists now.

## Index

| ADR | Status | Decision |
| --- | --- | --- |
| [0001](0001-use-workspace.md) | Accepted | Use a Cargo workspace with inward dependencies |
| [0002](0002-plugin-boundary.md) | Accepted | Keep plugins behind a source-level Rust trait boundary |
| [0003](0003-event-bus.md) | Accepted | Separate core event contracts from scanner event delivery |
| [0004](0004-reasoning-runtime-boundary.md) | Accepted | Keep deterministic reasoning inward of execution and runtime |
| [0005](0005-shared-predicate-vocabulary.md) | Accepted | Share predicate vocabulary through venom-core |

## Format

New records use the next four-digit number and contain: Status, Context, Decision, Consequences, and Alternatives considered. Accepted ADRs are immutable; supersede one with a new ADR instead of rewriting history.
