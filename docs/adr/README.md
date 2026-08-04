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
| [0006](0006-api-visibility-ingestion.md) | Accepted | Keep API visibility ingestion outside the decision runner |
| [0007](0007-scan-context-construction-boundary.md) | Accepted | Make ScanContext constructor-owned and non-exhaustive |
| [0008](0008-version-api-comparison-projections.md) | Accepted | Version API comparison projections outside the core wire contract |
| [0009](0009-host-owned-transport-accounting.md) | Superseded by 0012 | Make the standard runtime own transport accounting |
| [0010](0010-planner-selected-payload-strategies.md) | Accepted | Select payload strategies without moving payloads into planning |
| [0011](0011-version-api-explanation-semantics.md) | Accepted | Version API explanation semantics |
| [0012](0012-account-delivered-transport-bytes.md) | Accepted | Account delivered transport bytes at the broker boundary |
| [0013](0013-runtime-owned-api-visibility-pairs.md) | Accepted | Run authorized API visibility pairs as a runtime-owned workflow |
| [0014](0014-runtime-truth-consolidation.md) | Accepted | Freeze runtime truth before capability expansion |
| [0015](0015-platform-shell-boundary.md) | Proposed | Separate platform-shell modules from scan and decision runtime paths |

## Format

New records use the next four-digit number and contain: Status, Context, Decision, Consequences, and Alternatives considered. Accepted ADRs are immutable; supersede one with a new ADR instead of rewriting history.
