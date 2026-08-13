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
| [0014](0014-runtime-truth-consolidation.md) | Superseded by 0017 | Consolidate runtime truth into three named surfaces |
| [0015](0015-platform-shell-boundary.md) | Accepted | Classify the platform shell by execution reality |
| [0016](0016-bound-legacy-discovery-authority.md) | Accepted; phase 5–9 inventory superseded by 0018 | Bound legacy discovery behind a shared authority |
| [0017](0017-make-deterministic-scan-the-default.md) | Accepted | Make the deterministic runtime the canonical `scan` command |
| [0018](0018-bound-legacy-verification-authority.md) | Accepted | Bound legacy verification behind a separate active authority |

## Format

New records use the next four-digit number and contain: Status, Context, Decision, Consequences, and Alternatives considered. Accepted ADRs are immutable; supersede one with a new ADR instead of rewriting history.
