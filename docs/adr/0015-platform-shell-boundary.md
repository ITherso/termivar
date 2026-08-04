# ADR 0015: Platform shell boundary for non-scan modules

- Status: Proposed
- Date: 2026-08-04
- Supersedes: ADR 0014
- Scope: Repository migration sequencing and runtime truth

## Context

Milestone 5.4 completed the three in-tree dead-refactor cleanups
(`anomaly`, `distributed`, `lua`), but `venom-scanner` still contains a large set
of modules that are feature-scoped and not part of the default `venom scan`
execution path.

These modules are useful, but they are currently mixed with scanner/runtime
ownership in the same crate. This creates repeated risks:

- Users cannot quickly distinguish what is production scan behavior.
- Contributors cannot tell what is "kept" versus "intended" versus "obsolete."
- Feature-gated modules may be treated as active runtime behavior by mistake.

## Decision

Create an explicit **Platform Shell** boundary with three states:

1. **Keep**
   - Modules that are on the default scan path or directly required for default
     scan correctness.
2. **Migrate**
   - Feature-scoped modules not executed by `venom scan` but still valuable.
   - They remain in-tree as platform shell until explicitly moved into a
     dedicated integration milestone.
3. **Delete/Refactor**
   - Only for modules proven obsolete.

The following modules are explicitly in Platform Shell scope under this decision:

- `advanced_detection`, `compliance`, `monitoring`, `threat_intelligence`
- `plugins`, `plugin`, `persistence`, `reporting`, `realtime`
- `dashboard`, `post_exploitation`, `ml`, `distributed`, `lua_engine`

## Consequences

- Architecture truth source remains:
  - `cargo xtask architecture`
  - runtime migration docs (`docs/migrations/*.md`)
  - ADR chain.
- Product communication can now distinguish:
  - default legacy scan runtime,
  - in-tree decision/runtime branch,
  - platform shell.
- PR quality improves with explicit module decisions before implementation.

## Concrete 5.5 plan

1. Add a complete runtime inventory and keep/migrate/delete matrix in
   `docs/migrations/runtime-consolidation-5.5.md`.
2. Keep 5.5 strictly to docs/wiring/deprecation only:
   - no planner changes,
   - no feature additions,
   - no new scanning behavior.
3. Start the next capability milestone only when each platform module has either:
   - a dedicated ADR, or
   - a migration PR ticket with explicit target scope.
