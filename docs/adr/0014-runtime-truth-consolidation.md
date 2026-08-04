# ADR 0014: Freeze runtime truth before capability expansion

- Status: Proposed
- Date: 2026-08-04
- Supersedes: ADR 0004, ADR 0006, ADR 0012, ADR 0013
- Scope: Repository governance and migration sequencing

## Context

`venom-scanner` contains three concurrent product states:

1. legacy CLI phase runner
2. deterministic decision runtime
3. platform/application shell features

This has created a recurring class of defects where scaffolds or partially wired
modules are perceived as active behavior. We already added a source reachability
gate, but the repo still needs an explicit sequencing rule before capability
growth resumes.

## Decision

The team will run all future feature work only after a **Runtime Truth Freeze**
milestone, which requires:

1. Public `venom scan` behavior remains the legacy ordered phase runner until a
   dedicated switch/command is introduced.
2. Decision runtime modules remain in-tree but are not promoted to default scan
   execution without a separate scan-path milestone.
3. Platform shell modules remain feature-scoped and non-default unless a release
   explicitly advertises them.
4. All dead/unexecuted runtime artifacts are classified into one of:
   `migrate`, `delete`, `move-to-legacy`, or `explicitly scaffolded`.
5. `cargo xtask architecture` with explicit allowlists is required before merge for
   every migration PR.

## Consequences

- Release notes can truthfully distinguish what is executable by default from what
  is scaffolding.
- PR review quality improves because source ownership and module graph health are
  explicit per subsystem.
- Contributors can start cleanup work in small, bounded epics without introducing
  new behavior regressions.
- Product-facing decisions stay on top of a stable reality map.

## Alternatives considered

- Continue shipping new capabilities under a “best effort” migration model.
  Rejected because it normalizes hidden dead code and weakens release trust.
- Move all in-tree scaffolds into one separate crate.
  Rejected for now; it requires broad refactors and risk while migration scope is still
  being established.
- Remove all feature-scoped shells immediately.
  Rejected because it would throw away potentially useful scaffolds without preserving
  migration context.

## Rollout

ADR 0014 applies to the Runtime Consolidation 5.4 milestone sequence:

- `docs/migrations/runtime-consolidation-5.4.md`
- `anomaly` cleanup PR
- `distributed` cleanup PR
- `lua` cleanup PR

