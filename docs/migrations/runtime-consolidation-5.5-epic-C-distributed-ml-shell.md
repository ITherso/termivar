# Runtime Consolidation 5.5 — Epic C: Distributed + ML Shell Handoff

Status: **ready**

Scope: `distributed`, `ml`

Owner: `team-platform-core`

Goal: convert distributed and ML scaffolding to explicit non-default shell status
while preserving source modules for later migration.

## 1) Current runtime facts (from 5.5 inventory)

| Module(s) | Default feature compiled | Reachable | Exported | Executed by `venom scan` | 5.5 class |
| --- | --- | --- | --- | --- | --- |
| `distributed.rs` | ❌ (feature) | ✅ | ✅ | ❌ | `platform-shell` |
| `ml.rs` | ❌ (feature) | ✅ | ✅ | ❌ | `platform-shell` |

Both modules are available in gated builds only and must not imply baseline scan
behavior.

## 2) Non-negotiable constraints

- No machine-learning model/behavior changes.
- No transport/runtime accounting behavior changes.
- No planner/policy logic changes.
- No CLI default path activation.

## 3) Required migration artifacts

1. Add explicit module note: non-default, platform-shell only.
2. Add API/developer documentation that names expected integration points and
   explicitly excludes these from default scan execution.
3. Add ticket for post-5.5 migration into dedicated architecture phase.

## 4) Exit criteria

- `docs/migrations/runtime-consolidation-5.5.md` updated with current Epic C status.
- `docs/adr/0015-platform-shell-boundary.md` remains consistent.
- CI gate still passes:
  - `cargo run --locked -p xtask -- architecture`
  - `cargo check -p venom-scanner --locked`

## 5) PR checklist

- [ ] docs-only changes.
- [ ] no new dependencies or behavior.
- [ ] boundary text updated in migration docs and ADR-linked references.
- [ ] ticket + owner in PR description.

