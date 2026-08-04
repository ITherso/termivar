# Runtime Consolidation 5.5 — Epic D: Plugin + Lua Shell Handoff

Status: **ready**

Scope: `plugin`, `plugins/*`, `lua_engine`

Owner: `team-plugins`

Goal: keep plugin execution surfaces clear as platform shell until dedicated runtime
integration milestone.

## 1) Current runtime facts (from 5.5 inventory)

| Module(s) | Default feature compiled | Reachable | Exported | Executed by `venom scan` | 5.5 class |
| --- | --- | --- | --- | --- | --- |
| `plugin.rs` | ❌ (feature) | ✅ | ✅ | ❌ | `platform-shell` |
| `plugins/*` | ❌ (feature) | ✅ | ✅ | ❌ | `platform-shell` |
| `lua_engine.rs` | ❌ (feature) | ✅ | ✅ | ❌ | `platform-shell` |

`lua_engine` is the active Lua runtime path after the 5.4 cleanup; legacy split
or refactor alternatives are not active in scan.

## 2) Non-negotiable constraints

- No scanner feature activation.
- No plugin API or runtime contract change.
- No planner/rule/plausibility behavior change.
- No behavior path changes in default CLI.

## 3) Required migration artifacts

1. Add boundary note: plugin and Lua modules are not used in default legacy scan path.
2. Add migration/deprecation note at module root where users may assume active use.
3. Reference migration ticket and keep `5.5` ownership map updated.

## 4) Exit criteria

- Migration note and map updates merged in docs.
- ADR 0015 boundary remains accurate.
- Architecture gate remains green:
  - `cargo run --locked -p xtask -- architecture`
  - `cargo check -p venom-scanner --locked`

## 5) PR checklist

- [ ] docs-only scope.
- [ ] no code change in scanning/decision runtime behavior.
- [ ] clear "not in scan default path" statement.
- [ ] ticket + owner in PR description.

