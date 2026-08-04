# Runtime Consolidation 5.4 — Controlled Migration Sequence (No New Features)

This milestone keeps the focus strictly on repository truth, wiring, and migration
operations. We do **not** add scanner capabilities, planning behavior, semantic
expansion, payload strategy changes, or runtime behavior in this milestone.

Scope for 5.4:

- `venom-scanner` source topology cleanup by subsystem
- Explicit migration decision for each quarantined branch
- One active PR per subsystem:
  - `anomaly`
  - `distributed`
  - `lua`
- Maintain the architecture gate in `cargo xtask architecture` as the enforcement
  point for source reachability debt.

## 1) Migration policy (hard constraints)

1. Keep current `venom scan` legacy path stable while it is the only scan
   command used by users.
2. Keep decision/runtime modules available, but do not activate them from the CLI
   until a dedicated "runtime switch" milestone.
3. Do not land unreferenced refactor code without explicit intent and an
   ADR/PR plan.
4. No behavior changes in this milestone.
5. Quarantined files must be either:
   - removed,
   - intentionally moved behind an explicit migration namespace,
   - or made compile-reachable with clear ADR alignment.

## 2) Subsystem split strategy

### Epic A — `anomaly`

Current state:

- `src/anomaly.rs` is linked and exported.
- `src/anomaly/*.rs` submodules are unreferenced dead files.

Decision options (choose exactly one before implementation PR):

1. **Migrate** all orphan anomaly modules into a coherent `anomaly/` module graph and
   wire `src/anomaly.rs` to it.
2. **Delete** orphan modules if they are obsolete.
3. **Move** them to a dedicated migration namespace (e.g., `legacy/anomaly/`)
   with a deprecation note in code comments.

Constraint:
- This epic must finish `allowlist` alignment (for this file group) before any
  other subsystem PR is merged.

### Epic B — `distributed`

Current state:

- `src/distributed.rs` is linked (only feature-gated by `features = ["distributed"]`).
- `src/distributed/*.rs` worker/queue/scheduler modules are unreferenced dead files.

Decision options:

1. **Keep as façade**: retain `src/distributed.rs` and move internals to a clearly
   named scaffold path with no runtime implication.
2. **Migrate** module graph now: wire submodules, update `lib.rs`, add
   regression tests, keep API compatible.
3. **Remove** feature and scaffold if distribution is out-of-scope for this cycle.

### Epic C — `lua`

Current state:

- `src/lua_engine.rs` is linked and exported.
- `src/lua/*.rs` modules are unreferenced dead files with partially duplicated intent
  versus `lua_engine.rs`.

Decision options:

1. **Consolidate**: convert `src/lua_engine.rs` to a compatibility shim over
   `src/lua/` and remove duplicated legacy implementation.
2. **Keep shim**: keep both only as explicit long-term migration surface with clear
   deprecation notes, no behavior changes.
3. **Split**: move/rename dead `src/lua/*.rs` to migration namespace and remove
   references until ready.

Constraint:
- PRs in this epic must include explicit compiler boundary notes for API parity.

## 3) Required PR ordering

1. ADR update + runtime boundary freeze note.
2. `anomaly` cleanup PR.
3. `distributed` cleanup PR.
4. `lua` cleanup PR.
5. Final consolidation PR:
   - update `runtime-consolidation-5.3.md` with final results,
   - verify `cargo xtask architecture` with allowlist exactly matching the chosen outcomes.

## 4) Readiness checklist (must be green before 5.4 finish)

- `cargo check -p venom-scanner --locked` passes.
- `cargo check -p xtask --locked` passes.
- `cargo xtask architecture` remains a no-violation pass locally and in CI.
- Each moved/removed file appears in an explicit migration ADR and migration map.
- No PR in 5.4 introduces a new scanning feature or planner behavior.

## 5) Repository map to use across all PRs

Use the following runtime map as the single truth source for communication:

```text
venom scan
  └─ legacy runner (phases) path only

Decision runtime (in-tree, not scan-default)
  ├─ web_runtime
  ├─ planner
  ├─ decision_loop
  ├─ web_verification
  ├─ runtime_budget
  └─ http_evidence

Platform shell (feature-scoped, not default runtime)
  ├─ plugins
  ├─ compliance / monitoring / threat_intel
  ├─ distributed / ml / lua_engine
  └─ reporting / dashboard / realtime / persistence / post_exploitation
```

