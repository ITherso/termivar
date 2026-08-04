# Runtime Consolidation 5.5 — Operations Gatebook

This document is the runbook for moving from discovery to implementation without
changing runtime behavior.

## 0) Rule of the game

- No feature additions.
- No planner/decision/verification behavior changes.
- No scanner behavior changes.
- No semantic model expansion.
- No runtime feature activation from defaults.
- No module moves outside the documented migration sequence.

Any PR touching `venom-scanner` must prove it only updates boundaries/docs and keeps
the same runtime executable shape.

## 1) Pre-flight checks

Run before every Milestone/EPIC PR:

- `cargo run --locked -p xtask -- architecture`
- `cargo check -p venom-scanner --locked`
- `cargo check -p venom-scanner --locked --no-default-features`
- `cargo check -p venom-scanner --locked --features full`

Required output on pass:

- no output violations from reachability gate,
- no new unintentional `unreachable Rust source` entries,
- no accidental compile regression in default or full feature sets.

## 2) Legacy / active / shell map (quick classification)

### A) Executed by `venom scan` today

- `runner`, `context`, `contracts`, `phases/*`, `event_bus`, `logging`, and scan
  utilities they require.

### B) Compiled and exported but currently not executed by `venom scan`

- `api`, `api_evidence`, `api_gateway`, `api_observation`, `api_reasoning`
- `web_*` runtime branch (`web_runtime`, `web_execution`, `web_planning`,
  `web_reasoning`, `web_decision`, `web_verification`)
- `planner`, `decision_loop`, `decision_runner`, `runtime_budget`, `http_evidence`,
  `verification`, `adaptive`, `defense`, `semantic`, `rules`, `knowledge`,
  `experience`

### C) Platform shell (feature-scoped / non-default product path)

- `advanced_detection`, `anomaly`, `compliance`, `monitoring`, `threat_intelligence`
- `distributed`, `ml`
- `plugin`, `plugins`, `lua_engine`
- `persistence`, `reporting`, `realtime`, `dashboard`, `post_exploitation`

### D) Test scaffold / explicit allowlist

- `src/api_evidence_tests.rs`
- `src/web_runtime_tests.rs`
- `src/api_evidence/profiled_tests.rs`
- `src/web_runtime/api_visibility/differential_tests.rs`

## 3) EPIC execution order and artifact updates

When opening an EPIC PR:

- Update only the scope's dedicated handoff doc.
- Update this file or `runtime-consolidation-5.5.md` status marker.
- Link a migration ticket.
- Keep PR body scoped to docs/mapping metadata only.

Execution sequence:

1. **Epic A** (`advanced_detection`, `anomaly`)
2. **Epic B** (`compliance`, `monitoring`, `threat_intelligence`)
3. **Epic C** (`distributed`, `ml`)
4. **Epic D** (`plugin`, `plugins/*`, `lua_engine`)
5. **Epic E** (`persistence`, `reporting`, `realtime`, `dashboard`, `post_exploitation`)

## 4) EPIC status board

| EPIC | Scope | Owner | Handoff doc | Ticket | Status |
| --- | --- | --- | --- | --- | --- |
| A | `advanced_detection`, `anomaly` | `team-runtime-science` | [Epic A](runtime-consolidation-5.5-epic-A-detection-shell.md) | `RUNTIME-5.5.A-001` | Done (boundary docs added) |
| B | `compliance`, `monitoring`, `threat_intelligence` | `team-platform-observability` | [Epic B](runtime-consolidation-5.5-epic-B-compliance-shell.md) | `RUNTIME-5.5.B-001` | Done (boundary docs added) |
| C | `distributed`, `ml` | `team-platform-core` | [Epic C](runtime-consolidation-5.5-epic-C-distributed-ml-shell.md) | `RUNTIME-5.5.C-001` | Done (boundary docs added) |
| D | `plugin`, `plugins/*`, `lua_engine` | `team-plugins` | [Epic D](runtime-consolidation-5.5-epic-D-plugin-lua-shell.md) | `RUNTIME-5.5.D-001` | Done (boundary docs added) |
| E | `persistence`, `reporting`, `realtime`, `dashboard`, `post_exploitation` | `team-platform-runtime` | [Epic E](runtime-consolidation-5.5-epic-E-persistence-reporting-shell.md) | `RUNTIME-5.5.E-001` | Done (boundary docs added) |

## 5) Exit criteria for this gatebook phase

- 5.5 module classifications remain stable for this phase.
- 5.5 docs mention a single source of truth for runtime ownership.
- No default scan execution path changes occur before EPIC integration switch.

