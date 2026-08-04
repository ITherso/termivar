# Runtime Consolidation 5.5 — Epic B: Compliance Shell Handoff

Status: **in progress (boundary docs added)**

Scope: `compliance`, `monitoring`, `threat_intelligence`

Owner: `team-platform-observability`

Goal: keep all observability/compliance capabilities explicitly non-default,
platform-shell documented until a dedicated integration milestone decides relocation.

## 1) Current runtime facts (from 5.5 inventory)

| Module(s) | Default feature compiled | Reachable | Executed by `venom scan` | 5.5 class |
| --- | --- | --- | --- | --- |
| `compliance` | ❌ (feature) | ✅ | ❌ | `platform-shell` |
| `monitoring` | ❌ (feature) | ✅ | ❌ | `platform-shell` |
| `threat_intelligence` | ❌ (feature) | ✅ | ❌ | `platform-shell` |

These modules are important for product ambitions but are not part of production
scan behavior yet.

## 2) Non-negotiable constraints

- No runtime behavior changes.
- No new scan features.
- No semantic engine changes.
- No planner/rule/budget behavior changes.
- Keep modules behind feature gating and explicit docs note.

## 3) Runtime migration ticket

Runtime ticket target: `RUNTIME-5.5.B-001`.

## 4) Required migration artifacts

1. Add or refresh docs/ADR text asserting these modules are
   `platform-shell` and not scan-default.
2. Add a feature matrix to module docs showing:
   - default scan behavior (off),
   - feature-activated surfaces,
   - intended long-term ownership.
3. Link the corresponding migration ticket for future integration.
   - `RUNTIME-5.5.B-001`.

## 5) Exit criteria

- `docs/migrations/runtime-consolidation-5.5.md` references current status.
- `docs/adr/0015-platform-shell-boundary.md` remains consistent.
- `cargo run --locked -p xtask -- architecture` passes.
- `cargo check -p venom-scanner --locked` does not regress.

## 6) PR checklist

- [ ] docs-only, no runtime/path behavioral changes.
- [ ] explicit compatibility matrix for feature-gated modules.
- [ ] ticket (`RUNTIME-5.5.B-001`) + owner in PR description.
- [ ] no new references from `venom scan` decision flow.

## 7) Planned execution hook

- Add/update explicit boundary notes to:
  - `crates/venom-scanner/src/compliance.rs`
  - `crates/venom-scanner/src/monitoring.rs`
  - `crates/venom-scanner/src/threat_intelligence.rs`
- Keep modules off by default for scan execution while preserving feature surfaces for
  future migration milestones.
