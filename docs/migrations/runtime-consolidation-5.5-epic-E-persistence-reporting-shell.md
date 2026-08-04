# Runtime Consolidation 5.5 — Epic E: Persistence + Reporting Shell Handoff

Status: **ready**

Scope: `persistence`, `reporting`, `realtime`, `dashboard`, `post_exploitation`

Owner: `team-platform-runtime`

Goal: mark these modules as explicit platform-shell features and prevent implicit
assumptions that they are active production scan behavior.

## 1) Current runtime facts (from 5.5 inventory)

| Module(s) | Default feature compiled | Reachable | Exported | Executed by `venom scan` | 5.5 class |
| --- | --- | --- | --- | --- | --- |
| `persistence` | ✅ | ✅ | ✅ | ❌ | `platform-shell` |
| `reporting` | ✅ | ✅ | ✅ | ❌ | `platform-shell` |
| `realtime` | ✅ | ✅ | ✅ | ❌ | `platform-shell` |
| `dashboard` | ✅ | ✅ | ✅ | ❌ | `platform-shell` |
| `post_exploitation` | ✅ | ✅ | ✅ | ❌ | `platform-shell` |

These files compile in the current default feature set but are not invoked by default scan execution.

## 2) Non-negotiable constraints

- No runtime behavior change.
- No scan execution path additions.
- No integration behavior changes (auth, dashboard, persistence semantics).
- No feature semantics changes without explicit migration ticket.

## 3) Required migration artifacts

1. Add explicit docs/ADR note that these modules are feature-independent or
   post-scan platform surfaces, not production scan defaults.
2. Document API and behavior boundaries in migration note.
3. Attach dedicated ticket for any future migration out of shell scope.

## 4) Exit criteria

- `docs/migrations/runtime-consolidation-5.5.md` records current non-executed status.
- `docs/adr/0015-platform-shell-boundary.md` and ADR chain remain internally consistent.
- Required gates pass:
  - `cargo run --locked -p xtask -- architecture`
  - `cargo check -p venom-scanner --locked`

## 5) PR checklist

- [ ] docs-only.
- [ ] no CLI/runtime behavior changes.
- [ ] explicit non-default/non-scan execution note.
- [ ] ticket + owner in PR description.

