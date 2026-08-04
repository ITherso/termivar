# Runtime Consolidation 5.5 — Epic A: Detection Shell Handoff

Status: **completed (boundary docs added)**

Scope: `advanced_detection`, `anomaly`

Owner: `team-runtime-science`

Goal: convert Detection Shell out of "accidentally implied production" into an explicit
platform-shell boundary without adding behavior.

## 1) Current runtime facts (from 5.5 inventory)

| Module(s) | Default feature compiled | Reachable | Exported | Executed by `venom scan` | 5.5 class |
| --- | --- | --- | --- | --- | --- |
| `advanced_detection` | ✅ | ✅ | ✅ | ❌ | `platform-shell` |
| `anomaly` | ✅ | ✅ | ✅ | ❌ | `platform-shell` |

`anomaly`/`advanced_detection` are reachable and compile-visible but are not used by the
legacy scan CLI path. They must remain present only as a shell boundary until a dedicated
milestone decides their migration.

## 2) Non-negotiable constraints for this epic

- Do **not** change runtime behavior.
- Do **not** expose these modules in `venom scan` execution path.
- Do **not** alter planner, verifier, payload strategy, or budget contracts.
- Keep all changes in docs, deprecation banners, ADR references, and migration ticket
  references.

## 3) Runtime migration ticket

Runtime ticket target: `RUNTIME-5.5.A-001`.

Every PR in Epic A must leave these artifacts in-tree and reviewed:

1. A module-boundary note in docs stating:
   - `advanced_detection` and `anomaly` are part of `platform-shell`.
   - they are **not** active scan defaults.
2. An updated migration record linked from:
   - `docs/migrations/runtime-consolidation-5.5.md`
   - `docs/adr/0015-platform-shell-boundary.md`
3. A dedicated ticket reference in the PR body (and module scope):
   - `RUNTIME-5.5.A-001`.
4. Explicit test/CI gate impact statement:
   - `cargo run --locked -p xtask -- architecture` remains green.
   - `cargo check -p venom-scanner --locked` remains green.

## 4) Approved migration options (to be used in a later milestone)

- Keep in platform-shell and mark as long-lived `scaffold`.
- Migrate into dedicated scanner/decision runtime layer after dedicated integration plan is approved.
- Remove, only with replacement plan and ADR.

## 5) Exit criteria for Epic A completion

- No code behavior change in `venom-scanner`, `venom-cli`, or `venom-core`.
- Runtime boundary text for Detection Shell appears in migration docs and ADR references.
- No additional files are added to `venom scan` execution chain.
- 5.5 class for these modules remains `platform-shell` until explicitly reclassified.

## 6) PR checklist (copy/paste)

- [x] PR includes only docs/metadata/migration updates for this boundary.
- [ ] PR does not touch planner/rules/payload/verification behavior.
- [ ] PR updates `runtime-consolidation-5.5.md` with current epic status.
- [ ] PR includes `Scope`, `Owner`, and `Ticket` in description.
- [ ] CI checks for architecture and compilation remain green.

## 7) Planned execution hook

- Add explicit boundary notes to:
  - `crates/venom-scanner/src/advanced_detection.rs`
  - `crates/venom-scanner/src/anomaly.rs`
- Keep these modules feature-scoped and non-default for scan execution until a dedicated
  integration milestone validates ownership transfer.

