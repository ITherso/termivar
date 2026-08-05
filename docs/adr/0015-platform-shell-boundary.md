# ADR 0015: Classify the platform shell by execution reality

- Status: In review
- Date: 2026-08-05
- Extends: ADR 0014

## Context

ADR 0014 named the three runtime surfaces and pointed at the runtime map. Surface
C — the "platform shell" — still needs a durable rule for how each module is
described, because it mixes very different levels of support: some modules run on
the default CLI scan, some are compiled but never executed by it, some are behind
non-default features, and a few are experimental or unsupported.

Without an explicit rule, a module's mere existence (or an aspirational doc
string) reads as a support claim. That is the exact drift ADR 0014 set out to
stop.

## Decision

Every platform-shell module is classified along two verifiable axes: the default
feature set (`["core", "scanning", "detection"]`) and the default execution path
(the `venom scan` phase pipeline). Each module is exactly one of:

- **Executed by the default CLI** — on the surface A phase pipeline.
- **Compiled but not executed by the default CLI** — present under the default
  feature set, but not on the default scan path (for example the decision-runtime
  stack and the detection modules).
- **Opt-in feature** — requires a non-default cargo feature (`ml`, `distributed`,
  `monitoring`, `compliance`, `threat-intel`, `plugins`).
- **Experimental / scaffold** — present but with an explicitly unstable contract
  (for example `venom-proxy`'s `AsyncMitmProxy`, with an unstable interception
  API and a hard-coded upstream).
- **Unsupported** — not wired into any runnable, supported path (for example the
  `venom api` listener, which does not bind; and deployment manifests, removed in
  the infrastructure consolidation).

The per-module classification lives in
[`internals/runtime-map.md`](../internals/runtime-map.md) and is the single place
to update when a module's status changes. This ADR **extends** ADR 0014; it does
not supersede it — ADR 0014's runtime-truth decision stands, and this record adds
the classification rule for surface C.

## Consequences

- A module's status is a deliberate, reviewable classification, not an accident
  of whether a file exists.
- Promoting a module (for example wiring the decision runtime into the default
  CLI, or stabilising the proxy) is a documented status change.
- Documentation-only: no Rust, Cargo, CI, infrastructure, runtime, or scanner
  behavior changes. Source-level `//! Runtime scope` banners are intentionally
  out of scope here and are handled separately.

## Alternatives considered

- **Supersede ADR 0014 with a single combined record.** Rejected: ADR 0014's
  decision is still in force; superseding would erase it. Extending keeps the
  runtime-truth decision intact and layers the shell classification on top.
- **Classify only by cargo feature.** Rejected: a feature axis alone cannot
  distinguish "compiled under default but never executed by the default CLI" from
  "executed by the default CLI" — the distinction readers most need.
