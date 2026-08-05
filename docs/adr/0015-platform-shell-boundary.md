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

Classify runtime-critical module groups along **independent** axes rather than a
single exclusive category, because build/execution facts and maturity are
orthogonal (a module can be both opt-in and experimental) and a module can
participate in more than one surface (`knowledge`, for example, is instantiated on
the legacy `ScanContext` path *and* is a core part of the deterministic runtime).
The axes are:

- **Build availability** — always/default, opt-in cargo feature (`ml`,
  `distributed`, `monitoring`, `compliance`, `threat-intel`, `plugins`), a
  separate workspace crate, or absent.
- **Execution participation** — surface A (default scan), surface B (deterministic
  runtime), an explicit CLI adapter (`api`, `proxy`), library/host-only, or none.
- **Default `venom scan` participation** — yes, no, or conditional.
- **Support status** — implemented and tested, legacy alpha, experimental,
  scaffold, or unsupported.

The per-group classification lives in
[`internals/runtime-map.md`](../internals/runtime-map.md) and is the single place
to update when a module's status changes. The runtime map deliberately classifies
**runtime-critical module groups**, not every `pub mod`; exhaustive module-level
annotations are the scope of the source-level runtime-scope banners (PR-D2), not
this record.

This ADR **extends** ADR 0014; it does not supersede it — ADR 0014's runtime-truth
decision stands, and this record adds the classification model for surface C.

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
