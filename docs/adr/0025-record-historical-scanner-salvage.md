# ADR 0025: Record historical scanner salvage before restoring capability

- Status: Accepted
- Date: 2026-09-01

## Context

The workspace migration left the former root `src/scanner/` tree outside the
current crate graph, and commit
`28bfb2d8ae3a4f707b7423cac65b6be8e11085b6` later removed that unbuilt
monolith. Reverting the deletion would restore neither a coherent product
boundary nor trustworthy behavior. The historical sources mixed reusable
algorithms and taxonomies with direct I/O, unbounded caller-owned values,
random identity, and findings that were not supported by target evidence.

The deletion nevertheless removed useful recovery knowledge. In the
immediately preceding snapshot
`ede3d9e5b1098434a771ae6ca3cb530941e22210`, the 38 files under
`src/scanner/` include algorithms, research vocabulary, fixtures, and rejected
behaviors that should not have to be rediscovered from informal Git archaeology.
The workspace split at `3c90364279284bdbb82494b4e03d71b5066657c4`
did not faithfully port that tree into the current scanner crate.

A whole-file verdict is not sufficient. For example, historical `detector.rs`
contains a useful hexadecimal/wildcard buffer-signature scanner, an unsafe
memory-mapped file adapter, and an unrelated request-path detector that treated
payload text as proof of a vulnerability. Those components require different
decisions.

## Decision

- Keep the monolith deleted. Historical source is recovery evidence, not
  current product authority, and no ledger entry makes historical code
  compiled, reachable, supported, or executable.
- Maintain `salvage/historical-scanner/ledger.toml` as the authoritative strict
  `venom.historical-scanner-salvage/v1` inventory. Its generated readable view
  is `docs/history/historical-scanner-salvage.md`; the Markdown report is not a
  second independently maintained classification.
- Bind each of the 38 historical paths to its local Git blob identity and byte
  size. Classify reusable and prohibited behavior at component granularity
  with closed dispositions, priorities, modern destinations, and lifecycle
  statuses.
- Validate the ledger through `cargo run --locked -p xtask --
  scanner-salvage`. The validator uses local Git objects only, proves the
  source/split/deletion identities and exact tree inventory, checks component
  contracts, recalculates a deterministic semantic digest, and rejects a stale
  generated report. It neither compiles nor executes historical code.
- Require any future recovery to update only the relevant component from
  `Planned` to `Restored` and identify its reviewed modern implementation.
  Classification is not a promise that every planned component will ship.
- Record the byte-pattern compiler and caller-buffer scanning core from
  `detector.rs` as the first P0 recovery candidate for a future separate
  `venom-artifact` domain. Do not restore its unsafe mmap adapter, fabricated
  URL/request finding generator, random finding identity, raw payload evidence,
  or automatic severity. `venom-artifact` does not exist in this change.
- Keep this inventory entirely in repository tooling and documentation. It
  adds no scanner, CLI, API, proxy, exploit, network, filesystem, or process
  runtime and changes no scan behavior or claim policy.

## Consequences

- Useful historical concepts remain discoverable without treating deleted
  source as supported code or restoring mixed authority.
- Component-level records can preserve a payload taxonomy or fixture while
  explicitly rejecting fabricated findings or unsafe adapters from the same
  file.
- Exact local Git proof makes missing files, extra classifications, blob drift,
  and stale generated documentation fail closed in repository validation.
- Future recovery work has a reviewable chain from historical component to
  bounded modern implementation. Deleting obsolete source no longer silently
  deletes the decision record about recoverable value.
- This change has no runtime effect. Default `venom scan`, the opt-in legacy
  runner, exploit isolation, evidence semantics, and all network authorities
  remain unchanged.

## Alternatives considered

- **Revert the monolith deletion.** Rejected because it would reintroduce an
  unbuilt, mixed-quality tree outside current crate, authority, evidence,
  coverage, and compatibility contracts.
- **Classify only whole files.** Rejected because valuable algorithms and
  prohibited behavior coexist in files such as `detector.rs`.
- **Copy promising source into the ledger or report.** Rejected because the
  inventory should bind compact facts to Git objects, not create another source
  archive or executable path.
- **Treat Git history alone as the inventory.** Rejected because Git preserves
  bytes but not a reviewed disposition, modern destination, rejected behavior,
  or restoration status.
- **Restore the byte scanner in this decision.** Rejected because the ledger
  must land without runtime changes; a bounded artifact domain requires its own
  exact-head reviewed increment.
