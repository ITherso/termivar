# ADR 0027: Record the post-workspace WAF/evasion salvage epoch

- **Status:** Accepted
- **Date:** 2026-09-01
- **Extends:** [ADR 0025](0025-record-historical-scanner-salvage.md) with a
  separate source epoch
- **Runtime effect:** None

## Context

The pre-workspace salvage inventory in ADR 0025 covers the deleted 38-file
`src/scanner/` monolith. A later and distinct removal wave occurred after the
Cargo workspace existed. Source snapshot
`52238460484e7a1469f1028fdd6361072a0daba5` contained WAF fingerprinting,
adaptive selection, scoring, and payload-transformation code under
`crates/venom-scanner`. Its direct child
`5a0563886658859b6e3e163f732a298914b10800` removed five relevant files and
materially narrowed other files in that capability graph.

This second epoch must not be folded into the first ledger. The source roots,
build context, deletion mechanism, and modern replacements differ. The scoped
inventory contains 13 historical files and 39 component-level decisions.

The historical `waf.rs` also combined concerns that the current architecture
keeps separate. Product fingerprinting, status observations, payload
transformations, request-shape mutation, and claims of bypass shared one
module and a generic dispatcher. Current Venom already has bounded,
observation-only defense fingerprinting and typed defense state/transition
evidence. Blindly restoring the old source would duplicate that work while
reintroducing selection without typed compatibility, semantic verification,
request accounting, or conservative claim authority.

## Decision

- Maintain `salvage/post-workspace-waf-evasion/ledger.toml` as the authoritative
  strict `venom.post-workspace-waf-evasion-salvage/v1` inventory. Its generated
  readable projection is
  `docs/history/post-workspace-waf-evasion-salvage.md`; the Markdown is not a
  second classification source.
- Keep this ledger separate from `salvage/historical-scanner/ledger.toml`.
  Neither epoch changes the other's source scope, semantic digest, component
  meaning, or restoration status.
- Bind all 13 scoped historical paths to exact local Git blob identities and
  byte sizes. Classify 39 components with closed dispositions, priorities,
  statuses, modern destinations, prerequisites, prohibited restoration
  behavior, and factual rationale.
- Validate the epoch with `cargo run --locked -p xtask --
  waf-evasion-salvage`. The validator uses local Git objects only, proves the
  source/quarantine parent relationship, validates removed or narrowed state,
  recalculates a deterministic semantic digest, and rejects a stale generated
  report. It never compiles, interprets, or executes historical source and
  never accesses the network.
- Treat historical WAF fingerprinting as superseded by the modern `defense`
  domain and its bounded fingerprint, state, transition, and evidence
  contracts. Historical neutral percent and hexadecimal encoding map only to
  the existing payload-strategy encoding boundary. These replacement mappings
  describe current ownership; they grant no execution or claim authority.
- Preserve grammar-aware case and whitespace concepts, explicit encoding-layer
  concepts, transformation taxonomy, and useful ranking dimensions only as
  recovery metadata requiring new contracts. A ledger disposition is not an
  executable transform or a promise to ship one.
- Continue rejecting status-code-to-evasion mapping, generic transformation
  dispatch, parameter pollution as an ordinary payload mutation, semantic
  truncation claims, rate-limit evasion, HTTP splitting, CRLF injection, and
  unverified bypass claims.
- Do not restore `crates/venom-scanner/src/waf.rs`, the retired
  `adaptive::{payloads,scoring,strategy}` modules, the old
  `payload_strategies::normalization` module, or the historical
  `EvasionTechnique` dispatcher. Existing architecture gates remain intact.
- Add no scanner, CLI, API, proxy, exploit, artifact, network, filesystem,
  process, or browser runtime. Default `venom scan`, request authority,
  evidence semantics, and claim policy remain unchanged.

## Consequences

- Both removal waves remain independently auditable without making either
  historical tree current product authority.
- Modern defense observation is distinguished from future payload
  transformation. A fingerprint or status code cannot authorize execution.
- Recoverable transformation concepts have provenance and explicit
  prerequisites without restoring attack-shaped code or unsupported claims.
- Exact local-Git validation detects missing paths, extra paths, blob/size
  drift, removal-state drift, contradictory classifications, digest drift, and
  stale generated documentation.
- A future normalization-resilience runtime, if separately reviewed, must use
  explicit opt-in, typed compatibility, bounded shared-broker execution,
  application-semantic verification, replay, and conservative authority. This
  decision implements none of that runtime.

## Alternatives considered

- **Merge the two historical epochs into one ledger.** Rejected because it
  would obscure distinct source roots, removal events, modern replacements,
  and restoration status.
- **Restore `waf.rs` or the adaptive modules.** Rejected because those sources
  mix observation, mutation, dispatch, and claim authority and conflict with
  current architecture gates.
- **Treat current defense fingerprinting as missing capability.** Rejected
  because bounded typed fingerprinting already exists in the modern defense
  domain; the removed exact-string detector is superseded rather than lost.
- **Activate transformations while inventorying them.** Rejected because
  transformation execution requires a separate feature, runtime policy,
  compatibility contract, evidence model, semantic verifier, replay, budget,
  and exact-head CI review.
- **Use HTTP status alone as WAF or bypass evidence.** Rejected because a bare
  status proves neither a defensive product, candidate-specific engagement,
  semantic equivalence, nor application impact.
