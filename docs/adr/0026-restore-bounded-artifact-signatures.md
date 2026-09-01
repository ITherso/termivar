# ADR 0026: Restore bounded artifact signature scanning as a separate domain

- **Status:** Accepted
- **Supersedes:** no earlier artifact-scanner ADR
- **Extends:** [ADR 0025](0025-record-historical-scanner-salvage.md)

## Context

The deleted `src/scanner/detector.rs` mixed three different kinds of behavior:
a useful hexadecimal/wildcard buffer matcher, an unsafe memory-mapped file
adapter, and request-path substring heuristics that fabricated vulnerability
records. Restoring the file or old monolith would also restore authority and
claims that violate current Venom contracts.

## Decision

- Reimplement only the byte-pattern concept in an independent, non-published
  `venom-artifact` crate with `unsafe_code = "forbid"`.
- Keep the library transport- and path-neutral. It scans caller-supplied bytes
  and bounded readers, produces deterministic observations, retains no raw
  matched content, and never assigns vulnerability severity or a malware
  verdict.
- Preserve exact and wildcard matching while correcting the historical overlap
  bug. Streaming uses bounded carry and must equal byte-slice results for a
  complete scan.
- Version the pack schema, matching algorithm, canonical pattern syntax,
  catalog identity, and report schema. Repository packs are strict metadata;
  `xtask artifact-catalog` validates but never scans them.
- Put explicit local regular-file access in the non-default CLI
  `artifact-adapter` feature. The adapter accepts one caller-selected file and
  one manifest, performs no recursion, writes nothing, and does not alter
  `venom scan`.
- Mark only `detector.byte-pattern` as restored in the salvage ledger. Keep the
  unsafe mmap adapter, fabricated request vulnerability logic, random result
  identity, raw payload evidence, automatic severity, and unsupported BMH or
  zero-copy claims rejected.

## Consequences

Artifact observations remain separate from web assessment findings and exploit
authorization. `venom-scanner` and `venom-exploit` do not depend on
`venom-artifact`; the default CLI does not include it. Future signature packs
must satisfy bounded schema, identity, catalog, report, coverage, and exact-head
CI contracts, but catalog membership never triggers scanning.

The V1 implementation does not acquire process memory, recurse through a
machine, provide antivirus protection, execute content, or confirm malware or a
vulnerability.

## Alternatives considered

- **Restore `detector.rs` or the monolith.** Rejected because useful matching was
  inseparable from unsafe I/O and fabricated claims.
- **Place the matcher in `venom-scanner`.** Rejected because artifact bytes and
  web transport are different authority domains.
- **Use memory mapping for throughput.** Rejected for V1 because a safe bounded
  reader supplies the required large-file semantics without unsafe code.
- **Treat a match as a vulnerability or malware verdict.** Rejected because a
  signature observation does not establish provenance, execution, or impact.
