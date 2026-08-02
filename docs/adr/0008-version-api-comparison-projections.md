# ADR 0008: Version API comparison projections outside the core wire contract

- Status: Accepted
- Date: 2026-08-02
- Extends: ADR 0006

## Context

The first API visibility comparator intentionally reduces authorized JSON views
to bounded signatures and emits the shared nine-field
`ApiVisibilityComparison`. That contract cannot explain which structural paths
differed, cannot ignore volatile fields, and has no persisted comparator or
canonicalization version.

Adding fields to the core comparison would change its wire shape and evidence
digest. Adding fields to `ApiVisibilityLimits` would also break its strict
unknown-field deserializer. Retrofitting projection into the existing signature
domains would make old and new evidence indistinguishable during replay.

## Decision

Projection-aware comparison is an additive scanner-owned API:

1. `ApiComparisonProfile` defines selected, ignored, and explicitly unordered
   paths plus one global explanation limit. The profile is normalized and
   content-addressed.
2. `capture_profiled_view` uses new domain-separated tree hashes. It first runs
   the complete legacy resource-envelope validation so projection cannot hide
   oversized input.
3. Captured views retain only signatures and a bounded index of path, type, and
   scalar-value digests. They retain no raw values or clear observed paths.
4. `compare_profiled` returns a separate envelope containing the unchanged core
   comparison, comparator/canonicalization versions, projection-policy ID,
   limits, and bounded redacted path differences.
5. The nested comparison ID is bound to the metadata tuple. Envelope
   deserialization rejects a nested identity that does not match its metadata.
6. Existing `capture_view`, `compare`, legacy signature domains, ordered-array
   semantics, limits, wire fields, and evidence digests remain unchanged.

## Consequences

- Existing consumers can continue using the legacy comparator without a source
  or wire migration.
- Replay-aware consumers must persist the complete profiled envelope; retaining
  only its nested core comparison discards projection metadata and explanation.
- Volatile fields and intentional set-like arrays can be modeled explicitly
  without silently changing global JSON semantics.
- Difference output is deterministic and bounded across added, removed,
  changed-type, and changed-value categories.
- Path and value digests are pseudonymous, not confidential. Common names and
  low-entropy values remain susceptible to dictionary attacks.

## Alternatives considered

- Extend `ApiVisibilityComparison`: rejected because it changes the shared core
  wire contract and digest identity.
- Add optional metadata fields and let old readers ignore them: rejected because
  silent metadata loss is a replay downgrade.
- Change legacy canonicalization in place: rejected because old snapshots would
  become uninterpretable under the same version and signature domains.
- Store clear diff paths or values: rejected because it expands retained
  application data and makes redaction host-dependent.
