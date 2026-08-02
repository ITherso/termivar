# ADR 0011: Version API explanation semantics

- Status: Accepted
- Date: 2026-08-02
- Extends: ADR 0008

## Context

The V2 profiled API comparator could report a status difference together with
body-path differences even though the body did not explain the selected status
dimension. An empty path diff was also ambiguous: it could mean equivalence, a
status-only difference, an ordered-array difference, or a quota-limited result.
Changing those meanings under the same algorithm version would make persisted
comparisons non-deterministic across binaries.

## Decision

1. Comparator semantics move to `ComparisonAlgorithmVersion::V3` and a V3
   comparison-identity domain.
2. Status comparisons never fabricate body-path explanations.
3. `VisibilityExplanationDisposition` distinguishes equivalence, a bounded
   path summary, and a difference without a representable path summary.
4. Current profile and envelope deserializers reject non-current comparator or
   canonicalization versions before interpreting their explanation fields.
5. Historical V2 replay requires the matching binary or an explicit migration;
   the current binary does not silently reinterpret a V2 envelope as V3.

## Consequences

- The same V3 fixture, profile, and metadata produce the same result and
  explanation disposition.
- Persisted V2 profiles and envelopes do not load in the V3 reader.
- The legacy nine-field core comparison remains unchanged.
- Every future explanation-semantic change requires another algorithm version
  and identity domain.

## Alternatives considered

- Keep V2 and document the changed behavior: rejected because identical replay
  metadata could then produce different explanations.
- Decode V2 and infer its intended meaning in the V3 reader: rejected because
  the old empty-diff shape does not contain enough information to do that
  without ambiguity.
