# Derived-evidence lineage

Termivar records immutable [`Evidence`]. Some records are **derived**: computed from
other evidence records rather than observed first-hand. This page defines how a
derived record identifies the exact source record(s) that justify it.

## Direct vs. derived

- **Direct evidence** — a first-hand observation. Its origin is
  `EvidenceOrigin::Direct`. This is the default and the historical meaning of
  every record.
- **Derived evidence** — a record computed from one or more exact parent
  records. Its origin is `EvidenceOrigin::Derived(EvidenceDerivation)`.

A record with no parents is direct. There is no "zero-parent derivation": an
empty parent set is rejected at construction.

## Producer provenance is not derivation lineage

These are distinct and must not be conflated:

| Concept | Where it lives | Meaning |
| --- | --- | --- |
| Producer provenance | `EvidenceSource { component, method }` | *Who* produced the record and *how* |
| Case correlation | `EvidenceSource.correlation_id` | *Which* verification case / execution turn emitted it |
| **Derivation lineage** | `EvidenceOrigin::Derived` | *Which exact records* were transformed into this one |
| Reasoning support | `Fact.evidence_ids`, `EvidenceContribution` | Which records support a fact or hypothesis |
| Entity relation | `KnowledgeRelation` | A semantic edge between knowledge entities |

Sharing a `correlation_id` means two records came from the same turn — **not**
that one was derived from the other. Lineage is exact parent `EvidenceId`s.

## Contract

- **Exact parents.** `EvidenceDerivation` holds one or more parent `EvidenceId`s,
  canonicalized (sorted, de-duplicated). Acceptance never depends on input order,
  and an equivalent lineage is a single stable value.
- **Algorithm identity.** A stable, bounded `DerivationAlgorithm { name, version }`
  lets a consumer know exactly which transformation produced a child, not merely
  that some transformation did.
- **Atomic insertion.** The knowledge store validates lineage before any write:
  self-reference, parent existence (over the committed store plus the same
  batch), subject agreement, and cycle freedom. Any violation rejects the whole
  batch — no orphan child, no orphan lineage, no partial index. A parent may
  appear after its child within a batch.
- **Boundedness.** Parents per record are bounded by `MAX_DERIVATION_PARENTS`;
  the algorithm name by `MAX_DERIVATION_ALGORITHM_BYTES`. Cycle detection is an
  explicit-stack (never recursive) traversal scoped to a batch's new records,
  bounded by batch size times the parent bound.
- **Identity.** Origin participates in structural equality, so reusing an
  evidence ID as direct-vs-derived, or with a different parent set, is an
  identity conflict.

## What lineage does *not* do

- It does **not** change claim semantics. Reasoning still evaluates predicates
  and values exactly as before; an `EvidenceSelector` contributes the derived
  record, not automatically its ancestors. Parent reliability and contribution
  are never auto-propagated into hypotheses.
- It does **not** assert completeness. A derived record reflects a bounded
  observation, never a complete inventory.
- It does **not** create findings or confirm hypotheses.

## Compatibility

Lineage is **runtime truth held in the live knowledge store**. It is
deliberately excluded from the serialized `Evidence` wire (`origin` is
`#[serde(skip)]`): the serialized form of every record — direct or derived — is
byte-identical to the historical contract, and historical/current direct wire
loads unchanged. This avoids encoding a strippable derived/direct discriminator
on a wire that has no durable archive today. Durable lineage export is a future,
explicitly versioned surface (see the profiled API-comparison envelope for the
pattern), not this record's wire.

## First consumer

`http.response.form-control-names` is derived from the exact
`http.response.response-body-sample` record it parsed, using the
`http.form-control-names` v1 algorithm. The body sample is the sole
transformation input; the response media type and truncation flag gate or
contextualize extraction but are not cited as lineage.
