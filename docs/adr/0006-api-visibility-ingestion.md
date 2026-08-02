# ADR 0006: Keep API visibility ingestion outside the decision runner

- Status: Accepted
- Date: 2026-08-02
- Clarifies: ADR 0005's use of "durable" for in-memory knowledge records

## Context

An API visibility comparison is not ordinary endpoint evidence. It represents
two already-authorized views of the same logical resource. Its evidence subject
is a pseudonymous `api-comparison:*` identity, while an evidence-backed relation
links that comparison to the host's opaque resource scope.

The decision runner deliberately accepts evidence only for the outstanding
verification case's subject. Weakening that invariant would allow an executor
to write observations about unrelated principals or resources. It would also
be insufficient: the decision loop reasons over one session-subject snapshot,
so silently accepting a second subject would not make the comparison visible to
the active decision turn.

Hosts also need a deterministic way to compare normalized JSON views without
retaining response bodies, credentials, or application values in the resulting
knowledge records.

ADR 0005 used "durable" to distinguish the bundled relation from detached
evidence. This ADR narrows that wording: the bundle is committed to the
supplied in-memory `KnowledgeBase`, while crash persistence is always owned by
the host.

## Decision

API visibility uses a dedicated, transport-free evidence boundary:

1. A bounded comparator reduces each authorized JSON view to canonical
   signatures for status, field shape, and resource content. Map order is
   normalized; array order and duplicate array elements remain meaningful.
2. The comparator validates shared resource scope and surface plus distinct
   opaque contexts, then produces only an `ApiVisibilityComparison`.
3. The comparison creates one `ApiVisibilityObservation`. A host-facing
   ingestion operation validates the expected resource, atomically commits its
   evidence and scope relation, and applies reasoning to the comparison subject.
4. The ingestion result is a typed receipt. If reasoning fails after the
   observation pair is committed to the supplied knowledge-base instance, the
   error retains the commit receipt rather than implying rollback. Host-owned
   persistence remains a separate concern.
5. Resource review views are cursor-bounded projections over the canonical
   scope relation. Rejected edges consume a hard-limited page budget; the view
   inspects referenced variable fields before cloning them and does not merge
   comparison subjects or convert a boundary into a vulnerability.

The existing `DecisionActionExecutor` subject invariant remains unchanged.
This slice performs no network requests, chooses no planner actions, carries no
credentials, and provides no active verifier.

## Consequences

- Evidence collection and decision policy remain separate and independently
  testable.
- Raw JSON is consumed transiently and is absent from visibility snapshots,
  evidence, relations, receipts, and review projections.
- Depth, node, field, and canonical-byte limits fail closed before a comparison
  is emitted.
- Canonical hashes are deterministic pseudonymous fingerprints, not encryption,
  authentication, or a confidentiality boundary. Low-entropy values may still
  be guessable by a party that already has the same candidate input.
- A committed observation remains present in that knowledge-base instance if
  later rule evaluation fails. The receipt makes that partial turn explicit;
  it is not a persistence acknowledgement.
- Planner or active-verification support requires a later design for
  relation-aware review commands; it must not be implemented by relaxing the
  runner's one-subject evidence validation.

## Alternatives considered

- Allow decision executors to return arbitrary-subject evidence: rejected
  because it weakens case isolation and still does not change the loop's
  subject-scoped snapshot.
- Rewrite comparison evidence onto the endpoint subject: rejected because it
  could combine different principals, resources, or comparison turns.
- Store raw response pairs for later comparison: rejected because it expands
  secret-retention and payload-size risk without improving deterministic
  reasoning.
- Infer authorization bypass directly from a difference: rejected because a
  visibility difference may be intentional and remains a reviewable boundary,
  not a vulnerability claim.
