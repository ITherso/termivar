# API visibility evidence

Venom separates API observation from API interpretation. The evidence layer
compares two views that the host has already authorized and paired; the
decision layer turns the resulting immutable observation into reviewable
hypotheses.

```text
authorized baseline JSON ----+
                             +--> ApiVisibilityComparator
authorized candidate JSON ---+              |
                                            v
                              ApiVisibilityComparison
                                            |
                                            v
                               ApiVisibilityObservation
                                            |
                                            v
                         evidence + resource relation commit
                                            |
                                            v
                              StandardApiReasoning rules
                                            |
                                            v
                         resource-scoped review projection
```

This path performs no network I/O, chooses no attack, carries no credential,
and does not classify a vulnerability.

## Bounded comparator

`ApiVisibilityComparator` borrows a `serde_json::Value` only while producing
two SHA-256 signatures. `ApiVisibilityView` retains the signatures, exact HTTP
status, declared API surface, selected limits, and non-secret opaque context and
resource handles. It never retains the JSON value or a canonical byte buffer.
The value has already been read and parsed before this API is called, so these
limits do not bound response-body buffering or JSON parser allocation. Hosts
must enforce a response-byte ceiling before parsing; the standard runtime's
`max_response_bytes` is that outer boundary when this comparator is integrated
there.

Canonicalization has explicit semantics:

- object keys are ordered by their UTF-8 bytes, so map insertion order is not
  evidence;
- array order and duplicate array elements remain meaningful;
- `Fields` compares key and schema structure without scalar values;
- `Resources` compares the complete canonical JSON structure and values;
- `Status` compares the exact validated HTTP status;
- views captured under different policies, resources, or API surfaces cannot
  be compared;
- both contexts must be distinct bounded opaque handles.

The default and compiled hard ceilings are:

| Dimension | Default | Hard ceiling |
| --- | ---: | ---: |
| JSON depth | 64 | 128 |
| JSON nodes | 100,000 | 1,000,000 |
| Object fields | 50,000 | 250,000 |
| Bytes per canonical stream | 8 MiB | 64 MiB |

Every configurable value must be positive and no larger than its hard ceiling.
Persisted `ApiVisibilityLimits` reject unknown fields and are revalidated on
load. The serialized policy is versioned with the Preview comparator contract;
adding a required field is intentionally treated as incompatible until a
versioned migration exists. Limit exhaustion returns an error before a
comparison is emitted.

JSON numbers are encoded through the pinned `serde_json` implementation. Their
canonical text and the resulting fingerprints are deterministic for this
comparator/toolchain contract, but are not promised as permanent cross-version
wire hashes. Hosts that persist signatures for replay must pin dependencies and
record the Venom comparator version.

```rust
use serde_json::json;
use venom_core::{
    ApiSurfaceKind, ApiVisibilityDimension, ApiVisibilityPairKind,
    ConfidenceScore, EntityId,
};
use venom_scanner::{
    ApiVisibilityComparator, ApiVisibilityReviewQuery, KnowledgeBase,
    RuleEngine, StandardApiReasoning, api_visibility_reviews_for_resource,
    ingest_api_visibility_observation,
};

let comparator = ApiVisibilityComparator::default();
let baseline = comparator.capture_view(
    "anonymous-view",
    "resource:account-42",
    ApiSurfaceKind::JsonHttp,
    200,
    &json!({"id": 42}),
)?;
let candidate = comparator.capture_view(
    "member-view",
    "resource:account-42",
    ApiSurfaceKind::JsonHttp,
    200,
    &json!({"id": 42, "email": "redacted@example.test"}),
)?;
let comparison = comparator.compare(
    "comparison-17",
    ApiVisibilityPairKind::AuthorizationContext,
    ApiVisibilityDimension::Fields,
    &baseline,
    &candidate,
    1_800_000_000_000,
)?;
let observation = comparison.to_observation(
    "host.api-comparator",
    ConfidenceScore::MAX,
)?;

let resource = EntityId::new("resource:account-42")?;
let knowledge = KnowledgeBase::new();
let mut rules = RuleEngine::new();
StandardApiReasoning::new()?.install(&knowledge, &mut rules)?;
let receipt = ingest_api_visibility_observation(
    observation,
    &resource,
    &knowledge,
    &rules,
)?;
assert_eq!(receipt.commit().resource_scope(), &resource);

let query = ApiVisibilityReviewQuery::new(32)?;
let page = api_visibility_reviews_for_resource(&knowledge, &resource, &query);
assert_eq!(page.reviews().len(), 1);
if let Some(cursor) = page.next_after_relation_id() {
    let next_query = ApiVisibilityReviewQuery::new(32)?
        .after_relation_id(cursor.clone())?;
    let _next_page = api_visibility_reviews_for_resource(
        &knowledge,
        &resource,
        &next_query,
    );
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

The example value is consumed transiently. Neither it nor the email string is
stored in the view, comparison evidence, resource relation, receipt, or review
projection.

## Authorized runtime workflow

`StandardWebDecisionRuntime` can host the same ingestion and review boundary
when it is built with `.enable_api_reasoning()`:

```rust
let mut runtime = StandardWebDecisionRuntime::builder(target)
    .enable_api_reasoning()
    .build()?;

let receipt = runtime.ingest_api_visibility(observation, &resource)?;
let page = runtime.api_visibility_reviews(
    &resource,
    &ApiVisibilityReviewQuery::new(32)?,
)?;
```

The facade accepts only the typed, host-created observation. It does not fetch
or pair responses and never receives raw JSON, credentials, or principal
identities. The host must authenticate the producer, authorize both views, and
assert their shared logical resource. Comparison subjects remain isolated, and
ingestion does not change runtime requests, response-byte accounting, planning,
experience, or decision-session state. A runtime without API reasoning enabled
returns `RuntimeApiVisibilityError::ApiReasoningDisabled` before any write.
Post-commit reasoning failures retain their observation receipt.

## Commit and reasoning receipts

`ingest_api_visibility_observation` verifies the caller's expected resource
before writing. It then commits the comparison evidence and its sole
`api.visibility.resource-scope` relation atomically. Reasoning runs afterwards
on the pseudonymous comparison subject.

`ApiObservationReceipt` contains:

- the comparison subject and resource scope;
- the evidence and relation IDs;
- idempotent `KnowledgeWrite` results for both records;
- rule applications and hypothesis write statuses in stable rule-ID order.

Each `RuleApplication` contains the candidate evaluated from that cycle's
snapshot. It is not a post-commit hypothesis clone: terminal-state preservation
can make stored state differ from the candidate. Consumers needing the
committed view must re-read the hypothesis from the knowledge base.

Comparison evidence is immutable within the supplied `KnowledgeBase` instance.
If rule evaluation fails after the pair is committed,
`ApiObservationError::ReasoningAfterCommit` carries the committed
`ApiObservationCommitReceipt`. A retry therefore has enough information to
distinguish a post-commit failure from a pre-commit rejection. Persistence
beyond the in-memory knowledge base remains a host responsibility. Materialized
hypotheses retain their evaluation timestamps, so full reasoning-receipt bytes
are not guaranteed to be identical across exact replays even though rule order
and idempotent write results are deterministic. Rule-produced hypotheses
themselves are batch-preflighted and written atomically, so a late identity
conflict cannot leave only the earlier conclusions from that reasoning pass.
The rule engine also compares subject and ontology revisions at commit time and
re-evaluates a stale snapshot within a fixed retry limit. Continuous concurrent
writes fail explicitly instead of allowing an old belief trail to overwrite a
newer one.

## Resource review projection

`api_visibility_reviews_for_resource` follows incoming canonical scope
relations and returns a deterministic relation-ID-ordered page. Callers supply
an `ApiVisibilityReviewQuery`; the default scans 128 incoming relations and the
compiled hard ceiling is 1,024. Malformed, unrelated, or forged-looking
relations are omitted but still consume the scan budget. When more relations
exist, `next_after_relation_id` identifies the last relation actually scanned
and becomes the exclusive cursor for the next query. This keeps both cloning
and inspection bounded even when a resource has many rejected edges.

The knowledge store also rejects oversized relation records before insertion:

| Relation field | Hard ceiling |
| --- | ---: |
| Relation ID | 512 bytes |
| Source or destination entity ID | 2,048 bytes each |
| Custom relation kind | 256 bytes |
| Evidence provenance | 32 IDs |
| Each provenance ID | 512 bytes |

The page clones at most its validated count of these bounded records. It checks
for a following relation against the borrowed index without cloning that
look-ahead record. Before cloning referenced records, the projection inspects
them while borrowed and rejects a producer component above 256 bytes or a
boundary rationale above 1,024 bytes. The ingestion boundary applies the
producer-component limit before its atomic write; the read-side check also
covers trusted code that writes directly to `KnowledgeBase`. Cursor IDs and
content fingerprints are redacted from the new API types' `Debug` output;
hosts should still avoid logging serialized cursors or other low-entropy
deterministic identifiers.

The cursor is scoped to that resource and is not a frozen database snapshot.
Concurrent inserts sort by their stable relation IDs; a relation inserted at or
before an already consumed cursor may not appear in later pages. Hosts needing
a point-in-time export must provide an external snapshot or quiesce writes.

Each review contains the comparison evidence and only a canonical-shaped
visibility-boundary hypothesis. The expected standard hypothesis ID,
predicate, pair, result, value, and sole evidence binding must all agree;
equivalent comparisons remain visible with an empty boundary list. These
checks do not attest which rule installation produced the hypothesis. Surface
and response-format hypotheses are intentionally excluded.

The projection validates canonical IDs, provenance linkage, evidence kind,
method, reliability, predicate, dimension, and belief evidence before including
a record. These are structural hygiene checks, not producer authentication.

## Trust and privacy boundary

The comparator hashes raw values but does not encrypt them. Its signatures and
the core comparison digest are pseudonymous deterministic fingerprints, not
HMACs, signatures, attestations, or proof that a comparison occurred. An actor
with a low-entropy candidate value may be able to reproduce a digest.

Hosts must authenticate evidence producers, authorize both views, and use
non-secret opaque handles. The decision runner's one-case/one-subject evidence
rule remains unchanged; paired comparison ingestion is deliberately outside
that execution path. See [ADR 0006](../adr/0006-api-visibility-ingestion.md).
