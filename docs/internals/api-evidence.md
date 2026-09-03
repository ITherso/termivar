# API visibility evidence

Termivar separates API observation from API interpretation. The evidence layer
compares two views that the host has already authorized and paired; the
decision layer turns the resulting immutable observation into reviewable
hypotheses.

The explicitly enabled OpenAPI review follows the same separation. Its native
executor commits bounded HTTP media and replayed document-catalog evidence to
the parent assessment's shared knowledge base. The existing transport-neutral
API reasoning rules may consume that committed evidence, but the reasoner never
selects a document, dispatches a request, materializes a parameter, or executes
an operation described by the contract.

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

The comparator and ingestion path shown above performs no network I/O, chooses
no attack, carries no credential, and does not classify a vulnerability. The
standard runtime also exposes a narrower broker-backed collector described
below; it feeds this same comparison and ingestion boundary.

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
record the Termivar comparator version.

## Profiled comparator v3

The additive profiled API leaves `ApiVisibilityLimits`, `ApiVisibilityView`,
`ApiVisibilityComparison`, `capture_view`, and `compare` unchanged. This is
deliberate: the legacy comparison keeps its exact nine-field wire shape and its
existing evidence identity.

`capture_profiled_view` and `compare_profiled` add an explicit
`ApiComparisonProfile` and return `ProfiledApiVisibilityComparison`. The
profiled envelope persists:

- the comparator and canonicalization versions;
- a content-derived projection-policy ID;
- the validated resource limits;
- the nested legacy comparison;
- a globally bounded, raw-value-free `RedactedVisibilityDiff`.

Comparator v3 makes explanations dimension-aware: a status comparison never
attaches unrelated body paths, while a real difference without a representable
path summary remains explicit rather than being mistaken for equivalence.
Persisted v2 profiles and envelopes are deliberately rejected rather than
silently reinterpreted under v3 semantics. Hosts that must replay historical v2
records need the matching pre-rebrand binary or an explicit offline migration.
See [ADR 0011](../adr/0011-version-api-explanation-semantics.md).

Profiles support selected subtrees, ignored subtrees, and explicitly unordered
arrays. Paths use RFC 6901 escaping. A segment equal to `*` is Termivar's bounded
wildcard extension, primarily for structural array paths such as
`/data/edges/*/node/id`. Empty selection means the complete document. Ignore
rules take precedence, and construction rejects a selected path already hidden
by an ignored ancestor. Input order and duplicates do not change the policy ID.

```rust
use serde_json::json;
use termivar_core::{
    ApiSurfaceKind, ApiVisibilityDimension, ApiVisibilityPairKind,
};
use termivar_scanner::{
    ApiComparisonProfile, ApiVisibilityComparator, JsonPathPattern,
};

let profile = ApiComparisonProfile::new(
    vec![JsonPathPattern::new("/data")?],
    vec![JsonPathPattern::new("/data/request_id")?],
    vec![JsonPathPattern::new("/data/items")?],
    64,
)?;
let comparator = ApiVisibilityComparator::default();
let baseline = comparator.capture_profiled_view(
    &profile,
    "anonymous-view",
    "resource:account-42",
    ApiSurfaceKind::JsonHttp,
    200,
    &json!({"data":{"request_id":"a","items":[{"id":1}]}}),
)?;
let candidate = comparator.capture_profiled_view(
    &profile,
    "member-view",
    "resource:account-42",
    ApiSurfaceKind::JsonHttp,
    200,
    &json!({"data":{"request_id":"b","items":[{"id":1},{"id":2}]}}),
)?;
let report = comparator.compare_profiled(
    &profile,
    "comparison-18",
    ApiVisibilityPairKind::AuthorizationContext,
    ApiVisibilityDimension::Fields,
    &baseline,
    &candidate,
    1_800_000_000_000,
)?;

assert_eq!(report.projection_policy_id(), profile.projection_policy_id());
assert!(!report.diff().added_path_hashes().is_empty());
# Ok::<(), Box<dyn std::error::Error>>(())
```

Every captured snapshot is first checked against the complete legacy resource
envelope. Selected or ignored paths therefore cannot conceal excessive input.
The profiled pass builds domain-separated tree hashes and a compact index of
path digests, type masks, and scalar-value digests. It retains neither clear
observed paths nor scalar values. Added, removed, changed-type, and
changed-value paths share one deterministic `max_diff_paths` quota;
`omitted_diff_count` records the exact remainder.

Path digests are pseudonymous, not confidential. Common field names can be
guessed by dictionary attack. A host may hash a reviewed allowlist with
`PathDigest::for_pattern` to resolve selected explanations, but must not treat
the digest as encryption or log serialized profiles containing sensitive
selector names.

Comparison checks version, canonicalization, projection policy, limits,
contexts, resource scope, and surface before emitting a result. Its nested
comparison ID is also bound to the version and policy metadata. Deserialization
rejects an envelope whose nested identity does not match that metadata, so a
persisted report cannot silently downgrade to a differently projected replay.

```rust
use serde_json::json;
use termivar_core::{
    ApiSurfaceKind, ApiVisibilityDimension, ApiVisibilityPairKind,
    ConfidenceScore, EntityId,
};
use termivar_scanner::{
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

## Transport-free authorized runtime workflow

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

## Native broker-backed authorization-context workflow

`StandardWebDecisionRuntime::run_api_visibility_pair` collects one explicit
control/candidate pair before entering the same Comparator V3 and observation
path. This is a host-triggered, single-use side path, not a planner-selected
capability or `DecisionActionExecutor`. It preserves the runner's rule that
normal executor evidence belongs to the outstanding endpoint subject; paired
evidence continues to use its isolated `api-comparison:*` subject.

The request is deliberately narrow:

- both probes are bodyless `GET` requests for the exact runtime target;
- the target must use HTTPS, except for an exact HTTP loopback fixture;
- the pair is `AuthorizationContext` over the `JsonHttp` surface;
- the host declares a bounded set of allowed credential and supporting
  anti-CSRF header names;
- at least one primary credential header differs, while every non-context
  header is identical;
- the comparison dimension is explicitly `Fields`, `Resources`, or `Status`.

Control and candidate receive separate redirect-disabled and
implicit-retry-disabled connection pools. Both pools share the runtime's
immutable HTTP policy and broker accounting authority. Each leg is charged as
an active verification and consumes its own request lease. Delivered response
chunks remain charged on timeout, cancellation, truncation, or later failure.
No cookie or connection pool is reused from control to candidate.

Only two complete, non-truncated, JSON-compatible responses proceed. A `429`,
server error, malformed JSON document, policy denial, transport failure,
cancellation, or budget stop cannot produce a paired observation. The response
bodies exist only while each bounded document is parsed and reduced to a
profiled view. A successful report retains the raw-value-free V3 comparison,
an observation/reasoning receipt for the atomic evidence/relation commit and
subsequent rule application, and the exact resource review projection.

`ApiVisibilityDifferentialAudit` is available on every post-start report and
on post-transport execution errors. It captures monotonic runtime usage and a
receipt for each completed leg; request-template and retained-body digests are
pseudonymous replay metadata, not secret-safe commitments. An incomplete pair
has no comparison. If cancellation or a wall limit arrives after comparison,
the report can retain the comparison; if it arrives after ingestion, the
committed observation and review can also remain. A later reasoning or review
projection error exposes the comparison and available commit receipt rather
than claiming rollback.

The only positive review state is the canonical weak, supported boundary
hypothesis with `AwaitHumanReview`. That state is never a broken-access-control
finding, verifier success, planner outcome, Experience update, or endpoint
decision-loop command. See
[ADR 0013](../adr/0013-runtime-owned-api-visibility-pairs.md).

## Four-view resource authorization workflow

The non-default resource authorization review reuses the same value-sensitive,
raw-value-free `ApiVisibilityComparator` view reduction, but it is not another
`run_api_visibility_pair` facade. One optional native action inside
`WebAssessmentRuntime` captures four views for one operator-selected
exact-origin JSON resource: primary candidate, peer candidate, primary replay,
and peer replay. It computes primary stability, peer stability, and two
cross-principal comparisons over `Status`, `Fields`, and `Resources` without an
additional request or a second JSON canonicalizer.

The strict `security.authorization-review-policy/v1` profile requires bounded
exact JSON Pointer selections. Complete bodies exist only long enough to build
the four bounded view receipts. The retained contract excludes raw JSON,
canonical JSON bytes, scalar values, response bodies, credential material, raw
resource URLs, and clear selected paths. Four distinct response receipts, one
policy identity, one exact resource scope, complete path presence, and
correlation equality are mandatory.

`StableCrossPrincipalEquivalence` requires both roles to be independently
stable and both cross-principal rounds to be value-equivalent. Status or field
shape alone is insufficient. This state can project one
`NeedsReview` / `KnowledgeOnly` observation under the operator-declared
`primary-only` policy; it is not an IDOR, BOLA, broken-access-control, or data
exposure confirmation. Peer denial or non-equivalence creates no “secure”
finding. The transport-neutral API reasoner remains incapable of dispatching
these requests; the existing assessment executor owns them through the shared
broker.

REST read-only review reuses the same raw-value-free comparison foundation for
an exact replay, not for a cross-principal judgment. After same-run OpenAPI
candidate/replay stability, at most one anonymous, bodyless, exact-origin
zero-input `GET` is selected. Its candidate and replay must agree in `Status`,
`Fields`, and value-sensitive `Resources`. The comparison retains no scalar
values or response bodies and can produce only the informational
`api.rest-readonly-surface-observed@1` observation. It grants no execution
authority to other documented operations or vulnerability families.

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

`api_visibility_reviews_for_resource` preserves the original trusted-process
continuation API and returns a deterministic relation-ID-ordered page. Its
`ApiVisibilityReviewQuery` carries only a relation ID and therefore cannot
enforce resource binding. New integrations should use
`api_visibility_reviews_for_resource_v2`, pass its optional typed
`ApiVisibilityReviewCursor`, and derive the next token with
`ApiVisibilityReviewPage::next_cursor`. The v2 entry point validates the
cursor's resource digest before scanning. Both APIs use the same validated
scan limits: the default is 128 incoming relations and the compiled hard
ceiling is 1,024. Malformed, unrelated, or forged-looking relations are omitted
but still consume the scan budget. This keeps both cloning and inspection
bounded even when a resource has many rejected edges.

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
content fingerprints are redacted from the new API types' `Debug` output. The
v2 cursor contains a domain-separated SHA-256 resource digest plus the last
relation ID as lowercase hexadecimal bytes. The resource digest is
pseudonymous rather than confidential: dictionary attacks remain possible for
low-entropy identifiers. The cursor is deterministic and neither signed nor
authenticated. Hosts should avoid logging its serialized form, and an external
transport may wrap it in a signature or MAC before returning it to an
untrusted client.

The v2 cursor is bound to its resource but is not a frozen database snapshot.
Concurrent inserts sort by their stable relation IDs; a relation inserted at
or before an already consumed cursor may not appear in later pages. Hosts
needing a point-in-time export must provide an external snapshot or quiesce
writes.

Each review contains the comparison evidence and only a canonical-shaped
visibility-boundary hypothesis. The expected standard hypothesis ID,
predicate, pair, result, value, weak strength, supported state, and sole evidence
binding must all agree;
equivalent comparisons remain visible with an empty boundary list. These
checks do not attest which rule installation produced the hypothesis. Surface
and response-format hypotheses are intentionally excluded.

`ApiVisibilityReview::disposition()` keeps handling semantics explicit without
changing the serialized review record:

- `NoDifferenceObserved` means the canonical evidence was equivalent;
- `UnresolvedDifference` means a difference was stored but no exact canonical
  boundary hypothesis was available;
- `AwaitHumanReview` means the exact weak/supported boundary hypothesis is
  present and bound to that comparison evidence.

This is a review-read-model state, not a target-scoped decision-loop command and
not a vulnerability verdict. Golden fixtures under
`crates/termivar-scanner/tests/fixtures/api_authorization/` lock UI/API,
anonymous/authenticated, owner/unrelated-user, and read/write-capability
behavior through the full transport-neutral comparison and reasoning path.
Their expected projection-policy, comparison-subject, path, and serialized
envelope digests are literal fixture data rather than values regenerated by
the comparator under test. The three authorization-context fixtures also run
through the broker-backed native pair facade and must remain review-only with
no Experience or terminal hypothesis transition.

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
