# Resource authorization differential review

Authorization Differential Foundation V1 is a transport-neutral contract for
comparing one operator-selected JSON resource across two distinct authenticated
principal contexts and independent replays. It is intentionally narrower than
an IDOR or BOLA scanner: the operator supplies the resource and declares the
expected relation, while the foundation only validates policy and classifies
already captured response views.

The policy, principal, response-reduction, and comparison foundation remains
transport-neutral. The non-default `authorization-review` integration uses it
as exactly one optional native capability inside the existing
`WebAssessmentRuntime`; it is not an independently operating authorization
scanner. The integration performs only the bounded network work described
below and projects through the assessment's existing evidence, completeness,
and report lifecycle.

## Build and explicit opt-in

The scanner and CLI must be compiled with `authorization-review`. The operator
must then select explicit `web-review`, one policy file, and exactly one source
for each principal:

```text
venom scan https://authorized.example.test \
  --profile web-review \
  --authorization-review-policy ./review.toml \
  --authz-primary-env PRIMARY_AUTH_CONTEXT \
  --authz-peer-env PEER_AUTH_CONTEXT
```

Each environment/file/stdin value is a complete `Authorization` header value;
the CLI does not assume `Bearer`. The existing bounded secret-input module is
the sole loader. There is no raw credential-value argument. File inputs must be
regular non-symlink files, and at most one of the two roles may use stdin. V1
rejects combining this workflow with the existing exact-root
`--auth-env`/`--auth-file`/`--auth-stdin` comparison so principal roles and
accounting cannot become ambiguous. The policy path, secret-source names, and
credential values are redacted from diagnostics.

The option is rejected for `baseline` and with no explicit profile. Compiling
the feature alone adds no action or request, and the default CLI help,
`venom scan`, and `decision-scan/v1` remain unchanged.

## Policy contract

The strict schema is `security.authorization-review-policy/v1`. V1 accepts one
bodyless `GET` resource and one executable expectation, `primary-only`:

```toml
schema = "security.authorization-review-policy/v1"
resource = "/api/accounts/42"
resource_handle = "account-self-profile"
expectation = "primary-only"
method = "GET"

[comparison]
selected_paths = ["/data/account"]
ignored_paths = ["/data/account/updated_at"]
unordered_array_paths = ["/data/account/roles"]
max_diff_paths = 32
```

`primary-only` is an operator assertion: the primary principal is expected to
receive the selected resource representation and the peer principal is not.
The assertion grants neither network authority nor confidence that the stated
business policy is correct.

The resource can be an absolute URL under the assessment's exact origin or a
relative reference resolved against that origin. The existing HTTP evidence
policy performs canonicalization and exact-origin enforcement. Cross-origin,
scheme-, host-, or effective-port changes, user information, fragments,
credential-bearing URLs, empty resources, ambiguous references, and oversized
URLs fail closed. Query values can be policy input. Their canonical resource
digest is identity material, but their clear text never enters reports,
evidence values, logs, diagnostics, or item identity.

The resource handle is a bounded, non-secret opaque token. It helps bind the
policy to the intended logical selection but does not identify a principal and
does not authorize access.

The comparison profile reuses `ApiComparisonProfile` and exact RFC 6901 JSON
Pointers under a stricter authorization-review wrapper:

| Dimension | V1 ceiling |
| --- | ---: |
| Policy source | 64 KiB |
| Selected paths | 8 |
| Ignored paths | 16 |
| Unordered-array paths | 8 |
| One path | 256 UTF-8 bytes |
| Retained diff paths | 32 |

At least one non-root selected path is required. Wildcards and duplicate paths
are rejected. An ignored path must be a strict descendant of a selected
subtree, and an unordered-array path must lie within a selected subtree. A
selected path hidden by an ignored ancestor, a zero diff limit, or a profile
that ignores the entire selection is invalid. Every selected path must resolve
in every comparable view, and at least one selected subtree must contain a
material non-null value before a positive outcome is possible.

## Semantic identity and redaction

The comparison algorithm is
`security.authorization-differential/v1`. A deterministic, domain-separated
policy identity binds the schema and algorithm revisions, canonical resource
scope, resource-handle digest, expectation, method, normalized comparison
profile, and limits. Ordering that is semantically irrelevant does not change
the identity; changing the resource or comparison policy does.

Credential bytes, credential digests, credential-source names, filesystem
paths, timestamps, machine details, branches, and random identifiers do not
enter policy identity. Resource and path digests are pseudonymous rather than
confidential: low-entropy inputs may be guessed, so serialized identities must
not be treated as encryption or secret storage.

The validated policy's `Debug` output redacts the resource and clear resource
handle. Static errors do not echo URLs, query values, handles, JSON values, or
credentials.

## Primary and peer principal roles

The foundation defines exactly two role-bound, move-only credentials:

- `PrimaryAuthorizationPrincipal`
- `PeerAuthorizationPrincipal`

Each value is one complete bounded `Authorization` header value. Validation
rejects empty or oversized values, non-ASCII/control bytes, NUL, CR/LF, and
leading or trailing whitespace. The types are not cloneable or serializable,
have fully redacted `Debug` output, and do not expose a public credential
getter.

`AuthorizationPrincipalPair` requires one value for each role and rejects
identical credential bytes before any I/O. It produces a value-free proof that
the two contexts were distinct. Principal identity is never derived from a
credential, and neither role implies attacker, victim, administrator,
privilege, tenant, or ownership semantics.

## Four-view comparison

The pure comparator consumes four independently correlated views:

```text
PrimaryCandidate ----+----> primary stability ----+
PrimaryReplay -------+                           |
                                                  +--> typed outcome
PeerCandidate -------+----> peer stability -------+
PeerReplay ----------+

PrimaryCandidate <--------> PeerCandidate  (cross-principal round one)
PrimaryReplay    <--------> PeerReplay     (cross-principal replay)
```

Every view binds its fixed role, policy identity, resource-scope identity,
optional exact status, normalized media class, typed completion state,
selected-path presence, and a unique response-receipt identity. Pre-response
cancellation and budget exhaustion carry no fabricated HTTP status. Complete
JSON is immediately reduced through the
existing value-sensitive `ApiVisibilityComparator`; the view retains bounded
fingerprints and typed metadata, not raw JSON, canonical JSON bytes, scalar
values, credentials, response bodies, raw resource URLs, or selected-path
values.

Each of the following pairs is compared in all three existing dimensions:

| Relationship | Status | Fields | Resources |
| --- | :---: | :---: | :---: |
| Primary candidate vs primary replay | required | required | required |
| Peer candidate vs peer replay | required | required | required |
| Primary vs peer, first round | required | required | required |
| Primary vs peer, replay round | required | required | required |

`Resources` is the existing value-sensitive, raw-value-free canonical resource
fingerprint. Status equality or field-shape equality alone is insufficient.
Four distinct receipt identities, one policy, one resource scope, and all four
exact roles must reconcile; a correlation mismatch is an internal contract
error rather than a target outcome. The result binds the algorithm revision,
policy identity, resource-scope identity, and an ordered digest of all four
scanner-owned receipt identities.

## Positive and fail-closed outcomes

`StableCrossPrincipalEquivalence` requires four complete, non-truncated,
JSON-compatible views. Both primary responses and both peer responses must have
stable successful `2xx` statuses; every selected path must resolve; primary and
peer views must each replay equivalently across `Status`, `Fields`, and
`Resources`; and both cross-principal rounds must also be equivalent across all
three dimensions.

That outcome means only that the selected representations repeatedly matched
under the operator's declared policy. It does not validate the declaration,
prove exploitability, establish business impact, or confirm IDOR, BOLA, broken
access control, or sensitive-data exposure.

The typed outcome model keeps non-positive states explicit, including invalid
or unstable primary baselines, peer denial, peer instability, cross-status or
resource differences, fields-only equivalence, missing selected paths,
unsupported media, malformed JSON, a successful generic JSON error-only
envelope, redirect, challenge/defense interference,
rate limiting, truncation, incomplete transport, budget exhaustion, and
cancellation. None is converted into a "secure" conclusion: absence of stable
equivalence is not proof that authorization is correct.

## Corpus and compatibility boundary

The authorization subset of the sanitized scanner conformance corpus exercises
stable equivalence, unstable replays, common peer-denial statuses, fields-only
matches, value-sensitive differences, missing/null selections, ignored
volatile fields, ordered and explicitly unordered arrays, generic JSON
error-only envelopes, malformed or truncated JSON, HTML challenge material,
and rate limiting. Corpus execution
calls the production policy and comparison components without issuing a
request. Synthetic cases are conformance evidence, not labelled real-world
vulnerabilities or empirical accuracy data.

The existing root anonymous/authorized visibility comparison remains a
separate compatibility surface. Its public types, CLI inputs, two-request
accounting, evidence identity, comparison semantics, item capability, and
report shape do not change. Shared pure validation or comparison internals may
be reused, but the foundation does not create a second canonicalization or JSON
comparison implementation.

## Native runtime composition

The feature registers one optional native action,
`web.review.authorization.resource-differential`. It reuses the parent
assessment's `SharedWebRuntimeAuthority`, exact-origin policy, request broker,
`RuntimeBudget`, response-byte accounting, cancellation token, deadline,
executor/action catalog, defense validation, evidence registry, completeness
lifecycle, stable identities, and final `AssessmentReport`. It does not create
an independent authorization runtime, client, broker, budget, evidence store,
URL normalizer, detached post-scan pass, or separately finalized report.

The action selects one resource at most and executes one bodyless `GET`
template in this exact order:

1. `PrimaryCandidate`
2. `PeerCandidate`
3. `PrimaryReplay`
4. `PeerReplay`

The two candidate legs are collected by the action's passive stage. The single
logical active-verification lease is charged when `PrimaryReplay` begins;
`PeerReplay` remains part of the same active decision phase but is
passive-accounted, so the four-view review cannot charge the logical active
verification twice. This is not a second action or a detached child runner.

Each leg carries only fixed `Accept: application/json` plus the exact role's
`Authorization` header. Candidate and replay use distinct scanner-owned
correlation identities without changing the resource. Redirects and implicit
retries remain disabled; there is no cookie jar, request body, method override,
custom header mutation, or query mutation. Primary and peer connection state
is isolated through the broker's governed isolation mechanism while accounting
remains shared. The full child is capped at one selected resource, four request
leases, and one logical active verification. An exhausted per-leg lease keeps
already charged evidence but makes the review incomplete and prevents a
positive item. This capability-specific four-leg plan does not widen the
authority-wide `RuntimeBudget` same-action-attempt default of three for
unrelated actions.

Only complete JSON-compatible responses are reduced to the raw-value-free
views. Redirects, rate limiting, challenge/defense interference, server errors,
malformed JSON, unsupported media, truncation, cancellation, or transport and
budget incompleteness cannot produce a positive projection. Normalization
resilience is never applied to credentials or authorization headers.

## Projection and audit

`StableCrossPrincipalEquivalence` may project at most one
`authorization.resource-cross-principal-equivalence@1` item titled
“Unexpected cross-principal resource equivalence observed.” The disposition is
`NeedsReview` and its authority is `KnowledgeOnly`; no path can produce
`Confirmed`. Stable item identity binds the stable assessment/resource scope,
exact-origin identity, policy semantic identity, capability and algorithm
revision. It excludes credentials and their digests/sources, raw URLs and
query values, JSON values and bodies, operation order, timestamps, and random
identifiers.

The composed assessment may include one redaction-safe authorization audit:
policy identity, bounded profile counts, request count, outcome class,
primary/peer stability, cross-resource equivalence, and projection state. It
contains no credential material,
source/path name, raw resource URL or handle, JSON Pointer text, selected
scalar, body, or raw error. Shared evidence identifiers are registered once.
Missing action, executor, defense, ledger, projection, or accounting parity
fails closed as incomplete execution.

The review does not guess or mutate identifiers, enumerate resources, change
methods, test writes, carry cookies, follow redirects, evade defensive
controls, or invoke exploit orchestration. Absence of equivalence is not proof
that authorization is secure, and stable equivalence does not validate the
operator's policy assertion or establish exploitability or business impact.
