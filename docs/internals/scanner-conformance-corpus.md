# Scanner conformance corpus

The scanner conformance corpus is repository-only test data. It contains 103
sanitized request/response cases for deterministic checks of current scanner
semantics and explicitly identified future protocol cases. Twenty-three cases
exercise the transport-neutral four-view authorization differential contract.
It is not loaded by `termivar scan` and grants no network, execution, or claim
authority.

## Case contract

Each case uses the strict internal schema
`security-assessment-fixture/v1`. A case has a stable identity and revision,
sanitized request/response metadata, one or more typed expectations, and a
provenance label. Expectations may describe a positive, negative, ambiguous,
incomplete, or metadata-only relationship; an omitted expectation is never
inferred.

Fixture bodies live outside production source. Cases use reserved example or
loopback identities and scanner-owned inert canaries. They must not contain
real targets, credentials, customer evidence, executable payloads, fabricated
findings, or synthetic severity claims. Historical inputs are re-authored and
sanitized rather than copied as product evidence.

## Validation

Run the repository validator with:

```bash
cargo run --locked -p xtask -- scanner-corpus
```

The validator performs bounded strict parsing, path and symlink checks,
reserved-identity and secret-pattern checks, reference validation, and
deterministic corpus-digest and inventory verification. It reads only the
repository corpus, performs no network I/O, executes no payload, and does not
dispatch a scanner request.

Where a case targets an implemented semantic contract, the conformance harness
reuses the corresponding production parser, observer, classifier, or reasoner.
Metadata-only cases validate their fixture contract without pretending that a
runtime capability exists. Unsupported, incomplete, and mismatched cases stay
explicit; they are not silently treated as passes.

## GraphQL V1 cases

The GraphQL subset exercises the production bounded classifier for a control
envelope, available and restricted root introspection, malformed JSON, partial
data with errors, and parser-limit incompleteness. Existing generic-JSON and
GraphQL-like-HTML cases remain current negative controls: neither can establish
a GraphQL surface. Batch-shaped responses and GET-query support remain
metadata-only because GraphQL V1 executes only the fixed anonymous POST/JSON
control, candidate, and replay protocol.

These cases do not send requests from the corpus harness. They validate the
same production operation and response contracts used by the explicitly
enabled runtime. See [GraphQL surface review](graphql-review.md).

## OpenAPI contract catalog cases

The OpenAPI subset exercises the transport-neutral JSON parser and deterministic
catalog for OpenAPI 3.0 and 3.1 documents. It covers supported operation
metadata, source-order independence, malformed and unsupported inputs, and the
compiled document, structure, and catalog limits. Input is capped at 2 MiB;
depth, nodes, aggregate object members, arrays, strings, paths, and operations
are bounded as documented in the
[OpenAPI contract catalog](openapi-contract-catalog.md).

Cases supply sanitized bytes directly. The harness does not discover or fetch a
contract, resolve an external reference, contact a declared server, construct
or dispatch a request, use credentials, execute a payload, or emit evidence,
reports, findings, or claims. YAML remains a future unsupported input, while
Swagger/OpenAPI 2.0 is metadata-only and cannot produce an operation catalog.

## Authorization differential cases

The authorization subset supplies four safe synthetic response views—primary
candidate, peer candidate, primary replay, and peer replay—to the production
authorization policy and comparator. It covers stable equivalence, independent
principal instability, 401/403/404 peer outcomes, status- and fields-only
matches, value-sensitive differences, missing or null selections, ignored
volatile fields, ordered and explicitly unordered arrays, malformed or
truncated JSON, redirect, HTML challenge, and rate limiting.

These cases contain no real credentials or target data and dispatch no
requests. Stable equivalence is conformance evidence for the pure comparator,
not a labelled vulnerability or proof that an operator-declared policy is
correct. The same pure contract is used by the explicitly enabled resource
authorization runtime; corpus cases themselves still issue no requests. See
[Authorization differential review](authorization-differential-review.md).

## What passing means

Passing proves that the checked-in bounded cases agree with the current typed
contracts. It does not establish real-world precision, recall, protocol
coverage, vulnerability prevalence, or scanner accuracy. Those measurements
require independently labelled, representative data and a separate evaluation
methodology.

Future capabilities should add a small balanced set of positive, negative,
ambiguous, incomplete, and regression cases. Adding corpus breadth must not add
runtime actions, requests, executors, report claims, or default features.
