# Scanner conformance corpus

The scanner conformance corpus is repository-only test data. It contains a
bounded set of 30–50 sanitized request/response cases for deterministic checks
of current scanner semantics and explicitly identified future protocol cases.
It is not loaded by `venom scan` and grants no network, execution, or claim
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

## What passing means

Passing proves that the checked-in bounded cases agree with the current typed
contracts. It does not establish real-world precision, recall, protocol
coverage, vulnerability prevalence, or scanner accuracy. Those measurements
require independently labelled, representative data and a separate evaluation
methodology.

Future capabilities should add a small balanced set of positive, negative,
ambiguous, incomplete, and regression cases. Adding corpus breadth must not add
runtime actions, requests, executors, report claims, or default features.
