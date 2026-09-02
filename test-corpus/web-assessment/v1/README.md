# Web-assessment conformance corpus V1

This directory contains sanitized, repository-owned request and response
fixtures. Each case uses `security-assessment-fixture/v1` and has at least one
typed expected outcome.

The corpus is inert test data. It grants no network or scanner authority,
contains no client evidence, and makes no vulnerability or accuracy claim.
Historical-sanitized cases were re-authored from useful fixture concepts; no
historical finding, severity, identity, or raw target data was copied.

The 103-case V1 inventory includes 23 four-view authorization differential
cases and 30 OpenAPI contract-catalog cases. The OpenAPI matrix exercises the
bounded production JSON parser, stable reduction, catalog metadata, semantic
digest, and generated size/path ceilings. Corpus cases perform no requests and
do not turn protocol metadata or response equivalence into vulnerability
claims.

Validate the corpus and its generated inventory with:

```text
cargo run --locked -p xtask -- scanner-corpus
```

Only explicit generation mode may update the stored semantic digest and
`INVENTORY.md`.
