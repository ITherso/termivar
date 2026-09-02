# Web-assessment conformance corpus V1

This directory contains sanitized, repository-owned request and response
fixtures. Each case uses `security-assessment-fixture/v1` and has at least one
typed expected outcome.

The corpus is inert test data. It grants no network or scanner authority,
contains no client evidence, and makes no vulnerability or accuracy claim.
Historical-sanitized cases were re-authored from useful fixture concepts; no
historical finding, severity, identity, or raw target data was copied.

The 73-case V1 inventory includes 23 four-view authorization differential
cases. Those cases exercise the pure policy/comparison foundation with safe
reserved identities and synthetic JSON only; they perform no requests and do
not label an equivalence fixture as a proven authorization vulnerability.

Validate the corpus and its generated inventory with:

```text
cargo run --locked -p xtask -- scanner-corpus
```

Only explicit generation mode may update the stored semantic digest and
`INVENTORY.md`.
