# Current-head downstream compile fixtures

This nested, separately locked workspace checks whether four representative
downstream crates compile against the Termivar sources in the same checkout:

- the default, transport-neutral `termivar-core` surface;
- deterministic assessment and typed reporting;
- the historical `ScannerSdk` facade behind `legacy-scanner`;
- the evidence-only native plugin API 0.2 line.

Each package is `publish = false`, forbids unsafe code, and binds its Termivar
dependencies to this checkout with `path` dependencies. The fixture tests do
not execute a scan or make a network request.

Run each feature closure independently from this directory:

```text
cargo test --locked -p termivar-current-head-core-consumer
cargo test --locked -p termivar-current-head-deterministic-assessment-consumer
cargo test --locked -p termivar-current-head-scanner-sdk-consumer
cargo test --locked -p termivar-current-head-plugin-api-0-2-consumer
```

These checks are same-revision source-compatibility evidence only. They do not
select a v1 baseline, compare two Termivar releases, promise a stable Rust ABI,
prove external adoption, or validate a separately published crate artifact.
