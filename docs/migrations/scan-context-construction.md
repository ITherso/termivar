# ScanContext construction migration

This guide applies when moving from the tagged `v0.9.0-alpha` scanner contract
to the next Preview release. The destination version has not been released or
baselined yet.

## Replace struct literals

`ScanContext` is now runtime-owned and non-exhaustive. Replace a complete struct
literal with the narrowest named constructor that supplies the policy you need:

```rust
use reqwest::Client;
use url::Url;
use venom_scanner::ScanContext;

let (telemetry_tx, _telemetry_rx) = tokio::sync::mpsc::unbounded_channel();
let context = ScanContext::new(
    Url::parse("https://example.test").expect("valid target URL"),
    Client::new(),
    telemetry_tx,
);
```

Use `with_timeout`, `with_cancellation`, or `with_event_bus` only when the host
owns that policy. `ScannerSdk` remains the preferred application composition
surface and constructs the context for its host.

## Borrow reasoning state

The tagged `v0.9.0-alpha` contract did not contain a knowledge field. Consumers
that followed unreleased `main` while reasoning support was introduced must
replace field access:

```rust
let stats = context.knowledge().stats();
assert_eq!(stats.evidence, 0);
```

`knowledge()` returns the context-owned `KnowledgeBase` by shared reference.
Its synchronized insert and query operations do not require replacing the base
or obtaining `&mut KnowledgeBase`.

## Release boundary

This is an intentional incompatible pre-1.0 transition. Release notes must
list it under Upgrade notes, select a new alpha minor line, and link this guide.
Only after that release is tagged may its peeled commit become the blocking
`venom-scanner` compatibility baseline.
