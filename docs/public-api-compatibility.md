# Public API compatibility status

This page inventories the current public Rust surfaces and the evidence that
exists for them. Lifecycle labels describe executable truth at the current
revision; they are not promises of semantic-version stability.

## Evidence boundary

The workspace under `compat/current-head/` contains four independent,
`publish = false` consumers. They use path dependencies into the same checkout
and share a separate lockfile for third-party dependency resolution. Their
tests build public APIs without running a scan or making any network request.

This is **same-revision source-compatibility evidence only**. It does not:

- select or validate a v1 Scanner SDK/plugin baseline;
- compare the current API with an accepted previous Venom revision;
- promise a stable Rust ABI (Rust libraries do not expose such a promise here);
- test separately published crates from a registry;
- demonstrate an independent downstream integration or external adoption.

## Lifecycle inventory

| Public surface | Feature closure | Lifecycle | Current evidence and boundary |
|---|---|---|---|
| Default `termivar-core` evidence, reasoning, ontology, outcome, predicate, and typed `RunReport` contracts | `termivar-core` with no features | Stable candidate | The core consumer builds validated identity, confidence, unknown-outcome, and stop-reason values. “Stable candidate” is an inventory classification, not an accepted compatibility baseline. |
| Historical configuration, event, raw HTTP/result, and stringly finding records | `termivar-core/legacy-contracts` | Legacy | Quarantined behind a non-default feature and intentionally absent from the core consumer. New integrations should not adopt it. |
| Standard single-subject decision runtime and bounded exact-origin `WebAssessmentRuntime` | `termivar-scanner/scanning` | Preview | The deterministic consumer builds the opt-in `web-review` runtime from its checked profile but never calls `analyze`; therefore the fixture sends no request. |
| `venom.scan-profile/v1`, `AssessmentItem`, and runtime-owned `AssessmentRunReport` projection | `termivar-scanner/scanning` plus `reporting` for the completed report | Preview | The consumer checks the versioned profile/capability surface and compiles a renderer function that accepts only an already completed typed assessment report. It cannot manufacture runtime completion truth. |
| Bounded JSON, CSV, HTML, and Markdown report renderers | `termivar-scanner/reporting` | Preview | The deterministic consumer compiles `ReportGenerator::generate_assessment` and verifies format negotiation. Rendering does not author findings or upgrade dispositions. |
| `ScannerSdk`, `ScannerBuilder`, `ScanPhase`, and the ordered legacy runner | `termivar-scanner/legacy-scanner` | Legacy facade | A dedicated consumer proves only that an empty historical scanner can be built through the public facade at the same revision. The feature still admits historical phase contracts and raw compatibility-client authority; it is not the default deterministic product or a stable SDK baseline. |
| Native plugin API `0.2` (`Plugin`, registry, limits, host context, broker, and observation recorder) | `termivar-scanner/plugins` | Preview | The plugin consumer registers an API-0.2 implementation without executing it. Its `execute` signature can stage a `PluginObservation`; it cannot return a finding, severity, verifier outcome, or confirmation. Native plugins are trusted in-process code, not a sandbox. |
| Lua host surface | `termivar-scanner/lua` | Experimental | Bounded, process-local and explicitly enabled. It is not composed into the default scan and is outside the current-head consumer set. |
| Process-local distributed coordinator | `termivar-scanner/distributed` | Experimental | No durable transport, persistence, or real distributed control plane is claimed. It is outside the current-head consumer set. |
| Platform/service models, detection/ML records, monitoring, compliance, and threat-intelligence catalogs | Their explicit non-default features | Experimental or legacy compatibility surface | These opt-in library records do not make an API listener, dashboard, durable service, feed runtime, or production detector part of the default product. They are outside the current-head consumer set. |

`ScannerSdk` therefore remains a **Legacy facade**, while the deterministic
runtime, typed assessment/report contracts, and plugin API 0.2 remain
**Preview**. No surface in this inventory is declared v1-stable.

## Reproducing the compile evidence

Run these commands from `compat/current-head/`:

```text
cargo test --locked -p termivar-current-head-core-consumer
cargo test --locked -p termivar-current-head-deterministic-assessment-consumer
cargo test --locked -p termivar-current-head-scanner-sdk-consumer
cargo test --locked -p termivar-current-head-plugin-api-0-2-consumer
```

Each command isolates one declared feature closure. The nested `Cargo.lock`
must be updated deliberately when the current checkout changes its dependency
resolution. A later compatibility baseline must add an accepted prior-version
fixture and explicit deprecation policy before it can support a cross-version
claim.
