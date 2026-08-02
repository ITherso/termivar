# Scanner SDK

`ScannerSdk` is the composition surface for applications that build scanners with Venom. Hosts supply `ScanPhase` implementations; Venom owns ordering, per-phase timeouts, cancellation context, lifecycle events, telemetry, and finding aggregation.

## Generate a scanner

```bash
cargo install cargo-generate
cargo xtask generate scanner my-scanner
cd my-scanner
cargo test
```

The generated project contains a complete custom phase and an executable scanner. During alpha it tracks Venom `main`; pin a release tag or commit before distribution.

## Compose directly

```rust
use async_trait::async_trait;
use venom_scanner::{Result, ScanContext, ScanFinding, ScanPhase, ScannerSdk};

struct Headers;

#[async_trait]
impl ScanPhase for Headers {
    fn phase_number(&self) -> u8 { 10 }
    fn name(&self) -> &'static str { "headers" }

    async fn execute(&self, context: &ScanContext) -> Result<Vec<ScanFinding>> {
        Ok(vec![ScanFinding {
            phase: self.phase_number(),
            module_name: self.name().into(),
            severity: "INFO".into(),
            description: "Custom phase executed".into(),
            evidence: context.target.to_string(),
        }])
    }
}

# async fn example() -> Result<()> {
let scanner = ScannerSdk::builder().phase(Headers).build();
let report = scanner.scan("https://example.test").await?;
assert_eq!(report.findings.len(), 1);
# Ok(())
# }
```

## Boundary

- A phase owns detection behavior and returns structured findings.
- The SDK owns execution policy and shared runtime context.
- A host may provide a configured HTTP client and event bus through the builder.
- Product policy, UI, report rendering, and transports remain outside phase implementations.

`ScanContext` is non-exhaustive and runtime-constructed. Extensions borrow it,
use its methods and documented public handles, and must not depend on struct
literals. Access reasoning state through `ScanContext::knowledge()`. Consumers
moving from the tagged v0.9 contract or from unreleased `main` should follow the
[ScanContext construction migration](migrations/scan-context-construction.md).

This is a Preview source-level SDK. The plugin registration contract follows
the [Plugin API and SemVer policy](plugin-api-policy.md); broader scanner source
compatibility remains governed by the release notes, accepted ADRs, and the
explicit baseline status in [Repository health](repository-health.md).
