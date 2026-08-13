# Scanner SDK

`ScannerSdk` is the opt-in historical composition surface for applications that
build scanners with Venom. Hosts supply `ScanPhase` implementations; Venom owns
ordering, per-phase timeouts, cancellation context, lifecycle events, and the
typed run-report boundary.

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
assert_eq!(report.outcomes().len(), 1);
assert_eq!(report.outcomes()[0].confidence().parts_per_million(), 0);
# Ok(())
# }
```

## Boundary

- A phase owns historical heuristic behavior and returns compatibility records.
- The SDK owns execution policy and shared runtime context.
- The public SDK result is `venom_core::RunReport`; phase errors, timeouts,
  cancellation, and panics while polling phase execution remain visible as
  typed step state.
- Raw phase descriptions/evidence and telemetry do not cross the public report
  boundary. Compatibility records become informational `Unknown` observations
  with zero confidence and no fabricated evidence IDs. Only the built-in,
  allowlisted SQL-behavior, template-arithmetic, and local-file-canary paths can
  instead publish verifier-owned, knowledge-only `NeedsReview` outcomes.
- Whole-run request/byte dimensions are explicitly `Unmetered` because custom
  phases and built-in phase one can retain raw transport authority. The bounded
  phase-two-to-four discovery and phase-five-to-nine active-verification slices
  are not complete-run accounting; only elapsed wall time is observed at the
  report boundary.
- A host may provide an event bus, finite `DiscoveryLimits` and
  `VerificationLimits` envelopes, and a configured raw HTTP client through the
  builder. The raw client is used only by phase one and custom phases;
  built-in phases two through four use an isolated passive broker, and built-in
  phases five through nine use a distinct `Active`-stage broker.
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

The ordered runtime boundaries are recorded in
[ADR 0016](adr/0016-bound-legacy-discovery-authority.md) and
[ADR 0018](adr/0018-bound-legacy-verification-authority.md).
