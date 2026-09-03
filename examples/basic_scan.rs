//! Build a scanner from an application-defined phase.
//!
//! Run with:
//! `cargo run -p termivar-examples --bin basic_scan`

use async_trait::async_trait;
use termivar_scanner::{Result, ScanContext, ScanFinding, ScanPhase, ScannerSdk};

struct InventoryPhase;

#[async_trait]
impl ScanPhase for InventoryPhase {
    fn phase_number(&self) -> u8 {
        10
    }

    fn name(&self) -> &'static str {
        "inventory"
    }

    async fn execute(&self, context: &ScanContext) -> Result<Vec<ScanFinding>> {
        Ok(vec![ScanFinding {
            phase: self.phase_number(),
            module_name: self.name().into(),
            severity: "INFO".into(),
            description: "Authorized target accepted by the Scanner SDK".into(),
            evidence: context.target.to_string(),
        }])
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // This documentation target is intentionally non-routable. Replace it only
    // with a system you own or have explicit permission to test.
    let scanner = ScannerSdk::builder().phase(InventoryPhase).build();
    let report = scanner.scan("https://example.test").await?;

    println!("target: {}", report.target());
    println!("status: {:?}", report.status());
    for observation in report.outcomes() {
        println!(
            "id={} action={} disposition={:?}",
            observation.fingerprint(),
            observation.action_id(),
            observation.disposition(),
        );
    }

    Ok(())
}
