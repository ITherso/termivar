//! Same-revision consumer of the opt-in historical `ScannerSdk` facade.

#![forbid(unsafe_code)]

use std::time::Duration;

use venom_scanner::{ScannerBuilder, ScannerSdk};

/// Builds an empty historical scanner facade without executing a scan.
///
/// The `legacy-scanner` feature is intentional: this fixture records that the
/// facade still compiles at current head, not that it is a stable SDK baseline.
pub fn build_historical_sdk() -> ScannerSdk {
    ScannerBuilder::new()
        .phase_timeout(Duration::from_secs(2))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_scanner_sdk_facade_compiles_without_scanning() {
        let scanner = build_historical_sdk();
        let _event_bus = scanner.event_bus();
    }
}
