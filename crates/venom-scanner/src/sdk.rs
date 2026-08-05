//! Public composition API for building scanners from Venom phases.
//!
//! ## Runtime scope
//!
//! - **Build:** default via `scanning`.
//! - **Execution:** host/library only (public composition API for host-built
//!   scanners; not invoked by `venom scan`).
//! - **Default `venom scan`:** no.
//! - **Support:** implemented and tested (Scanner SDK Template).
//!
//! See `docs/internals/runtime-map.md`.

use crate::{EventBus, Result, ScanContext, ScanFinding, ScanPhase, ScanRunner};
use reqwest::Client;
use std::{sync::Arc, time::Duration};
use url::Url;

/// Result returned by a scanner assembled with [`ScannerSdk`].
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ScanReport {
    /// Authorized target supplied to [`ScannerSdk::scan`].
    pub target: String,
    /// Findings aggregated in phase order.
    pub findings: Vec<ScanFinding>,
    /// Human-readable telemetry emitted during the scan.
    pub telemetry: Vec<String>,
}

/// Reusable scanner assembled from application-defined [`ScanPhase`] values.
///
/// The SDK owns composition and execution policy while phases own detection
/// behavior. Hosts do not need to construct [`ScanContext`] or [`ScanRunner`]
/// directly.
pub struct ScannerSdk {
    runner: ScanRunner,
    client: Client,
    phase_timeout_secs: u64,
    event_bus: Arc<EventBus>,
}

impl ScannerSdk {
    /// Starts a custom scanner builder.
    pub fn builder() -> ScannerBuilder {
        ScannerBuilder::new()
    }

    /// Executes the configured phases against an authorized target.
    pub async fn scan(&self, target: &str) -> Result<ScanReport> {
        let target_url = Url::parse(target)?;
        let (telemetry_tx, mut telemetry_rx) = tokio::sync::mpsc::unbounded_channel();
        let context = ScanContext::with_event_bus(
            target_url,
            self.client.clone(),
            telemetry_tx,
            self.phase_timeout_secs,
            tokio_util::sync::CancellationToken::new(),
            self.event_bus.clone(),
        );

        let findings = self.runner.run_pipeline(context).await;
        let mut telemetry = Vec::new();
        while let Ok(message) = telemetry_rx.try_recv() {
            telemetry.push(message);
        }

        Ok(ScanReport {
            target: target.to_string(),
            findings,
            telemetry,
        })
    }

    /// Returns the event bus used by this scanner for host subscriptions.
    pub fn event_bus(&self) -> Arc<EventBus> {
        self.event_bus.clone()
    }
}

/// Builder for a custom [`ScannerSdk`].
pub struct ScannerBuilder {
    phases: Vec<Box<dyn ScanPhase>>,
    client: Client,
    phase_timeout_secs: u64,
    event_bus: Arc<EventBus>,
}

impl ScannerBuilder {
    /// Creates a builder with a five-minute phase timeout.
    pub fn new() -> Self {
        Self {
            phases: Vec::new(),
            client: Client::new(),
            phase_timeout_secs: 300,
            event_bus: Arc::new(EventBus::new()),
        }
    }

    /// Adds a phase. Execution order is determined by `phase_number()`.
    pub fn phase<P>(mut self, phase: P) -> Self
    where
        P: ScanPhase + 'static,
    {
        self.phases.push(Box::new(phase));
        self
    }

    /// Adds a boxed phase selected dynamically by the host.
    pub fn boxed_phase(mut self, phase: Box<dyn ScanPhase>) -> Self {
        self.phases.push(phase);
        self
    }

    /// Replaces the HTTP client shared by all phases.
    pub fn client(mut self, client: Client) -> Self {
        self.client = client;
        self
    }

    /// Sets a minimum one-second timeout for each phase.
    pub fn phase_timeout(mut self, timeout: Duration) -> Self {
        self.phase_timeout_secs = timeout.as_secs().max(1);
        self
    }

    /// Replaces the event bus used for lifecycle publication.
    pub fn event_bus(mut self, event_bus: Arc<EventBus>) -> Self {
        self.event_bus = event_bus;
        self
    }

    /// Builds a reusable scanner.
    pub fn build(self) -> ScannerSdk {
        let mut runner = ScanRunner::new();
        for phase in self.phases {
            runner.register_phase(phase);
        }

        ScannerSdk {
            runner,
            client: self.client,
            phase_timeout_secs: self.phase_timeout_secs,
            event_bus: self.event_bus,
        }
    }
}

impl Default for ScannerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ExamplePhase;

    #[async_trait::async_trait]
    impl ScanPhase for ExamplePhase {
        fn phase_number(&self) -> u8 {
            42
        }

        fn name(&self) -> &'static str {
            "example"
        }

        async fn execute(&self, context: &ScanContext) -> Result<Vec<ScanFinding>> {
            Ok(vec![ScanFinding {
                phase: self.phase_number(),
                module_name: self.name().to_string(),
                severity: "INFO".to_string(),
                description: "SDK phase executed".to_string(),
                evidence: context.target.to_string(),
            }])
        }
    }

    #[tokio::test]
    async fn custom_scanner_executes_registered_phase() {
        let scanner = ScannerSdk::builder().phase(ExamplePhase).build();
        let report = scanner.scan("https://example.test").await.unwrap();

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].phase, 42);
        assert!(!report.telemetry.is_empty());
    }
}
