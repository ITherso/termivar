//! Public composition API for the opt-in historical scanner SDK.
//!
//! The SDK returns the shared typed [`RunReport`]
//! contract. Raw phase telemetry and `ScanFinding` strings do not cross this
//! host boundary.

use std::{sync::Arc, time::Duration};

use reqwest::Client;
use tokio_util::sync::CancellationToken;
use url::Url;
use venom_core::RunReport;

use crate::{EventBus, Result, ScanContext, ScanPhase, ScanRunner};

/// Reusable scanner assembled from application-defined [`ScanPhase`] values.
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

    /// Executes configured phases against an authorized target.
    pub async fn scan(&self, target: &str) -> Result<RunReport> {
        self.scan_with_cancellation(target, CancellationToken::new())
            .await
    }

    /// Executes configured phases with a host-owned cancellation token.
    pub async fn scan_with_cancellation(
        &self,
        target: &str,
        cancellation: CancellationToken,
    ) -> Result<RunReport> {
        let target_url = Url::parse(target)?;
        let (telemetry, receiver) = tokio::sync::mpsc::unbounded_channel();
        drop(receiver);
        let context = ScanContext::with_event_bus(
            target_url,
            self.client.clone(),
            telemetry,
            self.phase_timeout_secs,
            cancellation,
            Arc::clone(&self.event_bus),
        );
        Ok(self.runner.run_pipeline(context).await?)
    }

    /// Returns the event bus used by this scanner for host subscriptions.
    pub fn event_bus(&self) -> Arc<EventBus> {
        Arc::clone(&self.event_bus)
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
    use venom_core::{OutcomeStatus, Probability, RunStatus, RunStepStatus, SecuritySeverity};

    use super::*;
    use crate::ScanFinding;

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
                severity: "HIGH".to_string(),
                description: "SDK phase executed".to_string(),
                evidence: context.target.to_string(),
            }])
        }
    }

    #[tokio::test]
    async fn custom_scanner_returns_only_the_typed_report_boundary() {
        let scanner = ScannerSdk::builder().phase(ExamplePhase).build();
        let report = scanner.scan("https://example.test").await.unwrap();

        assert_eq!(report.status(), RunStatus::Complete);
        assert_eq!(report.steps()[0].status(), RunStepStatus::Succeeded);
        assert_eq!(report.outcomes()[0].disposition(), OutcomeStatus::Unknown);
        assert_eq!(report.outcomes()[0].severity(), SecuritySeverity::Info);
        assert_eq!(report.outcomes()[0].confidence(), Probability::ZERO);
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("SDK phase executed"));
        assert!(!json.contains("HIGH"));
    }
}
