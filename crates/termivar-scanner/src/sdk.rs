//! Public composition API for the opt-in historical scanner SDK.
//!
//! The SDK returns the shared typed [`RunReport`]
//! contract. Raw phase telemetry and `ScanFinding` strings do not cross this
//! host boundary. Built-in phases 2–4 and 5–9 receive separate finite
//! discovery and active-verification envelopes. Phase 1 or a custom phase may
//! still use the compatibility client, so whole-run request/body accounting is
//! `Unmetered`.

use std::{sync::Arc, time::Duration};

use reqwest::Client;
use termivar_core::RunReport;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::{
    DiscoveryLimits, EventBus, Result, ScanContext, ScanPhase, ScanRunner, VerificationLimits,
};

/// Reusable legacy scanner assembled from application-defined [`ScanPhase`]
/// values.
///
/// Custom phases can use the raw compatibility client and therefore cannot
/// inherit the bounded-accounting claim of either built-in transport slice.
pub struct ScannerSdk {
    runner: ScanRunner,
    client: Client,
    discovery_limits: DiscoveryLimits,
    verification_limits: VerificationLimits,
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
        )
        .with_pre_execution_discovery_limits(self.discovery_limits)
        .with_pre_execution_verification_limits(self.verification_limits);
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
    discovery_limits: DiscoveryLimits,
    verification_limits: VerificationLimits,
    phase_timeout_secs: u64,
    event_bus: Arc<EventBus>,
}

impl ScannerBuilder {
    /// Creates a builder with a five-minute phase timeout.
    pub fn new() -> Self {
        Self {
            phases: Vec::new(),
            client: Client::new(),
            discovery_limits: DiscoveryLimits::default(),
            verification_limits: VerificationLimits::default(),
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

    /// Replaces the raw HTTP client used by phase one and custom legacy
    /// phases. Built-in phases two through nine use isolated, bounded,
    /// redirect-disabled authorities instead.
    pub fn client(mut self, client: Client) -> Self {
        self.client = client;
        self
    }

    /// Replaces the finite exact-origin envelope shared by built-in discovery
    /// phases 2–4.
    pub fn discovery_limits(mut self, limits: DiscoveryLimits) -> Self {
        self.discovery_limits = limits;
        self
    }

    /// Replaces the finite exact-origin envelope shared by built-in legacy
    /// verification phases five through nine.
    pub fn verification_limits(mut self, limits: VerificationLimits) -> Self {
        self.verification_limits = limits;
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
            discovery_limits: self.discovery_limits,
            verification_limits: self.verification_limits,
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
    use termivar_core::{OutcomeStatus, Probability, RunStatus, RunStepStatus, SecuritySeverity};

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

    #[test]
    fn builder_retains_explicit_discovery_limits() {
        let limits = DiscoveryLimits::new().with_max_requests(7);
        let scanner = ScannerSdk::builder().discovery_limits(limits).build();

        assert_eq!(scanner.discovery_limits.max_requests(), 7);
    }

    #[test]
    fn builder_retains_explicit_verification_limits() {
        let limits = VerificationLimits::new().with_max_requests(11).unwrap();
        let scanner = ScannerSdk::builder().verification_limits(limits).build();

        assert_eq!(scanner.verification_limits.max_requests(), 11);
    }
}
