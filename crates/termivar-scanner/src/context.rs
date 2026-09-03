//! Scan context: shared state for the historical `termivar legacy-scan` pipeline.
//!
//! ## Runtime scope
//!
//! - **Build:** non-default `legacy-scanner` feature.
//! - **Execution:** Surface A — `ScanContext` owns the shared scan state and a
//!   private `KnowledgeBase`. Corrected built-in verification phases may record
//!   bounded evidence and knowledge-only `NeedsReview` outcomes through the
//!   verifier-owned bridge; arbitrary legacy strings never gain that authority.
//! - **Default `termivar scan`:** no.
//! - **Support:** legacy alpha.
//!
//! See `docs/internals/runtime-map.md`.

use crate::event_bus::EventBus;
use crate::http_evidence::HttpProbeMethod;
use crate::knowledge::KnowledgeBase;
use crate::legacy_discovery::{
    BoundedHttpResponse, DiscoveryDelta, DiscoveryForm, DiscoveryLimits, DiscoverySnapshot,
    LegacyDiscoveryAuthority, LegacyVerificationAuthority, VerificationLimits,
};
use crate::logging::{LogLevel, Logger};
use crate::ScannerError;
use dashmap::{DashMap, DashSet};
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    sync::Mutex,
};
use termivar_core::{
    EntityId, OutcomeStatus, RunOutcomeRecord, VerificationStage, MAX_RUN_REPORT_OUTCOMES,
};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::verification::VerificationReport;

const LEGACY_VERIFICATION_REDACTED_SUMMARY: &str =
    "Verifier-backed bounded legacy evidence; raw response content is withheld.";
const LEGACY_SQL_ACTION_ID: &str = "legacy.observer.sql_behavior";
const LEGACY_SSTI_ACTION_ID: &str = "legacy.observer.template_arithmetic";
const LEGACY_LFI_ACTION_ID: &str = "legacy.verification.local-file-canary";

pub(crate) fn legacy_subject_digest(origin: &str) -> String {
    let mut digest = Sha256::new();
    digest.update((origin.len() as u64).to_be_bytes());
    digest.update(origin.as_bytes());
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Zero-copy shared state across all scan phases.
///
/// Construct contexts through [`ScanContext::new`] or one of the policy-aware
/// constructors. Additional runtime state may be introduced without requiring
/// extension authors to initialize internal fields.
///
/// # Examples
///
/// ```rust
/// use reqwest::Client;
/// use url::Url;
/// use termivar_scanner::ScanContext;
///
/// let (telemetry_tx, _telemetry_rx) = tokio::sync::mpsc::unbounded_channel();
/// let context = ScanContext::new(
///     Url::parse("https://example.test")?,
///     Client::new(),
///     telemetry_tx,
/// );
///
/// assert_eq!(context.knowledge().stats().evidence, 0);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// Direct construction is intentionally unsupported so new runtime state does
/// not break extension code:
///
/// ```compile_fail
/// use reqwest::Client;
/// use url::Url;
/// use termivar_scanner::ScanContext;
///
/// let (telemetry_tx, _telemetry_rx) = tokio::sync::mpsc::unbounded_channel();
/// let context = ScanContext::new(
///     Url::parse("https://example.test").unwrap(),
///     Client::new(),
///     telemetry_tx,
/// );
/// let _modified = ScanContext {
///     phase_timeout_secs: 30,
///     ..context
/// };
/// ```
#[derive(Clone)]
#[non_exhaustive]
pub struct ScanContext {
    /// Compatibility view of the root URL whose scope is being scanned.
    ///
    /// Mutating this pre-1.0 public field does not change the immutable target
    /// captured by built-in authorities or the runner's provenance envelope.
    pub target: Url,
    /// Raw HTTP client retained for phase one and custom phases that explicitly
    /// accept the legacy direct-I/O contract.
    ///
    /// Built-in phases two through nine ignore this client. Discovery and
    /// verification use distinct private exact-origin bounded authorities.
    pub client: Arc<Client>,
    /// Discovered endpoints mapped to their observed parameter names.
    pub discovered_endpoints: Arc<DashMap<String, Vec<String>>>,
    /// URLs already visited by discovery phases.
    pub visited_urls: Arc<DashSet<String>>,
    /// Asynchronous telemetry channel for logging and analysis.
    pub telemetry_tx: tokio::sync::mpsc::UnboundedSender<String>,
    /// Structured logger shared by scan phases.
    pub logger: Arc<Logger>,
    /// Maximum runtime of an individual phase, in seconds.
    pub phase_timeout_secs: u64,
    /// Token used to propagate graceful scan cancellation.
    ///
    /// Calling [`CancellationToken::cancel`] affects the immutable shared token
    /// captured by the runner and built-in authorities. Replacing this public
    /// compatibility field does not replace that runtime authority.
    pub cancel_token: CancellationToken,
    /// Event bus used to publish scan lifecycle and progress events.
    pub event_bus: Arc<EventBus>,
    // Evidence-driven memory shared by discovery, reasoning, and execution phases.
    // Kept private so its construction and replacement remain runtime policy.
    knowledge: KnowledgeBase,
    // Immutable target/provenance authority captured at construction. The
    // public compatibility field cannot retarget built-in transport or reports.
    authorized_target: Url,
    // Immutable clone of the host-supplied cancellation authority. Calling
    // cancel through any clone remains effective; replacing the public field
    // cannot desynchronize built-ins from the runner.
    runtime_cancel_token: CancellationToken,
    // Shared, redirect-disabled authority for legacy discovery phases 2–4.
    discovery: LegacyDiscoveryAuthority,
    // Distinct active authority shared by legacy verification phases 5–9.
    verification: LegacyVerificationAuthority,
    // Serializes typed discovery commits with their public compatibility-map
    // projection so internal consumers observe an old or complete new batch.
    discovery_bridge: Arc<Mutex<()>>,
    // Verifier-owned, knowledge-only outcomes accepted from corrected built-in
    // legacy phases. The runner checkpoints this ledger per phase so an error,
    // timeout, panic, or cancellation cannot publish a partial claim batch.
    legacy_verification_outcomes: Arc<Mutex<Vec<RunOutcomeRecord>>>,
}

impl ScanContext {
    /// Creates a context with a five-minute phase timeout, a fresh cancellation
    /// token, and a fresh event bus.
    pub fn new(
        target: Url,
        client: Client,
        telemetry_tx: tokio::sync::mpsc::UnboundedSender<String>,
    ) -> Self {
        Self::with_timeout(target, client, telemetry_tx, 300) // 5 min default
    }

    /// Creates a context with a host-selected finite discovery envelope and
    /// otherwise default runtime services.
    pub fn new_with_discovery_limits(
        target: Url,
        client: Client,
        telemetry_tx: tokio::sync::mpsc::UnboundedSender<String>,
        discovery_limits: DiscoveryLimits,
    ) -> Self {
        Self::new(target, client, telemetry_tx)
            .with_pre_execution_discovery_limits(discovery_limits)
    }

    /// Creates a context with a host-selected finite verification envelope and
    /// otherwise default runtime services.
    pub fn new_with_verification_limits(
        target: Url,
        client: Client,
        telemetry_tx: tokio::sync::mpsc::UnboundedSender<String>,
        verification_limits: VerificationLimits,
    ) -> Self {
        Self::new(target, client, telemetry_tx)
            .with_pre_execution_verification_limits(verification_limits)
    }

    /// Creates a context with an explicit per-phase timeout in seconds.
    ///
    /// A fresh cancellation token and event bus are installed for the scan.
    pub fn with_timeout(
        target: Url,
        client: Client,
        telemetry_tx: tokio::sync::mpsc::UnboundedSender<String>,
        phase_timeout_secs: u64,
    ) -> Self {
        Self::with_cancellation(
            target,
            client,
            telemetry_tx,
            phase_timeout_secs,
            CancellationToken::new(),
        )
    }

    /// Creates a context with explicit timeout and cancellation policy.
    ///
    /// A fresh event bus is installed for the scan.
    pub fn with_cancellation(
        target: Url,
        client: Client,
        telemetry_tx: tokio::sync::mpsc::UnboundedSender<String>,
        phase_timeout_secs: u64,
        cancel_token: CancellationToken,
    ) -> Self {
        Self::with_event_bus(
            target,
            client,
            telemetry_tx,
            phase_timeout_secs,
            cancel_token,
            Arc::new(EventBus::new()),
        )
    }

    /// Creates a context with all externally configurable runtime services.
    ///
    /// The authorized root endpoint is registered immediately; the visited
    /// set, typed forms, logger, and knowledge base start empty. The supplied
    /// raw HTTP client is promoted into shared ownership for unmigrated and
    /// custom legacy phases.
    pub fn with_event_bus(
        target: Url,
        client: Client,
        telemetry_tx: tokio::sync::mpsc::UnboundedSender<String>,
        phase_timeout_secs: u64,
        cancel_token: CancellationToken,
        event_bus: Arc<EventBus>,
    ) -> Self {
        let discovery = LegacyDiscoveryAuthority::new(
            &target,
            DiscoveryLimits::default(),
            cancel_token.clone(),
        );
        let verification = LegacyVerificationAuthority::new(
            &target,
            VerificationLimits::default(),
            cancel_token.clone(),
        );
        let discovered_endpoints = Arc::new(DashMap::new());
        for (url, parameters) in discovery.snapshot().endpoints() {
            discovered_endpoints.insert(url.clone(), parameters.iter().cloned().collect());
        }
        Self {
            target: target.clone(),
            client: Arc::new(client),
            discovered_endpoints,
            visited_urls: Arc::new(DashSet::new()),
            telemetry_tx,
            logger: Arc::new(Logger::new(LogLevel::Info)),
            phase_timeout_secs,
            cancel_token: cancel_token.clone(),
            event_bus,
            knowledge: KnowledgeBase::new(),
            authorized_target: target,
            runtime_cancel_token: cancel_token,
            discovery,
            verification,
            discovery_bridge: Arc::new(Mutex::new(())),
            legacy_verification_outcomes: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub(crate) fn with_pre_execution_discovery_limits(mut self, limits: DiscoveryLimits) -> Self {
        // Crate-owned composition calls this only before the context is shared
        // or any discovery request can consume authority. Keeping this seam
        // private prevents hosts from multiplying a live budget or discarding
        // committed typed state through mid-run reconfiguration.
        self.discovery = LegacyDiscoveryAuthority::new(
            &self.authorized_target,
            limits,
            self.runtime_cancel_token.clone(),
        );
        self.discovered_endpoints.clear();
        for (url, parameters) in self.discovery.snapshot().endpoints() {
            self.discovered_endpoints
                .insert(url.clone(), parameters.iter().cloned().collect());
        }
        self
    }

    /// Returns the configured discovery envelope.
    pub const fn discovery_limits(&self) -> DiscoveryLimits {
        self.discovery.limits()
    }

    pub(crate) fn with_pre_execution_verification_limits(
        mut self,
        limits: VerificationLimits,
    ) -> Self {
        // As with discovery policy, crate-owned composition calls this only
        // before execution. A live authority can never be reset to multiply
        // its request or byte budget.
        self.verification = LegacyVerificationAuthority::new(
            &self.authorized_target,
            limits,
            self.runtime_cancel_token.clone(),
        );
        self
    }

    /// Returns the finite envelope shared by built-in legacy verification
    /// phases five through nine.
    pub const fn verification_limits(&self) -> VerificationLimits {
        self.verification.limits()
    }

    pub(crate) const fn authorized_target(&self) -> &Url {
        &self.authorized_target
    }

    pub(crate) fn runtime_cancel_token(&self) -> CancellationToken {
        self.runtime_cancel_token.clone()
    }

    pub(crate) fn runtime_authority_is_intact(&self) -> bool {
        self.target == self.authorized_target
    }

    pub(crate) async fn request(
        &self,
        action_id: &str,
        method: HttpProbeMethod,
        url: Url,
    ) -> Result<BoundedHttpResponse, ScannerError> {
        self.discovery.request(action_id, method, url).await
    }

    pub(crate) async fn verification_request(
        &self,
        action_id: &str,
        method: HttpProbeMethod,
        url: Url,
    ) -> Result<BoundedHttpResponse, ScannerError> {
        self.verification.request(action_id, method, url).await
    }

    pub(crate) fn ensure_legacy_verification_commit(
        &self,
        action_id: &str,
    ) -> Result<(), ScannerError> {
        self.verification.ensure_commit_allowed(action_id)
    }

    /// Returns the non-secret subject shared by legacy verification records.
    ///
    /// The typed report already carries the exact authorized origin. Evidence
    /// identity deliberately omits paths, query names, parameter names, and
    /// unkeyed digests of those low-entropy values.
    pub(crate) fn legacy_verification_subject(&self) -> Result<EntityId, ScannerError> {
        let origin = self.authorized_target.origin().ascii_serialization();
        EntityId::new(format!(
            "authorized-origin:sha256:{}",
            legacy_subject_digest(&origin)
        ))
        .map_err(|_| ScannerError::InvalidLegacyVerificationReport)
    }

    /// Atomically accepts verifier-produced manual-review outcomes from one
    /// corrected built-in legacy phase.
    ///
    /// The bridge intentionally permits only active, knowledge-only
    /// `NeedsReview` reports. It cannot mint success, confirmation, negative
    /// claims, or hypothesis transitions. Each report is first validated
    /// against the same knowledge snapshot from which its verifier evaluated
    /// evidence.
    pub(crate) fn record_legacy_verification_reports(
        &self,
        reports: Vec<VerificationReport>,
    ) -> Result<(), ScannerError> {
        let Some(first_report) = reports.first() else {
            return Ok(());
        };
        let batch_action_id = first_report.case().action_id();
        let max_reports = match batch_action_id {
            LEGACY_SQL_ACTION_ID => 2,
            LEGACY_SSTI_ACTION_ID | LEGACY_LFI_ACTION_ID => 1,
            _ => return Err(ScannerError::InvalidLegacyVerificationReport),
        };
        if reports.len() > max_reports
            || reports
                .iter()
                .any(|report| report.case().action_id() != batch_action_id)
        {
            return Err(ScannerError::InvalidLegacyVerificationReport);
        }
        self.ensure_legacy_verification_commit(batch_action_id)?;

        let expected_subject = self.legacy_verification_subject()?;
        let mut accepted = Vec::with_capacity(reports.len());
        for report in reports {
            let action_id = report.case().action_id();
            if report.case().applies_hypothesis_transition()
                || report.stage() != VerificationStage::Active
                || report.outcome().status() != OutcomeStatus::NeedsReview
                || report.case().subject() != &expected_subject
                || report.outcome().subject() != &expected_subject
                || !matches!(
                    action_id,
                    LEGACY_SQL_ACTION_ID | LEGACY_SSTI_ACTION_ID | LEGACY_LFI_ACTION_ID
                )
            {
                return Err(ScannerError::InvalidLegacyVerificationReport);
            }

            let outcome = report.outcome();
            if outcome.case_id() != report.case().id() {
                return Err(ScannerError::InvalidLegacyVerificationReport);
            }
            let hypothesis = self
                .knowledge
                .hypothesis(outcome.hypothesis_id())
                .ok_or(ScannerError::InvalidLegacyVerificationReport)?;
            if hypothesis.subject() != &expected_subject
                || outcome.evidence_ids().iter().any(|evidence_id| {
                    self.knowledge.evidence(evidence_id).is_none_or(|evidence| {
                        evidence.subject() != &expected_subject
                            || evidence.source().component() != action_id
                            || evidence.source().correlation_id() != Some(report.case().id())
                    })
                })
            {
                return Err(ScannerError::InvalidLegacyVerificationReport);
            }
            report
                .apply(&self.knowledge)
                .map_err(|_| ScannerError::InvalidLegacyVerificationReport)?;
            accepted.push(RunOutcomeRecord::from_outcome(
                report.outcome().clone(),
                LEGACY_VERIFICATION_REDACTED_SUMMARY,
            )?);
        }

        let mut ledger = self
            .legacy_verification_outcomes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let next_len = ledger
            .len()
            .checked_add(accepted.len())
            .ok_or(ScannerError::LegacyVerificationStateLimitExceeded)?;
        if next_len > MAX_RUN_REPORT_OUTCOMES {
            return Err(ScannerError::LegacyVerificationStateLimitExceeded);
        }
        let mut fingerprints = ledger
            .iter()
            .map(|record| record.fingerprint())
            .collect::<BTreeSet<_>>();
        if accepted
            .iter()
            .any(|record| !fingerprints.insert(record.fingerprint()))
        {
            return Err(ScannerError::InvalidLegacyVerificationReport);
        }
        ledger.extend(accepted);
        Ok(())
    }

    pub(crate) fn legacy_verification_checkpoint(&self) -> usize {
        self.legacy_verification_outcomes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    pub(crate) fn legacy_verification_outcomes_since(
        &self,
        checkpoint: usize,
    ) -> Vec<RunOutcomeRecord> {
        let ledger = self
            .legacy_verification_outcomes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ledger.get(checkpoint..).unwrap_or_default().to_vec()
    }

    pub(crate) fn rollback_legacy_verification_outcomes(&self, checkpoint: usize) {
        self.legacy_verification_outcomes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .truncate(checkpoint);
    }

    pub(crate) fn canonicalize_discovery_url(&self, url: &Url) -> Result<Url, ScannerError> {
        self.discovery.canonicalize(url)
    }

    pub(crate) fn discovery_snapshot(&self) -> DiscoverySnapshot {
        // Preserve the pre-1.0 host seeding contract while phases migrate to
        // typed state. Invalid or out-of-scope legacy strings are never
        // promoted into the bounded authority snapshot. Capture compatibility
        // mirrors first and clone typed state last: internal commits publish
        // typed state before updating those mirrors, so this ordering can
        // observe only the old or complete new typed batch, never a strict
        // partial internal commit.
        let _bridge = self
            .discovery_bridge
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let legacy_endpoints = self
            .discovered_endpoints
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect::<BTreeMap<_, _>>();
        let legacy_visited = self
            .visited_urls
            .iter()
            .map(|entry| entry.key().clone())
            .collect::<std::collections::BTreeSet<_>>();
        let mut snapshot = self.discovery.snapshot();
        for (raw_url, parameters) in legacy_endpoints {
            let Ok(url) = self.authorized_target.join(&raw_url) else {
                continue;
            };
            let Ok(url) = self.discovery.canonicalize(&url) else {
                continue;
            };
            snapshot.merge_endpoint(url, parameters);
        }
        for raw_url in legacy_visited {
            let Ok(url) = self.authorized_target.join(&raw_url) else {
                continue;
            };
            let Ok(url) = self.discovery.canonicalize(&url) else {
                continue;
            };
            snapshot.merge_visited(url);
        }
        snapshot
    }

    /// Returns stable typed form observations from bounded discovery.
    ///
    /// Ownership is parser-tree-descendant based; malformed HTML form-owner
    /// associations are not inferred.
    pub fn discovery_forms(&self) -> Vec<DiscoveryForm> {
        self.discovery.snapshot().forms().iter().cloned().collect()
    }

    pub(crate) fn commit_discovery(
        &self,
        action_id: &str,
        delta: DiscoveryDelta,
    ) -> Result<(), ScannerError> {
        let _bridge = self
            .discovery_bridge
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let snapshot = self.discovery.commit(action_id, delta)?;
        for (url, parameters) in snapshot.endpoints() {
            self.discovered_endpoints
                .insert(url.clone(), parameters.iter().cloned().collect());
        }
        for url in snapshot.visited() {
            self.visited_urls.insert(url.clone());
        }
        Ok(())
    }

    /// Sends a plain-text message to the telemetry channel.
    ///
    /// Messages are dropped when the receiving side has closed.
    pub fn log(&self, msg: String) {
        let _ = self.telemetry_tx.send(msg);
    }

    /// Records a discovered endpoint and its observed parameter names.
    ///
    /// Recording the same URL again replaces its prior parameter list.
    pub fn add_endpoint(&self, url: String, params: Vec<String>) {
        let _bridge = self
            .discovery_bridge
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.discovered_endpoints.insert(url, params);
    }

    /// Marks a URL as visited for duplicate-scan prevention.
    pub fn mark_visited(&self, url: String) {
        let _bridge = self
            .discovery_bridge
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.visited_urls.insert(url);
    }

    /// Returns whether a URL has already been marked as visited.
    pub fn is_visited(&self, url: &str) -> bool {
        let _bridge = self
            .discovery_bridge
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.visited_urls.contains(url)
    }

    /// Returns the number of distinct discovered endpoint URLs.
    pub fn endpoint_count(&self) -> usize {
        let _bridge = self
            .discovery_bridge
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.discovered_endpoints.len()
    }

    /// Returns the evidence-driven knowledge base shared by this scan.
    ///
    /// The context retains ownership so the runtime can preserve one knowledge
    /// identity across phases and cloned contexts.
    pub fn knowledge(&self) -> &KnowledgeBase {
        &self.knowledge
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use termivar_core::{
        ConfidenceScore, Evidence, EvidenceId, EvidenceKind, EvidenceSource, EvidenceValue,
        Hypothesis, KnowledgePredicate, Probability,
    };

    use super::*;
    use crate::{
        rules::{Expression, KnowledgeLayer},
        verification::{ActiveVerifier, PassiveVerifier, VerificationCase, VerificationRule},
    };

    const TEST_ACTION_ID: &str = "legacy.observer.template_arithmetic";

    struct ReportFixture {
        report: VerificationReport,
        hypothesis: Hypothesis,
        evidence: Evidence,
    }

    type ReportIdentity<'a> = (&'a str, &'a str, &'a str);
    type ReportBehavior = (VerificationStage, OutcomeStatus, bool);
    type ReportScope<'a> = (bool, Option<&'a str>);

    fn report_fixture(
        knowledge: &KnowledgeBase,
        subject: EntityId,
        identity: ReportIdentity<'_>,
        behavior: ReportBehavior,
    ) -> ReportFixture {
        report_fixture_with_scope(knowledge, subject, identity, behavior, (true, None))
    }

    fn report_fixture_with_scope(
        knowledge: &KnowledgeBase,
        subject: EntityId,
        identity: ReportIdentity<'_>,
        behavior: ReportBehavior,
        scope: ReportScope<'_>,
    ) -> ReportFixture {
        let (action_id, source_component, suffix) = identity;
        let (stage, status, knowledge_only) = behavior;
        let (case_correlated_evidence, correlation_id) = scope;
        let hypothesis_id = format!("hypothesis:legacy.bridge-test.{suffix}");
        let case_id = format!("case:legacy.bridge-test.{suffix}");
        let predicate = KnowledgePredicate::new("legacy.bridge-test", suffix).unwrap();
        let hypothesis = Hypothesis::with_id(
            hypothesis_id.clone(),
            subject.clone(),
            KnowledgePredicate::new("legacy.bridge-test", "audit-anchor").unwrap(),
            EvidenceValue::Text("manual-review".to_owned()),
            Probability::from_percent(50).unwrap(),
        )
        .unwrap();
        knowledge.upsert_hypothesis(hypothesis.clone()).unwrap();
        let baseline = knowledge.snapshot_for_subject(&subject);

        let evidence = Evidence::with_id_at(
            EvidenceId::parse(format!("evidence:legacy.bridge-test.{suffix}")).unwrap(),
            subject.clone(),
            EvidenceKind::Content,
            predicate.clone(),
            EvidenceValue::Boolean(true),
            EvidenceSource::new(source_component, "bounded-review-observation")
                .unwrap()
                .with_correlation_id(correlation_id.unwrap_or(&case_id))
                .unwrap(),
            ConfidenceScore::from_percent(70).unwrap(),
            0,
        );
        knowledge.insert_evidence(evidence.clone()).unwrap();
        let after_probe = knowledge.snapshot_for_subject(&subject);

        let case = VerificationCase::new(case_id, subject, action_id, hypothesis_id).unwrap();
        let case = if knowledge_only {
            case.without_hypothesis_transition()
        } else {
            case
        };
        let rule = VerificationRule::new(
            format!("verify:legacy.bridge-test.{suffix}"),
            stage,
            100,
            Expression::equals(
                KnowledgeLayer::Evidence,
                predicate,
                EvidenceValue::Boolean(true),
            ),
            status,
            Probability::from_percent(70).unwrap(),
            "Bounded observation requires review",
        )
        .unwrap()
        .scoped_to_action(action_id)
        .unwrap();
        let rule = if case_correlated_evidence {
            rule.with_case_correlated_evidence().unwrap()
        } else {
            rule
        };

        let report = match stage {
            VerificationStage::Active => {
                let mut verifier = ActiveVerifier::new();
                verifier.register(rule).unwrap();
                verifier
                    .verify_snapshots(&case, &baseline, &after_probe)
                    .unwrap()
            },
            VerificationStage::Passive => {
                let mut verifier = PassiveVerifier::new();
                verifier.register(rule).unwrap();
                verifier.verify_snapshot(&case, &after_probe).unwrap()
            },
            _ => panic!("unsupported test verification stage"),
        };
        ReportFixture {
            report,
            hypothesis,
            evidence,
        }
    }

    fn bridge_context(cancellation: CancellationToken) -> ScanContext {
        let (tx, _) = tokio::sync::mpsc::unbounded_channel();
        ScanContext::with_cancellation(
            Url::parse("https://example.test/").unwrap(),
            Client::new(),
            tx,
            30,
            cancellation,
        )
    }

    #[tokio::test]
    async fn test_scan_context_creation() {
        let (tx, _) = tokio::sync::mpsc::unbounded_channel();
        let url = Url::parse("http://example.com").unwrap();
        let client = Client::new();

        let ctx = ScanContext::new(url, client, tx);
        assert_eq!(
            ctx.endpoint_count(),
            1,
            "the authorized root is always registered"
        );
        assert_eq!(ctx.knowledge().stats().evidence, 0);
    }

    #[test]
    fn discovery_and_verification_envelopes_are_distinct() {
        let (tx, _) = tokio::sync::mpsc::unbounded_channel();
        let target = Url::parse("https://example.test/").unwrap();
        let discovery = DiscoveryLimits::new().with_max_requests(7);
        let verification = VerificationLimits::new().with_max_requests(11).unwrap();

        let context = ScanContext::new_with_discovery_limits(target, Client::new(), tx, discovery)
            .with_pre_execution_verification_limits(verification);

        assert_eq!(context.discovery_limits().max_requests(), 7);
        assert_eq!(context.verification_limits().max_requests(), 11);
    }

    #[test]
    fn public_target_replacement_cannot_retarget_built_in_authorities() {
        let (tx, _) = tokio::sync::mpsc::unbounded_channel();
        let authorized = Url::parse("https://authorized.example.test/root").unwrap();
        let replacement = Url::parse("https://replacement.example.test/").unwrap();
        let mut context = ScanContext::new(authorized.clone(), Client::new(), tx);

        context.target = replacement.clone();

        assert_eq!(context.authorized_target(), &authorized);
        assert_eq!(
            context.legacy_verification_subject().unwrap().as_str(),
            format!(
                "authorized-origin:sha256:{}",
                legacy_subject_digest("https://authorized.example.test")
            )
        );
        assert!(context.canonicalize_discovery_url(&authorized).is_ok());
        assert!(matches!(
            context.canonicalize_discovery_url(&replacement),
            Err(ScannerError::InvalidTarget)
        ));
    }

    #[test]
    fn public_cancellation_replacement_cannot_desynchronize_runtime_authority() {
        let (tx, _) = tokio::sync::mpsc::unbounded_channel();
        let target = Url::parse("https://example.test/").unwrap();
        let original = CancellationToken::new();
        let mut context =
            ScanContext::with_cancellation(target, Client::new(), tx, 1, original.clone());

        context.cancel_token = CancellationToken::new();
        original.cancel();

        assert!(context.runtime_cancel_token().is_cancelled());
        assert!(!context.cancel_token.is_cancelled());
    }

    #[test]
    fn verifier_bridge_rejects_reports_not_backed_by_local_knowledge() {
        let context = bridge_context(CancellationToken::new());
        let foreign = KnowledgeBase::new();
        let fixture = report_fixture(
            &foreign,
            context.legacy_verification_subject().unwrap(),
            (TEST_ACTION_ID, TEST_ACTION_ID, "foreign"),
            (VerificationStage::Active, OutcomeStatus::NeedsReview, true),
        );

        let error = context
            .record_legacy_verification_reports(vec![fixture.report])
            .unwrap_err();

        assert!(matches!(
            error,
            ScannerError::InvalidLegacyVerificationReport
        ));
        assert_eq!(context.legacy_verification_checkpoint(), 0);
    }

    #[test]
    fn verifier_bridge_rejects_mirrored_foreign_knowledge_authority() {
        let context = bridge_context(CancellationToken::new());
        let foreign = KnowledgeBase::new();
        let fixture = report_fixture(
            &foreign,
            context.legacy_verification_subject().unwrap(),
            (TEST_ACTION_ID, TEST_ACTION_ID, "mirrored-foreign"),
            (VerificationStage::Active, OutcomeStatus::NeedsReview, true),
        );

        // Reproduce the exact records and write order locally so subjects,
        // identifiers, values, and revision counters all match. The report
        // must still remain bound to the foreign in-memory authority that
        // evaluated it.
        context
            .knowledge()
            .upsert_hypothesis(fixture.hypothesis)
            .unwrap();
        context
            .knowledge()
            .insert_evidence(fixture.evidence)
            .unwrap();

        let error = context
            .record_legacy_verification_reports(vec![fixture.report])
            .unwrap_err();

        assert!(matches!(
            error,
            ScannerError::InvalidLegacyVerificationReport
        ));
        assert_eq!(context.legacy_verification_checkpoint(), 0);
    }

    #[test]
    fn verifier_bridge_rejects_missing_local_evidence_or_hypothesis() {
        let missing_evidence_context = bridge_context(CancellationToken::new());
        let foreign = KnowledgeBase::new();
        let missing_evidence = report_fixture(
            &foreign,
            missing_evidence_context
                .legacy_verification_subject()
                .unwrap(),
            (TEST_ACTION_ID, TEST_ACTION_ID, "missing-evidence"),
            (VerificationStage::Active, OutcomeStatus::NeedsReview, true),
        );
        missing_evidence_context
            .knowledge()
            .upsert_hypothesis(missing_evidence.hypothesis)
            .unwrap();

        let error = missing_evidence_context
            .record_legacy_verification_reports(vec![missing_evidence.report])
            .unwrap_err();
        assert!(matches!(
            error,
            ScannerError::InvalidLegacyVerificationReport
        ));
        assert_eq!(missing_evidence_context.legacy_verification_checkpoint(), 0);

        let missing_hypothesis_context = bridge_context(CancellationToken::new());
        let foreign = KnowledgeBase::new();
        let missing_hypothesis = report_fixture(
            &foreign,
            missing_hypothesis_context
                .legacy_verification_subject()
                .unwrap(),
            (TEST_ACTION_ID, TEST_ACTION_ID, "missing-hypothesis"),
            (VerificationStage::Active, OutcomeStatus::NeedsReview, true),
        );
        missing_hypothesis_context
            .knowledge()
            .insert_evidence(missing_hypothesis.evidence)
            .unwrap();

        let error = missing_hypothesis_context
            .record_legacy_verification_reports(vec![missing_hypothesis.report])
            .unwrap_err();
        assert!(matches!(
            error,
            ScannerError::InvalidLegacyVerificationReport
        ));
        assert_eq!(
            missing_hypothesis_context.legacy_verification_checkpoint(),
            0
        );
    }

    #[test]
    fn verifier_bridge_rejects_transition_status_and_stage_broadening() {
        let scenarios = [
            (
                VerificationStage::Active,
                OutcomeStatus::NeedsReview,
                false,
                "transition-authorized",
            ),
            (
                VerificationStage::Active,
                OutcomeStatus::Success,
                true,
                "success",
            ),
            (
                VerificationStage::Passive,
                OutcomeStatus::NeedsReview,
                true,
                "passive",
            ),
        ];

        for (stage, status, knowledge_only, suffix) in scenarios {
            let context = bridge_context(CancellationToken::new());
            let fixture = report_fixture(
                context.knowledge(),
                context.legacy_verification_subject().unwrap(),
                (TEST_ACTION_ID, TEST_ACTION_ID, suffix),
                (stage, status, knowledge_only),
            );

            let error = context
                .record_legacy_verification_reports(vec![fixture.report])
                .unwrap_err();
            assert!(matches!(
                error,
                ScannerError::InvalidLegacyVerificationReport
            ));
            assert_eq!(context.legacy_verification_checkpoint(), 0, "{suffix}");
        }
    }

    #[test]
    fn verifier_bridge_rejects_wrong_subject_action_and_producer() {
        let wrong_subject_context = bridge_context(CancellationToken::new());
        let wrong_subject = report_fixture(
            wrong_subject_context.knowledge(),
            EntityId::new("authorized-origin:https://other.test").unwrap(),
            (TEST_ACTION_ID, TEST_ACTION_ID, "wrong-subject"),
            (VerificationStage::Active, OutcomeStatus::NeedsReview, true),
        );
        assert!(matches!(
            wrong_subject_context.record_legacy_verification_reports(vec![wrong_subject.report]),
            Err(ScannerError::InvalidLegacyVerificationReport)
        ));

        let wrong_action_context = bridge_context(CancellationToken::new());
        let wrong_action = report_fixture(
            wrong_action_context.knowledge(),
            wrong_action_context.legacy_verification_subject().unwrap(),
            (
                "legacy.observer.unsupported",
                "legacy.observer.unsupported",
                "wrong-action",
            ),
            (VerificationStage::Active, OutcomeStatus::NeedsReview, true),
        );
        assert!(matches!(
            wrong_action_context.record_legacy_verification_reports(vec![wrong_action.report]),
            Err(ScannerError::InvalidLegacyVerificationReport)
        ));

        let wrong_producer_context = bridge_context(CancellationToken::new());
        let wrong_producer = report_fixture(
            wrong_producer_context.knowledge(),
            wrong_producer_context
                .legacy_verification_subject()
                .unwrap(),
            (
                TEST_ACTION_ID,
                "legacy.observer.different-producer",
                "wrong-producer",
            ),
            (VerificationStage::Active, OutcomeStatus::NeedsReview, true),
        );
        assert!(matches!(
            wrong_producer_context.record_legacy_verification_reports(vec![wrong_producer.report]),
            Err(ScannerError::InvalidLegacyVerificationReport)
        ));

        assert_eq!(wrong_subject_context.legacy_verification_checkpoint(), 0);
        assert_eq!(wrong_action_context.legacy_verification_checkpoint(), 0);
        assert_eq!(wrong_producer_context.legacy_verification_checkpoint(), 0);
    }

    #[test]
    fn verifier_bridge_rejects_evidence_from_another_case() {
        let context = bridge_context(CancellationToken::new());
        let fixture = report_fixture_with_scope(
            context.knowledge(),
            context.legacy_verification_subject().unwrap(),
            (TEST_ACTION_ID, TEST_ACTION_ID, "wrong-correlation"),
            (VerificationStage::Active, OutcomeStatus::NeedsReview, true),
            (false, Some("case:legacy.bridge-test.another-case")),
        );
        assert_eq!(
            fixture.report.outcome().status(),
            OutcomeStatus::NeedsReview
        );

        assert!(matches!(
            context.record_legacy_verification_reports(vec![fixture.report]),
            Err(ScannerError::InvalidLegacyVerificationReport)
        ));
        assert_eq!(context.legacy_verification_checkpoint(), 0);
    }

    #[test]
    fn duplicate_verifier_report_batch_is_rejected_atomically() {
        let context = bridge_context(CancellationToken::new());
        let fixture = report_fixture(
            context.knowledge(),
            context.legacy_verification_subject().unwrap(),
            (LEGACY_SQL_ACTION_ID, LEGACY_SQL_ACTION_ID, "duplicate"),
            (VerificationStage::Active, OutcomeStatus::NeedsReview, true),
        );

        let error = context
            .record_legacy_verification_reports(vec![fixture.report.clone(), fixture.report])
            .unwrap_err();

        assert!(matches!(
            error,
            ScannerError::InvalidLegacyVerificationReport
        ));
        assert_eq!(context.legacy_verification_checkpoint(), 0);
    }

    #[test]
    fn verifier_report_replay_cannot_mutate_an_accepted_ledger() {
        let context = bridge_context(CancellationToken::new());
        let fixture = report_fixture(
            context.knowledge(),
            context.legacy_verification_subject().unwrap(),
            (TEST_ACTION_ID, TEST_ACTION_ID, "replay"),
            (VerificationStage::Active, OutcomeStatus::NeedsReview, true),
        );

        context
            .record_legacy_verification_reports(vec![fixture.report.clone()])
            .unwrap();
        let accepted = context.legacy_verification_outcomes_since(0);
        let error = context
            .record_legacy_verification_reports(vec![fixture.report])
            .unwrap_err();

        assert!(matches!(
            error,
            ScannerError::InvalidLegacyVerificationReport
        ));
        assert_eq!(context.legacy_verification_outcomes_since(0), accepted);
    }

    #[test]
    fn cancellation_before_verifier_commit_leaves_ledger_empty() {
        let cancellation = CancellationToken::new();
        let context = bridge_context(cancellation.clone());
        let fixture = report_fixture(
            context.knowledge(),
            context.legacy_verification_subject().unwrap(),
            (TEST_ACTION_ID, TEST_ACTION_ID, "cancelled"),
            (VerificationStage::Active, OutcomeStatus::NeedsReview, true),
        );
        cancellation.cancel();

        let error = context
            .record_legacy_verification_reports(vec![fixture.report])
            .unwrap_err();

        assert!(matches!(error, ScannerError::Cancelled));
        assert_eq!(context.legacy_verification_checkpoint(), 0);
    }

    #[test]
    fn expired_verification_deadline_leaves_ledger_empty() {
        let (tx, _) = tokio::sync::mpsc::unbounded_channel();
        let limits = VerificationLimits::new()
            .with_max_wall_time(Duration::from_millis(1))
            .unwrap();
        let context = ScanContext::new_with_verification_limits(
            Url::parse("https://example.test/").unwrap(),
            Client::new(),
            tx,
            limits,
        );
        let fixture = report_fixture(
            context.knowledge(),
            context.legacy_verification_subject().unwrap(),
            (TEST_ACTION_ID, TEST_ACTION_ID, "deadline"),
            (VerificationStage::Active, OutcomeStatus::NeedsReview, true),
        );
        context
            .ensure_legacy_verification_commit(TEST_ACTION_ID)
            .unwrap();
        std::thread::sleep(Duration::from_millis(5));

        let error = context
            .record_legacy_verification_reports(vec![fixture.report])
            .unwrap_err();

        assert!(matches!(error, ScannerError::BudgetExceeded(_)));
        assert_eq!(context.legacy_verification_checkpoint(), 0);
    }

    #[tokio::test]
    async fn test_add_endpoint_zero_copy() {
        let (tx, _) = tokio::sync::mpsc::unbounded_channel();
        let url = Url::parse("http://example.com").unwrap();
        let client = Client::new();
        let ctx = ScanContext::new(url, client, tx);

        ctx.add_endpoint(
            "/api/users".to_string(),
            vec!["id".to_string(), "email".to_string()],
        );
        assert_eq!(ctx.endpoint_count(), 2);

        let endpoints = ctx.discovered_endpoints.clone();
        assert!(endpoints.contains_key("/api/users"));
        let snapshot = ctx.discovery_snapshot();
        let canonical = "http://example.com/api/users";
        assert_eq!(
            snapshot.endpoints()[canonical],
            std::collections::BTreeSet::from(["email".to_owned(), "id".to_owned()]),
            "relative public host seeds remain visible to migrated phases"
        );
    }

    #[tokio::test]
    async fn public_endpoint_seed_derives_existing_query_names() {
        let (tx, _) = tokio::sync::mpsc::unbounded_channel();
        let target = Url::parse("http://example.com/").unwrap();
        let ctx = ScanContext::new(target, Client::new(), tx);

        ctx.add_endpoint("/search?q=known&mode=safe".to_owned(), Vec::new());

        let snapshot = ctx.discovery_snapshot();
        assert_eq!(
            snapshot.endpoints()["http://example.com/search?mode=safe&q=known"],
            std::collections::BTreeSet::from(["mode".to_owned(), "q".to_owned()])
        );
    }

    #[tokio::test]
    async fn test_visited_urls_concurrent() {
        let (tx, _) = tokio::sync::mpsc::unbounded_channel();
        let url = Url::parse("http://example.com").unwrap();
        let client = Client::new();
        let ctx = ScanContext::new(url, client, tx);

        ctx.mark_visited("http://example.com/page1".to_string());
        assert!(ctx.is_visited("http://example.com/page1"));
        assert!(!ctx.is_visited("http://example.com/page2"));
    }
}
