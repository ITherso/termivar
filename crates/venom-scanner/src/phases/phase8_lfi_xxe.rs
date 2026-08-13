//! # Phase 8: opt-in local-file canary verification
//!
//! There are no default file-system probes. A host may opt in by placing a
//! benign, scan-specific canary file on an authorized fixture and configuring
//! two independent version-four UUIDs: one identifies the file name and the
//! other identifies its expected contents. The contents must be absent from a
//! baseline and a randomized missing-file control, then present in two exact
//! canary replays.
//!
//! XXE remains quarantined. The shared legacy authority currently supports
//! only bodyless discovery requests and has no trusted callback receipt
//! provider. Sending an XML or OOB probe would therefore be only a dispatch
//! receipt, not evidence sufficient for an XXE claim, and this phase does
//! neither.

use std::fmt;

use async_trait::async_trait;
use url::Url;
use uuid::{Uuid, Version};
use venom_core::{
    ConfidenceScore, Evidence, EvidenceId, EvidenceKind, EvidenceSource, EvidenceValue, Hypothesis,
    KnowledgePredicate, OutcomeStatus, Probability, VerificationStage,
};

use crate::{
    context::ScanContext,
    contracts::{ScanFinding, ScanPhase},
    error::ScannerError,
    http_evidence::HttpProbeMethod,
    legacy_discovery::BoundedHttpResponse,
    rules::{Expression, KnowledgeLayer},
    verification::{ActiveVerifier, VerificationCase, VerificationReport, VerificationRule},
};

const LFI_CANARY_ACTION_ID: &str = "legacy.verification.local-file-canary";
const LFI_FILE_PREFIX: &str = "venom-lfi-canary-";
const LFI_CONTROL_PREFIX: &str = "venom-lfi-missing-control-";
const LFI_MARKER_PREFIX: &str = "VENOM_LFI_CANARY_CONTENT_";
const LFI_EVIDENCE_NAMESPACE: &str = "legacy.lfi-canary";
const LFI_EVIDENCE_NAME: &str = "bounded-four-leg-observation";
const LFI_AUDIT_NAMESPACE: &str = "legacy.audit";
const LFI_AUDIT_NAME: &str = "manual-review-anchor";
const LFI_EVIDENCE_ID: &str = "legacy.lfi-canary.evidence";
const LFI_CASE_ID: &str = "legacy.lfi-canary.case";
const LFI_HYPOTHESIS_ID: &str = "legacy.lfi-canary.audit-anchor";
const LFI_RULE_ID: &str = "legacy.verify.lfi-canary.needs-review";
const LFI_RULE_RATIONALE: &str =
    "A bounded host-provisioned canary comparison produced a reproducible manual-review observation";
const MAX_LFI_CANARY_REQUESTS: usize = 16;
const LFI_REQUESTS_PER_PARAMETER: usize = 4;

#[derive(Clone, PartialEq, Eq)]
struct LfiCanary {
    file_name: String,
    expected_marker: String,
}

impl LfiCanary {
    fn new(file_id: Uuid, content_id: Uuid) -> Result<Self, ScannerError> {
        if file_id == content_id || !is_random_uuid(file_id) || !is_random_uuid(content_id) {
            return Err(ScannerError::PayloadGenerationError(
                "LFI canary requires two distinct version-four UUIDs".to_owned(),
            ));
        }
        Ok(Self {
            file_name: format!("{LFI_FILE_PREFIX}{}.txt", file_id.simple()),
            expected_marker: format!("{LFI_MARKER_PREFIX}{}", content_id.simple()),
        })
    }
}

fn is_random_uuid(value: Uuid) -> bool {
    value.get_version() == Some(Version::Random) && !value.is_nil()
}

/// Legacy phase-eight observer with risky probes disabled by default.
#[derive(Clone)]
pub struct LfiXxeScanner {
    // Retained for pre-1.0 source compatibility. A destination without a
    // trusted nonce-correlated callback provider grants no verification
    // authority and is never contacted.
    oob_domain: Option<String>,
    lfi_canary: Option<LfiCanary>,
}

impl fmt::Debug for LfiXxeScanner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LfiXxeScanner")
            .field("oob_domain_configured", &self.oob_domain.is_some())
            .field("lfi_canary_configured", &self.lfi_canary.is_some())
            .finish()
    }
}

impl LfiXxeScanner {
    /// Creates the quarantined default: no LFI or XXE requests are sent.
    pub const fn new() -> Self {
        Self {
            oob_domain: None,
            lfi_canary: None,
        }
    }

    /// Retains the historical configuration shape without treating a
    /// destination string as callback proof.
    ///
    /// No callback is contacted and no XXE request is dispatched. A future
    /// callback-capable API must accept a trusted verifier that returns a
    /// nonce-correlated receipt before it can support an OOB conclusion.
    pub fn with_oob_domain(oob_domain: String) -> Self {
        Self {
            oob_domain: Some(oob_domain),
            lfi_canary: None,
        }
    }

    /// Enables verification with a benign host-provisioned canary.
    ///
    /// The authorized fixture must expose the file through the tested query
    /// parameter while the file body contains exactly
    /// `VENOM_LFI_CANARY_CONTENT_<content UUID without hyphens>`. The UUIDs
    /// must be distinct version-four values so neither the requested name nor
    /// ordinary baseline text can predict the file-specific marker.
    pub fn with_lfi_canary(file_id: Uuid, content_id: Uuid) -> Result<Self, ScannerError> {
        Ok(Self {
            oob_domain: None,
            lfi_canary: Some(LfiCanary::new(file_id, content_id)?),
        })
    }
}

impl Default for LfiXxeScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScanPhase for LfiXxeScanner {
    fn phase_number(&self) -> u8 {
        8
    }

    fn name(&self) -> &'static str {
        "File Canary Observer"
    }

    async fn execute(&self, ctx: &ScanContext) -> Result<Vec<ScanFinding>, ScannerError> {
        if self.oob_domain.is_some() {
            ctx.log(
                "Phase 8: XXE OOB configuration is quarantined because no trusted nonce-correlated callback verifier is configured"
                    .to_owned(),
            );
        }
        let Some(canary) = &self.lfi_canary else {
            ctx.log(
                "Phase 8: no benign local-file canary configured; no LFI or XXE probes dispatched"
                    .to_owned(),
            );
            return Ok(Vec::new());
        };

        ctx.log("Phase 8: bounded local-file canary verification initiated".to_owned());
        let snapshot = ctx.discovery_snapshot();
        let mut accepted = Vec::new();
        let mut requests = 0_usize;

        'endpoints: for (endpoint, parameters) in snapshot.endpoints() {
            let endpoint = ctx.canonicalize_discovery_url(&Url::parse(endpoint)?)?;
            for parameter in parameters {
                if MAX_LFI_CANARY_REQUESTS.saturating_sub(requests) < LFI_REQUESTS_PER_PARAMETER {
                    break 'endpoints;
                }
                if observe_lfi_canary(ctx, &endpoint, parameter, canary).await? {
                    accepted.push((endpoint.clone(), parameter.clone()));
                }
                requests += LFI_REQUESTS_PER_PARAMETER;
            }
        }

        // Recheck cancellation and the monotonic verification deadline after
        // the complete probe set and before the first knowledge/report write.
        ctx.ensure_legacy_verification_commit(LFI_CANARY_ACTION_ID)?;
        let reports = lfi_manual_review_reports(ctx, accepted.len())?;
        ctx.record_legacy_verification_reports(reports)?;
        let findings = accepted
            .into_iter()
            .map(|(endpoint, parameter)| ScanFinding {
                phase: self.phase_number(),
                module_name: self.name().to_owned(),
                severity: "INFO".to_owned(),
                description: format!(
                    "A bounded four-leg comparison for parameter '{parameter}' reproduced the independently marked contents of a host-provisioned local-file canary. This observation requires manual review and does not establish LFI."
                ),
                evidence: format!(
                    "endpoint={}; benign_canary_observed=true; randomized_missing_file_control=true; exact_replay=true; response_truncated=false",
                    endpoint_subject(&endpoint)
                ),
            })
            .collect::<Vec<_>>();

        ctx.log(format!(
            "Phase 8: local-file canary verification completed with {} INFO observations across {} requests; XXE remained quarantined",
            findings.len(), requests
        ));
        Ok(findings)
    }
}

async fn observe_lfi_canary(
    ctx: &ScanContext,
    endpoint: &Url,
    parameter: &str,
    canary: &LfiCanary,
) -> Result<bool, ScannerError> {
    let control_file = format!("{LFI_CONTROL_PREFIX}{}.txt", Uuid::new_v4().simple());
    let baseline = ctx
        .verification_request(LFI_CANARY_ACTION_ID, HttpProbeMethod::Get, endpoint.clone())
        .await?;
    let control = ctx
        .verification_request(
            LFI_CANARY_ACTION_ID,
            HttpProbeMethod::Get,
            replace_query_parameter(endpoint, parameter, &control_file),
        )
        .await?;
    let candidate_url = replace_query_parameter(endpoint, parameter, &canary.file_name);
    let candidate = ctx
        .verification_request(
            LFI_CANARY_ACTION_ID,
            HttpProbeMethod::Get,
            candidate_url.clone(),
        )
        .await?;
    let reproduction = ctx
        .verification_request(LFI_CANARY_ACTION_ID, HttpProbeMethod::Get, candidate_url)
        .await?;

    Ok(file_canary_observed(
        &baseline,
        &control,
        &candidate,
        &reproduction,
        &canary.expected_marker,
    ))
}

fn file_canary_observed(
    baseline: &BoundedHttpResponse,
    control: &BoundedHttpResponse,
    candidate: &BoundedHttpResponse,
    reproduction: &BoundedHttpResponse,
    marker: &str,
) -> bool {
    ![baseline, control, candidate, reproduction]
        .into_iter()
        .any(|response| response.body_truncated() || !(200..300).contains(&response.status()))
        && !body_contains(baseline.body(), marker)
        && !body_contains(control.body(), marker)
        && !body_contains(baseline.body(), LFI_MARKER_PREFIX)
        && !body_contains(control.body(), LFI_MARKER_PREFIX)
        && body_contains(candidate.body(), marker)
        && body_contains(reproduction.body(), marker)
        && candidate.status() == reproduction.status()
        && candidate.content_type() == reproduction.content_type()
        && candidate.body() == reproduction.body()
}

fn lfi_manual_review_reports(
    ctx: &ScanContext,
    accepted_signals: usize,
) -> Result<Vec<VerificationReport>, ScannerError> {
    if accepted_signals == 0 {
        return Ok(Vec::new());
    }

    let subject = ctx.legacy_verification_subject()?;
    let evidence_predicate = lfi_evidence_predicate()?;
    let audit_predicate = KnowledgePredicate::new(LFI_AUDIT_NAMESPACE, LFI_AUDIT_NAME)
        .map_err(|_| legacy_report_error())?;
    let hypothesis = Hypothesis::with_id(
        LFI_HYPOTHESIS_ID,
        subject.clone(),
        audit_predicate,
        EvidenceValue::Text("local-file-canary-manual-review".to_owned()),
        Probability::from_percent(50).map_err(|_| legacy_report_error())?,
    )
    .map_err(|_| legacy_report_error())?;
    ctx.knowledge()
        .upsert_hypothesis(hypothesis)
        .map_err(|_| legacy_report_error())?;
    let baseline = ctx.knowledge().snapshot_for_subject(&subject);
    let source = EvidenceSource::new(LFI_CANARY_ACTION_ID, "bounded-four-leg-comparison")
        .and_then(|source| source.with_correlation_id(LFI_CASE_ID))
        .map_err(|_| legacy_report_error())?;
    let evidence = Evidence::with_id_at(
        EvidenceId::parse(LFI_EVIDENCE_ID).map_err(|_| legacy_report_error())?,
        subject.clone(),
        EvidenceKind::Custom("legacy-verification".to_owned()),
        evidence_predicate.clone(),
        EvidenceValue::Boolean(true),
        source,
        ConfidenceScore::MAX,
        0,
    );
    let write = ctx
        .knowledge()
        .insert_evidence(evidence)
        .map_err(|_| legacy_report_error())?;
    if write == crate::knowledge::KnowledgeWrite::Unchanged {
        // The immutable signal was already recorded before this active stage,
        // so it cannot be presented as fresh evidence for a second outcome or
        // silently downgraded to an unresolved raw observation.
        return Err(ScannerError::InvalidLegacyVerificationReport);
    }
    let after_probe = ctx.knowledge().snapshot_for_subject(&subject);
    let verifier = lfi_active_verifier(evidence_predicate)?;
    let case = VerificationCase::new(
        LFI_CASE_ID,
        subject,
        LFI_CANARY_ACTION_ID,
        LFI_HYPOTHESIS_ID,
    )
    .map_err(|_| legacy_report_error())?
    .without_hypothesis_transition();
    let report = verifier
        .verify_snapshots(&case, &baseline, &after_probe)
        .map_err(|_| legacy_report_error())?;
    Ok(vec![report])
}

fn lfi_active_verifier(
    evidence_predicate: KnowledgePredicate,
) -> Result<ActiveVerifier, ScannerError> {
    let mut verifier = ActiveVerifier::new();
    let rule = VerificationRule::new(
        LFI_RULE_ID,
        VerificationStage::Active,
        100,
        Expression::equals(
            KnowledgeLayer::Evidence,
            evidence_predicate,
            EvidenceValue::Boolean(true),
        ),
        OutcomeStatus::NeedsReview,
        Probability::from_percent(95).map_err(|_| legacy_report_error())?,
        LFI_RULE_RATIONALE,
    )
    .map_err(|_| legacy_report_error())?
    .scoped_to_action(LFI_CANARY_ACTION_ID)
    .map_err(|_| legacy_report_error())?
    .with_case_correlated_evidence()
    .map_err(|_| legacy_report_error())?;
    verifier.register(rule).map_err(|_| legacy_report_error())?;
    Ok(verifier)
}

fn lfi_evidence_predicate() -> Result<KnowledgePredicate, ScannerError> {
    KnowledgePredicate::new(LFI_EVIDENCE_NAMESPACE, LFI_EVIDENCE_NAME)
        .map_err(|_| legacy_report_error())
}

fn legacy_report_error() -> ScannerError {
    ScannerError::InvalidLegacyVerificationReport
}

fn replace_query_parameter(endpoint: &Url, name: &str, value: &str) -> Url {
    let retained = endpoint
        .query_pairs()
        .filter(|(existing, _)| existing != name)
        .map(|(existing, value)| (existing.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    let mut mutated = endpoint.clone();
    mutated
        .query_pairs_mut()
        .clear()
        .extend_pairs(retained)
        .append_pair(name, value);
    mutated
}

fn body_contains(body: &[u8], needle: &str) -> bool {
    !needle.is_empty()
        && body
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
}

fn endpoint_subject(endpoint: &Url) -> String {
    let mut subject = endpoint.clone();
    subject.set_query(None);
    subject.set_fragment(None);
    subject.to_string()
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use std::time::Duration;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
    };

    use super::*;
    use crate::{legacy_discovery::VerificationLimits, runner::ScanRunner};
    use venom_core::{HypothesisState, HypothesisStrength, SecuritySeverity};

    struct LocalFixture {
        target: Url,
        requests: Arc<AtomicUsize>,
        task: JoinHandle<()>,
    }

    impl Drop for LocalFixture {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn serve_fixture(
        max_requests: usize,
        handler: impl Fn(&Url) -> String + Send + Sync + 'static,
    ) -> LocalFixture {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let observed_requests = Arc::clone(&requests);
        let handler = Arc::new(handler);
        let task = tokio::spawn(async move {
            for _ in 0..max_requests {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut chunk = [0_u8; 1_024];
                    let read = stream.read(&mut chunk).await.unwrap();
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                    assert!(request.len() <= 16 * 1_024);
                }
                observed_requests.fetch_add(1, Ordering::SeqCst);
                let request_target = String::from_utf8_lossy(&request)
                    .lines()
                    .next()
                    .and_then(|line| line.split_ascii_whitespace().nth(1))
                    .unwrap()
                    .to_owned();
                let url = Url::parse(&format!("http://fixture{request_target}")).unwrap();
                let body = handler(&url);
                let wire = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(), body
                );
                stream.write_all(wire.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });

        LocalFixture {
            target: Url::parse(&format!("http://{address}/include?file=default.txt")).unwrap(),
            requests,
            task,
        }
    }

    fn scan_context(target: Url) -> ScanContext {
        let limits = VerificationLimits::new()
            .with_max_requests(8)
            .unwrap()
            .with_request_timeout(Duration::from_secs(1))
            .unwrap()
            .with_max_wall_time(Duration::from_secs(10))
            .unwrap()
            .with_body_limits(64 * 1_024, 16 * 1_024)
            .unwrap();
        let (telemetry, _receiver) = tokio::sync::mpsc::unbounded_channel();
        ScanContext::new_with_verification_limits(target, reqwest::Client::new(), telemetry, limits)
    }

    fn last_parameter(url: &Url, name: &str) -> Option<String> {
        url.query_pairs()
            .filter(|(parameter, _)| parameter == name)
            .map(|(_, value)| value.into_owned())
            .last()
    }

    #[test]
    fn phase_identity_and_quarantined_default_are_stable() {
        let scanner = LfiXxeScanner::new();
        assert_eq!(scanner.phase_number(), 8);
        assert_eq!(scanner.name(), "File Canary Observer");
        assert!(scanner.lfi_canary.is_none());
        assert!(scanner.oob_domain.is_none());
    }

    #[test]
    fn canary_requires_distinct_random_uuids() {
        let random = Uuid::new_v4();
        assert!(LfiXxeScanner::with_lfi_canary(random, random).is_err());
        assert!(LfiXxeScanner::with_lfi_canary(Uuid::nil(), Uuid::new_v4()).is_err());

        let scanner = LfiXxeScanner::with_lfi_canary(Uuid::new_v4(), Uuid::new_v4()).unwrap();
        let canary = scanner.lfi_canary.unwrap();
        assert!(canary.file_name.starts_with(LFI_FILE_PREFIX));
        assert!(canary.expected_marker.starts_with(LFI_MARKER_PREFIX));
        assert!(!canary.file_name.contains(&canary.expected_marker));
    }

    #[test]
    fn debug_output_redacts_canary_and_oob_configuration_values() {
        let file_id = Uuid::new_v4();
        let content_id = Uuid::new_v4();
        let scanner = LfiXxeScanner::with_lfi_canary(file_id, content_id).unwrap();
        let debug = format!("{scanner:?}");
        assert!(debug.contains("lfi_canary_configured: true"));
        assert!(!debug.contains(&file_id.simple().to_string()));
        assert!(!debug.contains(&content_id.simple().to_string()));

        let oob = LfiXxeScanner::with_oob_domain("private-callback.example".to_owned());
        let debug = format!("{oob:?}");
        assert!(debug.contains("oob_domain_configured: true"));
        assert!(!debug.contains("private-callback.example"));
    }

    #[tokio::test]
    async fn default_and_oob_compatibility_configuration_dispatch_nothing() {
        let fixture = serve_fixture(0, |_| unreachable!()).await;
        let context = scan_context(fixture.target.clone());

        assert!(LfiXxeScanner::new()
            .execute(&context)
            .await
            .unwrap()
            .is_empty());
        assert!(LfiXxeScanner::with_oob_domain("unused.invalid".to_owned())
            .execute(&context)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn independent_host_canary_is_observed_on_local_fixture() {
        let file_id = Uuid::new_v4();
        let content_id = Uuid::new_v4();
        let canary = LfiCanary::new(file_id, content_id).unwrap();
        let file_name = canary.file_name.clone();
        let expected_marker = canary.expected_marker.clone();
        let fixture = serve_fixture(4, move |url| {
            if last_parameter(url, "file").as_deref() == Some(&file_name) {
                expected_marker.clone()
            } else {
                "ordinary fixture response without a local-file marker".to_owned()
            }
        })
        .await;
        let context = scan_context(fixture.target.clone());
        let scanner = LfiXxeScanner::with_lfi_canary(file_id, content_id).unwrap();

        let findings = scanner.execute(&context).await.unwrap();

        assert_eq!(fixture.requests.load(Ordering::SeqCst), 4);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "INFO");
        assert!(findings[0].description.contains("host-provisioned"));
        assert!(findings[0].description.contains("manual review"));
        assert!(findings[0].description.contains("does not establish LFI"));
        assert!(!findings[0].evidence.contains(&canary.expected_marker));
    }

    #[tokio::test]
    async fn runner_projects_one_verifier_owned_needs_review_record() {
        let file_id = Uuid::new_v4();
        let content_id = Uuid::new_v4();
        let canary = LfiCanary::new(file_id, content_id).unwrap();
        let file_name = canary.file_name.clone();
        let expected_marker = canary.expected_marker.clone();
        let fixture = serve_fixture(4, move |url| {
            if last_parameter(url, "file").as_deref() == Some(&file_name) {
                expected_marker.clone()
            } else {
                "ordinary fixture response without a local-file marker".to_owned()
            }
        })
        .await;
        let context = scan_context(fixture.target.clone());
        let retained_context = context.clone();
        let mut runner = ScanRunner::new();
        runner.register_phase(Box::new(
            LfiXxeScanner::with_lfi_canary(file_id, content_id).unwrap(),
        ));

        let report = runner.run_pipeline(context).await.unwrap();

        assert_eq!(report.outcomes().len(), 1);
        let observation = &report.outcomes()[0];
        assert_eq!(observation.severity(), SecuritySeverity::Info);
        assert_eq!(observation.disposition(), OutcomeStatus::NeedsReview);
        assert_eq!(
            observation.evidence_ids().iter().next().unwrap().as_str(),
            LFI_EVIDENCE_ID
        );
        let verified = observation.verification_outcome().unwrap();
        assert_eq!(verified.stage(), VerificationStage::Active);
        assert_eq!(verified.status(), OutcomeStatus::NeedsReview);
        assert_eq!(verified.verifier_rule_id(), Some(LFI_RULE_ID));
        assert_eq!(verified.evidence_ids(), observation.evidence_ids());

        let evidence = retained_context
            .knowledge()
            .evidence(&EvidenceId::parse(LFI_EVIDENCE_ID).unwrap())
            .unwrap();
        assert_eq!(evidence.value(), &EvidenceValue::Boolean(true));
        assert_eq!(evidence.observed_at_ms(), 0);
        assert_eq!(evidence.source().correlation_id(), Some(LFI_CASE_ID));
        let anchor = retained_context
            .knowledge()
            .hypothesis(LFI_HYPOTHESIS_ID)
            .unwrap();
        assert_eq!(anchor.state(), HypothesisState::Proposed);
        assert_eq!(anchor.strength(), HypothesisStrength::Weak);

        let typed = serde_json::to_string(observation).unwrap();
        assert!(!typed.contains(&file_id.simple().to_string()));
        assert!(!typed.contains(&content_id.simple().to_string()));
        assert!(!typed.contains("/include"));
        assert!(!typed.contains("default.txt"));
    }

    #[tokio::test]
    async fn equivalent_canaries_produce_the_same_typed_fingerprint() {
        let first_file_id = Uuid::new_v4();
        let first_content_id = Uuid::new_v4();
        let first = LfiCanary::new(first_file_id, first_content_id).unwrap();
        let second_file_id = Uuid::new_v4();
        let second_content_id = Uuid::new_v4();
        let second = LfiCanary::new(second_file_id, second_content_id).unwrap();
        let first_file = first.file_name.clone();
        let first_marker = first.expected_marker.clone();
        let second_file = second.file_name.clone();
        let second_marker = second.expected_marker.clone();
        let fixture = serve_fixture(8, move |url| {
            let value = last_parameter(url, "file").unwrap();
            if value == first_file {
                first_marker.clone()
            } else if value == second_file {
                second_marker.clone()
            } else {
                "ordinary fixture response without a local-file marker".to_owned()
            }
        })
        .await;

        let mut first_runner = ScanRunner::new();
        first_runner.register_phase(Box::new(
            LfiXxeScanner::with_lfi_canary(first_file_id, first_content_id).unwrap(),
        ));
        let first_report = first_runner
            .run_pipeline(scan_context(fixture.target.clone()))
            .await
            .unwrap();
        let mut second_runner = ScanRunner::new();
        second_runner.register_phase(Box::new(
            LfiXxeScanner::with_lfi_canary(second_file_id, second_content_id).unwrap(),
        ));
        let second_report = second_runner
            .run_pipeline(scan_context(fixture.target.clone()))
            .await
            .unwrap();

        assert_eq!(first_report.outcomes().len(), 1);
        assert_eq!(second_report.outcomes().len(), 1);
        assert_eq!(
            first_report.outcomes()[0].fingerprint(),
            second_report.outcomes()[0].fingerprint()
        );
    }

    #[tokio::test]
    async fn ordinary_localhost_text_and_single_leg_marker_are_not_lfi_proof() {
        let file_id = Uuid::new_v4();
        let content_id = Uuid::new_v4();
        let canary = LfiCanary::new(file_id, content_id).unwrap();
        let file_name = canary.file_name.clone();
        let expected_marker = canary.expected_marker.clone();
        let candidate_count = Arc::new(AtomicUsize::new(0));
        let observed_candidate_count = Arc::clone(&candidate_count);
        let fixture = serve_fixture(4, move |url| {
            let value = last_parameter(url, "file").unwrap();
            if value == file_name && observed_candidate_count.fetch_add(1, Ordering::SeqCst) == 0 {
                expected_marker.clone()
            } else {
                "127.0.0.1 localhost ordinary application text".to_owned()
            }
        })
        .await;
        let context = scan_context(fixture.target.clone());
        let scanner = LfiXxeScanner::with_lfi_canary(file_id, content_id).unwrap();

        let findings = scanner.execute(&context).await.unwrap();

        assert!(findings.is_empty());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 4);
    }
}
