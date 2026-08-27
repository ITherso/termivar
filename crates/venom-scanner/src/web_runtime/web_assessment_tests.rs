use std::{
    collections::{BTreeMap, BTreeSet},
    future::pending,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{Mutex, Notify},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use url::Url;
use venom_core::{ConfidenceScore, EntityId, KnowledgePredicate};

use super::*;
use crate::web_runtime::assessment_defense::{
    CommittedAssessmentDefenseLedger, ASSESSMENT_DEFENSE_NAMESPACE,
};
use crate::{
    defense::MAX_FINGERPRINT_BODY_SCAN_BYTES,
    http_evidence::{
        complete_http_response_observation_for_test, CompleteHttpResponseObservationTestInput,
    },
    HttpBodyCapture, HttpEvidencePolicy, KnowledgeWrite, RuntimeBudgetDimension,
    SemanticEntityType, TransportDispatchOutcome, DEFAULT_MAX_CONSECUTIVE_NO_PROGRESS_TURNS,
    DEFAULT_MAX_REQUEST_BODY_BYTES, DEFAULT_MAX_SAME_ACTION_ATTEMPTS,
};

#[test]
fn defense_mode_is_explicit_and_defaults_to_observation_only() {
    let target = Url::parse("https://example.test/").unwrap();
    let observed = WebAssessmentRuntime::builder(target.clone())
        .build()
        .unwrap();
    assert_eq!(
        observed.defense_audit.mode(),
        WebAssessmentDefenseMode::ObservationOnly
    );

    let enforced = WebAssessmentRuntime::builder(target)
        .enable_defense_enforcement()
        .build()
        .unwrap();
    assert_eq!(
        enforced.defense_audit.mode(),
        WebAssessmentDefenseMode::Enforced
    );
}

#[tokio::test]
async fn default_defense_audit_replays_committed_receipts_without_enforcement() {
    let server = serve(|_| {
        FixtureReply::Response(
            FixtureResponse::new(
                "403 Forbidden",
                Some("text/html"),
                "<html><body>blocked</body></html>",
            )
            .with_header("CF-Ray", "fixed-fixture-id")
            .with_header("Set-Cookie", "laravel_session=secret; HttpOnly")
            .with_header("Set-Cookie", "XSRF-TOKEN=secret"),
        )
    })
    .await;
    let mut runtime = WebAssessmentRuntime::builder(server.url("/root"))
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    assert_eq!(
        report.defense().mode(),
        WebAssessmentDefenseMode::ObservationOnly
    );
    assert!(!report.defense().observations().is_empty());
    assert!(report
        .defense()
        .observations()
        .iter()
        .all(|observation| observation.subject().as_str().starts_with("endpoint:")));
    assert!(report
        .defense()
        .shadow_plans()
        .iter()
        .all(|shadow| shadow.policy_authorized().subject() == shadow.shadow().subject()));
    assert!(report
        .defense()
        .shadow_plans()
        .iter()
        .any(|shadow| !shadow.delta().is_empty()));
    let actual_plans = actual_assessment_plans(&report);
    assert_eq!(actual_plans.len(), report.defense().shadow_plans().len());
    for (actual, shadow) in actual_plans
        .into_iter()
        .zip(report.defense().shadow_plans())
    {
        assert_eq!(actual, shadow.policy_authorized());
        let baseline_ids: Vec<_> = shadow
            .policy_authorized()
            .steps()
            .iter()
            .map(|step| step.action_id())
            .collect();
        assert!(shadow
            .shadow()
            .steps()
            .iter()
            .all(|step| baseline_ids.contains(&step.action_id())));
    }
    assert!(server.hit_count("/root").await >= 2);

    let bootstrap = report.subjects()[0].bootstrap().unwrap();
    let without_projection: Vec<_> = bootstrap
        .evidence()
        .iter()
        .filter(|evidence| evidence.predicate().namespace() != ASSESSMENT_DEFENSE_NAMESPACE)
        .cloned()
        .collect();
    let (knowledge, local_receipt) = receipt_with_committed_batch(bootstrap, without_projection);
    let mut replay = CommittedAssessmentDefenseLedger::default();
    assert!(replay
        .ingest_receipt(&local_receipt, &knowledge, false)
        .is_ok());
    let before = replay.clone();
    assert!(replay
        .ingest_receipt(&local_receipt, &knowledge, true)
        .is_err());
    assert_eq!(replay, before);
}

#[tokio::test]
async fn enforced_defense_plan_exactly_matches_public_shadow_and_suppresses() {
    let server = serve(|_| {
        FixtureReply::Response(
            FixtureResponse::new(
                "403 Forbidden",
                Some("text/html"),
                "<html><body>blocked</body></html>",
            )
            .with_header("CF-Ray", "fixed-fixture-id")
            .with_header("Set-Cookie", "laravel_session=secret; HttpOnly")
            .with_header("Set-Cookie", "XSRF-TOKEN=secret"),
        )
    })
    .await;
    let mut runtime = WebAssessmentRuntime::builder(server.url("/root"))
        .enable_defense_enforcement()
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();

    assert_eq!(report.defense().mode(), WebAssessmentDefenseMode::Enforced);
    let actual_plans = actual_assessment_plans(&report);
    assert!(!actual_plans.is_empty());
    assert_eq!(actual_plans.len(), report.defense().shadow_plans().len());
    for (actual, shadow) in actual_plans
        .into_iter()
        .zip(report.defense().shadow_plans())
    {
        assert_eq!(actual, shadow.shadow());
    }
    assert!(report
        .defense()
        .shadow_plans()
        .iter()
        .any(|shadow| !shadow.delta().suppressed().is_empty()));
    assert!(server.hit_count("/root").await >= 2);
}

#[tokio::test]
async fn public_defense_coverage_withholds_open_and_weak_hint_never_suppresses() {
    let mut root_body =
        b"<html><head><link href='/asset' rel='stylesheet'></head><body><a href='/weak'>weak</a>"
            .to_vec();
    root_body.resize(MAX_FINGERPRINT_BODY_SCAN_BYTES + 1, b'x');
    root_body.extend_from_slice(b"</body></html>");
    let server = serve(move |request| {
        let response = match request.path() {
            "/root" => FixtureResponse::html(root_body.clone()),
            "/weak" => FixtureResponse::html("<html><body>ok</body></html>")
                .with_header("X-Amzn-RequestId", "fixed-weak-hint")
                .with_header("Set-Cookie", "laravel_session=secret; HttpOnly")
                .with_header("Set-Cookie", "XSRF-TOKEN=secret"),
            _ => FixtureResponse::new("200 OK", Some("text/css"), "body{}"),
        };
        FixtureReply::Response(response)
    })
    .await;
    let mut runtime = WebAssessmentRuntime::builder(server.url("/root"))
        .enable_defense_enforcement()
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();

    let capped = defense_observation_for_path(&report, "/root");
    assert_eq!(
        capped.body_coverage(),
        WebAssessmentDefenseBodyCoverage::CompleteUtf8Prefix
    );
    assert!(capped.input_limit_reached());
    assert_eq!(capped.posture(), None);
    assert!(!capped.challenge_observed());
    assert!(!capped.rate_limit_observed());
    assert!(capped.fingerprint_hint().is_none());

    let metadata_only = defense_observation_for_path(&report, "/asset");
    assert_eq!(
        metadata_only.body_coverage(),
        WebAssessmentDefenseBodyCoverage::MetadataOnly
    );
    assert_eq!(metadata_only.posture(), None);
    assert!(!metadata_only.challenge_observed());
    assert!(!metadata_only.rate_limit_observed());
    assert!(metadata_only.fingerprint_hint().is_none());

    let weak = defense_observation_for_path(&report, "/weak");
    assert_eq!(
        weak.fingerprint_hint(),
        Some((DefenseProduct::AwsWaf, FingerprintConfidence::Weak))
    );
    assert_eq!(weak.posture(), Some(DefensePosture::Suspected));
    let weak_subject = weak.subject().clone();
    let weak_shadows: Vec<_> = report
        .defense()
        .shadow_plans()
        .iter()
        .filter(|shadow| shadow.policy_authorized().subject() == &weak_subject)
        .collect();
    assert!(!weak_shadows.is_empty());
    assert!(weak_shadows
        .iter()
        .all(|shadow| shadow.delta().suppressed().is_empty()));
    let requests = server.requests().await;
    assert!(requests
        .iter()
        .any(|request| request.path() == "/asset" && request.method == "HEAD"));
}

#[tokio::test]
async fn defense_ledger_is_idempotent_and_rejects_tampering_atomically() {
    let server =
        serve(|_| FixtureReply::Response(FixtureResponse::html("<html><body>ok</body></html>")))
            .await;
    let mut runtime = WebAssessmentRuntime::builder(server.url("/root"))
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    let bootstrap = report.subjects()[0].bootstrap().unwrap();

    let mut ledger = CommittedAssessmentDefenseLedger::default();
    assert!(ledger
        .ingest_receipt(bootstrap, runtime.knowledge(), true)
        .unwrap()
        .is_some());
    let committed = ledger.clone();
    assert!(ledger
        .ingest_receipt(bootstrap, runtime.knowledge(), true)
        .unwrap()
        .is_none());
    assert_eq!(ledger, committed);

    let mut reordered = bootstrap.evidence().to_vec();
    let method_index = reordered
        .iter()
        .position(|evidence| {
            evidence.predicate() == &HttpEvidencePredicate::REQUEST_METHOD.into_knowledge()
        })
        .unwrap();
    let url_index = reordered
        .iter()
        .position(|evidence| {
            evidence.predicate() == &HttpEvidencePredicate::REQUEST_URL.into_knowledge()
        })
        .unwrap();
    reordered.swap(method_index, url_index);
    let (reordered_knowledge, reordered_receipt) =
        receipt_with_committed_batch(bootstrap, reordered);
    let mut rejected = CommittedAssessmentDefenseLedger::default();
    let before = rejected.clone();
    assert!(rejected
        .ingest_receipt(&reordered_receipt, &reordered_knowledge, true)
        .is_err());
    assert_eq!(rejected, before);

    let mut defense_reordered = bootstrap.evidence().to_vec();
    let first_defense = defense_reordered
        .iter()
        .position(|evidence| evidence.predicate().namespace() == ASSESSMENT_DEFENSE_NAMESPACE)
        .unwrap();
    defense_reordered.swap(first_defense, first_defense + 1);
    let (defense_reordered_knowledge, defense_reordered_receipt) =
        receipt_with_committed_batch(bootstrap, defense_reordered);
    assert!(rejected
        .ingest_receipt(
            &defense_reordered_receipt,
            &defense_reordered_knowledge,
            true,
        )
        .is_err());
    assert_eq!(rejected, before);

    let mut direct_defense = bootstrap.evidence().to_vec();
    let original_defense = direct_defense[first_defense].clone();
    direct_defense[first_defense] = rebuild_evidence(
        &original_defense,
        original_defense.kind().clone(),
        original_defense.value().clone(),
        original_defense.source().clone(),
        EvidenceOrigin::Direct,
    );
    let (direct_defense_knowledge, direct_defense_receipt) =
        receipt_with_committed_batch(bootstrap, direct_defense);
    assert!(rejected
        .ingest_receipt(&direct_defense_receipt, &direct_defense_knowledge, true)
        .is_err());
    assert_eq!(rejected, before);

    let mut updated_writes = bootstrap.writes().to_vec();
    updated_writes[0] = KnowledgeWrite::Updated;
    let updated_receipt = bootstrap.with_test_committed_batch(
        bootstrap.evidence().to_vec(),
        updated_writes,
        bootstrap.after_execution().clone(),
    );
    assert!(rejected
        .ingest_receipt(&updated_receipt, runtime.knowledge(), true)
        .is_err());
    assert_eq!(rejected, before);

    assert!(rejected
        .ingest_receipt(bootstrap, &KnowledgeBase::new(), true)
        .is_err());
    assert_eq!(rejected, before);
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordedRequest {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
}

impl RecordedRequest {
    fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or(&self.target)
    }

    fn host(&self) -> &str {
        self.headers.get("host").map(String::as_str).unwrap_or("")
    }
}

#[derive(Clone)]
struct FixtureResponse {
    status: &'static str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl FixtureResponse {
    fn html(body: impl Into<Vec<u8>>) -> Self {
        Self::new("200 OK", Some("text/html"), body)
    }

    fn new(status: &'static str, media_type: Option<&str>, body: impl Into<Vec<u8>>) -> Self {
        let mut headers = Vec::new();
        if let Some(media_type) = media_type {
            headers.push(("Content-Type".to_owned(), media_type.to_owned()));
        }
        Self {
            status,
            headers,
            body: body.into(),
        }
    }

    fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    fn encode(&self, method: &str) -> Vec<u8> {
        let mut encoded = format!("HTTP/1.1 {}\r\n", self.status).into_bytes();
        for (name, value) in &self.headers {
            encoded.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        encoded.extend_from_slice(
            format!(
                "Content-Length: {}\r\nConnection: close\r\n\r\n",
                self.body.len()
            )
            .as_bytes(),
        );
        if method != "HEAD" {
            encoded.extend_from_slice(&self.body);
        }
        encoded
    }
}

#[derive(Clone)]
enum FixtureReply {
    Response(FixtureResponse),
    CloseWithoutResponse,
    Stall,
}

struct LocalServer {
    origin: Url,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    request_seen: Arc<Notify>,
    task: JoinHandle<()>,
}

impl LocalServer {
    fn url(&self, path: &str) -> Url {
        self.origin.join(path).expect("fixture path must be valid")
    }

    async fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().await.clone()
    }

    async fn hit_count(&self, path: &str) -> usize {
        self.requests()
            .await
            .iter()
            .filter(|request| request.path() == path)
            .count()
    }

    fn request_notification(&self) -> Arc<Notify> {
        self.request_seen.clone()
    }
}

impl Drop for LocalServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(
    handler: impl Fn(&RecordedRequest) -> FixtureReply + Send + Sync + 'static,
) -> LocalServer {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback fixture must bind");
    let address = listener.local_addr().expect("fixture address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = requests.clone();
    let request_seen = Arc::new(Notify::new());
    let notify = request_seen.clone();
    let handler = Arc::new(handler);
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let mut bytes = Vec::new();
            loop {
                let mut chunk = [0_u8; 1_024];
                let Ok(read) = stream.read(&mut chunk).await else {
                    break;
                };
                if read == 0 {
                    break;
                }
                bytes.extend_from_slice(&chunk[..read]);
                if bytes.windows(4).any(|window| window == b"\r\n\r\n") || bytes.len() >= 64 * 1_024
                {
                    break;
                }
            }
            let Some(request) = parse_request(&bytes) else {
                let _ = stream.shutdown().await;
                continue;
            };
            recorded.lock().await.push(request.clone());
            notify.notify_one();
            match handler(&request) {
                FixtureReply::Response(response) => {
                    let _ = stream.write_all(&response.encode(&request.method)).await;
                    let _ = stream.shutdown().await;
                },
                FixtureReply::CloseWithoutResponse => {
                    let _ = stream.shutdown().await;
                },
                FixtureReply::Stall => pending::<()>().await,
            }
        }
    });
    LocalServer {
        origin: Url::parse(&format!("http://{address}/")).expect("fixture URL"),
        requests,
        request_seen,
        task,
    }
}

fn parse_request(bytes: &[u8]) -> Option<RecordedRequest> {
    let request = String::from_utf8_lossy(bytes);
    let mut lines = request.split("\r\n");
    let mut request_line = lines.next()?.split_whitespace();
    let method = request_line.next()?.to_owned();
    let target = request_line.next()?.to_owned();
    let mut headers = BTreeMap::new();
    for line in lines.take_while(|line| !line.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
    }
    Some(RecordedRequest {
        method,
        target,
        headers,
    })
}

#[derive(Clone, Copy)]
struct TestObservationEnvelope<'a> {
    case_id: &'a str,
    action_id: &'a str,
    hypothesis_id: &'a str,
    has_payload_strategy: bool,
    applies_hypothesis_transition: bool,
    stage: DecisionExecutionStage,
    subject: &'a EntityId,
    method: HttpProbeMethod,
    requested_url: &'a Url,
}

impl<'a> TestObservationEnvelope<'a> {
    fn exact(subject: &'a EntityId, requested_url: &'a Url, method: HttpProbeMethod) -> Self {
        Self {
            case_id: BOOTSTRAP_CASE_ID,
            action_id: BOOTSTRAP_ACTION_ID,
            hypothesis_id: BOOTSTRAP_HYPOTHESIS_ID,
            has_payload_strategy: false,
            applies_hypothesis_transition: true,
            stage: DecisionExecutionStage::Passive,
            subject,
            method,
            requested_url,
        }
    }
}

struct TestObservationParents {
    request_method: EvidenceId,
    request_url: EvidenceId,
    response_status: EvidenceId,
    response_media_type: EvidenceId,
    response_body_truncated: EvidenceId,
    response_body_digest: EvidenceId,
}

impl TestObservationParents {
    fn new() -> Self {
        Self {
            request_method: EvidenceId::new(),
            request_url: EvidenceId::new(),
            response_status: EvidenceId::new(),
            response_media_type: EvidenceId::new(),
            response_body_truncated: EvidenceId::new(),
            response_body_digest: EvidenceId::new(),
        }
    }

    fn refs(&self, include_media: bool) -> TestObservationParentRefs<'_> {
        TestObservationParentRefs {
            request_method: Some(&self.request_method),
            request_url: Some(&self.request_url),
            response_status: Some(&self.response_status),
            response_media_type: include_media.then_some(&self.response_media_type),
            response_body_truncated: Some(&self.response_body_truncated),
            response_body_digest: Some(&self.response_body_digest),
        }
    }

    fn expected(&self, include_media: bool) -> Vec<EvidenceId> {
        let mut expected = vec![
            self.request_method.clone(),
            self.request_url.clone(),
            self.response_status.clone(),
            self.response_body_truncated.clone(),
            self.response_body_digest.clone(),
        ];
        if include_media {
            expected.push(self.response_media_type.clone());
        }
        expected.sort();
        expected
    }
}

#[derive(Clone, Copy)]
struct TestObservationParentRefs<'a> {
    request_method: Option<&'a EvidenceId>,
    request_url: Option<&'a EvidenceId>,
    response_status: Option<&'a EvidenceId>,
    response_media_type: Option<&'a EvidenceId>,
    response_body_truncated: Option<&'a EvidenceId>,
    response_body_digest: Option<&'a EvidenceId>,
}

fn observe_for_test(
    observer: &AssessmentDiscoveryObserver,
    envelope: TestObservationEnvelope<'_>,
    status: u16,
    media_type: Option<&str>,
    complete_body: Option<&[u8]>,
    parents: TestObservationParentRefs<'_>,
) -> Result<Vec<Evidence>, HttpEvidenceError> {
    observer.observe(complete_http_response_observation_for_test(
        CompleteHttpResponseObservationTestInput {
            case_id: envelope.case_id,
            action_id: envelope.action_id,
            hypothesis_id: envelope.hypothesis_id,
            has_payload_strategy: envelope.has_payload_strategy,
            applies_hypothesis_transition: envelope.applies_hypothesis_transition,
            stage: envelope.stage,
            subject: envelope.subject,
            method: envelope.method,
            requested_url: envelope.requested_url,
            status,
            media_type,
            reliability: ConfidenceScore::from_percent(100).unwrap(),
            complete_body,
            request_method_evidence_id: parents.request_method,
            request_url_evidence_id: parents.request_url,
            response_status_evidence_id: parents.response_status,
            response_media_type_evidence_id: parents.response_media_type,
            response_body_truncated_evidence_id: parents.response_body_truncated,
            response_body_digest_evidence_id: parents.response_body_digest,
        },
    ))
}

fn observer_fixture(
    url: Url,
    method: WebAssessmentMethod,
    cancellation: CancellationToken,
    deadline: Option<tokio::time::Instant>,
) -> (AssessmentDiscoveryObserver, WebAssessmentSubject, EntityId) {
    let limits = WebAssessmentLimits::default();
    let subject = WebAssessmentSubject {
        url: url.clone(),
        method,
        depth: 0,
        origin: WebAssessmentSubjectOrigin::AuthorizedRoot,
        query_parameter_names: Vec::new(),
        evidence_ids: Vec::new(),
    };
    let mut envelope = AssessmentLedger::new(&subject).snapshot(limits, subject.depth);
    envelope
        .subjects
        .get_mut(url.as_str())
        .expect("observer subject admission")
        .executed = true;
    let policy = HttpEvidencePolicy::for_origin(url.clone()).unwrap();
    let observer = AssessmentDiscoveryObserver::new(
        policy,
        limits,
        envelope,
        &subject,
        cancellation,
        deadline,
    );
    let entity = EntityId::new(format!("endpoint:{url}")).unwrap();
    (observer, subject, entity)
}

fn derivation_parents(evidence: &Evidence) -> &[EvidenceId] {
    evidence
        .origin()
        .derivation()
        .expect("discovery evidence must be derived")
        .parents()
}

fn rebuild_evidence(
    original: &Evidence,
    kind: EvidenceKind,
    value: EvidenceValue,
    source: EvidenceSource,
    origin: EvidenceOrigin,
) -> Evidence {
    let rebuilt = Evidence::with_id_at(
        original.id().clone(),
        original.subject().clone(),
        kind,
        original.predicate().clone(),
        value,
        source,
        original.reliability(),
        original.observed_at_ms(),
    );
    match origin {
        EvidenceOrigin::Derived(derivation) => rebuilt.derived_from(derivation),
        EvidenceOrigin::Direct => rebuilt,
        _ => unreachable!("test only handles known evidence origins"),
    }
}

fn source_with_method(original: &Evidence, method: &str) -> EvidenceSource {
    let source = EvidenceSource::new(original.source().component(), method).unwrap();
    match original.source().correlation_id() {
        Some(correlation_id) => source.with_correlation_id(correlation_id).unwrap(),
        None => source,
    }
}

fn receipt_with_committed_batch(
    template: &DecisionEvidenceReceipt,
    evidence: Vec<Evidence>,
) -> (KnowledgeBase, DecisionEvidenceReceipt) {
    let knowledge = KnowledgeBase::new();
    let writes = knowledge
        .insert_evidence_batch(evidence.clone())
        .expect("mutated test batch must be structurally committable");
    let after_execution = knowledge.snapshot_for_subject(template.case().subject());
    let receipt = template.with_test_committed_batch(evidence, writes, after_execution);
    (knowledge, receipt)
}

fn subject_path(report: &WebAssessmentSubjectReport) -> &str {
    report.subject().url().path()
}

fn actual_assessment_plans(report: &WebAssessmentRunReport) -> Vec<&AttackPlan> {
    report
        .subjects()
        .iter()
        .flat_map(WebAssessmentSubjectReport::turns)
        .filter_map(|turn| match turn {
            StandardWebDecisionRuntimeTurn::Planning(planning) => Some(planning.plan()),
            StandardWebDecisionRuntimeTurn::Outcome { .. } => None,
        })
        .collect()
}

fn defense_observation_for_path<'a>(
    report: &'a WebAssessmentRunReport,
    path: &str,
) -> &'a WebAssessmentDefenseObservation {
    report
        .defense()
        .observations()
        .iter()
        .find(|observation| observation.subject().as_str().contains(path))
        .unwrap_or_else(|| panic!("missing defense observation for {path}"))
}

fn public_subject_shape(
    report: &WebAssessmentSubjectReport,
) -> (String, WebAssessmentMethod, u16, Vec<String>) {
    (
        report.subject().url().path().to_owned(),
        report.subject().method(),
        report.subject().depth(),
        report.subject().query_parameter_names().to_vec(),
    )
}

fn assert_transport_reconciles(usage: WebAssessmentUsage, audit: &TransportDispatchAudit) {
    let audited = u64::try_from(audit.receipts().len())
        .unwrap_or(u64::MAX)
        .saturating_add(audit.omitted_receipt_count());
    assert_eq!(audited, u64::from(usage.total_requests()));
    for (sequence, receipt) in audit.receipts().iter().enumerate() {
        assert_eq!(receipt.sequence(), u64::try_from(sequence).unwrap());
    }
}

fn assert_report_reconciles(report: &WebAssessmentRunReport) {
    let usage = report.usage();
    assert_eq!(usage.retained_subjects(), report.subjects().len());
    assert_eq!(
        usage.executed_subjects(),
        report
            .subjects()
            .iter()
            .filter(|subject| subject.was_executed())
            .count()
    );
    assert_eq!(usage.retained_forms(), report.forms().len());
    assert_eq!(usage.request_body_bytes(), 0);
    assert_transport_reconciles(usage, report.transport());

    let unique_urls: BTreeSet<_> = report
        .subjects()
        .iter()
        .map(|subject| subject.subject().url().to_string())
        .chain(report.forms().iter().map(|form| form.action().to_string()))
        .collect();
    assert_eq!(
        usage.retained_unique_url_bytes(),
        unique_urls.iter().map(String::len).sum::<usize>()
    );
    assert!(report.subjects().windows(2).all(|pair| {
        let left = pair[0].subject();
        let right = pair[1].subject();
        (left.depth(), left.url().as_str()) <= (right.depth(), right.url().as_str())
    }));
    assert!(report.forms().windows(2).all(|pair| {
        (pair[0].action().as_str(), pair[0].method())
            <= (pair[1].action().as_str(), pair[1].method())
    }));

    match report.completion() {
        WebAssessmentCompletion::Complete => {
            assert!(report.completion().reasons().is_empty());
            assert!(report
                .subjects()
                .iter()
                .all(|subject| subject.was_executed()));
        },
        WebAssessmentCompletion::Incomplete { reasons } => {
            assert!(!reasons.is_empty());
        },
    }

    for subject in report.subjects() {
        let Some(bootstrap) = subject.bootstrap() else {
            continue;
        };
        let expected = format!("endpoint:{}", subject.subject().url());
        assert_eq!(bootstrap.case().subject().as_str(), expected);
        assert!(
            bootstrap
                .evidence()
                .iter()
                .all(|evidence| evidence.subject().as_str() == expected),
            "bootstrap evidence crossed subject boundary for {expected}"
        );
    }

    let debug = format!("{:?}", report.subjects());
    assert!(!debug.contains("TransportDispatchAudit"));
    assert!(!debug.contains("RuntimeUsage"));
}

fn assert_failure_reconciles(receipt: &WebAssessmentFailureReceipt) {
    assert!(receipt.inventory_consistent());
    assert_eq!(receipt.unrepresented_ledger_subjects(), 0);
    assert!(!receipt.incomplete_reasons().is_empty());
    let usage = receipt.usage();
    let retained = receipt
        .completed_subjects()
        .len()
        .saturating_add(1)
        .saturating_add(receipt.pending_subjects().len());
    assert_eq!(usage.retained_subjects(), retained);
    let executed = receipt
        .completed_subjects()
        .iter()
        .filter(|subject| subject.was_executed())
        .count()
        .saturating_add(usize::from(receipt.current_subject_report().was_executed()));
    assert_eq!(usage.executed_subjects(), executed);
    assert_eq!(usage.retained_forms(), receipt.forms().len());
    assert_eq!(usage.request_body_bytes(), 0);
    assert_transport_reconciles(usage, receipt.transport());

    let completed: BTreeSet<_> = receipt
        .completed_subjects()
        .iter()
        .map(|subject| subject.subject().url().to_string())
        .collect();
    let pending: BTreeSet<_> = receipt
        .pending_subjects()
        .iter()
        .map(|subject| subject.url().to_string())
        .collect();
    let current = receipt.current_subject().url().to_string();
    assert_eq!(completed.len(), receipt.completed_subjects().len());
    assert_eq!(pending.len(), receipt.pending_subjects().len());
    assert!(!completed.contains(&current));
    assert!(!pending.contains(&current));
    assert!(completed.is_disjoint(&pending));
    assert!(receipt.pending_subjects().windows(2).all(|pair| {
        (pair[0].depth(), pair[0].url().as_str()) <= (pair[1].depth(), pair[1].url().as_str())
    }));

    let unique_urls: BTreeSet<_> = completed
        .into_iter()
        .chain(std::iter::once(current))
        .chain(pending)
        .chain(receipt.forms().iter().map(|form| form.action().to_string()))
        .collect();
    assert_eq!(
        usage.retained_unique_url_bytes(),
        unique_urls.iter().map(String::len).sum::<usize>()
    );
    let debug = format!(
        "{:?}{:?}",
        receipt.completed_subjects(),
        receipt.current_subject_report()
    );
    assert!(!debug.contains("TransportDispatchAudit"));
    assert!(!debug.contains("RuntimeUsage"));
}

fn assert_no_secret(haystack: &str, secrets: &[&str]) {
    for secret in secrets {
        assert!(
            !haystack.contains(secret),
            "secret sentinel {secret:?} escaped into: {haystack}"
        );
    }
}

fn knowledge_debug(runtime: &WebAssessmentRuntime, report: &WebAssessmentRunReport) -> String {
    report
        .subjects()
        .iter()
        .map(|subject| {
            let id = EntityId::new(format!("endpoint:{}", subject.subject().url()))
                .expect("canonical endpoint identity");
            format!("{:?}", runtime.knowledge().snapshot_for_subject(&id))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn limits_defaults_and_compiled_ceilings_are_coherent() {
    let defaults = WebAssessmentLimits::default();
    assert_eq!(defaults.max_subjects(), DEFAULT_WEB_ASSESSMENT_MAX_SUBJECTS);
    assert_eq!(
        defaults.max_discovery_depth(),
        DEFAULT_WEB_ASSESSMENT_MAX_DEPTH
    );
    assert_eq!(
        defaults.max_references_per_document(),
        DEFAULT_WEB_ASSESSMENT_MAX_REFERENCES_PER_DOCUMENT
    );
    assert_eq!(
        defaults.max_canonical_url_bytes(),
        DEFAULT_WEB_ASSESSMENT_MAX_CANONICAL_URL_BYTES
    );
    assert_eq!(
        defaults.max_retained_url_bytes(),
        DEFAULT_WEB_ASSESSMENT_MAX_RETAINED_URL_BYTES
    );
    assert_eq!(defaults.max_forms(), DEFAULT_WEB_ASSESSMENT_MAX_FORMS);
    assert_eq!(
        defaults.max_controls_per_form(),
        DEFAULT_WEB_ASSESSMENT_MAX_CONTROLS_PER_FORM
    );
    assert_eq!(
        defaults.max_query_parameter_names(),
        DEFAULT_WEB_ASSESSMENT_MAX_QUERY_NAMES
    );
    assert_eq!(
        defaults.max_total_requests(),
        DEFAULT_WEB_ASSESSMENT_MAX_TOTAL_REQUESTS
    );
    assert_eq!(
        defaults.max_response_body_bytes(),
        DEFAULT_WEB_ASSESSMENT_MAX_RESPONSE_BODY_BYTES
    );
    assert_eq!(
        defaults.max_total_response_bytes(),
        DEFAULT_WEB_ASSESSMENT_MAX_TOTAL_RESPONSE_BYTES
    );
    assert_eq!(
        defaults.max_wall_time(),
        DEFAULT_WEB_ASSESSMENT_MAX_WALL_TIME
    );
    assert_eq!(
        defaults.max_active_verifications(),
        DEFAULT_WEB_ASSESSMENT_MAX_ACTIVE_VERIFICATIONS
    );
    assert_eq!(defaults.concurrency(), WEB_ASSESSMENT_CONCURRENCY);
    assert_eq!(WEB_ASSESSMENT_CONCURRENCY, 1);

    const {
        assert!(DEFAULT_WEB_ASSESSMENT_MAX_SUBJECTS <= HARD_MAX_WEB_ASSESSMENT_SUBJECTS);
        assert!(DEFAULT_WEB_ASSESSMENT_MAX_DEPTH <= HARD_MAX_WEB_ASSESSMENT_DEPTH);
        assert!(
            DEFAULT_WEB_ASSESSMENT_MAX_REFERENCES_PER_DOCUMENT
                <= HARD_MAX_WEB_ASSESSMENT_REFERENCES_PER_DOCUMENT
        );
        assert!(
            DEFAULT_WEB_ASSESSMENT_MAX_CANONICAL_URL_BYTES
                <= HARD_MAX_WEB_ASSESSMENT_CANONICAL_URL_BYTES
        );
        assert!(
            DEFAULT_WEB_ASSESSMENT_MAX_RETAINED_URL_BYTES
                <= HARD_MAX_WEB_ASSESSMENT_RETAINED_URL_BYTES
        );
        assert!(DEFAULT_WEB_ASSESSMENT_MAX_FORMS <= HARD_MAX_WEB_ASSESSMENT_FORMS);
        assert!(
            DEFAULT_WEB_ASSESSMENT_MAX_CONTROLS_PER_FORM
                <= HARD_MAX_WEB_ASSESSMENT_CONTROLS_PER_FORM
        );
        assert!(DEFAULT_WEB_ASSESSMENT_MAX_QUERY_NAMES <= HARD_MAX_WEB_ASSESSMENT_QUERY_NAMES);
        assert!(
            DEFAULT_WEB_ASSESSMENT_MAX_TOTAL_REQUESTS <= HARD_MAX_WEB_ASSESSMENT_TOTAL_REQUESTS
        );
        assert!(
            DEFAULT_WEB_ASSESSMENT_MAX_RESPONSE_BODY_BYTES
                <= HARD_MAX_WEB_ASSESSMENT_RESPONSE_BODY_BYTES
        );
        assert!(
            DEFAULT_WEB_ASSESSMENT_MAX_TOTAL_RESPONSE_BYTES
                <= HARD_MAX_WEB_ASSESSMENT_TOTAL_RESPONSE_BYTES
        );
        assert!(
            DEFAULT_WEB_ASSESSMENT_MAX_WALL_TIME.as_secs()
                <= HARD_MAX_WEB_ASSESSMENT_WALL_TIME.as_secs()
        );
        assert!(
            DEFAULT_WEB_ASSESSMENT_MAX_ACTIVE_VERIFICATIONS
                <= HARD_MAX_WEB_ASSESSMENT_ACTIVE_VERIFICATIONS
        );
    }

    assert!(matches!(
        defaults.with_max_subjects(0),
        Err(WebAssessmentLimitsError::ZeroRequired {
            dimension: "max_subjects"
        })
    ));
    assert!(matches!(
        defaults.with_max_canonical_url_bytes(0),
        Err(WebAssessmentLimitsError::ZeroRequired {
            dimension: "max_canonical_url_bytes"
        })
    ));
    assert!(matches!(
        defaults.with_max_retained_url_bytes(0),
        Err(WebAssessmentLimitsError::ZeroRequired {
            dimension: "max_retained_url_bytes"
        })
    ));
    assert!(matches!(
        defaults.with_max_response_body_bytes(0),
        Err(WebAssessmentLimitsError::ZeroRequired {
            dimension: "max_response_body_bytes"
        })
    ));
    assert!(matches!(
        defaults.with_max_total_response_bytes(0),
        Err(WebAssessmentLimitsError::ZeroRequired {
            dimension: "max_total_response_bytes"
        })
    ));

    macro_rules! assert_above {
        ($result:expr, $dimension:literal, $maximum:expr) => {
            assert!(matches!(
                $result,
                Err(WebAssessmentLimitsError::AboveHardMaximum {
                    dimension: $dimension,
                    maximum,
                    ..
                }) if maximum == u64::try_from($maximum).unwrap()
            ));
        };
    }
    assert_above!(
        defaults.with_max_subjects(HARD_MAX_WEB_ASSESSMENT_SUBJECTS + 1),
        "max_subjects",
        HARD_MAX_WEB_ASSESSMENT_SUBJECTS
    );
    assert_above!(
        defaults.with_max_discovery_depth(HARD_MAX_WEB_ASSESSMENT_DEPTH + 1),
        "max_discovery_depth",
        HARD_MAX_WEB_ASSESSMENT_DEPTH
    );
    assert_above!(
        defaults
            .with_max_references_per_document(HARD_MAX_WEB_ASSESSMENT_REFERENCES_PER_DOCUMENT + 1),
        "max_references_per_document",
        HARD_MAX_WEB_ASSESSMENT_REFERENCES_PER_DOCUMENT
    );
    assert_above!(
        defaults.with_max_canonical_url_bytes(HARD_MAX_WEB_ASSESSMENT_CANONICAL_URL_BYTES + 1),
        "max_canonical_url_bytes",
        HARD_MAX_WEB_ASSESSMENT_CANONICAL_URL_BYTES
    );
    assert_above!(
        defaults.with_max_retained_url_bytes(HARD_MAX_WEB_ASSESSMENT_RETAINED_URL_BYTES + 1),
        "max_retained_url_bytes",
        HARD_MAX_WEB_ASSESSMENT_RETAINED_URL_BYTES
    );
    assert_above!(
        defaults.with_max_forms(HARD_MAX_WEB_ASSESSMENT_FORMS + 1),
        "max_forms",
        HARD_MAX_WEB_ASSESSMENT_FORMS
    );
    assert_above!(
        defaults.with_max_controls_per_form(HARD_MAX_WEB_ASSESSMENT_CONTROLS_PER_FORM + 1),
        "max_controls_per_form",
        HARD_MAX_WEB_ASSESSMENT_CONTROLS_PER_FORM
    );
    assert_above!(
        defaults.with_max_query_parameter_names(HARD_MAX_WEB_ASSESSMENT_QUERY_NAMES + 1),
        "max_query_parameter_names",
        HARD_MAX_WEB_ASSESSMENT_QUERY_NAMES
    );
    assert_above!(
        defaults.with_max_total_requests(HARD_MAX_WEB_ASSESSMENT_TOTAL_REQUESTS + 1),
        "max_total_requests",
        HARD_MAX_WEB_ASSESSMENT_TOTAL_REQUESTS
    );
    assert_above!(
        defaults.with_max_response_body_bytes(HARD_MAX_WEB_ASSESSMENT_RESPONSE_BODY_BYTES + 1),
        "max_response_body_bytes",
        HARD_MAX_WEB_ASSESSMENT_RESPONSE_BODY_BYTES
    );
    assert_above!(
        defaults.with_max_total_response_bytes(HARD_MAX_WEB_ASSESSMENT_TOTAL_RESPONSE_BYTES + 1),
        "max_total_response_bytes",
        HARD_MAX_WEB_ASSESSMENT_TOTAL_RESPONSE_BYTES
    );
    assert_above!(
        defaults.with_max_active_verifications(HARD_MAX_WEB_ASSESSMENT_ACTIVE_VERIFICATIONS + 1),
        "max_active_verifications",
        HARD_MAX_WEB_ASSESSMENT_ACTIVE_VERIFICATIONS
    );
    assert!(matches!(
        defaults.with_max_wall_time(HARD_MAX_WEB_ASSESSMENT_WALL_TIME + Duration::from_millis(1)),
        Err(WebAssessmentLimitsError::AboveHardMaximum {
            dimension: "max_wall_time_ms",
            ..
        })
    ));

    let zero_capable = defaults
        .with_max_discovery_depth(0)
        .unwrap()
        .with_max_references_per_document(0)
        .unwrap()
        .with_max_forms(0)
        .unwrap()
        .with_max_controls_per_form(0)
        .unwrap()
        .with_max_query_parameter_names(0)
        .unwrap()
        .with_max_total_requests(0)
        .unwrap()
        .with_max_wall_time(Duration::ZERO)
        .unwrap()
        .with_max_active_verifications(0)
        .unwrap();
    assert_eq!(zero_capable.max_discovery_depth(), 0);
    assert_eq!(zero_capable.max_total_requests(), 0);
    assert_eq!(zero_capable.max_wall_time(), Duration::ZERO);

    let budget = defaults.runtime_budget();
    assert_eq!(
        budget.max_request_body_bytes(),
        DEFAULT_MAX_REQUEST_BODY_BYTES
    );
    assert_eq!(
        budget.max_same_action_attempts(),
        DEFAULT_MAX_SAME_ACTION_ATTEMPTS
    );
    assert_eq!(
        budget.max_consecutive_no_progress_turns(),
        DEFAULT_MAX_CONSECUTIVE_NO_PROGRESS_TURNS
    );
}

#[test]
fn sealed_observer_requires_the_exact_bootstrap_envelope_and_head_never_discovers() {
    let url = Url::parse("http://127.0.0.1:7777/root").unwrap();
    let (observer, _, entity) = observer_fixture(
        url.clone(),
        WebAssessmentMethod::Get,
        CancellationToken::new(),
        None,
    );
    let parents = TestObservationParents::new();
    let exact = TestObservationEnvelope::exact(&entity, &url, HttpProbeMethod::Get);
    let other_entity = EntityId::new("endpoint:http://127.0.0.1:7777/other").unwrap();
    let other_url = Url::parse("http://127.0.0.1:7777/other").unwrap();
    let query_url = Url::parse("http://127.0.0.1:7777/root?secret=value").unwrap();
    let fragment_url = Url::parse("http://127.0.0.1:7777/root#fragment").unwrap();
    let cross_origin_url = Url::parse("http://127.0.0.1:7778/root").unwrap();

    let mut wrong_envelopes = Vec::new();
    let mut wrong = exact;
    wrong.case_id = "case:wrong";
    wrong_envelopes.push(("case", wrong));
    let mut wrong = exact;
    wrong.action_id = "web.action.wrong";
    wrong_envelopes.push(("action", wrong));
    let mut wrong = exact;
    wrong.hypothesis_id = "hypothesis:wrong";
    wrong_envelopes.push(("hypothesis", wrong));
    let mut wrong = exact;
    wrong.has_payload_strategy = true;
    wrong_envelopes.push(("payload", wrong));
    let mut wrong = exact;
    wrong.applies_hypothesis_transition = false;
    wrong_envelopes.push(("transition", wrong));
    let mut wrong = exact;
    wrong.stage = DecisionExecutionStage::Active;
    wrong_envelopes.push(("stage", wrong));
    let mut wrong = exact;
    wrong.subject = &other_entity;
    wrong_envelopes.push(("subject", wrong));
    let mut wrong = exact;
    wrong.method = HttpProbeMethod::Head;
    wrong_envelopes.push(("method", wrong));
    let mut wrong = exact;
    wrong.requested_url = &other_url;
    wrong_envelopes.push(("request-url", wrong));
    let mut wrong = exact;
    wrong.requested_url = &query_url;
    wrong_envelopes.push(("query", wrong));
    let mut wrong = exact;
    wrong.requested_url = &fragment_url;
    wrong_envelopes.push(("fragment", wrong));
    let mut wrong = exact;
    wrong.requested_url = &cross_origin_url;
    wrong_envelopes.push(("origin", wrong));

    let ledger_shape = (
        observer.envelope.subjects.len(),
        observer.envelope.form_identities.len(),
        observer.envelope.retained_urls.clone(),
        observer.envelope.remaining_subjects,
        observer.envelope.remaining_forms,
        observer.envelope.remaining_url_bytes,
    );
    for (boundary, envelope) in wrong_envelopes {
        let evidence = observe_for_test(
            &observer,
            envelope,
            200,
            Some("text/html"),
            Some(b"<a href='/wrong-envelope-canary'>canary</a>"),
            parents.refs(true),
        )
        .unwrap_or_else(|error| panic!("{boundary} mismatch errored: {error}"));
        assert!(evidence.is_empty(), "{boundary} mismatch emitted evidence");
    }
    assert_eq!(
        (
            observer.envelope.subjects.len(),
            observer.envelope.form_identities.len(),
            observer.envelope.retained_urls.clone(),
            observer.envelope.remaining_subjects,
            observer.envelope.remaining_forms,
            observer.envelope.remaining_url_bytes,
        ),
        ledger_shape
    );

    let evidence = observe_for_test(
        &observer,
        exact,
        200,
        Some("text/html"),
        Some(b"<a href='/admitted'>admitted</a>"),
        parents.refs(true),
    )
    .unwrap();
    assert_eq!(evidence.len(), 2);
    assert_eq!(
        evidence[0].predicate(),
        &WebDiscoveryEvidencePredicate::DOCUMENT_PROJECTED.into_knowledge()
    );
    assert_eq!(derivation_parents(&evidence[0]), parents.expected(true));
    assert_eq!(
        evidence[1].predicate(),
        &WebDiscoveryEvidencePredicate::GET_ROUTE.into_knowledge()
    );

    let (head_observer, _, head_entity) = observer_fixture(
        url.clone(),
        WebAssessmentMethod::Head,
        CancellationToken::new(),
        None,
    );
    let head_envelope = TestObservationEnvelope::exact(&head_entity, &url, HttpProbeMethod::Head);
    for body in [None, Some(b"<a href='/head-canary'>canary</a>".as_slice())] {
        assert!(observe_for_test(
            &head_observer,
            head_envelope,
            200,
            Some("text/html"),
            body,
            parents.refs(true),
        )
        .unwrap()
        .is_empty());
    }
}

#[test]
fn no_eof_truth_precedes_stop_state_and_uses_exact_five_or_six_parents() {
    let url = Url::parse("http://127.0.0.1:7777/root").unwrap();
    let parents = TestObservationParents::new();
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let (cancelled_observer, _, cancelled_entity) =
        observer_fixture(url.clone(), WebAssessmentMethod::Get, cancelled, None);
    let cancelled_envelope =
        TestObservationEnvelope::exact(&cancelled_entity, &url, HttpProbeMethod::Get);

    for (status, media_type, include_media) in [
        (200, None, false),
        (200, Some("text/plain"), true),
        (206, Some("text/html"), true),
        (500, Some("text/html"), true),
    ] {
        let evidence = observe_for_test(
            &cancelled_observer,
            cancelled_envelope,
            status,
            media_type,
            None,
            parents.refs(include_media),
        )
        .unwrap();
        assert_eq!(evidence.len(), 1, "status={status} media={media_type:?}");
        assert_eq!(
            evidence[0].predicate(),
            &WebDiscoveryEvidencePredicate::DOCUMENT_BODY_INCOMPLETE.into_knowledge()
        );
        assert_eq!(
            derivation_parents(&evidence[0]),
            parents.expected(include_media)
        );
    }
    assert!(observe_for_test(
        &cancelled_observer,
        cancelled_envelope,
        200,
        Some("text/html"),
        Some(b"<a href='/cancelled-complete-canary'>canary</a>"),
        parents.refs(true),
    )
    .unwrap()
    .is_empty());

    let expired_deadline = tokio::time::Instant::now() - Duration::from_millis(1);
    let (deadline_observer, _, deadline_entity) = observer_fixture(
        url.clone(),
        WebAssessmentMethod::Get,
        CancellationToken::new(),
        Some(expired_deadline),
    );
    let deadline_envelope =
        TestObservationEnvelope::exact(&deadline_entity, &url, HttpProbeMethod::Get);
    let deadline_no_eof = observe_for_test(
        &deadline_observer,
        deadline_envelope,
        200,
        None,
        None,
        parents.refs(false),
    )
    .unwrap();
    assert_eq!(deadline_no_eof.len(), 1);
    assert_eq!(
        derivation_parents(&deadline_no_eof[0]),
        parents.expected(false)
    );
    assert!(observe_for_test(
        &deadline_observer,
        deadline_envelope,
        200,
        Some("text/html"),
        Some(b"<a href='/deadline-complete-canary'>canary</a>"),
        parents.refs(true),
    )
    .unwrap()
    .is_empty());

    let (eligible_observer, _, eligible_entity) = observer_fixture(
        url.clone(),
        WebAssessmentMethod::Get,
        CancellationToken::new(),
        None,
    );
    let eligible_envelope =
        TestObservationEnvelope::exact(&eligible_entity, &url, HttpProbeMethod::Get);
    let partial = observe_for_test(
        &eligible_observer,
        eligible_envelope,
        206,
        Some("text/html"),
        Some(b"<a href='/partial-canary'>canary</a>"),
        parents.refs(true),
    )
    .unwrap();
    assert_eq!(partial.len(), 1);
    assert_eq!(
        partial[0].predicate(),
        &WebDiscoveryEvidencePredicate::DOCUMENT_PARTIAL_REPRESENTATION.into_knowledge()
    );
    assert_eq!(derivation_parents(&partial[0]), parents.expected(true));
    for (status, media_type) in [(200, "text/plain"), (201, "text/html")] {
        assert!(observe_for_test(
            &eligible_observer,
            eligible_envelope,
            status,
            Some(media_type),
            Some(b"<a href='/ineligible-canary'>canary</a>"),
            parents.refs(true),
        )
        .unwrap()
        .is_empty());
    }

    let incomplete_required = [
        "request-method-evidence",
        "request-url-evidence",
        "response-status-evidence",
        "response-body-truncated-evidence",
        "response-body-digest-evidence",
    ];
    for (missing, expected_invariant) in incomplete_required.into_iter().enumerate() {
        let mut refs = parents.refs(false);
        match missing {
            0 => refs.request_method = None,
            1 => refs.request_url = None,
            2 => refs.response_status = None,
            3 => refs.response_body_truncated = None,
            4 => refs.response_body_digest = None,
            _ => unreachable!(),
        }
        assert!(matches!(
            observe_for_test(
                &eligible_observer,
                eligible_envelope,
                200,
                None,
                None,
                refs,
            ),
            Err(HttpEvidenceError::AssessmentObserverInvariant { invariant })
                if invariant == expected_invariant
        ));
    }

    let complete_required = [
        "request-method-evidence",
        "request-url-evidence",
        "response-status-evidence",
        "response-media-type-evidence",
        "response-body-truncated-evidence",
        "response-body-digest-evidence",
    ];
    for (missing, expected_invariant) in complete_required.into_iter().enumerate() {
        let mut refs = parents.refs(true);
        match missing {
            0 => refs.request_method = None,
            1 => refs.request_url = None,
            2 => refs.response_status = None,
            3 => refs.response_media_type = None,
            4 => refs.response_body_truncated = None,
            5 => refs.response_body_digest = None,
            _ => unreachable!(),
        }
        assert!(matches!(
            observe_for_test(
                &eligible_observer,
                eligible_envelope,
                200,
                Some("text/html"),
                Some(b"complete"),
                refs,
            ),
            Err(HttpEvidenceError::AssessmentObserverInvariant { invariant })
                if invariant == expected_invariant
        ));
    }
}

#[tokio::test]
async fn committed_bootstrap_replay_rejects_non_exact_batches_without_mutating_the_ledger() {
    let server = serve(|request| {
        let body = match request.path() {
            "/root" => {
                "<a href='/a'>a</a><a href='/b'>b</a>\
                 <form action='/submit' method='post'><input name='title'></form>"
            },
            _ => "done",
        };
        FixtureReply::Response(FixtureResponse::html(body))
    })
    .await;
    let target = server.url("/root");
    let mut runtime = WebAssessmentRuntime::builder(target.clone())
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    assert_report_reconciles(&report);
    let root_report = report
        .subjects()
        .iter()
        .find(|report| subject_path(report) == "/root")
        .expect("root report");
    let subject = root_report.subject().clone();
    let template = root_report
        .bootstrap()
        .expect("committed bootstrap")
        .clone();
    let original = template.evidence().to_vec();
    let marker_index = original
        .iter()
        .position(|evidence| {
            evidence.predicate()
                == &WebDiscoveryEvidencePredicate::DOCUMENT_PROJECTED.into_knowledge()
        })
        .expect("document projection marker");
    let first_defense = original
        .iter()
        .position(|evidence| evidence.predicate().namespace() == ASSESSMENT_DEFENSE_NAMESPACE)
        .expect("assessment defense suffix");
    assert!(marker_index + 1 < first_defense);
    assert!(original[marker_index..first_defense]
        .iter()
        .all(|evidence| evidence.predicate().namespace() == "web.discovery"));
    assert!(original[first_defense..]
        .iter()
        .all(|evidence| evidence.predicate().namespace() == ASSESSMENT_DEFENSE_NAMESPACE));
    let marker = original[marker_index].clone();
    let marker_parents = derivation_parents(&marker).to_vec();
    assert_eq!(marker_parents.len(), 6);

    let mut initial_ledger = AssessmentLedger::new(&subject);
    let mut envelope = initial_ledger.snapshot(runtime.limits, subject.depth);
    envelope
        .subjects
        .get_mut(subject.url.as_str())
        .expect("root admission")
        .executed = true;
    initial_ledger.mark_executed(&subject).unwrap();
    let exact = projection_from_committed_bootstrap(
        Some(&template),
        runtime.knowledge(),
        &subject,
        &runtime.discovery_policy,
        runtime.limits,
        &envelope,
    )
    .expect("exact committed receipt must project")
    .expect("HTML projection");
    assert_eq!(exact.routes.len(), 2);
    assert_eq!(exact.forms.len(), 1);

    let mut defense_before_discovery = original.clone();
    let leading_defense = defense_before_discovery.remove(first_defense);
    defense_before_discovery.insert(marker_index, leading_defense);

    let mut interleaved = original.clone();
    interleaved.swap(marker_index + 1, first_defense);

    let mut foreign_trailing = original.clone();
    foreign_trailing.push(Evidence::new(
        template.case().subject().clone(),
        EvidenceKind::Custom("assessment-test".to_owned()),
        KnowledgePredicate::new("test.web-assessment", "foreign-trailing").unwrap(),
        EvidenceValue::Boolean(true),
        EvidenceSource::new(HTTP_EVIDENCE_EXECUTOR_ID, "foreign-trailing")
            .unwrap()
            .with_correlation_id(BOOTSTRAP_CASE_ID)
            .unwrap(),
        marker.reliability(),
    ));
    for (name, batch) in [
        ("defense-before-discovery", defense_before_discovery),
        ("discovery-defense-interleaving", interleaved),
        ("foreign-trailing-namespace", foreign_trailing),
    ] {
        let (knowledge, receipt) = receipt_with_committed_batch(&template, batch);
        assert!(
            projection_from_committed_bootstrap(
                Some(&receipt),
                &knowledge,
                &subject,
                &runtime.discovery_policy,
                runtime.limits,
                &envelope,
            )
            .is_err(),
            "{name} batch was accepted",
        );
    }

    let mut semantic_evidence = super::semantic::AssessmentSemanticEvidence::default();
    assert!(semantic_evidence
        .commit_bootstrap(Some(&template), &KnowledgeBase::new(), &subject)
        .is_err());
    assert_eq!(semantic_evidence.record_count(), 0);
    semantic_evidence
        .commit_bootstrap(Some(&template), runtime.knowledge(), &subject)
        .expect("exact committed bootstrap must enter semantic input");
    let exact_record_count = semantic_evidence.record_count();
    semantic_evidence
        .commit_bootstrap(Some(&template), runtime.knowledge(), &subject)
        .expect("exact replay must be idempotent");
    assert_eq!(semantic_evidence.record_count(), exact_record_count);
    let semantic_once = semantic_evidence.extract(&runtime.semantic_limits);
    let semantic_twice = semantic_evidence.extract(&runtime.semantic_limits);
    assert_eq!(
        serde_json::to_vec(&semantic_once).unwrap(),
        serde_json::to_vec(&semantic_twice).unwrap()
    );
    let receipt_ids = original
        .iter()
        .map(|evidence| evidence.id().clone())
        .collect::<BTreeSet<_>>();
    assert!(semantic_once
        .entities
        .iter()
        .flat_map(|entity| entity.source_evidence_ids())
        .all(|id| receipt_ids.contains(id)));

    assert!(projection_from_committed_bootstrap(
        Some(&template),
        &KnowledgeBase::new(),
        &subject,
        &runtime.discovery_policy,
        runtime.limits,
        &envelope,
    )
    .is_err());

    let mut foreign_runtime = WebAssessmentRuntime::builder(target).build().unwrap();
    let foreign_report = foreign_runtime.analyze().await.unwrap();
    assert_report_reconciles(&foreign_report);
    assert!(projection_from_committed_bootstrap(
        Some(&template),
        foreign_runtime.knowledge(),
        &subject,
        &runtime.discovery_policy,
        runtime.limits,
        &envelope,
    )
    .is_err());

    let runtime_ledger_before = (
        runtime.ledger.subjects.keys().cloned().collect::<Vec<_>>(),
        runtime.ledger.form_identities.clone(),
        runtime.ledger.retained_urls.clone(),
        runtime.ledger.retained_unique_url_bytes,
    );

    let mut conflicting_batch = original.clone();
    let conflicting_marker = rebuild_evidence(
        &marker,
        marker.kind().clone(),
        EvidenceValue::Boolean(false),
        marker.source().clone(),
        marker.origin().clone(),
    );
    conflicting_batch.insert(marker_index, conflicting_marker);
    let rejected_knowledge = KnowledgeBase::new();
    assert!(rejected_knowledge
        .insert_evidence_batch(conflicting_batch)
        .is_err());
    assert!(original
        .iter()
        .all(|evidence| rejected_knowledge.evidence(evidence.id()).is_none()));

    let mut mutations = Vec::<(&str, Vec<Evidence>)>::new();

    let mut batch = original.clone();
    let duplicate_marker = Evidence::new(
        marker.subject().clone(),
        marker.kind().clone(),
        marker.predicate().clone(),
        marker.value().clone(),
        marker.source().clone(),
        marker.reliability(),
    )
    .derived_from(
        EvidenceDerivation::new(
            marker_parents.clone(),
            DerivationAlgorithm::new("web.discovery.html5ever-names-only", 1).unwrap(),
        )
        .unwrap(),
    );
    assert_ne!(duplicate_marker.id(), marker.id());
    batch.insert(marker_index + 1, duplicate_marker);
    mutations.push(("duplicate-predicate", batch));

    let mut batch = original.clone();
    let route_indexes = batch
        .iter()
        .enumerate()
        .filter_map(|(index, evidence)| {
            (evidence.predicate() == &WebDiscoveryEvidencePredicate::GET_ROUTE.into_knowledge())
                .then_some(index)
        })
        .collect::<Vec<_>>();
    assert_eq!(route_indexes.len(), 2);
    batch.swap(route_indexes[0], route_indexes[1]);
    mutations.push(("route-order", batch));

    let mut batch = original.clone();
    batch[marker_index] = rebuild_evidence(
        &marker,
        EvidenceKind::Http,
        marker.value().clone(),
        marker.source().clone(),
        marker.origin().clone(),
    );
    mutations.push(("kind", batch));

    let mut batch = original.clone();
    batch[marker_index] = rebuild_evidence(
        &marker,
        marker.kind().clone(),
        marker.value().clone(),
        source_with_method(&marker, "wrong-source-method"),
        marker.origin().clone(),
    );
    mutations.push(("source-method", batch));

    let mut batch = original.clone();
    let wrong_algorithm = EvidenceDerivation::new(
        marker_parents.clone(),
        DerivationAlgorithm::new("web.discovery.wrong-algorithm", 1).unwrap(),
    )
    .unwrap();
    batch[marker_index] = rebuild_evidence(
        &marker,
        marker.kind().clone(),
        marker.value().clone(),
        marker.source().clone(),
        EvidenceOrigin::Derived(wrong_algorithm),
    );
    mutations.push(("algorithm", batch));

    let mut batch = original.clone();
    let missing_parent = EvidenceDerivation::new(
        marker_parents.iter().skip(1).cloned(),
        DerivationAlgorithm::new("web.discovery.html5ever-names-only", 1).unwrap(),
    )
    .unwrap();
    batch[marker_index] = rebuild_evidence(
        &marker,
        marker.kind().clone(),
        marker.value().clone(),
        marker.source().clone(),
        EvidenceOrigin::Derived(missing_parent),
    );
    mutations.push(("missing-parent", batch));

    let mut batch = original.clone();
    let extra_parent = Evidence::new(
        marker.subject().clone(),
        EvidenceKind::Content,
        KnowledgePredicate::new("test.web-assessment", "extra-parent").unwrap(),
        EvidenceValue::Boolean(true),
        EvidenceSource::new(HTTP_EVIDENCE_EXECUTOR_ID, "extra-parent")
            .unwrap()
            .with_correlation_id("case:foreign")
            .unwrap(),
        marker.reliability(),
    );
    let extra_parent_id = extra_parent.id().clone();
    let extra_derivation = EvidenceDerivation::new(
        marker_parents
            .iter()
            .cloned()
            .chain(std::iter::once(extra_parent_id)),
        DerivationAlgorithm::new("web.discovery.html5ever-names-only", 1).unwrap(),
    )
    .unwrap();
    batch[marker_index] = rebuild_evidence(
        &marker,
        marker.kind().clone(),
        marker.value().clone(),
        marker.source().clone(),
        EvidenceOrigin::Derived(extra_derivation),
    );
    batch.insert(marker_index, extra_parent);
    mutations.push(("extra-cross-case-parent", batch));

    let mut batch = original.clone();
    let route_index = route_indexes[0];
    let route = batch[route_index].clone();
    batch[route_index] = rebuild_evidence(
        &route,
        route.kind().clone(),
        EvidenceValue::Text(format!("{}a/../noncanonical", server.origin)),
        route.source().clone(),
        route.origin().clone(),
    );
    mutations.push(("canonical-url", batch));

    let mut batch = original.clone();
    let request_url_index = batch
        .iter()
        .position(|evidence| {
            evidence.predicate() == &HttpEvidencePredicate::REQUEST_URL.into_knowledge()
        })
        .expect("request URL evidence");
    let request_url = batch[request_url_index].clone();
    batch[request_url_index] = rebuild_evidence(
        &request_url,
        request_url.kind().clone(),
        EvidenceValue::Text(server.url("/other").to_string()),
        request_url.source().clone(),
        request_url.origin().clone(),
    );
    let mismatched_receipt = template.with_test_committed_batch(
        batch.clone(),
        template.writes().to_vec(),
        template.after_execution().clone(),
    );
    assert!(projection_from_committed_bootstrap(
        Some(&mismatched_receipt),
        runtime.knowledge(),
        &subject,
        &runtime.discovery_policy,
        runtime.limits,
        &envelope,
    )
    .is_err());
    mutations.push(("request-url", batch));

    for (name, batch) in mutations {
        let (knowledge, receipt) = receipt_with_committed_batch(&template, batch);
        assert!(
            projection_from_committed_bootstrap(
                Some(&receipt),
                &knowledge,
                &subject,
                &runtime.discovery_policy,
                runtime.limits,
                &envelope,
            )
            .is_err(),
            "{name} committed batch was accepted"
        );
    }
    assert_eq!(
        (
            runtime.ledger.subjects.keys().cloned().collect::<Vec<_>>(),
            runtime.ledger.form_identities.clone(),
            runtime.ledger.retained_urls.clone(),
            runtime.ledger.retained_unique_url_bytes,
        ),
        runtime_ledger_before
    );
}

#[tokio::test]
async fn deterministic_bfs_is_exact_origin_deduplicated_and_subject_isolated() {
    let outside = serve(|_| {
        FixtureReply::Response(FixtureResponse::html(
            "<a href='/outside-canary'>outside</a>",
        ))
    })
    .await;
    let outside_url = outside.url("/escape?outside_value=never-retain");
    let server = serve(move |request| {
        let body = match request.path() {
            "/root" => format!(
                "<a href='/b?b_value=hidden#frag'>b</a>\
                 <a href='./a?token=link-secret'>a</a>\
                 <a href='http://{}/a?other=also-secret#two'>absolute-a</a>\
                 <a href='/a#duplicate'>duplicate-a</a>\
                 <link href='/head.css?cache=secret' rel='stylesheet'>\
                 <a href='{outside_url}'>outside</a>",
                request.host()
            ),
            "/a" => "<a href='/root'>cycle</a><a href='/c'>c</a><a href='/b'>b</a>".to_owned(),
            "/b" => "<a href='/c#again'>c</a><a href='/a'>a</a>".to_owned(),
            "/c" => "done".to_owned(),
            "/head.css" => "<a href='/head-body-canary'>must-not-project</a>".to_owned(),
            _ => "not-found-canary".to_owned(),
        };
        FixtureReply::Response(FixtureResponse::html(body))
    })
    .await;

    let mut first_runtime = WebAssessmentRuntime::builder(server.url("/root"))
        .build()
        .unwrap();
    let first = first_runtime.analyze().await.unwrap();
    assert_report_reconciles(&first);
    assert!(matches!(
        first.completion(),
        WebAssessmentCompletion::Complete
    ));
    let first_shape: Vec<_> = first.subjects().iter().map(public_subject_shape).collect();
    assert_eq!(
        first_shape
            .iter()
            .map(|item| item.0.as_str())
            .collect::<Vec<_>>(),
        ["/root", "/a", "/b", "/head.css", "/c"]
    );
    assert_eq!(first_shape[0].2, 0);
    assert!(first_shape[1..=3].iter().all(|item| item.2 == 1));
    assert_eq!(first_shape[4].2, 2);
    assert_eq!(first_shape[1].3, ["other", "token"]);
    assert_eq!(first_shape[2].3, ["b_value"]);
    assert_eq!(first_shape[3].1, WebAssessmentMethod::Head);
    assert!(first
        .subjects()
        .iter()
        .all(|subject| subject.subject().url().query().is_none()));
    assert!(!first_shape.iter().any(|item| item.0 == "/head-body-canary"));
    assert_eq!(outside.requests().await, []);

    let requests = server.requests().await;
    assert_eq!(requests.len(), 5);
    assert!(requests.iter().all(|request| !request.target.contains('?')));
    assert_eq!(
        requests
            .iter()
            .map(|request| (request.method.as_str(), request.path()))
            .collect::<Vec<_>>(),
        [
            ("GET", "/root"),
            ("GET", "/a"),
            ("GET", "/b"),
            ("HEAD", "/head.css"),
            ("GET", "/c"),
        ]
    );

    let mut replay_runtime = WebAssessmentRuntime::builder(server.url("/root"))
        .build()
        .unwrap();
    let replay = replay_runtime.analyze().await.unwrap();
    assert_report_reconciles(&replay);
    assert_eq!(
        replay
            .subjects()
            .iter()
            .map(public_subject_shape)
            .collect::<Vec<_>>(),
        first_shape
    );
    assert_eq!(outside.requests().await, []);
}

#[tokio::test]
async fn same_layer_head_candidate_upgrades_to_get_and_executed_urls_are_not_redispatched() {
    let server = serve(|request| {
        let body = match request.path() {
            "/root" => "<a href='/a'>a</a><a href='/b'>b</a>",
            "/a" => "<link href='/target' rel='stylesheet'>",
            "/b" => "<a href='/target'>target</a>",
            "/target" => {
                "<a href='/a'>executed-get</a><link href='/b' rel='stylesheet'>executed-head"
            },
            _ => "unexpected",
        };
        FixtureReply::Response(FixtureResponse::html(body))
    })
    .await;

    let limits = WebAssessmentLimits::default()
        .with_max_discovery_depth(3)
        .unwrap();
    let mut runtime = WebAssessmentRuntime::builder(server.url("/root"))
        .limits(limits)
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    assert_report_reconciles(&report);
    assert!(matches!(
        report.completion(),
        WebAssessmentCompletion::Complete
    ));
    assert_eq!(
        report
            .subjects()
            .iter()
            .map(subject_path)
            .collect::<Vec<_>>(),
        ["/root", "/a", "/b", "/target"]
    );
    let target = report
        .subjects()
        .iter()
        .find(|subject| subject_path(subject) == "/target")
        .expect("merged pending target");
    assert_eq!(target.subject().method(), WebAssessmentMethod::Get);
    assert_eq!(target.subject().depth(), 2);
    assert_eq!(server.hit_count("/a").await, 1);
    assert_eq!(server.hit_count("/b").await, 1);
    assert_eq!(server.hit_count("/target").await, 1);
    assert_eq!(
        server
            .requests()
            .await
            .iter()
            .map(|request| (request.method.as_str(), request.path()))
            .collect::<Vec<_>>(),
        [
            ("GET", "/root"),
            ("GET", "/a"),
            ("GET", "/b"),
            ("GET", "/target"),
        ]
    );
}

#[tokio::test]
async fn forms_are_names_only_and_only_get_actions_are_dispatched() {
    const SECRETS: &[&str] = &[
        "ROOT_QUERY_SECRET",
        "FORM_QUERY_SECRET",
        "POST_QUERY_SECRET",
        "CONTROL_VALUE_SECRET",
        "PASSWORD_VALUE_SECRET",
        "COOKIE_VALUE_SECRET",
        "AUTH_HEADER_SECRET",
        "CSP_NONCE_SECRET",
        "CONTENT_TYPE_SECRET",
        "BODY_TEXT_SECRET",
        "RETRY_AFTER_SECRET",
        "RATELIMIT_SECRET",
    ];
    let outside =
        serve(|_| FixtureReply::Response(FixtureResponse::html("outside must not be reached")))
            .await;
    let outside_origin = outside.url("/");
    let server = serve(|request| {
        let response = match request.path() {
            "/forms" => FixtureResponse::new(
                "200 OK",
                Some("text/html; boundary=CONTENT_TYPE_SECRET"),
                "<p>BODY_TEXT_SECRET</p>\
                 <form action='/search?q=FORM_QUERY_SECRET' method='get'>\
                   <input name='q' value='CONTROL_VALUE_SECRET'>\
                   <input name='csrf' value='CONTROL_VALUE_SECRET'>\
                   <input name='password' type='password' value='PASSWORD_VALUE_SECRET'>\
                 </form>\
                 <form action='/write?token=POST_QUERY_SECRET' method='post'>\
                   <textarea name='title'>CONTROL_VALUE_SECRET</textarea>\
                 </form>\
                 <form action='/modal' method='dialog'><button name='accept'>yes</button></form>",
            )
            .with_header("Set-Cookie", "session=COOKIE_VALUE_SECRET; HttpOnly")
            .with_header("WWW-Authenticate", "Bearer AUTH_HEADER_SECRET")
            .with_header(
                "Content-Security-Policy",
                "script-src 'nonce-CSP_NONCE_SECRET'",
            )
            .with_header("Retry-After", "RETRY_AFTER_SECRET")
            .with_header("RateLimit-Remaining", "RATELIMIT_SECRET"),
            "/search" => FixtureResponse::html("search result"),
            _ => FixtureResponse::new("404 Not Found", Some("text/plain"), Vec::new()),
        };
        FixtureReply::Response(response)
    })
    .await;
    let target = server.url("/forms?root=ROOT_QUERY_SECRET#fragment");
    let policy = HttpEvidencePolicy::new(
        [target.clone(), outside_origin],
        Duration::from_secs(2),
        8 * 1_024,
    )
    .unwrap()
    .with_body_capture(HttpBodyCapture::TextSample { max_chars: 4_096 })
    .unwrap()
    .capture_header("set-cookie")
    .unwrap()
    .capture_header("www-authenticate")
    .unwrap()
    .capture_header("content-security-policy")
    .unwrap();
    let mut runtime = WebAssessmentRuntime::builder(target)
        .http_policy(policy)
        .build()
        .unwrap();
    assert_eq!(runtime.authorized_root().query_parameter_names(), ["root"]);
    let report = runtime.analyze().await.unwrap();
    assert_report_reconciles(&report);
    assert!(matches!(
        report.completion(),
        WebAssessmentCompletion::Complete
    ));
    assert_eq!(
        report
            .subjects()
            .iter()
            .map(subject_path)
            .collect::<Vec<_>>(),
        ["/forms", "/search"]
    );
    assert_eq!(report.forms().len(), 3);
    let get = report
        .forms()
        .iter()
        .find(|form| form.method() == WebAssessmentFormMethod::Get)
        .unwrap();
    assert_eq!(get.action().path(), "/search");
    assert_eq!(get.query_parameter_names(), ["q"]);
    assert_eq!(get.control_names(), ["csrf", "password", "q"]);
    let post = report
        .forms()
        .iter()
        .find(|form| form.method() == WebAssessmentFormMethod::Post)
        .unwrap();
    assert_eq!(post.action().path(), "/write");
    assert_eq!(post.query_parameter_names(), ["token"]);
    assert_eq!(post.control_names(), ["title"]);

    let requests = server.requests().await;
    assert_eq!(
        requests
            .iter()
            .map(|request| (request.method.as_str(), request.path()))
            .collect::<Vec<_>>(),
        [("GET", "/forms"), ("GET", "/search")]
    );
    assert!(requests.iter().all(|request| !request.target.contains('?')));
    assert_eq!(outside.requests().await, []);

    let report_debug = format!("{report:?}");
    let knowledge = knowledge_debug(&runtime, &report);
    assert_no_secret(&report_debug, SECRETS);
    assert_no_secret(&knowledge, SECRETS);
}

#[tokio::test]
async fn redirects_are_observed_without_following_same_or_cross_origin_locations() {
    const REDIRECT_SECRET: &str = "REDIRECT_LOCATION_SECRET";
    let outside =
        serve(|_| FixtureReply::Response(FixtureResponse::html("cross-origin redirect canary")))
            .await;
    let outside_location = outside.url(&format!("/cross-target?token={REDIRECT_SECRET}"));
    let server = serve(move |request| {
        let response = match request.path() {
            "/same-redirect" => FixtureResponse::new("302 Found", None, Vec::new())
                .with_header("Location", &format!("/same-target?token={REDIRECT_SECRET}")),
            "/cross-redirect" => FixtureResponse::new("302 Found", None, Vec::new())
                .with_header("Location", outside_location.as_str()),
            "/same-target" => FixtureResponse::html("same-origin redirect canary"),
            _ => FixtureResponse::new("404 Not Found", None, Vec::new()),
        };
        FixtureReply::Response(response)
    })
    .await;

    for path in ["/same-redirect", "/cross-redirect"] {
        let mut runtime = WebAssessmentRuntime::builder(server.url(path))
            .build()
            .unwrap();
        let report = runtime.analyze().await.unwrap();
        assert_report_reconciles(&report);
        assert!(matches!(
            report.completion(),
            WebAssessmentCompletion::Complete
        ));
        assert_eq!(report.subjects().len(), 1);
        assert_no_secret(&format!("{report:?}"), &[REDIRECT_SECRET]);
        assert_no_secret(&knowledge_debug(&runtime, &report), &[REDIRECT_SECRET]);
    }
    assert_eq!(server.hit_count("/same-target").await, 0);
    assert_eq!(outside.requests().await, []);
}

#[tokio::test]
async fn complete_body_status_and_media_boundaries_fail_closed() {
    const BODY_LIMIT: usize = 96;
    let exact_prefix = "<a href='/exact-cap-canary'>x</a>";
    let mut exact_body = exact_prefix.as_bytes().to_vec();
    exact_body.resize(BODY_LIMIT, b' ');
    let over_prefix = "<a href='/over-cap-canary'>x</a>";
    let mut over_body = over_prefix.as_bytes().to_vec();
    over_body.resize(BODY_LIMIT + 1, b' ');
    let server = serve(move |request| {
        let response = match request.path() {
            "/short" => FixtureResponse::html("<a href='/short-child'>child</a>"),
            "/short-child" => FixtureResponse::html("done"),
            "/exact" => FixtureResponse::html(exact_body.clone()),
            "/over" => FixtureResponse::html(over_body.clone()),
            "/partial" => FixtureResponse::new(
                "206 Partial Content",
                Some("text/html"),
                "<a href='/partial-canary'>partial</a>",
            ),
            "/created" => FixtureResponse::new(
                "201 Created",
                Some("text/html"),
                "<a href='/created-canary'>created</a>",
            ),
            "/plain" => FixtureResponse::new(
                "200 OK",
                Some("text/plain"),
                "<a href='/plain-canary'>plain</a>",
            ),
            "/invalid" => FixtureResponse::new("200 OK", Some("text/html"), vec![0xff, 0xfe, 0xfd]),
            _ => FixtureResponse::html("unexpected canary target"),
        };
        FixtureReply::Response(response)
    })
    .await;
    let limits = WebAssessmentLimits::default()
        .with_max_response_body_bytes(BODY_LIMIT)
        .unwrap();

    let mut short_runtime = WebAssessmentRuntime::builder(server.url("/short"))
        .limits(limits)
        .build()
        .unwrap();
    let short = short_runtime.analyze().await.unwrap();
    assert_report_reconciles(&short);
    assert!(matches!(
        short.completion(),
        WebAssessmentCompletion::Complete
    ));
    assert_eq!(
        short
            .subjects()
            .iter()
            .map(subject_path)
            .collect::<Vec<_>>(),
        ["/short", "/short-child"]
    );

    let cases = [
        (
            "/exact",
            Some(WebAssessmentIncompleteReason::ResponseBodyIncomplete),
            "/exact-cap-canary",
        ),
        (
            "/over",
            Some(WebAssessmentIncompleteReason::ResponseBodyIncomplete),
            "/over-cap-canary",
        ),
        (
            "/partial",
            Some(WebAssessmentIncompleteReason::PartialRepresentation),
            "/partial-canary",
        ),
        ("/created", None, "/created-canary"),
        ("/plain", None, "/plain-canary"),
        (
            "/invalid",
            Some(WebAssessmentIncompleteReason::InvalidUtf8),
            "/invalid-canary",
        ),
    ];
    for (path, expected_reason, canary) in cases {
        let mut runtime = WebAssessmentRuntime::builder(server.url(path))
            .limits(limits)
            .build()
            .unwrap();
        let report = runtime.analyze().await.unwrap();
        assert_report_reconciles(&report);
        assert_eq!(report.subjects().len(), 1);
        assert!(!report
            .subjects()
            .iter()
            .any(|subject| subject.subject().url().path() == canary));
        match expected_reason {
            Some(reason) => {
                assert!(report.completion().reasons().contains(&reason));
                assert!(matches!(
                    report.completion(),
                    WebAssessmentCompletion::Incomplete { .. }
                ));
            },
            None => assert!(matches!(
                report.completion(),
                WebAssessmentCompletion::Complete
            )),
        }
    }
}

#[tokio::test]
async fn subject_form_and_unique_url_limits_drop_canaries_with_typed_reasons() {
    let server = serve(|request| {
        let body = match request.path() {
            "/caps" => {
                "<a href='/a'>a</a><a href='/b'>b</a>\
                        <form action='/form-a' method='post'><input name='a'></form>\
                        <form action='/form-b' method='post'><input name='b'></form>"
            },
            "/url-caps" => "<a href='/url-a'>a</a><a href='/url-b'>b</a>",
            _ => "done",
        };
        FixtureReply::Response(FixtureResponse::html(body))
    })
    .await;

    let limits = WebAssessmentLimits::default()
        .with_max_subjects(2)
        .unwrap()
        .with_max_forms(1)
        .unwrap();
    let mut runtime = WebAssessmentRuntime::builder(server.url("/caps"))
        .limits(limits)
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    assert_report_reconciles(&report);
    let reasons = report.completion().reasons();
    assert!(reasons.contains(&WebAssessmentIncompleteReason::SubjectLimit));
    assert!(reasons.contains(&WebAssessmentIncompleteReason::FormLimit));
    assert_eq!(
        report
            .subjects()
            .iter()
            .map(subject_path)
            .collect::<Vec<_>>(),
        ["/caps", "/a"]
    );
    assert_eq!(report.forms().len(), 1);
    assert_eq!(report.forms()[0].action().path(), "/form-a");
    assert_eq!(server.hit_count("/b").await, 0);
    assert_eq!(server.hit_count("/form-b").await, 0);

    let root = server.url("/url-caps");
    let first = server.url("/url-a");
    let retained_limit = root.as_str().len().saturating_add(first.as_str().len());
    let url_limits = WebAssessmentLimits::default()
        .with_max_retained_url_bytes(retained_limit)
        .unwrap();
    let mut url_runtime = WebAssessmentRuntime::builder(root)
        .limits(url_limits)
        .build()
        .unwrap();
    let url_report = url_runtime.analyze().await.unwrap();
    assert_report_reconciles(&url_report);
    assert!(url_report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::RetainedUrlBytesLimit));
    assert_eq!(
        url_report
            .subjects()
            .iter()
            .map(subject_path)
            .collect::<Vec<_>>(),
        ["/url-caps", "/url-a"]
    );
    assert_eq!(
        url_report.usage().retained_unique_url_bytes(),
        retained_limit
    );
    assert_eq!(server.hit_count("/url-b").await, 0);
}

#[tokio::test]
async fn wildcard_cycle_is_bounded_by_depth_and_never_reported_complete() {
    let server = serve(|request| {
        let body = match request.path() {
            "/wild/0" => "<a href='/wild/1'>next</a>",
            "/wild/1" => "<a href='/wild/0'>cycle</a><a href='/wild/2'>next</a>",
            "/wild/2" => "<a href='/wild/3'>next</a>",
            "/wild/3" => "<a href='/wild/4'>next</a>",
            _ => "<a href='/wild/0'>wildcard-cycle</a>",
        };
        FixtureReply::Response(FixtureResponse::html(body))
    })
    .await;
    let limits = WebAssessmentLimits::default()
        .with_max_discovery_depth(2)
        .unwrap();
    let mut runtime = WebAssessmentRuntime::builder(server.url("/wild/0"))
        .limits(limits)
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    assert_report_reconciles(&report);
    assert!(report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::DiscoveryDepthLimit));
    assert!(matches!(
        report.completion(),
        WebAssessmentCompletion::Incomplete { .. }
    ));
    assert_eq!(
        report
            .subjects()
            .iter()
            .map(subject_path)
            .collect::<Vec<_>>(),
        ["/wild/0", "/wild/1", "/wild/2"]
    );
    assert_eq!(server.hit_count("/wild/0").await, 1);
    assert_eq!(server.hit_count("/wild/1").await, 1);
    assert_eq!(server.hit_count("/wild/2").await, 1);
    assert_eq!(server.hit_count("/wild/3").await, 0);
}

#[tokio::test]
async fn cancellation_wall_and_global_budgets_are_fail_closed() {
    let server = serve(|request| {
        let response = match request.path() {
            "/budget" => FixtureResponse::html("<a href='/a'>a</a><a href='/b'>b</a>"),
            "/bytes" => FixtureResponse::html(vec![b'x'; 512]),
            _ => FixtureResponse::html("done"),
        };
        FixtureReply::Response(response)
    })
    .await;

    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let mut cancelled_runtime = WebAssessmentRuntime::builder(server.url("/cancelled"))
        .cancellation_token(cancelled)
        .build()
        .unwrap();
    let cancelled_report = cancelled_runtime.analyze().await.unwrap();
    assert_report_reconciles(&cancelled_report);
    assert!(cancelled_report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::HostCancellation));
    assert_eq!(cancelled_report.usage().total_requests(), 0);
    assert!(!cancelled_report.subjects()[0].was_executed());

    let wall_limits = WebAssessmentLimits::default()
        .with_max_wall_time(Duration::ZERO)
        .unwrap();
    let mut wall_runtime = WebAssessmentRuntime::builder(server.url("/wall"))
        .limits(wall_limits)
        .build()
        .unwrap();
    let wall_report = wall_runtime.analyze().await.unwrap();
    assert_report_reconciles(&wall_report);
    assert!(wall_report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::WallTimeLimit));
    assert_eq!(wall_report.usage().total_requests(), 0);
    assert!(!wall_report.subjects()[0].was_executed());

    let request_limits = WebAssessmentLimits::default()
        .with_max_total_requests(1)
        .unwrap();
    let mut request_runtime = WebAssessmentRuntime::builder(server.url("/budget"))
        .limits(request_limits)
        .build()
        .unwrap();
    let request_report = request_runtime.analyze().await.unwrap();
    assert_report_reconciles(&request_report);
    assert!(request_report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::TotalRequestLimit));
    assert_eq!(request_report.usage().total_requests(), 1);
    assert_eq!(server.hit_count("/budget").await, 1);
    assert_eq!(server.hit_count("/a").await, 0);
    assert_eq!(server.hit_count("/b").await, 0);

    let response_limits = WebAssessmentLimits::default()
        .with_max_total_response_bytes(32)
        .unwrap();
    let mut response_runtime = WebAssessmentRuntime::builder(server.url("/bytes"))
        .limits(response_limits)
        .build()
        .unwrap();
    let response_report = response_runtime.analyze().await.unwrap();
    assert_report_reconciles(&response_report);
    assert!(response_report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::ResponseBytesLimit));
    assert!(response_report.usage().response_bytes() >= 32);
    assert_eq!(response_report.usage().total_requests(), 1);
}

#[tokio::test]
async fn semantic_projection_consumes_only_receipt_owned_names_and_never_unrelated_secrets() {
    const SECRET: &str = "UNRELATED_SHARED_KB_AUTH_SECRET";
    let server = serve(|request| {
        let body = if request.path() == "/root" {
            "<a href='/search?q=discarded-value&page=2'>search</a>\
             <form action='/submit?next=discarded-target' method='post'>\
               <input name='email' value='private@example.test'>\
               <input name='password' value='never-retain-this'>\
             </form>"
        } else {
            "done"
        };
        FixtureReply::Response(FixtureResponse::html(body))
    })
    .await;
    let target = server.url("/root");
    let mut runtime = WebAssessmentRuntime::builder(target.clone())
        .build()
        .unwrap();
    let root_id = EntityId::new(format!("endpoint:{target}")).unwrap();
    let hostile = Evidence::new(
        root_id,
        EvidenceKind::Authentication,
        KnowledgePredicate::new("authentication", "bearer").unwrap(),
        EvidenceValue::Text(SECRET.to_owned()),
        EvidenceSource::new("hostile.test", "unrelated-auth").unwrap(),
        ConfidenceScore::from_percent(100).unwrap(),
    );
    let hostile_id = hostile.id().clone();
    runtime.knowledge().insert_evidence(hostile).unwrap();

    let report = runtime.analyze().await.unwrap();
    assert_report_reconciles(&report);
    assert!(!report.semantics().truncated);
    assert!(report.semantics().entities.iter().all(|entity| matches!(
        entity.entity_type(),
        SemanticEntityType::Endpoint | SemanticEntityType::Parameter
    )));
    let parameters = report
        .semantics()
        .entities
        .iter()
        .filter(|entity| entity.entity_type() == SemanticEntityType::Parameter)
        .flat_map(|entity| entity.attributes()["name"].iter().cloned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        parameters,
        BTreeSet::from([
            "email".to_owned(),
            "next".to_owned(),
            "page".to_owned(),
            "password".to_owned(),
            "q".to_owned(),
        ])
    );
    assert!(report.semantics().entities.iter().all(|entity| {
        entity
            .attributes()
            .values()
            .flatten()
            .all(|value| !value.contains("discarded") && !value.contains("never-retain"))
    }));

    let committed_ids = report
        .subjects()
        .iter()
        .filter_map(WebAssessmentSubjectReport::bootstrap)
        .flat_map(DecisionEvidenceReceipt::evidence)
        .map(|evidence| evidence.id().clone())
        .collect::<BTreeSet<_>>();
    assert!(report
        .semantics()
        .entities
        .iter()
        .flat_map(|entity| entity.source_evidence_ids())
        .all(|id| committed_ids.contains(id) && id != &hostile_id));
    let semantic_debug = format!("{:?}", report.semantics());
    let semantic_json = serde_json::to_string(report.semantics()).unwrap();
    assert!(!semantic_debug.contains(SECRET));
    assert!(!semantic_json.contains(SECRET));

    let first = runtime.semantic_evidence.extract(&runtime.semantic_limits);
    let second = runtime.semantic_evidence.extract(&runtime.semantic_limits);
    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&second).unwrap()
    );
    assert_eq!(&first, report.semantics());
}

#[tokio::test]
async fn semantic_entity_ceiling_marks_the_assessment_incomplete_without_extra_dispatch() {
    let links = (0..16)
        .map(|route| {
            let query = (0..64)
                .map(|name| format!("name-{name:02}=discarded"))
                .collect::<Vec<_>>()
                .join("&");
            format!("<a href='/route-{route:02}?{query}'>route</a>")
        })
        .collect::<String>();
    let server = serve(move |request| {
        let body = if request.path() == "/root" {
            links.clone()
        } else {
            "done".to_owned()
        };
        FixtureReply::Response(FixtureResponse::html(body))
    })
    .await;
    let limits = WebAssessmentLimits::default()
        .with_max_total_requests(1)
        .unwrap();
    let mut runtime = WebAssessmentRuntime::builder(server.url("/root"))
        .limits(limits)
        .build()
        .unwrap();

    let report = runtime.analyze().await.unwrap();

    assert_report_reconciles(&report);
    assert!(report.semantics().truncated);
    assert_eq!(
        report.semantics().entities.len(),
        SemanticExtractionLimits::default().max_entities()
    );
    assert!(report.semantics().dropped_entities > 0);
    assert!(report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::SemanticExtractionLimit));
    assert!(report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::TotalRequestLimit));
    assert_eq!(report.usage().total_requests(), 1);
    assert_eq!(server.hit_count("/root").await, 1);
    assert!(server
        .requests()
        .await
        .iter()
        .all(|request| request.path() == "/root"));

    runtime.limits = runtime
        .limits
        .with_max_wall_time(Duration::from_millis(1))
        .unwrap();
    let deliberately_expired = tokio::time::Instant::now() - Duration::from_millis(2);
    let mut post_extraction_reasons = BTreeSet::new();
    let repeated = runtime
        .extract_semantics_and_refresh_limits(&mut post_extraction_reasons, deliberately_expired);
    assert!(repeated.truncated);
    assert!(post_extraction_reasons.contains(&WebAssessmentIncompleteReason::WallTimeLimit));
    assert!(
        post_extraction_reasons.contains(&WebAssessmentIncompleteReason::SemanticExtractionLimit)
    );
}

#[tokio::test]
async fn in_flight_cancellation_and_timeout_preserve_typed_audits() {
    let server = serve(|_| FixtureReply::Stall).await;
    let target = server.url("/stall");
    let token = CancellationToken::new();
    let policy = HttpEvidencePolicy::new(
        [target.clone()],
        Duration::from_millis(50),
        DEFAULT_WEB_ASSESSMENT_MAX_RESPONSE_BODY_BYTES,
    )
    .unwrap();
    let mut runtime = WebAssessmentRuntime::builder(target)
        .http_policy(policy)
        .cancellation_token(token.clone())
        .build()
        .unwrap();
    let notification = server.request_notification();
    let canceller = tokio::spawn(async move {
        notification.notified().await;
        token.cancel();
    });
    let report = runtime.analyze().await.unwrap();
    canceller.await.unwrap();
    assert_report_reconciles(&report);
    assert!(report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::HostCancellation));
    assert_eq!(report.usage().total_requests(), 1);
    assert_eq!(report.transport().receipts().len(), 1);
    assert_eq!(
        report.transport().receipts()[0].outcome(),
        TransportDispatchOutcome::Cancelled
    );

    drop(server);
    let timeout_server = serve(|_| FixtureReply::Stall).await;
    let timeout_target = timeout_server.url("/timeout");
    let timeout_policy = HttpEvidencePolicy::new(
        [timeout_target.clone()],
        Duration::from_millis(50),
        DEFAULT_WEB_ASSESSMENT_MAX_RESPONSE_BODY_BYTES,
    )
    .unwrap();
    let mut timeout_runtime = WebAssessmentRuntime::builder(timeout_target)
        .http_policy(timeout_policy)
        .build()
        .unwrap();
    let timeout_error = timeout_runtime.analyze().await.unwrap_err();
    let timeout_receipt = timeout_error
        .failure_receipt()
        .expect("started timeout failure receipt");
    assert_failure_reconciles(timeout_receipt);
    assert!(timeout_receipt
        .incomplete_reasons()
        .contains(&WebAssessmentIncompleteReason::SubjectExecutionIncomplete));
    assert_eq!(timeout_receipt.usage().total_requests(), 1);
    assert_eq!(timeout_receipt.transport().receipts().len(), 1);
    assert_eq!(
        timeout_receipt.transport().receipts()[0].outcome(),
        TransportDispatchOutcome::RequestTimeout
    );
}

#[tokio::test]
async fn committed_bootstrap_is_drained_once_when_a_later_action_fails() {
    const COOKIE_VALUE_SECRETS: &[&str] = &["LARAVEL_COOKIE_SECRET", "XSRF_COOKIE_SECRET"];
    let root_requests = Arc::new(AtomicUsize::new(0));
    let observed_root_requests = root_requests.clone();
    let server = serve(move |request| {
        if request.path() != "/root" {
            return FixtureReply::Response(FixtureResponse::html("unexpected subject"));
        }
        if observed_root_requests.fetch_add(1, Ordering::SeqCst) == 0 {
            return FixtureReply::Response(
                FixtureResponse::html(
                    "<a href='/pending?name=route'>pending</a>\
                     <form action='/write?mode=preview' method='post'>\
                       <input name='title' value='not-retained'>\
                     </form>",
                )
                .with_header(
                    "Set-Cookie",
                    "laravel_session=LARAVEL_COOKIE_SECRET; HttpOnly",
                )
                .with_header("Set-Cookie", "XSRF-TOKEN=XSRF_COOKIE_SECRET"),
            );
        }
        FixtureReply::CloseWithoutResponse
    })
    .await;

    let mut runtime = WebAssessmentRuntime::builder(server.url("/root"))
        .build()
        .unwrap();
    let error = runtime.analyze().await.unwrap_err();
    let receipt = error
        .failure_receipt()
        .expect("later action failure receipt");
    assert_failure_reconciles(receipt);
    assert!(receipt.completed_subjects().is_empty());
    assert_eq!(receipt.current_subject().url().path(), "/root");
    assert!(receipt.current_subject_report().bootstrap().is_some());
    assert_eq!(receipt.pending_subjects().len(), 1);
    assert_eq!(receipt.pending_subjects()[0].url().path(), "/pending");
    assert_eq!(
        receipt.pending_subjects()[0].query_parameter_names(),
        ["name"]
    );
    assert_eq!(receipt.forms().len(), 1);
    assert_eq!(receipt.forms()[0].action().path(), "/write");
    assert_eq!(receipt.forms()[0].method(), WebAssessmentFormMethod::Post);
    assert_eq!(receipt.forms()[0].query_parameter_names(), ["mode"]);
    assert_eq!(receipt.forms()[0].control_names(), ["title"]);
    assert_eq!(server.hit_count("/root").await, 2);
    assert_eq!(server.hit_count("/pending").await, 0);
    assert_eq!(receipt.usage().total_requests(), 2);
    assert_eq!(receipt.transport().receipts().len(), 2);
    assert_eq!(
        receipt.transport().receipts()[1].outcome(),
        TransportDispatchOutcome::TransportFailure
    );
    let debug = format!("{error:?}{receipt:?}");
    assert_no_secret(&debug, COOKIE_VALUE_SECRETS);
    let root_id = EntityId::new(format!("endpoint:{}", receipt.current_subject().url())).unwrap();
    assert_no_secret(
        &format!("{:?}", runtime.knowledge().snapshot_for_subject(&root_id)),
        COOKIE_VALUE_SECRETS,
    );
}

#[tokio::test]
async fn started_subject_failure_partitions_completed_current_and_pending_inventory() {
    const FAILURE_SECRETS: &[&str] = &[
        "FAIL_ROOT_SECRET",
        "FAIL_LINK_SECRET",
        "FAIL_PENDING_SECRET",
        "FAIL_FORM_SECRET",
        "FAIL_CONTROL_SECRET",
        "FAIL_BODY_SECRET",
        "FAIL_COOKIE_SECRET",
        "FAIL_AUTH_SECRET",
        "FAIL_LOCATION_SECRET",
        "FAIL_RETRY_AFTER_SECRET",
        "FAIL_RATELIMIT_SECRET",
    ];
    let server = serve(|request| match request.path() {
        "/root" => FixtureReply::Response(
            FixtureResponse::html(
                "<p>FAIL_BODY_SECRET</p>\
                 <a href='/a?candidate=FAIL_LINK_SECRET'>a</a>\
                 <a href='/b?pending=FAIL_PENDING_SECRET'>b</a>\
                 <form action='/write?token=FAIL_FORM_SECRET' method='post'>\
                   <input name='csrf' value='FAIL_CONTROL_SECRET'>\
                 </form>",
            )
            .with_header("Set-Cookie", "failure=FAIL_COOKIE_SECRET")
            .with_header("WWW-Authenticate", "Bearer FAIL_AUTH_SECRET")
            .with_header("Location", "/unused?token=FAIL_LOCATION_SECRET")
            .with_header("Retry-After", "FAIL_RETRY_AFTER_SECRET")
            .with_header("X-RateLimit-Reset", "FAIL_RATELIMIT_SECRET"),
        ),
        "/a" => FixtureReply::CloseWithoutResponse,
        _ => FixtureReply::Response(FixtureResponse::html("done")),
    })
    .await;
    let mut runtime = WebAssessmentRuntime::builder(server.url("/root?root=FAIL_ROOT_SECRET"))
        .build()
        .unwrap();
    let error = runtime.analyze().await.unwrap_err();
    let receipt = error.failure_receipt().expect("started failure receipt");
    assert_failure_reconciles(receipt);
    assert_eq!(receipt.completed_subjects().len(), 1);
    assert_eq!(subject_path(&receipt.completed_subjects()[0]), "/root");
    assert_eq!(receipt.current_subject().url().path(), "/a");
    assert!(receipt.current_subject_report().was_executed());
    assert_eq!(receipt.pending_subjects().len(), 1);
    assert_eq!(receipt.pending_subjects()[0].url().path(), "/b");
    assert_eq!(receipt.forms().len(), 1);
    assert_eq!(receipt.forms()[0].action().path(), "/write");
    assert_eq!(receipt.forms()[0].query_parameter_names(), ["token"]);
    assert_eq!(receipt.forms()[0].control_names(), ["csrf"]);
    assert!(receipt
        .incomplete_reasons()
        .contains(&WebAssessmentIncompleteReason::SubjectExecutionIncomplete));
    assert_eq!(
        server
            .requests()
            .await
            .iter()
            .map(|request| request.path())
            .collect::<Vec<_>>(),
        ["/root", "/a"]
    );
    assert_eq!(receipt.transport().receipts().len(), 2);
    assert_eq!(
        receipt.transport().receipts()[1].outcome(),
        TransportDispatchOutcome::TransportFailure
    );
    let failure_debug = format!("{error:?}{receipt:?}");
    assert_no_secret(&failure_debug, FAILURE_SECRETS);
    assert!(!receipt.semantics().truncated);
    assert!(receipt.semantics().entities.iter().all(|entity| matches!(
        entity.entity_type(),
        SemanticEntityType::Endpoint | SemanticEntityType::Parameter
    )));
    let semantic_names = receipt
        .semantics()
        .entities
        .iter()
        .filter(|entity| entity.entity_type() == SemanticEntityType::Parameter)
        .flat_map(|entity| entity.attributes()["name"].iter().cloned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        semantic_names,
        BTreeSet::from([
            "candidate".to_owned(),
            "csrf".to_owned(),
            "pending".to_owned(),
            "token".to_owned(),
        ])
    );
    assert_no_secret(
        &serde_json::to_string(receipt.semantics()).unwrap(),
        FAILURE_SECRETS,
    );
    let subject_ids: Vec<_> = receipt
        .completed_subjects()
        .iter()
        .map(|report| report.subject().url().clone())
        .chain(std::iter::once(receipt.current_subject().url().clone()))
        .chain(
            receipt
                .pending_subjects()
                .iter()
                .map(|subject| subject.url().clone()),
        )
        .collect();
    let knowledge = subject_ids
        .iter()
        .map(|url| {
            let id = EntityId::new(format!("endpoint:{url}"))
                .expect("failure subject identity must be valid");
            format!("{:?}", runtime.knowledge().snapshot_for_subject(&id))
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert_no_secret(&knowledge, FAILURE_SECRETS);
    let nested_debug = format!(
        "{:?}{:?}",
        receipt.completed_subjects(),
        receipt.current_subject_report()
    );
    assert!(!nested_debug.contains("TransportDispatchAudit"));
    assert!(!nested_debug.contains("RuntimeUsage"));
}

#[tokio::test]
async fn ledger_only_subject_drift_returns_one_current_subject_and_typed_inventory_failure() {
    let server = serve(|_| FixtureReply::Response(FixtureResponse::html("done"))).await;
    let mut runtime = WebAssessmentRuntime::builder(server.url("/root"))
        .build()
        .unwrap();
    let ghost_url = server.url("/ledger-only");
    runtime.ledger.subjects.insert(
        ghost_url.to_string(),
        SubjectAdmission {
            method: WebAssessmentMethod::Head,
            query_parameter_names: BTreeSet::new(),
            executed: false,
        },
    );
    runtime.ledger.retain_url(&ghost_url);

    let error = runtime.analyze().await.unwrap_err();
    assert!(matches!(
        error,
        WebAssessmentRuntimeError::ProjectionInvariant { .. }
    ));
    let receipt = error.failure_receipt().expect("projection receipt");
    assert!(!receipt.inventory_consistent());
    assert_eq!(receipt.unrepresented_ledger_subjects(), 1);
    let root_occurrences = receipt
        .completed_subjects()
        .iter()
        .filter(|report| subject_path(report) == "/root")
        .count()
        + receipt
            .pending_subjects()
            .iter()
            .filter(|subject| subject.url().path() == "/root")
            .count()
        + usize::from(receipt.current_subject().url().path() == "/root");
    assert_eq!(root_occurrences, 1);
    assert!(receipt.completed_subjects().is_empty());
    assert!(receipt.pending_subjects().is_empty());
    assert_eq!(receipt.current_subject().url().path(), "/root");
    assert!(receipt.current_subject_report().was_executed());
    assert_eq!(receipt.usage().retained_subjects(), 1);
    assert_eq!(receipt.usage().executed_subjects(), 1);
    assert_eq!(server.hit_count("/root").await, 1);
    assert_eq!(server.hit_count("/ledger-only").await, 0);
}

#[tokio::test]
async fn zero_request_budget_is_typed_incomplete_without_network_io() {
    let server =
        serve(|_| FixtureReply::Response(FixtureResponse::html("network must not be reached")))
            .await;
    let limits = WebAssessmentLimits::default()
        .with_max_total_requests(0)
        .unwrap();
    let mut runtime = WebAssessmentRuntime::builder(server.url("/zero"))
        .limits(limits)
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    assert_report_reconciles(&report);
    assert!(report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::TotalRequestLimit));
    assert_eq!(report.usage().total_requests(), 0);
    assert_eq!(report.transport().receipts(), []);
    assert_eq!(server.requests().await, []);
}

#[test]
fn runtime_budget_dimension_mapping_remains_total_and_exhaustive() {
    let expected = [
        (
            RuntimeBudgetDimension::TotalRequests,
            WebAssessmentIncompleteReason::TotalRequestLimit,
        ),
        (
            RuntimeBudgetDimension::WallTime,
            WebAssessmentIncompleteReason::WallTimeLimit,
        ),
        (
            RuntimeBudgetDimension::ResponseBytes,
            WebAssessmentIncompleteReason::ResponseBytesLimit,
        ),
        (
            RuntimeBudgetDimension::RequestBodyBytes,
            WebAssessmentIncompleteReason::RequestBodyBytesLimit,
        ),
        (
            RuntimeBudgetDimension::ActiveVerifications,
            WebAssessmentIncompleteReason::ActiveVerificationLimit,
        ),
        (
            RuntimeBudgetDimension::SameActionAttempts,
            WebAssessmentIncompleteReason::SameActionAttemptLimit,
        ),
        (
            RuntimeBudgetDimension::ConsecutiveNoProgressTurns,
            WebAssessmentIncompleteReason::ConsecutiveNoProgressLimit,
        ),
    ];
    for (dimension, reason) in expected {
        assert_eq!(reason_for_runtime_dimension(dimension), reason);
    }
}
