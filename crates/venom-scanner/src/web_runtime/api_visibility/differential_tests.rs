use std::{future::pending, sync::Arc, time::Duration};

use serde::Deserialize;
use serde_json::{json, Value};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Mutex,
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use venom_core::{
    ApiEvidencePredicate, ApiKnowledgePredicate, ApiSurfaceKind, ApiVisibilityComparison,
    ApiVisibilityPairKind, ApiVisibilityResult, ConfidenceScore, EvidenceValue, HypothesisState,
    HypothesisStrength, KnowledgePredicate, Probability,
};

use super::*;
use crate::{
    ingest_api_visibility_observation, ApiVisibilityReviewDisposition, DecisionLoopState,
    EvidenceCalibration, EvidenceSelector, Expression, HttpEvidencePolicy, HypothesisConclusion,
    JsonPathPattern, KnowledgeLayer, KnowledgeWrite, PathDigest, ReasoningRule, RuleEngineError,
    RuntimeBudget, RuntimeBudgetDimension, StandardWebDecisionRuntime,
    StandardWebDecisionRuntimeError, VisibilityExplanationDisposition,
};

const OBSERVED_AT_MS: u64 = 1_800_000_000_000;
const CONTROL_SECRET: &str = "control-credential-sentinel";
const CANDIDATE_SECRET: &str = "candidate-credential-sentinel";
const COOKIE_SECRET: &str = "server-cookie-sentinel";
const AUTHORIZATION_FIXTURES: &[&str] = &[
    include_str!("../../../tests/fixtures/api_authorization/anonymous_authenticated.json"),
    include_str!("../../../tests/fixtures/api_authorization/owner_unrelated.json"),
    include_str!("../../../tests/fixtures/api_authorization/read_write_capability.json"),
];

#[derive(Deserialize)]
struct GoldenFixture {
    comparison_id: String,
    pair: String,
    dimension: String,
    baseline_context: String,
    candidate_context: String,
    resource_scope: String,
    expected_category: String,
    expected_path: String,
    expected_omitted_diff_count: u32,
    forbidden_values: Vec<String>,
    baseline: Value,
    candidate: Value,
}

fn golden_fixture() -> GoldenFixture {
    serde_json::from_str(AUTHORIZATION_FIXTURES[0]).unwrap()
}

enum Reply {
    Response {
        bytes: Vec<u8>,
        cancel_after_write: Option<CancellationToken>,
    },
    PartialThenStall(Vec<u8>),
    CancelThenStall(CancellationToken),
}

struct TestServer {
    target: url::Url,
    requests: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}

impl TestServer {
    fn target(&self) -> url::Url {
        self.target.clone()
    }

    async fn requests(&self) -> Vec<String> {
        self.requests.lock().await.clone()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(replies: Vec<Reply>) -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&requests);
    let task = tokio::spawn(async move {
        for reply in replies {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut chunk = [0_u8; 512];
                let bytes = stream.read(&mut chunk).await.unwrap();
                if bytes == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..bytes]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            recorded
                .lock()
                .await
                .push(String::from_utf8_lossy(&request).into_owned());
            match reply {
                Reply::Response {
                    bytes,
                    cancel_after_write,
                } => {
                    stream.write_all(&bytes).await.unwrap();
                    stream.shutdown().await.unwrap();
                    if let Some(cancellation) = cancel_after_write {
                        cancellation.cancel();
                    }
                },
                Reply::PartialThenStall(bytes) => {
                    stream.write_all(&bytes).await.unwrap();
                    stream.flush().await.unwrap();
                    pending::<()>().await;
                },
                Reply::CancelThenStall(cancellation) => {
                    cancellation.cancel();
                    pending::<()>().await;
                },
            }
        }
    });
    TestServer {
        target: url::Url::parse(&format!("http://{address}/api/accounts/42")).unwrap(),
        requests,
        task,
    }
}

async fn serve_keep_alive_pair(control_body: &Value, candidate_body: &Value) -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&requests);
    let control_response = String::from_utf8(json_response(200, control_body, &[]))
        .unwrap()
        .replace("Connection: close", "Connection: keep-alive")
        .into_bytes();
    let candidate_response = json_response(200, candidate_body, &[]);
    let task = tokio::spawn(async move {
        let (mut control, _) = listener.accept().await.unwrap();
        let mut control_request = Vec::new();
        loop {
            let mut chunk = [0_u8; 512];
            let bytes = control.read(&mut chunk).await.unwrap();
            control_request.extend_from_slice(&chunk[..bytes]);
            if bytes == 0
                || control_request
                    .windows(4)
                    .any(|window| window == b"\r\n\r\n")
            {
                break;
            }
        }
        recorded
            .lock()
            .await
            .push(String::from_utf8_lossy(&control_request).into_owned());
        control.write_all(&control_response).await.unwrap();
        control.flush().await.unwrap();

        let (mut candidate, _) = tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .expect("candidate context must use a separate connection pool")
            .unwrap();
        let mut candidate_request = Vec::new();
        loop {
            let mut chunk = [0_u8; 512];
            let bytes = candidate.read(&mut chunk).await.unwrap();
            candidate_request.extend_from_slice(&chunk[..bytes]);
            if bytes == 0
                || candidate_request
                    .windows(4)
                    .any(|window| window == b"\r\n\r\n")
            {
                break;
            }
        }
        recorded
            .lock()
            .await
            .push(String::from_utf8_lossy(&candidate_request).into_owned());
        candidate.write_all(&candidate_response).await.unwrap();
        candidate.shutdown().await.unwrap();
        control.shutdown().await.unwrap();
    });
    TestServer {
        target: url::Url::parse(&format!("http://{address}/api/accounts/42")).unwrap(),
        requests,
        task,
    }
}

fn json_response(status: u16, body: &Value, extra_headers: &[(&str, &str)]) -> Vec<u8> {
    let body = serde_json::to_vec(body).unwrap();
    let status_text = match status {
        200 => "OK",
        302 => "Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Status",
    };
    let mut response = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    )
    .into_bytes();
    for (name, value) in extra_headers {
        response.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    response.extend_from_slice(b"\r\n");
    response.extend_from_slice(&body);
    response
}

fn partial_json_response(body_prefix: &[u8], declared_length: usize) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {declared_length}\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    response.extend_from_slice(body_prefix);
    response
}

fn profile() -> ApiComparisonProfile {
    ApiComparisonProfile::new(
        Vec::new(),
        ["/meta/request_id", "/meta/timestamp"]
            .into_iter()
            .map(|path| JsonPathPattern::new(path).unwrap())
            .collect(),
        Vec::new(),
        8,
    )
    .unwrap()
}

fn pair_request(target: &url::Url, fixture: &GoldenFixture) -> ApiVisibilityDifferentialRequest {
    assert_eq!(fixture.pair, "authorization-context");
    let dimension = match fixture.dimension.as_str() {
        "fields" => ApiVisibilityDimension::Fields,
        "resources" => ApiVisibilityDimension::Resources,
        other => panic!("unsupported authorization fixture dimension {other}"),
    };
    let control = HttpProbe::new(target.clone(), HttpProbeMethod::Get)
        .unwrap()
        .with_header("authorization", format!("Bearer {CONTROL_SECRET}"))
        .unwrap()
        .with_header("accept", "application/json")
        .unwrap();
    let candidate = HttpProbe::new(target.clone(), HttpProbeMethod::Get)
        .unwrap()
        .with_header("authorization", format!("Bearer {CANDIDATE_SECRET}"))
        .unwrap()
        .with_header("accept", "application/json")
        .unwrap();
    ApiVisibilityDifferentialRequest::new(
        &fixture.comparison_id,
        EntityId::new(&fixture.resource_scope).unwrap(),
        ApiVisibilityContextProbe::new(&fixture.baseline_context, control).unwrap(),
        ApiVisibilityContextProbe::new(&fixture.candidate_context, candidate).unwrap(),
        ["authorization"],
        profile(),
        dimension,
        OBSERVED_AT_MS,
    )
    .unwrap()
}

fn assert_fixture_diff(fixture: &GoldenFixture, comparison: &ProfiledApiVisibilityComparison) {
    let expected = PathDigest::for_pattern(&JsonPathPattern::new(&fixture.expected_path).unwrap());
    let observed = match fixture.expected_category.as_str() {
        "added" => comparison.diff().added_path_hashes(),
        "removed" => comparison.diff().removed_path_hashes(),
        "changed_value" => comparison.diff().changed_value_path_hashes(),
        other => panic!("unsupported authorization fixture category {other}"),
    };
    assert_eq!(observed, [expected]);
    assert_eq!(
        comparison.diff().omitted_diff_count(),
        fixture.expected_omitted_diff_count
    );
}

fn runtime(
    target: url::Url,
    budget: RuntimeBudget,
    timeout: Duration,
) -> StandardWebDecisionRuntime {
    let policy = HttpEvidencePolicy::new([target.clone()], timeout, 64 * 1024).unwrap();
    StandardWebDecisionRuntime::builder(target)
        .http_policy(policy)
        .runtime_budget(budget)
        .enable_api_reasoning()
        .build()
        .unwrap()
}

#[tokio::test]
async fn different_complete_pair_yields_review_without_a_vulnerability_verdict() {
    let fixture = golden_fixture();
    let control_body = serde_json::to_vec(&fixture.baseline).unwrap();
    let candidate_body = serde_json::to_vec(&fixture.candidate).unwrap();
    let server = serve(vec![
        Reply::Response {
            bytes: json_response(
                200,
                &fixture.baseline,
                &[("Set-Cookie", &format!("session={COOKIE_SECRET}; Path=/"))],
            ),
            cancel_after_write: None,
        },
        Reply::Response {
            bytes: json_response(200, &fixture.candidate, &[]),
            cancel_after_write: None,
        },
    ])
    .await;
    let target = server.target();
    let request = pair_request(&target, &fixture);
    let request_debug = format!("{request:?}");
    assert!(!request_debug.contains(CONTROL_SECRET));
    assert!(!request_debug.contains(CANDIDATE_SECRET));
    let mut runtime = runtime(
        target,
        RuntimeBudget::default()
            .with_max_total_requests(2)
            .with_max_active_verifications(2),
        Duration::from_secs(1),
    );

    let report = runtime.run_api_visibility_pair(request).await.unwrap();

    assert_eq!(
        report.disposition(),
        ApiVisibilityDifferentialDisposition::AwaitHumanReview
    );
    assert_eq!(report.audit().usage().total_requests(), 2);
    assert_eq!(report.audit().usage().active_verifications(), 2);
    assert_eq!(report.audit().usage().passive_requests(), 0);
    assert_eq!(report.audit().usage().planned_requests(), 0);
    assert_eq!(
        report.audit().usage().response_bytes(),
        u64::try_from(control_body.len() + candidate_body.len()).unwrap()
    );
    assert!(report.limit_exceeded().is_none());
    assert!(report.audit().control().is_some());
    assert!(report.audit().candidate().is_some());
    assert_eq!(
        report.audit().comparison_id().as_str(),
        fixture.comparison_id
    );
    assert_eq!(
        report.audit().resource_scope_id().as_str(),
        fixture.resource_scope
    );
    assert_eq!(
        report.audit().control_context_id().as_str(),
        fixture.baseline_context
    );
    assert_eq!(
        report.audit().candidate_context_id().as_str(),
        fixture.candidate_context
    );
    assert_eq!(report.audit().dimension(), ApiVisibilityDimension::Fields);
    assert_eq!(report.audit().observed_at_ms(), OBSERVED_AT_MS);
    assert_eq!(report.audit().operation_sha256().len(), 64);
    assert_eq!(report.audit().request_template_sha256().len(), 64);

    let comparison = report.comparison().unwrap();
    assert_eq!(
        comparison.comparison().result(),
        ApiVisibilityResult::Different
    );
    let expected = PathDigest::for_pattern(&JsonPathPattern::new(&fixture.expected_path).unwrap());
    assert_eq!(fixture.expected_category, "added");
    assert_eq!(comparison.diff().added_path_hashes(), [expected]);
    assert_eq!(
        comparison.diff().omitted_diff_count(),
        fixture.expected_omitted_diff_count
    );
    let review = report.review().unwrap();
    assert_eq!(
        review.disposition(),
        ApiVisibilityReviewDisposition::AwaitHumanReview
    );
    assert_eq!(review.boundary_hypotheses().len(), 1);
    let boundary = &review.boundary_hypotheses()[0];
    assert_eq!(boundary.strength(), HypothesisStrength::Weak);
    assert_eq!(boundary.state(), HypothesisState::Supported);
    assert_eq!(
        boundary.predicate(),
        &ApiKnowledgePredicate::VISIBILITY_BOUNDARY.into_knowledge()
    );
    assert_eq!(boundary.belief().evidence().len(), 1);
    assert!(runtime.experience().is_empty());
    assert!(runtime.has_started());
    assert!(matches!(
        runtime.session().state(),
        DecisionLoopState::Ready
    ));

    let requests = server.requests().await;
    assert_eq!(requests.len(), 2);
    assert!(requests[0].contains(CONTROL_SECRET));
    assert!(!requests[0].contains(CANDIDATE_SECRET));
    assert!(requests[1].contains(CANDIDATE_SECRET));
    assert!(!requests[1].contains(CONTROL_SECRET));
    assert!(!requests[1].contains(COOKIE_SECRET));

    let serialized = serde_json::to_string(&report).unwrap();
    let debug = format!("{report:?}");
    for secret in [CONTROL_SECRET, CANDIDATE_SECRET, COOKIE_SECRET] {
        assert!(!serialized.contains(secret));
        assert!(!debug.contains(secret));
    }
    for forbidden in &fixture.forbidden_values {
        assert!(!serialized.contains(forbidden));
        assert!(!debug.contains(forbidden));
    }
    for opaque in [
        &fixture.comparison_id,
        &fixture.resource_scope,
        &fixture.baseline_context,
        &fixture.candidate_context,
    ] {
        assert!(serialized.contains(opaque));
        assert!(!debug.contains(opaque));
    }
}

#[tokio::test]
async fn every_authorization_golden_pair_uses_the_broker_and_stays_review_only() {
    for encoded in AUTHORIZATION_FIXTURES {
        let fixture: GoldenFixture = serde_json::from_str(encoded).unwrap();
        let server = serve(vec![
            Reply::Response {
                bytes: json_response(200, &fixture.baseline, &[]),
                cancel_after_write: None,
            },
            Reply::Response {
                bytes: json_response(200, &fixture.candidate, &[]),
                cancel_after_write: None,
            },
        ])
        .await;
        let target = server.target();
        let mut runtime = runtime(
            target.clone(),
            RuntimeBudget::default()
                .with_max_total_requests(2)
                .with_max_active_verifications(2),
            Duration::from_secs(1),
        );

        let report = runtime
            .run_api_visibility_pair(pair_request(&target, &fixture))
            .await
            .unwrap();

        assert_eq!(
            report.disposition(),
            ApiVisibilityDifferentialDisposition::AwaitHumanReview
        );
        assert_fixture_diff(&fixture, report.comparison().unwrap());
        assert_eq!(
            report.review().unwrap().disposition(),
            ApiVisibilityReviewDisposition::AwaitHumanReview
        );
        assert_eq!(report.audit().usage().total_requests(), 2);
        assert_eq!(report.audit().usage().active_verifications(), 2);
        assert!(runtime.experience().is_empty());
        assert!(matches!(
            runtime.session().state(),
            DecisionLoopState::Ready
        ));
        assert!(runtime
            .knowledge()
            .hypotheses_for_subject(&report.comparison().unwrap().comparison().subject())
            .iter()
            .all(|hypothesis| !matches!(
                hypothesis.state(),
                HypothesisState::Confirmed | HypothesisState::Rejected
            )));
        assert_eq!(server.requests().await.len(), 2);

        let serialized = serde_json::to_string(&report).unwrap();
        for forbidden in &fixture.forbidden_values {
            assert!(!serialized.contains(forbidden));
        }
    }
}

#[tokio::test]
async fn authorization_contexts_use_distinct_connection_pools_with_shared_accounting() {
    let fixture = golden_fixture();
    let server = serve_keep_alive_pair(&fixture.baseline, &fixture.candidate).await;
    let target = server.target();
    let mut runtime = runtime(
        target.clone(),
        RuntimeBudget::default()
            .with_max_total_requests(2)
            .with_max_active_verifications(2),
        Duration::from_secs(2),
    );

    let report = runtime
        .run_api_visibility_pair(pair_request(&target, &fixture))
        .await
        .unwrap();

    assert_eq!(
        report.disposition(),
        ApiVisibilityDifferentialDisposition::AwaitHumanReview
    );
    assert_eq!(report.audit().usage().total_requests(), 2);
    assert_eq!(report.audit().usage().active_verifications(), 2);
    assert_eq!(server.requests().await.len(), 2);
}

#[tokio::test]
async fn equivalent_pair_produces_no_boundary_hypothesis() {
    let fixture = golden_fixture();
    let equivalent = json!({
        "data": {"account_id": "acct-42"},
        "meta": {"request_id": "changed", "timestamp": 42}
    });
    let server = serve(vec![
        Reply::Response {
            bytes: json_response(200, &fixture.baseline, &[]),
            cancel_after_write: None,
        },
        Reply::Response {
            bytes: json_response(200, &equivalent, &[]),
            cancel_after_write: None,
        },
    ])
    .await;
    let target = server.target();
    let mut runtime = runtime(
        target.clone(),
        RuntimeBudget::default(),
        Duration::from_secs(1),
    );

    let report = runtime
        .run_api_visibility_pair(pair_request(&target, &fixture))
        .await
        .unwrap();

    assert_eq!(
        report.disposition(),
        ApiVisibilityDifferentialDisposition::NoDifferenceObserved
    );
    assert_eq!(
        report.comparison().unwrap().comparison().result(),
        ApiVisibilityResult::Equivalent
    );
    assert!(report.comparison().unwrap().diff().is_empty());
    assert!(report.review().unwrap().boundary_hypotheses().is_empty());
}

#[tokio::test]
async fn review_projection_returns_the_exact_new_commit_after_prior_resource_relations() {
    let fixture = golden_fixture();
    let server = serve(vec![
        Reply::Response {
            bytes: json_response(200, &fixture.baseline, &[]),
            cancel_after_write: None,
        },
        Reply::Response {
            bytes: json_response(200, &fixture.candidate, &[]),
            cancel_after_write: None,
        },
    ])
    .await;
    let target = server.target();
    let mut runtime = runtime(
        target.clone(),
        RuntimeBudget::default(),
        Duration::from_secs(1),
    );
    let resource = EntityId::new(&fixture.resource_scope).unwrap();
    for index in 0..3 {
        let prior = ApiVisibilityComparison::new(
            format!("prior-{index}"),
            ApiSurfaceKind::JsonHttp,
            ApiVisibilityPairKind::AuthorizationContext,
            ApiVisibilityResult::Equivalent,
            ApiVisibilityDimension::Fields,
            format!("prior-control-{index}"),
            format!("prior-candidate-{index}"),
            resource.as_str(),
        )
        .unwrap()
        .with_observed_at_ms(OBSERVED_AT_MS - 1)
        .to_observation("test.prior", ConfidenceScore::MAX)
        .unwrap();
        ingest_api_visibility_observation(
            prior,
            &resource,
            runtime.knowledge(),
            runtime.decision_loop.rules(),
        )
        .unwrap();
    }

    let report = runtime
        .run_api_visibility_pair(pair_request(&target, &fixture))
        .await
        .unwrap();

    let observation = report.observation().unwrap().commit();
    let review = report.review().unwrap();
    assert_eq!(review.relation_id(), observation.relation_id());
    assert_eq!(review.evidence().id(), observation.evidence_id());
    assert_eq!(
        review.comparison_subject(),
        observation.comparison_subject()
    );
}

#[tokio::test]
async fn json_status_difference_has_no_body_path_claim_and_requires_review() {
    let fixture = golden_fixture();
    let server = serve(vec![
        Reply::Response {
            bytes: json_response(401, &json!({"error": "unauthorized"}), &[]),
            cancel_after_write: None,
        },
        Reply::Response {
            bytes: json_response(200, &fixture.candidate, &[]),
            cancel_after_write: None,
        },
    ])
    .await;
    let target = server.target();
    let mut request = pair_request(&target, &fixture);
    request.dimension = ApiVisibilityDimension::Status;
    let mut runtime = runtime(target, RuntimeBudget::default(), Duration::from_secs(1));

    let report = runtime.run_api_visibility_pair(request).await.unwrap();

    assert_eq!(
        report.disposition(),
        ApiVisibilityDifferentialDisposition::AwaitHumanReview
    );
    let comparison = report.comparison().unwrap();
    assert_eq!(
        comparison.comparison().result(),
        ApiVisibilityResult::Different
    );
    assert_eq!(
        comparison.comparison().dimension(),
        ApiVisibilityDimension::Status
    );
    assert!(comparison.diff().is_empty());
    assert_eq!(
        comparison.explanation_disposition(),
        VisibilityExplanationDisposition::DifferenceWithoutPathSummary
    );
    assert_eq!(report.review().unwrap().boundary_hypotheses().len(), 1);
}

#[tokio::test]
async fn candidate_request_budget_denial_preserves_control_audit() {
    let fixture = golden_fixture();
    let server = serve(vec![Reply::Response {
        bytes: json_response(200, &fixture.baseline, &[]),
        cancel_after_write: None,
    }])
    .await;
    let target = server.target();
    let mut runtime = runtime(
        target.clone(),
        RuntimeBudget::default()
            .with_max_total_requests(1)
            .with_max_active_verifications(2),
        Duration::from_secs(1),
    );

    let report = runtime
        .run_api_visibility_pair(pair_request(&target, &fixture))
        .await
        .unwrap();

    assert_eq!(
        report.disposition(),
        ApiVisibilityDifferentialDisposition::RuntimeBudgetLimit
    );
    assert_eq!(report.stopped_leg(), Some(ApiVisibilityLeg::Candidate));
    assert_eq!(
        report.limit_exceeded().unwrap().dimension(),
        RuntimeBudgetDimension::TotalRequests
    );
    assert_eq!(report.audit().usage().total_requests(), 1);
    assert_eq!(report.audit().usage().active_verifications(), 1);
    assert!(report.audit().control().is_some());
    assert!(report.audit().candidate().is_none());
    assert!(report.comparison().is_none());
    assert!(report.review().is_none());
    assert!(matches!(
        runtime.session().state(),
        DecisionLoopState::Ready
    ));
    assert_eq!(server.requests().await.len(), 1);
}

#[tokio::test]
async fn candidate_active_budget_denial_happens_before_socket() {
    let fixture = golden_fixture();
    let server = serve(vec![Reply::Response {
        bytes: json_response(200, &fixture.baseline, &[]),
        cancel_after_write: None,
    }])
    .await;
    let target = server.target();
    let mut runtime = runtime(
        target.clone(),
        RuntimeBudget::default()
            .with_max_total_requests(2)
            .with_max_active_verifications(1),
        Duration::from_secs(1),
    );

    let report = runtime
        .run_api_visibility_pair(pair_request(&target, &fixture))
        .await
        .unwrap();

    assert_eq!(
        report.limit_exceeded().unwrap().dimension(),
        RuntimeBudgetDimension::ActiveVerifications
    );
    assert_eq!(report.audit().usage().total_requests(), 1);
    assert_eq!(report.audit().usage().active_verifications(), 1);
    assert_eq!(server.requests().await.len(), 1);
    assert!(matches!(
        runtime.session().state(),
        DecisionLoopState::Ready
    ));
}

#[tokio::test]
async fn candidate_crossing_response_budget_is_charged_and_cannot_commit() {
    let fixture = golden_fixture();
    let control_bytes = serde_json::to_vec(&fixture.baseline).unwrap().len();
    let candidate_bytes = serde_json::to_vec(&fixture.candidate).unwrap().len();
    let server = serve(vec![
        Reply::Response {
            bytes: json_response(200, &fixture.baseline, &[]),
            cancel_after_write: None,
        },
        Reply::Response {
            bytes: json_response(200, &fixture.candidate, &[]),
            cancel_after_write: None,
        },
    ])
    .await;
    let target = server.target();
    let limit = u64::try_from(control_bytes + 1).unwrap();
    let mut runtime = runtime(
        target.clone(),
        RuntimeBudget::default().with_max_response_bytes(limit),
        Duration::from_secs(1),
    );

    let report = runtime
        .run_api_visibility_pair(pair_request(&target, &fixture))
        .await
        .unwrap();

    assert_eq!(
        report.disposition(),
        ApiVisibilityDifferentialDisposition::RuntimeBudgetLimit
    );
    assert_eq!(
        report.limit_exceeded().unwrap().dimension(),
        RuntimeBudgetDimension::ResponseBytes
    );
    assert_eq!(
        report.audit().usage().response_bytes(),
        u64::try_from(control_bytes + candidate_bytes).unwrap()
    );
    assert!(report.audit().candidate().unwrap().body_truncated());
    assert!(report.comparison().is_none());
    assert!(report.observation().is_none());
    assert!(report.review().is_none());
    assert_eq!(server.requests().await.len(), 2);
}

#[tokio::test]
async fn malformed_candidate_is_inconclusive_and_never_commits_comparison() {
    let fixture = golden_fixture();
    let malformed = Value::String("unused".to_owned());
    let mut malformed_response = json_response(200, &malformed, &[]);
    let body_start = malformed_response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;
    malformed_response.truncate(body_start);
    malformed_response.extend_from_slice(b"{not-json}");
    let declared = b"\"unused\"".len().to_string();
    let encoded = String::from_utf8_lossy(&malformed_response)
        .replace(&format!("Content-Length: {declared}"), "Content-Length: 10");
    let server = serve(vec![
        Reply::Response {
            bytes: json_response(200, &fixture.baseline, &[]),
            cancel_after_write: None,
        },
        Reply::Response {
            bytes: encoded.into_bytes(),
            cancel_after_write: None,
        },
    ])
    .await;
    let target = server.target();
    let mut runtime = runtime(
        target.clone(),
        RuntimeBudget::default(),
        Duration::from_secs(1),
    );

    let report = runtime
        .run_api_visibility_pair(pair_request(&target, &fixture))
        .await
        .unwrap();

    assert_eq!(
        report.disposition(),
        ApiVisibilityDifferentialDisposition::Inconclusive
    );
    assert_eq!(report.stopped_leg(), Some(ApiVisibilityLeg::Candidate));
    assert_eq!(
        report.inconclusive_reason(),
        Some(ApiVisibilityInconclusiveReason::MalformedJson)
    );
    assert!(report.comparison().is_none());
    assert!(report.observation().is_none());
    assert!(report.review().is_none());
    assert!(report.audit().candidate().is_some());
}

#[tokio::test]
async fn rate_limited_and_server_error_control_responses_never_reach_comparator() {
    let fixture = golden_fixture();
    for (status, reason) in [
        (429, ApiVisibilityInconclusiveReason::RateLimited),
        (500, ApiVisibilityInconclusiveReason::ServerError),
    ] {
        let server = serve(vec![Reply::Response {
            bytes: json_response(status, &json!({"error": "bounded"}), &[]),
            cancel_after_write: None,
        }])
        .await;
        let target = server.target();
        let mut runtime = runtime(
            target.clone(),
            RuntimeBudget::default(),
            Duration::from_secs(1),
        );

        let report = runtime
            .run_api_visibility_pair(pair_request(&target, &fixture))
            .await
            .unwrap();

        assert_eq!(
            report.disposition(),
            ApiVisibilityDifferentialDisposition::Inconclusive
        );
        assert_eq!(report.stopped_leg(), Some(ApiVisibilityLeg::Control));
        assert_eq!(report.inconclusive_reason(), Some(reason));
        assert!(report.comparison().is_none());
        assert!(report.observation().is_none());
        assert!(report.review().is_none());
        assert_eq!(server.requests().await.len(), 1);
    }
}

#[tokio::test]
async fn post_commit_reasoning_failure_preserves_comparison_audit_and_knowledge_receipt() {
    let fixture = golden_fixture();
    let server = serve(vec![
        Reply::Response {
            bytes: json_response(200, &fixture.baseline, &[]),
            cancel_after_write: None,
        },
        Reply::Response {
            bytes: json_response(200, &fixture.candidate, &[]),
            cancel_after_write: None,
        },
    ])
    .await;
    let target = server.target();
    let mut runtime = runtime(
        target.clone(),
        RuntimeBudget::default(),
        Duration::from_secs(1),
    );
    let comparison_predicate =
        ApiEvidencePredicate::JSON_AUTHORIZATION_CONTEXT_DIFFERENCE.into_knowledge();
    let unrelated = KnowledgePredicate::new("test", "unrelated").unwrap();
    runtime
        .decision_loop
        .rules_mut()
        .register(
            ReasoningRule::new(
                "000.runtime-differential-invalid-calibration",
                Expression::exists(KnowledgeLayer::Evidence, comparison_predicate),
                HypothesisConclusion::new(
                    KnowledgePredicate::new("test", "result").unwrap(),
                    EvidenceValue::Boolean(true),
                    Probability::from_percent(10).unwrap(),
                    HypothesisStrength::Weak,
                    HypothesisState::Supported,
                    vec![EvidenceCalibration::new(
                        EvidenceSelector::exists(unrelated),
                        Probability::from_percent(90).unwrap(),
                        Probability::from_percent(10).unwrap(),
                        "deliberately cannot bind the paired comparison",
                    )
                    .unwrap()],
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();

    let error = runtime
        .run_api_visibility_pair(pair_request(&target, &fixture))
        .await
        .unwrap_err();

    assert!(matches!(
        &error,
        RuntimeApiVisibilityExecutionError::Observation { source, .. }
            if matches!(source.reasoning_source(), Some(RuleEngineError::MissingCalibratedEvidence { .. }))
    ));
    assert_eq!(error.audit().unwrap().usage().total_requests(), 2);
    assert!(error.comparison().is_some());
    let commit = error.committed_observation().unwrap();
    assert_eq!(commit.evidence_write(), KnowledgeWrite::Inserted);
    assert_eq!(commit.relation_write(), KnowledgeWrite::Inserted);
    assert!(runtime.knowledge().evidence(commit.evidence_id()).is_some());
    assert!(runtime.knowledge().relation(commit.relation_id()).is_some());
}

#[tokio::test]
async fn comparison_evidence_uses_http_policy_reliability() {
    let fixture = golden_fixture();
    let server = serve(vec![
        Reply::Response {
            bytes: json_response(200, &fixture.baseline, &[]),
            cancel_after_write: None,
        },
        Reply::Response {
            bytes: json_response(200, &fixture.candidate, &[]),
            cancel_after_write: None,
        },
    ])
    .await;
    let target = server.target();
    let reliability = ConfidenceScore::from_percent(55).unwrap();
    let policy = HttpEvidencePolicy::new([target.clone()], Duration::from_secs(1), 64 * 1024)
        .unwrap()
        .with_reliability(reliability)
        .unwrap();
    let mut runtime = StandardWebDecisionRuntime::builder(target.clone())
        .http_policy(policy)
        .enable_api_reasoning()
        .build()
        .unwrap();

    let report = runtime
        .run_api_visibility_pair(pair_request(&target, &fixture))
        .await
        .unwrap();

    assert_eq!(
        report.review().unwrap().evidence().reliability(),
        reliability
    );
}

#[tokio::test]
async fn partial_candidate_timeout_keeps_control_and_transport_usage() {
    let fixture = golden_fixture();
    let control_bytes = serde_json::to_vec(&fixture.baseline).unwrap().len();
    let server = serve(vec![
        Reply::Response {
            bytes: json_response(200, &fixture.baseline, &[]),
            cancel_after_write: None,
        },
        Reply::PartialThenStall(partial_json_response(b"{\"x\"", 20)),
    ])
    .await;
    let target = server.target();
    let mut runtime = runtime(
        target.clone(),
        RuntimeBudget::default(),
        Duration::from_millis(500),
    );

    let report = runtime
        .run_api_visibility_pair(pair_request(&target, &fixture))
        .await
        .unwrap();

    assert_eq!(
        report.inconclusive_reason(),
        Some(ApiVisibilityInconclusiveReason::RequestTimeout)
    );
    assert_eq!(report.audit().usage().total_requests(), 2);
    assert_eq!(report.audit().usage().active_verifications(), 2);
    assert_eq!(
        report.audit().usage().response_bytes(),
        u64::try_from(control_bytes + 4).unwrap()
    );
    assert!(report.audit().control().is_some());
    assert!(report.audit().candidate().is_none());
    assert!(report.comparison().is_none());
    assert!(report.observation().is_none());
    assert!(report.review().is_none());
}

#[tokio::test]
async fn pre_cancelled_pair_keeps_intent_audit_and_opens_no_socket() {
    let fixture = golden_fixture();
    let server = serve(Vec::new()).await;
    let target = server.target();
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let policy =
        HttpEvidencePolicy::new([target.clone()], Duration::from_secs(1), 64 * 1024).unwrap();
    let mut runtime = StandardWebDecisionRuntime::builder(target.clone())
        .http_policy(policy)
        .cancellation_token(cancellation)
        .enable_api_reasoning()
        .build()
        .unwrap();

    let report = runtime
        .run_api_visibility_pair(pair_request(&target, &fixture))
        .await
        .unwrap();

    assert_eq!(
        report.disposition(),
        ApiVisibilityDifferentialDisposition::CancelledByHost
    );
    assert_eq!(report.stopped_leg(), None);
    assert_eq!(report.audit().usage().total_requests(), 0);
    assert_eq!(
        report.audit().comparison_id().as_str(),
        fixture.comparison_id
    );
    assert_eq!(report.audit().operation_sha256().len(), 64);
    assert!(server.requests().await.is_empty());
    assert!(matches!(
        runtime.session().state(),
        DecisionLoopState::Ready
    ));
}

#[tokio::test]
async fn cancellation_ready_with_malformed_response_wins_before_json_classification() {
    let fixture = golden_fixture();
    let cancellation = CancellationToken::new();
    let malformed = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10\r\nConnection: close\r\n\r\n{not-json}".to_vec();
    let server = serve(vec![Reply::Response {
        bytes: malformed,
        cancel_after_write: Some(cancellation.clone()),
    }])
    .await;
    let target = server.target();
    let policy =
        HttpEvidencePolicy::new([target.clone()], Duration::from_secs(1), 64 * 1024).unwrap();
    let mut runtime = StandardWebDecisionRuntime::builder(target.clone())
        .http_policy(policy)
        .cancellation_token(cancellation)
        .enable_api_reasoning()
        .build()
        .unwrap();

    let report = runtime
        .run_api_visibility_pair(pair_request(&target, &fixture))
        .await
        .unwrap();

    assert_eq!(
        report.disposition(),
        ApiVisibilityDifferentialDisposition::CancelledByHost
    );
    assert!(report.inconclusive_reason().is_none());
    assert!(report.comparison().is_none());
    assert!(report.observation().is_none());
    assert_eq!(report.audit().usage().total_requests(), 1);
}

#[tokio::test]
async fn cancellation_during_candidate_preserves_control_and_charged_dispatch() {
    let fixture = golden_fixture();
    let cancellation = CancellationToken::new();
    let server = serve(vec![
        Reply::Response {
            bytes: json_response(200, &fixture.baseline, &[]),
            cancel_after_write: None,
        },
        Reply::CancelThenStall(cancellation.clone()),
    ])
    .await;
    let target = server.target();
    let policy =
        HttpEvidencePolicy::new([target.clone()], Duration::from_secs(1), 64 * 1024).unwrap();
    let mut runtime = StandardWebDecisionRuntime::builder(target.clone())
        .http_policy(policy)
        .cancellation_token(cancellation)
        .enable_api_reasoning()
        .build()
        .unwrap();

    let report = runtime
        .run_api_visibility_pair(pair_request(&target, &fixture))
        .await
        .unwrap();

    assert_eq!(
        report.disposition(),
        ApiVisibilityDifferentialDisposition::CancelledByHost
    );
    assert_eq!(report.stopped_leg(), Some(ApiVisibilityLeg::Candidate));
    assert_eq!(report.audit().usage().total_requests(), 2);
    assert!(report.audit().control().is_some());
    assert!(report.audit().candidate().is_none());
    assert_eq!(server.requests().await.len(), 2);
    assert!(matches!(
        runtime.session().state(),
        DecisionLoopState::Ready
    ));
}

#[tokio::test]
async fn redirect_is_observed_without_following_location() {
    let fixture = golden_fixture();
    let server = serve(vec![
        Reply::Response {
            bytes: json_response(
                302,
                &fixture.baseline,
                &[("Location", "http://127.0.0.1:9/outside")],
            ),
            cancel_after_write: None,
        },
        Reply::Response {
            bytes: json_response(200, &fixture.candidate, &[]),
            cancel_after_write: None,
        },
    ])
    .await;
    let target = server.target();
    let mut runtime = runtime(
        target.clone(),
        RuntimeBudget::default(),
        Duration::from_secs(1),
    );

    let report = runtime
        .run_api_visibility_pair(pair_request(&target, &fixture))
        .await
        .unwrap();

    assert_eq!(report.audit().usage().total_requests(), 2);
    assert_eq!(server.requests().await.len(), 2);
    assert!(report.comparison().is_some());
}

#[test]
fn pair_validation_rejects_template_aliases_and_redacts_credentials() {
    let target = url::Url::parse("https://example.test/api/accounts/42").unwrap();
    let other = url::Url::parse("https://example.test/api/accounts/43").unwrap();
    let control = HttpProbe::new(target.clone(), HttpProbeMethod::Get)
        .unwrap()
        .with_header("authorization", CONTROL_SECRET)
        .unwrap();
    assert!(!format!("{control:?}").contains(CONTROL_SECRET));
    let candidate = HttpProbe::new(other, HttpProbeMethod::Get)
        .unwrap()
        .with_header("authorization", CANDIDATE_SECRET)
        .unwrap();
    let error = ApiVisibilityDifferentialRequest::new(
        "comparison",
        EntityId::new("resource:42").unwrap(),
        ApiVisibilityContextProbe::new("control", control).unwrap(),
        ApiVisibilityContextProbe::new("candidate", candidate).unwrap(),
        ["authorization"],
        profile(),
        ApiVisibilityDimension::Fields,
        OBSERVED_AT_MS,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        ApiVisibilityDifferentialRequestError::RequestTargetMismatch
    ));

    let same_control = HttpProbe::new(target.clone(), HttpProbeMethod::Get)
        .unwrap()
        .with_header("authorization", CONTROL_SECRET)
        .unwrap();
    let same_candidate = HttpProbe::new(target, HttpProbeMethod::Get)
        .unwrap()
        .with_header("authorization", CONTROL_SECRET)
        .unwrap();
    let same_error = ApiVisibilityDifferentialRequest::new(
        "comparison",
        EntityId::new("resource:42").unwrap(),
        ApiVisibilityContextProbe::new("control", same_control).unwrap(),
        ApiVisibilityContextProbe::new("candidate", same_candidate).unwrap(),
        ["authorization"],
        profile(),
        ApiVisibilityDimension::Fields,
        OBSERVED_AT_MS,
    )
    .unwrap_err();
    assert!(matches!(
        same_error,
        ApiVisibilityDifferentialRequestError::IdenticalAuthorizationContext
    ));
}

#[test]
fn pair_validation_rejects_non_auth_differences_insecure_transport_and_oversized_input() {
    let https = url::Url::parse("https://example.test/api/accounts/42").unwrap();
    let probe = |target: url::Url, auth: &str, accept: &str, csrf: &str| {
        HttpProbe::new(target, HttpProbeMethod::Get)
            .unwrap()
            .with_header("authorization", auth)
            .unwrap()
            .with_header("accept", accept)
            .unwrap()
            .with_header("x-csrf-token", csrf)
            .unwrap()
    };
    let build = |control: HttpProbe,
                 candidate: HttpProbe,
                 context_headers: Vec<&str>,
                 resource: EntityId| {
        ApiVisibilityDifferentialRequest::new(
            "comparison",
            resource,
            ApiVisibilityContextProbe::new("control", control).unwrap(),
            ApiVisibilityContextProbe::new("candidate", candidate).unwrap(),
            context_headers,
            profile(),
            ApiVisibilityDimension::Fields,
            OBSERVED_AT_MS,
        )
    };

    let representation = build(
        probe(https.clone(), "Bearer a", "application/json", "same"),
        probe(https.clone(), "Bearer b", "text/plain", "same"),
        vec!["authorization", "accept"],
        EntityId::new("resource:42").unwrap(),
    )
    .unwrap_err();
    assert!(matches!(
        representation,
        ApiVisibilityDifferentialRequestError::UnsupportedContextHeader
    ));

    let supporting_only = build(
        probe(https.clone(), "Bearer same", "application/json", "first"),
        probe(https.clone(), "Bearer same", "application/json", "second"),
        vec!["authorization", "x-csrf-token"],
        EntityId::new("resource:42").unwrap(),
    )
    .unwrap_err();
    assert!(matches!(
        supporting_only,
        ApiVisibilityDifferentialRequestError::IdenticalAuthorizationContext
    ));

    let insecure = url::Url::parse("http://example.test/api/accounts/42").unwrap();
    let insecure_error = build(
        probe(insecure.clone(), "Bearer a", "application/json", "same"),
        probe(insecure, "Bearer b", "application/json", "same"),
        vec!["authorization"],
        EntityId::new("resource:42").unwrap(),
    )
    .unwrap_err();
    assert!(matches!(
        insecure_error,
        ApiVisibilityDifferentialRequestError::InsecureAuthenticatedTransport
    ));

    let long_value = "x".repeat(MAX_DIFFERENTIAL_HEADER_VALUE_BYTES + 1);
    let oversized_header = build(
        probe(https.clone(), &long_value, "application/json", "same"),
        probe(https.clone(), "Bearer b", "application/json", "same"),
        vec!["authorization"],
        EntityId::new("resource:42").unwrap(),
    )
    .unwrap_err();
    assert!(matches!(
        oversized_header,
        ApiVisibilityDifferentialRequestError::HeaderValueTooLong
    ));

    let oversized_scope = build(
        probe(https.clone(), "Bearer a", "application/json", "same"),
        probe(https, "Bearer b", "application/json", "same"),
        vec!["authorization"],
        EntityId::new("r".repeat(257)).unwrap(),
    )
    .unwrap_err();
    assert!(matches!(
        oversized_scope,
        ApiVisibilityDifferentialRequestError::Vocabulary(_)
    ));
}

#[tokio::test]
async fn disabled_or_mismatched_runtime_rejects_before_socket_and_is_not_consumed() {
    let fixture = golden_fixture();
    let server = serve(Vec::new()).await;
    let target = server.target();
    let mut disabled = StandardWebDecisionRuntime::builder(target.clone())
        .build()
        .unwrap();
    assert!(matches!(
        disabled
            .run_api_visibility_pair(pair_request(&target, &fixture))
            .await,
        Err(RuntimeApiVisibilityExecutionError::ApiReasoningDisabled)
    ));
    assert!(!disabled.has_started());
    assert_eq!(disabled.usage().total_requests(), 0);

    let other_target = url::Url::parse("https://example.test/api/accounts/42").unwrap();
    let mut mismatched = StandardWebDecisionRuntime::builder(other_target)
        .enable_api_reasoning()
        .build()
        .unwrap();
    assert!(matches!(
        mismatched
            .run_api_visibility_pair(pair_request(&target, &fixture))
            .await,
        Err(RuntimeApiVisibilityExecutionError::RuntimeTargetMismatch)
    ));
    assert!(!mismatched.has_started());
    assert_eq!(mismatched.usage().total_requests(), 0);
    assert!(server.requests().await.is_empty());
}

#[tokio::test]
async fn completed_pair_consumes_the_runtime_single_use_right() {
    let fixture = golden_fixture();
    let server = serve(vec![
        Reply::Response {
            bytes: json_response(200, &fixture.baseline, &[]),
            cancel_after_write: None,
        },
        Reply::Response {
            bytes: json_response(200, &fixture.candidate, &[]),
            cancel_after_write: None,
        },
    ])
    .await;
    let target = server.target();
    let mut runtime = runtime(
        target.clone(),
        RuntimeBudget::default(),
        Duration::from_secs(1),
    );
    runtime
        .run_api_visibility_pair(pair_request(&target, &fixture))
        .await
        .unwrap();

    assert!(matches!(
        runtime
            .run_api_visibility_pair(pair_request(&target, &fixture))
            .await,
        Err(RuntimeApiVisibilityExecutionError::AlreadyStarted)
    ));
    assert!(matches!(
        runtime.analyze().await,
        Err(StandardWebDecisionRuntimeError::AlreadyStarted)
    ));
}
