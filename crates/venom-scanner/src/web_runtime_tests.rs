use std::{collections::BTreeSet, future::pending, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Mutex,
    task::JoinHandle,
};
use venom_core::{
    EvidenceValue, HypothesisState, OutcomeStatus, Probability, WebKnowledgePredicate,
};

use super::*;
use crate::{
    ActionCost, AdaptivePipeline, AttackAction, DecisionLoopState, DecisionStopReason,
    ExclusionReason, Expression, HttpBodyCapture, HypothesisSelector, KnowledgeLayer,
    RequiredStrength, StandardWebActionKind,
};

const BASIC: &[u8] = b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"admin\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const RATE_LIMITED: &[u8] = b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const LIVEWIRE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 9\r\nConnection: close\r\n\r\nwire:id=x";
const NGINX: &[u8] =
    b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

enum Reply {
    Response(&'static [u8]),
    Stall,
}

struct TestServer {
    target: Url,
    methods: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}

impl TestServer {
    fn target(&self) -> Url {
        self.target.clone()
    }

    async fn methods(&self) -> Vec<String> {
        self.methods.lock().await.clone()
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
    let methods = Arc::new(Mutex::new(Vec::new()));
    let recorded = methods.clone();
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
            let method = String::from_utf8_lossy(&request)
                .split_whitespace()
                .next()
                .unwrap()
                .to_owned();
            recorded.lock().await.push(method);
            match reply {
                Reply::Response(response) => {
                    stream.write_all(response).await.unwrap();
                    stream.shutdown().await.unwrap();
                },
                Reply::Stall => pending::<()>().await,
            }
        }
    });
    TestServer {
        target: Url::parse(&format!("http://{address}/admin")).unwrap(),
        methods,
        task,
    }
}

fn assert_runtime_limit(
    report: &StandardWebDecisionRunReport,
    dimension: RuntimeBudgetDimension,
) -> &RuntimeLimitExceeded {
    assert!(
        matches!(
            report.terminal(),
            DecisionLoopCommand::Halt {
                reason: DecisionStopReason::RuntimeBudgetLimit
            }
        ),
        "unexpected terminal command: {:?}",
        report.terminal()
    );
    let limit = report.limit_exceeded().unwrap();
    assert_eq!(limit.dimension(), dimension);
    limit
}

fn evidence_value<'a>(
    receipt: &'a DecisionEvidenceReceipt,
    predicate: &str,
) -> Option<&'a EvidenceValue> {
    receipt
        .evidence()
        .iter()
        .find(|evidence| {
            evidence.source().correlation_id() == Some(receipt.case().id())
                && evidence.predicate().dotted() == predicate
        })
        .map(|evidence| evidence.value())
}

#[test]
fn builder_validates_decision_limits_and_exposes_runtime_defaults() {
    let target = Url::parse("https://example.test/app").unwrap();
    assert!(matches!(
        StandardWebDecisionRuntime::builder(target.clone())
            .risk_limit(0)
            .build(),
        Err(StandardWebDecisionRuntimeError::Planner(_))
    ));
    assert!(matches!(
        StandardWebDecisionRuntime::builder(target.clone())
            .max_action_cycles(0)
            .build(),
        Err(StandardWebDecisionRuntimeError::Decision(_))
    ));

    let runtime = StandardWebDecisionRuntime::builder(target).build().unwrap();
    assert_eq!(runtime.decision_loop.planner().len(), 9);
    assert_eq!(runtime.runner.executors().len(), 6);
    assert_eq!(runtime.unsupported_actions().len(), 4);
    assert_eq!(runtime.budget(), RuntimeBudget::default());
    assert_eq!(runtime.usage(), &RuntimeUsage::default());
    assert!(runtime
        .unsupported_actions()
        .contains(StandardWebActionKind::NginxConfiguration.action_id()));
    assert!(!runtime
        .unsupported_actions()
        .contains(StandardWebActionKind::HttpBasicAuthBoundary.action_id()));
}

#[test]
fn builder_rejects_a_target_outside_custom_policy() {
    let target = Url::parse("https://example.test/app").unwrap();
    let policy =
        HttpEvidencePolicy::for_origin(Url::parse("https://different.test/").unwrap()).unwrap();

    assert!(matches!(
        StandardWebDecisionRuntime::builder(target)
            .http_policy(policy)
            .build(),
        Err(StandardWebDecisionRuntimeError::Http(
            HttpEvidenceError::TargetOutsidePolicy { .. }
        ))
    ));
}

#[tokio::test]
async fn runtime_drives_basic_evidence_to_a_confirmed_outcome_at_exact_request_limit() {
    let server = serve(vec![Reply::Response(BASIC), Reply::Response(BASIC)]).await;
    let mut runtime = StandardWebDecisionRuntime::builder(server.target())
        .max_total_requests(2)
        .build()
        .unwrap();

    let report = runtime.analyze().await.unwrap();

    assert!(report.bootstrap().is_some());
    assert!(report.limit_exceeded().is_none());
    assert!(matches!(
        report.terminal(),
        DecisionLoopCommand::Complete { .. }
    ));
    let outcomes: Vec<_> = report.outcome_reports().collect();
    assert_eq!(outcomes.len(), 1);
    assert_eq!(
        outcomes[0].verification().outcome().status(),
        OutcomeStatus::Success
    );
    let hypothesis_id = outcomes[0].verification().case().hypothesis_id();
    assert_eq!(
        runtime
            .knowledge()
            .hypothesis(hypothesis_id)
            .unwrap()
            .state(),
        HypothesisState::Confirmed
    );
    assert_eq!(report.usage().total_requests(), 2);
    assert_eq!(report.usage().passive_requests(), 2);
    assert_eq!(report.usage().bootstrap_requests(), 1);
    assert_eq!(report.usage().planned_requests(), 1);
    assert_eq!(report.usage().active_verifications(), 0);
    assert_eq!(server.methods().await, ["GET", "HEAD"]);
    assert!(matches!(
        runtime.analyze().await,
        Err(StandardWebDecisionRuntimeError::AlreadyStarted)
    ));
}

#[tokio::test]
async fn runtime_exposes_reasoning_committed_before_a_planning_failure() {
    let server = serve(vec![Reply::Response(NGINX)]).await;
    let mut runtime = StandardWebDecisionRuntime::builder(server.target())
        .build()
        .unwrap();
    runtime
        .decision_loop
        .planner_mut()
        .register(
            AttackAction::new(
                "invalid.runtime.action",
                "plugin.invalid",
                Expression::exists(
                    KnowledgeLayer::Evidence,
                    HttpEvidencePredicate::RESPONSE_STATUS.into_knowledge(),
                ),
                HypothesisSelector::new(
                    WebKnowledgePredicate::TECHNOLOGY_WEB_SERVER.into_knowledge(),
                    EvidenceValue::Text("nginx".to_owned()),
                    Probability::from_percent(50).unwrap(),
                    RequiredStrength::Any,
                ),
                BenefitScore::from_percent(50).unwrap(),
                ActionCost::new(1).unwrap(),
                RiskScore::from_percent(10).unwrap(),
                BTreeSet::from(["missing.runtime.action".to_owned()]),
            )
            .unwrap(),
        )
        .unwrap();
    let initial_session = runtime.session().clone();

    let error = runtime.analyze().await.unwrap_err();

    assert_eq!(runtime.session(), &initial_session);
    assert_eq!(runtime.usage().total_requests(), 1);
    let receipt = error.committed_reasoning().unwrap();
    assert_eq!(receipt.subject(), runtime.subject());
    assert!(receipt
        .rule_applications()
        .iter()
        .any(|application| matches!(
            application.write(),
            Some(KnowledgeWrite::Inserted | KnowledgeWrite::Updated)
        )));
    assert!(runtime.knowledge().stats().hypotheses > 0);
    assert_eq!(
        error.into_committed_reasoning().unwrap().subject(),
        runtime.subject()
    );
}

#[tokio::test]
async fn unavailable_executor_is_reported_as_a_policy_suppression() {
    let nginx =
        b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    let server = serve(vec![Reply::Response(nginx)]).await;
    let mut runtime = StandardWebDecisionRuntime::builder(server.target())
        .build()
        .unwrap();

    let report = runtime.analyze().await.unwrap();

    assert!(matches!(
        report.terminal(),
        DecisionLoopCommand::Halt {
            reason: DecisionStopReason::NoEligibleAction
        }
    ));
    let planning = report.planning_reports().next().unwrap();
    let nginx = planning
        .plan()
        .excluded()
        .iter()
        .find(|excluded| {
            excluded.action_id() == StandardWebActionKind::NginxConfiguration.action_id()
        })
        .unwrap();
    assert!(matches!(nginx.reason(), ExclusionReason::PolicySuppressed));
    assert_eq!(server.methods().await, ["GET"]);
}

#[tokio::test]
async fn total_request_limit_stops_before_the_next_socket_dispatch() {
    let server = serve(vec![Reply::Response(BASIC)]).await;
    let mut runtime = StandardWebDecisionRuntime::builder(server.target())
        .max_total_requests(1)
        .build()
        .unwrap();

    let report = runtime.analyze().await.unwrap();

    let limit = assert_runtime_limit(&report, RuntimeBudgetDimension::TotalRequests);
    assert_eq!(limit.limit(), 1);
    assert_eq!(limit.observed(), 2);
    assert_eq!(report.usage().total_requests(), 1);
    assert_eq!(server.methods().await, ["GET"]);
    assert!(matches!(
        runtime.session().state(),
        DecisionLoopState::Halted {
            reason: DecisionStopReason::RuntimeBudgetLimit
        }
    ));
}

#[tokio::test]
async fn response_budget_clamps_the_bootstrap_body_and_stops_before_more_io() {
    let response = b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"admin\"\r\nContent-Type: text/plain\r\nContent-Length: 10\r\nConnection: close\r\n\r\n0123456789";
    let server = serve(vec![Reply::Response(response)]).await;
    let policy = HttpEvidencePolicy::for_origin(server.target())
        .unwrap()
        .with_body_capture(HttpBodyCapture::TextSample { max_chars: 4 })
        .unwrap();
    let mut runtime = StandardWebDecisionRuntime::builder(server.target())
        .http_policy(policy)
        .max_response_bytes(4)
        .build()
        .unwrap();

    let report = runtime.analyze().await.unwrap();

    assert_runtime_limit(&report, RuntimeBudgetDimension::ResponseBytes);
    let bootstrap = report.bootstrap().unwrap();
    assert_eq!(
        evidence_value(bootstrap, "http.response.body-bytes-observed"),
        Some(&EvidenceValue::Unsigned(4))
    );
    assert_eq!(
        evidence_value(bootstrap, "http.response.body-truncated"),
        Some(&EvidenceValue::Boolean(true))
    );
    assert_eq!(report.usage().response_bytes(), 4);
    assert_eq!(server.methods().await, ["GET"]);
}

#[tokio::test]
async fn response_budget_passes_only_the_cumulative_remainder_to_later_requests() {
    let server = serve(vec![Reply::Response(LIVEWIRE), Reply::Response(LIVEWIRE)]).await;
    let policy = HttpEvidencePolicy::for_origin(server.target())
        .unwrap()
        .with_body_capture(HttpBodyCapture::TextSample { max_chars: 12 })
        .unwrap();
    let mut runtime = StandardWebDecisionRuntime::builder(server.target())
        .http_policy(policy)
        .max_response_bytes(12)
        .build()
        .unwrap();

    let report = runtime.analyze().await.unwrap();

    assert_runtime_limit(&report, RuntimeBudgetDimension::ResponseBytes);
    let later_receipt = report
        .turns()
        .iter()
        .find_map(|turn| match turn {
            StandardWebDecisionRuntimeTurn::Outcome { evidence, .. } => Some(evidence.as_ref()),
            StandardWebDecisionRuntimeTurn::Planning(_) => None,
        })
        .unwrap();
    assert_eq!(
        evidence_value(later_receipt, "http.response.body-bytes-observed"),
        Some(&EvidenceValue::Unsigned(3))
    );
    assert_eq!(
        evidence_value(later_receipt, "http.response.body-truncated"),
        Some(&EvidenceValue::Boolean(true))
    );
    assert_eq!(report.usage().response_bytes(), 12);
    assert_eq!(server.methods().await, ["GET", "GET"]);
}

#[tokio::test]
async fn active_verification_limit_preserves_the_passive_outcome() {
    let server = serve(vec![Reply::Response(BASIC), Reply::Response(OK)]).await;
    let mut runtime = StandardWebDecisionRuntime::builder(server.target())
        .max_active_verifications(0)
        .build()
        .unwrap();

    let report = runtime.analyze().await.unwrap();

    assert_runtime_limit(&report, RuntimeBudgetDimension::ActiveVerifications);
    assert_eq!(report.usage().total_requests(), 2);
    assert_eq!(report.usage().active_verifications(), 0);
    assert_eq!(report.outcome_reports().count(), 1);
    assert_eq!(server.methods().await, ["GET", "HEAD"]);
}

#[tokio::test]
async fn active_verification_accounts_only_its_exact_execution_batch() {
    let server = serve(vec![
        Reply::Response(BASIC),
        Reply::Response(OK),
        Reply::Response(BASIC),
    ])
    .await;
    let action_id = StandardWebActionKind::HttpBasicAuthBoundary.action_id();
    let mut runtime = StandardWebDecisionRuntime::builder(server.target())
        .max_total_requests(3)
        .max_active_verifications(1)
        .max_same_action_attempts(2)
        .build()
        .unwrap();

    let report = runtime.analyze().await.unwrap();

    assert!(matches!(
        report.terminal(),
        DecisionLoopCommand::Complete { .. }
    ));
    assert!(report.limit_exceeded().is_none());
    let statuses: Vec<_> = report
        .outcome_reports()
        .map(|outcome| outcome.verification().outcome().status())
        .collect();
    assert_eq!(statuses, [OutcomeStatus::Unknown, OutcomeStatus::Success]);
    assert_eq!(report.usage().total_requests(), 3);
    assert_eq!(report.usage().active_verifications(), 1);
    assert_eq!(report.usage().same_action_attempts(action_id), 2);
    assert_eq!(server.methods().await, ["GET", "HEAD", "HEAD"]);
}

#[tokio::test]
async fn same_action_limit_counts_passive_and_active_under_one_identity() {
    let server = serve(vec![Reply::Response(BASIC), Reply::Response(OK)]).await;
    let action_id = StandardWebActionKind::HttpBasicAuthBoundary.action_id();
    let mut runtime = StandardWebDecisionRuntime::builder(server.target())
        .max_same_action_attempts(1)
        .build()
        .unwrap();

    let report = runtime.analyze().await.unwrap();

    let limit = assert_runtime_limit(&report, RuntimeBudgetDimension::SameActionAttempts);
    assert_eq!(limit.action_id(), Some(action_id));
    assert_eq!(report.usage().same_action_attempts(action_id), 1);
    assert_eq!(report.usage().active_verifications(), 0);
    assert_eq!(server.methods().await, ["GET", "HEAD"]);
}

#[tokio::test]
async fn no_progress_limit_stops_an_adaptive_retry() {
    let server = serve(vec![Reply::Response(BASIC), Reply::Response(RATE_LIMITED)]).await;
    let mut runtime = StandardWebDecisionRuntime::builder(server.target())
        .max_same_action_attempts(8)
        .max_consecutive_no_progress_turns(1)
        .build()
        .unwrap();
    *runtime.decision_loop.adaptive_mut() = AdaptivePipeline::with_standard_policies().unwrap();

    let report = runtime.analyze().await.unwrap();

    assert_runtime_limit(&report, RuntimeBudgetDimension::ConsecutiveNoProgressTurns);
    assert_eq!(report.usage().consecutive_no_progress_turns(), 1);
    assert_eq!(report.usage().completed_execution_turns(), 1);
    assert_eq!(report.usage().retry_requests(), 0);
    assert_eq!(server.methods().await, ["GET", "HEAD"]);
}

#[tokio::test]
async fn wall_deadline_cancels_a_stalled_bootstrap_without_committing_evidence() {
    let server = serve(vec![Reply::Stall]).await;
    let mut runtime = StandardWebDecisionRuntime::builder(server.target())
        .max_wall_time(Duration::from_millis(500))
        .build()
        .unwrap();

    let report = runtime.analyze().await.unwrap();

    assert_runtime_limit(&report, RuntimeBudgetDimension::WallTime);
    assert!(report.bootstrap().is_none());
    assert_eq!(report.usage().total_requests(), 1);
    assert!(report.usage().elapsed() >= Duration::from_millis(500));
    assert_eq!(server.methods().await, ["GET"]);
}

#[tokio::test]
async fn wall_deadline_cancels_retry_delay_but_keeps_the_reserved_attempt() {
    let server = serve(vec![Reply::Response(BASIC), Reply::Response(RATE_LIMITED)]).await;
    let mut runtime = StandardWebDecisionRuntime::builder(server.target())
        .max_wall_time(Duration::from_millis(750))
        .max_same_action_attempts(8)
        .max_consecutive_no_progress_turns(8)
        .build()
        .unwrap();
    *runtime.decision_loop.adaptive_mut() = AdaptivePipeline::with_standard_policies().unwrap();

    let report = runtime.analyze().await.unwrap();

    assert_runtime_limit(&report, RuntimeBudgetDimension::WallTime);
    assert_eq!(report.usage().total_requests(), 3);
    assert_eq!(report.usage().retry_requests(), 1);
    assert_eq!(server.methods().await, ["GET", "HEAD"]);
}
