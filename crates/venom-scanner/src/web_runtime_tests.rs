use std::{collections::BTreeSet, future::pending, sync::Arc, time::Duration};

use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Mutex,
    task::JoinHandle,
};
use venom_core::{
    ApiKnowledgePredicate, ApiResponseFormat, ApiSurfaceKind, ApiVisibilityBoundaryKind,
    ApiVisibilityComparison, ApiVisibilityDimension, ApiVisibilityObservation,
    ApiVisibilityPairKind, ApiVisibilityResult, ConfidenceScore, EntityId, Evidence, EvidenceKind,
    EvidenceSource, EvidenceValue, Hypothesis, HypothesisState, HypothesisStrength, OutcomeStatus,
    PredicateDescriptor, Probability, WebKnowledgePredicate,
};

use super::*;
use crate::{
    ActionCost, AdaptivePipeline, ApiVisibilityReviewQuery, AttackAction, DecisionActionExecutor,
    DecisionExecutionFailureKind, DecisionExecutionRequest, DecisionExecutorError,
    DecisionExecutorRegistry, DecisionLoopState, DecisionRunnerAdapter, DecisionStopReason,
    ExclusionReason, Expression, HttpBodyCapture, HttpEvidenceExecutor, HypothesisSelector,
    KnowledgeLayer, KnowledgeSnapshot, RequiredStrength, StandardWebActionKind,
    SubjectHttpProbeProvider, TransportDispatchOutcome,
};

const BASIC: &[u8] = b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"admin\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const RATE_LIMITED: &[u8] = b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const LIVEWIRE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 9\r\nConnection: close\r\n\r\nwire:id=x";
const NGINX: &[u8] =
    b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const JSON: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
const GRAPHQL: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/graphql-response+json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";

struct FailingRuntimeExecutor {
    id: &'static str,
    kind: DecisionExecutionFailureKind,
    diagnostic: &'static str,
}

struct BudgetDeniedRuntimeExecutor {
    id: &'static str,
    limit: RuntimeLimitExceeded,
}

struct CancelAfterEvidenceExecutor {
    id: &'static str,
    cancellation: CancellationToken,
}

struct MissingResponseUsageExecutor {
    id: &'static str,
}

struct ResponseOvershootExecutor {
    id: &'static str,
    accounting: RequestAccountingBroker,
    delivered_bytes: u64,
}

#[async_trait]
impl DecisionActionExecutor for BudgetDeniedRuntimeExecutor {
    fn id(&self) -> &str {
        self.id
    }

    async fn execute(
        &self,
        _request: &DecisionExecutionRequest,
    ) -> Result<Vec<Evidence>, DecisionExecutorError> {
        Err(DecisionExecutorError::from_runtime_limit(
            self.limit.clone(),
        ))
    }
}

#[async_trait]
impl DecisionActionExecutor for FailingRuntimeExecutor {
    fn id(&self) -> &str {
        self.id
    }

    async fn execute(
        &self,
        _request: &DecisionExecutionRequest,
    ) -> Result<Vec<Evidence>, DecisionExecutorError> {
        Err(DecisionExecutorError::with_kind(self.kind, self.diagnostic))
    }
}

#[async_trait]
impl DecisionActionExecutor for CancelAfterEvidenceExecutor {
    fn id(&self) -> &str {
        self.id
    }

    async fn execute(
        &self,
        request: &DecisionExecutionRequest,
    ) -> Result<Vec<Evidence>, DecisionExecutorError> {
        let source = EvidenceSource::new(self.id, "cancel-after-evidence")
            .unwrap()
            .with_correlation_id(request.case().id())
            .unwrap();
        let evidence = Evidence::new(
            request.case().subject().clone(),
            EvidenceKind::Http,
            HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED.into_knowledge(),
            EvidenceValue::Unsigned(0),
            source,
            ConfidenceScore::MAX,
        );
        self.cancellation.cancel();
        Ok(vec![evidence])
    }
}

#[async_trait]
impl DecisionActionExecutor for MissingResponseUsageExecutor {
    fn id(&self) -> &str {
        self.id
    }

    async fn execute(
        &self,
        request: &DecisionExecutionRequest,
    ) -> Result<Vec<Evidence>, DecisionExecutorError> {
        let source = EvidenceSource::new(self.id, "missing-response-usage")
            .unwrap()
            .with_correlation_id(request.case().id())
            .unwrap();
        Ok(vec![Evidence::new(
            request.case().subject().clone(),
            EvidenceKind::Http,
            HttpEvidencePredicate::RESPONSE_STATUS.into_knowledge(),
            EvidenceValue::Unsigned(200),
            source,
            ConfidenceScore::MAX,
        )])
    }
}

#[async_trait]
impl DecisionActionExecutor for ResponseOvershootExecutor {
    fn id(&self) -> &str {
        self.id
    }

    async fn execute(
        &self,
        request: &DecisionExecutionRequest,
    ) -> Result<Vec<Evidence>, DecisionExecutorError> {
        let mut lease = self
            .accounting
            .try_begin_with_request_body_bytes(
                request.case().action_id(),
                request.stage(),
                request.origin(),
                0,
            )
            .map_err(DecisionExecutorError::from_runtime_limit)?;
        let retained = lease.observe_response_bytes(self.delivered_bytes);
        let source = EvidenceSource::new(self.id, "response-budget-overshoot")
            .unwrap()
            .with_correlation_id(request.case().id())
            .unwrap();
        Ok(vec![Evidence::new(
            request.case().subject().clone(),
            EvidenceKind::Http,
            HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED.into_knowledge(),
            EvidenceValue::Unsigned(retained),
            source,
            ConfidenceScore::MAX,
        )])
    }
}

enum Reply {
    Response(&'static [u8]),
    PartialThenStall(&'static [u8]),
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
                Reply::PartialThenStall(response_prefix) => {
                    stream.write_all(response_prefix).await.unwrap();
                    stream.flush().await.unwrap();
                    pending::<()>().await;
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

fn assert_host_cancelled(report: &StandardWebDecisionRunReport) {
    assert!(matches!(
        report.terminal(),
        DecisionLoopCommand::Halt {
            reason: DecisionStopReason::CancelledByHost
        }
    ));
    assert!(report.limit_exceeded().is_none());
    assert!(report.execution_failure().is_none());
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

fn api_hypothesis(
    snapshot: &KnowledgeSnapshot,
    predicate: PredicateDescriptor,
    value: EvidenceValue,
) -> Option<&Hypothesis> {
    let predicate = predicate.into_knowledge();
    snapshot
        .hypotheses()
        .iter()
        .find(|hypothesis| hypothesis.predicate() == &predicate && hypothesis.value() == &value)
}

fn runtime_visibility_observation(id: &str, resource: &EntityId) -> ApiVisibilityObservation {
    ApiVisibilityComparison::new(
        id,
        ApiSurfaceKind::JsonHttp,
        ApiVisibilityPairKind::AuthorizationContext,
        ApiVisibilityResult::Different,
        ApiVisibilityDimension::Fields,
        "anonymous-view",
        "member-view",
        resource.as_str(),
    )
    .unwrap()
    .with_observed_at_ms(1_800_000_000_000)
    .to_observation("host.api-comparator", ConfidenceScore::MAX)
    .unwrap()
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
    assert_eq!(runtime.runner.executors().len(), 7);
    assert_eq!(runtime.unsupported_actions().len(), 3);
    assert_eq!(runtime.budget(), RuntimeBudget::default());
    assert_eq!(runtime.usage(), &RuntimeUsage::default());
    assert!(runtime.api_reasoning_installation().is_none());
    assert_eq!(
        runtime.decision_loop.rules().len(),
        crate::STANDARD_WEB_RULE_COUNT
    );
    // nginx configuration is now an executor-backed route and no longer appears
    // in the unsupported inventory; apache/php/laravel-input remain unsupported.
    assert!(!runtime
        .unsupported_actions()
        .contains(StandardWebActionKind::NginxConfiguration.action_id()));
    assert!(runtime
        .unsupported_actions()
        .contains(StandardWebActionKind::ApacheConfiguration.action_id()));
    assert!(runtime
        .unsupported_actions()
        .contains(StandardWebActionKind::PhpInputDiscovery.action_id()));
    assert!(runtime
        .unsupported_actions()
        .contains(StandardWebActionKind::LaravelInputAnalysis.action_id()));
    assert!(!runtime
        .unsupported_actions()
        .contains(StandardWebActionKind::HttpBasicAuthBoundary.action_id()));
}

#[tokio::test]
async fn pre_cancelled_runtime_stops_before_bootstrap_io() {
    let server = serve(vec![Reply::Response(OK)]).await;
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let mut runtime = StandardWebDecisionRuntime::builder(server.target())
        .cancellation_token(cancellation)
        .build()
        .unwrap();

    let report = runtime.analyze().await.unwrap();

    assert_host_cancelled(&report);
    assert!(report.bootstrap().is_none());
    assert!(report.unverified_evidence().is_none());
    assert_eq!(report.usage().total_requests(), 0);
    assert_eq!(runtime.knowledge().stats().evidence, 0);
    assert!(matches!(
        runtime.session().state(),
        DecisionLoopState::Halted {
            reason: DecisionStopReason::CancelledByHost
        }
    ));
    assert!(server.methods().await.is_empty());
}

#[tokio::test]
async fn host_cancellation_interrupts_in_flight_bootstrap_without_becoming_a_wall_limit() {
    let server = serve(vec![Reply::Stall]).await;
    let cancellation = CancellationToken::new();
    let observed_methods = server.methods.clone();
    let cancel_from_host = cancellation.clone();
    let canceller = tokio::spawn(async move {
        loop {
            if !observed_methods.lock().await.is_empty() {
                cancel_from_host.cancel();
                break;
            }
            tokio::task::yield_now().await;
        }
    });
    let mut runtime = StandardWebDecisionRuntime::builder(server.target())
        .cancellation_token(cancellation)
        .max_wall_time(Duration::from_secs(5))
        .build()
        .unwrap();

    let report = runtime.analyze().await.unwrap();
    canceller.await.unwrap();

    assert_host_cancelled(&report);
    assert!(report.bootstrap().is_none());
    assert!(report.unverified_evidence().is_none());
    assert_eq!(report.usage().total_requests(), 1);
    assert!(report.usage().elapsed() < Duration::from_secs(5));
    assert_eq!(server.methods().await, ["GET"]);
}

#[tokio::test]
async fn host_cancellation_interrupts_an_in_flight_planned_action() {
    let server = serve(vec![Reply::Response(BASIC), Reply::Stall]).await;
    let cancellation = CancellationToken::new();
    let observed_methods = server.methods.clone();
    let cancel_from_host = cancellation.clone();
    let canceller = tokio::spawn(async move {
        loop {
            if observed_methods.lock().await.len() == 2 {
                cancel_from_host.cancel();
                break;
            }
            tokio::task::yield_now().await;
        }
    });
    let mut runtime = StandardWebDecisionRuntime::builder(server.target())
        .cancellation_token(cancellation)
        .max_wall_time(Duration::from_secs(5))
        .build()
        .unwrap();

    let report = runtime.analyze().await.unwrap();
    canceller.await.unwrap();

    assert_host_cancelled(&report);
    assert!(report.bootstrap().is_some());
    assert_eq!(report.planning_reports().count(), 1);
    assert_eq!(report.outcome_reports().count(), 0);
    assert!(report.unverified_evidence().is_none());
    assert_eq!(report.usage().total_requests(), 2);
    assert_eq!(report.usage().total_action_attempts(), 2);
    assert_eq!(server.methods().await, ["GET", "HEAD"]);
}

#[tokio::test]
async fn explicit_cancellation_wins_over_an_already_expired_wall_budget() {
    let server = serve(vec![Reply::Response(OK)]).await;
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let mut runtime = StandardWebDecisionRuntime::builder(server.target())
        .cancellation_token(cancellation)
        .max_wall_time(Duration::ZERO)
        .build()
        .unwrap();

    let report = runtime.analyze().await.unwrap();

    assert_host_cancelled(&report);
    assert!(report.limit_exceeded().is_none());
    assert_eq!(report.usage().total_requests(), 0);
    assert!(server.methods().await.is_empty());
}

#[tokio::test]
async fn cancellation_after_evidence_commit_keeps_an_unverified_receipt() {
    let server = serve(vec![Reply::Response(BASIC)]).await;
    let policy = HttpEvidencePolicy::for_origin(server.target()).unwrap();
    let cancellation = CancellationToken::new();
    let mut runtime = StandardWebDecisionRuntime::builder(server.target())
        .http_policy(policy.clone())
        .cancellation_token(cancellation.clone())
        .build()
        .unwrap();
    let action = StandardWebActionKind::HttpBasicAuthBoundary;
    let mut registry = DecisionExecutorRegistry::new();
    registry
        .register(Arc::new(
            HttpEvidenceExecutor::new_with_accounting(
                policy,
                Arc::new(SubjectHttpProbeProvider::new(HttpProbeMethod::Get)),
                runtime.request_accounting.clone(),
            )
            .unwrap(),
        ))
        .unwrap();
    registry
        .register(Arc::new(CancelAfterEvidenceExecutor {
            id: action.executor_id(),
            cancellation,
        }))
        .unwrap();
    runtime.runner = DecisionRunnerAdapter::new(registry);

    let report = runtime.analyze().await.unwrap();

    assert_host_cancelled(&report);
    assert!(report.bootstrap().is_some());
    assert_eq!(report.planning_reports().count(), 1);
    assert_eq!(report.outcome_reports().count(), 0);
    let receipt = report.unverified_evidence().unwrap();
    assert_eq!(receipt.case().action_id(), action.action_id());
    assert_eq!(receipt.stage(), DecisionExecutionStage::Passive);
    assert_eq!(receipt.evidence().len(), 1);
    assert_eq!(receipt.writes(), [KnowledgeWrite::Inserted]);
    assert!(runtime
        .knowledge()
        .evidence(receipt.evidence()[0].id())
        .is_some());
    assert_eq!(report.usage().total_action_attempts(), 2);
    assert_eq!(report.usage().total_requests(), 1);
    assert!(matches!(
        runtime.session().state(),
        DecisionLoopState::Halted {
            reason: DecisionStopReason::CancelledByHost
        }
    ));
    assert_eq!(server.methods().await, ["GET"]);
}

#[tokio::test]
async fn runtime_forwards_bootstrap_failure_without_learning_from_it() {
    let target = Url::parse("https://example.test/app").unwrap();
    let mut runtime = StandardWebDecisionRuntime::builder(target).build().unwrap();
    let mut registry = DecisionExecutorRegistry::new();
    registry
        .register(Arc::new(FailingRuntimeExecutor {
            id: HTTP_EVIDENCE_EXECUTOR_ID,
            kind: DecisionExecutionFailureKind::TransportFailure,
            diagnostic: "transport unavailable before headers",
        }))
        .unwrap();
    runtime.runner = DecisionRunnerAdapter::new(registry);

    let error = runtime.analyze().await.unwrap_err();
    let audit = error.failure_receipt().unwrap();
    let receipt = error.execution_failure().unwrap();

    assert!(audit.bootstrap().is_none());
    assert!(audit.completed_turns().is_empty());
    assert_eq!(audit.usage().total_requests(), 0);
    assert_eq!(audit.usage().total_action_attempts(), 1);
    assert_eq!(receipt.case().id(), BOOTSTRAP_CASE_ID);
    assert_eq!(receipt.action_id(), BOOTSTRAP_ACTION_ID);
    assert_eq!(receipt.stage(), DecisionExecutionStage::Passive);
    assert_eq!(receipt.origin(), Some(DecisionActionOrigin::Bootstrap));
    assert_eq!(receipt.executor_id(), HTTP_EVIDENCE_EXECUTOR_ID);
    assert_eq!(
        receipt.kind(),
        DecisionExecutionFailureKind::TransportFailure
    );
    assert_eq!(runtime.usage().total_requests(), 0);
    assert_eq!(runtime.usage().bootstrap_requests(), 0);
    assert_eq!(runtime.usage().total_action_attempts(), 1);
    assert_eq!(runtime.usage().same_action_attempts(BOOTSTRAP_ACTION_ID), 1);
    assert_eq!(runtime.usage().completed_execution_turns(), 0);
    assert_eq!(runtime.knowledge().stats().evidence, 0);
    assert!(runtime.experience().is_empty());
    assert!(matches!(
        runtime.session().state(),
        DecisionLoopState::Ready
    ));
    assert!(runtime.has_started());

    let owned = error.into_execution_failure().unwrap();
    assert_eq!(owned.case().id(), BOOTSTRAP_CASE_ID);
}

#[tokio::test]
async fn planned_failure_preserves_bootstrap_and_outstanding_session_without_suppression() {
    let server = serve(vec![Reply::Response(BASIC)]).await;
    let policy = HttpEvidencePolicy::for_origin(server.target()).unwrap();
    let mut runtime = StandardWebDecisionRuntime::builder(server.target())
        .http_policy(policy.clone())
        .build()
        .unwrap();
    let action = StandardWebActionKind::HttpBasicAuthBoundary;
    let mut registry = DecisionExecutorRegistry::new();
    registry
        .register(Arc::new(
            HttpEvidenceExecutor::new_with_accounting(
                policy,
                Arc::new(SubjectHttpProbeProvider::new(HttpProbeMethod::Get)),
                runtime.request_accounting.clone(),
            )
            .unwrap(),
        ))
        .unwrap();
    registry
        .register(Arc::new(FailingRuntimeExecutor {
            id: action.executor_id(),
            kind: DecisionExecutionFailureKind::BlockedByPolicy,
            diagnostic: "host policy denied the planned probe",
        }))
        .unwrap();
    runtime.runner = DecisionRunnerAdapter::new(registry);

    let error = runtime.analyze().await.unwrap_err();
    let audit = error.failure_receipt().unwrap();
    let receipt = error.execution_failure().unwrap();

    assert_eq!(audit.bootstrap().unwrap().case().id(), BOOTSTRAP_CASE_ID);
    assert_eq!(audit.completed_turns().len(), 1);
    assert!(matches!(
        audit.completed_turns()[0],
        StandardWebDecisionRuntimeTurn::Planning(_)
    ));
    assert_eq!(audit.usage().total_requests(), 1);
    assert_eq!(audit.usage().total_action_attempts(), 2);
    let dispatches = audit.transport().receipts();
    assert_eq!(dispatches.len(), 1);
    assert_eq!(dispatches[0].action_id(), BOOTSTRAP_ACTION_ID);
    assert_eq!(dispatches[0].outcome(), TransportDispatchOutcome::Completed);
    assert_eq!(receipt.action_id(), action.action_id());
    assert_eq!(receipt.stage(), DecisionExecutionStage::Passive);
    assert_eq!(receipt.origin(), Some(DecisionActionOrigin::Planned));
    assert_eq!(receipt.executor_id(), action.executor_id());
    assert_eq!(
        receipt.kind(),
        DecisionExecutionFailureKind::BlockedByPolicy
    );
    assert_eq!(runtime.usage().total_requests(), 1);
    assert_eq!(runtime.usage().bootstrap_requests(), 1);
    assert_eq!(runtime.usage().planned_requests(), 0);
    assert_eq!(runtime.usage().total_action_attempts(), 2);
    assert_eq!(runtime.usage().completed_execution_turns(), 0);
    assert_eq!(runtime.usage().same_action_attempts(action.action_id()), 1);
    assert!(runtime.knowledge().stats().evidence > 0);
    assert!(runtime.experience().is_empty());
    assert!(matches!(
        runtime.session().state(),
        DecisionLoopState::AwaitingPassive { case } if case.action_id() == action.action_id()
    ));
    assert_eq!(server.methods().await, ["GET"]);

    let owned_audit = error.into_failure_receipt().unwrap();
    assert_eq!(
        owned_audit.bootstrap().unwrap().case().id(),
        BOOTSTRAP_CASE_ID
    );
}

#[tokio::test]
async fn response_usage_failure_preserves_prior_turns_and_current_evidence() {
    let server = serve(vec![Reply::Response(BASIC)]).await;
    let policy = HttpEvidencePolicy::for_origin(server.target()).unwrap();
    let mut runtime = StandardWebDecisionRuntime::builder(server.target())
        .http_policy(policy.clone())
        .build()
        .unwrap();
    let action = StandardWebActionKind::HttpBasicAuthBoundary;
    let mut registry = DecisionExecutorRegistry::new();
    registry
        .register(Arc::new(
            HttpEvidenceExecutor::new_with_accounting(
                policy,
                Arc::new(SubjectHttpProbeProvider::new(HttpProbeMethod::Get)),
                runtime.request_accounting.clone(),
            )
            .unwrap(),
        ))
        .unwrap();
    registry
        .register(Arc::new(MissingResponseUsageExecutor {
            id: action.executor_id(),
        }))
        .unwrap();
    runtime.runner = DecisionRunnerAdapter::new(registry);

    let error = runtime.analyze().await.unwrap_err();

    assert!(matches!(
        &error,
        StandardWebDecisionRuntimeError::RunFailed { source, .. }
            if matches!(
                source.as_ref(),
                StandardWebDecisionRuntimeError::ResponseUsageEvidence { observations: 0, .. }
            )
    ));
    let audit = error.failure_receipt().unwrap();
    assert_eq!(audit.bootstrap().unwrap().case().id(), BOOTSTRAP_CASE_ID);
    assert_eq!(audit.completed_turns().len(), 1);
    assert!(matches!(
        audit.completed_turns()[0],
        StandardWebDecisionRuntimeTurn::Planning(_)
    ));
    assert_eq!(audit.usage().total_requests(), 1);
    assert_eq!(audit.usage().total_action_attempts(), 2);
    assert_eq!(audit.transport().receipts().len(), 1);
    assert_eq!(
        audit.transport().receipts()[0].outcome(),
        TransportDispatchOutcome::Completed
    );

    let committed = error.committed_evidence().unwrap();
    assert_eq!(committed.case().action_id(), action.action_id());
    assert_eq!(committed.writes(), [KnowledgeWrite::Inserted]);
    assert!(runtime
        .knowledge()
        .evidence(committed.evidence()[0].id())
        .is_some());
    assert!(runtime.experience().is_empty());
    assert!(matches!(
        runtime.session().state(),
        DecisionLoopState::AwaitingPassive { case } if case.action_id() == action.action_id()
    ));
    assert_eq!(server.methods().await, ["GET"]);
}

#[tokio::test]
async fn response_overshoot_halts_the_same_turn_and_keeps_evidence_auditable() {
    let server = serve(vec![Reply::Response(BASIC)]).await;
    let policy = HttpEvidencePolicy::for_origin(server.target()).unwrap();
    let mut runtime = StandardWebDecisionRuntime::builder(server.target())
        .http_policy(policy.clone())
        .max_response_bytes(4)
        .build()
        .unwrap();
    let action = StandardWebActionKind::HttpBasicAuthBoundary;
    let mut registry = DecisionExecutorRegistry::new();
    registry
        .register(Arc::new(
            HttpEvidenceExecutor::new_with_accounting(
                policy,
                Arc::new(SubjectHttpProbeProvider::new(HttpProbeMethod::Get)),
                runtime.request_accounting.clone(),
            )
            .unwrap(),
        ))
        .unwrap();
    registry
        .register(Arc::new(ResponseOvershootExecutor {
            id: action.executor_id(),
            accounting: runtime.request_accounting.clone(),
            delivered_bytes: 10,
        }))
        .unwrap();
    runtime.runner = DecisionRunnerAdapter::new(registry);

    let report = runtime.analyze().await.unwrap();

    let limit = assert_runtime_limit(&report, RuntimeBudgetDimension::ResponseBytes);
    assert_eq!(limit.limit(), 4);
    assert_eq!(limit.observed(), 10);
    assert_eq!(limit.action_id(), Some(action.action_id()));
    assert_eq!(report.usage().response_bytes(), 10);
    assert_eq!(report.usage().total_requests(), 2);
    assert_eq!(report.outcome_reports().count(), 0);
    let dispatches = report.transport().receipts();
    assert_eq!(dispatches.len(), 2);
    assert_eq!(dispatches[0].action_id(), BOOTSTRAP_ACTION_ID);
    assert_eq!(dispatches[0].outcome(), TransportDispatchOutcome::Completed);
    assert_eq!(dispatches[1].action_id(), action.action_id());
    assert_eq!(dispatches[1].response_bytes(), 10);
    assert_eq!(dispatches[1].outcome(), TransportDispatchOutcome::Cancelled);
    let committed = report.unverified_evidence().unwrap();
    assert_eq!(committed.case().action_id(), action.action_id());
    assert_eq!(committed.writes(), [KnowledgeWrite::Inserted]);
    assert!(runtime
        .knowledge()
        .evidence(committed.evidence()[0].id())
        .is_some());
    assert!(runtime.experience().is_empty());
    assert!(matches!(
        runtime.session().state(),
        DecisionLoopState::Halted {
            reason: DecisionStopReason::RuntimeBudgetLimit
        }
    ));
    assert_eq!(server.methods().await, ["GET"]);
}

#[tokio::test]
async fn in_executor_budget_denial_preserves_prior_evidence_and_failure_receipt() {
    let server = serve(vec![Reply::Response(BASIC)]).await;
    let policy = HttpEvidencePolicy::for_origin(server.target()).unwrap();
    let mut runtime = StandardWebDecisionRuntime::builder(server.target())
        .http_policy(policy.clone())
        .build()
        .unwrap();
    let action = StandardWebActionKind::HttpBasicAuthBoundary;
    let mut registry = DecisionExecutorRegistry::new();
    registry
        .register(Arc::new(
            HttpEvidenceExecutor::new_with_accounting(
                policy,
                Arc::new(SubjectHttpProbeProvider::new(HttpProbeMethod::Get)),
                runtime.request_accounting.clone(),
            )
            .unwrap(),
        ))
        .unwrap();
    registry
        .register(Arc::new(BudgetDeniedRuntimeExecutor {
            id: action.executor_id(),
            limit: RuntimeLimitExceeded::new(
                RuntimeBudgetDimension::TotalRequests,
                1,
                2,
                Some(action.action_id().to_owned()),
            ),
        }))
        .unwrap();
    runtime.runner = DecisionRunnerAdapter::new(registry);

    let report = runtime.analyze().await.unwrap();

    let limit = assert_runtime_limit(&report, RuntimeBudgetDimension::TotalRequests);
    assert_eq!(limit.limit(), 1);
    assert_eq!(limit.observed(), 2);
    assert!(report.bootstrap().is_some());
    let failure = report.execution_failure().unwrap();
    assert_eq!(failure.action_id(), action.action_id());
    assert_eq!(failure.origin(), Some(DecisionActionOrigin::Planned));
    assert_eq!(failure.runtime_limit(), Some(limit));
    assert_eq!(report.usage().total_requests(), 1);
    assert_eq!(report.usage().planned_requests(), 0);
    assert_eq!(report.usage().total_action_attempts(), 2);
    assert_eq!(report.transport().receipts().len(), 1);
    assert_eq!(
        report.transport().receipts()[0].outcome(),
        TransportDispatchOutcome::Completed
    );
    assert!(runtime.knowledge().stats().evidence > 0);
    assert!(runtime.experience().is_empty());
    assert_eq!(server.methods().await, ["GET"]);
}

#[tokio::test]
async fn passive_api_reasoning_is_opt_in_and_adds_no_request() {
    let disabled_server = serve(vec![Reply::Response(GRAPHQL)]).await;
    let mut disabled = StandardWebDecisionRuntime::builder(disabled_server.target())
        .build()
        .unwrap();
    disabled.analyze().await.unwrap();

    let disabled_snapshot = disabled
        .knowledge()
        .snapshot_for_subject(disabled.subject());
    assert!(disabled.api_reasoning_installation().is_none());
    assert!(api_hypothesis(
        &disabled_snapshot,
        ApiKnowledgePredicate::SURFACE_KIND,
        ApiSurfaceKind::GraphQl.into(),
    )
    .is_none());
    assert_eq!(disabled.usage().total_requests(), 1);

    let enabled_server = serve(vec![Reply::Response(GRAPHQL)]).await;
    let mut enabled = StandardWebDecisionRuntime::builder(enabled_server.target())
        .enable_api_reasoning()
        .build()
        .unwrap();
    let installation = enabled.api_reasoning_installation().unwrap();
    assert_eq!(
        installation.concepts_inserted(),
        crate::STANDARD_API_CONCEPT_COUNT
    );
    assert_eq!(
        installation.axioms_inserted(),
        crate::STANDARD_API_AXIOM_COUNT
    );
    assert_eq!(
        installation.rules_inserted(),
        crate::STANDARD_API_RULE_COUNT
    );
    assert_eq!(
        enabled.decision_loop.rules().len(),
        crate::STANDARD_WEB_RULE_COUNT + crate::STANDARD_API_RULE_COUNT
    );

    enabled.analyze().await.unwrap();

    let enabled_snapshot = enabled.knowledge().snapshot_for_subject(enabled.subject());
    let graphql = api_hypothesis(
        &enabled_snapshot,
        ApiKnowledgePredicate::SURFACE_KIND,
        ApiSurfaceKind::GraphQl.into(),
    )
    .unwrap();
    assert_eq!(graphql.strength(), HypothesisStrength::Strong);
    assert!(api_hypothesis(
        &enabled_snapshot,
        ApiKnowledgePredicate::VISIBILITY_BOUNDARY,
        ApiVisibilityBoundaryKind::UiApi.into(),
    )
    .is_none());
    assert!(api_hypothesis(
        &enabled_snapshot,
        ApiKnowledgePredicate::VISIBILITY_BOUNDARY,
        ApiVisibilityBoundaryKind::AuthorizationContext.into(),
    )
    .is_none());
    assert_eq!(enabled.usage().total_requests(), 1);
    assert_eq!(enabled.usage().active_verifications(), 0);
    assert_eq!(enabled.usage().response_bytes(), 2);
}

#[tokio::test]
async fn paired_visibility_ingress_is_runtime_neutral_before_and_after_analysis() {
    let server = serve(vec![Reply::Response(OK)]).await;
    let mut runtime = StandardWebDecisionRuntime::builder(server.target())
        .enable_api_reasoning()
        .build()
        .unwrap();
    let first_resource = EntityId::new("resource:account-42").unwrap();
    let initial_session = runtime.session().clone();

    runtime
        .ingest_api_visibility(
            runtime_visibility_observation("comparison-before-run", &first_resource),
            &first_resource,
        )
        .unwrap();
    assert_eq!(runtime.session(), &initial_session);
    assert_eq!(runtime.usage(), &RuntimeUsage::default());
    assert!(runtime.experience().is_empty());

    let report = runtime.analyze().await.unwrap();
    assert!(matches!(
        report.terminal(),
        DecisionLoopCommand::Halt {
            reason: DecisionStopReason::NoEligibleAction
        }
    ));
    assert_eq!(server.methods().await, ["GET"]);
    assert_eq!(runtime.usage().total_requests(), 1);

    let usage_after_run = runtime.usage().clone();
    let session_after_run = runtime.session().clone();
    let experience_after_run = runtime.experience().len();
    let second_resource = EntityId::new("resource:account-7").unwrap();
    runtime
        .ingest_api_visibility(
            runtime_visibility_observation("comparison-after-run", &second_resource),
            &second_resource,
        )
        .unwrap();

    assert_eq!(runtime.usage(), &usage_after_run);
    assert_eq!(runtime.session(), &session_after_run);
    assert_eq!(runtime.experience().len(), experience_after_run);
    assert_eq!(server.methods().await, ["GET"]);
    assert_eq!(
        runtime
            .api_visibility_reviews(&second_resource, &ApiVisibilityReviewQuery::default(),)
            .unwrap()
            .reviews()
            .len(),
        1
    );
}

#[tokio::test]
async fn api_reasoning_preserves_an_existing_web_action_sequence() {
    let server = serve(vec![
        Reply::Response(BASIC),
        Reply::Response(BASIC),
        Reply::Response(BASIC),
        Reply::Response(BASIC),
    ])
    .await;
    let target = server.target();
    let mut disabled = StandardWebDecisionRuntime::builder(target.clone())
        .build()
        .unwrap();
    let disabled_report = disabled.analyze().await.unwrap();
    let disabled_usage = disabled.usage().clone();

    let mut enabled = StandardWebDecisionRuntime::builder(target)
        .enable_api_reasoning()
        .build()
        .unwrap();
    let enabled_report = enabled.analyze().await.unwrap();
    let enabled_usage = enabled.usage();

    assert_eq!(disabled_report.terminal(), enabled_report.terminal());
    assert_eq!(
        disabled_usage.total_requests(),
        enabled_usage.total_requests()
    );
    assert_eq!(
        disabled_usage.passive_requests(),
        enabled_usage.passive_requests()
    );
    assert_eq!(
        disabled_usage.active_verifications(),
        enabled_usage.active_verifications()
    );
    assert_eq!(
        disabled_usage.bootstrap_requests(),
        enabled_usage.bootstrap_requests()
    );
    assert_eq!(
        disabled_usage.planned_requests(),
        enabled_usage.planned_requests()
    );
    assert_eq!(
        disabled_usage.response_bytes(),
        enabled_usage.response_bytes()
    );
    assert_eq!(disabled_usage.total_requests(), 2);
    assert_eq!(server.methods().await, ["GET", "HEAD", "GET", "HEAD"]);
}

#[tokio::test]
async fn generic_json_runtime_evidence_never_implies_graphql() {
    let server = serve(vec![Reply::Response(JSON)]).await;
    let mut runtime = StandardWebDecisionRuntime::builder(server.target())
        .enable_api_reasoning()
        .build()
        .unwrap();

    runtime.analyze().await.unwrap();

    let snapshot = runtime.knowledge().snapshot_for_subject(runtime.subject());
    assert!(api_hypothesis(
        &snapshot,
        ApiKnowledgePredicate::RESPONSE_FORMAT,
        ApiResponseFormat::Json.into(),
    )
    .is_some());
    assert!(api_hypothesis(
        &snapshot,
        ApiKnowledgePredicate::SURFACE_KIND,
        ApiSurfaceKind::GraphQl.into(),
    )
    .is_none());
    assert_eq!(runtime.usage().total_requests(), 1);
    assert_eq!(runtime.usage().active_verifications(), 0);
}

#[tokio::test]
async fn graphql_path_signal_remains_a_weak_runtime_hypothesis() {
    let server = serve(vec![Reply::Response(OK)]).await;
    let mut target = server.target();
    target.set_path("/graphql");
    let mut runtime = StandardWebDecisionRuntime::builder(target)
        .enable_api_reasoning()
        .build()
        .unwrap();

    runtime.analyze().await.unwrap();

    let snapshot = runtime.knowledge().snapshot_for_subject(runtime.subject());
    let graphql = api_hypothesis(
        &snapshot,
        ApiKnowledgePredicate::SURFACE_KIND,
        ApiSurfaceKind::GraphQl.into(),
    )
    .unwrap();
    assert_eq!(graphql.strength(), HypothesisStrength::Weak);
    assert_eq!(runtime.usage().total_requests(), 1);
    assert_eq!(runtime.usage().response_bytes(), 0);
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
    let audit = error.failure_receipt().unwrap();
    assert_eq!(audit.bootstrap().unwrap().case().id(), BOOTSTRAP_CASE_ID);
    assert!(audit.completed_turns().is_empty());
    assert_eq!(audit.usage().total_requests(), 1);
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
    // apache remains an executor-less route: it activates a hypothesis but its
    // planner action is excluded as a policy suppression, dispatching nothing
    // beyond the bootstrap probe. (nginx is now executor-backed; see the
    // decision-scan activation corpus for its end-to-end paths.)
    let apache = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.58 (Unix)\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    let server = serve(vec![Reply::Response(apache)]).await;
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
    let apache = planning
        .plan()
        .excluded()
        .iter()
        .find(|excluded| {
            excluded.action_id() == StandardWebActionKind::ApacheConfiguration.action_id()
        })
        .unwrap();
    assert!(matches!(apache.reason(), ExclusionReason::PolicySuppressed));
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
    assert!(report.bootstrap().is_some());
    assert!(report.execution_failure().is_none());
    assert_eq!(server.methods().await, ["GET"]);
    assert!(matches!(
        runtime.session().state(),
        DecisionLoopState::Halted {
            reason: DecisionStopReason::RuntimeBudgetLimit
        }
    ));
}

#[tokio::test]
async fn partial_body_timeout_remains_charged_without_committing_evidence() {
    let server = serve(vec![Reply::PartialThenStall(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 10\r\nConnection: close\r\n\r\n0123",
    )])
    .await;
    let policy = HttpEvidencePolicy::new(
        [server.target()],
        Duration::from_millis(100),
        crate::DEFAULT_HTTP_BODY_LIMIT,
    )
    .unwrap();
    let mut runtime = StandardWebDecisionRuntime::builder(server.target())
        .http_policy(policy)
        .max_wall_time(Duration::from_secs(2))
        .build()
        .unwrap();

    let error = runtime.analyze().await.unwrap_err();

    let failure = error.execution_failure().unwrap();
    assert_eq!(failure.kind(), DecisionExecutionFailureKind::RequestTimeout);
    assert_eq!(failure.action_id(), BOOTSTRAP_ACTION_ID);
    assert!(failure.diagnostic().contains("timed out"));
    assert_eq!(runtime.usage().total_requests(), 1);
    assert_eq!(runtime.usage().response_bytes(), 4);
    assert_eq!(runtime.usage().total_action_attempts(), 1);
    assert_eq!(runtime.knowledge().stats().evidence, 0);
    assert!(runtime.experience().is_empty());
    assert!(matches!(
        runtime.session().state(),
        DecisionLoopState::Ready
    ));
    assert_eq!(server.methods().await, ["GET"]);
}

#[tokio::test]
async fn response_budget_clamps_retention_and_records_the_full_received_chunk() {
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
    let observed = report.usage().response_bytes();
    assert!(
        (5..=10).contains(&observed),
        "broker must charge the complete chunk that crosses the four-byte retention limit; observed {observed}"
    );
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
    let later_receipt = report.unverified_evidence().unwrap();
    assert_eq!(
        evidence_value(later_receipt, "http.response.body-bytes-observed"),
        Some(&EvidenceValue::Unsigned(3))
    );
    assert_eq!(
        evidence_value(later_receipt, "http.response.body-truncated"),
        Some(&EvidenceValue::Boolean(true))
    );
    let observed = report.usage().response_bytes();
    assert!(
        (13..=18).contains(&observed),
        "broker must charge the complete chunk that crosses the cumulative twelve-byte retention limit; observed {observed}"
    );
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
async fn semantic_retry_is_denied_before_socket_when_total_budget_is_exhausted() {
    let server = serve(vec![Reply::Response(BASIC), Reply::Response(RATE_LIMITED)]).await;
    let mut runtime = StandardWebDecisionRuntime::builder(server.target())
        .max_total_requests(2)
        .max_same_action_attempts(8)
        .max_consecutive_no_progress_turns(8)
        .build()
        .unwrap();
    *runtime.decision_loop.adaptive_mut() = AdaptivePipeline::with_standard_policies().unwrap();

    let report = runtime.analyze().await.unwrap();

    let limit = assert_runtime_limit(&report, RuntimeBudgetDimension::TotalRequests);
    assert_eq!(limit.limit(), 2);
    assert_eq!(limit.observed(), 3);
    assert_eq!(report.usage().total_requests(), 2);
    assert_eq!(report.usage().retry_requests(), 0);
    assert_eq!(report.usage().total_action_attempts(), 2);
    assert_eq!(report.transport().receipts().len(), 2);
    assert!(report
        .transport()
        .receipts()
        .iter()
        .all(|receipt| receipt.outcome() == TransportDispatchOutcome::Completed));
    assert_eq!(server.methods().await, ["GET", "HEAD"]);
}

#[tokio::test]
async fn dispatched_retry_is_charged_at_the_transport_boundary() {
    let server = serve(vec![
        Reply::Response(BASIC),
        Reply::Response(RATE_LIMITED),
        Reply::Response(OK),
    ])
    .await;
    let mut runtime = StandardWebDecisionRuntime::builder(server.target())
        .max_total_requests(3)
        .max_wall_time(Duration::from_secs(3))
        .max_same_action_attempts(8)
        .max_consecutive_no_progress_turns(8)
        .build()
        .unwrap();
    *runtime.decision_loop.adaptive_mut() = AdaptivePipeline::with_standard_policies().unwrap();

    let report = runtime.analyze().await.unwrap();

    assert_eq!(report.usage().total_requests(), 3);
    assert_eq!(report.usage().retry_requests(), 1);
    assert_eq!(report.usage().total_action_attempts(), 3);
    let dispatches = report.transport().receipts();
    assert_eq!(dispatches.len(), 3);
    assert_eq!(
        dispatches[0].origin(),
        Some(DecisionActionOrigin::Bootstrap)
    );
    assert_eq!(dispatches[1].origin(), Some(DecisionActionOrigin::Planned));
    assert_eq!(dispatches[2].origin(), Some(DecisionActionOrigin::Retry));
    assert!(dispatches
        .iter()
        .all(|receipt| receipt.outcome() == TransportDispatchOutcome::Completed));
    assert_eq!(server.methods().await, ["GET", "HEAD", "HEAD"]);
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
    assert_eq!(report.usage().total_requests(), 2);
    assert_eq!(report.usage().retry_requests(), 0);
    assert_eq!(report.usage().total_action_attempts(), 3);
    assert_eq!(server.methods().await, ["GET", "HEAD"]);
}

#[test]
fn execution_metadata_fails_closed_for_non_execution_commands() {
    let case = VerificationCase::new(
        "case:test:metadata",
        EntityId::new("endpoint:https://example.test/").unwrap(),
        "web.action.test",
        "hypothesis:test:metadata",
    )
    .unwrap();
    let execute = DecisionLoopCommand::ExecuteAction {
        case: case.clone(),
        executor: Some("test.executor".to_owned()),
        origin: DecisionActionOrigin::Planned,
        delay_ms: None,
    };
    let active = DecisionLoopCommand::CollectActiveEvidence { case: case.clone() };

    assert_eq!(
        execution_metadata(&execute).unwrap(),
        (case.action_id(), DecisionExecutionStage::Passive)
    );
    assert_eq!(
        execution_metadata(&active).unwrap(),
        (case.action_id(), DecisionExecutionStage::Active)
    );

    for command in [
        DecisionLoopCommand::Replan,
        DecisionLoopCommand::Complete { case: case.clone() },
        DecisionLoopCommand::AwaitHumanReview { case: case.clone() },
        DecisionLoopCommand::Halt {
            reason: DecisionStopReason::NoEligibleAction,
        },
    ] {
        assert!(matches!(
            execution_metadata(&command),
            Err(StandardWebDecisionRuntimeError::ExecutionMetadataUnavailable)
        ));
    }
}
