use super::*;
use crate::{
    ActionCost, AdaptationLimits, AttackAction, BenefitScore, DecisionLoopConfig, ExperiencePolicy,
    Expression, HypothesisSelector, KnowledgeLayer, PlanningContext, RequiredStrength, RiskScore,
    VerificationRule, VerificationTarget,
};
use termivar_core::{
    ConfidenceScore, EvidenceKind, EvidenceSource, EvidenceValue, Hypothesis, HypothesisState,
    HypothesisStrength, KnowledgePredicate, OutcomeStatus, Probability, VerificationStage,
};

struct RecordingExecutor {
    id: &'static str,
    subject_override: Option<EntityId>,
}

struct FailingExecutor {
    id: &'static str,
    kind: DecisionExecutionFailureKind,
    diagnostic: &'static str,
}

struct StrategyExecutor {
    id: &'static str,
    strategy: PayloadStrategyRef,
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

struct CountingExecutor {
    id: &'static str,
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait]
impl DecisionActionExecutor for RecordingExecutor {
    fn id(&self) -> &str {
        self.id
    }

    async fn execute(
        &self,
        request: &DecisionExecutionRequest,
    ) -> Result<Vec<Evidence>, DecisionExecutorError> {
        let source = EvidenceSource::new(self.id, "response-status")
            .unwrap()
            .with_correlation_id(request.case().id())
            .unwrap();
        Ok(vec![Evidence::new(
            self.subject_override
                .clone()
                .unwrap_or_else(|| request.case().subject().clone()),
            EvidenceKind::Http,
            KnowledgePredicate::new("http.response", "status").unwrap(),
            EvidenceValue::Unsigned(200),
            source,
            ConfidenceScore::MAX,
        )])
    }
}

#[async_trait]
impl DecisionActionExecutor for FailingExecutor {
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
impl DecisionActionExecutor for StrategyExecutor {
    fn id(&self) -> &str {
        self.id
    }

    fn supports_payload_strategy(&self, strategy: &PayloadStrategyRef) -> bool {
        strategy == &self.strategy
    }

    async fn execute(
        &self,
        request: &DecisionExecutionRequest,
    ) -> Result<Vec<Evidence>, DecisionExecutorError> {
        assert_eq!(request.payload_strategy(), Some(&self.strategy));
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let source = EvidenceSource::new(self.id, "strategy-observation")
            .unwrap()
            .with_correlation_id(request.case().id())
            .unwrap();
        Ok(vec![Evidence::new(
            request.case().subject().clone(),
            EvidenceKind::Http,
            KnowledgePredicate::new("http.response", "status").unwrap(),
            EvidenceValue::Unsigned(200),
            source,
            ConfidenceScore::MAX,
        )])
    }
}

#[async_trait]
impl DecisionActionExecutor for CountingExecutor {
    fn id(&self) -> &str {
        self.id
    }

    async fn execute(
        &self,
        request: &DecisionExecutionRequest,
    ) -> Result<Vec<Evidence>, DecisionExecutorError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let source = EvidenceSource::new(self.id, "counted-observation")
            .unwrap()
            .with_correlation_id(request.case().id())
            .unwrap();
        Ok(vec![Evidence::new(
            request.case().subject().clone(),
            EvidenceKind::Http,
            KnowledgePredicate::new("http.response", "status").unwrap(),
            EvidenceValue::Unsigned(200),
            source,
            ConfidenceScore::MAX,
        )])
    }
}

/// A transport-free executor: it declares `LocalKnowledge`, reads one
/// deterministic value from the immutable subject snapshot (the observed
/// evidence count), and derives one new evidence record. Its `execute`
/// (transport) path deliberately fails, proving the runner never routes a
/// local action through transport.
struct LocalKnowledgeExecutor {
    id: &'static str,
}

#[async_trait]
impl DecisionActionExecutor for LocalKnowledgeExecutor {
    fn id(&self) -> &str {
        self.id
    }

    fn execution_class(&self) -> DecisionExecutionClass {
        DecisionExecutionClass::LocalKnowledge
    }

    async fn execute(
        &self,
        _request: &DecisionExecutionRequest,
    ) -> Result<Vec<Evidence>, DecisionExecutorError> {
        Err(DecisionExecutorError::new(
            "local-knowledge executor must run through execute_with_snapshot",
        ))
    }

    async fn execute_with_snapshot(
        &self,
        request: &DecisionExecutionRequest,
        snapshot: &KnowledgeSnapshot,
    ) -> Result<Vec<Evidence>, DecisionExecutorError> {
        let observed = u64::try_from(snapshot.evidence().len()).unwrap_or(u64::MAX);
        let source = EvidenceSource::new(self.id, "local-derivation")
            .unwrap()
            .with_correlation_id(request.case().id())
            .unwrap();
        Ok(vec![Evidence::new(
            request.case().subject().clone(),
            EvidenceKind::Content,
            KnowledgePredicate::new("test.local", "observed-evidence-count").unwrap(),
            EvidenceValue::Unsigned(observed),
            source,
            ConfidenceScore::MAX,
        )])
    }
}

fn subject() -> EntityId {
    EntityId::new("endpoint:https://example.test").unwrap()
}

fn case(action_id: &str) -> VerificationCase {
    VerificationCase::new("case:1", subject(), action_id, "hypothesis:1").unwrap()
}

fn baseline_evidence() -> Evidence {
    Evidence::new(
        subject(),
        EvidenceKind::Http,
        KnowledgePredicate::new("http.response", "status").unwrap(),
        EvidenceValue::Unsigned(200),
        EvidenceSource::new("test.seed", "seed").unwrap(),
        ConfidenceScore::MAX,
    )
}

fn execute_action(action_id: &str, executor_id: &str) -> DecisionLoopCommand {
    DecisionLoopCommand::ExecuteAction {
        case: case(action_id),
        executor: Some(executor_id.to_owned()),
        origin: DecisionActionOrigin::Planned,
        delay_ms: None,
    }
}

fn local_registry() -> DecisionExecutorRegistry {
    let mut registry = DecisionExecutorRegistry::new();
    registry
        .register(Arc::new(LocalKnowledgeExecutor { id: "local.test" }))
        .unwrap();
    registry
        .route_action(
            DecisionExecutionStage::Passive,
            "action.local",
            "local.test",
        )
        .unwrap();
    registry
}

#[tokio::test]
async fn local_knowledge_executor_derives_evidence_from_the_snapshot() {
    // C + H: local-derived evidence passes the same provenance validation and
    // atomic commit; the derived value is a deterministic function of the
    // immutable snapshot (here: two seeded evidence records observed).
    let knowledge = KnowledgeBase::new();
    knowledge.insert_evidence(baseline_evidence()).unwrap();
    knowledge
        .insert_evidence(Evidence::new(
            subject(),
            EvidenceKind::Http,
            KnowledgePredicate::new("http.header", "server").unwrap(),
            EvidenceValue::Text("nginx".to_owned()),
            EvidenceSource::new("test.seed", "seed-2").unwrap(),
            ConfidenceScore::MAX,
        ))
        .unwrap();
    let adapter = DecisionRunnerAdapter::new(local_registry());

    let receipt = adapter
        .execute_command(&execute_action("action.local", "local.test"), &knowledge)
        .await
        .unwrap();

    assert_eq!(receipt.evidence().len(), 1);
    let derived = &receipt.evidence()[0];
    assert_eq!(
        derived.predicate().dotted(),
        "test.local.observed-evidence-count"
    );
    assert_eq!(derived.value(), &EvidenceValue::Unsigned(2));
    assert_eq!(derived.subject(), &subject());
    assert_eq!(derived.source().component(), "local.test");
    assert_eq!(derived.source().correlation_id(), Some("case:1"));
    // Committed atomically through the same knowledge writer.
    assert!(knowledge.stats().evidence >= 3);
}

#[tokio::test]
async fn local_knowledge_never_routes_through_the_transport_execute_path() {
    // The executor's transport `execute` fails; the run still succeeds because
    // the runner dispatches a LocalKnowledge action through the snapshot path.
    let knowledge = KnowledgeBase::new();
    knowledge.insert_evidence(baseline_evidence()).unwrap();
    let adapter = DecisionRunnerAdapter::new(local_registry());

    let receipt = adapter
        .execute_command(&execute_action("action.local", "local.test"), &knowledge)
        .await
        .unwrap();
    assert_eq!(receipt.evidence().len(), 1);
}

#[test]
fn execution_class_is_resolved_from_the_registry_route() {
    let adapter = DecisionRunnerAdapter::new(local_registry());
    assert_eq!(
        adapter
            .execution_class_for_command(&execute_action("action.local", "local.test"))
            .unwrap(),
        DecisionExecutionClass::LocalKnowledge
    );
    // A default executor reports TransportBound without any implementation
    // change (compatibility).
    let mut registry = DecisionExecutorRegistry::new();
    registry
        .register(Arc::new(RecordingExecutor {
            id: "http.test",
            subject_override: None,
        }))
        .unwrap();
    registry
        .route_action(DecisionExecutionStage::Passive, "action.http", "http.test")
        .unwrap();
    let adapter = DecisionRunnerAdapter::new(registry);
    assert_eq!(
        adapter
            .execution_class_for_command(&execute_action("action.http", "http.test"))
            .unwrap(),
        DecisionExecutionClass::TransportBound
    );
}

/// Declares LocalKnowledge but never overrides snapshot execution. Its
/// transport `execute` records a call so the test can prove it is never made.
struct MislabeledLocalExecutor {
    executed: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait]
impl DecisionActionExecutor for MislabeledLocalExecutor {
    fn id(&self) -> &str {
        "mislabeled.local"
    }

    fn execution_class(&self) -> DecisionExecutionClass {
        DecisionExecutionClass::LocalKnowledge
    }

    async fn execute(
        &self,
        _request: &DecisionExecutionRequest,
    ) -> Result<Vec<Evidence>, DecisionExecutorError> {
        self.executed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(Vec::new())
    }
}

#[tokio::test]
async fn local_knowledge_without_snapshot_override_is_fail_closed() {
    // A LocalKnowledge executor that forgets to override snapshot execution
    // must produce a deterministic error, and its transport `execute` must
    // NEVER run — the runtime has already skipped transport accounting for it.
    let executed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut registry = DecisionExecutorRegistry::new();
    registry
        .register(Arc::new(MislabeledLocalExecutor {
            executed: executed.clone(),
        }))
        .unwrap();
    registry
        .route_action(
            DecisionExecutionStage::Passive,
            "action.mislabeled",
            "mislabeled.local",
        )
        .unwrap();
    let adapter = DecisionRunnerAdapter::new(registry);

    let error = adapter
        .execute_command(
            &execute_action("action.mislabeled", "mislabeled.local"),
            &KnowledgeBase::new(),
        )
        .await
        .unwrap_err();

    assert!(
        !executed.load(std::sync::atomic::Ordering::SeqCst),
        "the transport execute() path must not be reached"
    );
    assert!(matches!(error, DecisionRunnerError::Executor { .. }));
}

fn executor(
    id: &'static str,
    subject_override: Option<EntityId>,
) -> Arc<dyn DecisionActionExecutor> {
    Arc::new(RecordingExecutor {
        id,
        subject_override,
    })
}

fn failing_executor(
    id: &'static str,
    kind: DecisionExecutionFailureKind,
    diagnostic: &'static str,
) -> Arc<dyn DecisionActionExecutor> {
    Arc::new(FailingExecutor {
        id,
        kind,
        diagnostic,
    })
}

fn empty_decision_loop() -> DecisionLoop {
    let planning = PlanningContext::new(
        BenefitScore::from_percent(80).unwrap(),
        100,
        RiskScore::from_percent(40).unwrap(),
    );
    DecisionLoop::new(
        DecisionLoopConfig::new(
            planning,
            AdaptationLimits::default(),
            ExperiencePolicy::default(),
            4,
        )
        .unwrap(),
    )
}

fn loop_with_supported_http_action() -> (DecisionLoop, KnowledgeBase) {
    loop_with_supported_http_action_target(VerificationTarget::Motivation)
}

fn loop_with_supported_http_action_target(
    target: VerificationTarget,
) -> (DecisionLoop, KnowledgeBase) {
    let mut decision_loop = empty_decision_loop();
    let predicate = KnowledgePredicate::new("stack", "framework").unwrap();
    let value = EvidenceValue::Text("Laravel".to_owned());
    decision_loop
        .planner_mut()
        .register(
            AttackAction::new(
                "http.probe",
                "plugin.http",
                Expression::equals(KnowledgeLayer::Hypothesis, predicate.clone(), value.clone()),
                HypothesisSelector::new(
                    predicate.clone(),
                    value.clone(),
                    Probability::from_percent(50).unwrap(),
                    RequiredStrength::Strong,
                ),
                BenefitScore::from_percent(80).unwrap(),
                ActionCost::new(10).unwrap(),
                RiskScore::from_percent(20).unwrap(),
                BTreeSet::new(),
            )
            .unwrap()
            .with_verification_target(target),
        )
        .unwrap();
    let knowledge = KnowledgeBase::new();
    let mut hypothesis = Hypothesis::with_id(
        "hypothesis:1",
        subject(),
        predicate,
        value,
        Probability::from_percent(90).unwrap(),
    )
    .unwrap();
    hypothesis.set_strength(HypothesisStrength::Strong);
    hypothesis.set_state(HypothesisState::Supported);
    knowledge.upsert_hypothesis(hypothesis).unwrap();
    (decision_loop, knowledge)
}

#[tokio::test]
async fn explicit_executor_records_a_validated_atomic_batch() {
    let mut registry = DecisionExecutorRegistry::new();
    registry.register(executor("plugin.http", None)).unwrap();
    let adapter = DecisionRunnerAdapter::new(registry);
    let knowledge = KnowledgeBase::new();
    let command = DecisionLoopCommand::ExecuteAction {
        case: case("http.probe"),
        executor: Some("plugin.http".to_owned()),
        origin: DecisionActionOrigin::Planned,
        delay_ms: None,
    };

    let receipt = adapter.execute_command(&command, &knowledge).await.unwrap();

    assert_eq!(receipt.stage(), DecisionExecutionStage::Passive);
    assert_eq!(receipt.executor_id(), "plugin.http");
    assert_eq!(receipt.evidence().len(), 1);
    assert_eq!(receipt.writes(), &[KnowledgeWrite::Inserted]);
    let write_set: Vec<_> = receipt.write_set().collect();
    assert_eq!(write_set.len(), 1);
    assert_eq!(write_set[0].0.id(), receipt.evidence()[0].id());
    assert_eq!(write_set[0].1, KnowledgeWrite::Inserted);
    assert!(receipt.baseline().is_none());
    assert_eq!(receipt.after_execution().evidence().len(), 1);
}

#[tokio::test]
async fn executor_must_explicitly_support_the_planner_selected_strategy() {
    let strategy = PayloadStrategyRef::new("visibility.control-pair", 1).unwrap();
    let unsupported_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut unsupported_registry = DecisionExecutorRegistry::new();
    unsupported_registry
        .register(Arc::new(StrategyExecutor {
            id: "capability.visibility",
            strategy: PayloadStrategyRef::new("visibility.control-pair", 2).unwrap(),
            calls: Arc::clone(&unsupported_calls),
        }))
        .unwrap();
    let selected_case = case("visibility.compare").with_payload_strategy(Some(strategy.clone()));
    let command = DecisionLoopCommand::ExecuteAction {
        case: selected_case.clone(),
        executor: Some("capability.visibility".to_owned()),
        origin: DecisionActionOrigin::Planned,
        delay_ms: None,
    };
    let knowledge = KnowledgeBase::new();
    let error = DecisionRunnerAdapter::new(unsupported_registry)
        .execute_command(&command, &knowledge)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        DecisionRunnerError::UnsupportedPayloadStrategy {
            executor_id,
            strategy: rejected,
        } if executor_id == "capability.visibility" && rejected == strategy
    ));
    assert_eq!(
        unsupported_calls.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(knowledge.stats().evidence, 0);

    let supported_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut supported_registry = DecisionExecutorRegistry::new();
    supported_registry
        .register(Arc::new(StrategyExecutor {
            id: "capability.visibility",
            strategy,
            calls: Arc::clone(&supported_calls),
        }))
        .unwrap();
    let receipt = DecisionRunnerAdapter::new(supported_registry)
        .execute_command(&command, &KnowledgeBase::new())
        .await
        .unwrap();
    assert_eq!(
        receipt.case().payload_strategy(),
        selected_case.payload_strategy()
    );
    assert_eq!(supported_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn executor_error_defaults_to_executor_failure_and_normalizes_diagnostics() {
    let generic = DecisionExecutorError::new("plugin failed");
    assert_eq!(
        generic.kind(),
        DecisionExecutionFailureKind::ExecutorFailure
    );
    assert_eq!(generic.message(), "plugin failed");
    assert!(generic.execution_failure().is_none());

    let transport =
        DecisionExecutorError::with_kind(DecisionExecutionFailureKind::TransportFailure, "   ");
    assert_eq!(
        transport.kind(),
        DecisionExecutionFailureKind::TransportFailure
    );
    assert_eq!(transport.message(), "executor failed without a diagnostic");

    let limit = RuntimeLimitExceeded::new(
        crate::RuntimeBudgetDimension::TotalRequests,
        1,
        2,
        Some("http.probe".to_owned()),
    );
    let limited = DecisionExecutorError::from_runtime_limit(limit.clone());
    assert_eq!(
        limited.kind(),
        DecisionExecutionFailureKind::BlockedByPolicy
    );
    assert_eq!(limited.runtime_limit(), Some(&limit));
    assert_eq!(limited.message(), limit.to_string());
}

#[test]
fn request_timeout_has_a_stable_transport_neutral_wire_name() {
    assert_eq!(
        serde_json::to_string(&DecisionExecutionFailureKind::RequestTimeout).unwrap(),
        "\"request_timeout\""
    );
}

#[tokio::test]
async fn failed_execution_exposes_an_immutable_typed_receipt() {
    let mut registry = DecisionExecutorRegistry::new();
    registry
        .register(failing_executor(
            "plugin.http",
            DecisionExecutionFailureKind::TransportFailure,
            "connection reset before headers",
        ))
        .unwrap();
    let adapter = DecisionRunnerAdapter::new(registry);
    let knowledge = KnowledgeBase::new();
    let command = DecisionLoopCommand::ExecuteAction {
        case: case("http.probe"),
        executor: Some("plugin.http".to_owned()),
        origin: DecisionActionOrigin::Planned,
        delay_ms: None,
    };
    let limits = DecisionExecutionLimits::new().with_max_response_body_bytes(4096);

    let error = adapter
        .execute_command_with_limits(&command, &knowledge, limits)
        .await
        .unwrap_err();
    assert!(matches!(
        &error,
        DecisionRunnerError::Executor {
            executor_id,
            source,
        } if executor_id == "plugin.http"
            && source.kind() == DecisionExecutionFailureKind::TransportFailure
    ));

    let receipt = error.execution_failure().unwrap();
    assert_eq!(receipt.case().id(), "case:1");
    assert_eq!(receipt.action_id(), "http.probe");
    assert_eq!(receipt.stage(), DecisionExecutionStage::Passive);
    assert_eq!(receipt.origin(), Some(DecisionActionOrigin::Planned));
    assert_eq!(receipt.delay_ms(), None);
    assert_eq!(receipt.limits(), limits);
    assert_eq!(receipt.request().limits(), limits);
    assert_eq!(receipt.executor_id(), "plugin.http");
    assert_eq!(receipt.diagnostic(), "connection reset before headers");
    assert_eq!(
        receipt.kind(),
        DecisionExecutionFailureKind::TransportFailure
    );
    assert_eq!(knowledge.stats().evidence, 0);

    let expected = receipt.clone();
    let owned = error.into_execution_failure().unwrap();
    assert_eq!(owned, expected);
}

#[tokio::test]
async fn failed_active_execution_receipt_preserves_the_resolved_stage_and_route() {
    let mut registry = DecisionExecutorRegistry::new();
    registry
        .register(failing_executor(
            "plugin.active-http",
            DecisionExecutionFailureKind::BlockedByPolicy,
            "active requests are disabled by host policy",
        ))
        .unwrap();
    registry
        .route_action(
            DecisionExecutionStage::Active,
            "http.probe",
            "plugin.active-http",
        )
        .unwrap();
    let adapter = DecisionRunnerAdapter::new(registry);
    let knowledge = KnowledgeBase::new();

    let error = adapter
        .execute_command(
            &DecisionLoopCommand::CollectActiveEvidence {
                case: case("http.probe"),
            },
            &knowledge,
        )
        .await
        .unwrap_err();
    let receipt = error.execution_failure().unwrap();

    assert_eq!(receipt.action_id(), "http.probe");
    assert_eq!(receipt.stage(), DecisionExecutionStage::Active);
    assert_eq!(receipt.executor_id(), "plugin.active-http");
    assert_eq!(
        receipt.kind(),
        DecisionExecutionFailureKind::BlockedByPolicy
    );
    assert_eq!(knowledge.stats().evidence, 0);
}

#[test]
fn unrestricted_execution_limits_preserve_the_existing_wire_shape() {
    let unrestricted = DecisionExecutionRequest::new(
        case("http.probe"),
        DecisionExecutionStage::Passive,
        Some(DecisionActionOrigin::Planned),
        None,
        DecisionExecutionLimits::default(),
    );
    let unrestricted = serde_json::to_value(unrestricted).unwrap();
    assert!(unrestricted.get("limits").is_none());

    let bounded = DecisionExecutionRequest::new(
        case("http.probe"),
        DecisionExecutionStage::Passive,
        Some(DecisionActionOrigin::Planned),
        None,
        DecisionExecutionLimits::new().with_max_response_body_bytes(64),
    );
    assert_eq!(
        serde_json::to_value(bounded).unwrap()["limits"]["max_response_body_bytes"],
        serde_json::json!(64)
    );
}

#[tokio::test]
async fn action_routes_resolve_adaptive_and_active_executors_separately() {
    let mut registry = DecisionExecutorRegistry::new();
    registry.register(executor("plugin.retry", None)).unwrap();
    registry.register(executor("plugin.verify", None)).unwrap();
    registry
        .route_action(
            DecisionExecutionStage::Passive,
            "http.retry",
            "plugin.retry",
        )
        .unwrap();
    registry
        .route_action(
            DecisionExecutionStage::Active,
            "http.retry",
            "plugin.verify",
        )
        .unwrap();
    let adapter = DecisionRunnerAdapter::new(registry);
    let knowledge = KnowledgeBase::new();
    let adaptive = DecisionLoopCommand::ExecuteAction {
        case: case("http.retry"),
        executor: None,
        origin: DecisionActionOrigin::Adaptive,
        delay_ms: None,
    };
    let active = DecisionLoopCommand::CollectActiveEvidence {
        case: case("http.retry"),
    };

    let passive_receipt = adapter
        .execute_command(&adaptive, &knowledge)
        .await
        .unwrap();
    let active_receipt = adapter.execute_command(&active, &knowledge).await.unwrap();

    assert_eq!(passive_receipt.executor_id(), "plugin.retry");
    assert_eq!(active_receipt.executor_id(), "plugin.verify");
    assert!(active_receipt.baseline().is_some());
    assert_eq!(active_receipt.baseline().unwrap().evidence().len(), 1);
    assert_eq!(active_receipt.after_execution().evidence().len(), 2);
}

#[tokio::test]
async fn invalid_provenance_rejects_the_complete_batch() {
    let mut registry = DecisionExecutorRegistry::new();
    registry
        .register(executor(
            "plugin.http",
            Some(EntityId::new("endpoint:https://other.test").unwrap()),
        ))
        .unwrap();
    let adapter = DecisionRunnerAdapter::new(registry);
    let knowledge = KnowledgeBase::new();
    let command = DecisionLoopCommand::ExecuteAction {
        case: case("http.probe"),
        executor: Some("plugin.http".to_owned()),
        origin: DecisionActionOrigin::Planned,
        delay_ms: None,
    };

    let error = adapter
        .execute_command(&command, &knowledge)
        .await
        .unwrap_err();
    assert!(matches!(
        &error,
        DecisionRunnerError::EvidenceSubjectMismatch { .. }
    ));
    assert!(error.committed_evidence().is_none());
    assert_eq!(knowledge.stats().evidence, 0);
}

#[tokio::test]
async fn post_commit_transition_error_returns_the_durable_receipt() {
    let mut registry = DecisionExecutorRegistry::new();
    registry.register(executor("plugin.http", None)).unwrap();
    let adapter = DecisionRunnerAdapter::new(registry);
    let decision_loop = empty_decision_loop();
    let knowledge = KnowledgeBase::new();
    let mut experience = ExperienceStore::new();
    let mut session = DecisionSession::new(subject());
    let initial_session = session.clone();
    let command = DecisionLoopCommand::ExecuteAction {
        case: case("http.probe"),
        executor: Some("plugin.http".to_owned()),
        origin: DecisionActionOrigin::Planned,
        delay_ms: None,
    };

    let receipt = adapter.execute_command(&command, &knowledge).await.unwrap();
    let evidence_id = receipt.evidence()[0].id().clone();
    let error = adapter
        .resume_session_command(
            &decision_loop,
            &command,
            &knowledge,
            &mut experience,
            &mut session,
            receipt,
        )
        .unwrap_err();

    assert!(matches!(
        &error,
        DecisionRunnerError::OutcomeAfterEvidenceCommit { .. }
    ));
    let committed = error.committed_evidence().unwrap();
    assert_eq!(committed.case().id(), "case:1");
    assert_eq!(committed.evidence()[0].id(), &evidence_id);
    assert!(knowledge
        .snapshot_for_subject(&subject())
        .evidence()
        .iter()
        .any(|evidence| evidence.id() == &evidence_id));
    assert_eq!(session, initial_session);
    assert!(experience.is_empty());

    let committed = error.into_committed_evidence().unwrap();
    assert_eq!(committed.evidence()[0].id(), &evidence_id);
}

#[tokio::test]
async fn unregistered_case_after_low_level_commit_keeps_evidence_auditable() {
    let mut registry = DecisionExecutorRegistry::new();
    registry.register(executor("plugin.http", None)).unwrap();
    let adapter = DecisionRunnerAdapter::new(registry);
    let decision_loop = empty_decision_loop();
    let knowledge = KnowledgeBase::new();
    let mut experience = ExperienceStore::new();
    let command_case = case("http.probe");
    let command = DecisionLoopCommand::ExecuteAction {
        case: command_case.clone(),
        executor: Some("plugin.http".to_owned()),
        origin: DecisionActionOrigin::Planned,
        delay_ms: None,
    };
    let mut session: DecisionSession = serde_json::from_value(serde_json::json!({
        "subject": subject().as_str(),
        "action_cycles": 1,
        "state": {
            "state": "awaiting_passive",
            "case": command_case
        },
        "adaptation": {
            "transitions": 0,
            "rule_applications": {},
            "action_schedules": {},
            "suppressed_actions": []
        }
    }))
    .unwrap();
    let initial_session = session.clone();

    let receipt = adapter.execute_command(&command, &knowledge).await.unwrap();
    let evidence_id = receipt.evidence()[0].id().clone();
    let error = adapter
        .resume_session_command(
            &decision_loop,
            &command,
            &knowledge,
            &mut experience,
            &mut session,
            receipt,
        )
        .unwrap_err();

    assert!(matches!(
        &error,
        DecisionRunnerError::OutcomeAfterEvidenceCommit { source, .. }
            if matches!(
                source.as_ref(),
                DecisionRunnerError::Decision(
                    DecisionLoopError::UnregisteredDecisionAction { .. }
                )
            )
    ));
    let committed = error.committed_evidence().unwrap();
    assert_eq!(committed.evidence()[0].id(), &evidence_id);
    assert!(knowledge
        .snapshot_for_subject(&subject())
        .evidence()
        .iter()
        .any(|evidence| evidence.id() == &evidence_id));
    assert_eq!(session, initial_session);
    assert!(experience.is_empty());
}

#[tokio::test]
async fn drive_command_rejects_stale_session_before_executor_work() {
    let mut registry = DecisionExecutorRegistry::new();
    registry.register(executor("plugin.http", None)).unwrap();
    let adapter = DecisionRunnerAdapter::new(registry);
    let (decision_loop, knowledge) = loop_with_supported_http_action();
    let mut experience = ExperienceStore::new();
    let mut session = DecisionSession::new(subject());
    let command = DecisionLoopCommand::ExecuteAction {
        case: case("http.probe"),
        executor: Some("plugin.http".to_owned()),
        origin: DecisionActionOrigin::Planned,
        delay_ms: None,
    };

    assert!(matches!(
        adapter
            .drive_command(
                &decision_loop,
                &command,
                &knowledge,
                &mut experience,
                &mut session,
            )
            .await,
        Err(DecisionRunnerError::UnexpectedSessionState { .. })
    ));
    assert_eq!(knowledge.stats().evidence, 0);
}

#[tokio::test]
async fn context_free_drive_rejects_every_continuation_before_executor_work() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut registry = DecisionExecutorRegistry::new();
    registry
        .register(Arc::new(CountingExecutor {
            id: "plugin.http",
            calls: Arc::clone(&calls),
        }))
        .unwrap();
    let adapter = DecisionRunnerAdapter::new(registry);
    let decision_loop = empty_decision_loop();
    let knowledge = KnowledgeBase::new();
    let commands = [
        DecisionLoopCommand::ExecuteAction {
            case: case("http.probe"),
            executor: Some("plugin.http".to_owned()),
            origin: DecisionActionOrigin::Adaptive,
            delay_ms: None,
        },
        DecisionLoopCommand::ExecuteAction {
            case: case("http.probe"),
            executor: Some("plugin.http".to_owned()),
            origin: DecisionActionOrigin::Retry,
            delay_ms: None,
        },
        DecisionLoopCommand::CollectActiveEvidence {
            case: case("http.probe"),
        },
        DecisionLoopCommand::Replan,
    ];

    for (command, expected) in commands.into_iter().zip([
        "adaptive_execute_action",
        "retry_execute_action",
        "collect_active_evidence",
        "replan",
    ]) {
        let mut experience = ExperienceStore::new();
        let mut session = DecisionSession::new(subject());
        assert!(matches!(
            adapter
                .drive_command(
                    &decision_loop,
                    &command,
                    &knowledge,
                    &mut experience,
                    &mut session,
                )
                .await,
            Err(DecisionRunnerError::HostPolicyContextRequired { command })
                if command == expected
        ));
        assert_eq!(session, DecisionSession::new(subject()));
        assert!(experience.is_empty());
    }
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(knowledge.stats().evidence, 0);
}

#[tokio::test]
async fn current_host_suppression_rejects_execution_before_executor_work() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut registry = DecisionExecutorRegistry::new();
    registry
        .register(Arc::new(CountingExecutor {
            id: "plugin.http",
            calls: Arc::clone(&calls),
        }))
        .unwrap();
    let adapter = DecisionRunnerAdapter::new(registry);
    let decision_loop = empty_decision_loop();
    let knowledge = KnowledgeBase::new();
    let suppressions = BTreeSet::from(["http.probe".to_owned()]);
    let commands = [
        DecisionLoopCommand::ExecuteAction {
            case: case("http.probe"),
            executor: Some("plugin.http".to_owned()),
            origin: DecisionActionOrigin::Planned,
            delay_ms: None,
        },
        DecisionLoopCommand::CollectActiveEvidence {
            case: case("http.probe"),
        },
    ];

    for command in commands {
        let mut experience = ExperienceStore::new();
        let mut session = DecisionSession::new(subject());
        assert!(matches!(
            adapter
                .drive_command_with_suppressed_actions(
                    &decision_loop,
                    &command,
                    &knowledge,
                    &mut experience,
                    &mut session,
                    &suppressions,
                )
                .await,
            Err(DecisionRunnerError::ActionSuppressedByHostPolicy { action_id })
                if action_id == "http.probe"
        ));
        assert_eq!(session, DecisionSession::new(subject()));
        assert!(experience.is_empty());
    }
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(knowledge.stats().evidence, 0);
}

#[test]
fn defense_suppression_has_distinct_predispatch_precedence() {
    let adapter = DecisionRunnerAdapter::new(DecisionExecutorRegistry::new());
    let command = execute_action("http.probe", "plugin.http");
    let both = BTreeSet::from(["http.probe".to_owned()]);
    let suppressions = ActionSuppressionContext::new(both.clone(), both);

    assert!(matches!(
        adapter.validate_command_suppression(&command, &suppressions),
        Err(DecisionRunnerError::ActionSuppressedByDefense { action_id })
            if action_id == "http.probe"
    ));
}

#[tokio::test]
async fn defense_suppressed_predispatch_replans_without_executor_work() {
    for active in [false, true] {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut registry = DecisionExecutorRegistry::new();
        registry
            .register(Arc::new(CountingExecutor {
                id: "plugin.http",
                calls: Arc::clone(&calls),
            }))
            .unwrap();
        let adapter = DecisionRunnerAdapter::new(registry);
        let (decision_loop, knowledge) = loop_with_supported_http_action();
        let mut experience = ExperienceStore::new();
        let mut session = DecisionSession::new(subject());
        let planning = decision_loop
            .plan_next(&knowledge, &experience, &mut session)
            .unwrap();
        let planned_case = match planning.command() {
            DecisionLoopCommand::ExecuteAction { case, .. } => case.clone(),
            other => panic!("expected planned execution, got {other:?}"),
        };
        let command = if active {
            let mut wire = serde_json::to_value(&session).unwrap();
            wire["state"]["state"] = serde_json::json!("awaiting_active");
            session = serde_json::from_value(wire).unwrap();
            DecisionLoopCommand::CollectActiveEvidence { case: planned_case }
        } else {
            planning.command().clone()
        };
        let evidence_before = knowledge.stats().evidence;
        let cycles_before = session.action_cycles();
        let suppressions = ActionSuppressionContext::new(
            BTreeSet::new(),
            BTreeSet::from(["http.probe".to_owned()]),
        );

        let turn = adapter
            .drive_command_with_action_suppressions(
                &decision_loop,
                &command,
                &knowledge,
                &mut experience,
                &mut session,
                &suppressions,
            )
            .await
            .unwrap();

        let DecisionRunnerTurn::Planning(report) = turn else {
            panic!("defense suppression must return a planning turn");
        };
        assert!(report.plan().steps().is_empty());
        assert!(report.plan().excluded().iter().any(|entry| {
            entry.action_id() == "http.probe"
                && entry.reason() == &crate::ExclusionReason::DefenseSuppressed
        }));
        assert!(matches!(report.command(), DecisionLoopCommand::Halt { .. }));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(knowledge.stats().evidence, evidence_before);
        assert_eq!(session.action_cycles(), cycles_before);
    }
}

#[tokio::test]
async fn newly_defense_suppressed_resume_preserves_evidence_and_replans() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut registry = DecisionExecutorRegistry::new();
    registry
        .register(Arc::new(CountingExecutor {
            id: "plugin.http",
            calls: Arc::clone(&calls),
        }))
        .unwrap();
    let adapter = DecisionRunnerAdapter::new(registry);
    let (decision_loop, knowledge) = loop_with_supported_http_action();
    let mut experience = ExperienceStore::new();
    let mut session = DecisionSession::new(subject());
    let planning = decision_loop
        .plan_next(&knowledge, &experience, &mut session)
        .unwrap();
    let command = planning.command().clone();
    let receipt = adapter.execute_command(&command, &knowledge).await.unwrap();
    let committed_id = receipt.evidence()[0].id().clone();
    let suppressions =
        ActionSuppressionContext::new(BTreeSet::new(), BTreeSet::from(["http.probe".to_owned()]));

    let turn = adapter
        .resume_session_command_with_action_suppressions(
            &decision_loop,
            &command,
            &knowledge,
            &mut experience,
            &mut session,
            ContinuationAuthority::new(receipt, &suppressions),
        )
        .unwrap();

    assert!(matches!(
        turn,
        DecisionRunnerTurn::Outcome { evidence, decision }
            if evidence.evidence()[0].id() == &committed_id
                && matches!(decision.command(), DecisionLoopCommand::Replan)
    ));
    assert!(knowledge
        .snapshot_for_subject(&subject())
        .evidence()
        .iter()
        .any(|evidence| evidence.id() == &committed_id));
    assert!(matches!(session.state(), DecisionLoopState::Ready));
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn high_level_runner_rejects_broadened_knowledge_only_replay_before_executor_work() {
    for active in [false, true] {
        let (decision_loop, knowledge) =
            loop_with_supported_http_action_target(VerificationTarget::KnowledgeOnly);
        let experience = ExperienceStore::new();
        let mut issued = DecisionSession::new(subject());
        decision_loop
            .plan_next(&knowledge, &experience, &mut issued)
            .unwrap();
        let mut wire = serde_json::to_value(&issued).unwrap();
        let state = wire["state"].as_object_mut().unwrap();
        if active {
            state.insert("state".to_owned(), serde_json::json!("awaiting_active"));
        }
        let case_wire = state["case"].as_object_mut().unwrap();
        case_wire.remove("applies_hypothesis_transition");
        case_wire.remove("payload_claim_policy_guard");
        let mut session: DecisionSession = serde_json::from_value(wire).unwrap();
        let broadened_case = match session.state() {
            DecisionLoopState::AwaitingPassive { case }
            | DecisionLoopState::AwaitingActive { case } => case.clone(),
            state => panic!("expected replayed outstanding case, got {state:?}"),
        };
        assert!(broadened_case.applies_hypothesis_transition());
        let command = if active {
            DecisionLoopCommand::CollectActiveEvidence {
                case: broadened_case,
            }
        } else {
            DecisionLoopCommand::ExecuteAction {
                case: broadened_case,
                executor: Some("plugin.http".to_owned()),
                origin: DecisionActionOrigin::Planned,
                delay_ms: None,
            }
        };
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let executor_id = if active {
            "plugin.active"
        } else {
            "plugin.http"
        };
        let mut registry = DecisionExecutorRegistry::new();
        registry
            .register(Arc::new(CountingExecutor {
                id: executor_id,
                calls: Arc::clone(&calls),
            }))
            .unwrap();
        if active {
            registry
                .route_action(DecisionExecutionStage::Active, "http.probe", executor_id)
                .unwrap();
        }
        let adapter = DecisionRunnerAdapter::new(registry);
        let before_session = session.clone();
        let mut replay_experience = experience.clone();

        let error = adapter
            .drive_command_with_suppressed_actions(
                &decision_loop,
                &command,
                &knowledge,
                &mut replay_experience,
                &mut session,
                &BTreeSet::new(),
            )
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            DecisionRunnerError::Decision(
                DecisionLoopError::DecisionCaseAuthorityExceeded { action_id }
            ) if action_id == "http.probe"
        ));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(knowledge.stats().evidence, 0);
        assert_eq!(session, before_session);
        assert_eq!(replay_experience, experience);
    }
}

#[tokio::test]
async fn defense_suppression_cannot_hide_a_broadened_knowledge_only_replay() {
    let (decision_loop, knowledge) =
        loop_with_supported_http_action_target(VerificationTarget::KnowledgeOnly);
    let experience = ExperienceStore::new();
    let mut issued = DecisionSession::new(subject());
    decision_loop
        .plan_next(&knowledge, &experience, &mut issued)
        .unwrap();
    let mut wire = serde_json::to_value(&issued).unwrap();
    let case_wire = wire["state"]["case"].as_object_mut().unwrap();
    case_wire.remove("applies_hypothesis_transition");
    case_wire.remove("payload_claim_policy_guard");
    let mut session: DecisionSession = serde_json::from_value(wire).unwrap();
    let broadened_case = match session.state() {
        DecisionLoopState::AwaitingPassive { case } => case.clone(),
        state => panic!("expected replayed passive case, got {state:?}"),
    };
    let command = DecisionLoopCommand::ExecuteAction {
        case: broadened_case,
        executor: Some("plugin.http".to_owned()),
        origin: DecisionActionOrigin::Planned,
        delay_ms: None,
    };
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut registry = DecisionExecutorRegistry::new();
    registry
        .register(Arc::new(CountingExecutor {
            id: "plugin.http",
            calls: Arc::clone(&calls),
        }))
        .unwrap();
    let adapter = DecisionRunnerAdapter::new(registry);
    let suppressions =
        ActionSuppressionContext::new(BTreeSet::new(), BTreeSet::from(["http.probe".to_owned()]));
    let before = session.clone();
    let mut replay_experience = experience.clone();

    let error = adapter
        .drive_command_with_action_suppressions(
            &decision_loop,
            &command,
            &knowledge,
            &mut replay_experience,
            &mut session,
            &suppressions,
        )
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        DecisionRunnerError::Decision(
            DecisionLoopError::DecisionCaseAuthorityExceeded { action_id }
        ) if action_id == "http.probe"
    ));
    assert_eq!(session, before);
    assert_eq!(replay_experience, experience);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn explicit_empty_host_policy_allows_authorized_adaptive_and_retry_execution() {
    for origin in [DecisionActionOrigin::Adaptive, DecisionActionOrigin::Retry] {
        let (decision_loop, knowledge) = loop_with_supported_http_action();
        let mut experience = ExperienceStore::new();
        let mut session = DecisionSession::new(subject());
        let planning = decision_loop
            .plan_next(&knowledge, &experience, &mut session)
            .unwrap();
        let (case, executor) = match planning.command() {
            DecisionLoopCommand::ExecuteAction { case, executor, .. } => {
                (case.clone(), executor.clone())
            },
            other => panic!("expected planned execution, got {other:?}"),
        };
        let command = DecisionLoopCommand::ExecuteAction {
            case,
            executor,
            origin,
            delay_ms: None,
        };
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut registry = DecisionExecutorRegistry::new();
        registry
            .register(Arc::new(CountingExecutor {
                id: "plugin.http",
                calls: Arc::clone(&calls),
            }))
            .unwrap();
        let adapter = DecisionRunnerAdapter::new(registry);

        let turn = adapter
            .drive_command_with_suppressed_actions(
                &decision_loop,
                &command,
                &knowledge,
                &mut experience,
                &mut session,
                &BTreeSet::new(),
            )
            .await
            .unwrap();

        assert!(matches!(
            turn,
            DecisionRunnerTurn::Outcome { decision, .. }
                if matches!(decision.command(), DecisionLoopCommand::CollectActiveEvidence { .. })
        ));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(knowledge.stats().evidence, 1);
    }
}

#[tokio::test]
async fn suppression_aware_replan_forwards_policy_into_planning() {
    let adapter = DecisionRunnerAdapter::new(DecisionExecutorRegistry::new());
    let (decision_loop, knowledge) = loop_with_supported_http_action();
    let mut experience = ExperienceStore::new();
    let mut session = DecisionSession::new(subject());

    let turn = adapter
        .drive_command_with_suppressed_actions(
            &decision_loop,
            &DecisionLoopCommand::Replan,
            &knowledge,
            &mut experience,
            &mut session,
            &BTreeSet::from(["http.probe".to_owned()]),
        )
        .await
        .unwrap();

    assert!(matches!(
        turn,
        DecisionRunnerTurn::Planning(report)
            if report.plan().steps().is_empty()
                && report.suppressed_actions().contains("http.probe")
                && matches!(report.command(), DecisionLoopCommand::Halt { .. })
    ));
}

#[tokio::test]
async fn replan_command_with_explicit_host_policy_advances_without_an_executor() {
    let adapter = DecisionRunnerAdapter::new(DecisionExecutorRegistry::new());
    let decision_loop = empty_decision_loop();
    let knowledge = KnowledgeBase::new();
    let mut experience = ExperienceStore::new();
    let mut session = DecisionSession::new(subject());

    let turn = adapter
        .drive_command_with_suppressed_actions(
            &decision_loop,
            &DecisionLoopCommand::Replan,
            &knowledge,
            &mut experience,
            &mut session,
            &BTreeSet::new(),
        )
        .await
        .unwrap();

    assert!(matches!(
        turn,
        DecisionRunnerTurn::Planning(report)
            if matches!(report.command(), DecisionLoopCommand::Halt { .. })
    ));
    assert!(matches!(session.state(), DecisionLoopState::Halted { .. }));
}

#[tokio::test]
async fn planned_action_runs_through_evidence_and_passive_verification() {
    let mut decision_loop = empty_decision_loop();
    let hypothesis_predicate = KnowledgePredicate::new("stack", "framework").unwrap();
    let hypothesis_value = EvidenceValue::Text("Laravel".to_owned());
    decision_loop
        .planner_mut()
        .register(
            AttackAction::new(
                "http.probe",
                "plugin.http",
                Expression::equals(
                    KnowledgeLayer::Hypothesis,
                    hypothesis_predicate.clone(),
                    hypothesis_value.clone(),
                ),
                HypothesisSelector::new(
                    hypothesis_predicate.clone(),
                    hypothesis_value.clone(),
                    Probability::from_percent(50).unwrap(),
                    RequiredStrength::Strong,
                ),
                BenefitScore::from_percent(80).unwrap(),
                ActionCost::new(10).unwrap(),
                RiskScore::from_percent(20).unwrap(),
                std::collections::BTreeSet::new(),
            )
            .unwrap(),
        )
        .unwrap();
    decision_loop
        .verification_mut()
        .passive_mut()
        .register(
            VerificationRule::new(
                "verify.http-200",
                VerificationStage::Passive,
                100,
                Expression::equals(
                    KnowledgeLayer::Evidence,
                    KnowledgePredicate::new("http.response", "status").unwrap(),
                    EvidenceValue::Unsigned(200),
                ),
                OutcomeStatus::Success,
                Probability::from_percent(95).unwrap(),
                "HTTP response confirms the action",
            )
            .unwrap(),
        )
        .unwrap();

    let knowledge = KnowledgeBase::new();
    let mut hypothesis = Hypothesis::with_id(
        "hypothesis:1",
        subject(),
        hypothesis_predicate,
        hypothesis_value,
        Probability::from_percent(90).unwrap(),
    )
    .unwrap();
    hypothesis.set_strength(HypothesisStrength::Strong);
    hypothesis.set_state(HypothesisState::Supported);
    knowledge.upsert_hypothesis(hypothesis).unwrap();

    let mut registry = DecisionExecutorRegistry::new();
    registry.register(executor("plugin.http", None)).unwrap();
    let adapter = DecisionRunnerAdapter::new(registry);
    let mut experience = ExperienceStore::new();
    let mut session = DecisionSession::new(subject());
    let planning = decision_loop
        .plan_next(&knowledge, &experience, &mut session)
        .unwrap();

    let turn = adapter
        .drive_command(
            &decision_loop,
            planning.command(),
            &knowledge,
            &mut experience,
            &mut session,
        )
        .await
        .unwrap();

    assert!(matches!(
        turn,
        DecisionRunnerTurn::Outcome { evidence, decision }
            if evidence.writes() == [KnowledgeWrite::Inserted]
                && decision.verification().outcome().status() == OutcomeStatus::Success
                && matches!(decision.command(), DecisionLoopCommand::Complete { .. })
    ));
    assert!(matches!(session.state(), DecisionLoopState::Completed));
    assert_eq!(experience.len(), 1);
}

#[test]
fn registry_rejects_ambiguous_routes_and_unknown_executors() {
    let mut registry = DecisionExecutorRegistry::new();
    registry.register(executor("first", None)).unwrap();
    registry.register(executor("second", None)).unwrap();
    registry
        .route_action(DecisionExecutionStage::Active, "verify", "first")
        .unwrap();

    assert!(matches!(
        registry.route_action(DecisionExecutionStage::Active, "verify", "second"),
        Err(DecisionRunnerError::ActionRouteConflict { .. })
    ));
    assert!(matches!(
        registry.route_action(DecisionExecutionStage::Passive, "probe", "missing"),
        Err(DecisionRunnerError::UnknownExecutor { .. })
    ));
}

#[cfg(feature = "plugins")]
struct ObservationPlugin;

#[cfg(feature = "plugins")]
#[async_trait]
impl crate::Plugin for ObservationPlugin {
    fn id(&self) -> &str {
        "plugin.observer"
    }

    fn name(&self) -> &str {
        "Observation Plugin"
    }

    fn version(&self) -> &str {
        "0.2.0"
    }

    fn description(&self) -> &str {
        "test bridge"
    }

    fn author(&self) -> &str {
        "Termivar"
    }

    fn category(&self) -> crate::PluginCategory {
        crate::PluginCategory::Custom
    }

    async fn execute(&self, context: &crate::PluginContext) -> Result<(), crate::PluginError> {
        context.record(crate::PluginObservation::new(
            EvidenceKind::Custom("plugin.observation".to_owned()),
            KnowledgePredicate::new("plugin.observation", "marker").unwrap(),
            EvidenceValue::Text(String::from_utf8_lossy(context.input()).into_owned()),
            "marker",
        )?)
    }
}

#[cfg(feature = "plugins")]
struct RequestingPlugin;

#[cfg(feature = "plugins")]
#[async_trait]
impl crate::Plugin for RequestingPlugin {
    fn id(&self) -> &str {
        "plugin.requesting"
    }

    fn name(&self) -> &str {
        "Requesting Plugin"
    }

    fn version(&self) -> &str {
        "0.2.0"
    }

    fn description(&self) -> &str {
        "test response allowance bridge"
    }

    fn author(&self) -> &str {
        "Termivar"
    }

    fn category(&self) -> crate::PluginCategory {
        crate::PluginCategory::Custom
    }

    async fn execute(&self, context: &crate::PluginContext) -> Result<(), crate::PluginError> {
        context
            .request(
                crate::PluginHttpMethod::Get,
                context.authorized_origin().clone(),
            )
            .await?;
        Ok(())
    }
}

#[cfg(feature = "plugins")]
struct CaptureLimitBroker {
    limits: std::sync::Mutex<Vec<u64>>,
}

#[cfg(feature = "plugins")]
#[async_trait]
impl crate::PluginRequestBroker for CaptureLimitBroker {
    async fn execute(
        &self,
        request: crate::PluginHttpRequest,
    ) -> Result<crate::PluginHttpResponse, crate::PluginError> {
        self.limits
            .lock()
            .map_err(|_| crate::PluginError::HostStateUnavailable)?
            .push(request.max_response_body_bytes());
        crate::PluginHttpResponse::new(200, request.url().clone(), Vec::new())
    }
}

#[cfg(feature = "plugins")]
struct UnusedPluginBroker;

#[cfg(feature = "plugins")]
#[async_trait]
impl crate::PluginRequestBroker for UnusedPluginBroker {
    async fn execute(
        &self,
        _request: crate::PluginHttpRequest,
    ) -> Result<crate::PluginHttpResponse, crate::PluginError> {
        Err(crate::PluginError::BrokerFailure(
            "observation-only test broker must not execute".to_owned(),
        ))
    }
}

#[cfg(feature = "plugins")]
fn plugin_request(
    subject: EntityId,
    case_id: &str,
) -> Result<crate::PluginExecutionRequest, DecisionExecutorError> {
    crate::PluginExecutionRequest::new(
        subject,
        url::Url::parse("https://example.test").unwrap(),
        case_id,
        Arc::new(UnusedPluginBroker),
    )
    .map_err(|error| DecisionExecutorError::new(error.to_string()))
}

#[cfg(feature = "plugins")]
#[tokio::test]
async fn plugin_bridge_rejects_provider_identity_mismatch_before_plugin_execution() {
    let providers: Vec<Arc<dyn PluginExecutionRequestProvider>> = vec![
        Arc::new(|request: &DecisionExecutionRequest| {
            plugin_request(
                EntityId::new("endpoint:https://other.test").unwrap(),
                request.case().id(),
            )
        }),
        Arc::new(|request: &DecisionExecutionRequest| {
            plugin_request(request.case().subject().clone(), "case:other")
        }),
    ];

    for provider in providers {
        let plugins = Arc::new(crate::PluginRegistry::new());
        plugins
            .register(Arc::new(ObservationPlugin), crate::PluginConfig::default())
            .unwrap();
        let bridge =
            PluginDecisionExecutor::new(Arc::clone(&plugins), "plugin.observer", provider).unwrap();
        let mut registry = DecisionExecutorRegistry::new();
        registry.register(Arc::new(bridge)).unwrap();
        let command = DecisionLoopCommand::ExecuteAction {
            case: case("http.probe"),
            executor: Some("plugin.observer".to_owned()),
            origin: DecisionActionOrigin::Planned,
            delay_ms: None,
        };

        let error = DecisionRunnerAdapter::new(registry)
            .execute_command(&command, &KnowledgeBase::new())
            .await
            .unwrap_err();

        assert_eq!(
            error.execution_failure().unwrap().kind(),
            DecisionExecutionFailureKind::BlockedByPolicy
        );
        assert_eq!(
            plugins
                .get_metadata("plugin.observer")
                .unwrap()
                .execution_count(),
            0
        );
    }
}

#[cfg(feature = "plugins")]
#[tokio::test]
async fn plugin_registry_bridge_commits_observation_without_creating_a_claim() {
    let plugins = Arc::new(crate::PluginRegistry::new());
    plugins
        .register(Arc::new(ObservationPlugin), crate::PluginConfig::default())
        .unwrap();
    let requests: Arc<dyn PluginExecutionRequestProvider> =
        Arc::new(|request: &DecisionExecutionRequest| {
            plugin_request(request.case().subject().clone(), request.case().id())
                .and_then(|plugin_request| {
                    plugin_request
                        .with_input(b"server: nginx".to_vec())
                        .map_err(|error| DecisionExecutorError::new(error.to_string()))
                })
                .map(|plugin_request| {
                    plugin_request.with_reliability(ConfidenceScore::from_percent(90).unwrap())
                })
        });
    let bridge = PluginDecisionExecutor::new(plugins, "plugin.observer", requests).unwrap();
    let mut registry = DecisionExecutorRegistry::new();
    registry.register(Arc::new(bridge)).unwrap();
    let adapter = DecisionRunnerAdapter::new(registry);
    let knowledge = KnowledgeBase::new();
    let command = DecisionLoopCommand::ExecuteAction {
        case: case("http.probe"),
        executor: Some("plugin.observer".to_owned()),
        origin: DecisionActionOrigin::Planned,
        delay_ms: None,
    };

    let receipt = adapter.execute_command(&command, &knowledge).await.unwrap();
    let observation = &receipt.after_execution().evidence()[0];

    assert_eq!(receipt.writes(), &[KnowledgeWrite::Inserted]);
    assert_eq!(observation.source().component(), "plugin.observer");
    assert_eq!(observation.source().correlation_id(), Some("case:1"));
    assert_eq!(
        observation.predicate().dotted(),
        "plugin.observation.marker"
    );
    assert_eq!(knowledge.stats().facts, 0);
    assert_eq!(knowledge.stats().hypotheses, 0);

    let mut decision_loop = empty_decision_loop();
    let hypothesis_predicate = KnowledgePredicate::new("stack", "framework").unwrap();
    let hypothesis_value = EvidenceValue::Text("fixture".to_owned());
    decision_loop
        .planner_mut()
        .register(
            AttackAction::new(
                "http.probe",
                "plugin.observer",
                Expression::equals(
                    KnowledgeLayer::Hypothesis,
                    hypothesis_predicate.clone(),
                    hypothesis_value.clone(),
                ),
                HypothesisSelector::new(
                    hypothesis_predicate.clone(),
                    hypothesis_value.clone(),
                    Probability::from_percent(50).unwrap(),
                    RequiredStrength::Strong,
                ),
                BenefitScore::from_percent(80).unwrap(),
                ActionCost::new(10).unwrap(),
                RiskScore::from_percent(20).unwrap(),
                BTreeSet::new(),
            )
            .unwrap(),
        )
        .unwrap();
    let knowledge = KnowledgeBase::new();
    let mut hypothesis = Hypothesis::with_id(
        "hypothesis:plugin-observation",
        subject(),
        hypothesis_predicate,
        hypothesis_value,
        Probability::from_percent(90).unwrap(),
    )
    .unwrap();
    hypothesis.set_strength(HypothesisStrength::Strong);
    hypothesis.set_state(HypothesisState::Supported);
    knowledge.upsert_hypothesis(hypothesis).unwrap();
    let mut experience = ExperienceStore::new();
    let mut session = DecisionSession::new(subject());
    let planning = decision_loop
        .plan_next(&knowledge, &experience, &mut session)
        .unwrap();
    let turn = adapter
        .drive_command_with_suppressed_actions(
            &decision_loop,
            planning.command(),
            &knowledge,
            &mut experience,
            &mut session,
            &BTreeSet::new(),
        )
        .await
        .unwrap();
    assert!(matches!(
        turn,
        DecisionRunnerTurn::Outcome { decision, .. }
            if decision.verification().outcome().status() == OutcomeStatus::Unknown
    ));
    let snapshot = knowledge.snapshot_for_subject(&subject());
    let retained = snapshot
        .hypotheses()
        .iter()
        .find(|candidate| candidate.id() == "hypothesis:plugin-observation")
        .unwrap();
    assert_eq!(retained.state(), HypothesisState::Supported);
}

#[cfg(feature = "plugins")]
#[tokio::test]
async fn plugin_bridge_intersects_response_allowance_and_preserves_failure_kind() {
    let plugins = Arc::new(crate::PluginRegistry::new());
    plugins
        .register(Arc::new(RequestingPlugin), crate::PluginConfig::default())
        .unwrap();
    let broker = Arc::new(CaptureLimitBroker {
        limits: std::sync::Mutex::new(Vec::new()),
    });
    let provider_broker = broker.clone();
    let provider: Arc<dyn PluginExecutionRequestProvider> =
        Arc::new(move |request: &DecisionExecutionRequest| {
            crate::PluginExecutionRequest::new(
                request.case().subject().clone(),
                url::Url::parse("https://example.test").unwrap(),
                request.case().id(),
                provider_broker.clone(),
            )
            .map_err(|error| DecisionExecutorError::new(error.to_string()))
        });
    let bridge = PluginDecisionExecutor::new(plugins, "plugin.requesting", provider).unwrap();
    let request = DecisionExecutionRequest::new(
        case("http.probe"),
        DecisionExecutionStage::Passive,
        Some(DecisionActionOrigin::Planned),
        None,
        DecisionExecutionLimits::new().with_max_response_body_bytes(3),
    );
    assert!(bridge.execute(&request).await.unwrap().is_empty());
    assert_eq!(*broker.limits.lock().unwrap(), vec![3]);

    for (error, expected) in [
        (
            crate::PluginError::ScopeViolation,
            DecisionExecutionFailureKind::BlockedByPolicy,
        ),
        (
            crate::PluginError::BrokerFailure("transport".to_owned()),
            DecisionExecutionFailureKind::TransportFailure,
        ),
        (
            crate::PluginError::RequestTimeout,
            DecisionExecutionFailureKind::RequestTimeout,
        ),
        (
            crate::PluginError::ExecutionFailed("plugin".to_owned()),
            DecisionExecutionFailureKind::ExecutorFailure,
        ),
    ] {
        assert_eq!(plugin_executor_error(error).kind(), expected);
    }
}
