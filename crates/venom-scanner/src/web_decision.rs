//! One-shot composition of the standard deterministic web decision stack.
//!
//! ## Runtime scope
//!
//! - **Build:** default via `scanning`.
//! - **Execution:** Surface B (deterministic decision runtime).
//! - **Default `venom scan`:** no.
//! - **Support:** implemented and tested.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! The composite profile keeps domain reasoning, utility planning, bounded
//! execution, and verification independently inspectable while providing one
//! preflighted installation boundary for hosts.

use serde::Serialize;
use thiserror::Error;

use crate::{
    http_evidence::HttpRequestBroker, DecisionExecutorRegistry, DecisionLoop, HttpEvidencePolicy,
    KnowledgeBase, StandardWebAttackInstallReport, StandardWebAttackProfile,
    StandardWebDiscoveryExecutorProfile, StandardWebDiscoveryInstallReport,
    StandardWebExecutionError, StandardWebInstallReport, StandardWebPlanningError,
    StandardWebReasoning, StandardWebReasoningError, StandardWebVerificationError,
    StandardWebVerificationInstallReport, StandardWebVerificationProfile,
};

/// Failures while constructing or installing the composite web decision stack.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StandardWebDecisionError {
    /// Standard ontology or reasoning rules failed validation or installation.
    #[error(transparent)]
    Reasoning(#[from] StandardWebReasoningError),

    /// Standard planner actions failed validation or installation.
    #[error(transparent)]
    Planning(#[from] StandardWebPlanningError),

    /// Scope-bound semantic executors failed construction or installation.
    #[error(transparent)]
    Execution(#[from] StandardWebExecutionError),

    /// Passive or active verifier rules failed validation or installation.
    #[error(transparent)]
    Verification(#[from] StandardWebVerificationError),
}

/// Per-layer writes produced by one composite profile installation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct StandardWebDecisionInstallReport {
    reasoning: StandardWebInstallReport,
    planning: StandardWebAttackInstallReport,
    execution: StandardWebDiscoveryInstallReport,
    verification: StandardWebVerificationInstallReport,
}

impl StandardWebDecisionInstallReport {
    /// Returns ontology and reasoning-rule writes.
    pub fn reasoning(self) -> StandardWebInstallReport {
        self.reasoning
    }

    /// Returns utility-planner action writes.
    pub fn planning(self) -> StandardWebAttackInstallReport {
        self.planning
    }

    /// Returns semantic executor writes.
    pub fn execution(self) -> StandardWebDiscoveryInstallReport {
        self.execution
    }

    /// Returns passive and active verifier-rule writes.
    pub fn verification(self) -> StandardWebVerificationInstallReport {
        self.verification
    }
}

/// Complete opt-in standard web decision profile.
///
/// Construction validates every layer and binds execution to one immutable
/// [`HttpEvidencePolicy`]. Installation prepares the decision loop and executor
/// registry on owned clones. Ontology definitions are committed under one
/// knowledge-base write lock only after every other layer has preflighted.
///
/// # Examples
///
/// ```rust
/// use url::Url;
/// use venom_scanner::{
///     AdaptationLimits, BenefitScore, DecisionExecutorRegistry, DecisionLoop,
///     DecisionLoopConfig, ExperiencePolicy, HttpEvidencePolicy, KnowledgeBase,
///     PlanningContext, RiskScore, StandardWebDecisionProfile,
/// };
///
/// let target = Url::parse("https://example.test/")?;
/// let config = DecisionLoopConfig::new(
///     PlanningContext::new(
///         BenefitScore::from_percent(80)?,
///         100,
///         RiskScore::from_percent(40)?,
///     ),
///     AdaptationLimits::default(),
///     ExperiencePolicy::default(),
///     8,
/// )?;
/// let knowledge = KnowledgeBase::new();
/// let mut decision_loop = DecisionLoop::new(config);
/// let mut executors = DecisionExecutorRegistry::new();
///
/// StandardWebDecisionProfile::new(HttpEvidencePolicy::for_origin(target)?)?
///     .install(&knowledge, &mut decision_loop, &mut executors)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct StandardWebDecisionProfile {
    reasoning: StandardWebReasoning,
    planning: StandardWebAttackProfile,
    execution: StandardWebDiscoveryExecutorProfile,
    verification: StandardWebVerificationProfile,
}

impl StandardWebDecisionProfile {
    /// Builds and validates all four layers before any host state is changed.
    pub fn new(policy: HttpEvidencePolicy) -> Result<Self, StandardWebDecisionError> {
        Self::build(StandardWebDiscoveryExecutorProfile::new(policy)?)
    }

    pub(crate) fn new_with_request_broker(
        requests: HttpRequestBroker,
    ) -> Result<Self, StandardWebDecisionError> {
        Self::build(StandardWebDiscoveryExecutorProfile::new_with_request_broker(requests)?)
    }

    fn build(
        execution: StandardWebDiscoveryExecutorProfile,
    ) -> Result<Self, StandardWebDecisionError> {
        Ok(Self {
            reasoning: StandardWebReasoning::new()?,
            planning: StandardWebAttackProfile::new()?,
            execution,
            verification: StandardWebVerificationProfile::new()?,
        })
    }

    /// Installs the full profile with preflighted all-or-nothing semantics.
    pub fn install(
        &self,
        knowledge: &KnowledgeBase,
        decision_loop: &mut DecisionLoop,
        executors: &mut DecisionExecutorRegistry,
    ) -> Result<StandardWebDecisionInstallReport, StandardWebDecisionError> {
        let mut prospective_loop = decision_loop.clone();
        let mut prospective_executors = executors.clone();

        let planning = self.planning.install(prospective_loop.planner_mut())?;
        let verification = self
            .verification
            .install(prospective_loop.verification_mut())?;
        let execution = self.execution.install(&mut prospective_executors)?;
        let reasoning = self
            .reasoning
            .install(knowledge, prospective_loop.rules_mut())?;

        *decision_loop = prospective_loop;
        *executors = prospective_executors;
        Ok(StandardWebDecisionInstallReport {
            reasoning,
            planning,
            execution,
            verification,
        })
    }

    /// Returns the standard ontology and fingerprint profile.
    pub fn reasoning(&self) -> &StandardWebReasoning {
        &self.reasoning
    }

    /// Returns the standard utility-planner profile.
    pub fn planning(&self) -> &StandardWebAttackProfile {
        &self.planning
    }

    /// Returns the scope-bound discovery executor profile.
    pub fn execution(&self) -> &StandardWebDiscoveryExecutorProfile {
        &self.execution
    }

    /// Returns the passive and active verifier profile.
    pub fn verification(&self) -> &StandardWebVerificationProfile {
        &self.verification
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use url::Url;
    use venom_core::{
        ConceptId, ConfidenceScore, EntityId, Evidence, EvidenceKind, EvidenceSource,
        EvidenceValue, HypothesisState, KnowledgePredicate, OntologyConcept, OutcomeStatus,
    };

    use super::*;
    use crate::{
        AdaptationLimits, BenefitScore, DecisionExecutionStage, DecisionLoopConfig,
        DecisionRunnerAdapter, DecisionRunnerTurn, DecisionSession, ExperiencePolicy,
        ExperienceStore, HttpEvidenceExecutor, HttpProbeMethod, PlanningContext, RiskScore,
        StandardWebActionKind, SubjectHttpProbeProvider, STANDARD_WEB_ACTION_COUNT,
        STANDARD_WEB_AXIOM_COUNT, STANDARD_WEB_CONCEPT_COUNT,
        STANDARD_WEB_DISCOVERY_EXECUTOR_COUNT, STANDARD_WEB_RULE_COUNT,
        STANDARD_WEB_VERIFICATION_RULE_COUNT,
    };

    fn decision_loop() -> DecisionLoop {
        DecisionLoop::new(
            DecisionLoopConfig::new(
                PlanningContext::new(
                    BenefitScore::from_percent(90).unwrap(),
                    200,
                    RiskScore::from_percent(100).unwrap(),
                ),
                AdaptationLimits::default(),
                ExperiencePolicy::new(3).unwrap(),
                8,
            )
            .unwrap(),
        )
    }

    fn profile(target: Url) -> StandardWebDecisionProfile {
        StandardWebDecisionProfile::new(HttpEvidencePolicy::for_origin(target).unwrap()).unwrap()
    }

    #[test]
    fn composite_install_is_complete_and_idempotent() {
        let target = Url::parse("https://example.test/app").unwrap();
        let profile = profile(target);
        let knowledge = KnowledgeBase::new();
        let mut decision_loop = decision_loop();
        let mut executors = DecisionExecutorRegistry::new();

        let first = profile
            .install(&knowledge, &mut decision_loop, &mut executors)
            .unwrap();
        let second = profile
            .install(&knowledge, &mut decision_loop, &mut executors)
            .unwrap();

        assert_eq!(
            first.reasoning().concepts_inserted(),
            STANDARD_WEB_CONCEPT_COUNT
        );
        assert_eq!(
            first.reasoning().axioms_inserted(),
            STANDARD_WEB_AXIOM_COUNT
        );
        assert_eq!(first.reasoning().rules_inserted(), STANDARD_WEB_RULE_COUNT);
        assert_eq!(
            first.planning().actions_inserted(),
            STANDARD_WEB_ACTION_COUNT
        );
        assert_eq!(
            first.execution().executors_inserted(),
            STANDARD_WEB_DISCOVERY_EXECUTOR_COUNT
        );
        assert_eq!(
            first.verification().total_rules_inserted(),
            STANDARD_WEB_VERIFICATION_RULE_COUNT
        );
        assert_eq!(second, StandardWebDecisionInstallReport::default());
        assert_eq!(decision_loop.rules().len(), STANDARD_WEB_RULE_COUNT);
        assert_eq!(decision_loop.planner().len(), STANDARD_WEB_ACTION_COUNT);
        assert_eq!(decision_loop.verification().passive().len(), 10);
        assert_eq!(decision_loop.verification().active().len(), 10);
        assert_eq!(executors.len(), STANDARD_WEB_DISCOVERY_EXECUTOR_COUNT);
    }

    #[test]
    fn executor_route_conflict_rolls_back_every_layer() {
        let target = Url::parse("https://example.test/app").unwrap();
        let policy = HttpEvidencePolicy::for_origin(target.clone()).unwrap();
        let profile = StandardWebDecisionProfile::new(policy.clone()).unwrap();
        let knowledge = KnowledgeBase::new();
        let ontology_before = knowledge.stats().ontology;
        let mut decision_loop = decision_loop();
        let mut executors = DecisionExecutorRegistry::new();
        let custom = HttpEvidenceExecutor::with_id(
            "host.custom",
            policy,
            Arc::new(SubjectHttpProbeProvider::new(HttpProbeMethod::Head)),
        )
        .unwrap();
        executors.register(Arc::new(custom)).unwrap();
        executors
            .route_action(
                DecisionExecutionStage::Passive,
                StandardWebActionKind::LaravelRouteDiscovery.action_id(),
                "host.custom",
            )
            .unwrap();

        assert!(matches!(
            profile.install(&knowledge, &mut decision_loop, &mut executors),
            Err(StandardWebDecisionError::Execution(_))
        ));
        assert_eq!(knowledge.stats().ontology, ontology_before);
        assert!(decision_loop.rules().is_empty());
        assert!(decision_loop.planner().is_empty());
        assert!(decision_loop.verification().passive().is_empty());
        assert!(decision_loop.verification().active().is_empty());
        assert_eq!(executors.len(), 1);
        assert!(executors.contains("host.custom"));
    }

    #[test]
    fn ontology_conflict_does_not_commit_preflighted_runtime_layers() {
        let target = Url::parse("https://example.test/app").unwrap();
        let profile = profile(target);
        let knowledge = KnowledgeBase::new();
        knowledge
            .register_concept(
                OntologyConcept::new(ConceptId::new("technology").unwrap(), "Conflicting label")
                    .unwrap(),
            )
            .unwrap();
        let ontology_before = knowledge.stats().ontology;
        let mut decision_loop = decision_loop();
        let mut executors = DecisionExecutorRegistry::new();

        assert!(matches!(
            profile.install(&knowledge, &mut decision_loop, &mut executors),
            Err(StandardWebDecisionError::Reasoning(_))
        ));
        assert_eq!(knowledge.stats().ontology, ontology_before);
        assert!(decision_loop.rules().is_empty());
        assert!(decision_loop.planner().is_empty());
        assert!(decision_loop.verification().passive().is_empty());
        assert!(executors.is_empty());
    }

    async fn serve_basic_challenge() -> Url {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 2048];
            let bytes = stream.read(&mut request).await.unwrap();
            assert!(String::from_utf8_lossy(&request[..bytes]).starts_with("HEAD "));
            stream
                .write_all(
                    b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"admin\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        });
        Url::parse(&format!("http://{address}/admin")).unwrap()
    }

    #[tokio::test]
    async fn composed_stack_runs_evidence_to_confirmed_outcome() {
        let target = serve_basic_challenge().await;
        let subject = EntityId::new(format!("endpoint:{target}")).unwrap();
        let knowledge = KnowledgeBase::new();
        knowledge
            .insert_evidence(Evidence::new(
                subject.clone(),
                EvidenceKind::Authentication,
                KnowledgePredicate::new("http.header", "www-authenticate").unwrap(),
                EvidenceValue::Text("Basic realm=\"initial\"".to_owned()),
                EvidenceSource::new("http.evidence", "initial-challenge").unwrap(),
                ConfidenceScore::MAX,
            ))
            .unwrap();
        let profile = profile(target);
        let mut decision_loop = decision_loop();
        let mut executors = DecisionExecutorRegistry::new();
        profile
            .install(&knowledge, &mut decision_loop, &mut executors)
            .unwrap();
        let mut experience = ExperienceStore::new();
        let mut session = DecisionSession::new(subject);
        let planned = decision_loop
            .plan_next(&knowledge, &experience, &mut session)
            .unwrap();
        assert_eq!(
            planned.plan().steps()[0].action_id(),
            StandardWebActionKind::HttpBasicAuthBoundary.action_id()
        );

        let turn = DecisionRunnerAdapter::new(executors)
            .drive_command(
                &decision_loop,
                planned.command(),
                &knowledge,
                &mut experience,
                &mut session,
            )
            .await
            .unwrap();
        let DecisionRunnerTurn::Outcome { decision, .. } = turn else {
            panic!("planned execution must produce an outcome turn");
        };

        assert_eq!(
            decision.verification().outcome().status(),
            OutcomeStatus::Success
        );
        let hypothesis_id = decision.verification().case().hypothesis_id();
        assert_eq!(
            knowledge.hypothesis(hypothesis_id).unwrap().state(),
            HypothesisState::Confirmed
        );
    }
}
