use super::*;
use crate::{
    ActionCost, AdaptationRule, AttackAction, BenefitScore, EvidenceCalibration, EvidenceSelector,
    ExperienceDisposition, ExperienceRecommendation, Expression, HypothesisConclusion,
    HypothesisSelector, KnowledgeLayer, OutcomeSelector, ReasoningRule, RequiredStrength,
    RiskScore, VerificationRule, VerificationTarget,
};
use venom_core::{
    ConfidenceScore, Evidence, EvidenceId, EvidenceKind, EvidenceSource, EvidenceValue, Hypothesis,
    HypothesisState, HypothesisStrength, KnowledgePredicate, OutcomeStatus, Probability,
    VerificationStage,
};

fn subject() -> EntityId {
    EntityId::new("endpoint:https://example.test").unwrap()
}

fn technology_predicate() -> KnowledgePredicate {
    KnowledgePredicate::new("technology", "framework").unwrap()
}

fn hypothesis_predicate() -> KnowledgePredicate {
    KnowledgePredicate::new("stack", "framework").unwrap()
}

fn status_predicate() -> KnowledgePredicate {
    KnowledgePredicate::new("http.response", "status").unwrap()
}

fn active_predicate() -> KnowledgePredicate {
    KnowledgePredicate::new("verification", "active-control").unwrap()
}

fn laravel() -> EvidenceValue {
    EvidenceValue::Text("Laravel".into())
}

fn knowledge(include_status: bool) -> KnowledgeBase {
    let knowledge = KnowledgeBase::new();
    knowledge
        .insert_evidence(Evidence::new(
            subject(),
            EvidenceKind::Technology,
            technology_predicate(),
            laravel(),
            EvidenceSource::new("discovery", "framework-header").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        ))
        .unwrap();
    if include_status {
        knowledge
            .insert_evidence(Evidence::new(
                subject(),
                EvidenceKind::Http,
                status_predicate(),
                EvidenceValue::Unsigned(403),
                EvidenceSource::new("http.executor", "response-status").unwrap(),
                ConfidenceScore::MAX,
            ))
            .unwrap();
    }
    knowledge
}

fn configured_loop(
    passive_status: Option<OutcomeStatus>,
    experience_limit: u16,
    max_action_cycles: u32,
) -> DecisionLoop {
    configured_loop_with_strategy(passive_status, experience_limit, max_action_cycles, None)
}

fn configured_loop_with_strategy(
    passive_status: Option<OutcomeStatus>,
    experience_limit: u16,
    max_action_cycles: u32,
    payload_strategy: Option<PayloadStrategyRef>,
) -> DecisionLoop {
    configured_loop_with_target(
        passive_status,
        experience_limit,
        max_action_cycles,
        payload_strategy,
        VerificationTarget::Motivation,
    )
}

fn configured_loop_with_target(
    passive_status: Option<OutcomeStatus>,
    experience_limit: u16,
    max_action_cycles: u32,
    payload_strategy: Option<PayloadStrategyRef>,
    verification_target: VerificationTarget,
) -> DecisionLoop {
    let planning = PlanningContext::new(
        BenefitScore::from_percent(90).unwrap(),
        100,
        RiskScore::from_percent(80).unwrap(),
    );
    let config = DecisionLoopConfig::new(
        planning,
        AdaptationLimits::default(),
        ExperiencePolicy::new(experience_limit).unwrap(),
        max_action_cycles,
    )
    .unwrap();
    let mut decision_loop = DecisionLoop::new(config);

    let calibration = EvidenceCalibration::new(
        EvidenceSelector::equals(technology_predicate(), laravel()),
        Probability::from_percent(85).unwrap(),
        Probability::from_percent(15).unwrap(),
        "Laravel fingerprint",
    )
    .unwrap();
    let conclusion = HypothesisConclusion::new(
        hypothesis_predicate(),
        laravel(),
        Probability::from_percent(50).unwrap(),
        HypothesisStrength::Strong,
        HypothesisState::Supported,
        vec![calibration],
    )
    .unwrap();
    decision_loop
        .rules_mut()
        .register(
            ReasoningRule::new(
                "detect.laravel",
                Expression::equals(KnowledgeLayer::Evidence, technology_predicate(), laravel()),
                conclusion,
            )
            .unwrap(),
        )
        .unwrap();
    let action = AttackAction::new(
        "http.probe",
        "plugin.http-probe",
        Expression::equals(
            KnowledgeLayer::Hypothesis,
            hypothesis_predicate(),
            laravel(),
        ),
        HypothesisSelector::new(
            hypothesis_predicate(),
            laravel(),
            Probability::from_percent(50).unwrap(),
            RequiredStrength::Strong,
        ),
        BenefitScore::from_percent(80).unwrap(),
        ActionCost::new(10).unwrap(),
        RiskScore::from_percent(20).unwrap(),
        BTreeSet::new(),
    )
    .unwrap();
    let action = action.with_verification_target(verification_target);
    let action = match payload_strategy {
        Some(strategy) => action.with_payload_strategy(strategy),
        None => action,
    };
    decision_loop.planner_mut().register(action).unwrap();
    if let Some(status) = passive_status {
        decision_loop
            .verification_mut()
            .passive_mut()
            .register(
                VerificationRule::new(
                    "verify.http-403",
                    VerificationStage::Passive,
                    100,
                    Expression::equals(
                        KnowledgeLayer::Evidence,
                        status_predicate(),
                        EvidenceValue::Unsigned(403),
                    ),
                    status,
                    Probability::from_percent(95).unwrap(),
                    "HTTP control response classified the action",
                )
                .unwrap(),
            )
            .unwrap();
    }
    *decision_loop.adaptive_mut() = AdaptivePipeline::with_standard_policies().unwrap();
    decision_loop
}

fn register_adaptive_action(
    decision_loop: &mut DecisionLoop,
    action_id: &str,
    executor: &str,
    cost: u32,
    risk_percent: u8,
    prerequisites: BTreeSet<String>,
) {
    decision_loop
        .planner_mut()
        .register(
            AttackAction::new(
                action_id,
                executor,
                Expression::equals(
                    KnowledgeLayer::Hypothesis,
                    hypothesis_predicate(),
                    laravel(),
                ),
                HypothesisSelector::new(
                    hypothesis_predicate(),
                    laravel(),
                    Probability::from_percent(50).unwrap(),
                    RequiredStrength::Strong,
                ),
                BenefitScore::from_percent(10).unwrap(),
                ActionCost::new(cost).unwrap(),
                RiskScore::from_percent(risk_percent).unwrap(),
                prerequisites,
            )
            .unwrap(),
        )
        .unwrap();
}

#[test]
fn planned_knowledge_only_target_keeps_motivation_as_audit_anchor() {
    let decision_loop =
        configured_loop_with_target(None, 1, 8, None, VerificationTarget::KnowledgeOnly);
    let knowledge = knowledge(false);
    let experience = ExperienceStore::new();
    let mut session = DecisionSession::new(subject());

    let planning = decision_loop
        .plan_next(&knowledge, &experience, &mut session)
        .unwrap();
    let case = execution_case(planning.command());

    assert_eq!(
        planning.plan().steps()[0].confidence_hypothesis_id(),
        case.hypothesis_id()
    );
    assert_eq!(
        planning.plan().steps()[0].verification_target(),
        &ResolvedVerificationTarget::KnowledgeOnly
    );
    assert!(!case.applies_hypothesis_transition());
}

#[test]
fn knowledge_only_success_resets_action_experience_without_transitioning_motivation() {
    let planning_policy = ExperiencePolicy::new(2).unwrap();
    let suppression_policy = ExperiencePolicy::new(1).unwrap();
    let decision_loop = configured_loop_with_target(
        Some(OutcomeStatus::Success),
        planning_policy.consecutive_suppressible_failure_limit(),
        8,
        None,
        VerificationTarget::KnowledgeOnly,
    );
    let knowledge = knowledge(true);
    let mut experience = ExperienceStore::new();
    experience
        .observe(
            Outcome::verified(
                "case:prior-negative",
                subject(),
                "http.probe",
                "hypothesis:prior-http-probe",
                "verify.prior-negative",
                VerificationStage::Active,
                OutcomeStatus::ConfirmedNegative,
                Probability::from_percent(99).unwrap(),
                "prior active control confirmed a negative action result",
                BTreeSet::from([EvidenceId::parse("evidence:prior-negative").unwrap()]),
            )
            .unwrap(),
        )
        .unwrap();
    let before = experience.assess(&subject(), "http.probe", suppression_policy);
    assert_eq!(before.consecutive_suppressible_failures(), 1);
    assert!(before.is_suppressed());
    assert_eq!(
        before.last_disposition(),
        Some(ExperienceDisposition::ConfirmedNegative)
    );
    let mut session = DecisionSession::new(subject());

    let planning = decision_loop
        .plan_next(&knowledge, &experience, &mut session)
        .unwrap();
    let case = execution_case(planning.command());
    let motivation_id = case.hypothesis_id().to_owned();
    assert!(!case.applies_hypothesis_transition());
    assert_eq!(
        knowledge.hypothesis(&motivation_id).unwrap().state(),
        HypothesisState::Supported
    );

    let report = decision_loop
        .submit_passive(&knowledge, &mut experience, &mut session)
        .unwrap();

    assert_eq!(
        report.verification().outcome().status(),
        OutcomeStatus::Success
    );
    assert!(!report.verification().case().applies_hypothesis_transition());
    assert_eq!(report.experience_write(), ExperienceWrite::Inserted);
    assert_eq!(report.hypothesis_write(), None);
    assert_eq!(
        knowledge.hypothesis(&motivation_id).unwrap().state(),
        HypothesisState::Supported
    );
    let after = experience.assess(&subject(), "http.probe", suppression_policy);
    assert_eq!(after.completed_attempts(), 2);
    assert_eq!(after.last_status(), Some(OutcomeStatus::Success));
    assert_eq!(
        after.last_disposition(),
        Some(ExperienceDisposition::ConfirmedPositive)
    );
    assert_eq!(after.consecutive_suppressible_failures(), 0);
    assert_eq!(after.recommendation(), ExperienceRecommendation::Continue);
    assert!(!after.is_suppressed());
}

#[test]
fn replayed_case_cannot_broaden_current_knowledge_only_authority() {
    let decision_loop = configured_loop_with_target(
        Some(OutcomeStatus::Success),
        2,
        8,
        None,
        VerificationTarget::KnowledgeOnly,
    );
    let knowledge = knowledge(true);
    let experience = ExperienceStore::new();
    let mut issued = DecisionSession::new(subject());
    decision_loop
        .plan_next(&knowledge, &experience, &mut issued)
        .unwrap();
    let genuine_case = issued.state().case().unwrap();
    assert!(!genuine_case.applies_hypothesis_transition());
    let hypothesis_id = genuine_case.hypothesis_id().to_owned();

    let mut wire = serde_json::to_value(&issued).unwrap();
    let case = wire["state"]["case"].as_object_mut().unwrap();
    case.remove("applies_hypothesis_transition");
    case.remove("payload_claim_policy_guard");
    let mut replayed: DecisionSession = serde_json::from_value(wire).unwrap();
    assert!(replayed
        .state()
        .case()
        .unwrap()
        .applies_hypothesis_transition());
    let before_session = replayed.clone();
    let before_hypothesis = knowledge.hypothesis(&hypothesis_id).unwrap();
    let mut replay_experience = experience.clone();

    let error = decision_loop
        .submit_passive_with_suppressed_actions(
            &knowledge,
            &mut replay_experience,
            &mut replayed,
            &BTreeSet::new(),
        )
        .unwrap_err();

    assert!(matches!(
        error,
        DecisionLoopError::DecisionCaseAuthorityExceeded { action_id }
            if action_id == "http.probe"
    ));
    assert_eq!(replayed, before_session);
    assert_eq!(replay_experience, experience);
    assert_eq!(
        knowledge.hypothesis(&hypothesis_id).unwrap(),
        before_hypothesis
    );
}

#[test]
fn replayed_unregistered_case_is_rejected_atomically() {
    let mut decision_loop = configured_loop(Some(OutcomeStatus::Success), 2, 8);
    let knowledge = knowledge(true);
    let mut experience = ExperienceStore::new();
    let mut session = DecisionSession::new(subject());
    decision_loop
        .plan_next(&knowledge, &experience, &mut session)
        .unwrap();
    *decision_loop.planner_mut() = AttackPlanner::new();
    let before_session = session.clone();
    let before_experience = experience.clone();

    let error = decision_loop
        .submit_passive_with_suppressed_actions(
            &knowledge,
            &mut experience,
            &mut session,
            &BTreeSet::new(),
        )
        .unwrap_err();

    assert!(matches!(
        error,
        DecisionLoopError::UnregisteredDecisionAction { action_id }
            if action_id == "http.probe"
    ));
    assert_eq!(session, before_session);
    assert_eq!(experience, before_experience);
}

#[test]
fn bootstrap_execution_is_the_only_unregistered_authority_exemption() {
    let decision_loop = configured_loop(Some(OutcomeStatus::Success), 2, 8);
    let knowledge = knowledge(true);
    let case = VerificationCase::new(
        "case:bootstrap",
        subject(),
        "bootstrap.http",
        "hypothesis:bootstrap",
    )
    .unwrap();
    let bootstrap = DecisionLoopCommand::ExecuteAction {
        case: case.clone(),
        executor: Some("bootstrap.http".to_owned()),
        origin: DecisionActionOrigin::Bootstrap,
        delay_ms: None,
    };

    decision_loop
        .validate_execution_command_authority(&knowledge, &bootstrap)
        .unwrap();

    let planned = DecisionLoopCommand::ExecuteAction {
        case,
        executor: Some("bootstrap.http".to_owned()),
        origin: DecisionActionOrigin::Planned,
        delay_ms: None,
    };
    assert!(matches!(
        decision_loop.validate_execution_command_authority(&knowledge, &planned),
        Err(DecisionLoopError::UnregisteredDecisionAction { action_id })
            if action_id == "bootstrap.http"
    ));
}

#[test]
fn distinct_target_confirms_only_the_separately_resolved_hypothesis() {
    let distinct_predicate = active_predicate();
    let distinct_value = EvidenceValue::Boolean(true);
    let decision_loop = configured_loop_with_target(
        Some(OutcomeStatus::Success),
        1,
        8,
        None,
        VerificationTarget::Distinct(HypothesisSelector::new(
            distinct_predicate.clone(),
            distinct_value.clone(),
            Probability::from_percent(60).unwrap(),
            RequiredStrength::Strong,
        )),
    );
    let knowledge = knowledge(true);
    let mut distinct = Hypothesis::with_id(
        "hypothesis:distinct",
        subject(),
        distinct_predicate,
        distinct_value,
        Probability::from_percent(80).unwrap(),
    )
    .unwrap();
    distinct.set_strength(HypothesisStrength::Strong);
    distinct.set_state(HypothesisState::Supported);
    knowledge.upsert_hypothesis(distinct).unwrap();
    let mut experience = ExperienceStore::new();
    let mut session = DecisionSession::new(subject());

    let planning = decision_loop
        .plan_next(&knowledge, &experience, &mut session)
        .unwrap();
    let motivation_id = planning.plan().steps()[0]
        .confidence_hypothesis_id()
        .to_owned();
    let case = execution_case(planning.command());
    assert_eq!(case.hypothesis_id(), "hypothesis:distinct");
    assert!(case.applies_hypothesis_transition());

    let report = decision_loop
        .submit_passive(&knowledge, &mut experience, &mut session)
        .unwrap();

    assert_eq!(
        report.verification().outcome().status(),
        OutcomeStatus::Success
    );
    assert_eq!(
        knowledge.hypothesis("hypothesis:distinct").unwrap().state(),
        HypothesisState::Confirmed
    );
    assert_eq!(
        knowledge.hypothesis(&motivation_id).unwrap().state(),
        HypothesisState::Supported
    );
}

#[test]
fn adaptive_schedule_resolves_the_registered_actions_own_target_policy() {
    let mut decision_loop = configured_loop(None, 1, 8);
    decision_loop
        .planner_mut()
        .register(
            AttackAction::new(
                "knowledge.followup",
                "plugin.knowledge-followup",
                Expression::equals(
                    KnowledgeLayer::Hypothesis,
                    hypothesis_predicate(),
                    laravel(),
                ),
                HypothesisSelector::new(
                    active_predicate(),
                    EvidenceValue::Boolean(true),
                    Probability::from_percent(50).unwrap(),
                    RequiredStrength::Strong,
                ),
                BenefitScore::from_percent(10).unwrap(),
                ActionCost::new(10).unwrap(),
                RiskScore::from_percent(20).unwrap(),
                BTreeSet::new(),
            )
            .unwrap()
            .with_verification_target(VerificationTarget::KnowledgeOnly),
        )
        .unwrap();
    let knowledge = knowledge(false);
    let mut scheduled_motivation = Hypothesis::with_id(
        "hypothesis:scheduled-motivation",
        subject(),
        active_predicate(),
        EvidenceValue::Boolean(true),
        Probability::from_percent(80).unwrap(),
    )
    .unwrap();
    scheduled_motivation.set_strength(HypothesisStrength::Strong);
    scheduled_motivation.set_state(HypothesisState::Supported);
    knowledge.upsert_hypothesis(scheduled_motivation).unwrap();
    let experience = ExperienceStore::new();
    let mut planned_session = DecisionSession::new(subject());
    let planning = decision_loop
        .plan_next(&knowledge, &experience, &mut planned_session)
        .unwrap();
    let source_case = execution_case(planning.command());
    assert!(source_case.applies_hypothesis_transition());
    let outcome = Outcome::unknown(
        source_case.id(),
        subject(),
        source_case.action_id(),
        source_case.hypothesis_id(),
        VerificationStage::Passive,
        "fixture schedules a separate action",
    )
    .unwrap();
    let snapshot = knowledge.snapshot_for_subject(&subject());
    let mut scheduled_session = DecisionSession::new(subject());

    let command = transition_from_adaptive(
        &mut scheduled_session,
        8,
        decision_loop.planner(),
        decision_loop.config().planning(),
        &snapshot,
        &source_case,
        &outcome,
        &PipelineDirective::ScheduleAction {
            action_id: "knowledge.followup".to_owned(),
        },
        &ActionSuppressionContext::default(),
    )
    .unwrap();
    let scheduled_case = execution_case(&command);

    assert_eq!(scheduled_case.action_id(), "knowledge.followup");
    assert_eq!(
        scheduled_case.hypothesis_id(),
        "hypothesis:scheduled-motivation"
    );
    assert!(!scheduled_case.applies_hypothesis_transition());
}

#[test]
fn adaptive_schedule_uses_the_registered_actions_own_motivation_hypothesis() {
    let mut decision_loop = configured_loop(None, 1, 8);
    decision_loop
        .planner_mut()
        .register(
            AttackAction::new(
                "motivated.followup",
                "plugin.motivated-followup",
                Expression::equals(
                    KnowledgeLayer::Hypothesis,
                    hypothesis_predicate(),
                    laravel(),
                ),
                HypothesisSelector::new(
                    active_predicate(),
                    EvidenceValue::Boolean(true),
                    Probability::from_percent(50).unwrap(),
                    RequiredStrength::Strong,
                ),
                BenefitScore::from_percent(10).unwrap(),
                ActionCost::new(10).unwrap(),
                RiskScore::from_percent(20).unwrap(),
                BTreeSet::new(),
            )
            .unwrap(),
        )
        .unwrap();
    let knowledge = knowledge(false);
    let mut scheduled_motivation = Hypothesis::with_id(
        "hypothesis:scheduled-motivation",
        subject(),
        active_predicate(),
        EvidenceValue::Boolean(true),
        Probability::from_percent(80).unwrap(),
    )
    .unwrap();
    scheduled_motivation.set_strength(HypothesisStrength::Strong);
    scheduled_motivation.set_state(HypothesisState::Supported);
    knowledge.upsert_hypothesis(scheduled_motivation).unwrap();
    let experience = ExperienceStore::new();
    let mut planned_session = DecisionSession::new(subject());
    let planning = decision_loop
        .plan_next(&knowledge, &experience, &mut planned_session)
        .unwrap();
    let source_case = execution_case(planning.command());
    let outcome = Outcome::unknown(
        source_case.id(),
        subject(),
        source_case.action_id(),
        source_case.hypothesis_id(),
        VerificationStage::Passive,
        "fixture schedules a separately motivated action",
    )
    .unwrap();
    let snapshot = knowledge.snapshot_for_subject(&subject());
    let mut scheduled_session = DecisionSession::new(subject());

    let command = transition_from_adaptive(
        &mut scheduled_session,
        8,
        decision_loop.planner(),
        decision_loop.config().planning(),
        &snapshot,
        &source_case,
        &outcome,
        &PipelineDirective::ScheduleAction {
            action_id: "motivated.followup".to_owned(),
        },
        &ActionSuppressionContext::default(),
    )
    .unwrap();
    let scheduled_case = execution_case(&command);

    assert_eq!(
        scheduled_case.hypothesis_id(),
        "hypothesis:scheduled-motivation"
    );
    assert!(scheduled_case.applies_hypothesis_transition());
}

#[test]
fn adaptive_schedule_missing_motivation_fails_without_mutating_session() {
    let mut decision_loop = configured_loop(None, 1, 8);
    decision_loop
        .planner_mut()
        .register(
            AttackAction::new(
                "missing-motivation.followup",
                "plugin.missing-motivation-followup",
                Expression::equals(
                    KnowledgeLayer::Hypothesis,
                    hypothesis_predicate(),
                    laravel(),
                ),
                HypothesisSelector::new(
                    active_predicate(),
                    EvidenceValue::Boolean(true),
                    Probability::from_percent(50).unwrap(),
                    RequiredStrength::Strong,
                ),
                BenefitScore::from_percent(10).unwrap(),
                ActionCost::new(10).unwrap(),
                RiskScore::from_percent(20).unwrap(),
                BTreeSet::new(),
            )
            .unwrap(),
        )
        .unwrap();
    let knowledge = knowledge(false);
    let experience = ExperienceStore::new();
    let mut planned_session = DecisionSession::new(subject());
    let planning = decision_loop
        .plan_next(&knowledge, &experience, &mut planned_session)
        .unwrap();
    let source_case = execution_case(planning.command());
    let outcome = Outcome::unknown(
        source_case.id(),
        subject(),
        source_case.action_id(),
        source_case.hypothesis_id(),
        VerificationStage::Passive,
        "fixture schedules an action without its motivation",
    )
    .unwrap();
    let snapshot = knowledge.snapshot_for_subject(&subject());
    let mut scheduled_session = DecisionSession::new(subject());
    let before = scheduled_session.transition_summary();

    let error = transition_from_adaptive(
        &mut scheduled_session,
        8,
        decision_loop.planner(),
        decision_loop.config().planning(),
        &snapshot,
        &source_case,
        &outcome,
        &PipelineDirective::ScheduleAction {
            action_id: "missing-motivation.followup".to_owned(),
        },
        &ActionSuppressionContext::default(),
    )
    .unwrap_err();

    assert!(matches!(
        error,
        DecisionLoopError::NoEligibleScheduledMotivationHypothesis { action_id }
            if action_id == "missing-motivation.followup"
    ));
    assert_eq!(scheduled_session.transition_summary(), before);
}

#[test]
fn adaptive_schedule_invalid_distinct_targets_fail_without_mutating_session() {
    let mut decision_loop = configured_loop(None, 1, 8);
    decision_loop
        .planner_mut()
        .register(
            AttackAction::new(
                "distinct.followup",
                "plugin.distinct-followup",
                Expression::equals(
                    KnowledgeLayer::Hypothesis,
                    hypothesis_predicate(),
                    laravel(),
                ),
                HypothesisSelector::new(
                    hypothesis_predicate(),
                    laravel(),
                    Probability::from_percent(50).unwrap(),
                    RequiredStrength::Strong,
                ),
                BenefitScore::from_percent(10).unwrap(),
                ActionCost::new(10).unwrap(),
                RiskScore::from_percent(20).unwrap(),
                BTreeSet::new(),
            )
            .unwrap()
            .with_verification_target(VerificationTarget::Distinct(HypothesisSelector::new(
                active_predicate(),
                EvidenceValue::Boolean(true),
                Probability::from_percent(50).unwrap(),
                RequiredStrength::Strong,
            ))),
        )
        .unwrap();
    decision_loop
        .planner_mut()
        .register(
            AttackAction::new(
                "same-target.followup",
                "plugin.same-target-followup",
                Expression::equals(
                    KnowledgeLayer::Hypothesis,
                    hypothesis_predicate(),
                    laravel(),
                ),
                HypothesisSelector::new(
                    hypothesis_predicate(),
                    laravel(),
                    Probability::from_percent(50).unwrap(),
                    RequiredStrength::Strong,
                ),
                BenefitScore::from_percent(10).unwrap(),
                ActionCost::new(10).unwrap(),
                RiskScore::from_percent(20).unwrap(),
                BTreeSet::new(),
            )
            .unwrap()
            .with_verification_target(VerificationTarget::Distinct(HypothesisSelector::new(
                hypothesis_predicate(),
                laravel(),
                Probability::from_percent(50).unwrap(),
                RequiredStrength::Strong,
            ))),
        )
        .unwrap();
    let knowledge = knowledge(false);
    let experience = ExperienceStore::new();
    let mut planned_session = DecisionSession::new(subject());
    let planning = decision_loop
        .plan_next(&knowledge, &experience, &mut planned_session)
        .unwrap();
    let source_case = execution_case(planning.command());
    let outcome = Outcome::unknown(
        source_case.id(),
        subject(),
        source_case.action_id(),
        source_case.hypothesis_id(),
        VerificationStage::Passive,
        "fixture schedules an action without its distinct target",
    )
    .unwrap();
    let snapshot = knowledge.snapshot_for_subject(&subject());
    let mut scheduled_session = DecisionSession::new(subject());
    let before = scheduled_session.transition_summary();

    let error = transition_from_adaptive(
        &mut scheduled_session,
        8,
        decision_loop.planner(),
        decision_loop.config().planning(),
        &snapshot,
        &source_case,
        &outcome,
        &PipelineDirective::ScheduleAction {
            action_id: "distinct.followup".to_owned(),
        },
        &ActionSuppressionContext::default(),
    )
    .unwrap_err();

    assert!(matches!(
        error,
        DecisionLoopError::NoEligibleScheduledVerificationTarget { action_id }
            if action_id == "distinct.followup"
    ));
    assert_eq!(scheduled_session.transition_summary(), before);

    let mut same_target_session = DecisionSession::new(subject());
    let same_target_before = same_target_session.transition_summary();
    let error = transition_from_adaptive(
        &mut same_target_session,
        8,
        decision_loop.planner(),
        decision_loop.config().planning(),
        &snapshot,
        &source_case,
        &outcome,
        &PipelineDirective::ScheduleAction {
            action_id: "same-target.followup".to_owned(),
        },
        &ActionSuppressionContext::default(),
    )
    .unwrap_err();

    assert!(matches!(
        error,
        DecisionLoopError::NoEligibleScheduledVerificationTarget { action_id }
            if action_id == "same-target.followup"
    ));
    assert_eq!(same_target_session.transition_summary(), same_target_before);
}

#[test]
fn strategy_and_transition_policy_survive_active_and_retry_cases() {
    let strategy = PayloadStrategyRef::new("visibility.control-pair", 1).unwrap();
    let decision_loop = configured_loop_with_target(
        None,
        1,
        8,
        Some(strategy.clone()),
        VerificationTarget::KnowledgeOnly,
    );
    let knowledge = knowledge(false);
    let experience = ExperienceStore::new();
    let mut planned_session = DecisionSession::new(subject());

    let planning = decision_loop
        .plan_next(&knowledge, &experience, &mut planned_session)
        .unwrap();
    let planned_case = execution_case(planning.command());
    let snapshot = knowledge.snapshot_for_subject(&subject());
    assert_eq!(planned_case.payload_strategy(), Some(&strategy));
    assert!(!planned_case.applies_hypothesis_transition());

    let outcome = Outcome::unknown(
        planned_case.id(),
        subject(),
        planned_case.action_id(),
        planned_case.hypothesis_id(),
        VerificationStage::Passive,
        "fixture remains unresolved",
    )
    .unwrap();
    let mut active_session = DecisionSession::new(subject());
    let active = transition_from_adaptive(
        &mut active_session,
        8,
        decision_loop.planner(),
        decision_loop.config().planning(),
        &snapshot,
        &planned_case,
        &outcome,
        &PipelineDirective::AwaitActiveVerification,
        &ActionSuppressionContext::default(),
    )
    .unwrap();
    let active_case = match active {
        DecisionLoopCommand::CollectActiveEvidence { case } => case,
        other => panic!("expected active evidence command, got {other:?}"),
    };
    assert_eq!(active_case.payload_strategy(), Some(&strategy));
    assert!(!active_case.applies_hypothesis_transition());

    let mut retry_session = DecisionSession::new(subject());
    let retry = transition_from_adaptive(
        &mut retry_session,
        8,
        decision_loop.planner(),
        decision_loop.config().planning(),
        &snapshot,
        &planned_case,
        &outcome,
        &PipelineDirective::Throttle {
            delay_ms: 5,
            retry_current_action: true,
        },
        &ActionSuppressionContext::default(),
    )
    .unwrap();
    let retry_case = execution_case(&retry);
    assert_eq!(retry_case.payload_strategy(), Some(&strategy));
    assert!(!retry_case.applies_hypothesis_transition());
}

#[test]
fn outstanding_case_pins_strategy_across_planner_reconfiguration() {
    let revision_one = PayloadStrategyRef::new("visibility.control-pair", 1).unwrap();
    let revision_two = PayloadStrategyRef::new("visibility.control-pair", 2).unwrap();
    let mut decision_loop = configured_loop_with_strategy(None, 1, 8, Some(revision_one.clone()));
    let replacement = configured_loop_with_strategy(None, 1, 8, Some(revision_two));
    let knowledge = knowledge(false);
    let mut experience = ExperienceStore::new();
    let mut session = DecisionSession::new(subject());

    let planning = decision_loop
        .plan_next(&knowledge, &experience, &mut session)
        .unwrap();
    assert_eq!(
        execution_case(planning.command()).payload_strategy(),
        Some(&revision_one)
    );

    *decision_loop.planner_mut() = replacement.planner().clone();
    let passive = decision_loop
        .submit_passive_with_suppressed_actions(
            &knowledge,
            &mut experience,
            &mut session,
            &BTreeSet::new(),
        )
        .unwrap();
    let active_case = match passive.command() {
        DecisionLoopCommand::CollectActiveEvidence { case } => case,
        other => panic!("expected active evidence command, got {other:?}"),
    };
    assert_eq!(active_case.payload_strategy(), Some(&revision_one));
}

fn execution_case(command: &DecisionLoopCommand) -> VerificationCase {
    match command {
        DecisionLoopCommand::ExecuteAction { case, .. } => case.clone(),
        other => panic!("expected execute action, got {other:?}"),
    }
}

fn register_action_with_missing_prerequisite(decision_loop: &mut DecisionLoop) {
    decision_loop
        .planner_mut()
        .register(
            AttackAction::new(
                "invalid.action",
                "plugin.invalid",
                Expression::exists(KnowledgeLayer::Evidence, technology_predicate()),
                HypothesisSelector::new(
                    hypothesis_predicate(),
                    laravel(),
                    Probability::from_percent(50).unwrap(),
                    RequiredStrength::Strong,
                ),
                BenefitScore::from_percent(50).unwrap(),
                ActionCost::new(1).unwrap(),
                RiskScore::from_percent(10).unwrap(),
                BTreeSet::from(["missing.action".to_owned()]),
            )
            .unwrap(),
        )
        .unwrap();
}

#[test]
fn planning_error_after_reasoning_preserves_session_and_returns_commit_receipt() {
    let mut decision_loop = configured_loop(None, 1, 8);
    register_action_with_missing_prerequisite(&mut decision_loop);
    let knowledge = knowledge(false);
    let experience = ExperienceStore::new();
    let mut session = DecisionSession::new(subject());
    let initial_session = session.clone();

    let error = decision_loop
        .plan_next(&knowledge, &experience, &mut session)
        .unwrap_err();

    assert_eq!(session, initial_session);
    let receipt = error.committed_reasoning().unwrap();
    assert_eq!(receipt.subject(), &subject());
    let committed_snapshot = knowledge.snapshot_for_subject(&subject());
    assert_eq!(
        receipt.planner_subject_revision(),
        committed_snapshot.subject_revision()
    );
    assert_eq!(
        receipt.planner_ontology_revision(),
        committed_snapshot.ontology_revision()
    );
    assert_eq!(receipt.rule_applications().len(), 1);
    assert_eq!(
        receipt.rule_applications()[0].write(),
        Some(KnowledgeWrite::Inserted)
    );
    assert!(matches!(
        &error,
        DecisionLoopError::PlanningAfterReasoningCommit { source, .. }
            if matches!(
                source.as_ref(),
                DecisionLoopError::Planner(PlannerError::UnknownPrerequisite { .. })
            )
    ));
    assert_eq!(knowledge.stats().hypotheses, 1);
    assert_eq!(
        error
            .into_committed_reasoning()
            .unwrap()
            .rule_applications()
            .len(),
        1
    );
}

#[test]
fn stale_planner_snapshot_cannot_commit_a_session_transition() {
    let decision_loop = configured_loop(None, 1, 8);
    let knowledge = knowledge(false);
    let experience = ExperienceStore::new();
    let mut session = DecisionSession::new(subject());
    let initial_session = session.clone();

    let error = decision_loop
        .plan_next_with_suppressed_actions_before_commit(
            &knowledge,
            &experience,
            &mut session,
            &BTreeSet::new(),
            |_| {
                knowledge
                    .insert_evidence(Evidence::new(
                        subject(),
                        EvidenceKind::Http,
                        active_predicate(),
                        EvidenceValue::Boolean(true),
                        EvidenceSource::new("concurrent.discovery", "late-observation").unwrap(),
                        ConfidenceScore::MAX,
                    ))
                    .unwrap();
            },
        )
        .unwrap_err();

    assert_eq!(session, initial_session);
    assert!(matches!(
        &error,
        DecisionLoopError::PlanningAfterReasoningCommit { source, .. }
            if matches!(
                source.as_ref(),
                DecisionLoopError::StalePlanningSnapshot {
                    source: KnowledgeBaseError::StaleSnapshot { .. }
                }
            )
    ));
    let receipt = error.committed_reasoning().unwrap();
    let current = knowledge.snapshot_for_subject(&subject());
    assert!(current.subject_revision() > receipt.planner_subject_revision());
    assert_eq!(knowledge.stats().hypotheses, 1);
}

#[test]
fn action_limit_planning_error_does_not_partially_halt_session() {
    let mut decision_loop = configured_loop(None, 1, 1);
    register_action_with_missing_prerequisite(&mut decision_loop);
    let knowledge = knowledge(false);
    let experience = ExperienceStore::new();
    let mut session = DecisionSession::new(subject());
    session.action_cycles = 1;
    let initial_session = session.clone();

    let error = decision_loop
        .plan_next(&knowledge, &experience, &mut session)
        .unwrap_err();

    assert!(matches!(
        error,
        DecisionLoopError::Planner(PlannerError::UnknownPrerequisite { .. })
    ));
    assert_eq!(session, initial_session);
    assert_eq!(knowledge.stats().hypotheses, 0);
}

#[test]
fn blocked_action_uses_bounded_adaptation_without_learning_a_negative() {
    let mut decision_loop = configured_loop(Some(OutcomeStatus::Blocked), 1, 8);
    register_adaptive_action(
        &mut decision_loop,
        "http.403-bypass",
        "plugin.http-403-bypass",
        10,
        20,
        BTreeSet::new(),
    );
    let knowledge = knowledge(true);
    let mut experience = ExperienceStore::new();
    let mut session = DecisionSession::new(subject());

    let planning = decision_loop
        .plan_next(&knowledge, &experience, &mut session)
        .unwrap();
    assert_eq!(planning.rule_applications().len(), 1);
    assert_eq!(planning.plan().steps().len(), 2);
    assert_eq!(execution_case(planning.command()).action_id(), "http.probe");
    assert!(planning.suppressed_actions().is_empty());
    assert!(matches!(
        planning.session_transition().before().state(),
        DecisionLoopState::Ready
    ));
    assert!(matches!(
        planning.session_transition().after().state(),
        DecisionLoopState::AwaitingPassive { .. }
    ));
    assert!(serde_json::to_value(&planning)
        .unwrap()
        .get("session_transition")
        .is_none());
    assert!(matches!(
        planning.command(),
        DecisionLoopCommand::ExecuteAction {
            origin: DecisionActionOrigin::Planned,
            executor: Some(executor),
            ..
        } if executor == "plugin.http-probe"
    ));

    let first = decision_loop
        .submit_passive_with_suppressed_actions(
            &knowledge,
            &mut experience,
            &mut session,
            &BTreeSet::new(),
        )
        .unwrap();
    assert_eq!(first.adaptive().selected_rule_id(), Some("http.403.bypass"));
    assert!(matches!(
        first.command(),
        DecisionLoopCommand::ExecuteAction {
            case,
            origin: DecisionActionOrigin::Adaptive,
            executor: Some(executor),
            delay_ms: None,
        } if case.action_id() == "http.403-bypass"
            && executor == "plugin.http-403-bypass"
    ));
    assert_eq!(session.action_cycles(), 2);

    let second = decision_loop
        .submit_passive_with_suppressed_actions(
            &knowledge,
            &mut experience,
            &mut session,
            &BTreeSet::new(),
        )
        .unwrap();
    assert_eq!(
        second.adaptive().selected_rule_id(),
        Some("http.403.bypass")
    );
    assert!(matches!(
        second.command(),
        DecisionLoopCommand::ExecuteAction {
            case,
            origin: DecisionActionOrigin::Adaptive,
            ..
        } if case.action_id() == "http.403-bypass"
    ));

    let third = decision_loop
        .submit_passive_with_suppressed_actions(
            &knowledge,
            &mut experience,
            &mut session,
            &BTreeSet::new(),
        )
        .unwrap();
    assert!(third.adaptive().selected_rule_id().is_none());
    assert!(matches!(
        third.command(),
        DecisionLoopCommand::AwaitHumanReview { case }
            if case.action_id() == "http.403-bypass"
    ));
    assert!(matches!(
        session.state(),
        DecisionLoopState::Halted {
            reason: DecisionStopReason::HumanReview
        }
    ));
    assert_eq!(experience.len(), 3);
    assert!(experience
        .suppressed_actions(&subject(), ExperiencePolicy::new(1).unwrap())
        .is_empty());
    assert_eq!(
        experience
            .assess(
                &subject(),
                "http.403-bypass",
                ExperiencePolicy::new(1).unwrap(),
            )
            .consecutive_suppressible_failures(),
        0
    );
}

#[test]
fn adaptive_execution_without_explicit_host_context_fails_atomically() {
    let decision_loop = configured_loop(Some(OutcomeStatus::Blocked), 1, 8);
    let knowledge = knowledge(true);
    let mut experience = ExperienceStore::new();
    let mut session = DecisionSession::new(subject());
    decision_loop
        .plan_next(&knowledge, &experience, &mut session)
        .unwrap();
    let initial_session = session.clone();
    let initial_experience = experience.clone();
    let hypothesis_id = session.state().case().unwrap().hypothesis_id().to_owned();
    let initial_hypothesis = knowledge.hypothesis(&hypothesis_id).unwrap();

    let error = decision_loop
        .submit_passive(&knowledge, &mut experience, &mut session)
        .unwrap_err();

    assert!(matches!(
        error,
        DecisionLoopError::AdaptiveExecutionRequiresHostPolicyContext { action_id }
            if action_id == "http.403-bypass"
    ));
    assert_eq!(session, initial_session);
    assert_eq!(experience, initial_experience);
    assert_eq!(
        knowledge.hypothesis(&hypothesis_id).unwrap(),
        initial_hypothesis
    );
}

#[test]
fn active_and_replan_continuations_without_host_context_fail_atomically() {
    for passive_status in [None, Some(OutcomeStatus::FalsePositive)] {
        let decision_loop = configured_loop(passive_status, 1, 8);
        let knowledge = knowledge(true);
        let mut experience = ExperienceStore::new();
        let mut session = DecisionSession::new(subject());
        decision_loop
            .plan_next(&knowledge, &experience, &mut session)
            .unwrap();
        let initial_session = session.clone();
        let initial_experience = experience.clone();
        let hypothesis_id = session.state().case().unwrap().hypothesis_id().to_owned();
        let initial_hypothesis = knowledge.hypothesis(&hypothesis_id).unwrap();

        let error = decision_loop
            .submit_passive(&knowledge, &mut experience, &mut session)
            .unwrap_err();

        assert!(matches!(
            error,
            DecisionLoopError::AdaptiveExecutionRequiresHostPolicyContext { action_id }
                if action_id == "http.probe"
        ));
        assert_eq!(session, initial_session);
        assert_eq!(experience, initial_experience);
        assert_eq!(
            knowledge.hypothesis(&hypothesis_id).unwrap(),
            initial_hypothesis
        );
    }
}

#[test]
fn unregistered_adaptive_action_is_rejected_atomically() {
    let decision_loop = configured_loop(Some(OutcomeStatus::Blocked), 1, 8);
    let knowledge = knowledge(true);
    let mut experience = ExperienceStore::new();
    let mut session = DecisionSession::new(subject());
    decision_loop
        .plan_next(&knowledge, &experience, &mut session)
        .unwrap();
    let initial_session = session.clone();
    let initial_experience = experience.clone();
    let hypothesis_id = session.state().case().unwrap().hypothesis_id().to_owned();
    let initial_hypothesis = knowledge.hypothesis(&hypothesis_id).unwrap();

    let error = decision_loop
        .submit_passive_with_suppressed_actions(
            &knowledge,
            &mut experience,
            &mut session,
            &BTreeSet::new(),
        )
        .unwrap_err();

    assert!(matches!(
        error,
        DecisionLoopError::UnregisteredDecisionAction { action_id }
            if action_id == "http.403-bypass"
    ));
    assert_eq!(session, initial_session);
    assert_eq!(experience, initial_experience);
    assert_eq!(
        knowledge.hypothesis(&hypothesis_id).unwrap(),
        initial_hypothesis
    );
}

#[test]
fn host_suppression_survives_planning_and_adaptive_selection() {
    let mut decision_loop = configured_loop(Some(OutcomeStatus::Blocked), 1, 8);
    register_adaptive_action(
        &mut decision_loop,
        "http.403-bypass",
        "plugin.http-403-bypass",
        10,
        20,
        BTreeSet::new(),
    );
    let knowledge = knowledge(true);
    let mut experience = ExperienceStore::new();
    let mut session = DecisionSession::new(subject());
    let host_suppressions = BTreeSet::from(["http.403-bypass".to_owned()]);

    let planning = decision_loop
        .plan_next_with_suppressed_actions(
            &knowledge,
            &experience,
            &mut session,
            &host_suppressions,
        )
        .unwrap();
    assert_eq!(execution_case(planning.command()).action_id(), "http.probe");
    assert!(planning.suppressed_actions().contains("http.403-bypass"));

    let outcome = decision_loop
        .submit_passive_with_suppressed_actions(
            &knowledge,
            &mut experience,
            &mut session,
            &host_suppressions,
        )
        .unwrap();

    assert!(outcome.adaptive().selected_rule_id().is_none());
    assert!(matches!(
        outcome.command(),
        DecisionLoopCommand::AwaitHumanReview { case }
            if case.action_id() == "http.probe"
    ));
    assert_eq!(session.action_cycles(), 1);
    assert!(matches!(
        session.state(),
        DecisionLoopState::Halted {
            reason: DecisionStopReason::HumanReview
        }
    ));
}

#[test]
fn defense_suppression_is_distinct_from_the_existing_policy_audit() {
    let decision_loop = configured_loop(None, 1, 8);
    let knowledge = knowledge(false);
    let experience = ExperienceStore::new();
    let mut session = DecisionSession::new(subject());
    let suppressions =
        ActionSuppressionContext::new(BTreeSet::new(), BTreeSet::from(["http.probe".to_owned()]));

    let planning = decision_loop
        .plan_next_with_action_suppressions(&knowledge, &experience, &mut session, &suppressions)
        .unwrap();

    assert!(planning.suppressed_actions().is_empty());
    assert!(planning.plan().steps().is_empty());
    assert!(planning.plan().excluded().iter().any(|entry| {
        entry.action_id() == "http.probe"
            && entry.reason() == &crate::ExclusionReason::DefenseSuppressed
    }));
    assert!(matches!(
        planning.command(),
        DecisionLoopCommand::Halt { .. }
    ));
    let wire = serde_json::to_value(&planning).unwrap();
    assert!(wire.get("defense_suppressed_actions").is_none());
    assert!(wire.get("policy_authorized_plan").is_none());
}

#[test]
fn registered_but_ineligible_adaptive_action_is_rejected_atomically() {
    let mut decision_loop = configured_loop(Some(OutcomeStatus::Blocked), 1, 8);
    register_adaptive_action(
        &mut decision_loop,
        "http.403-bypass",
        "plugin.http-403-bypass",
        101,
        20,
        BTreeSet::new(),
    );
    let knowledge = knowledge(true);
    let mut experience = ExperienceStore::new();
    let mut session = DecisionSession::new(subject());
    decision_loop
        .plan_next(&knowledge, &experience, &mut session)
        .unwrap();
    let initial_session = session.clone();
    let initial_experience = experience.clone();

    let error = decision_loop
        .submit_passive_with_suppressed_actions(
            &knowledge,
            &mut experience,
            &mut session,
            &BTreeSet::new(),
        )
        .unwrap_err();

    assert!(matches!(
        error,
        DecisionLoopError::IneligibleAdaptiveAction { action_id }
            if action_id == "http.403-bypass"
    ));
    assert_eq!(session, initial_session);
    assert_eq!(experience, initial_experience);
}

#[test]
fn adaptive_schedule_cannot_skip_registered_prerequisites() {
    let mut decision_loop = configured_loop(Some(OutcomeStatus::Blocked), 1, 8);
    let knowledge = knowledge(true);
    let mut experience = ExperienceStore::new();
    let mut session = DecisionSession::new(subject());
    decision_loop
        .plan_next(&knowledge, &experience, &mut session)
        .unwrap();
    register_adaptive_action(
        &mut decision_loop,
        "http.prepare-bypass",
        "plugin.http-prepare-bypass",
        10,
        20,
        BTreeSet::new(),
    );
    register_adaptive_action(
        &mut decision_loop,
        "http.403-bypass",
        "plugin.http-403-bypass",
        10,
        20,
        BTreeSet::from(["http.prepare-bypass".to_owned()]),
    );
    let initial_session = session.clone();
    let initial_experience = experience.clone();

    let error = decision_loop
        .submit_passive_with_suppressed_actions(
            &knowledge,
            &mut experience,
            &mut session,
            &BTreeSet::new(),
        )
        .unwrap_err();

    assert!(matches!(
        error,
        DecisionLoopError::AdaptiveActionRequiresPlanning { action_id }
            if action_id == "http.403-bypass"
    ));
    assert_eq!(session, initial_session);
    assert_eq!(experience, initial_experience);
}

#[test]
fn adaptive_authorization_observes_the_outcomes_prospective_hypothesis_state() {
    let mut decision_loop = configured_loop(Some(OutcomeStatus::FalsePositive), 1, 8);
    let knowledge = knowledge(true);
    let mut experience = ExperienceStore::new();
    let mut session = DecisionSession::new(subject());
    decision_loop
        .plan_next(&knowledge, &experience, &mut session)
        .unwrap();
    register_adaptive_action(
        &mut decision_loop,
        "followup.after-rejection",
        "plugin.followup-after-rejection",
        10,
        20,
        BTreeSet::new(),
    );
    decision_loop
        .adaptive_mut()
        .register(
            AdaptationRule::new(
                "test.schedule-after-rejection",
                OutcomeSelector::any_stage(BTreeSet::from([OutcomeStatus::FalsePositive])).unwrap(),
                1_000,
                None,
                PipelineDirective::ScheduleAction {
                    action_id: "followup.after-rejection".to_owned(),
                },
                "fixture attempts to schedule from a rejected motivation",
                1,
            )
            .unwrap(),
        )
        .unwrap();
    let initial_session = session.clone();
    let initial_experience = experience.clone();
    let hypothesis_id = session.state().case().unwrap().hypothesis_id().to_owned();
    let initial_hypothesis = knowledge.hypothesis(&hypothesis_id).unwrap();

    let error = decision_loop
        .submit_passive_with_suppressed_actions(
            &knowledge,
            &mut experience,
            &mut session,
            &BTreeSet::new(),
        )
        .unwrap_err();

    assert!(matches!(
        error,
        DecisionLoopError::NoEligibleScheduledMotivationHypothesis { action_id }
            if action_id == "followup.after-rejection"
    ));
    assert_eq!(session, initial_session);
    assert_eq!(experience, initial_experience);
    assert_eq!(
        knowledge.hypothesis(&hypothesis_id).unwrap(),
        initial_hypothesis
    );
}

#[test]
fn defense_suppression_does_not_promote_a_lower_priority_adaptive_rule() {
    let mut decision_loop = configured_loop(Some(OutcomeStatus::Blocked), 1, 8);
    register_adaptive_action(
        &mut decision_loop,
        "adaptive.high",
        "plugin.adaptive-high",
        10,
        20,
        BTreeSet::new(),
    );
    register_adaptive_action(
        &mut decision_loop,
        "adaptive.low",
        "plugin.adaptive-low",
        10,
        20,
        BTreeSet::new(),
    );
    *decision_loop.adaptive_mut() = AdaptivePipeline::new();
    let selector = OutcomeSelector::any_stage(BTreeSet::from([OutcomeStatus::Blocked])).unwrap();
    for (rule_id, priority, action_id) in [
        ("test.high", 1_000, "adaptive.high"),
        ("test.low", 900, "adaptive.low"),
    ] {
        decision_loop
            .adaptive_mut()
            .register(
                AdaptationRule::new(
                    rule_id,
                    selector.clone(),
                    priority,
                    None,
                    PipelineDirective::ScheduleAction {
                        action_id: action_id.to_owned(),
                    },
                    "fixture schedules one eligible action",
                    1,
                )
                .unwrap(),
            )
            .unwrap();
    }
    let knowledge = knowledge(true);
    let mut experience = ExperienceStore::new();
    let mut session = DecisionSession::new(subject());
    decision_loop
        .plan_next(&knowledge, &experience, &mut session)
        .unwrap();
    let cycles_before = session.action_cycles();
    let suppressions = ActionSuppressionContext::new(
        BTreeSet::new(),
        BTreeSet::from(["adaptive.high".to_owned()]),
    );

    let report = decision_loop
        .submit_passive_with_action_suppressions(
            &knowledge,
            &mut experience,
            &mut session,
            &suppressions,
        )
        .unwrap();

    assert_eq!(report.adaptive().selected_rule_id(), Some("test.high"));
    assert!(matches!(
        report.adaptive().directive(),
        PipelineDirective::ScheduleAction { action_id } if action_id == "adaptive.high"
    ));
    assert!(report
        .adaptive()
        .evaluations()
        .iter()
        .all(|evaluation| !evaluation.policy_suppressed()));
    assert!(matches!(report.command(), DecisionLoopCommand::Replan));
    assert!(matches!(session.state(), DecisionLoopState::Ready));
    assert_eq!(session.action_cycles(), cycles_before);
    assert_eq!(session.adaptation().action_schedules("adaptive.low"), 0);
}

#[test]
fn defense_suppression_replans_retry_and_active_without_issuing_work() {
    let decision_loop = configured_loop(None, 1, 8);
    let knowledge = knowledge(false);
    let experience = ExperienceStore::new();
    let mut planned_session = DecisionSession::new(subject());
    let planning = decision_loop
        .plan_next(&knowledge, &experience, &mut planned_session)
        .unwrap();
    let current_case = execution_case(planning.command());
    let outcome = Outcome::unknown(
        current_case.id(),
        subject(),
        current_case.action_id(),
        current_case.hypothesis_id(),
        VerificationStage::Passive,
        "fixture remains unresolved",
    )
    .unwrap();
    let snapshot = knowledge.snapshot_for_subject(&subject());
    let suppressions = ActionSuppressionContext::new(
        BTreeSet::new(),
        BTreeSet::from([current_case.action_id().to_owned()]),
    );

    for directive in [
        PipelineDirective::Throttle {
            delay_ms: 5,
            retry_current_action: true,
        },
        PipelineDirective::AwaitActiveVerification,
    ] {
        let mut session = planned_session.clone();
        let command = transition_from_adaptive(
            &mut session,
            8,
            decision_loop.planner(),
            decision_loop.config().planning(),
            &snapshot,
            &current_case,
            &outcome,
            &directive,
            &suppressions,
        )
        .unwrap();

        assert!(matches!(command, DecisionLoopCommand::Replan));
        assert!(matches!(session.state(), DecisionLoopState::Ready));
        assert_eq!(session.action_cycles(), planned_session.action_cycles());
    }
}

#[test]
fn adaptive_retry_requires_context_and_honors_dynamic_host_suppression() {
    let mut decision_loop = configured_loop(None, 1, 8);
    decision_loop
        .verification_mut()
        .passive_mut()
        .register(
            VerificationRule::new(
                "verify.http-429",
                VerificationStage::Passive,
                100,
                Expression::equals(
                    KnowledgeLayer::Evidence,
                    status_predicate(),
                    EvidenceValue::Unsigned(429),
                ),
                OutcomeStatus::Blocked,
                Probability::from_percent(95).unwrap(),
                "HTTP rate limiting blocks the current action",
            )
            .unwrap(),
        )
        .unwrap();
    let knowledge = knowledge(false);
    knowledge
        .insert_evidence(Evidence::new(
            subject(),
            EvidenceKind::Http,
            status_predicate(),
            EvidenceValue::Unsigned(429),
            EvidenceSource::new("http.executor", "rate-limit-status").unwrap(),
            ConfidenceScore::MAX,
        ))
        .unwrap();

    let mut no_context_experience = ExperienceStore::new();
    let mut no_context_session = DecisionSession::new(subject());
    decision_loop
        .plan_next(&knowledge, &no_context_experience, &mut no_context_session)
        .unwrap();
    let initial_session = no_context_session.clone();
    let initial_experience = no_context_experience.clone();
    let error = decision_loop
        .submit_passive(
            &knowledge,
            &mut no_context_experience,
            &mut no_context_session,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        DecisionLoopError::AdaptiveExecutionRequiresHostPolicyContext { action_id }
            if action_id == "http.probe"
    ));
    assert_eq!(no_context_session, initial_session);
    assert_eq!(no_context_experience, initial_experience);

    let mut suppressed_experience = ExperienceStore::new();
    let mut suppressed_session = DecisionSession::new(subject());
    decision_loop
        .plan_next(&knowledge, &suppressed_experience, &mut suppressed_session)
        .unwrap();
    let suppressions = BTreeSet::from(["http.probe".to_owned()]);
    let outcome = decision_loop
        .submit_passive_with_suppressed_actions(
            &knowledge,
            &mut suppressed_experience,
            &mut suppressed_session,
            &suppressions,
        )
        .unwrap();
    assert!(outcome.adaptive().selected_rule_id().is_none());
    assert!(matches!(
        outcome.command(),
        DecisionLoopCommand::AwaitHumanReview { case }
            if case.action_id() == "http.probe"
    ));
    assert_eq!(suppressed_session.action_cycles(), 1);
}

#[test]
fn unresolved_passive_case_completes_after_fresh_active_evidence() {
    let mut decision_loop = configured_loop(None, 10, 8);
    decision_loop
        .verification_mut()
        .active_mut()
        .register(
            VerificationRule::new(
                "verify.active-control",
                VerificationStage::Active,
                100,
                Expression::equals(
                    KnowledgeLayer::Evidence,
                    active_predicate(),
                    EvidenceValue::Boolean(true),
                ),
                OutcomeStatus::Success,
                Probability::from_percent(99).unwrap(),
                "fresh active control evidence confirmed the hypothesis",
            )
            .unwrap(),
        )
        .unwrap();
    let knowledge = knowledge(false);
    let mut experience = ExperienceStore::new();
    let mut session = DecisionSession::new(subject());
    let planning = decision_loop
        .plan_next(&knowledge, &experience, &mut session)
        .unwrap();
    let case = execution_case(planning.command());
    let baseline = knowledge.snapshot_for_subject(&subject());

    let passive = decision_loop
        .submit_passive_with_suppressed_actions(
            &knowledge,
            &mut experience,
            &mut session,
            &BTreeSet::new(),
        )
        .unwrap();
    assert_eq!(
        passive.verification().outcome().status(),
        OutcomeStatus::Unknown
    );
    assert!(matches!(
        passive.command(),
        DecisionLoopCommand::CollectActiveEvidence { case: active_case }
            if active_case == &case
    ));

    knowledge
        .insert_evidence(Evidence::new(
            subject(),
            EvidenceKind::Custom("verification.active".into()),
            active_predicate(),
            EvidenceValue::Boolean(true),
            EvidenceSource::new("active.probe", "control-response").unwrap(),
            ConfidenceScore::MAX,
        ))
        .unwrap();
    let after_probe = knowledge.snapshot_for_subject(&subject());
    let active = decision_loop
        .submit_active_with_suppressed_actions(
            &knowledge,
            &mut experience,
            &mut session,
            &baseline,
            &after_probe,
            &BTreeSet::new(),
        )
        .unwrap();

    assert_eq!(
        active.verification().outcome().status(),
        OutcomeStatus::Success
    );
    assert_eq!(active.hypothesis_write(), Some(KnowledgeWrite::Updated));
    assert!(matches!(
        active.command(),
        DecisionLoopCommand::Complete { case: completed } if completed == &case
    ));
    assert!(matches!(session.state(), DecisionLoopState::Completed));
    assert_eq!(
        knowledge.hypothesis(case.hypothesis_id()).unwrap().state(),
        HypothesisState::Confirmed
    );
    let assessment = experience.assess(&subject(), "http.probe", ExperiencePolicy::default());
    assert_eq!(assessment.completed_attempts(), 1);
    assert_eq!(assessment.last_status(), Some(OutcomeStatus::Success));
}

#[test]
fn active_confirmed_negative_rejects_and_records_the_hypothesis() {
    let mut decision_loop = configured_loop(None, 1, 8);
    decision_loop
        .verification_mut()
        .active_mut()
        .register(
            VerificationRule::new(
                "verify.active-negative-control",
                VerificationStage::Active,
                100,
                Expression::equals(
                    KnowledgeLayer::Evidence,
                    active_predicate(),
                    EvidenceValue::Boolean(true),
                ),
                OutcomeStatus::ConfirmedNegative,
                Probability::from_percent(99).unwrap(),
                "fresh active control evidence disproved the hypothesis",
            )
            .unwrap(),
        )
        .unwrap();
    let knowledge = knowledge(false);
    let mut experience = ExperienceStore::new();
    let mut session = DecisionSession::new(subject());
    let planning = decision_loop
        .plan_next(&knowledge, &experience, &mut session)
        .unwrap();
    let case = execution_case(planning.command());
    let baseline = knowledge.snapshot_for_subject(&subject());

    let passive = decision_loop
        .submit_passive_with_suppressed_actions(
            &knowledge,
            &mut experience,
            &mut session,
            &BTreeSet::new(),
        )
        .unwrap();
    assert!(matches!(
        passive.command(),
        DecisionLoopCommand::CollectActiveEvidence { .. }
    ));

    knowledge
        .insert_evidence(Evidence::new(
            subject(),
            EvidenceKind::Custom("verification.active".into()),
            active_predicate(),
            EvidenceValue::Boolean(true),
            EvidenceSource::new("active.probe", "negative-control").unwrap(),
            ConfidenceScore::MAX,
        ))
        .unwrap();
    let after_probe = knowledge.snapshot_for_subject(&subject());
    let active = decision_loop
        .submit_active_with_suppressed_actions(
            &knowledge,
            &mut experience,
            &mut session,
            &baseline,
            &after_probe,
            &BTreeSet::new(),
        )
        .unwrap();

    assert_eq!(
        active.verification().outcome().status(),
        OutcomeStatus::ConfirmedNegative
    );
    assert_eq!(active.hypothesis_write(), Some(KnowledgeWrite::Updated));
    assert!(matches!(active.command(), DecisionLoopCommand::Replan));
    assert_eq!(
        knowledge.hypothesis(case.hypothesis_id()).unwrap().state(),
        HypothesisState::Rejected
    );
    let assessment = experience.assess(&subject(), "http.probe", ExperiencePolicy::new(1).unwrap());
    assert_eq!(
        assessment.last_disposition(),
        Some(ExperienceDisposition::ConfirmedNegative)
    );
    assert_eq!(assessment.consecutive_suppressible_failures(), 1);
    assert!(assessment.is_suppressed());
}

#[test]
fn false_positive_replans_with_the_source_action_suppressed() {
    let decision_loop = configured_loop(Some(OutcomeStatus::FalsePositive), 10, 8);
    let knowledge = knowledge(true);
    let mut experience = ExperienceStore::new();
    let mut session = DecisionSession::new(subject());
    decision_loop
        .plan_next(&knowledge, &experience, &mut session)
        .unwrap();

    let rejected = decision_loop
        .submit_passive_with_suppressed_actions(
            &knowledge,
            &mut experience,
            &mut session,
            &BTreeSet::new(),
        )
        .unwrap();
    let hypothesis_id = rejected.verification().outcome().hypothesis_id().to_owned();
    assert!(matches!(rejected.command(), DecisionLoopCommand::Replan));
    assert!(session
        .adaptation()
        .suppressed_actions()
        .contains("http.probe"));
    assert_eq!(rejected.hypothesis_write(), Some(KnowledgeWrite::Updated));
    assert!(matches!(
        rejected.session_transition().before().state(),
        DecisionLoopState::AwaitingPassive { .. }
    ));
    assert!(matches!(
        rejected.session_transition().after().state(),
        DecisionLoopState::Ready
    ));
    assert_eq!(
        rejected
            .session_transition()
            .before()
            .adaptation_transitions(),
        0
    );
    assert_eq!(
        rejected
            .session_transition()
            .after()
            .adaptation_transitions(),
        1
    );
    let assessment = experience.assess(&subject(), "http.probe", ExperiencePolicy::default());
    assert_eq!(assessment.consecutive_suppressible_failures(), 1);
    assert!(!assessment.is_suppressed());
    assert!(serde_json::to_value(&rejected)
        .unwrap()
        .get("session_transition")
        .is_none());

    let replanned = decision_loop
        .plan_next(&knowledge, &experience, &mut session)
        .unwrap();
    assert!(replanned.plan().steps().is_empty());
    assert!(replanned.suppressed_actions().contains("http.probe"));
    assert_eq!(
        replanned.command(),
        &DecisionLoopCommand::Halt {
            reason: DecisionStopReason::NoEligibleAction
        }
    );
    assert_eq!(
        knowledge.hypothesis(&hypothesis_id).unwrap().state(),
        HypothesisState::Rejected
    );
}

#[test]
fn outer_action_limit_overrides_an_adaptive_schedule() {
    let decision_loop = configured_loop(Some(OutcomeStatus::Blocked), 10, 1);
    let knowledge = knowledge(true);
    let mut experience = ExperienceStore::new();
    let mut session = DecisionSession::new(subject());
    decision_loop
        .plan_next(&knowledge, &experience, &mut session)
        .unwrap();

    let outcome = decision_loop
        .submit_passive_with_suppressed_actions(
            &knowledge,
            &mut experience,
            &mut session,
            &BTreeSet::new(),
        )
        .unwrap();
    assert_eq!(
        outcome.adaptive().selected_rule_id(),
        Some("http.403.bypass")
    );
    assert_eq!(
        outcome.command(),
        &DecisionLoopCommand::Halt {
            reason: DecisionStopReason::ActionCycleLimit
        }
    );
    assert_eq!(session.action_cycles(), 1);
    assert!(matches!(
        session.state(),
        DecisionLoopState::Halted {
            reason: DecisionStopReason::ActionCycleLimit
        }
    ));
}

#[test]
fn session_replay_validates_state_subject_and_action_count() {
    let decision_loop = configured_loop(None, 10, 8);
    let knowledge = knowledge(false);
    let experience = ExperienceStore::new();
    let mut session = DecisionSession::new(subject());
    decision_loop
        .plan_next(&knowledge, &experience, &mut session)
        .unwrap();

    let encoded = serde_json::to_value(&session).unwrap();
    assert_eq!(
        serde_json::from_value::<DecisionSession>(encoded.clone()).unwrap(),
        session
    );
    let mut zero_cycles = encoded.clone();
    zero_cycles["action_cycles"] = serde_json::json!(0);
    assert!(serde_json::from_value::<DecisionSession>(zero_cycles).is_err());

    let mut wrong_subject = encoded;
    wrong_subject["state"]["case"]["subject"] = serde_json::json!("endpoint:https://other.test");
    assert!(serde_json::from_value::<DecisionSession>(wrong_subject).is_err());
    assert!(
        serde_json::from_value::<DecisionLoopConfig>(serde_json::json!({
            "planning": decision_loop.config().planning(),
            "adaptation": decision_loop.config().adaptation(),
            "experience": decision_loop.config().experience(),
            "max_action_cycles": 0
        }))
        .is_err()
    );
}

#[test]
fn evidence_submissions_are_rejected_out_of_order() {
    let decision_loop = configured_loop(None, 10, 8);
    let knowledge = knowledge(false);
    let mut experience = ExperienceStore::new();
    let mut session = DecisionSession::new(subject());

    assert!(matches!(
        decision_loop.submit_passive(&knowledge, &mut experience, &mut session),
        Err(DecisionLoopError::InvalidTransition { .. })
    ));
    let snapshot = knowledge.snapshot_for_subject(&subject());
    assert!(matches!(
        decision_loop.submit_active(
            &knowledge,
            &mut experience,
            &mut session,
            &snapshot,
            &snapshot,
        ),
        Err(DecisionLoopError::InvalidTransition { .. })
    ));
}
