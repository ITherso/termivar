use std::collections::BTreeSet;

use serde_json::Value;
use termivar_core::{
    ConfidenceScore, EntityId, Evidence, EvidenceId, EvidenceKind, EvidenceSource, EvidenceValue,
    HypothesisState, HypothesisStrength, KnowledgePredicate, OutcomeStatus, Probability,
    VerificationStage,
};
use termivar_scanner::{
    ActionCost, AdaptationLimits, AdaptationRule, AdaptivePipeline, AttackAction, AttackPlanner,
    BenefitScore, DecisionActionOrigin, DecisionLoop, DecisionLoopCommand, DecisionLoopConfig,
    DecisionLoopError, DecisionLoopState, DecisionSession, EvidenceCalibration, EvidenceSelector,
    ExperiencePolicy, ExperienceStore, Expression, HypothesisConclusion, HypothesisSelector,
    KnowledgeBase, KnowledgeLayer, OutcomeSelector, PipelineDirective, PlanningContext,
    ReasoningRule, RequiredStrength, RiskScore, VerificationRule, VerificationTarget,
};

/// Maximum byte buffer accepted by the adaptive-authority semantic harness.
pub const MAX_AUTHORITY_FUZZ_INPUT_BYTES: usize = 16 * 1024;

const SOURCE_ACTION_ID: &str = "http.probe";
const SCHEDULED_ACTION_ID: &str = "http.403-bypass";
const PREREQUISITE_ACTION_ID: &str = "http.prepare-bypass";
const REJECTED_FOLLOWUP_ACTION_ID: &str = "followup.after-rejection";

/// Exercises the planner/DecisionLoop boundary that grants adaptive execution
/// authority.
///
/// Each bounded input selects one structured policy scenario. The oracle runs
/// that scenario twice in independent stores and requires identical semantic
/// output. Error cases must be atomic across session, Experience, and
/// hypothesis state. Successful adaptive dispatch must carry the registered
/// executor and the scheduled action's own verification policy.
pub fn check_decision_loop_authority(data: &[u8]) {
    if data.len() > MAX_AUTHORITY_FUZZ_INPUT_BYTES {
        return;
    }

    let model = AuthorityModel::from_input(data);
    let first = run_scenario(&model);
    let repeated = run_scenario(&model);
    assert_eq!(
        first, repeated,
        "identical adaptive authority input must produce identical semantics"
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scenario {
    Unregistered,
    HostSuppressed,
    RequirementsNotMet,
    RiskExceeded,
    BudgetExceeded,
    HasPrerequisite,
    EligibleKnowledgeOnly,
    EligibleMotivation,
    NoContextSchedule,
    NoContextRetry,
    ProspectiveRejection,
    ActiveHostSuppressed,
    ReplayUnregisteredSource,
    ReplayKnowledgeOnlyEscalation,
}

impl Scenario {
    fn from_name(value: &str) -> Option<Self> {
        match value {
            "unregistered" => Some(Self::Unregistered),
            "host_suppressed" => Some(Self::HostSuppressed),
            "requirements_not_met" => Some(Self::RequirementsNotMet),
            "risk_exceeded" => Some(Self::RiskExceeded),
            "budget_exceeded" => Some(Self::BudgetExceeded),
            "has_prerequisite" => Some(Self::HasPrerequisite),
            "eligible_knowledge_only" => Some(Self::EligibleKnowledgeOnly),
            "eligible_motivation" => Some(Self::EligibleMotivation),
            "no_context_schedule" => Some(Self::NoContextSchedule),
            "no_context_retry" => Some(Self::NoContextRetry),
            "prospective_rejection" => Some(Self::ProspectiveRejection),
            "active_host_suppressed" => Some(Self::ActiveHostSuppressed),
            "replay_unregistered_source" => Some(Self::ReplayUnregisteredSource),
            "replay_knowledge_only_escalation" => Some(Self::ReplayKnowledgeOnlyEscalation),
            _ => None,
        }
    }

    fn from_byte(value: u8) -> Self {
        match value % 14 {
            0 => Self::Unregistered,
            1 => Self::HostSuppressed,
            2 => Self::RequirementsNotMet,
            3 => Self::RiskExceeded,
            4 => Self::BudgetExceeded,
            5 => Self::HasPrerequisite,
            6 => Self::EligibleKnowledgeOnly,
            7 => Self::EligibleMotivation,
            8 => Self::NoContextSchedule,
            9 => Self::NoContextRetry,
            10 => Self::ProspectiveRejection,
            11 => Self::ActiveHostSuppressed,
            12 => Self::ReplayUnregisteredSource,
            _ => Self::ReplayKnowledgeOnlyEscalation,
        }
    }

    fn expects_error(self) -> bool {
        !matches!(
            self,
            Self::HostSuppressed | Self::EligibleKnowledgeOnly | Self::EligibleMotivation
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthorityModel {
    scenario: Scenario,
    executor: String,
    budget: u64,
    risk_limit: u8,
    eligible_cost: u32,
    eligible_risk: u8,
}

impl AuthorityModel {
    fn from_input(data: &[u8]) -> Self {
        let root = serde_json::from_slice::<Value>(data).ok();
        let object = root.as_ref().and_then(Value::as_object);
        let scenario = object
            .and_then(|value| value.get("scenario"))
            .and_then(Value::as_str)
            .and_then(Scenario::from_name)
            .unwrap_or_else(|| Scenario::from_byte(data.first().copied().unwrap_or_default()));
        let budget = bounded_u64(
            object
                .and_then(|value| value.get("budget"))
                .and_then(Value::as_u64),
            data.get(1).copied().unwrap_or(28),
            4,
            64,
        );
        let risk_limit = bounded_u64(
            object
                .and_then(|value| value.get("risk_limit"))
                .and_then(Value::as_u64),
            data.get(2).copied().unwrap_or(39),
            1,
            99,
        ) as u8;
        let eligible_cost = bounded_u64(
            object
                .and_then(|value| value.get("target_cost"))
                .and_then(Value::as_u64),
            data.get(3).copied().unwrap_or(7),
            1,
            budget,
        ) as u32;
        let eligible_risk = bounded_u64(
            object
                .and_then(|value| value.get("target_risk"))
                .and_then(Value::as_u64),
            data.get(4).copied().unwrap_or(19),
            1,
            u64::from(risk_limit),
        ) as u8;
        let token = object
            .and_then(|value| value.get("executor_token"))
            .and_then(Value::as_str)
            .map(safe_token)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| byte_token(data));

        Self {
            scenario,
            executor: format!("plugin.wave3.{token}"),
            budget,
            risk_limit,
            eligible_cost,
            eligible_risk,
        }
    }
}

fn bounded_u64(candidate: Option<u64>, fallback: u8, minimum: u64, maximum: u64) -> u64 {
    candidate
        .unwrap_or(u64::from(fallback))
        .clamp(minimum, maximum)
}

fn safe_token(value: &str) -> String {
    value
        .bytes()
        .filter(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        .take(32)
        .map(char::from)
        .collect()
}

fn byte_token(data: &[u8]) -> String {
    let token: String = data
        .iter()
        .take(8)
        .map(|byte| char::from(b'a' + byte % 26))
        .collect();
    if token.is_empty() {
        "empty".to_owned()
    } else {
        token
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScenarioObservation {
    error: Option<&'static str>,
    command: Option<Value>,
    session: Value,
    experience: Value,
    hypothesis_state: HypothesisState,
    hypothesis_strength: HypothesisStrength,
    hypothesis_posterior_parts_per_million: u32,
}

fn run_scenario(model: &AuthorityModel) -> ScenarioObservation {
    let response_status = if model.scenario == Scenario::NoContextRetry {
        429
    } else {
        403
    };
    let knowledge = knowledge(response_status);
    let passive_status = match model.scenario {
        Scenario::ProspectiveRejection => Some(OutcomeStatus::FalsePositive),
        Scenario::ActiveHostSuppressed => None,
        Scenario::ReplayUnregisteredSource => Some(OutcomeStatus::Success),
        Scenario::ReplayKnowledgeOnlyEscalation => Some(OutcomeStatus::Success),
        _ => Some(OutcomeStatus::Blocked),
    };
    let mut decision_loop = configured_loop(model, response_status, passive_status);
    register_scenario_actions(&mut decision_loop, model);
    let mut experience = ExperienceStore::new();
    let mut session = DecisionSession::new(subject());
    let planning_suppressions = if model.scenario == Scenario::HostSuppressed {
        BTreeSet::from([SCHEDULED_ACTION_ID.to_owned()])
    } else {
        BTreeSet::new()
    };
    let submission_suppressions = if model.scenario == Scenario::ActiveHostSuppressed {
        BTreeSet::from([SOURCE_ACTION_ID.to_owned()])
    } else {
        planning_suppressions.clone()
    };

    let planning = decision_loop
        .plan_next_with_suppressed_actions(
            &knowledge,
            &experience,
            &mut session,
            &planning_suppressions,
        )
        .expect("the independent source action must remain plannable");
    assert!(matches!(
        planning.command(),
        DecisionLoopCommand::ExecuteAction {
            case,
            executor: Some(executor),
            origin: DecisionActionOrigin::Planned,
            delay_ms: None,
        } if case.action_id() == SOURCE_ACTION_ID && executor == "plugin.http-probe"
    ));
    if model.scenario == Scenario::HostSuppressed {
        assert!(planning.suppressed_actions().contains(SCHEDULED_ACTION_ID));
        assert!(planning
            .plan()
            .steps()
            .iter()
            .all(|step| step.action_id() != SCHEDULED_ACTION_ID));
    }
    if model.scenario == Scenario::ReplayUnregisteredSource {
        *decision_loop.planner_mut() = AttackPlanner::new();
    } else if model.scenario == Scenario::ReplayKnowledgeOnlyEscalation {
        session = replay_case_as_legacy_transition_authorized(session);
    }

    let hypothesis_id = outstanding_hypothesis_id(&session);
    let initial_session = session.clone();
    let initial_experience = experience.clone();
    let initial_hypothesis = knowledge
        .hypothesis(&hypothesis_id)
        .expect("planned source action must retain its motivation hypothesis");

    let result = if matches!(
        model.scenario,
        Scenario::NoContextSchedule | Scenario::NoContextRetry
    ) {
        decision_loop.submit_passive(&knowledge, &mut experience, &mut session)
    } else {
        decision_loop.submit_passive_with_suppressed_actions(
            &knowledge,
            &mut experience,
            &mut session,
            &submission_suppressions,
        )
    };

    assert_expected_result(model, &result);
    if model.scenario.expects_error() {
        assert_eq!(
            session, initial_session,
            "adaptive authorization error partially mutated the session"
        );
        assert_eq!(
            experience, initial_experience,
            "adaptive authorization error partially mutated Experience"
        );
        assert_eq!(
            knowledge.hypothesis(&hypothesis_id).as_ref(),
            Some(&initial_hypothesis),
            "adaptive authorization error partially transitioned the hypothesis"
        );
    }

    let (error, command) = match result {
        Ok(report) => (None, Some(command_value(report.command()))),
        Err(error) => (Some(error_class(&error)), None),
    };
    let hypothesis = knowledge
        .hypothesis(&hypothesis_id)
        .expect("motivation hypothesis must remain present");
    ScenarioObservation {
        error,
        command,
        session: serde_json::to_value(&session).expect("session serialization must succeed"),
        experience: serde_json::to_value(&experience)
            .expect("Experience serialization must succeed"),
        hypothesis_state: hypothesis.state(),
        hypothesis_strength: hypothesis.strength(),
        hypothesis_posterior_parts_per_million: hypothesis.posterior().parts_per_million(),
    }
}

fn assert_expected_result(
    model: &AuthorityModel,
    result: &Result<termivar_scanner::DecisionOutcomeReport, DecisionLoopError>,
) {
    match (model.scenario, result) {
        (
            Scenario::Unregistered,
            Err(DecisionLoopError::UnregisteredDecisionAction { action_id }),
        ) => assert_eq!(action_id, SCHEDULED_ACTION_ID),
        (
            Scenario::RequirementsNotMet | Scenario::RiskExceeded | Scenario::BudgetExceeded,
            Err(DecisionLoopError::IneligibleAdaptiveAction { action_id }),
        ) => assert_eq!(action_id, SCHEDULED_ACTION_ID),
        (
            Scenario::HasPrerequisite,
            Err(DecisionLoopError::AdaptiveActionRequiresPlanning { action_id }),
        ) => assert_eq!(action_id, SCHEDULED_ACTION_ID),
        (
            Scenario::NoContextSchedule,
            Err(DecisionLoopError::AdaptiveExecutionRequiresHostPolicyContext { action_id }),
        ) => assert_eq!(action_id, SCHEDULED_ACTION_ID),
        (
            Scenario::NoContextRetry,
            Err(DecisionLoopError::AdaptiveExecutionRequiresHostPolicyContext { action_id }),
        ) => assert_eq!(action_id, SOURCE_ACTION_ID),
        (
            Scenario::ProspectiveRejection,
            Err(DecisionLoopError::NoEligibleScheduledMotivationHypothesis { action_id }),
        ) => assert_eq!(action_id, REJECTED_FOLLOWUP_ACTION_ID),
        (
            Scenario::ActiveHostSuppressed,
            Err(DecisionLoopError::IneligibleAdaptiveAction { action_id }),
        ) => assert_eq!(action_id, SOURCE_ACTION_ID),
        (
            Scenario::ReplayUnregisteredSource,
            Err(DecisionLoopError::UnregisteredDecisionAction { action_id }),
        ) => assert_eq!(action_id, SOURCE_ACTION_ID),
        (
            Scenario::ReplayKnowledgeOnlyEscalation,
            Err(DecisionLoopError::DecisionCaseAuthorityExceeded { action_id }),
        ) => assert_eq!(action_id, SOURCE_ACTION_ID),
        (Scenario::HostSuppressed, Ok(report)) => {
            assert!(report.adaptive().selected_rule_id().is_none());
            assert!(matches!(
                report.command(),
                DecisionLoopCommand::AwaitHumanReview { case }
                    if case.action_id() == SOURCE_ACTION_ID
            ));
            assert!(!command_dispatches(report.command(), SCHEDULED_ACTION_ID));
        },
        (Scenario::EligibleKnowledgeOnly, Ok(report)) => {
            assert_registered_dispatch(report.command(), model, false);
        },
        (Scenario::EligibleMotivation, Ok(report)) => {
            assert_registered_dispatch(report.command(), model, true);
        },
        (scenario, other) => panic!(
            "adaptive authority scenario {scenario:?} produced an unexpected result: {other:?}"
        ),
    }
}

fn assert_registered_dispatch(
    command: &DecisionLoopCommand,
    model: &AuthorityModel,
    applies_hypothesis_transition: bool,
) {
    assert!(matches!(
        command,
        DecisionLoopCommand::ExecuteAction {
            case,
            executor: Some(executor),
            origin: DecisionActionOrigin::Adaptive,
            delay_ms: None,
        } if case.action_id() == SCHEDULED_ACTION_ID
            && executor == &model.executor
            && case.applies_hypothesis_transition() == applies_hypothesis_transition
    ));
}

fn command_dispatches(command: &DecisionLoopCommand, action_id: &str) -> bool {
    matches!(
        command,
        DecisionLoopCommand::ExecuteAction { case, .. } if case.action_id() == action_id
    )
}

fn command_value(command: &DecisionLoopCommand) -> Value {
    serde_json::to_value(command).expect("decision command serialization must succeed")
}

fn error_class(error: &DecisionLoopError) -> &'static str {
    match error {
        DecisionLoopError::AdaptiveExecutionRequiresHostPolicyContext { .. } => {
            "host_policy_context_required"
        },
        DecisionLoopError::UnregisteredDecisionAction { .. } => "unregistered",
        DecisionLoopError::IneligibleAdaptiveAction { .. } => "ineligible",
        DecisionLoopError::AdaptiveActionRequiresPlanning { .. } => "requires_planning",
        DecisionLoopError::NoEligibleScheduledMotivationHypothesis { .. } => {
            "prospective_motivation_ineligible"
        },
        DecisionLoopError::DecisionCaseAuthorityExceeded { .. } => {
            "replay_claim_authority_exceeded"
        },
        _ => "unexpected",
    }
}

fn configured_loop(
    model: &AuthorityModel,
    response_status: u64,
    passive_status: Option<OutcomeStatus>,
) -> DecisionLoop {
    let planning = PlanningContext::new(
        BenefitScore::from_percent(90).expect("fixed business value must be valid"),
        model.budget,
        RiskScore::from_percent(model.risk_limit).expect("bounded risk limit must be valid"),
    );
    let config = DecisionLoopConfig::new(
        planning,
        AdaptationLimits::default(),
        ExperiencePolicy::new(1).expect("fixed Experience limit must be valid"),
        4,
    )
    .expect("fixed decision-loop bounds must be valid");
    let mut decision_loop = DecisionLoop::new(config);

    let calibration = EvidenceCalibration::new(
        EvidenceSelector::equals(technology_predicate(), laravel()),
        Probability::from_percent(85).expect("fixed likelihood must be valid"),
        Probability::from_percent(15).expect("fixed likelihood must be valid"),
        "stable Laravel fingerprint",
    )
    .expect("fixed calibration must be valid");
    let conclusion = HypothesisConclusion::new(
        hypothesis_predicate(),
        laravel(),
        Probability::from_percent(50).expect("fixed prior must be valid"),
        HypothesisStrength::Strong,
        HypothesisState::Supported,
        vec![calibration],
    )
    .expect("fixed conclusion must be valid");
    decision_loop
        .rules_mut()
        .register(
            ReasoningRule::new(
                "detect.laravel",
                Expression::equals(KnowledgeLayer::Evidence, technology_predicate(), laravel()),
                conclusion,
            )
            .expect("fixed reasoning rule must be valid"),
        )
        .expect("fixed reasoning rule must register");
    decision_loop
        .planner_mut()
        .register(action(
            SOURCE_ACTION_ID,
            "plugin.http-probe",
            Expression::equals(
                KnowledgeLayer::Hypothesis,
                hypothesis_predicate(),
                laravel(),
            ),
            80,
            1,
            1,
            BTreeSet::new(),
            if model.scenario == Scenario::ReplayKnowledgeOnlyEscalation {
                VerificationTarget::KnowledgeOnly
            } else {
                VerificationTarget::Motivation
            },
        ))
        .expect("source action must register");
    if let Some(passive_status) = passive_status {
        decision_loop
            .verification_mut()
            .passive_mut()
            .register(
                VerificationRule::new(
                    format!("verify.http-{response_status}"),
                    VerificationStage::Passive,
                    100,
                    Expression::equals(
                        KnowledgeLayer::Evidence,
                        status_predicate(),
                        EvidenceValue::Unsigned(response_status),
                    ),
                    passive_status,
                    Probability::from_percent(95).expect("fixed confidence must be valid"),
                    "HTTP control response classified the action",
                )
                .expect("fixed verification rule must be valid"),
            )
            .expect("fixed verification rule must register");
    }
    *decision_loop.adaptive_mut() =
        AdaptivePipeline::with_standard_policies().expect("standard policy must construct");
    decision_loop
}

fn register_scenario_actions(decision_loop: &mut DecisionLoop, model: &AuthorityModel) {
    match model.scenario {
        Scenario::Unregistered
        | Scenario::NoContextRetry
        | Scenario::ActiveHostSuppressed
        | Scenario::ReplayUnregisteredSource
        | Scenario::ReplayKnowledgeOnlyEscalation => {},
        Scenario::ProspectiveRejection => {
            decision_loop
                .planner_mut()
                .register(action(
                    REJECTED_FOLLOWUP_ACTION_ID,
                    &model.executor,
                    matching_requirement(),
                    10,
                    model.eligible_cost,
                    model.eligible_risk,
                    BTreeSet::new(),
                    VerificationTarget::KnowledgeOnly,
                ))
                .expect("prospective follow-up action must register");
            decision_loop
                .adaptive_mut()
                .register(
                    AdaptationRule::new(
                        "fuzz.schedule-after-rejection",
                        OutcomeSelector::any_stage(BTreeSet::from([OutcomeStatus::FalsePositive]))
                            .expect("fixed outcome selector must be valid"),
                        1_000,
                        None,
                        PipelineDirective::ScheduleAction {
                            action_id: REJECTED_FOLLOWUP_ACTION_ID.to_owned(),
                        },
                        "fuzz attempts scheduling after rejecting the motivation",
                        1,
                    )
                    .expect("fixed prospective adaptation must be valid"),
                )
                .expect("fixed prospective adaptation must register");
        },
        Scenario::HasPrerequisite => {
            decision_loop
                .planner_mut()
                .register(action(
                    PREREQUISITE_ACTION_ID,
                    "plugin.wave3.prepare",
                    matching_requirement(),
                    5,
                    1,
                    model.eligible_risk,
                    BTreeSet::new(),
                    VerificationTarget::Motivation,
                ))
                .expect("prerequisite action must register");
            decision_loop
                .planner_mut()
                .register(action(
                    SCHEDULED_ACTION_ID,
                    &model.executor,
                    matching_requirement(),
                    10,
                    model.eligible_cost,
                    model.eligible_risk,
                    BTreeSet::from([PREREQUISITE_ACTION_ID.to_owned()]),
                    VerificationTarget::KnowledgeOnly,
                ))
                .expect("dependent scheduled action must register");
        },
        scenario => {
            let requirements = if scenario == Scenario::RequirementsNotMet {
                Expression::exists(
                    KnowledgeLayer::Evidence,
                    KnowledgePredicate::new("fuzz.authority", "missing")
                        .expect("fixed missing predicate must be valid"),
                )
            } else {
                matching_requirement()
            };
            let cost = if scenario == Scenario::BudgetExceeded {
                u32::try_from(model.budget + 1).expect("bounded budget must fit u32")
            } else {
                model.eligible_cost
            };
            let risk = if scenario == Scenario::RiskExceeded {
                model.risk_limit + 1
            } else {
                model.eligible_risk
            };
            let target = if scenario == Scenario::EligibleMotivation {
                VerificationTarget::Motivation
            } else {
                VerificationTarget::KnowledgeOnly
            };
            decision_loop
                .planner_mut()
                .register(action(
                    SCHEDULED_ACTION_ID,
                    &model.executor,
                    requirements,
                    10,
                    cost,
                    risk,
                    BTreeSet::new(),
                    target,
                ))
                .expect("bounded scheduled action must register");
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn action(
    id: &str,
    executor: &str,
    requirements: Expression,
    gain_percent: u8,
    cost: u32,
    risk_percent: u8,
    prerequisites: BTreeSet<String>,
    target: VerificationTarget,
) -> AttackAction {
    AttackAction::new(
        id,
        executor,
        requirements,
        HypothesisSelector::new(
            hypothesis_predicate(),
            laravel(),
            Probability::from_percent(50).expect("fixed selector floor must be valid"),
            RequiredStrength::Strong,
        ),
        BenefitScore::from_percent(gain_percent).expect("bounded gain must be valid"),
        ActionCost::new(cost).expect("positive bounded cost must be valid"),
        RiskScore::from_percent(risk_percent).expect("bounded action risk must be valid"),
        prerequisites,
    )
    .expect("bounded action must be valid")
    .with_verification_target(target)
}

fn matching_requirement() -> Expression {
    Expression::equals(
        KnowledgeLayer::Hypothesis,
        hypothesis_predicate(),
        laravel(),
    )
}

fn knowledge(response_status: u64) -> KnowledgeBase {
    let knowledge = KnowledgeBase::new();
    knowledge
        .insert_evidence(Evidence::with_id_at(
            EvidenceId::parse("fuzz-authority-framework").expect("fixed evidence ID must be valid"),
            subject(),
            EvidenceKind::Technology,
            technology_predicate(),
            laravel(),
            EvidenceSource::new("fuzz.authority", "framework")
                .expect("fixed evidence source must be valid"),
            ConfidenceScore::from_percent(90).expect("fixed reliability must be valid"),
            1,
        ))
        .expect("framework evidence must insert");
    knowledge
        .insert_evidence(Evidence::with_id_at(
            EvidenceId::parse("fuzz-authority-status").expect("fixed evidence ID must be valid"),
            subject(),
            EvidenceKind::Http,
            status_predicate(),
            EvidenceValue::Unsigned(response_status),
            EvidenceSource::new("fuzz.authority", "status")
                .expect("fixed evidence source must be valid"),
            ConfidenceScore::MAX,
            2,
        ))
        .expect("status evidence must insert");
    knowledge
}

fn outstanding_hypothesis_id(session: &DecisionSession) -> String {
    match session.state() {
        DecisionLoopState::AwaitingPassive { case } => case.hypothesis_id().to_owned(),
        state => panic!("planning did not leave an outstanding passive case: {state:?}"),
    }
}

fn replay_case_as_legacy_transition_authorized(session: DecisionSession) -> DecisionSession {
    let mut wire = serde_json::to_value(&session).expect("session serialization must succeed");
    let case = wire
        .get_mut("state")
        .and_then(Value::as_object_mut)
        .and_then(|state| state.get_mut("case"))
        .and_then(Value::as_object_mut)
        .expect("planned session wire must contain a case");
    assert_eq!(
        case.remove("applies_hypothesis_transition"),
        Some(Value::Bool(false)),
        "KnowledgeOnly case must serialize its transition denial"
    );
    assert_eq!(
        case.remove("payload_claim_policy_guard"),
        Some(Value::Bool(true)),
        "KnowledgeOnly case must serialize its compatibility guard"
    );
    let replayed: DecisionSession =
        serde_json::from_value(wire).expect("legacy default case wire must remain readable");
    assert!(matches!(
        replayed.state(),
        DecisionLoopState::AwaitingPassive { case }
            if case.applies_hypothesis_transition()
    ));
    replayed
}

fn subject() -> EntityId {
    EntityId::new("endpoint:https://fuzz.invalid").expect("fixed subject must be valid")
}

fn technology_predicate() -> KnowledgePredicate {
    KnowledgePredicate::new("technology", "framework").expect("fixed predicate must be valid")
}

fn hypothesis_predicate() -> KnowledgePredicate {
    KnowledgePredicate::new("stack", "framework").expect("fixed predicate must be valid")
}

fn status_predicate() -> KnowledgePredicate {
    KnowledgePredicate::new("http.response", "status").expect("fixed predicate must be valid")
}

fn laravel() -> EvidenceValue {
    EvidenceValue::Text("Laravel".to_owned())
}
