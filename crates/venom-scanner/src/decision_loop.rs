//! Deterministic orchestration across reasoning, planning, verification, adaptation, and experience.
//!
//! The decision loop is a state machine, not an executor. It mutates only the
//! knowledge, adaptive ledger, and experience records supplied by the host.
//! Network traffic, plugin execution, delays, and cancellation remain runner
//! responsibilities represented by explicit [`DecisionLoopCommand`] values.

use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use venom_core::{EntityId, Outcome};

use crate::{
    apply_outcome, AdaptationLedger, AdaptationLimits, AdaptiveDecision, AdaptivePipeline,
    AdaptivePipelineError, AttackPlan, AttackPlanner, ExperiencePolicy, ExperienceStore,
    ExperienceStoreError, ExperienceWrite, KnowledgeBase, KnowledgeSnapshot, KnowledgeWrite,
    PipelineDirective, PlannerError, PlanningContext, RuleApplication, RuleEngine, RuleEngineError,
    VerificationCase, VerificationError, VerificationPipeline, VerificationReport,
};

/// Validation and transition failures raised by the decision loop.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DecisionLoopError {
    /// An action-cycle limit of zero would prevent all execution.
    #[error("maximum decision-loop action cycles must be greater than zero")]
    ZeroActionCycles,

    /// A command was submitted while the session was in another state.
    #[error("cannot {operation} while decision loop is {state}")]
    InvalidTransition {
        /// Attempted operation.
        operation: &'static str,
        /// Current stable state name.
        state: &'static str,
    },

    /// Persisted state contained a case for another subject.
    #[error("decision session subject {expected} does not match case subject {actual}")]
    CaseSubjectMismatch {
        /// Session subject.
        expected: EntityId,
        /// Case subject.
        actual: EntityId,
    },

    /// Persisted state awaited evidence before issuing any action.
    #[error("decision session cannot await evidence with zero issued action cycles")]
    AwaitingWithoutAction,

    /// The monotonic action-cycle counter could not be incremented safely.
    #[error("decision-loop action cycle counter overflowed")]
    ActionCycleOverflow,

    /// Reasoning failed.
    #[error(transparent)]
    Rules(#[from] RuleEngineError),

    /// Planning failed.
    #[error(transparent)]
    Planner(#[from] PlannerError),

    /// Verification failed.
    #[error(transparent)]
    Verification(#[from] VerificationError),

    /// Adaptive policy evaluation failed.
    #[error(transparent)]
    Adaptive(#[from] AdaptivePipelineError),

    /// Experience recording or validation failed.
    #[error(transparent)]
    Experience(#[from] ExperienceStoreError),
}

/// Stable configuration shared by all turns in one decision loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DecisionLoopConfig {
    planning: PlanningContext,
    adaptation: AdaptationLimits,
    experience: ExperiencePolicy,
    max_action_cycles: u32,
}

impl DecisionLoopConfig {
    /// Creates a configuration with positive action-cycle bounds.
    pub fn new(
        planning: PlanningContext,
        adaptation: AdaptationLimits,
        experience: ExperiencePolicy,
        max_action_cycles: u32,
    ) -> Result<Self, DecisionLoopError> {
        if max_action_cycles == 0 {
            return Err(DecisionLoopError::ZeroActionCycles);
        }
        Ok(Self {
            planning,
            adaptation,
            experience,
            max_action_cycles,
        })
    }

    /// Returns planner utility, budget, and risk policy.
    pub fn planning(self) -> PlanningContext {
        self.planning
    }

    /// Returns adaptive transition limits.
    pub fn adaptation(self) -> AdaptationLimits {
        self.adaptation
    }

    /// Returns experience suppression policy.
    pub fn experience(self) -> ExperiencePolicy {
        self.experience
    }

    /// Returns the maximum number of emitted action executions.
    pub fn max_action_cycles(self) -> u32 {
        self.max_action_cycles
    }
}

impl<'de> Deserialize<'de> for DecisionLoopConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireConfig {
            planning: PlanningContext,
            adaptation: AdaptationLimits,
            experience: ExperiencePolicy,
            max_action_cycles: u32,
        }

        let wire = WireConfig::deserialize(deserializer)?;
        Self::new(
            wire.planning,
            wire.adaptation,
            wire.experience,
            wire.max_action_cycles,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// Why an action execution was emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DecisionActionOrigin {
    /// Selected by utility planning.
    Planned,
    /// Scheduled by adaptive policy.
    Adaptive,
    /// Re-issued after adaptive backpressure.
    Retry,
}

/// Stable terminal reason for a decision session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DecisionStopReason {
    /// A verifier confirmed the current objective.
    ObjectiveComplete,
    /// Planning found no executable action.
    NoEligibleAction,
    /// Policy requires a human decision.
    HumanReview,
    /// Adaptive transition limits were exhausted.
    AdaptationLimit,
    /// The outer action-cycle guard was exhausted.
    ActionCycleLimit,
}

/// Side-effect-free command consumed by a runner or scheduler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
#[non_exhaustive]
pub enum DecisionLoopCommand {
    /// Execute one action and record its observations as evidence.
    ExecuteAction {
        /// Verification identity attached to the execution.
        case: VerificationCase,
        /// Concrete executor selected by the planner, when applicable.
        executor: Option<String>,
        /// Source of the execution request.
        origin: DecisionActionOrigin,
        /// Required scheduler delay before execution.
        delay_ms: Option<u64>,
    },
    /// Collect explicit probe evidence for an unresolved case.
    CollectActiveEvidence {
        /// Case awaiting active evidence.
        case: VerificationCase,
    },
    /// Re-run reasoning and utility planning.
    Replan,
    /// Stop because the current objective was verified.
    Complete {
        /// Completed verification case.
        case: VerificationCase,
    },
    /// Preserve the case for a human decision.
    AwaitHumanReview {
        /// Case requiring review.
        case: VerificationCase,
    },
    /// Stop deterministically at a loop boundary.
    Halt {
        /// Reason no further command will be emitted.
        reason: DecisionStopReason,
    },
}

/// Replayable state of one target-scoped decision session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
#[non_exhaustive]
pub enum DecisionLoopState {
    /// Ready to run reasoning and planning.
    Ready,
    /// Waiting for evidence produced by an emitted action.
    AwaitingPassive {
        /// Case attached to the outstanding action.
        case: VerificationCase,
    },
    /// Waiting for evidence from an explicit verification probe.
    AwaitingActive {
        /// Case attached to the outstanding probe.
        case: VerificationCase,
    },
    /// The current objective was verified.
    Completed,
    /// The session stopped without a completed objective.
    Halted {
        /// Stable stop reason.
        reason: DecisionStopReason,
    },
}

impl DecisionLoopState {
    fn name(&self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::AwaitingPassive { .. } => "awaiting_passive",
            Self::AwaitingActive { .. } => "awaiting_active",
            Self::Completed => "completed",
            Self::Halted { .. } => "halted",
        }
    }

    fn case(&self) -> Option<&VerificationCase> {
        match self {
            Self::AwaitingPassive { case } | Self::AwaitingActive { case } => Some(case),
            Self::Ready | Self::Completed | Self::Halted { .. } => None,
        }
    }
}

/// Target-scoped counters and adaptive ledger for deterministic replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecisionSession {
    subject: EntityId,
    action_cycles: u32,
    state: DecisionLoopState,
    adaptation: AdaptationLedger,
}

impl DecisionSession {
    /// Creates a ready session for one knowledge subject.
    pub fn new(subject: EntityId) -> Self {
        Self {
            subject,
            action_cycles: 0,
            state: DecisionLoopState::Ready,
            adaptation: AdaptationLedger::new(),
        }
    }

    /// Returns the session subject.
    pub fn subject(&self) -> &EntityId {
        &self.subject
    }

    /// Returns the number of action executions issued so far.
    pub fn action_cycles(&self) -> u32 {
        self.action_cycles
    }

    /// Returns the current state.
    pub fn state(&self) -> &DecisionLoopState {
        &self.state
    }

    /// Returns the adaptive transition ledger.
    pub fn adaptation(&self) -> &AdaptationLedger {
        &self.adaptation
    }
}

impl<'de> Deserialize<'de> for DecisionSession {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireSession {
            subject: EntityId,
            action_cycles: u32,
            state: DecisionLoopState,
            adaptation: AdaptationLedger,
        }

        let wire = WireSession::deserialize(deserializer)?;
        if let Some(case) = wire.state.case() {
            if case.subject() != &wire.subject {
                return Err(serde::de::Error::custom(
                    DecisionLoopError::CaseSubjectMismatch {
                        expected: wire.subject,
                        actual: case.subject().clone(),
                    },
                ));
            }
            if wire.action_cycles == 0 {
                return Err(serde::de::Error::custom(
                    DecisionLoopError::AwaitingWithoutAction,
                ));
            }
        }
        Ok(Self {
            subject: wire.subject,
            action_cycles: wire.action_cycles,
            state: wire.state,
            adaptation: wire.adaptation,
        })
    }
}

/// Audit record produced by a reasoning and planning turn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecisionPlanningReport {
    rule_applications: Vec<RuleApplication>,
    plan: AttackPlan,
    suppressed_actions: BTreeSet<String>,
    command: DecisionLoopCommand,
}

impl DecisionPlanningReport {
    /// Returns deterministic reasoning applications in rule-ID order.
    pub fn rule_applications(&self) -> &[RuleApplication] {
        &self.rule_applications
    }

    /// Returns the complete planner audit record.
    pub fn plan(&self) -> &AttackPlan {
        &self.plan
    }

    /// Returns suppressions applied to this planning cycle.
    pub fn suppressed_actions(&self) -> &BTreeSet<String> {
        &self.suppressed_actions
    }

    /// Returns the runner command selected for this turn.
    pub fn command(&self) -> &DecisionLoopCommand {
        &self.command
    }
}

/// Audit record produced by a passive or active verification turn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecisionOutcomeReport {
    verification: VerificationReport,
    adaptive: AdaptiveDecision,
    experience_write: ExperienceWrite,
    hypothesis_write: Option<KnowledgeWrite>,
    command: DecisionLoopCommand,
}

impl DecisionOutcomeReport {
    /// Returns the verifier outcome and rule trace.
    pub fn verification(&self) -> &VerificationReport {
        &self.verification
    }

    /// Returns the adaptive policy decision.
    pub fn adaptive(&self) -> &AdaptiveDecision {
        &self.adaptive
    }

    /// Returns whether experience inserted or already knew the outcome.
    pub fn experience_write(&self) -> ExperienceWrite {
        self.experience_write
    }

    /// Returns the verifier-owned hypothesis state write, when conclusive.
    pub fn hypothesis_write(&self) -> Option<KnowledgeWrite> {
        self.hypothesis_write
    }

    /// Returns the next runner command.
    pub fn command(&self) -> &DecisionLoopCommand {
        &self.command
    }
}

/// Deterministic coordinator for one evidence-to-command cycle.
///
/// # Example
///
/// ```rust
/// use venom_scanner::{
///     AdaptationLimits, BenefitScore, DecisionLoop, DecisionLoopConfig, ExperiencePolicy,
///     PlanningContext, RiskScore,
/// };
///
/// let planning = PlanningContext::new(
///     BenefitScore::from_percent(80)?,
///     100,
///     RiskScore::from_percent(40)?,
/// );
/// let config = DecisionLoopConfig::new(
///     planning,
///     AdaptationLimits::default(),
///     ExperiencePolicy::default(),
///     32,
/// )?;
/// let decision_loop = DecisionLoop::new(config);
/// assert!(decision_loop.planner().is_empty());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct DecisionLoop {
    config: DecisionLoopConfig,
    rules: RuleEngine,
    planner: AttackPlanner,
    verification: VerificationPipeline,
    adaptive: AdaptivePipeline,
}

impl DecisionLoop {
    /// Creates an empty coordinator with explicit limits.
    pub fn new(config: DecisionLoopConfig) -> Self {
        Self {
            config,
            rules: RuleEngine::new(),
            planner: AttackPlanner::new(),
            verification: VerificationPipeline::default(),
            adaptive: AdaptivePipeline::new(),
        }
    }

    /// Creates a coordinator from independently configured subsystems.
    pub fn with_components(
        config: DecisionLoopConfig,
        rules: RuleEngine,
        planner: AttackPlanner,
        verification: VerificationPipeline,
        adaptive: AdaptivePipeline,
    ) -> Self {
        Self {
            config,
            rules,
            planner,
            verification,
            adaptive,
        }
    }

    /// Returns the immutable configuration.
    pub fn config(&self) -> DecisionLoopConfig {
        self.config
    }

    /// Returns the reasoning registry.
    pub fn rules(&self) -> &RuleEngine {
        &self.rules
    }

    /// Returns the mutable reasoning registry.
    pub fn rules_mut(&mut self) -> &mut RuleEngine {
        &mut self.rules
    }

    /// Returns the attack planner.
    pub fn planner(&self) -> &AttackPlanner {
        &self.planner
    }

    /// Returns the mutable attack planner.
    pub fn planner_mut(&mut self) -> &mut AttackPlanner {
        &mut self.planner
    }

    /// Returns the verification pipeline.
    pub fn verification(&self) -> &VerificationPipeline {
        &self.verification
    }

    /// Returns the mutable verification pipeline.
    pub fn verification_mut(&mut self) -> &mut VerificationPipeline {
        &mut self.verification
    }

    /// Returns adaptive policy.
    pub fn adaptive(&self) -> &AdaptivePipeline {
        &self.adaptive
    }

    /// Returns mutable adaptive policy.
    pub fn adaptive_mut(&mut self) -> &mut AdaptivePipeline {
        &mut self.adaptive
    }

    /// Applies reasoning, utility planning, and target-scoped suppressions.
    pub fn plan_next(
        &self,
        knowledge: &KnowledgeBase,
        experience: &ExperienceStore,
        session: &mut DecisionSession,
    ) -> Result<DecisionPlanningReport, DecisionLoopError> {
        require_state(session, "plan", |state| {
            matches!(state, DecisionLoopState::Ready)
        })?;
        if session.action_cycles >= self.config.max_action_cycles {
            let reason = DecisionStopReason::ActionCycleLimit;
            session.state = DecisionLoopState::Halted { reason };
            let snapshot = knowledge.snapshot_for_subject(session.subject());
            let suppressions = combined_suppressions(experience, session, self.config.experience);
            return Ok(DecisionPlanningReport {
                rule_applications: Vec::new(),
                plan: self.planner.plan_snapshot_with_suppressed(
                    &snapshot,
                    self.config.planning,
                    &suppressions,
                )?,
                suppressed_actions: suppressions,
                command: DecisionLoopCommand::Halt { reason },
            });
        }

        let applications = self.rules.apply(knowledge, session.subject())?;
        let snapshot = knowledge.snapshot_for_subject(session.subject());
        let suppressions = combined_suppressions(experience, session, self.config.experience);
        let plan = self.planner.plan_snapshot_with_suppressed(
            &snapshot,
            self.config.planning,
            &suppressions,
        )?;
        let command = if let Some(step) = plan.steps().first() {
            let case = next_case(
                session,
                step.action_id(),
                step.confidence_hypothesis_id(),
                "planned",
            )?;
            issue_action(
                session,
                self.config.max_action_cycles,
                case,
                Some(step.executor().to_owned()),
                DecisionActionOrigin::Planned,
                None,
            )
        } else {
            let reason = DecisionStopReason::NoEligibleAction;
            session.state = DecisionLoopState::Halted { reason };
            DecisionLoopCommand::Halt { reason }
        };

        Ok(DecisionPlanningReport {
            rule_applications: applications,
            plan,
            suppressed_actions: suppressions,
            command,
        })
    }

    /// Evaluates evidence produced by the outstanding action.
    pub fn submit_passive(
        &self,
        knowledge: &KnowledgeBase,
        experience: &mut ExperienceStore,
        session: &mut DecisionSession,
    ) -> Result<DecisionOutcomeReport, DecisionLoopError> {
        let case = match session.state() {
            DecisionLoopState::AwaitingPassive { case } => case.clone(),
            state => {
                return Err(DecisionLoopError::InvalidTransition {
                    operation: "submit passive evidence",
                    state: state.name(),
                })
            },
        };
        let snapshot = knowledge.snapshot_for_subject(session.subject());
        let verification = self
            .verification
            .passive()
            .verify_snapshot(&case, &snapshot)?;
        self.finalize_outcome(knowledge, experience, session, verification, &snapshot)
    }

    /// Evaluates evidence produced by an explicit active verification probe.
    pub fn submit_active(
        &self,
        knowledge: &KnowledgeBase,
        experience: &mut ExperienceStore,
        session: &mut DecisionSession,
        baseline: &KnowledgeSnapshot,
        after_probe: &KnowledgeSnapshot,
    ) -> Result<DecisionOutcomeReport, DecisionLoopError> {
        let case = match session.state() {
            DecisionLoopState::AwaitingActive { case } => case.clone(),
            state => {
                return Err(DecisionLoopError::InvalidTransition {
                    operation: "submit active evidence",
                    state: state.name(),
                })
            },
        };
        let verification =
            self.verification
                .active()
                .verify_snapshots(&case, baseline, after_probe)?;
        self.finalize_outcome(knowledge, experience, session, verification, after_probe)
    }

    fn finalize_outcome(
        &self,
        knowledge: &KnowledgeBase,
        experience: &mut ExperienceStore,
        session: &mut DecisionSession,
        verification: VerificationReport,
        snapshot: &KnowledgeSnapshot,
    ) -> Result<DecisionOutcomeReport, DecisionLoopError> {
        let outcome = verification.outcome();
        let mut candidate_experience = experience.clone();
        let experience_write = candidate_experience.observe(outcome.clone())?;
        let suppressions =
            combined_suppressions(&candidate_experience, session, self.config.experience);
        let mut candidate_session = session.clone();
        let adaptive = self.adaptive.decide_and_record_with_suppressed_actions(
            outcome,
            snapshot,
            &mut candidate_session.adaptation,
            self.config.adaptation,
            &suppressions,
        )?;
        let command = transition_from_adaptive(
            &mut candidate_session,
            self.config.max_action_cycles,
            outcome,
            adaptive.directive(),
        )?;
        let hypothesis_write = apply_outcome(knowledge, outcome)?;

        *experience = candidate_experience;
        *session = candidate_session;
        Ok(DecisionOutcomeReport {
            verification,
            adaptive,
            experience_write,
            hypothesis_write,
            command,
        })
    }
}

fn require_state(
    session: &DecisionSession,
    operation: &'static str,
    predicate: impl FnOnce(&DecisionLoopState) -> bool,
) -> Result<(), DecisionLoopError> {
    if predicate(session.state()) {
        Ok(())
    } else {
        Err(DecisionLoopError::InvalidTransition {
            operation,
            state: session.state.name(),
        })
    }
}

fn combined_suppressions(
    experience: &ExperienceStore,
    session: &DecisionSession,
    policy: ExperiencePolicy,
) -> BTreeSet<String> {
    let mut suppressions = experience.suppressed_actions(session.subject(), policy);
    suppressions.extend(session.adaptation.suppressed_actions().iter().cloned());
    suppressions
}

fn next_case(
    session: &DecisionSession,
    action_id: &str,
    hypothesis_id: &str,
    origin: &str,
) -> Result<VerificationCase, DecisionLoopError> {
    let next_cycle = session
        .action_cycles
        .checked_add(1)
        .ok_or(DecisionLoopError::ActionCycleOverflow)?;
    Ok(VerificationCase::new(
        format!("case:decision:{next_cycle}:{origin}:{action_id}"),
        session.subject.clone(),
        action_id,
        hypothesis_id,
    )?)
}

fn issue_action(
    session: &mut DecisionSession,
    max_action_cycles: u32,
    case: VerificationCase,
    executor: Option<String>,
    origin: DecisionActionOrigin,
    delay_ms: Option<u64>,
) -> DecisionLoopCommand {
    if session.action_cycles >= max_action_cycles {
        let reason = DecisionStopReason::ActionCycleLimit;
        session.state = DecisionLoopState::Halted { reason };
        return DecisionLoopCommand::Halt { reason };
    }
    session.action_cycles += 1;
    session.state = DecisionLoopState::AwaitingPassive { case: case.clone() };
    DecisionLoopCommand::ExecuteAction {
        case,
        executor,
        origin,
        delay_ms,
    }
}

fn transition_from_adaptive(
    session: &mut DecisionSession,
    max_action_cycles: u32,
    outcome: &Outcome,
    directive: &PipelineDirective,
) -> Result<DecisionLoopCommand, DecisionLoopError> {
    match directive {
        PipelineDirective::Complete => {
            let case = case_from_outcome(outcome)?;
            session.state = DecisionLoopState::Completed;
            Ok(DecisionLoopCommand::Complete { case })
        },
        PipelineDirective::ScheduleAction { action_id } => {
            let case = next_case(session, action_id, outcome.hypothesis_id(), "adaptive")?;
            Ok(issue_action(
                session,
                max_action_cycles,
                case,
                None,
                DecisionActionOrigin::Adaptive,
                None,
            ))
        },
        PipelineDirective::Replan { .. } => {
            session.state = DecisionLoopState::Ready;
            Ok(DecisionLoopCommand::Replan)
        },
        PipelineDirective::Throttle {
            delay_ms,
            retry_current_action: true,
        } => {
            let case = next_case(
                session,
                outcome.action_id(),
                outcome.hypothesis_id(),
                "retry",
            )?;
            Ok(issue_action(
                session,
                max_action_cycles,
                case,
                None,
                DecisionActionOrigin::Retry,
                Some(*delay_ms),
            ))
        },
        PipelineDirective::Throttle {
            retry_current_action: false,
            ..
        } => {
            session.state = DecisionLoopState::Ready;
            Ok(DecisionLoopCommand::Replan)
        },
        PipelineDirective::AwaitActiveVerification => {
            let case = case_from_outcome(outcome)?;
            session.state = DecisionLoopState::AwaitingActive { case: case.clone() };
            Ok(DecisionLoopCommand::CollectActiveEvidence { case })
        },
        PipelineDirective::AwaitHumanReview => {
            let case = case_from_outcome(outcome)?;
            let reason = DecisionStopReason::HumanReview;
            session.state = DecisionLoopState::Halted { reason };
            Ok(DecisionLoopCommand::AwaitHumanReview { case })
        },
        PipelineDirective::Halt => {
            let reason = DecisionStopReason::AdaptationLimit;
            session.state = DecisionLoopState::Halted { reason };
            Ok(DecisionLoopCommand::Halt { reason })
        },
    }
}

fn case_from_outcome(outcome: &Outcome) -> Result<VerificationCase, VerificationError> {
    VerificationCase::new(
        outcome.case_id(),
        outcome.subject().clone(),
        outcome.action_id(),
        outcome.hypothesis_id(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ActionCost, AttackAction, BenefitScore, EvidenceCalibration, EvidenceSelector, Expression,
        HypothesisConclusion, HypothesisSelector, KnowledgeLayer, ReasoningRule, RequiredStrength,
        RiskScore, VerificationRule,
    };
    use venom_core::{
        ConfidenceScore, Evidence, EvidenceKind, EvidenceSource, EvidenceValue, HypothesisState,
        HypothesisStrength, KnowledgePredicate, OutcomeStatus, Probability, VerificationStage,
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
        decision_loop
            .planner_mut()
            .register(
                AttackAction::new(
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
                .unwrap(),
            )
            .unwrap();
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

    fn execution_case(command: &DecisionLoopCommand) -> VerificationCase {
        match command {
            DecisionLoopCommand::ExecuteAction { case, .. } => case.clone(),
            other => panic!("expected execute action, got {other:?}"),
        }
    }

    #[test]
    fn blocked_action_adapts_once_then_experience_stops_repetition() {
        let decision_loop = configured_loop(Some(OutcomeStatus::Blocked), 1, 8);
        let knowledge = knowledge(true);
        let mut experience = ExperienceStore::new();
        let mut session = DecisionSession::new(subject());

        let planning = decision_loop
            .plan_next(&knowledge, &experience, &mut session)
            .unwrap();
        assert_eq!(planning.rule_applications().len(), 1);
        assert_eq!(planning.plan().steps().len(), 1);
        assert!(planning.suppressed_actions().is_empty());
        assert!(matches!(
            planning.command(),
            DecisionLoopCommand::ExecuteAction {
                origin: DecisionActionOrigin::Planned,
                executor: Some(executor),
                ..
            } if executor == "plugin.http-probe"
        ));

        let first = decision_loop
            .submit_passive(&knowledge, &mut experience, &mut session)
            .unwrap();
        assert_eq!(first.adaptive().selected_rule_id(), Some("http.403.bypass"));
        assert!(matches!(
            first.command(),
            DecisionLoopCommand::ExecuteAction {
                case,
                origin: DecisionActionOrigin::Adaptive,
                executor: None,
                delay_ms: None,
            } if case.action_id() == "http.403-bypass"
        ));
        assert_eq!(session.action_cycles(), 2);

        let second = decision_loop
            .submit_passive(&knowledge, &mut experience, &mut session)
            .unwrap();
        assert!(second.adaptive().selected_rule_id().is_none());
        assert!(matches!(
            second.command(),
            DecisionLoopCommand::AwaitHumanReview { case }
                if case.action_id() == "http.403-bypass"
        ));
        assert!(matches!(
            session.state(),
            DecisionLoopState::Halted {
                reason: DecisionStopReason::HumanReview
            }
        ));
        assert_eq!(experience.len(), 2);
        assert!(experience
            .suppressed_actions(&subject(), ExperiencePolicy::new(1).unwrap())
            .contains("http.403-bypass"));
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
            .submit_passive(&knowledge, &mut experience, &mut session)
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
            .submit_active(
                &knowledge,
                &mut experience,
                &mut session,
                &baseline,
                &after_probe,
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
    fn false_positive_replans_with_the_source_action_suppressed() {
        let decision_loop = configured_loop(Some(OutcomeStatus::FalsePositive), 10, 8);
        let knowledge = knowledge(true);
        let mut experience = ExperienceStore::new();
        let mut session = DecisionSession::new(subject());
        decision_loop
            .plan_next(&knowledge, &experience, &mut session)
            .unwrap();

        let rejected = decision_loop
            .submit_passive(&knowledge, &mut experience, &mut session)
            .unwrap();
        let hypothesis_id = rejected.verification().outcome().hypothesis_id().to_owned();
        assert!(matches!(rejected.command(), DecisionLoopCommand::Replan));
        assert!(session
            .adaptation()
            .suppressed_actions()
            .contains("http.probe"));
        assert_eq!(rejected.hypothesis_write(), Some(KnowledgeWrite::Updated));

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
            .submit_passive(&knowledge, &mut experience, &mut session)
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
        wrong_subject["state"]["case"]["subject"] =
            serde_json::json!("endpoint:https://other.test");
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
}
