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
    AdaptationLedger, AdaptationLimits, AdaptiveDecision, AdaptivePipeline, AdaptivePipelineError,
    AttackPlan, AttackPlanner, ExperiencePolicy, ExperienceStore, ExperienceStoreError,
    ExperienceWrite, KnowledgeBase, KnowledgeBaseError, KnowledgeSnapshot, KnowledgeWrite,
    PipelineDirective, PlannerError, PlanningContext, RuleApplication, RuleEngine, RuleEngineError,
    VerificationCase, VerificationError, VerificationPipeline, VerificationReport,
};

/// Reasoning applications committed before a later planning-stage failure.
///
/// This receipt describes one successful in-memory [`RuleEngine::apply`]
/// transaction and its exact [`KnowledgeWrite`] statuses. It does not imply
/// durable persistence. A rule evaluation remains the pre-commit candidate;
/// hosts must query the knowledge base when verifier-owned terminal-state
/// preservation makes the stored hypothesis relevant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecisionReasoningCommitReceipt {
    subject: EntityId,
    planner_subject_revision: u64,
    planner_ontology_revision: u64,
    rule_applications: Vec<RuleApplication>,
}

impl DecisionReasoningCommitReceipt {
    /// Returns the subject whose hypotheses were evaluated and committed.
    pub fn subject(&self) -> &EntityId {
        &self.subject
    }

    /// Returns the subject revision captured by the attempted planner snapshot.
    pub fn planner_subject_revision(&self) -> u64 {
        self.planner_subject_revision
    }

    /// Returns the ontology revision captured by the attempted planner snapshot.
    pub fn planner_ontology_revision(&self) -> u64 {
        self.planner_ontology_revision
    }

    /// Returns deterministic applications and their exact write results.
    pub fn rule_applications(&self) -> &[RuleApplication] {
        &self.rule_applications
    }
}

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

    /// Knowledge changed after the planner captured its decision snapshot.
    #[error("planning snapshot became stale: {source}")]
    StalePlanningSnapshot {
        /// Exact revision mismatch detected before the session commit.
        #[source]
        source: KnowledgeBaseError,
    },

    /// Reasoning committed hypotheses before a later planning operation failed.
    #[error("planning failed after reasoning was committed: {source}")]
    PlanningAfterReasoningCommit {
        /// Exact rule applications committed before the failure.
        receipt: Box<DecisionReasoningCommitReceipt>,
        /// Planner or command-construction failure raised after the commit.
        #[source]
        source: Box<DecisionLoopError>,
    },
}

impl DecisionLoopError {
    /// Returns committed reasoning when this failure happened after hypothesis writes.
    pub fn committed_reasoning(&self) -> Option<&DecisionReasoningCommitReceipt> {
        match self {
            Self::PlanningAfterReasoningCommit { receipt, .. } => Some(receipt),
            _ => None,
        }
    }

    /// Takes the committed reasoning receipt without cloning it.
    pub fn into_committed_reasoning(self) -> Option<DecisionReasoningCommitReceipt> {
        match self {
            Self::PlanningAfterReasoningCommit { receipt, .. } => Some(*receipt),
            _ => None,
        }
    }
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
    /// Requested by a host runtime to establish initial observations.
    Bootstrap,
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
    /// A host runtime exhausted its side-effect resource envelope.
    RuntimeBudgetLimit,
    /// The host explicitly cancelled the target-scoped runtime.
    CancelledByHost,
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

    /// Stops an outstanding session when the host runtime refuses more work.
    pub(crate) fn halt_for_runtime_budget(&mut self) {
        self.state = DecisionLoopState::Halted {
            reason: DecisionStopReason::RuntimeBudgetLimit,
        };
    }

    /// Stops an outstanding session after an explicit host cancellation.
    pub(crate) fn halt_for_host_cancellation(&mut self) {
        self.state = DecisionLoopState::Halted {
            reason: DecisionStopReason::CancelledByHost,
        };
    }

    /// Returns the adaptive transition ledger.
    pub fn adaptation(&self) -> &AdaptationLedger {
        &self.adaptation
    }

    /// Captures a lightweight state summary at one outcome boundary.
    ///
    /// This intentionally omits the subject and full adaptation ledger. It is
    /// an audit summary for comparing one transition, not a persistence or
    /// replay snapshot.
    pub fn transition_summary(&self) -> DecisionSessionSummary {
        DecisionSessionSummary {
            state: self.state.clone(),
            action_cycles: self.action_cycles,
            adaptation_transitions: self.adaptation.transitions(),
        }
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

/// Lightweight audit summary captured around one outcome commit.
///
/// This is not a complete persistence or replay snapshot of a decision
/// session. The owning [`DecisionSession`] remains the source of that state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecisionSessionSummary {
    state: DecisionLoopState,
    action_cycles: u32,
    adaptation_transitions: u32,
}

impl DecisionSessionSummary {
    /// Returns the state at this commit boundary.
    pub fn state(&self) -> &DecisionLoopState {
        &self.state
    }

    /// Returns the number of issued action executions at this boundary.
    pub fn action_cycles(&self) -> u32 {
        self.action_cycles
    }

    /// Returns the number of recorded adaptive directives at this boundary.
    pub fn adaptation_transitions(&self) -> u32 {
        self.adaptation_transitions
    }
}

/// Before/after session summary produced by successful outcome processing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecisionSessionTransition {
    before: DecisionSessionSummary,
    after: DecisionSessionSummary,
}

impl DecisionSessionTransition {
    fn new(before: DecisionSessionSummary, after: DecisionSessionSummary) -> Self {
        Self { before, after }
    }

    /// Returns the session summary before verification and adaptation.
    pub fn before(&self) -> &DecisionSessionSummary {
        &self.before
    }

    /// Returns the session summary after successful outcome processing.
    pub fn after(&self) -> &DecisionSessionSummary {
        &self.after
    }
}

/// Audit record produced by a reasoning and planning turn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecisionPlanningReport {
    rule_applications: Vec<RuleApplication>,
    plan: AttackPlan,
    suppressed_actions: BTreeSet<String>,
    #[serde(skip_serializing)]
    session_transition: DecisionSessionTransition,
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

    /// Returns the session transition committed by this successful planning turn.
    ///
    /// This audit summary is intentionally excluded from the existing serialized
    /// planning-report shape.
    pub fn session_transition(&self) -> &DecisionSessionTransition {
        &self.session_transition
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
    #[serde(skip_serializing)]
    session_transition: DecisionSessionTransition,
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

    /// Returns the session transition applied during successful outcome processing.
    ///
    /// Candidate state makes normal returned-error paths error-atomic. This is
    /// not a cross-store or crash-atomic persistence guarantee.
    pub fn session_transition(&self) -> &DecisionSessionTransition {
        &self.session_transition
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
        self.plan_next_with_suppressed_actions(knowledge, experience, session, &BTreeSet::new())
    }

    /// Applies reasoning and planning while honoring host policy suppressions.
    ///
    /// Explicit suppressions are combined with experience and adaptive-session
    /// suppressions. They remain visible as policy exclusions in the returned
    /// planner audit record.
    pub fn plan_next_with_suppressed_actions(
        &self,
        knowledge: &KnowledgeBase,
        experience: &ExperienceStore,
        session: &mut DecisionSession,
        host_suppressed_actions: &BTreeSet<String>,
    ) -> Result<DecisionPlanningReport, DecisionLoopError> {
        self.plan_next_with_suppressed_actions_before_commit(
            knowledge,
            experience,
            session,
            host_suppressed_actions,
            |_| {},
        )
    }

    fn plan_next_with_suppressed_actions_before_commit<F>(
        &self,
        knowledge: &KnowledgeBase,
        experience: &ExperienceStore,
        session: &mut DecisionSession,
        host_suppressed_actions: &BTreeSet<String>,
        mut before_session_commit: F,
    ) -> Result<DecisionPlanningReport, DecisionLoopError>
    where
        F: FnMut(&KnowledgeSnapshot),
    {
        require_state(session, "plan", |state| {
            matches!(state, DecisionLoopState::Ready)
        })?;
        if session.action_cycles >= self.config.max_action_cycles {
            let mut candidate_session = session.clone();
            let reason = DecisionStopReason::ActionCycleLimit;
            candidate_session.state = DecisionLoopState::Halted { reason };
            let snapshot = knowledge.snapshot_for_subject(candidate_session.subject());
            let suppressions = combined_suppressions(
                experience,
                &candidate_session,
                self.config.experience,
                host_suppressed_actions,
            );
            let report = DecisionPlanningReport {
                rule_applications: Vec::new(),
                plan: self.planner.plan_snapshot_with_suppressed(
                    &snapshot,
                    self.config.planning,
                    &suppressions,
                )?,
                suppressed_actions: suppressions,
                session_transition: DecisionSessionTransition::new(
                    session.transition_summary(),
                    candidate_session.transition_summary(),
                ),
                command: DecisionLoopCommand::Halt { reason },
            };
            before_session_commit(&snapshot);
            knowledge
                .commit_if_snapshot_current(&snapshot, || *session = candidate_session)
                .map_err(|source| DecisionLoopError::StalePlanningSnapshot { source })?;
            return Ok(report);
        }

        let applications = self.rules.apply(knowledge, session.subject())?;
        let snapshot = knowledge.snapshot_for_subject(session.subject());
        let reasoning_changed = applications.iter().any(|application| {
            application
                .write()
                .is_some_and(|write| write != KnowledgeWrite::Unchanged)
        });
        let mut candidate_session = session.clone();
        let planning = (|| -> Result<
            (
                AttackPlan,
                BTreeSet<String>,
                DecisionSessionTransition,
                DecisionLoopCommand,
            ),
            DecisionLoopError,
        > {
            let suppressions = combined_suppressions(
                experience,
                &candidate_session,
                self.config.experience,
                host_suppressed_actions,
            );
            let plan = self.planner.plan_snapshot_with_suppressed(
                &snapshot,
                self.config.planning,
                &suppressions,
            )?;
            let command = if let Some(step) = plan.steps().first() {
                let case = next_case(
                    &candidate_session,
                    step.action_id(),
                    step.confidence_hypothesis_id(),
                    "planned",
                )?;
                issue_action(
                    &mut candidate_session,
                    self.config.max_action_cycles,
                    case,
                    Some(step.executor().to_owned()),
                    DecisionActionOrigin::Planned,
                    None,
                )
            } else {
                let reason = DecisionStopReason::NoEligibleAction;
                candidate_session.state = DecisionLoopState::Halted { reason };
                DecisionLoopCommand::Halt { reason }
            };
            let session_transition = DecisionSessionTransition::new(
                session.transition_summary(),
                candidate_session.transition_summary(),
            );
            Ok((plan, suppressions, session_transition, command))
        })();

        match planning {
            Ok((plan, suppressed_actions, session_transition, command)) => {
                before_session_commit(&snapshot);
                let commit = knowledge.commit_if_snapshot_current(&snapshot, || {
                    *session = candidate_session;
                });
                match commit {
                    Ok(()) => Ok(DecisionPlanningReport {
                        rule_applications: applications,
                        plan,
                        suppressed_actions,
                        session_transition,
                        command,
                    }),
                    Err(source) if reasoning_changed => {
                        Err(DecisionLoopError::PlanningAfterReasoningCommit {
                            receipt: Box::new(DecisionReasoningCommitReceipt {
                                subject: session.subject().clone(),
                                planner_subject_revision: snapshot.subject_revision(),
                                planner_ontology_revision: snapshot.ontology_revision(),
                                rule_applications: applications,
                            }),
                            source: Box::new(DecisionLoopError::StalePlanningSnapshot { source }),
                        })
                    },
                    Err(source) => Err(DecisionLoopError::StalePlanningSnapshot { source }),
                }
            },
            Err(source) if reasoning_changed => {
                Err(DecisionLoopError::PlanningAfterReasoningCommit {
                    receipt: Box::new(DecisionReasoningCommitReceipt {
                        subject: session.subject().clone(),
                        planner_subject_revision: snapshot.subject_revision(),
                        planner_ontology_revision: snapshot.ontology_revision(),
                        rule_applications: applications,
                    }),
                    source: Box::new(source),
                })
            },
            Err(source) => Err(source),
        }
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
        let before = session.transition_summary();
        let outcome = verification.outcome();
        let mut candidate_experience = experience.clone();
        let experience_write = candidate_experience.observe(outcome.clone())?;
        let suppressions = combined_suppressions(
            &candidate_experience,
            session,
            self.config.experience,
            &BTreeSet::new(),
        );
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
        let hypothesis_write = verification.apply(knowledge)?;
        let session_transition =
            DecisionSessionTransition::new(before, candidate_session.transition_summary());

        *experience = candidate_experience;
        *session = candidate_session;
        Ok(DecisionOutcomeReport {
            verification,
            adaptive,
            experience_write,
            hypothesis_write,
            session_transition,
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
    host_suppressed_actions: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut suppressions = experience.suppressed_actions(session.subject(), policy);
    suppressions.extend(session.adaptation.suppressed_actions().iter().cloned());
    suppressions.extend(host_suppressed_actions.iter().cloned());
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
        ActionCost, AttackAction, BenefitScore, EvidenceCalibration, EvidenceSelector,
        ExperienceDisposition, Expression, HypothesisConclusion, HypothesisSelector,
        KnowledgeLayer, ReasoningRule, RequiredStrength, RiskScore, VerificationRule,
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
                            EvidenceSource::new("concurrent.discovery", "late-observation")
                                .unwrap(),
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
            .submit_passive(&knowledge, &mut experience, &mut session)
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
            .submit_passive(&knowledge, &mut experience, &mut session)
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
            OutcomeStatus::ConfirmedNegative
        );
        assert_eq!(active.hypothesis_write(), Some(KnowledgeWrite::Updated));
        assert!(matches!(active.command(), DecisionLoopCommand::Replan));
        assert_eq!(
            knowledge.hypothesis(case.hypothesis_id()).unwrap().state(),
            HypothesisState::Rejected
        );
        let assessment =
            experience.assess(&subject(), "http.probe", ExperiencePolicy::new(1).unwrap());
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
            .submit_passive(&knowledge, &mut experience, &mut session)
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
