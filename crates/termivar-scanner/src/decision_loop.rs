//! Deterministic orchestration across reasoning, planning, verification, adaptation, and experience.
//!
//! ## Runtime scope
//!
//! - **Build:** default via `scanning`.
//! - **Execution:** Surface B (deterministic decision runtime).
//! - **Default `termivar scan`:** yes, through `StandardWebDecisionRuntime`.
//! - **Support:** implemented and tested.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! The decision loop is a state machine, not an executor. It mutates only the
//! knowledge, adaptive ledger, and experience records supplied by the host.
//! Network traffic, plugin execution, delays, and cancellation remain runner
//! responsibilities represented by explicit [`DecisionLoopCommand`] values.

use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize};
use termivar_core::{EntityId, Outcome};
use thiserror::Error;

use crate::planner::{ActionSuppressionContext, ScheduledActionAuthorizationError};
use crate::{
    AdaptationLedger, AdaptationLimits, AdaptiveDecision, AdaptivePipeline, AdaptivePipelineError,
    AttackPlan, AttackPlanner, ExperiencePolicy, ExperienceStore, ExperienceStoreError,
    ExperienceWrite, KnowledgeBase, KnowledgeBaseError, KnowledgeSnapshot, KnowledgeWrite,
    PayloadStrategyRef, PipelineDirective, PlannerError, PlanningContext,
    ResolvedVerificationTarget, RuleApplication, RuleEngine, RuleEngineError, VerificationCase,
    VerificationError, VerificationPipeline, VerificationReport,
};

mod command;
mod policy;
mod receipts;
mod state;

pub(crate) use command::{command_requiring_host_policy_context, execution_command_action_id};
pub use command::{DecisionActionOrigin, DecisionLoopCommand, DecisionStopReason};
#[cfg(test)]
use policy::transition_from_adaptive;
pub use policy::DecisionLoop;
pub use receipts::{DecisionOutcomeReport, DecisionPlanningReport, DecisionReasoningCommitReceipt};
pub use state::{
    DecisionLoopState, DecisionSession, DecisionSessionSummary, DecisionSessionTransition,
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

    /// An adaptively scheduled action declared a distinct verification target
    /// that was absent from the current immutable snapshot.
    #[error("scheduled action {action_id} has no eligible verification target")]
    NoEligibleScheduledVerificationTarget {
        /// Scheduled action whose target could not be resolved.
        action_id: String,
    },

    /// An adaptively scheduled action's own confidence source was absent from
    /// the current immutable snapshot.
    #[error("scheduled action {action_id} has no eligible motivation hypothesis")]
    NoEligibleScheduledMotivationHypothesis {
        /// Scheduled action whose confidence source could not be resolved.
        action_id: String,
    },

    /// Adaptive execution was requested without an explicit current host
    /// suppression context.
    #[error("adaptive execution of action {action_id} requires explicit host suppression context")]
    AdaptiveExecutionRequiresHostPolicyContext {
        /// Action whose adaptive continuation requires current host policy.
        action_id: String,
    },

    /// A decision case or adaptive policy named an unregistered action.
    #[error("decision action {action_id} is not registered with the planner")]
    UnregisteredDecisionAction {
        /// Unknown action identity.
        action_id: String,
    },

    /// A persisted case would authorize a broader claim transition than the
    /// currently registered action policy.
    #[error("decision case for action {action_id} exceeds current claim authority")]
    DecisionCaseAuthorityExceeded {
        /// Action whose transition target no longer authorizes the case claim.
        action_id: String,
    },

    /// A registered adaptive action failed current planner authorization.
    #[error("adaptive action {action_id} is not eligible under current planner policy")]
    IneligibleAdaptiveAction {
        /// Registered action excluded by current planner policy.
        action_id: String,
    },

    /// Current defense enforcement suppressed an adaptive, retry, or active action.
    #[error("defense enforcement suppresses action {action_id}")]
    DefenseSuppressedAction {
        /// Action rejected under the current defense context.
        action_id: String,
    },

    /// Direct adaptive dispatch would skip declared prerequisites.
    #[error(
        "adaptive action {action_id} declares prerequisites and must be selected by normal planning"
    )]
    AdaptiveActionRequiresPlanning {
        /// Adaptive action whose dependency order must be planned normally.
        action_id: String,
    },

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

pub(crate) struct ActiveEvidenceSnapshots<'a> {
    baseline: &'a KnowledgeSnapshot,
    after_probe: &'a KnowledgeSnapshot,
}

impl<'a> ActiveEvidenceSnapshots<'a> {
    pub(crate) const fn new(
        baseline: &'a KnowledgeSnapshot,
        after_probe: &'a KnowledgeSnapshot,
    ) -> Self {
        Self {
            baseline,
            after_probe,
        }
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

#[cfg(test)]
#[path = "decision_loop/decision_loop_tests.rs"]
mod tests;
