//! Side-effect-free commands emitted by the decision state machine.

use super::{Deserialize, Serialize, VerificationCase};

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

pub(crate) fn command_requiring_host_policy_context(
    command: &DecisionLoopCommand,
) -> Option<&'static str> {
    match command {
        DecisionLoopCommand::ExecuteAction {
            origin: DecisionActionOrigin::Adaptive,
            ..
        } => Some("adaptive_execute_action"),
        DecisionLoopCommand::ExecuteAction {
            origin: DecisionActionOrigin::Retry,
            ..
        } => Some("retry_execute_action"),
        DecisionLoopCommand::CollectActiveEvidence { .. } => Some("collect_active_evidence"),
        DecisionLoopCommand::Replan => Some("replan"),
        DecisionLoopCommand::ExecuteAction { .. }
        | DecisionLoopCommand::Complete { .. }
        | DecisionLoopCommand::AwaitHumanReview { .. }
        | DecisionLoopCommand::Halt { .. } => None,
    }
}

pub(crate) fn execution_command_action_id(command: &DecisionLoopCommand) -> Option<&str> {
    match command {
        DecisionLoopCommand::ExecuteAction { case, .. }
        | DecisionLoopCommand::CollectActiveEvidence { case } => Some(case.action_id()),
        DecisionLoopCommand::Replan
        | DecisionLoopCommand::Complete { .. }
        | DecisionLoopCommand::AwaitHumanReview { .. }
        | DecisionLoopCommand::Halt { .. } => None,
    }
}
