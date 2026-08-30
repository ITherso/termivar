use std::collections::BTreeSet;

use thiserror::Error;

use super::{model::ExclusionReason, PlannerError};

/// Current host-owned action suppressions, preserving their authority source.
///
/// This stays crate-private until the assessment/profile contract settles. The
/// existing public APIs remain compatibility wrappers that populate only the
/// policy set, while runtime composition can carry defense suppressions without
/// conflating them with operator, experience, or adaptive policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ActionSuppressionContext {
    policy_suppressed_actions: BTreeSet<String>,
    defense_suppressed_actions: BTreeSet<String>,
}

impl ActionSuppressionContext {
    pub(crate) fn new(
        policy_suppressed_actions: BTreeSet<String>,
        defense_suppressed_actions: BTreeSet<String>,
    ) -> Self {
        Self {
            policy_suppressed_actions,
            defense_suppressed_actions,
        }
    }

    pub(crate) fn policy_only(policy_suppressed_actions: &BTreeSet<String>) -> Self {
        Self::new(policy_suppressed_actions.clone(), BTreeSet::new())
    }

    pub(crate) fn policy_suppressed_actions(&self) -> &BTreeSet<String> {
        &self.policy_suppressed_actions
    }

    pub(crate) fn defense_suppressed_actions(&self) -> &BTreeSet<String> {
        &self.defense_suppressed_actions
    }
}

/// Why a registered action could not be authorized for immediate adaptive
/// dispatch.
///
/// This stays crate-private because it is an orchestration boundary between the
/// planner and decision loop, not a second public planning API.
#[derive(Debug, Error)]
pub(crate) enum ScheduledActionAuthorizationError {
    /// The registered action graph was invalid or requirement evaluation failed.
    #[error(transparent)]
    Planner(#[from] PlannerError),

    /// Adaptive policy referenced an action outside the planner registry.
    #[error("scheduled action {action_id} is not registered")]
    Unregistered {
        /// Unknown action identity.
        action_id: String,
    },

    /// Immediate dispatch cannot prove that prerequisites have already run.
    #[error("scheduled action {action_id} has prerequisites and cannot be dispatched directly")]
    HasPrerequisites {
        /// Registered action identity.
        action_id: String,
    },

    /// The normal planner eligibility policy excluded the requested action.
    #[error("scheduled action {action_id} is not authorized: {reason:?}")]
    Excluded {
        /// Registered action identity.
        action_id: String,
        /// Exact planner exclusion that denied authority.
        reason: ExclusionReason,
    },
}
