//! Replayable session state and transition summaries.

use super::*;

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
    pub(super) fn name(&self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::AwaitingPassive { .. } => "awaiting_passive",
            Self::AwaitingActive { .. } => "awaiting_active",
            Self::Completed => "completed",
            Self::Halted { .. } => "halted",
        }
    }

    pub(super) fn case(&self) -> Option<&VerificationCase> {
        match self {
            Self::AwaitingPassive { case } | Self::AwaitingActive { case } => Some(case),
            Self::Ready | Self::Completed | Self::Halted { .. } => None,
        }
    }
}

/// Target-scoped counters and adaptive ledger for deterministic replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecisionSession {
    pub(super) subject: EntityId,
    pub(super) action_cycles: u32,
    pub(super) state: DecisionLoopState,
    pub(super) adaptation: AdaptationLedger,
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

    /// Returns an outstanding execution to the planning boundary after the
    /// host's current defense authority suppresses it before dispatch.
    ///
    /// The issued-action counter remains monotonic: the command was already
    /// authorized and emitted even though the runner correctly performed no
    /// side effect. The next plan must use the same defense context and can
    /// therefore only choose from the filtered baseline.
    pub(crate) fn replan_after_defense_suppression(&mut self) -> Result<(), DecisionLoopError> {
        match &self.state {
            DecisionLoopState::AwaitingPassive { .. }
            | DecisionLoopState::AwaitingActive { .. } => {
                self.state = DecisionLoopState::Ready;
                Ok(())
            },
            _ => Err(DecisionLoopError::InvalidTransition {
                operation: "replan after defense suppression",
                state: self.state.name(),
            }),
        }
    }

    /// Finalizes a multi-objective session as completed at the aggregate
    /// boundary, once automated work is exhausted with at least one success and
    /// no unresolved case. Narrow host helper — not a general session resume.
    pub(crate) fn finalize_objective_complete(&mut self) {
        self.state = DecisionLoopState::Completed;
    }

    /// Finalizes a multi-objective session as pending human review at the
    /// aggregate boundary, once automated work is exhausted while at least one
    /// unresolved (blocked / active-inconclusive) case remains. Narrow host
    /// helper — not a general session resume.
    pub(crate) fn finalize_human_review(&mut self) {
        self.state = DecisionLoopState::Halted {
            reason: DecisionStopReason::HumanReview,
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
    pub(super) state: DecisionLoopState,
    pub(super) action_cycles: u32,
    pub(super) adaptation_transitions: u32,
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
    pub(super) before: DecisionSessionSummary,
    pub(super) after: DecisionSessionSummary,
}

impl DecisionSessionTransition {
    pub(super) fn new(before: DecisionSessionSummary, after: DecisionSessionSummary) -> Self {
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
