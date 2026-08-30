//! Immutable pre-commit failure and committed-evidence receipts.

use super::{
    DecisionActionOrigin, DecisionExecutionFailureKind, DecisionExecutionLimits,
    DecisionExecutionRequest, DecisionExecutionStage, DecisionLoopCommand, DecisionOutcomeReport,
    DecisionPlanningReport, Evidence, KnowledgeSnapshot, KnowledgeWrite, RuntimeLimitExceeded,
    Serialize, VerificationCase,
};

/// Immutable audit receipt for an executor-reported pre-commit failure.
///
/// The receipt exists only after an executor was resolved and returned
/// [`super::DecisionExecutorError`]. It does not represent route lookup, evidence
/// validation, knowledge storage, or runtime wall-time failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecisionExecutionFailureReceipt {
    pub(super) request: DecisionExecutionRequest,
    pub(super) executor_id: String,
    pub(super) diagnostic: String,
    pub(super) kind: DecisionExecutionFailureKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) runtime_limit: Option<RuntimeLimitExceeded>,
}

impl DecisionExecutionFailureReceipt {
    /// Returns the exact immutable request presented to the executor.
    pub fn request(&self) -> &DecisionExecutionRequest {
        &self.request
    }

    /// Returns the verification case whose action failed to execute.
    pub fn case(&self) -> &VerificationCase {
        self.request.case()
    }

    /// Returns the stable planned action identity.
    pub fn action_id(&self) -> &str {
        self.request.case().action_id()
    }

    /// Returns whether passive or active evidence was requested.
    pub fn stage(&self) -> DecisionExecutionStage {
        self.request.stage()
    }

    /// Returns the source of a passive action request.
    pub fn origin(&self) -> Option<DecisionActionOrigin> {
        self.request.origin()
    }

    /// Returns the scheduler delay honored before the failed execution.
    pub fn delay_ms(&self) -> Option<u64> {
        self.request.delay_ms()
    }

    /// Returns the host-owned resource allowances applied to the execution.
    pub fn limits(&self) -> DecisionExecutionLimits {
        self.request.limits()
    }

    /// Returns the resolved executor identity.
    pub fn executor_id(&self) -> &str {
        &self.executor_id
    }

    /// Returns the executor-supplied stable diagnostic.
    pub fn diagnostic(&self) -> &str {
        &self.diagnostic
    }

    /// Returns the structured reason execution produced no evidence.
    pub fn kind(&self) -> DecisionExecutionFailureKind {
        self.kind
    }

    /// Returns the host resource limit that refused the dispatch, if any.
    pub fn runtime_limit(&self) -> Option<&RuntimeLimitExceeded> {
        self.runtime_limit.as_ref()
    }
}

/// A committed evidence batch and the snapshots needed by verification.
#[derive(Debug, Clone)]
pub struct DecisionEvidenceReceipt {
    pub(super) case: VerificationCase,
    pub(super) stage: DecisionExecutionStage,
    pub(super) executor_id: String,
    pub(super) evidence: Vec<Evidence>,
    pub(super) writes: Vec<KnowledgeWrite>,
    pub(super) baseline: Option<KnowledgeSnapshot>,
    pub(super) after_execution: KnowledgeSnapshot,
}

impl DecisionEvidenceReceipt {
    /// Returns the verification case whose action produced the evidence.
    pub fn case(&self) -> &VerificationCase {
        &self.case
    }

    /// Returns the verification stage collected by this execution.
    pub fn stage(&self) -> DecisionExecutionStage {
        self.stage
    }

    /// Returns the resolved executor identity.
    pub fn executor_id(&self) -> &str {
        &self.executor_id
    }

    /// Returns the exact evidence batch emitted by this execution.
    pub fn evidence(&self) -> &[Evidence] {
        &self.evidence
    }

    /// Returns one idempotent knowledge write result per emitted observation.
    pub fn writes(&self) -> &[KnowledgeWrite] {
        &self.writes
    }

    /// Iterates over the exact evidence/write set committed by this execution.
    ///
    /// The two values share one input-order position, so hosts do not need to
    /// reconstruct the atomic batch by indexing separate slices.
    pub fn write_set(&self) -> impl ExactSizeIterator<Item = (&Evidence, KnowledgeWrite)> + '_ {
        debug_assert_eq!(self.evidence.len(), self.writes.len());
        self.evidence.iter().zip(self.writes.iter().copied())
    }

    /// Returns the pre-probe snapshot for active verification.
    pub fn baseline(&self) -> Option<&KnowledgeSnapshot> {
        self.baseline.as_ref()
    }

    /// Returns the subject snapshot after the evidence batch was committed.
    pub fn after_execution(&self) -> &KnowledgeSnapshot {
        &self.after_execution
    }

    #[cfg(test)]
    pub(crate) fn with_test_committed_batch(
        &self,
        evidence: Vec<Evidence>,
        writes: Vec<KnowledgeWrite>,
        after_execution: KnowledgeSnapshot,
    ) -> Self {
        Self {
            case: self.case.clone(),
            stage: self.stage,
            executor_id: self.executor_id.clone(),
            evidence,
            writes,
            baseline: self.baseline.clone(),
            after_execution,
        }
    }
}

/// Result of executing one decision-loop command through the runner boundary.
#[derive(Debug)]
#[non_exhaustive]
pub enum DecisionRunnerTurn {
    /// A `Replan` command completed reasoning and utility planning.
    Planning(Box<DecisionPlanningReport>),
    /// An action was executed, recorded, and evaluated by a verifier.
    Outcome {
        /// Audit receipt for the committed observations.
        evidence: Box<DecisionEvidenceReceipt>,
        /// Verification, adaptive-policy, and next-command report.
        decision: Box<DecisionOutcomeReport>,
    },
    /// A terminal or human-review command requires no executor work.
    Terminal(DecisionLoopCommand),
}
