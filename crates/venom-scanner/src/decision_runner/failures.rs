//! Typed execution and runner failure boundaries.

use super::{
    DecisionEvidenceReceipt, DecisionExecutionFailureReceipt, DecisionExecutionRequest,
    DecisionExecutionStage, DecisionLoopError, DecisionReasoningCommitReceipt, Deserialize,
    EntityId, Error, KnowledgeBaseError, PayloadStrategyRef, RuntimeLimitExceeded, Serialize,
};

/// Failure reported by an isolated action executor.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{message}")]
pub struct DecisionExecutorError {
    message: String,
    kind: DecisionExecutionFailureKind,
    receipt: Option<Box<DecisionExecutionFailureReceipt>>,
    runtime_limit: Option<Box<RuntimeLimitExceeded>>,
}

impl DecisionExecutorError {
    /// Creates a generic executor failure with a stable diagnostic.
    ///
    /// This compatibility constructor classifies the failure as
    /// [`DecisionExecutionFailureKind::ExecutorFailure`]. Executors with
    /// structured failure provenance should use [`Self::with_kind`].
    pub fn new(message: impl Into<String>) -> Self {
        Self::with_kind(DecisionExecutionFailureKind::ExecutorFailure, message)
    }

    /// Creates an executor failure with an explicit, transport-neutral kind.
    pub fn with_kind(kind: DecisionExecutionFailureKind, message: impl Into<String>) -> Self {
        let message = message.into();
        Self {
            message: if message.trim().is_empty() {
                "executor failed without a diagnostic".to_owned()
            } else {
                message
            },
            kind,
            receipt: None,
            runtime_limit: None,
        }
    }

    pub(crate) fn from_runtime_limit(limit: RuntimeLimitExceeded) -> Self {
        Self {
            message: limit.to_string(),
            kind: DecisionExecutionFailureKind::BlockedByPolicy,
            receipt: None,
            runtime_limit: Some(Box::new(limit)),
        }
    }

    /// Returns the executor-supplied diagnostic.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the structured failure classification supplied by the executor.
    pub fn kind(&self) -> DecisionExecutionFailureKind {
        self.kind
    }

    /// Returns runner-owned execution context when this error crossed the
    /// [`super::DecisionRunnerAdapter`] boundary.
    pub fn execution_failure(&self) -> Option<&DecisionExecutionFailureReceipt> {
        self.receipt.as_deref()
    }

    /// Returns the host resource limit that refused a transport dispatch.
    pub fn runtime_limit(&self) -> Option<&RuntimeLimitExceeded> {
        self.runtime_limit.as_deref()
    }

    pub(super) fn with_execution_context(
        mut self,
        request: DecisionExecutionRequest,
        executor_id: String,
    ) -> Self {
        self.receipt = Some(Box::new(DecisionExecutionFailureReceipt {
            request,
            executor_id,
            diagnostic: self.message.clone(),
            kind: self.kind,
            runtime_limit: self.runtime_limit.as_deref().cloned(),
        }));
        self
    }

    fn into_execution_failure(self) -> Option<DecisionExecutionFailureReceipt> {
        self.receipt.map(|receipt| *receipt)
    }

    fn into_runtime_limit(self) -> Option<RuntimeLimitExceeded> {
        self.runtime_limit.map(|limit| *limit)
    }
}

/// Transport-neutral reason an executor reported failure before evidence commit.
///
/// These classifications are audit facts only. They do not create verifier
/// outcomes or directly influence Experience Store suppression policy. Route
/// resolution, evidence provenance validation, knowledge writes, and host
/// wall-time enforcement remain separate runner or runtime failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DecisionExecutionFailureKind {
    /// The selected action does not apply to the decision subject.
    NotApplicable,
    /// Host authorization or safety policy refused the execution.
    BlockedByPolicy,
    /// Network transport failed before evidence could be collected.
    TransportFailure,
    /// A host-bounded request or response-body read exceeded its deadline.
    RequestTimeout,
    /// The executor failed independently of target transport.
    ExecutorFailure,
}

/// Failures raised while resolving, executing, or recording a command.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DecisionRunnerError {
    /// A registry or route identity was empty.
    #[error("{field} must not be empty")]
    EmptyValue { field: &'static str },

    /// An executor ID was registered twice.
    #[error("executor identity {executor_id} is already registered")]
    ExecutorIdentityConflict { executor_id: String },

    /// One action-stage pair was routed to two different executors.
    #[error("{stage} action {action_id} already has a different executor route")]
    ActionRouteConflict {
        /// Verification stage of the conflicting route.
        stage: DecisionExecutionStage,
        /// Action whose route was reused.
        action_id: String,
    },

    /// An explicit or routed executor was absent.
    #[error("decision executor {executor_id} is not registered")]
    UnknownExecutor { executor_id: String },

    /// An action-only command had no stage route.
    #[error("{stage} action {action_id} has no executor route")]
    MissingActionRoute {
        /// Verification stage being resolved.
        stage: DecisionExecutionStage,
        /// Action lacking a route.
        action_id: String,
    },

    /// The resolved executor cannot materialize the planner-selected strategy.
    #[error("decision executor {executor_id} does not support payload strategy {strategy}")]
    UnsupportedPayloadStrategy {
        /// Resolved executor identity.
        executor_id: String,
        /// Exact strategy revision selected by the planner.
        strategy: PayloadStrategyRef,
    },

    /// A non-execution command was passed to the low-level execution API.
    #[error("command {command} does not execute an action")]
    NonExecutionCommand { command: &'static str },

    /// The supplied command does not match the outstanding session case.
    #[error("command case {actual} does not match outstanding case {expected}")]
    CommandCaseMismatch { expected: String, actual: String },

    /// The supplied command does not match the session verification stage.
    #[error("cannot execute {expected} evidence while decision session is {actual}")]
    UnexpectedSessionState {
        /// Stage required by the command.
        expected: DecisionExecutionStage,
        /// Stable session state name.
        actual: &'static str,
    },

    /// An active execution receipt violated an adapter-owned invariant.
    #[error("active execution receipt did not capture a baseline snapshot")]
    MissingActiveBaseline,

    /// A high-level continuation command was supplied without the current
    /// host-owned suppression context.
    #[error("command {command} requires explicit host suppression context before execution")]
    HostPolicyContextRequired {
        /// Stable command class rejected before any executor work.
        command: &'static str,
    },

    /// Current host policy suppressed the outstanding action before dispatch.
    #[error("host policy suppresses action {action_id} before execution")]
    ActionSuppressedByHostPolicy {
        /// Action rejected before executor work or evidence commit.
        action_id: String,
    },

    /// Current defense enforcement suppressed the action before dispatch.
    #[error("defense enforcement suppresses action {action_id} before execution")]
    ActionSuppressedByDefense {
        /// Action rejected before executor work or evidence commit.
        action_id: String,
    },

    /// Executor evidence described another subject.
    #[error("evidence {evidence_id} subject {actual} does not match case subject {expected}")]
    EvidenceSubjectMismatch {
        /// Rejected evidence identity.
        evidence_id: String,
        /// Case subject.
        expected: EntityId,
        /// Evidence subject.
        actual: EntityId,
    },

    /// Executor evidence claimed another producing component.
    #[error("evidence {evidence_id} source {actual} does not match executor {expected}")]
    EvidenceSourceMismatch {
        /// Rejected evidence identity.
        evidence_id: String,
        /// Resolved executor identity.
        expected: String,
        /// Evidence source component.
        actual: String,
    },

    /// Executor evidence omitted or changed the verification correlation ID.
    #[error("evidence {evidence_id} correlation does not match case {expected}")]
    EvidenceCorrelationMismatch {
        /// Rejected evidence identity.
        evidence_id: String,
        /// Required case correlation identity.
        expected: String,
        /// Supplied correlation identity, if any.
        actual: Option<String>,
    },

    /// An isolated executor failed.
    #[error("decision executor {executor_id} failed: {source}")]
    Executor {
        /// Executor selected for the request.
        executor_id: String,
        /// Isolated executor diagnostic.
        #[source]
        source: DecisionExecutorError,
    },

    /// Evidence committed successfully but the subsequent decision transition failed.
    #[error("decision transition failed after evidence was committed: {source}")]
    OutcomeAfterEvidenceCommit {
        /// Durable append-only evidence commit token.
        receipt: Box<DecisionEvidenceReceipt>,
        /// Failure raised while resuming the state machine.
        #[source]
        source: Box<DecisionRunnerError>,
    },

    /// Atomic evidence storage failed.
    #[error(transparent)]
    Knowledge(#[from] KnowledgeBaseError),

    /// Resuming the deterministic state machine failed.
    #[error(transparent)]
    Decision(#[from] DecisionLoopError),
}

impl DecisionRunnerError {
    /// Returns the host resource limit reported by an executor, when applicable.
    pub fn runtime_limit(&self) -> Option<&RuntimeLimitExceeded> {
        match self {
            Self::Executor { source, .. } => source.runtime_limit(),
            _ => None,
        }
    }

    /// Takes an executor-reported host resource limit without cloning it.
    pub fn into_runtime_limit(self) -> Option<RuntimeLimitExceeded> {
        match self {
            Self::Executor { source, .. } => source.into_runtime_limit(),
            _ => None,
        }
    }

    /// Returns an executor-reported pre-commit failure receipt, when applicable.
    pub fn execution_failure(&self) -> Option<&DecisionExecutionFailureReceipt> {
        match self {
            Self::Executor { source, .. } => source.execution_failure(),
            _ => None,
        }
    }

    /// Takes ownership of an executor-reported failure receipt without cloning it.
    pub fn into_execution_failure(self) -> Option<DecisionExecutionFailureReceipt> {
        match self {
            Self::Executor { source, .. } => source.into_execution_failure(),
            _ => None,
        }
    }

    /// Returns evidence that was committed before this error, when applicable.
    pub fn committed_evidence(&self) -> Option<&DecisionEvidenceReceipt> {
        match self {
            Self::OutcomeAfterEvidenceCommit { receipt, .. } => Some(receipt),
            _ => None,
        }
    }

    /// Takes ownership of evidence committed before this error without cloning it.
    pub fn into_committed_evidence(self) -> Option<DecisionEvidenceReceipt> {
        match self {
            Self::OutcomeAfterEvidenceCommit { receipt, .. } => Some(*receipt),
            _ => None,
        }
    }

    /// Returns reasoning committed before a later planning failure, when applicable.
    pub fn committed_reasoning(&self) -> Option<&DecisionReasoningCommitReceipt> {
        match self {
            Self::Decision(source) => source.committed_reasoning(),
            Self::OutcomeAfterEvidenceCommit { source, .. } => source.committed_reasoning(),
            _ => None,
        }
    }

    /// Takes a post-reasoning planning receipt without cloning it.
    pub fn into_committed_reasoning(self) -> Option<DecisionReasoningCommitReceipt> {
        match self {
            Self::Decision(source) => source.into_committed_reasoning(),
            Self::OutcomeAfterEvidenceCommit { source, .. } => source.into_committed_reasoning(),
            _ => None,
        }
    }
}
