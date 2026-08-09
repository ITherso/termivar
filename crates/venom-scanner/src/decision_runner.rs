//! Runner boundary for executing deterministic decision-loop commands.
//!
//! ## Runtime scope
//!
//! - **Build:** default via `scanning`.
//! - **Execution:** Surface B (deterministic decision runtime).
//! - **Default `venom scan`:** no.
//! - **Support:** implemented and tested.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! The decision loop chooses an action; this module resolves its executor,
//! honors scheduler delays, records native evidence, and submits the resulting
//! snapshot to the correct verifier. Executors never receive the knowledge
//! base or decision policy, so plugins cannot bypass provenance checks or
//! mutate reasoning state directly.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use venom_core::{EntityId, Evidence};

use crate::{
    DecisionActionOrigin, DecisionLoop, DecisionLoopCommand, DecisionLoopError, DecisionLoopState,
    DecisionOutcomeReport, DecisionPlanningReport, DecisionReasoningCommitReceipt, DecisionSession,
    ExperienceStore, KnowledgeBase, KnowledgeBaseError, KnowledgeSnapshot, KnowledgeWrite,
    PayloadStrategyRef, RuntimeLimitExceeded, VerificationCase,
};

/// Verification stage whose evidence an executor must collect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DecisionExecutionStage {
    /// Evidence collected by the action selected by planning or adaptation.
    Passive,
    /// Fresh evidence collected by an explicit verification probe.
    Active,
}

impl std::fmt::Display for DecisionExecutionStage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Passive => "passive",
            Self::Active => "active",
        })
    }
}

/// Host-owned resource allowance attached to one isolated execution.
///
/// Executors may impose stricter policy limits. The allowance can only reduce
/// resource use; it never expands an executor's own security policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionExecutionLimits {
    max_response_body_bytes: Option<u64>,
}

impl DecisionExecutionLimits {
    /// Creates an unrestricted per-execution allowance.
    pub const fn new() -> Self {
        Self {
            max_response_body_bytes: None,
        }
    }

    /// Restricts the response body buffered by this execution.
    pub const fn with_max_response_body_bytes(mut self, limit: u64) -> Self {
        self.max_response_body_bytes = Some(limit);
        self
    }

    /// Returns the optional host-owned response buffer allowance.
    pub const fn max_response_body_bytes(self) -> Option<u64> {
        self.max_response_body_bytes
    }

    fn is_unrestricted(&self) -> bool {
        self.max_response_body_bytes.is_none()
    }
}

/// Immutable, transport-neutral request passed to one action executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecisionExecutionRequest {
    case: VerificationCase,
    stage: DecisionExecutionStage,
    origin: Option<DecisionActionOrigin>,
    delay_ms: Option<u64>,
    #[serde(skip_serializing_if = "DecisionExecutionLimits::is_unrestricted")]
    limits: DecisionExecutionLimits,
}

impl DecisionExecutionRequest {
    fn new(
        case: VerificationCase,
        stage: DecisionExecutionStage,
        origin: Option<DecisionActionOrigin>,
        delay_ms: Option<u64>,
        limits: DecisionExecutionLimits,
    ) -> Self {
        Self {
            case,
            stage,
            origin,
            delay_ms,
            limits,
        }
    }

    /// Returns the verification identity attached by the decision loop.
    pub fn case(&self) -> &VerificationCase {
        &self.case
    }

    /// Returns whether passive or active evidence is requested.
    pub fn stage(&self) -> DecisionExecutionStage {
        self.stage
    }

    /// Returns the source of a passive action request.
    pub fn origin(&self) -> Option<DecisionActionOrigin> {
        self.origin
    }

    /// Returns the scheduler delay already honored by the adapter.
    pub fn delay_ms(&self) -> Option<u64> {
        self.delay_ms
    }

    /// Returns host-owned resource allowances for this execution.
    pub const fn limits(&self) -> DecisionExecutionLimits {
        self.limits
    }

    /// Returns the exact planner-selected strategy revision, when present.
    pub const fn payload_strategy(&self) -> Option<&PayloadStrategyRef> {
        self.case.payload_strategy()
    }
}

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
    /// [`DecisionRunnerAdapter`] boundary.
    pub fn execution_failure(&self) -> Option<&DecisionExecutionFailureReceipt> {
        self.receipt.as_deref()
    }

    /// Returns the host resource limit that refused a transport dispatch.
    pub fn runtime_limit(&self) -> Option<&RuntimeLimitExceeded> {
        self.runtime_limit.as_deref()
    }

    fn with_execution_context(
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

/// Immutable audit receipt for an executor-reported pre-commit failure.
///
/// The receipt exists only after an executor was resolved and returned
/// [`DecisionExecutorError`]. It does not represent route lookup, evidence
/// validation, knowledge storage, or runtime wall-time failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecisionExecutionFailureReceipt {
    request: DecisionExecutionRequest,
    executor_id: String,
    diagnostic: String,
    kind: DecisionExecutionFailureKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime_limit: Option<RuntimeLimitExceeded>,
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

/// How a semantic action is executed: by touching the network, or purely from
/// already-committed immutable knowledge.
///
/// The runtime uses this to decide whether transport accounting and HTTP
/// response telemetry apply. It is declared explicitly by each executor and is
/// never inferred from executor IDs, action names, request methods, or whether a
/// broker happened to dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DecisionExecutionClass {
    /// The executor performs transport I/O (an HTTP probe) to observe evidence.
    TransportBound,
    /// The executor performs no transport I/O and derives evidence solely from
    /// an immutable, subject-scoped knowledge snapshot.
    LocalKnowledge,
}

/// Narrow execution API implemented by native collectors and plugin bridges.
///
/// The contract for what an executor may read is deliberately minimal:
///
/// - A [`DecisionExecutionClass::TransportBound`] executor (the default) runs
///   through [`execute`](Self::execute) and receives **no** reasoning state — no
///   `KnowledgeBase`, no snapshot, no decision policy.
/// - A [`DecisionExecutionClass::LocalKnowledge`] executor runs through
///   [`execute_with_snapshot`](Self::execute_with_snapshot) and may read **only**
///   an immutable, subject-scoped [`KnowledgeSnapshot`]. It never receives a
///   mutable `KnowledgeBase`: the runner remains the sole authority that
///   validates provenance and atomically commits any derived evidence.
#[async_trait]
pub trait DecisionActionExecutor: Send + Sync {
    /// Returns the stable identity used by planner executor fields and routes.
    fn id(&self) -> &str;

    /// Returns how this executor is driven. Defaults to
    /// [`DecisionExecutionClass::TransportBound`] so existing executors keep
    /// their current transport-accounted execution path unchanged.
    fn execution_class(&self) -> DecisionExecutionClass {
        DecisionExecutionClass::TransportBound
    }

    /// Returns whether this executor can materialize an exact strategy revision.
    ///
    /// The fail-closed default prevents a legacy executor from silently
    /// ignoring planner-selected strategy semantics.
    fn supports_payload_strategy(&self, _strategy: &PayloadStrategyRef) -> bool {
        false
    }

    /// Executes one semantic action request and returns immutable observations only.
    ///
    /// Every returned observation must describe `request.case().subject()`,
    /// identify this executor as its source component, and carry the case ID as
    /// its source correlation ID. The adapter rejects the complete batch when
    /// any observation violates that contract.
    async fn execute(
        &self,
        request: &DecisionExecutionRequest,
    ) -> Result<Vec<Evidence>, DecisionExecutorError>;

    /// Executes a [`DecisionExecutionClass::LocalKnowledge`] action from an
    /// immutable subject-scoped snapshot, returning immutable observations under
    /// the same provenance contract as [`execute`](Self::execute).
    ///
    /// This is additive: transport-bound executors never receive this call, so
    /// they need not implement it. It is deliberately **fail-closed** — the
    /// default returns a deterministic error rather than delegating to
    /// [`execute`](Self::execute). An executor that declares
    /// [`DecisionExecutionClass::LocalKnowledge`] but forgets to override this
    /// method therefore cannot silently run transport work while the runtime has
    /// already skipped request preflight, response accounting, and HTTP
    /// telemetry validation for it.
    async fn execute_with_snapshot(
        &self,
        request: &DecisionExecutionRequest,
        snapshot: &KnowledgeSnapshot,
    ) -> Result<Vec<Evidence>, DecisionExecutorError> {
        let _ = (request, snapshot);
        Err(DecisionExecutorError::new(
            "local-knowledge executor did not implement snapshot execution",
        ))
    }
}

/// Deterministic executor lookup used by the decision runner.
#[derive(Clone, Default)]
pub struct DecisionExecutorRegistry {
    executors: BTreeMap<String, Arc<dyn DecisionActionExecutor>>,
    routes: BTreeMap<(DecisionExecutionStage, String), String>,
}

impl DecisionExecutorRegistry {
    /// Creates an empty executor registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one executor identity.
    pub fn register(
        &mut self,
        executor: Arc<dyn DecisionActionExecutor>,
    ) -> Result<(), DecisionRunnerError> {
        let id = non_empty(executor.id(), "executor id")?;
        if self.executors.contains_key(&id) {
            return Err(DecisionRunnerError::ExecutorIdentityConflict { executor_id: id });
        }
        self.executors.insert(id, executor);
        Ok(())
    }

    /// Routes an action to an executor when the command does not name one.
    ///
    /// Active probes and explicitly host-owned low-level commands may carry
    /// only an action ID. Separate stage routes allow the explicit probe to use
    /// a stricter executor than the original passive action; high-level
    /// adaptive and retry commands pin the planner-authorized executor.
    pub fn route_action(
        &mut self,
        stage: DecisionExecutionStage,
        action_id: impl Into<String>,
        executor_id: impl Into<String>,
    ) -> Result<(), DecisionRunnerError> {
        let action_id = non_empty(action_id, "action id")?;
        let executor_id = non_empty(executor_id, "executor id")?;
        if !self.executors.contains_key(&executor_id) {
            return Err(DecisionRunnerError::UnknownExecutor { executor_id });
        }

        let key = (stage, action_id.clone());
        if let Some(existing) = self.routes.get(&key) {
            return if existing == &executor_id {
                Ok(())
            } else {
                Err(DecisionRunnerError::ActionRouteConflict { stage, action_id })
            };
        }
        self.routes.insert(key, executor_id);
        Ok(())
    }

    /// Returns whether an executor identity is registered.
    pub fn contains(&self, executor_id: &str) -> bool {
        self.executors.contains_key(executor_id)
    }

    /// Returns the number of registered executors.
    pub fn len(&self) -> usize {
        self.executors.len()
    }

    /// Returns whether the registry contains no executors.
    pub fn is_empty(&self) -> bool {
        self.executors.is_empty()
    }

    fn resolve(
        &self,
        stage: DecisionExecutionStage,
        action_id: &str,
        requested_executor: Option<&str>,
    ) -> Result<(String, Arc<dyn DecisionActionExecutor>), DecisionRunnerError> {
        let executor_id = if let Some(requested) = requested_executor {
            non_empty(requested, "executor id")?
        } else {
            self.routes
                .get(&(stage, action_id.to_owned()))
                .cloned()
                .ok_or_else(|| DecisionRunnerError::MissingActionRoute {
                    stage,
                    action_id: action_id.to_owned(),
                })?
        };
        let executor = self.executors.get(&executor_id).cloned().ok_or_else(|| {
            DecisionRunnerError::UnknownExecutor {
                executor_id: executor_id.clone(),
            }
        })?;
        Ok((executor_id, executor))
    }
}

/// A committed evidence batch and the snapshots needed by verification.
#[derive(Debug, Clone)]
pub struct DecisionEvidenceReceipt {
    case: VerificationCase,
    stage: DecisionExecutionStage,
    executor_id: String,
    evidence: Vec<Evidence>,
    writes: Vec<KnowledgeWrite>,
    baseline: Option<KnowledgeSnapshot>,
    after_execution: KnowledgeSnapshot,
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

fn non_empty(value: impl Into<String>, field: &'static str) -> Result<String, DecisionRunnerError> {
    let value = value.into();
    if value.trim().is_empty() {
        return Err(DecisionRunnerError::EmptyValue { field });
    }
    Ok(value)
}

/// Executes decision commands without moving policy into the runner.
pub struct DecisionRunnerAdapter {
    executors: DecisionExecutorRegistry,
}

impl DecisionRunnerAdapter {
    /// Creates an adapter backed by the supplied executor registry.
    pub fn new(executors: DecisionExecutorRegistry) -> Self {
        Self { executors }
    }

    /// Returns the configured executor registry.
    pub fn executors(&self) -> &DecisionExecutorRegistry {
        &self.executors
    }

    /// Resolves the execution class of the executor that would run this command,
    /// using the same registry route authority as execution. Lets a host decide
    /// which resource-accounting boundary to apply before it reserves resources.
    pub fn execution_class_for_command(
        &self,
        command: &DecisionLoopCommand,
    ) -> Result<DecisionExecutionClass, DecisionRunnerError> {
        let (stage, action_id, requested_executor) = match command {
            DecisionLoopCommand::ExecuteAction { case, executor, .. } => (
                DecisionExecutionStage::Passive,
                case.action_id(),
                executor.as_deref(),
            ),
            DecisionLoopCommand::CollectActiveEvidence { case } => {
                (DecisionExecutionStage::Active, case.action_id(), None)
            },
            DecisionLoopCommand::Replan => {
                return Err(DecisionRunnerError::NonExecutionCommand { command: "replan" })
            },
            DecisionLoopCommand::Complete { .. } => {
                return Err(DecisionRunnerError::NonExecutionCommand {
                    command: "complete",
                })
            },
            DecisionLoopCommand::AwaitHumanReview { .. } => {
                return Err(DecisionRunnerError::NonExecutionCommand {
                    command: "await_human_review",
                })
            },
            DecisionLoopCommand::Halt { .. } => {
                return Err(DecisionRunnerError::NonExecutionCommand { command: "halt" })
            },
        };
        let (_, executor) = self
            .executors
            .resolve(stage, action_id, requested_executor)?;
        Ok(executor.execution_class())
    }

    /// Resolves and executes one evidence-producing command.
    ///
    /// The complete evidence batch is validated before it is atomically
    /// committed. Active requests capture their baseline immediately before
    /// executor invocation.
    pub async fn execute_command(
        &self,
        command: &DecisionLoopCommand,
        knowledge: &KnowledgeBase,
    ) -> Result<DecisionEvidenceReceipt, DecisionRunnerError> {
        self.execute_command_with_limits(command, knowledge, DecisionExecutionLimits::default())
            .await
    }

    /// Resolves and executes one command under a host-owned resource allowance.
    pub async fn execute_command_with_limits(
        &self,
        command: &DecisionLoopCommand,
        knowledge: &KnowledgeBase,
        limits: DecisionExecutionLimits,
    ) -> Result<DecisionEvidenceReceipt, DecisionRunnerError> {
        let (case, stage, origin, delay_ms, requested_executor) = match command {
            DecisionLoopCommand::ExecuteAction {
                case,
                executor,
                origin,
                delay_ms,
            } => (
                case,
                DecisionExecutionStage::Passive,
                Some(*origin),
                *delay_ms,
                executor.as_deref(),
            ),
            DecisionLoopCommand::CollectActiveEvidence { case } => {
                (case, DecisionExecutionStage::Active, None, None, None)
            },
            DecisionLoopCommand::Replan => {
                return Err(DecisionRunnerError::NonExecutionCommand { command: "replan" })
            },
            DecisionLoopCommand::Complete { .. } => {
                return Err(DecisionRunnerError::NonExecutionCommand {
                    command: "complete",
                })
            },
            DecisionLoopCommand::AwaitHumanReview { .. } => {
                return Err(DecisionRunnerError::NonExecutionCommand {
                    command: "await_human_review",
                })
            },
            DecisionLoopCommand::Halt { .. } => {
                return Err(DecisionRunnerError::NonExecutionCommand { command: "halt" })
            },
        };

        let (executor_id, executor) =
            self.executors
                .resolve(stage, case.action_id(), requested_executor)?;
        if let Some(strategy) = case.payload_strategy() {
            if !executor.supports_payload_strategy(strategy) {
                return Err(DecisionRunnerError::UnsupportedPayloadStrategy {
                    executor_id,
                    strategy: strategy.clone(),
                });
            }
        }
        if let Some(delay_ms) = delay_ms.filter(|delay| *delay > 0) {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }

        let baseline = (stage == DecisionExecutionStage::Active)
            .then(|| knowledge.snapshot_for_subject(case.subject()));
        let request = DecisionExecutionRequest::new(case.clone(), stage, origin, delay_ms, limits);
        // TransportBound executors observe the network and receive no reasoning
        // state; LocalKnowledge executors derive evidence from an immutable
        // subject-scoped snapshot and never touch the network. Either way the
        // runner remains the sole authority that validates and commits.
        let evidence = match executor.execution_class() {
            DecisionExecutionClass::TransportBound => executor.execute(&request).await,
            DecisionExecutionClass::LocalKnowledge => {
                let snapshot = knowledge.snapshot_for_subject(case.subject());
                executor.execute_with_snapshot(&request, &snapshot).await
            },
        }
        .map_err(|source| {
            let source = source.with_execution_context(request.clone(), executor_id.clone());
            DecisionRunnerError::Executor {
                executor_id: executor_id.clone(),
                source,
            }
        })?;
        validate_evidence(&evidence, case, &executor_id)?;
        let receipt_evidence = evidence.clone();
        let writes = knowledge.insert_evidence_batch(evidence)?;
        let after_execution = knowledge.snapshot_for_subject(case.subject());

        Ok(DecisionEvidenceReceipt {
            case: case.clone(),
            stage,
            executor_id,
            evidence: receipt_evidence,
            writes,
            baseline,
            after_execution,
        })
    }

    /// Executes a command and resumes the matching decision-loop transition.
    ///
    /// `ExecuteAction` submits passive evidence, `CollectActiveEvidence`
    /// submits the captured before/after snapshots, and `Replan` invokes the
    /// reasoner and utility planner. Terminal commands are returned unchanged.
    /// Adaptive, retry, active, and replan continuations fail before execution;
    /// use [`Self::drive_command_with_suppressed_actions`] to reauthorize them.
    pub async fn drive_command(
        &self,
        decision_loop: &DecisionLoop,
        command: &DecisionLoopCommand,
        knowledge: &KnowledgeBase,
        experience: &mut ExperienceStore,
        session: &mut DecisionSession,
    ) -> Result<DecisionRunnerTurn, DecisionRunnerError> {
        self.drive_command_with_optional_suppressions(
            decision_loop,
            command,
            knowledge,
            experience,
            session,
            DecisionExecutionLimits::default(),
            None,
        )
        .await
    }

    /// Executes and resumes a command under explicit current host policy.
    ///
    /// Current suppressions are checked before executor work and remain in
    /// force through verification, adaptive authorization, and replanning.
    pub async fn drive_command_with_suppressed_actions(
        &self,
        decision_loop: &DecisionLoop,
        command: &DecisionLoopCommand,
        knowledge: &KnowledgeBase,
        experience: &mut ExperienceStore,
        session: &mut DecisionSession,
        host_suppressed_actions: &BTreeSet<String>,
    ) -> Result<DecisionRunnerTurn, DecisionRunnerError> {
        self.drive_command_with_optional_suppressions(
            decision_loop,
            command,
            knowledge,
            experience,
            session,
            DecisionExecutionLimits::default(),
            Some(host_suppressed_actions),
        )
        .await
    }

    /// Drives one command under a host-owned execution allowance.
    pub async fn drive_command_with_limits(
        &self,
        decision_loop: &DecisionLoop,
        command: &DecisionLoopCommand,
        knowledge: &KnowledgeBase,
        experience: &mut ExperienceStore,
        session: &mut DecisionSession,
        limits: DecisionExecutionLimits,
    ) -> Result<DecisionRunnerTurn, DecisionRunnerError> {
        self.drive_command_with_optional_suppressions(
            decision_loop,
            command,
            knowledge,
            experience,
            session,
            limits,
            None,
        )
        .await
    }

    /// Drives one command under explicit host policy and execution allowance.
    ///
    /// Current suppressions are checked before executor work and remain in
    /// force through verification, adaptive authorization, and replanning.
    #[allow(clippy::too_many_arguments)]
    pub async fn drive_command_with_limits_and_suppressed_actions(
        &self,
        decision_loop: &DecisionLoop,
        command: &DecisionLoopCommand,
        knowledge: &KnowledgeBase,
        experience: &mut ExperienceStore,
        session: &mut DecisionSession,
        limits: DecisionExecutionLimits,
        host_suppressed_actions: &BTreeSet<String>,
    ) -> Result<DecisionRunnerTurn, DecisionRunnerError> {
        self.drive_command_with_optional_suppressions(
            decision_loop,
            command,
            knowledge,
            experience,
            session,
            limits,
            Some(host_suppressed_actions),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn drive_command_with_optional_suppressions(
        &self,
        decision_loop: &DecisionLoop,
        command: &DecisionLoopCommand,
        knowledge: &KnowledgeBase,
        experience: &mut ExperienceStore,
        session: &mut DecisionSession,
        limits: DecisionExecutionLimits,
        host_suppressed_actions: Option<&BTreeSet<String>>,
    ) -> Result<DecisionRunnerTurn, DecisionRunnerError> {
        if host_suppressed_actions.is_none() {
            if let Some(command) = command_requiring_host_policy_context(command) {
                return Err(DecisionRunnerError::HostPolicyContextRequired { command });
            }
        }
        if let Some(suppressions) = host_suppressed_actions {
            if let Some(action_id) = execution_command_action_id(command) {
                if suppressions.contains(action_id) {
                    return Err(DecisionRunnerError::ActionSuppressedByHostPolicy {
                        action_id: action_id.to_owned(),
                    });
                }
            }
        }
        decision_loop.validate_execution_command_authority(knowledge, command)?;
        match command {
            DecisionLoopCommand::ExecuteAction { .. }
            | DecisionLoopCommand::CollectActiveEvidence { .. } => {
                let evidence = self
                    .execute_session_command_with_limits(command, knowledge, session, limits)
                    .await?;
                self.resume_session_command_with_optional_suppressions(
                    decision_loop,
                    command,
                    knowledge,
                    experience,
                    session,
                    evidence,
                    host_suppressed_actions,
                )
            },
            DecisionLoopCommand::Replan => {
                let planning = match host_suppressed_actions {
                    Some(suppressions) => decision_loop.plan_next_with_suppressed_actions(
                        knowledge,
                        experience,
                        session,
                        suppressions,
                    )?,
                    None => decision_loop.plan_next(knowledge, experience, session)?,
                };
                Ok(DecisionRunnerTurn::Planning(Box::new(planning)))
            },
            DecisionLoopCommand::Complete { .. }
            | DecisionLoopCommand::AwaitHumanReview { .. }
            | DecisionLoopCommand::Halt { .. } => Ok(DecisionRunnerTurn::Terminal(command.clone())),
        }
    }

    pub(crate) async fn execute_session_command_with_limits(
        &self,
        command: &DecisionLoopCommand,
        knowledge: &KnowledgeBase,
        session: &DecisionSession,
        limits: DecisionExecutionLimits,
    ) -> Result<DecisionEvidenceReceipt, DecisionRunnerError> {
        match command {
            DecisionLoopCommand::ExecuteAction { case, .. } => {
                validate_session_case(session, DecisionExecutionStage::Passive, case)?;
            },
            DecisionLoopCommand::CollectActiveEvidence { case } => {
                validate_session_case(session, DecisionExecutionStage::Active, case)?;
            },
            DecisionLoopCommand::Replan => {
                return Err(DecisionRunnerError::NonExecutionCommand { command: "replan" });
            },
            DecisionLoopCommand::Complete { .. } => {
                return Err(DecisionRunnerError::NonExecutionCommand {
                    command: "complete",
                });
            },
            DecisionLoopCommand::AwaitHumanReview { .. } => {
                return Err(DecisionRunnerError::NonExecutionCommand {
                    command: "await_human_review",
                });
            },
            DecisionLoopCommand::Halt { .. } => {
                return Err(DecisionRunnerError::NonExecutionCommand { command: "halt" });
            },
        }
        self.execute_command_with_limits(command, knowledge, limits)
            .await
    }

    #[cfg(test)]
    pub(crate) fn resume_session_command(
        &self,
        decision_loop: &DecisionLoop,
        command: &DecisionLoopCommand,
        knowledge: &KnowledgeBase,
        experience: &mut ExperienceStore,
        session: &mut DecisionSession,
        evidence: DecisionEvidenceReceipt,
    ) -> Result<DecisionRunnerTurn, DecisionRunnerError> {
        self.resume_session_command_with_optional_suppressions(
            decision_loop,
            command,
            knowledge,
            experience,
            session,
            evidence,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn resume_session_command_with_suppressed_actions(
        &self,
        decision_loop: &DecisionLoop,
        command: &DecisionLoopCommand,
        knowledge: &KnowledgeBase,
        experience: &mut ExperienceStore,
        session: &mut DecisionSession,
        evidence: DecisionEvidenceReceipt,
        host_suppressed_actions: &BTreeSet<String>,
    ) -> Result<DecisionRunnerTurn, DecisionRunnerError> {
        self.resume_session_command_with_optional_suppressions(
            decision_loop,
            command,
            knowledge,
            experience,
            session,
            evidence,
            Some(host_suppressed_actions),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn resume_session_command_with_optional_suppressions(
        &self,
        decision_loop: &DecisionLoop,
        command: &DecisionLoopCommand,
        knowledge: &KnowledgeBase,
        experience: &mut ExperienceStore,
        session: &mut DecisionSession,
        evidence: DecisionEvidenceReceipt,
        host_suppressed_actions: Option<&BTreeSet<String>>,
    ) -> Result<DecisionRunnerTurn, DecisionRunnerError> {
        let decision = (|| -> Result<Box<DecisionOutcomeReport>, DecisionRunnerError> {
            match command {
                DecisionLoopCommand::ExecuteAction { case, .. } => {
                    validate_session_case(session, DecisionExecutionStage::Passive, case)?;
                    let report = match host_suppressed_actions {
                        Some(suppressions) => decision_loop.submit_passive_with_suppressed_actions(
                            knowledge,
                            experience,
                            session,
                            suppressions,
                        ),
                        None => decision_loop.submit_passive(knowledge, experience, session),
                    }?;
                    Ok(Box::new(report))
                },
                DecisionLoopCommand::CollectActiveEvidence { case } => {
                    validate_session_case(session, DecisionExecutionStage::Active, case)?;
                    let baseline = evidence
                        .baseline()
                        .ok_or(DecisionRunnerError::MissingActiveBaseline)?;
                    let report = match host_suppressed_actions {
                        Some(suppressions) => decision_loop.submit_active_with_suppressed_actions(
                            knowledge,
                            experience,
                            session,
                            baseline,
                            evidence.after_execution(),
                            suppressions,
                        ),
                        None => decision_loop.submit_active(
                            knowledge,
                            experience,
                            session,
                            baseline,
                            evidence.after_execution(),
                        ),
                    }?;
                    Ok(Box::new(report))
                },
                DecisionLoopCommand::Replan => {
                    Err(DecisionRunnerError::NonExecutionCommand { command: "replan" })
                },
                DecisionLoopCommand::Complete { .. } => {
                    Err(DecisionRunnerError::NonExecutionCommand {
                        command: "complete",
                    })
                },
                DecisionLoopCommand::AwaitHumanReview { .. } => {
                    Err(DecisionRunnerError::NonExecutionCommand {
                        command: "await_human_review",
                    })
                },
                DecisionLoopCommand::Halt { .. } => {
                    Err(DecisionRunnerError::NonExecutionCommand { command: "halt" })
                },
            }
        })();

        match decision {
            Ok(decision) => Ok(DecisionRunnerTurn::Outcome {
                evidence: Box::new(evidence),
                decision,
            }),
            Err(source) => Err(DecisionRunnerError::OutcomeAfterEvidenceCommit {
                receipt: Box::new(evidence),
                source: Box::new(source),
            }),
        }
    }
}

fn command_requiring_host_policy_context(command: &DecisionLoopCommand) -> Option<&'static str> {
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

fn execution_command_action_id(command: &DecisionLoopCommand) -> Option<&str> {
    match command {
        DecisionLoopCommand::ExecuteAction { case, .. }
        | DecisionLoopCommand::CollectActiveEvidence { case } => Some(case.action_id()),
        DecisionLoopCommand::Replan
        | DecisionLoopCommand::Complete { .. }
        | DecisionLoopCommand::AwaitHumanReview { .. }
        | DecisionLoopCommand::Halt { .. } => None,
    }
}

fn validate_session_case(
    session: &DecisionSession,
    stage: DecisionExecutionStage,
    command_case: &VerificationCase,
) -> Result<(), DecisionRunnerError> {
    let outstanding = match (stage, session.state()) {
        (DecisionExecutionStage::Passive, DecisionLoopState::AwaitingPassive { case })
        | (DecisionExecutionStage::Active, DecisionLoopState::AwaitingActive { case }) => case,
        (_, state) => {
            return Err(DecisionRunnerError::UnexpectedSessionState {
                expected: stage,
                actual: session_state_name(state),
            })
        },
    };
    if outstanding != command_case {
        return Err(DecisionRunnerError::CommandCaseMismatch {
            expected: outstanding.id().to_owned(),
            actual: command_case.id().to_owned(),
        });
    }
    Ok(())
}

fn session_state_name(state: &DecisionLoopState) -> &'static str {
    match state {
        DecisionLoopState::Ready => "ready",
        DecisionLoopState::AwaitingPassive { .. } => "awaiting_passive",
        DecisionLoopState::AwaitingActive { .. } => "awaiting_active",
        DecisionLoopState::Completed => "completed",
        DecisionLoopState::Halted { .. } => "halted",
    }
}

fn validate_evidence(
    evidence: &[Evidence],
    case: &VerificationCase,
    executor_id: &str,
) -> Result<(), DecisionRunnerError> {
    for observation in evidence {
        if observation.subject() != case.subject() {
            return Err(DecisionRunnerError::EvidenceSubjectMismatch {
                evidence_id: observation.id().to_string(),
                expected: case.subject().clone(),
                actual: observation.subject().clone(),
            });
        }
        if observation.source().component() != executor_id {
            return Err(DecisionRunnerError::EvidenceSourceMismatch {
                evidence_id: observation.id().to_string(),
                expected: executor_id.to_owned(),
                actual: observation.source().component().to_owned(),
            });
        }
        if observation.source().correlation_id() != Some(case.id()) {
            return Err(DecisionRunnerError::EvidenceCorrelationMismatch {
                evidence_id: observation.id().to_string(),
                expected: case.id().to_owned(),
                actual: observation.source().correlation_id().map(str::to_owned),
            });
        }
    }
    Ok(())
}

/// Legacy plugin input selected by the host from a decision request.
#[cfg(feature = "plugins")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginExecutionInput {
    target: String,
    payload: String,
}

#[cfg(feature = "plugins")]
impl PluginExecutionInput {
    /// Creates validated legacy plugin arguments.
    pub fn new(
        target: impl Into<String>,
        payload: impl Into<String>,
    ) -> Result<Self, DecisionExecutorError> {
        let target = target.into();
        if target.trim().is_empty() {
            return Err(DecisionExecutorError::new(
                "plugin target must not be empty",
            ));
        }
        Ok(Self {
            target,
            payload: payload.into(),
        })
    }

    /// Returns the plugin target argument.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Returns the plugin payload or observed response argument.
    pub fn payload(&self) -> &str {
        &self.payload
    }
}

/// Host policy that maps a decision case to the legacy plugin arguments.
#[cfg(feature = "plugins")]
pub trait PluginInputProvider: Send + Sync {
    /// Produces target and payload values without mutating decision state.
    fn input_for(
        &self,
        request: &DecisionExecutionRequest,
    ) -> Result<PluginExecutionInput, DecisionExecutorError>;
}

#[cfg(feature = "plugins")]
impl<F> PluginInputProvider for F
where
    F: Fn(&DecisionExecutionRequest) -> Result<PluginExecutionInput, DecisionExecutorError>
        + Send
        + Sync,
{
    fn input_for(
        &self,
        request: &DecisionExecutionRequest,
    ) -> Result<PluginExecutionInput, DecisionExecutorError> {
        self(request)
    }
}

/// Bridge from the source-level [`crate::PluginRegistry`] to native evidence.
///
/// The input provider remains host-owned because an action ID is not an HTTP
/// payload. Findings are normalized into evidence only after plugin execution;
/// the regular adapter provenance checks still apply.
#[cfg(feature = "plugins")]
pub struct PluginDecisionExecutor {
    registry: Arc<crate::PluginRegistry>,
    plugin_id: String,
    input: Arc<dyn PluginInputProvider>,
    reliability: venom_core::ConfidenceScore,
}

#[cfg(feature = "plugins")]
impl PluginDecisionExecutor {
    /// Creates a bridge for one registered plugin identity.
    pub fn new(
        registry: Arc<crate::PluginRegistry>,
        plugin_id: impl Into<String>,
        input: Arc<dyn PluginInputProvider>,
        reliability: venom_core::ConfidenceScore,
    ) -> Result<Self, DecisionExecutorError> {
        let plugin_id = plugin_id.into();
        if plugin_id.trim().is_empty() {
            return Err(DecisionExecutorError::new("plugin id must not be empty"));
        }
        Ok(Self {
            registry,
            plugin_id,
            input,
            reliability,
        })
    }
}

#[cfg(feature = "plugins")]
#[async_trait]
impl DecisionActionExecutor for PluginDecisionExecutor {
    fn id(&self) -> &str {
        &self.plugin_id
    }

    async fn execute(
        &self,
        request: &DecisionExecutionRequest,
    ) -> Result<Vec<Evidence>, DecisionExecutorError> {
        use venom_core::{EvidenceKind, EvidenceSource, EvidenceValue, KnowledgePredicate};

        let input = self.input.input_for(request)?;
        let result = self
            .registry
            .execute(&self.plugin_id, input.target(), input.payload())
            .await
            .map_err(|error| DecisionExecutorError::new(error.to_string()))?;
        if !result.success {
            return Err(DecisionExecutorError::new(
                result
                    .error
                    .unwrap_or_else(|| "plugin execution failed".to_owned()),
            ));
        }

        result
            .findings
            .into_iter()
            .map(|finding| {
                let method = if finding.module_name.trim().is_empty() {
                    "finding".to_owned()
                } else {
                    finding.module_name.clone()
                };
                let source = EvidenceSource::new(self.plugin_id.clone(), method)
                    .and_then(|source| source.with_correlation_id(request.case().id()))
                    .map_err(|error| DecisionExecutorError::new(error.to_string()))?;
                let predicate = KnowledgePredicate::new("plugin.finding", self.plugin_id.clone())
                    .map_err(|error| DecisionExecutorError::new(error.to_string()))?;
                Ok(Evidence::new(
                    request.case().subject().clone(),
                    EvidenceKind::Custom("plugin.finding".to_owned()),
                    predicate,
                    EvidenceValue::TextList(vec![
                        format!("severity={}", finding.severity),
                        format!("description={}", finding.description),
                        format!("evidence={}", finding.evidence),
                        format!("phase={}", finding.phase),
                    ]),
                    source,
                    self.reliability,
                ))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ActionCost, AdaptationLimits, AttackAction, BenefitScore, DecisionLoopConfig,
        ExperiencePolicy, Expression, HypothesisSelector, KnowledgeLayer, PlanningContext,
        RequiredStrength, RiskScore, VerificationRule, VerificationTarget,
    };
    use venom_core::{
        ConfidenceScore, EvidenceKind, EvidenceSource, EvidenceValue, Hypothesis, HypothesisState,
        HypothesisStrength, KnowledgePredicate, OutcomeStatus, Probability, VerificationStage,
    };

    struct RecordingExecutor {
        id: &'static str,
        subject_override: Option<EntityId>,
    }

    struct FailingExecutor {
        id: &'static str,
        kind: DecisionExecutionFailureKind,
        diagnostic: &'static str,
    }

    struct StrategyExecutor {
        id: &'static str,
        strategy: PayloadStrategyRef,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    struct CountingExecutor {
        id: &'static str,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait]
    impl DecisionActionExecutor for RecordingExecutor {
        fn id(&self) -> &str {
            self.id
        }

        async fn execute(
            &self,
            request: &DecisionExecutionRequest,
        ) -> Result<Vec<Evidence>, DecisionExecutorError> {
            let source = EvidenceSource::new(self.id, "response-status")
                .unwrap()
                .with_correlation_id(request.case().id())
                .unwrap();
            Ok(vec![Evidence::new(
                self.subject_override
                    .clone()
                    .unwrap_or_else(|| request.case().subject().clone()),
                EvidenceKind::Http,
                KnowledgePredicate::new("http.response", "status").unwrap(),
                EvidenceValue::Unsigned(200),
                source,
                ConfidenceScore::MAX,
            )])
        }
    }

    #[async_trait]
    impl DecisionActionExecutor for FailingExecutor {
        fn id(&self) -> &str {
            self.id
        }

        async fn execute(
            &self,
            _request: &DecisionExecutionRequest,
        ) -> Result<Vec<Evidence>, DecisionExecutorError> {
            Err(DecisionExecutorError::with_kind(self.kind, self.diagnostic))
        }
    }

    #[async_trait]
    impl DecisionActionExecutor for StrategyExecutor {
        fn id(&self) -> &str {
            self.id
        }

        fn supports_payload_strategy(&self, strategy: &PayloadStrategyRef) -> bool {
            strategy == &self.strategy
        }

        async fn execute(
            &self,
            request: &DecisionExecutionRequest,
        ) -> Result<Vec<Evidence>, DecisionExecutorError> {
            assert_eq!(request.payload_strategy(), Some(&self.strategy));
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let source = EvidenceSource::new(self.id, "strategy-observation")
                .unwrap()
                .with_correlation_id(request.case().id())
                .unwrap();
            Ok(vec![Evidence::new(
                request.case().subject().clone(),
                EvidenceKind::Http,
                KnowledgePredicate::new("http.response", "status").unwrap(),
                EvidenceValue::Unsigned(200),
                source,
                ConfidenceScore::MAX,
            )])
        }
    }

    #[async_trait]
    impl DecisionActionExecutor for CountingExecutor {
        fn id(&self) -> &str {
            self.id
        }

        async fn execute(
            &self,
            request: &DecisionExecutionRequest,
        ) -> Result<Vec<Evidence>, DecisionExecutorError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let source = EvidenceSource::new(self.id, "counted-observation")
                .unwrap()
                .with_correlation_id(request.case().id())
                .unwrap();
            Ok(vec![Evidence::new(
                request.case().subject().clone(),
                EvidenceKind::Http,
                KnowledgePredicate::new("http.response", "status").unwrap(),
                EvidenceValue::Unsigned(200),
                source,
                ConfidenceScore::MAX,
            )])
        }
    }

    /// A transport-free executor: it declares `LocalKnowledge`, reads one
    /// deterministic value from the immutable subject snapshot (the observed
    /// evidence count), and derives one new evidence record. Its `execute`
    /// (transport) path deliberately fails, proving the runner never routes a
    /// local action through transport.
    struct LocalKnowledgeExecutor {
        id: &'static str,
    }

    #[async_trait]
    impl DecisionActionExecutor for LocalKnowledgeExecutor {
        fn id(&self) -> &str {
            self.id
        }

        fn execution_class(&self) -> DecisionExecutionClass {
            DecisionExecutionClass::LocalKnowledge
        }

        async fn execute(
            &self,
            _request: &DecisionExecutionRequest,
        ) -> Result<Vec<Evidence>, DecisionExecutorError> {
            Err(DecisionExecutorError::new(
                "local-knowledge executor must run through execute_with_snapshot",
            ))
        }

        async fn execute_with_snapshot(
            &self,
            request: &DecisionExecutionRequest,
            snapshot: &KnowledgeSnapshot,
        ) -> Result<Vec<Evidence>, DecisionExecutorError> {
            let observed = u64::try_from(snapshot.evidence().len()).unwrap_or(u64::MAX);
            let source = EvidenceSource::new(self.id, "local-derivation")
                .unwrap()
                .with_correlation_id(request.case().id())
                .unwrap();
            Ok(vec![Evidence::new(
                request.case().subject().clone(),
                EvidenceKind::Content,
                KnowledgePredicate::new("test.local", "observed-evidence-count").unwrap(),
                EvidenceValue::Unsigned(observed),
                source,
                ConfidenceScore::MAX,
            )])
        }
    }

    fn subject() -> EntityId {
        EntityId::new("endpoint:https://example.test").unwrap()
    }

    fn case(action_id: &str) -> VerificationCase {
        VerificationCase::new("case:1", subject(), action_id, "hypothesis:1").unwrap()
    }

    fn baseline_evidence() -> Evidence {
        Evidence::new(
            subject(),
            EvidenceKind::Http,
            KnowledgePredicate::new("http.response", "status").unwrap(),
            EvidenceValue::Unsigned(200),
            EvidenceSource::new("test.seed", "seed").unwrap(),
            ConfidenceScore::MAX,
        )
    }

    fn execute_action(action_id: &str, executor_id: &str) -> DecisionLoopCommand {
        DecisionLoopCommand::ExecuteAction {
            case: case(action_id),
            executor: Some(executor_id.to_owned()),
            origin: DecisionActionOrigin::Planned,
            delay_ms: None,
        }
    }

    fn local_registry() -> DecisionExecutorRegistry {
        let mut registry = DecisionExecutorRegistry::new();
        registry
            .register(Arc::new(LocalKnowledgeExecutor { id: "local.test" }))
            .unwrap();
        registry
            .route_action(
                DecisionExecutionStage::Passive,
                "action.local",
                "local.test",
            )
            .unwrap();
        registry
    }

    #[tokio::test]
    async fn local_knowledge_executor_derives_evidence_from_the_snapshot() {
        // C + H: local-derived evidence passes the same provenance validation and
        // atomic commit; the derived value is a deterministic function of the
        // immutable snapshot (here: two seeded evidence records observed).
        let knowledge = KnowledgeBase::new();
        knowledge.insert_evidence(baseline_evidence()).unwrap();
        knowledge
            .insert_evidence(Evidence::new(
                subject(),
                EvidenceKind::Http,
                KnowledgePredicate::new("http.header", "server").unwrap(),
                EvidenceValue::Text("nginx".to_owned()),
                EvidenceSource::new("test.seed", "seed-2").unwrap(),
                ConfidenceScore::MAX,
            ))
            .unwrap();
        let adapter = DecisionRunnerAdapter::new(local_registry());

        let receipt = adapter
            .execute_command(&execute_action("action.local", "local.test"), &knowledge)
            .await
            .unwrap();

        assert_eq!(receipt.evidence().len(), 1);
        let derived = &receipt.evidence()[0];
        assert_eq!(
            derived.predicate().dotted(),
            "test.local.observed-evidence-count"
        );
        assert_eq!(derived.value(), &EvidenceValue::Unsigned(2));
        assert_eq!(derived.subject(), &subject());
        assert_eq!(derived.source().component(), "local.test");
        assert_eq!(derived.source().correlation_id(), Some("case:1"));
        // Committed atomically through the same knowledge writer.
        assert!(knowledge.stats().evidence >= 3);
    }

    #[tokio::test]
    async fn local_knowledge_never_routes_through_the_transport_execute_path() {
        // The executor's transport `execute` fails; the run still succeeds because
        // the runner dispatches a LocalKnowledge action through the snapshot path.
        let knowledge = KnowledgeBase::new();
        knowledge.insert_evidence(baseline_evidence()).unwrap();
        let adapter = DecisionRunnerAdapter::new(local_registry());

        let receipt = adapter
            .execute_command(&execute_action("action.local", "local.test"), &knowledge)
            .await
            .unwrap();
        assert_eq!(receipt.evidence().len(), 1);
    }

    #[test]
    fn execution_class_is_resolved_from_the_registry_route() {
        let adapter = DecisionRunnerAdapter::new(local_registry());
        assert_eq!(
            adapter
                .execution_class_for_command(&execute_action("action.local", "local.test"))
                .unwrap(),
            DecisionExecutionClass::LocalKnowledge
        );
        // A default executor reports TransportBound without any implementation
        // change (compatibility).
        let mut registry = DecisionExecutorRegistry::new();
        registry
            .register(Arc::new(RecordingExecutor {
                id: "http.test",
                subject_override: None,
            }))
            .unwrap();
        registry
            .route_action(DecisionExecutionStage::Passive, "action.http", "http.test")
            .unwrap();
        let adapter = DecisionRunnerAdapter::new(registry);
        assert_eq!(
            adapter
                .execution_class_for_command(&execute_action("action.http", "http.test"))
                .unwrap(),
            DecisionExecutionClass::TransportBound
        );
    }

    /// Declares LocalKnowledge but never overrides snapshot execution. Its
    /// transport `execute` records a call so the test can prove it is never made.
    struct MislabeledLocalExecutor {
        executed: Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait]
    impl DecisionActionExecutor for MislabeledLocalExecutor {
        fn id(&self) -> &str {
            "mislabeled.local"
        }

        fn execution_class(&self) -> DecisionExecutionClass {
            DecisionExecutionClass::LocalKnowledge
        }

        async fn execute(
            &self,
            _request: &DecisionExecutionRequest,
        ) -> Result<Vec<Evidence>, DecisionExecutorError> {
            self.executed
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(Vec::new())
        }
    }

    #[tokio::test]
    async fn local_knowledge_without_snapshot_override_is_fail_closed() {
        // A LocalKnowledge executor that forgets to override snapshot execution
        // must produce a deterministic error, and its transport `execute` must
        // NEVER run — the runtime has already skipped transport accounting for it.
        let executed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut registry = DecisionExecutorRegistry::new();
        registry
            .register(Arc::new(MislabeledLocalExecutor {
                executed: executed.clone(),
            }))
            .unwrap();
        registry
            .route_action(
                DecisionExecutionStage::Passive,
                "action.mislabeled",
                "mislabeled.local",
            )
            .unwrap();
        let adapter = DecisionRunnerAdapter::new(registry);

        let error = adapter
            .execute_command(
                &execute_action("action.mislabeled", "mislabeled.local"),
                &KnowledgeBase::new(),
            )
            .await
            .unwrap_err();

        assert!(
            !executed.load(std::sync::atomic::Ordering::SeqCst),
            "the transport execute() path must not be reached"
        );
        assert!(matches!(error, DecisionRunnerError::Executor { .. }));
    }

    fn executor(
        id: &'static str,
        subject_override: Option<EntityId>,
    ) -> Arc<dyn DecisionActionExecutor> {
        Arc::new(RecordingExecutor {
            id,
            subject_override,
        })
    }

    fn failing_executor(
        id: &'static str,
        kind: DecisionExecutionFailureKind,
        diagnostic: &'static str,
    ) -> Arc<dyn DecisionActionExecutor> {
        Arc::new(FailingExecutor {
            id,
            kind,
            diagnostic,
        })
    }

    fn empty_decision_loop() -> DecisionLoop {
        let planning = PlanningContext::new(
            BenefitScore::from_percent(80).unwrap(),
            100,
            RiskScore::from_percent(40).unwrap(),
        );
        DecisionLoop::new(
            DecisionLoopConfig::new(
                planning,
                AdaptationLimits::default(),
                ExperiencePolicy::default(),
                4,
            )
            .unwrap(),
        )
    }

    fn loop_with_supported_http_action() -> (DecisionLoop, KnowledgeBase) {
        loop_with_supported_http_action_target(VerificationTarget::Motivation)
    }

    fn loop_with_supported_http_action_target(
        target: VerificationTarget,
    ) -> (DecisionLoop, KnowledgeBase) {
        let mut decision_loop = empty_decision_loop();
        let predicate = KnowledgePredicate::new("stack", "framework").unwrap();
        let value = EvidenceValue::Text("Laravel".to_owned());
        decision_loop
            .planner_mut()
            .register(
                AttackAction::new(
                    "http.probe",
                    "plugin.http",
                    Expression::equals(
                        KnowledgeLayer::Hypothesis,
                        predicate.clone(),
                        value.clone(),
                    ),
                    HypothesisSelector::new(
                        predicate.clone(),
                        value.clone(),
                        Probability::from_percent(50).unwrap(),
                        RequiredStrength::Strong,
                    ),
                    BenefitScore::from_percent(80).unwrap(),
                    ActionCost::new(10).unwrap(),
                    RiskScore::from_percent(20).unwrap(),
                    BTreeSet::new(),
                )
                .unwrap()
                .with_verification_target(target),
            )
            .unwrap();
        let knowledge = KnowledgeBase::new();
        let mut hypothesis = Hypothesis::with_id(
            "hypothesis:1",
            subject(),
            predicate,
            value,
            Probability::from_percent(90).unwrap(),
        )
        .unwrap();
        hypothesis.set_strength(HypothesisStrength::Strong);
        hypothesis.set_state(HypothesisState::Supported);
        knowledge.upsert_hypothesis(hypothesis).unwrap();
        (decision_loop, knowledge)
    }

    #[tokio::test]
    async fn explicit_executor_records_a_validated_atomic_batch() {
        let mut registry = DecisionExecutorRegistry::new();
        registry.register(executor("plugin.http", None)).unwrap();
        let adapter = DecisionRunnerAdapter::new(registry);
        let knowledge = KnowledgeBase::new();
        let command = DecisionLoopCommand::ExecuteAction {
            case: case("http.probe"),
            executor: Some("plugin.http".to_owned()),
            origin: DecisionActionOrigin::Planned,
            delay_ms: None,
        };

        let receipt = adapter.execute_command(&command, &knowledge).await.unwrap();

        assert_eq!(receipt.stage(), DecisionExecutionStage::Passive);
        assert_eq!(receipt.executor_id(), "plugin.http");
        assert_eq!(receipt.evidence().len(), 1);
        assert_eq!(receipt.writes(), &[KnowledgeWrite::Inserted]);
        let write_set: Vec<_> = receipt.write_set().collect();
        assert_eq!(write_set.len(), 1);
        assert_eq!(write_set[0].0.id(), receipt.evidence()[0].id());
        assert_eq!(write_set[0].1, KnowledgeWrite::Inserted);
        assert!(receipt.baseline().is_none());
        assert_eq!(receipt.after_execution().evidence().len(), 1);
    }

    #[tokio::test]
    async fn executor_must_explicitly_support_the_planner_selected_strategy() {
        let strategy = PayloadStrategyRef::new("visibility.control-pair", 1).unwrap();
        let unsupported_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut unsupported_registry = DecisionExecutorRegistry::new();
        unsupported_registry
            .register(Arc::new(StrategyExecutor {
                id: "capability.visibility",
                strategy: PayloadStrategyRef::new("visibility.control-pair", 2).unwrap(),
                calls: Arc::clone(&unsupported_calls),
            }))
            .unwrap();
        let selected_case =
            case("visibility.compare").with_payload_strategy(Some(strategy.clone()));
        let command = DecisionLoopCommand::ExecuteAction {
            case: selected_case.clone(),
            executor: Some("capability.visibility".to_owned()),
            origin: DecisionActionOrigin::Planned,
            delay_ms: None,
        };
        let knowledge = KnowledgeBase::new();
        let error = DecisionRunnerAdapter::new(unsupported_registry)
            .execute_command(&command, &knowledge)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            DecisionRunnerError::UnsupportedPayloadStrategy {
                executor_id,
                strategy: rejected,
            } if executor_id == "capability.visibility" && rejected == strategy
        ));
        assert_eq!(
            unsupported_calls.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(knowledge.stats().evidence, 0);

        let supported_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut supported_registry = DecisionExecutorRegistry::new();
        supported_registry
            .register(Arc::new(StrategyExecutor {
                id: "capability.visibility",
                strategy,
                calls: Arc::clone(&supported_calls),
            }))
            .unwrap();
        let receipt = DecisionRunnerAdapter::new(supported_registry)
            .execute_command(&command, &KnowledgeBase::new())
            .await
            .unwrap();
        assert_eq!(
            receipt.case().payload_strategy(),
            selected_case.payload_strategy()
        );
        assert_eq!(supported_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn executor_error_defaults_to_executor_failure_and_normalizes_diagnostics() {
        let generic = DecisionExecutorError::new("plugin failed");
        assert_eq!(
            generic.kind(),
            DecisionExecutionFailureKind::ExecutorFailure
        );
        assert_eq!(generic.message(), "plugin failed");
        assert!(generic.execution_failure().is_none());

        let transport =
            DecisionExecutorError::with_kind(DecisionExecutionFailureKind::TransportFailure, "   ");
        assert_eq!(
            transport.kind(),
            DecisionExecutionFailureKind::TransportFailure
        );
        assert_eq!(transport.message(), "executor failed without a diagnostic");

        let limit = RuntimeLimitExceeded::new(
            crate::RuntimeBudgetDimension::TotalRequests,
            1,
            2,
            Some("http.probe".to_owned()),
        );
        let limited = DecisionExecutorError::from_runtime_limit(limit.clone());
        assert_eq!(
            limited.kind(),
            DecisionExecutionFailureKind::BlockedByPolicy
        );
        assert_eq!(limited.runtime_limit(), Some(&limit));
        assert_eq!(limited.message(), limit.to_string());
    }

    #[test]
    fn request_timeout_has_a_stable_transport_neutral_wire_name() {
        assert_eq!(
            serde_json::to_string(&DecisionExecutionFailureKind::RequestTimeout).unwrap(),
            "\"request_timeout\""
        );
    }

    #[tokio::test]
    async fn failed_execution_exposes_an_immutable_typed_receipt() {
        let mut registry = DecisionExecutorRegistry::new();
        registry
            .register(failing_executor(
                "plugin.http",
                DecisionExecutionFailureKind::TransportFailure,
                "connection reset before headers",
            ))
            .unwrap();
        let adapter = DecisionRunnerAdapter::new(registry);
        let knowledge = KnowledgeBase::new();
        let command = DecisionLoopCommand::ExecuteAction {
            case: case("http.probe"),
            executor: Some("plugin.http".to_owned()),
            origin: DecisionActionOrigin::Planned,
            delay_ms: None,
        };
        let limits = DecisionExecutionLimits::new().with_max_response_body_bytes(4096);

        let error = adapter
            .execute_command_with_limits(&command, &knowledge, limits)
            .await
            .unwrap_err();
        assert!(matches!(
            &error,
            DecisionRunnerError::Executor {
                executor_id,
                source,
            } if executor_id == "plugin.http"
                && source.kind() == DecisionExecutionFailureKind::TransportFailure
        ));

        let receipt = error.execution_failure().unwrap();
        assert_eq!(receipt.case().id(), "case:1");
        assert_eq!(receipt.action_id(), "http.probe");
        assert_eq!(receipt.stage(), DecisionExecutionStage::Passive);
        assert_eq!(receipt.origin(), Some(DecisionActionOrigin::Planned));
        assert_eq!(receipt.delay_ms(), None);
        assert_eq!(receipt.limits(), limits);
        assert_eq!(receipt.request().limits(), limits);
        assert_eq!(receipt.executor_id(), "plugin.http");
        assert_eq!(receipt.diagnostic(), "connection reset before headers");
        assert_eq!(
            receipt.kind(),
            DecisionExecutionFailureKind::TransportFailure
        );
        assert_eq!(knowledge.stats().evidence, 0);

        let expected = receipt.clone();
        let owned = error.into_execution_failure().unwrap();
        assert_eq!(owned, expected);
    }

    #[tokio::test]
    async fn failed_active_execution_receipt_preserves_the_resolved_stage_and_route() {
        let mut registry = DecisionExecutorRegistry::new();
        registry
            .register(failing_executor(
                "plugin.active-http",
                DecisionExecutionFailureKind::BlockedByPolicy,
                "active requests are disabled by host policy",
            ))
            .unwrap();
        registry
            .route_action(
                DecisionExecutionStage::Active,
                "http.probe",
                "plugin.active-http",
            )
            .unwrap();
        let adapter = DecisionRunnerAdapter::new(registry);
        let knowledge = KnowledgeBase::new();

        let error = adapter
            .execute_command(
                &DecisionLoopCommand::CollectActiveEvidence {
                    case: case("http.probe"),
                },
                &knowledge,
            )
            .await
            .unwrap_err();
        let receipt = error.execution_failure().unwrap();

        assert_eq!(receipt.action_id(), "http.probe");
        assert_eq!(receipt.stage(), DecisionExecutionStage::Active);
        assert_eq!(receipt.executor_id(), "plugin.active-http");
        assert_eq!(
            receipt.kind(),
            DecisionExecutionFailureKind::BlockedByPolicy
        );
        assert_eq!(knowledge.stats().evidence, 0);
    }

    #[test]
    fn unrestricted_execution_limits_preserve_the_existing_wire_shape() {
        let unrestricted = DecisionExecutionRequest::new(
            case("http.probe"),
            DecisionExecutionStage::Passive,
            Some(DecisionActionOrigin::Planned),
            None,
            DecisionExecutionLimits::default(),
        );
        let unrestricted = serde_json::to_value(unrestricted).unwrap();
        assert!(unrestricted.get("limits").is_none());

        let bounded = DecisionExecutionRequest::new(
            case("http.probe"),
            DecisionExecutionStage::Passive,
            Some(DecisionActionOrigin::Planned),
            None,
            DecisionExecutionLimits::new().with_max_response_body_bytes(64),
        );
        assert_eq!(
            serde_json::to_value(bounded).unwrap()["limits"]["max_response_body_bytes"],
            serde_json::json!(64)
        );
    }

    #[tokio::test]
    async fn action_routes_resolve_adaptive_and_active_executors_separately() {
        let mut registry = DecisionExecutorRegistry::new();
        registry.register(executor("plugin.retry", None)).unwrap();
        registry.register(executor("plugin.verify", None)).unwrap();
        registry
            .route_action(
                DecisionExecutionStage::Passive,
                "http.retry",
                "plugin.retry",
            )
            .unwrap();
        registry
            .route_action(
                DecisionExecutionStage::Active,
                "http.retry",
                "plugin.verify",
            )
            .unwrap();
        let adapter = DecisionRunnerAdapter::new(registry);
        let knowledge = KnowledgeBase::new();
        let adaptive = DecisionLoopCommand::ExecuteAction {
            case: case("http.retry"),
            executor: None,
            origin: DecisionActionOrigin::Adaptive,
            delay_ms: None,
        };
        let active = DecisionLoopCommand::CollectActiveEvidence {
            case: case("http.retry"),
        };

        let passive_receipt = adapter
            .execute_command(&adaptive, &knowledge)
            .await
            .unwrap();
        let active_receipt = adapter.execute_command(&active, &knowledge).await.unwrap();

        assert_eq!(passive_receipt.executor_id(), "plugin.retry");
        assert_eq!(active_receipt.executor_id(), "plugin.verify");
        assert!(active_receipt.baseline().is_some());
        assert_eq!(active_receipt.baseline().unwrap().evidence().len(), 1);
        assert_eq!(active_receipt.after_execution().evidence().len(), 2);
    }

    #[tokio::test]
    async fn invalid_provenance_rejects_the_complete_batch() {
        let mut registry = DecisionExecutorRegistry::new();
        registry
            .register(executor(
                "plugin.http",
                Some(EntityId::new("endpoint:https://other.test").unwrap()),
            ))
            .unwrap();
        let adapter = DecisionRunnerAdapter::new(registry);
        let knowledge = KnowledgeBase::new();
        let command = DecisionLoopCommand::ExecuteAction {
            case: case("http.probe"),
            executor: Some("plugin.http".to_owned()),
            origin: DecisionActionOrigin::Planned,
            delay_ms: None,
        };

        let error = adapter
            .execute_command(&command, &knowledge)
            .await
            .unwrap_err();
        assert!(matches!(
            &error,
            DecisionRunnerError::EvidenceSubjectMismatch { .. }
        ));
        assert!(error.committed_evidence().is_none());
        assert_eq!(knowledge.stats().evidence, 0);
    }

    #[tokio::test]
    async fn post_commit_transition_error_returns_the_durable_receipt() {
        let mut registry = DecisionExecutorRegistry::new();
        registry.register(executor("plugin.http", None)).unwrap();
        let adapter = DecisionRunnerAdapter::new(registry);
        let decision_loop = empty_decision_loop();
        let knowledge = KnowledgeBase::new();
        let mut experience = ExperienceStore::new();
        let mut session = DecisionSession::new(subject());
        let initial_session = session.clone();
        let command = DecisionLoopCommand::ExecuteAction {
            case: case("http.probe"),
            executor: Some("plugin.http".to_owned()),
            origin: DecisionActionOrigin::Planned,
            delay_ms: None,
        };

        let receipt = adapter.execute_command(&command, &knowledge).await.unwrap();
        let evidence_id = receipt.evidence()[0].id().clone();
        let error = adapter
            .resume_session_command(
                &decision_loop,
                &command,
                &knowledge,
                &mut experience,
                &mut session,
                receipt,
            )
            .unwrap_err();

        assert!(matches!(
            &error,
            DecisionRunnerError::OutcomeAfterEvidenceCommit { .. }
        ));
        let committed = error.committed_evidence().unwrap();
        assert_eq!(committed.case().id(), "case:1");
        assert_eq!(committed.evidence()[0].id(), &evidence_id);
        assert!(knowledge
            .snapshot_for_subject(&subject())
            .evidence()
            .iter()
            .any(|evidence| evidence.id() == &evidence_id));
        assert_eq!(session, initial_session);
        assert!(experience.is_empty());

        let committed = error.into_committed_evidence().unwrap();
        assert_eq!(committed.evidence()[0].id(), &evidence_id);
    }

    #[tokio::test]
    async fn unregistered_case_after_low_level_commit_keeps_evidence_auditable() {
        let mut registry = DecisionExecutorRegistry::new();
        registry.register(executor("plugin.http", None)).unwrap();
        let adapter = DecisionRunnerAdapter::new(registry);
        let decision_loop = empty_decision_loop();
        let knowledge = KnowledgeBase::new();
        let mut experience = ExperienceStore::new();
        let command_case = case("http.probe");
        let command = DecisionLoopCommand::ExecuteAction {
            case: command_case.clone(),
            executor: Some("plugin.http".to_owned()),
            origin: DecisionActionOrigin::Planned,
            delay_ms: None,
        };
        let mut session: DecisionSession = serde_json::from_value(serde_json::json!({
            "subject": subject().as_str(),
            "action_cycles": 1,
            "state": {
                "state": "awaiting_passive",
                "case": command_case
            },
            "adaptation": {
                "transitions": 0,
                "rule_applications": {},
                "action_schedules": {},
                "suppressed_actions": []
            }
        }))
        .unwrap();
        let initial_session = session.clone();

        let receipt = adapter.execute_command(&command, &knowledge).await.unwrap();
        let evidence_id = receipt.evidence()[0].id().clone();
        let error = adapter
            .resume_session_command(
                &decision_loop,
                &command,
                &knowledge,
                &mut experience,
                &mut session,
                receipt,
            )
            .unwrap_err();

        assert!(matches!(
            &error,
            DecisionRunnerError::OutcomeAfterEvidenceCommit { source, .. }
                if matches!(
                    source.as_ref(),
                    DecisionRunnerError::Decision(
                        DecisionLoopError::UnregisteredDecisionAction { .. }
                    )
                )
        ));
        let committed = error.committed_evidence().unwrap();
        assert_eq!(committed.evidence()[0].id(), &evidence_id);
        assert!(knowledge
            .snapshot_for_subject(&subject())
            .evidence()
            .iter()
            .any(|evidence| evidence.id() == &evidence_id));
        assert_eq!(session, initial_session);
        assert!(experience.is_empty());
    }

    #[tokio::test]
    async fn drive_command_rejects_stale_session_before_executor_work() {
        let mut registry = DecisionExecutorRegistry::new();
        registry.register(executor("plugin.http", None)).unwrap();
        let adapter = DecisionRunnerAdapter::new(registry);
        let (decision_loop, knowledge) = loop_with_supported_http_action();
        let mut experience = ExperienceStore::new();
        let mut session = DecisionSession::new(subject());
        let command = DecisionLoopCommand::ExecuteAction {
            case: case("http.probe"),
            executor: Some("plugin.http".to_owned()),
            origin: DecisionActionOrigin::Planned,
            delay_ms: None,
        };

        assert!(matches!(
            adapter
                .drive_command(
                    &decision_loop,
                    &command,
                    &knowledge,
                    &mut experience,
                    &mut session,
                )
                .await,
            Err(DecisionRunnerError::UnexpectedSessionState { .. })
        ));
        assert_eq!(knowledge.stats().evidence, 0);
    }

    #[tokio::test]
    async fn context_free_drive_rejects_every_continuation_before_executor_work() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut registry = DecisionExecutorRegistry::new();
        registry
            .register(Arc::new(CountingExecutor {
                id: "plugin.http",
                calls: Arc::clone(&calls),
            }))
            .unwrap();
        let adapter = DecisionRunnerAdapter::new(registry);
        let decision_loop = empty_decision_loop();
        let knowledge = KnowledgeBase::new();
        let commands = [
            DecisionLoopCommand::ExecuteAction {
                case: case("http.probe"),
                executor: Some("plugin.http".to_owned()),
                origin: DecisionActionOrigin::Adaptive,
                delay_ms: None,
            },
            DecisionLoopCommand::ExecuteAction {
                case: case("http.probe"),
                executor: Some("plugin.http".to_owned()),
                origin: DecisionActionOrigin::Retry,
                delay_ms: None,
            },
            DecisionLoopCommand::CollectActiveEvidence {
                case: case("http.probe"),
            },
            DecisionLoopCommand::Replan,
        ];

        for (command, expected) in commands.into_iter().zip([
            "adaptive_execute_action",
            "retry_execute_action",
            "collect_active_evidence",
            "replan",
        ]) {
            let mut experience = ExperienceStore::new();
            let mut session = DecisionSession::new(subject());
            assert!(matches!(
                adapter
                    .drive_command(
                        &decision_loop,
                        &command,
                        &knowledge,
                        &mut experience,
                        &mut session,
                    )
                    .await,
                Err(DecisionRunnerError::HostPolicyContextRequired { command })
                    if command == expected
            ));
            assert_eq!(session, DecisionSession::new(subject()));
            assert!(experience.is_empty());
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(knowledge.stats().evidence, 0);
    }

    #[tokio::test]
    async fn current_host_suppression_rejects_execution_before_executor_work() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut registry = DecisionExecutorRegistry::new();
        registry
            .register(Arc::new(CountingExecutor {
                id: "plugin.http",
                calls: Arc::clone(&calls),
            }))
            .unwrap();
        let adapter = DecisionRunnerAdapter::new(registry);
        let decision_loop = empty_decision_loop();
        let knowledge = KnowledgeBase::new();
        let suppressions = BTreeSet::from(["http.probe".to_owned()]);
        let commands = [
            DecisionLoopCommand::ExecuteAction {
                case: case("http.probe"),
                executor: Some("plugin.http".to_owned()),
                origin: DecisionActionOrigin::Planned,
                delay_ms: None,
            },
            DecisionLoopCommand::CollectActiveEvidence {
                case: case("http.probe"),
            },
        ];

        for command in commands {
            let mut experience = ExperienceStore::new();
            let mut session = DecisionSession::new(subject());
            assert!(matches!(
                adapter
                    .drive_command_with_suppressed_actions(
                        &decision_loop,
                        &command,
                        &knowledge,
                        &mut experience,
                        &mut session,
                        &suppressions,
                    )
                    .await,
                Err(DecisionRunnerError::ActionSuppressedByHostPolicy { action_id })
                    if action_id == "http.probe"
            ));
            assert_eq!(session, DecisionSession::new(subject()));
            assert!(experience.is_empty());
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(knowledge.stats().evidence, 0);
    }

    #[tokio::test]
    async fn high_level_runner_rejects_broadened_knowledge_only_replay_before_executor_work() {
        for active in [false, true] {
            let (decision_loop, knowledge) =
                loop_with_supported_http_action_target(VerificationTarget::KnowledgeOnly);
            let experience = ExperienceStore::new();
            let mut issued = DecisionSession::new(subject());
            decision_loop
                .plan_next(&knowledge, &experience, &mut issued)
                .unwrap();
            let mut wire = serde_json::to_value(&issued).unwrap();
            let state = wire["state"].as_object_mut().unwrap();
            if active {
                state.insert("state".to_owned(), serde_json::json!("awaiting_active"));
            }
            let case_wire = state["case"].as_object_mut().unwrap();
            case_wire.remove("applies_hypothesis_transition");
            case_wire.remove("payload_claim_policy_guard");
            let mut session: DecisionSession = serde_json::from_value(wire).unwrap();
            let broadened_case = match session.state() {
                DecisionLoopState::AwaitingPassive { case }
                | DecisionLoopState::AwaitingActive { case } => case.clone(),
                state => panic!("expected replayed outstanding case, got {state:?}"),
            };
            assert!(broadened_case.applies_hypothesis_transition());
            let command = if active {
                DecisionLoopCommand::CollectActiveEvidence {
                    case: broadened_case,
                }
            } else {
                DecisionLoopCommand::ExecuteAction {
                    case: broadened_case,
                    executor: Some("plugin.http".to_owned()),
                    origin: DecisionActionOrigin::Planned,
                    delay_ms: None,
                }
            };
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let executor_id = if active {
                "plugin.active"
            } else {
                "plugin.http"
            };
            let mut registry = DecisionExecutorRegistry::new();
            registry
                .register(Arc::new(CountingExecutor {
                    id: executor_id,
                    calls: Arc::clone(&calls),
                }))
                .unwrap();
            if active {
                registry
                    .route_action(DecisionExecutionStage::Active, "http.probe", executor_id)
                    .unwrap();
            }
            let adapter = DecisionRunnerAdapter::new(registry);
            let before_session = session.clone();
            let mut replay_experience = experience.clone();

            let error = adapter
                .drive_command_with_suppressed_actions(
                    &decision_loop,
                    &command,
                    &knowledge,
                    &mut replay_experience,
                    &mut session,
                    &BTreeSet::new(),
                )
                .await
                .unwrap_err();

            assert!(matches!(
                error,
                DecisionRunnerError::Decision(
                    DecisionLoopError::DecisionCaseAuthorityExceeded { action_id }
                ) if action_id == "http.probe"
            ));
            assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
            assert_eq!(knowledge.stats().evidence, 0);
            assert_eq!(session, before_session);
            assert_eq!(replay_experience, experience);
        }
    }

    #[tokio::test]
    async fn explicit_empty_host_policy_allows_authorized_adaptive_and_retry_execution() {
        for origin in [DecisionActionOrigin::Adaptive, DecisionActionOrigin::Retry] {
            let (decision_loop, knowledge) = loop_with_supported_http_action();
            let mut experience = ExperienceStore::new();
            let mut session = DecisionSession::new(subject());
            let planning = decision_loop
                .plan_next(&knowledge, &experience, &mut session)
                .unwrap();
            let (case, executor) = match planning.command() {
                DecisionLoopCommand::ExecuteAction { case, executor, .. } => {
                    (case.clone(), executor.clone())
                },
                other => panic!("expected planned execution, got {other:?}"),
            };
            let command = DecisionLoopCommand::ExecuteAction {
                case,
                executor,
                origin,
                delay_ms: None,
            };
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let mut registry = DecisionExecutorRegistry::new();
            registry
                .register(Arc::new(CountingExecutor {
                    id: "plugin.http",
                    calls: Arc::clone(&calls),
                }))
                .unwrap();
            let adapter = DecisionRunnerAdapter::new(registry);

            let turn = adapter
                .drive_command_with_suppressed_actions(
                    &decision_loop,
                    &command,
                    &knowledge,
                    &mut experience,
                    &mut session,
                    &BTreeSet::new(),
                )
                .await
                .unwrap();

            assert!(matches!(
                turn,
                DecisionRunnerTurn::Outcome { decision, .. }
                    if matches!(decision.command(), DecisionLoopCommand::CollectActiveEvidence { .. })
            ));
            assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
            assert_eq!(knowledge.stats().evidence, 1);
        }
    }

    #[tokio::test]
    async fn suppression_aware_replan_forwards_policy_into_planning() {
        let adapter = DecisionRunnerAdapter::new(DecisionExecutorRegistry::new());
        let (decision_loop, knowledge) = loop_with_supported_http_action();
        let mut experience = ExperienceStore::new();
        let mut session = DecisionSession::new(subject());

        let turn = adapter
            .drive_command_with_suppressed_actions(
                &decision_loop,
                &DecisionLoopCommand::Replan,
                &knowledge,
                &mut experience,
                &mut session,
                &BTreeSet::from(["http.probe".to_owned()]),
            )
            .await
            .unwrap();

        assert!(matches!(
            turn,
            DecisionRunnerTurn::Planning(report)
                if report.plan().steps().is_empty()
                    && report.suppressed_actions().contains("http.probe")
                    && matches!(report.command(), DecisionLoopCommand::Halt { .. })
        ));
    }

    #[tokio::test]
    async fn replan_command_with_explicit_host_policy_advances_without_an_executor() {
        let adapter = DecisionRunnerAdapter::new(DecisionExecutorRegistry::new());
        let decision_loop = empty_decision_loop();
        let knowledge = KnowledgeBase::new();
        let mut experience = ExperienceStore::new();
        let mut session = DecisionSession::new(subject());

        let turn = adapter
            .drive_command_with_suppressed_actions(
                &decision_loop,
                &DecisionLoopCommand::Replan,
                &knowledge,
                &mut experience,
                &mut session,
                &BTreeSet::new(),
            )
            .await
            .unwrap();

        assert!(matches!(
            turn,
            DecisionRunnerTurn::Planning(report)
                if matches!(report.command(), DecisionLoopCommand::Halt { .. })
        ));
        assert!(matches!(session.state(), DecisionLoopState::Halted { .. }));
    }

    #[tokio::test]
    async fn planned_action_runs_through_evidence_and_passive_verification() {
        let mut decision_loop = empty_decision_loop();
        let hypothesis_predicate = KnowledgePredicate::new("stack", "framework").unwrap();
        let hypothesis_value = EvidenceValue::Text("Laravel".to_owned());
        decision_loop
            .planner_mut()
            .register(
                AttackAction::new(
                    "http.probe",
                    "plugin.http",
                    Expression::equals(
                        KnowledgeLayer::Hypothesis,
                        hypothesis_predicate.clone(),
                        hypothesis_value.clone(),
                    ),
                    HypothesisSelector::new(
                        hypothesis_predicate.clone(),
                        hypothesis_value.clone(),
                        Probability::from_percent(50).unwrap(),
                        RequiredStrength::Strong,
                    ),
                    BenefitScore::from_percent(80).unwrap(),
                    ActionCost::new(10).unwrap(),
                    RiskScore::from_percent(20).unwrap(),
                    std::collections::BTreeSet::new(),
                )
                .unwrap(),
            )
            .unwrap();
        decision_loop
            .verification_mut()
            .passive_mut()
            .register(
                VerificationRule::new(
                    "verify.http-200",
                    VerificationStage::Passive,
                    100,
                    Expression::equals(
                        KnowledgeLayer::Evidence,
                        KnowledgePredicate::new("http.response", "status").unwrap(),
                        EvidenceValue::Unsigned(200),
                    ),
                    OutcomeStatus::Success,
                    Probability::from_percent(95).unwrap(),
                    "HTTP response confirms the action",
                )
                .unwrap(),
            )
            .unwrap();

        let knowledge = KnowledgeBase::new();
        let mut hypothesis = Hypothesis::with_id(
            "hypothesis:1",
            subject(),
            hypothesis_predicate,
            hypothesis_value,
            Probability::from_percent(90).unwrap(),
        )
        .unwrap();
        hypothesis.set_strength(HypothesisStrength::Strong);
        hypothesis.set_state(HypothesisState::Supported);
        knowledge.upsert_hypothesis(hypothesis).unwrap();

        let mut registry = DecisionExecutorRegistry::new();
        registry.register(executor("plugin.http", None)).unwrap();
        let adapter = DecisionRunnerAdapter::new(registry);
        let mut experience = ExperienceStore::new();
        let mut session = DecisionSession::new(subject());
        let planning = decision_loop
            .plan_next(&knowledge, &experience, &mut session)
            .unwrap();

        let turn = adapter
            .drive_command(
                &decision_loop,
                planning.command(),
                &knowledge,
                &mut experience,
                &mut session,
            )
            .await
            .unwrap();

        assert!(matches!(
            turn,
            DecisionRunnerTurn::Outcome { evidence, decision }
                if evidence.writes() == [KnowledgeWrite::Inserted]
                    && decision.verification().outcome().status() == OutcomeStatus::Success
                    && matches!(decision.command(), DecisionLoopCommand::Complete { .. })
        ));
        assert!(matches!(session.state(), DecisionLoopState::Completed));
        assert_eq!(experience.len(), 1);
    }

    #[test]
    fn registry_rejects_ambiguous_routes_and_unknown_executors() {
        let mut registry = DecisionExecutorRegistry::new();
        registry.register(executor("first", None)).unwrap();
        registry.register(executor("second", None)).unwrap();
        registry
            .route_action(DecisionExecutionStage::Active, "verify", "first")
            .unwrap();

        assert!(matches!(
            registry.route_action(DecisionExecutionStage::Active, "verify", "second"),
            Err(DecisionRunnerError::ActionRouteConflict { .. })
        ));
        assert!(matches!(
            registry.route_action(DecisionExecutionStage::Passive, "probe", "missing"),
            Err(DecisionRunnerError::UnknownExecutor { .. })
        ));
    }

    #[cfg(feature = "plugins")]
    struct LegacyPlugin;

    #[cfg(feature = "plugins")]
    #[async_trait]
    impl crate::Plugin for LegacyPlugin {
        fn id(&self) -> &str {
            "legacy.http"
        }

        fn name(&self) -> &str {
            "Legacy HTTP"
        }

        fn version(&self) -> &str {
            "0.1.0"
        }

        fn description(&self) -> &str {
            "test bridge"
        }

        fn author(&self) -> &str {
            "Venom"
        }

        fn category(&self) -> crate::PluginCategory {
            crate::PluginCategory::Custom
        }

        fn enabled(&self) -> bool {
            true
        }

        async fn execute(
            &self,
            target: &str,
            payload: &str,
        ) -> Result<Vec<crate::ScanFinding>, crate::PluginError> {
            Ok(vec![crate::ScanFinding {
                phase: 1,
                module_name: self.id().to_owned(),
                severity: "INFO".to_owned(),
                description: format!("observed {payload}"),
                evidence: target.to_owned(),
            }])
        }
    }

    #[cfg(feature = "plugins")]
    #[tokio::test]
    async fn plugin_registry_bridge_normalizes_findings_into_correlated_evidence() {
        let plugins = Arc::new(crate::PluginRegistry::new());
        plugins.register(Arc::new(LegacyPlugin)).unwrap();
        let input: Arc<dyn PluginInputProvider> =
            Arc::new(|_request: &DecisionExecutionRequest| {
                PluginExecutionInput::new("https://example.test", "server: nginx")
            });
        let bridge = PluginDecisionExecutor::new(
            plugins,
            "legacy.http",
            input,
            ConfidenceScore::from_percent(90).unwrap(),
        )
        .unwrap();
        let mut registry = DecisionExecutorRegistry::new();
        registry.register(Arc::new(bridge)).unwrap();
        let adapter = DecisionRunnerAdapter::new(registry);
        let knowledge = KnowledgeBase::new();
        let command = DecisionLoopCommand::ExecuteAction {
            case: case("http.probe"),
            executor: Some("legacy.http".to_owned()),
            origin: DecisionActionOrigin::Planned,
            delay_ms: None,
        };

        let receipt = adapter.execute_command(&command, &knowledge).await.unwrap();
        let observation = &receipt.after_execution().evidence()[0];

        assert_eq!(receipt.writes(), &[KnowledgeWrite::Inserted]);
        assert_eq!(observation.source().component(), "legacy.http");
        assert_eq!(observation.source().correlation_id(), Some("case:1"));
        assert_eq!(
            observation.predicate().dotted(),
            "plugin.finding.legacy.http"
        );
    }
}
