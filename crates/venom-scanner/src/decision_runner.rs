//! Runner boundary for executing deterministic decision-loop commands.
//!
//! The decision loop chooses an action; this module resolves its executor,
//! honors scheduler delays, records native evidence, and submits the resulting
//! snapshot to the correct verifier. Executors never receive the knowledge
//! base or decision policy, so plugins cannot bypass provenance checks or
//! mutate reasoning state directly.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use venom_core::{EntityId, Evidence};

use crate::{
    DecisionActionOrigin, DecisionLoop, DecisionLoopCommand, DecisionLoopError, DecisionLoopState,
    DecisionOutcomeReport, DecisionPlanningReport, DecisionSession, ExperienceStore, KnowledgeBase,
    KnowledgeBaseError, KnowledgeSnapshot, KnowledgeWrite, VerificationCase,
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
}

/// Failure reported by an isolated action executor.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{message}")]
pub struct DecisionExecutorError {
    message: String,
}

impl DecisionExecutorError {
    /// Creates an executor failure with a stable diagnostic.
    pub fn new(message: impl Into<String>) -> Self {
        let message = message.into();
        Self {
            message: if message.trim().is_empty() {
                "executor failed without a diagnostic".to_owned()
            } else {
                message
            },
        }
    }

    /// Returns the executor-supplied diagnostic.
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Narrow execution API implemented by native collectors and plugin bridges.
#[async_trait]
pub trait DecisionActionExecutor: Send + Sync {
    /// Returns the stable identity used by planner executor fields and routes.
    fn id(&self) -> &str;

    /// Executes one request and returns immutable observations only.
    ///
    /// Every returned observation must describe `request.case().subject()`,
    /// identify this executor as its source component, and carry the case ID as
    /// its source correlation ID. The adapter rejects the complete batch when
    /// any observation violates that contract.
    async fn execute(
        &self,
        request: &DecisionExecutionRequest,
    ) -> Result<Vec<Evidence>, DecisionExecutorError>;
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
    /// Adaptive and active commands intentionally carry only an action ID.
    /// Separate stage routes allow the explicit probe to use a stricter
    /// executor than the original action.
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

    /// Atomic evidence storage failed.
    #[error(transparent)]
    Knowledge(#[from] KnowledgeBaseError),

    /// Resuming the deterministic state machine failed.
    #[error(transparent)]
    Decision(#[from] DecisionLoopError),
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
        if let Some(delay_ms) = delay_ms.filter(|delay| *delay > 0) {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }

        let baseline = (stage == DecisionExecutionStage::Active)
            .then(|| knowledge.snapshot_for_subject(case.subject()));
        let request = DecisionExecutionRequest::new(case.clone(), stage, origin, delay_ms, limits);
        let evidence =
            executor
                .execute(&request)
                .await
                .map_err(|source| DecisionRunnerError::Executor {
                    executor_id: executor_id.clone(),
                    source,
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
    pub async fn drive_command(
        &self,
        decision_loop: &DecisionLoop,
        command: &DecisionLoopCommand,
        knowledge: &KnowledgeBase,
        experience: &mut ExperienceStore,
        session: &mut DecisionSession,
    ) -> Result<DecisionRunnerTurn, DecisionRunnerError> {
        self.drive_command_with_limits(
            decision_loop,
            command,
            knowledge,
            experience,
            session,
            DecisionExecutionLimits::default(),
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
        match command {
            DecisionLoopCommand::ExecuteAction { .. }
            | DecisionLoopCommand::CollectActiveEvidence { .. } => {
                let evidence = self
                    .execute_session_command_with_limits(command, knowledge, session, limits)
                    .await?;
                self.resume_session_command(
                    decision_loop,
                    command,
                    knowledge,
                    experience,
                    session,
                    evidence,
                )
            },
            DecisionLoopCommand::Replan => Ok(DecisionRunnerTurn::Planning(Box::new(
                decision_loop.plan_next(knowledge, experience, session)?,
            ))),
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

    pub(crate) fn resume_session_command(
        &self,
        decision_loop: &DecisionLoop,
        command: &DecisionLoopCommand,
        knowledge: &KnowledgeBase,
        experience: &mut ExperienceStore,
        session: &mut DecisionSession,
        evidence: DecisionEvidenceReceipt,
    ) -> Result<DecisionRunnerTurn, DecisionRunnerError> {
        match command {
            DecisionLoopCommand::ExecuteAction { case, .. } => {
                validate_session_case(session, DecisionExecutionStage::Passive, case)?;
                let decision = decision_loop.submit_passive(knowledge, experience, session)?;
                Ok(DecisionRunnerTurn::Outcome {
                    evidence: Box::new(evidence),
                    decision: Box::new(decision),
                })
            },
            DecisionLoopCommand::CollectActiveEvidence { case } => {
                validate_session_case(session, DecisionExecutionStage::Active, case)?;
                let baseline = evidence
                    .baseline()
                    .ok_or(DecisionRunnerError::MissingActiveBaseline)?;
                let decision = decision_loop.submit_active(
                    knowledge,
                    experience,
                    session,
                    baseline,
                    evidence.after_execution(),
                )?;
                Ok(DecisionRunnerTurn::Outcome {
                    evidence: Box::new(evidence),
                    decision: Box::new(decision),
                })
            },
            DecisionLoopCommand::Replan => {
                Err(DecisionRunnerError::NonExecutionCommand { command: "replan" })
            },
            DecisionLoopCommand::Complete { .. } => Err(DecisionRunnerError::NonExecutionCommand {
                command: "complete",
            }),
            DecisionLoopCommand::AwaitHumanReview { .. } => {
                Err(DecisionRunnerError::NonExecutionCommand {
                    command: "await_human_review",
                })
            },
            DecisionLoopCommand::Halt { .. } => {
                Err(DecisionRunnerError::NonExecutionCommand { command: "halt" })
            },
        }
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
        RequiredStrength, RiskScore, VerificationRule,
    };
    use venom_core::{
        ConfidenceScore, EvidenceKind, EvidenceSource, EvidenceValue, Hypothesis, HypothesisState,
        HypothesisStrength, KnowledgePredicate, OutcomeStatus, Probability, VerificationStage,
    };

    struct RecordingExecutor {
        id: &'static str,
        subject_override: Option<EntityId>,
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

    fn subject() -> EntityId {
        EntityId::new("endpoint:https://example.test").unwrap()
    }

    fn case(action_id: &str) -> VerificationCase {
        VerificationCase::new("case:1", subject(), action_id, "hypothesis:1").unwrap()
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
        assert!(receipt.baseline().is_none());
        assert_eq!(receipt.after_execution().evidence().len(), 1);
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

        assert!(matches!(
            adapter.execute_command(&command, &knowledge).await,
            Err(DecisionRunnerError::EvidenceSubjectMismatch { .. })
        ));
        assert_eq!(knowledge.stats().evidence, 0);
    }

    #[tokio::test]
    async fn drive_command_rejects_stale_session_before_executor_work() {
        let mut registry = DecisionExecutorRegistry::new();
        registry.register(executor("plugin.http", None)).unwrap();
        let adapter = DecisionRunnerAdapter::new(registry);
        let decision_loop = empty_decision_loop();
        let knowledge = KnowledgeBase::new();
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
    async fn replan_command_advances_the_decision_loop_without_an_executor() {
        let adapter = DecisionRunnerAdapter::new(DecisionExecutorRegistry::new());
        let decision_loop = empty_decision_loop();
        let knowledge = KnowledgeBase::new();
        let mut experience = ExperienceStore::new();
        let mut session = DecisionSession::new(subject());

        let turn = adapter
            .drive_command(
                &decision_loop,
                &DecisionLoopCommand::Replan,
                &knowledge,
                &mut experience,
                &mut session,
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
