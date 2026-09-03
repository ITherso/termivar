//! Runner boundary for executing deterministic decision-loop commands.
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
use termivar_core::{EntityId, Evidence};
use thiserror::Error;

use crate::decision_loop::{
    command_requiring_host_policy_context, execution_command_action_id, ActiveEvidenceSnapshots,
};
use crate::planner::ActionSuppressionContext;
use crate::{
    DecisionActionOrigin, DecisionLoop, DecisionLoopCommand, DecisionLoopError, DecisionLoopState,
    DecisionOutcomeReport, DecisionPlanningReport, DecisionReasoningCommitReceipt, DecisionSession,
    ExperienceStore, KnowledgeBase, KnowledgeBaseError, KnowledgeSnapshot, KnowledgeWrite,
    PayloadStrategyRef, RuntimeLimitExceeded, VerificationCase,
};

mod execution;
mod failures;
mod receipts;
mod registry;

pub use execution::{
    DecisionActionExecutor, DecisionExecutionClass, DecisionExecutionLimits,
    DecisionExecutionRequest, DecisionExecutionStage,
};
pub use failures::{DecisionExecutionFailureKind, DecisionExecutorError, DecisionRunnerError};
pub use receipts::{DecisionEvidenceReceipt, DecisionExecutionFailureReceipt, DecisionRunnerTurn};
pub use registry::DecisionExecutorRegistry;

struct ExecutionAuthority<'a> {
    limits: DecisionExecutionLimits,
    suppressions: &'a ActionSuppressionContext,
}

impl<'a> ExecutionAuthority<'a> {
    const fn new(
        limits: DecisionExecutionLimits,
        suppressions: &'a ActionSuppressionContext,
    ) -> Self {
        Self {
            limits,
            suppressions,
        }
    }
}

pub(crate) struct ContinuationAuthority<'a> {
    evidence: DecisionEvidenceReceipt,
    suppressions: &'a ActionSuppressionContext,
}

impl<'a> ContinuationAuthority<'a> {
    pub(crate) const fn new(
        evidence: DecisionEvidenceReceipt,
        suppressions: &'a ActionSuppressionContext,
    ) -> Self {
        Self {
            evidence,
            suppressions,
        }
    }
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

    /// Revalidates the current host suppression authority before any executor,
    /// delay, budget reservation, or transport work.
    pub(crate) fn validate_command_suppression(
        &self,
        command: &DecisionLoopCommand,
        suppressions: &ActionSuppressionContext,
    ) -> Result<(), DecisionRunnerError> {
        let Some(action_id) = execution_command_action_id(command) else {
            return Ok(());
        };
        if suppressions
            .defense_suppressed_actions()
            .contains(action_id)
        {
            return Err(DecisionRunnerError::ActionSuppressedByDefense {
                action_id: action_id.to_owned(),
            });
        }
        if suppressions.policy_suppressed_actions().contains(action_id) {
            return Err(DecisionRunnerError::ActionSuppressedByHostPolicy {
                action_id: action_id.to_owned(),
            });
        }
        Ok(())
    }

    /// Moves a newly defense-suppressed outstanding command back to the
    /// planning boundary without executing it.
    ///
    /// This is intentionally distinct from [`Self::validate_command_suppression`]:
    /// the validator exposes the typed denial for low-level hosts, while the
    /// composed runner consumes that denial as a safe continuation rather than
    /// misreporting it as an execution failure.
    pub(crate) fn replan_defense_suppressed_command(
        &self,
        command: &DecisionLoopCommand,
        session: &mut DecisionSession,
        suppressions: &ActionSuppressionContext,
    ) -> Result<bool, DecisionRunnerError> {
        let Some(action_id) = execution_command_action_id(command) else {
            return Ok(false);
        };
        if !suppressions
            .defense_suppressed_actions()
            .contains(action_id)
        {
            return Ok(false);
        }
        match command {
            DecisionLoopCommand::ExecuteAction { case, .. } => {
                validate_session_case(session, DecisionExecutionStage::Passive, case)?;
            },
            DecisionLoopCommand::CollectActiveEvidence { case } => {
                validate_session_case(session, DecisionExecutionStage::Active, case)?;
            },
            DecisionLoopCommand::Replan
            | DecisionLoopCommand::Complete { .. }
            | DecisionLoopCommand::AwaitHumanReview { .. }
            | DecisionLoopCommand::Halt { .. } => return Ok(false),
        }
        session.replan_after_defense_suppression()?;
        Ok(true)
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
        let suppressions = ActionSuppressionContext::policy_only(host_suppressed_actions);
        self.drive_command_with_action_suppressions(
            decision_loop,
            command,
            knowledge,
            experience,
            session,
            &suppressions,
        )
        .await
    }

    pub(crate) async fn drive_command_with_action_suppressions(
        &self,
        decision_loop: &DecisionLoop,
        command: &DecisionLoopCommand,
        knowledge: &KnowledgeBase,
        experience: &mut ExperienceStore,
        session: &mut DecisionSession,
        suppressions: &ActionSuppressionContext,
    ) -> Result<DecisionRunnerTurn, DecisionRunnerError> {
        self.drive_command_with_optional_suppressions(
            decision_loop,
            command,
            knowledge,
            experience,
            session,
            DecisionExecutionLimits::default(),
            Some(suppressions),
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
        let suppressions = ActionSuppressionContext::policy_only(host_suppressed_actions);
        self.drive_command_with_limits_and_action_suppressions(
            decision_loop,
            command,
            knowledge,
            experience,
            session,
            ExecutionAuthority::new(limits, &suppressions),
        )
        .await
    }

    async fn drive_command_with_limits_and_action_suppressions(
        &self,
        decision_loop: &DecisionLoop,
        command: &DecisionLoopCommand,
        knowledge: &KnowledgeBase,
        experience: &mut ExperienceStore,
        session: &mut DecisionSession,
        authority: ExecutionAuthority<'_>,
    ) -> Result<DecisionRunnerTurn, DecisionRunnerError> {
        self.drive_command_with_optional_suppressions(
            decision_loop,
            command,
            knowledge,
            experience,
            session,
            authority.limits,
            Some(authority.suppressions),
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
        host_suppressions: Option<&ActionSuppressionContext>,
    ) -> Result<DecisionRunnerTurn, DecisionRunnerError> {
        if host_suppressions.is_none() {
            if let Some(command) = command_requiring_host_policy_context(command) {
                return Err(DecisionRunnerError::HostPolicyContextRequired { command });
            }
        }
        if let Some(suppressions) = host_suppressions {
            match self.validate_command_suppression(command, suppressions) {
                Err(source @ DecisionRunnerError::ActionSuppressedByDefense { .. }) => {
                    decision_loop.validate_execution_command_authority(knowledge, command)?;
                    if !self.replan_defense_suppressed_command(command, session, suppressions)? {
                        return Err(source);
                    }
                    let planning = decision_loop.plan_next_with_action_suppressions(
                        knowledge,
                        experience,
                        session,
                        suppressions,
                    )?;
                    return Ok(DecisionRunnerTurn::Planning(Box::new(planning)));
                },
                Err(source) => return Err(source),
                Ok(()) => {},
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
                    host_suppressions,
                )
            },
            DecisionLoopCommand::Replan => {
                let planning = match host_suppressions {
                    Some(suppressions) => decision_loop.plan_next_with_action_suppressions(
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

    pub(crate) fn resume_session_command_with_action_suppressions(
        &self,
        decision_loop: &DecisionLoop,
        command: &DecisionLoopCommand,
        knowledge: &KnowledgeBase,
        experience: &mut ExperienceStore,
        session: &mut DecisionSession,
        continuation: ContinuationAuthority<'_>,
    ) -> Result<DecisionRunnerTurn, DecisionRunnerError> {
        self.resume_session_command_with_optional_suppressions(
            decision_loop,
            command,
            knowledge,
            experience,
            session,
            continuation.evidence,
            Some(continuation.suppressions),
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
        host_suppressions: Option<&ActionSuppressionContext>,
    ) -> Result<DecisionRunnerTurn, DecisionRunnerError> {
        let decision = (|| -> Result<Box<DecisionOutcomeReport>, DecisionRunnerError> {
            match command {
                DecisionLoopCommand::ExecuteAction { case, .. } => {
                    validate_session_case(session, DecisionExecutionStage::Passive, case)?;
                    let report = match host_suppressions {
                        Some(suppressions) => decision_loop
                            .submit_passive_with_action_suppressions(
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
                    let report = match host_suppressions {
                        Some(suppressions) => decision_loop.submit_active_with_action_suppressions(
                            knowledge,
                            experience,
                            session,
                            ActiveEvidenceSnapshots::new(baseline, evidence.after_execution()),
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

/// Host policy that creates one capability-bound plugin invocation.
///
/// The provider receives the complete immutable decision request so it can bind
/// the plugin request to the exact evidence subject and verification case while
/// selecting host-owned origin, broker, input, budget, cancellation, redaction,
/// and reliability policy.
#[cfg(feature = "plugins")]
pub trait PluginExecutionRequestProvider: Send + Sync {
    /// Produces a host-owned plugin request without performing plugin work.
    fn request_for(
        &self,
        request: &DecisionExecutionRequest,
    ) -> Result<crate::PluginExecutionRequest, DecisionExecutorError>;
}

#[cfg(feature = "plugins")]
impl<F> PluginExecutionRequestProvider for F
where
    F: Fn(
            &DecisionExecutionRequest,
        ) -> Result<crate::PluginExecutionRequest, DecisionExecutorError>
        + Send
        + Sync,
{
    fn request_for(
        &self,
        request: &DecisionExecutionRequest,
    ) -> Result<crate::PluginExecutionRequest, DecisionExecutorError> {
        self(request)
    }
}

/// Bridge from the source-level [`crate::PluginRegistry`] to native evidence.
///
/// The request provider remains host-owned because an action ID is neither an
/// authorization grant nor plugin input. The registry returns only recorder-
/// owned evidence, and the regular adapter provenance checks still apply before
/// any knowledge write. A successful plugin invocation is not an outcome or a
/// finding.
#[cfg(feature = "plugins")]
pub struct PluginDecisionExecutor {
    registry: Arc<crate::PluginRegistry>,
    plugin_id: String,
    requests: Arc<dyn PluginExecutionRequestProvider>,
}

#[cfg(feature = "plugins")]
impl PluginDecisionExecutor {
    /// Creates a bridge for one registered plugin identity.
    pub fn new(
        registry: Arc<crate::PluginRegistry>,
        plugin_id: impl Into<String>,
        requests: Arc<dyn PluginExecutionRequestProvider>,
    ) -> Result<Self, DecisionExecutorError> {
        let plugin_id = plugin_id.into();
        if plugin_id.trim().is_empty() {
            return Err(DecisionExecutorError::new("plugin id must not be empty"));
        }
        Ok(Self {
            registry,
            plugin_id,
            requests,
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
        let mut plugin_request = self.requests.request_for(request)?;
        if plugin_request.subject() != request.case().subject() {
            return Err(DecisionExecutorError::with_kind(
                DecisionExecutionFailureKind::BlockedByPolicy,
                "plugin request subject does not match the decision case",
            ));
        }
        if plugin_request.case_id() != request.case().id() {
            return Err(DecisionExecutorError::with_kind(
                DecisionExecutionFailureKind::BlockedByPolicy,
                "plugin request correlation does not match the decision case",
            ));
        }
        if let Some(maximum) = request.limits().max_response_body_bytes() {
            plugin_request = plugin_request.restrict_response_body_bytes(maximum);
        }
        self.registry
            .execute(&self.plugin_id, plugin_request)
            .await
            .map(crate::PluginExecutionResult::into_observations)
            .map_err(plugin_executor_error)
    }
}

#[cfg(feature = "plugins")]
fn plugin_executor_error(error: crate::PluginError) -> DecisionExecutorError {
    use crate::PluginError;
    let kind = match &error {
        PluginError::Disabled
        | PluginError::Cancelled
        | PluginError::InputBudgetExceeded { .. }
        | PluginError::RequestBudgetExceeded
        | PluginError::ResponseBodyBudgetExceeded { .. }
        | PluginError::ResponseBodyBudgetUnavailable
        | PluginError::CumulativeBodyBudgetExceeded
        | PluginError::ObservationBudgetExceeded
        | PluginError::ObservationBytesBudgetExceeded
        | PluginError::ScopeViolation
        | PluginError::ContextSealed => DecisionExecutionFailureKind::BlockedByPolicy,
        PluginError::BrokerFailure(_) => DecisionExecutionFailureKind::TransportFailure,
        PluginError::RequestTimeout | PluginError::WallTimeExceeded => {
            DecisionExecutionFailureKind::RequestTimeout
        },
        _ => DecisionExecutionFailureKind::ExecutorFailure,
    };
    DecisionExecutorError::with_kind(kind, error.to_string())
}

#[cfg(test)]
#[path = "decision_runner/decision_runner_tests.rs"]
mod tests;
