//! Host-facing runtime for the standard deterministic web decision stack.
//!
//! The runtime owns composition and bounded command driving. Domain layers
//! remain independently testable and the caller remains responsible for
//! target authorization and HTTP evidence policy.

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use thiserror::Error;
use url::Url;
use venom_core::{
    EntityId, EvidenceValue, HttpEvidencePredicate, OutcomeStatus, ReasoningModelError,
};

use crate::{
    AdaptationLimits, BenefitScore, DecisionActionOrigin, DecisionEvidenceReceipt,
    DecisionExecutionLimits, DecisionExecutionStage, DecisionExecutorRegistry, DecisionLoop,
    DecisionLoopCommand, DecisionLoopConfig, DecisionLoopError, DecisionOutcomeReport,
    DecisionPlanningReport, DecisionReasoningCommitReceipt, DecisionRunnerAdapter,
    DecisionRunnerError, DecisionRunnerTurn, DecisionSession, ExperiencePolicy, ExperienceStore,
    ExperienceStoreError, HttpEvidenceError, HttpEvidenceExecutor, HttpEvidencePolicy, HttpProbe,
    HttpProbeMethod, KnowledgeBase, KnowledgeWrite, PlannerError, PlanningContext, RiskScore,
    RuntimeBudget, RuntimeBudgetDimension, RuntimeLimitExceeded, RuntimeUsage,
    StandardApiInstallReport, StandardApiReasoning, StandardApiReasoningError,
    StandardWebActionKind, StandardWebDecisionError, StandardWebDecisionInstallReport,
    StandardWebDecisionProfile, SubjectHttpProbeProvider, VerificationCase, VerificationError,
    HTTP_EVIDENCE_EXECUTOR_ID,
};

mod api_visibility;

pub use api_visibility::RuntimeApiVisibilityError;

const DEFAULT_BUSINESS_VALUE_PERCENT: u8 = 80;
const DEFAULT_PLANNING_BUDGET: u64 = 100;
const DEFAULT_RISK_LIMIT_PERCENT: u8 = 40;
const DEFAULT_MAX_ACTION_CYCLES: u32 = 8;
const DEFAULT_FAILURE_LIMIT: u16 = 10;
const BOOTSTRAP_ACTION_ID: &str = "web.action.bootstrap.http-evidence";
const BOOTSTRAP_CASE_ID: &str = "case:web-runtime:bootstrap:http";
const BOOTSTRAP_HYPOTHESIS_ID: &str = "hypothesis:web-runtime:bootstrap";
/// Construction and execution failures for [`StandardWebDecisionRuntime`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StandardWebDecisionRuntimeError {
    /// A runtime instance was asked to execute its single-use session twice.
    #[error("standard web decision runtime has already started")]
    AlreadyStarted,

    /// A planner score or action policy was invalid.
    #[error(transparent)]
    Planner(#[from] PlannerError),

    /// Decision-loop configuration or state transition failed.
    #[error(transparent)]
    Decision(#[from] DecisionLoopError),

    /// Experience suppression policy was invalid.
    #[error(transparent)]
    Experience(#[from] ExperienceStoreError),

    /// A target-scoped reasoning identity was invalid.
    #[error(transparent)]
    Reasoning(#[from] ReasoningModelError),

    /// A bootstrap verification identity was invalid.
    #[error(transparent)]
    Verification(#[from] VerificationError),

    /// HTTP scope, resource, or collector construction failed.
    #[error(transparent)]
    Http(#[from] HttpEvidenceError),

    /// The standard reasoning, planning, execution, or verification profile failed.
    #[error(transparent)]
    Profile(#[from] StandardWebDecisionError),

    /// The optional JSON response-format and GraphQL surface profile failed to install.
    #[error(transparent)]
    ApiReasoning(#[from] StandardApiReasoningError),

    /// An executor lookup, request, evidence commit, or runner transition failed.
    #[error(transparent)]
    Runner(#[from] DecisionRunnerError),

    /// Standard HTTP execution omitted or duplicated its resource telemetry.
    #[error(
        "execution case {case_id} emitted {observations} unsigned {predicate} observations; expected exactly one"
    )]
    ResponseUsageEvidence {
        /// Execution case whose correlated evidence was invalid.
        case_id: String,
        /// Stable response-body usage predicate.
        predicate: &'static str,
        /// Matching unsigned observations found in the committed snapshot.
        observations: usize,
        /// Durable evidence commit that exposed the telemetry violation.
        receipt: Box<DecisionEvidenceReceipt>,
    },
}

impl StandardWebDecisionRuntimeError {
    /// Returns evidence committed before this runtime error, when applicable.
    pub fn committed_evidence(&self) -> Option<&DecisionEvidenceReceipt> {
        match self {
            Self::Runner(source) => source.committed_evidence(),
            Self::ResponseUsageEvidence { receipt, .. } => Some(receipt),
            _ => None,
        }
    }

    /// Takes ownership of evidence committed before this error without cloning it.
    pub fn into_committed_evidence(self) -> Option<DecisionEvidenceReceipt> {
        match self {
            Self::Runner(source) => source.into_committed_evidence(),
            Self::ResponseUsageEvidence { receipt, .. } => Some(*receipt),
            _ => None,
        }
    }

    /// Returns reasoning committed before a later planning failure, when applicable.
    pub fn committed_reasoning(&self) -> Option<&DecisionReasoningCommitReceipt> {
        match self {
            Self::Decision(source) => source.committed_reasoning(),
            Self::Runner(source) => source.committed_reasoning(),
            _ => None,
        }
    }

    /// Takes a post-reasoning planning receipt without cloning it.
    pub fn into_committed_reasoning(self) -> Option<DecisionReasoningCommitReceipt> {
        match self {
            Self::Decision(source) => source.into_committed_reasoning(),
            Self::Runner(source) => source.into_committed_reasoning(),
            _ => None,
        }
    }
}

/// One non-terminal audit record produced while driving a runtime session.
#[derive(Debug)]
#[non_exhaustive]
pub enum StandardWebDecisionRuntimeTurn {
    /// Reasoning and utility planning selected the next command.
    Planning(Box<DecisionPlanningReport>),
    /// An executor committed evidence and the verifier classified the case.
    Outcome {
        /// Provenance-validated evidence commit receipt.
        evidence: Box<DecisionEvidenceReceipt>,
        /// Verification, adaptation, experience, and next-command report.
        decision: Box<DecisionOutcomeReport>,
    },
}

/// Complete audit trail from bootstrap evidence to a terminal command.
#[derive(Debug)]
pub struct StandardWebDecisionRunReport {
    bootstrap: Option<DecisionEvidenceReceipt>,
    turns: Vec<StandardWebDecisionRuntimeTurn>,
    terminal: DecisionLoopCommand,
    usage: RuntimeUsage,
    limit_exceeded: Option<RuntimeLimitExceeded>,
}

impl StandardWebDecisionRunReport {
    /// Returns the initial GET evidence committed before reasoning starts.
    pub fn bootstrap(&self) -> Option<&DecisionEvidenceReceipt> {
        self.bootstrap.as_ref()
    }

    /// Returns non-terminal planning and outcome turns in execution order.
    pub fn turns(&self) -> &[StandardWebDecisionRuntimeTurn] {
        &self.turns
    }

    /// Returns the command that ended the session.
    pub fn terminal(&self) -> &DecisionLoopCommand {
        &self.terminal
    }

    /// Returns the final resource accounting snapshot.
    pub fn usage(&self) -> &RuntimeUsage {
        &self.usage
    }

    /// Returns the structured runtime limit when the resource envelope stopped execution.
    pub fn limit_exceeded(&self) -> Option<&RuntimeLimitExceeded> {
        self.limit_exceeded.as_ref()
    }

    /// Iterates over planning audit reports in turn order.
    pub fn planning_reports(&self) -> impl Iterator<Item = &DecisionPlanningReport> {
        self.turns.iter().filter_map(|turn| match turn {
            StandardWebDecisionRuntimeTurn::Planning(report) => Some(report.as_ref()),
            StandardWebDecisionRuntimeTurn::Outcome { .. } => None,
        })
    }

    /// Iterates over verified outcome reports in turn order.
    pub fn outcome_reports(&self) -> impl Iterator<Item = &DecisionOutcomeReport> {
        self.turns.iter().filter_map(|turn| match turn {
            StandardWebDecisionRuntimeTurn::Outcome { decision, .. } => Some(decision.as_ref()),
            StandardWebDecisionRuntimeTurn::Planning(_) => None,
        })
    }
}

/// Builder for one target-scoped [`StandardWebDecisionRuntime`].
pub struct StandardWebDecisionRuntimeBuilder {
    target: Url,
    http_policy: Option<HttpEvidencePolicy>,
    business_value_percent: u8,
    planning_budget: u64,
    risk_limit_percent: u8,
    adaptation_limits: AdaptationLimits,
    experience_failure_limit: u16,
    max_action_cycles: u32,
    experience: ExperienceStore,
    runtime_budget: RuntimeBudget,
    api_reasoning_enabled: bool,
}

impl StandardWebDecisionRuntimeBuilder {
    /// Creates a builder with conservative deterministic defaults.
    pub fn new(target: Url) -> Self {
        Self {
            target,
            http_policy: None,
            business_value_percent: DEFAULT_BUSINESS_VALUE_PERCENT,
            planning_budget: DEFAULT_PLANNING_BUDGET,
            risk_limit_percent: DEFAULT_RISK_LIMIT_PERCENT,
            adaptation_limits: AdaptationLimits::default(),
            experience_failure_limit: DEFAULT_FAILURE_LIMIT,
            max_action_cycles: DEFAULT_MAX_ACTION_CYCLES,
            experience: ExperienceStore::new(),
            runtime_budget: RuntimeBudget::default(),
            api_reasoning_enabled: false,
        }
    }

    /// Enables passive JSON response-format and GraphQL surface reasoning.
    ///
    /// This opt-in reuses evidence already collected by the runtime. It adds no
    /// request, executor, payload, visibility comparison, or planner action.
    pub fn enable_api_reasoning(mut self) -> Self {
        self.api_reasoning_enabled = true;
        self
    }

    /// Replaces the default single-origin HTTP evidence policy.
    pub fn http_policy(mut self, policy: HttpEvidencePolicy) -> Self {
        self.http_policy = Some(policy);
        self
    }

    /// Sets target business value as an integer percentage.
    pub fn business_value(mut self, percent: u8) -> Self {
        self.business_value_percent = percent;
        self
    }

    /// Sets the planner's total action-cost budget.
    pub fn planning_budget(mut self, budget: u64) -> Self {
        self.planning_budget = budget;
        self
    }

    /// Sets the maximum accepted action risk as an integer percentage.
    pub fn risk_limit(mut self, percent: u8) -> Self {
        self.risk_limit_percent = percent;
        self
    }

    /// Replaces the adaptive transition limits.
    pub fn adaptation_limits(mut self, limits: AdaptationLimits) -> Self {
        self.adaptation_limits = limits;
        self
    }

    /// Sets the consecutive completed-failure suppression threshold.
    pub fn experience_failure_limit(mut self, limit: u16) -> Self {
        self.experience_failure_limit = limit;
        self
    }

    /// Sets the maximum number of passive action executions in one session.
    pub fn max_action_cycles(mut self, cycles: u32) -> Self {
        self.max_action_cycles = cycles;
        self
    }

    /// Seeds the runtime with experience retained by the host.
    pub fn experience_store(mut self, experience: ExperienceStore) -> Self {
        self.experience = experience;
        self
    }

    /// Replaces the complete runtime resource envelope.
    pub fn runtime_budget(mut self, budget: RuntimeBudget) -> Self {
        self.runtime_budget = budget;
        self
    }

    /// Sets the total bootstrap, passive, active, adaptive, and retry request limit.
    pub fn max_total_requests(mut self, limit: u32) -> Self {
        self.runtime_budget = self.runtime_budget.with_max_total_requests(limit);
        self
    }

    /// Sets the monotonic deadline for the complete runtime.
    pub fn max_wall_time(mut self, limit: Duration) -> Self {
        self.runtime_budget = self.runtime_budget.with_max_wall_time(limit);
        self
    }

    /// Sets the cumulative buffered response-body byte limit.
    pub fn max_response_bytes(mut self, limit: u64) -> Self {
        self.runtime_budget = self.runtime_budget.with_max_response_bytes(limit);
        self
    }

    /// Sets the maximum number of explicit active verification requests.
    pub fn max_active_verifications(mut self, limit: u16) -> Self {
        self.runtime_budget = self.runtime_budget.with_max_active_verifications(limit);
        self
    }

    /// Sets the maximum number of attempts for one semantic action.
    pub fn max_same_action_attempts(mut self, limit: u16) -> Self {
        self.runtime_budget = self.runtime_budget.with_max_same_action_attempts(limit);
        self
    }

    /// Sets the maximum consecutive completed execution turns without progress.
    pub fn max_consecutive_no_progress_turns(mut self, limit: u16) -> Self {
        self.runtime_budget = self
            .runtime_budget
            .with_max_consecutive_no_progress_turns(limit);
        self
    }

    /// Validates policy and composes the complete standard runtime.
    pub fn build(self) -> Result<StandardWebDecisionRuntime, StandardWebDecisionRuntimeError> {
        let policy = match self.http_policy {
            Some(policy) => policy,
            None => HttpEvidencePolicy::for_origin(self.target.clone())?,
        };
        let probe = HttpProbe::new(self.target.clone(), HttpProbeMethod::Get)?;
        if !policy
            .allowed_origins()
            .contains(&probe.url().origin().ascii_serialization())
        {
            return Err(HttpEvidenceError::TargetOutsidePolicy {
                url: self.target.to_string(),
            }
            .into());
        }

        let planning = PlanningContext::new(
            BenefitScore::from_percent(self.business_value_percent)?,
            self.planning_budget,
            RiskScore::from_percent(self.risk_limit_percent)?,
        );
        let config = DecisionLoopConfig::new(
            planning,
            self.adaptation_limits,
            ExperiencePolicy::new(self.experience_failure_limit)?,
            self.max_action_cycles,
        )?;
        let subject = EntityId::new(format!("endpoint:{}", self.target))?;
        let knowledge = KnowledgeBase::new();
        let mut decision_loop = DecisionLoop::new(config);
        let mut executors = DecisionExecutorRegistry::new();

        let profile = StandardWebDecisionProfile::new(policy.clone())?;
        let installation = profile.install(&knowledge, &mut decision_loop, &mut executors)?;
        let api_reasoning_installation = if self.api_reasoning_enabled {
            let profile = StandardApiReasoning::new()?;
            Some(profile.install(&knowledge, decision_loop.rules_mut())?)
        } else {
            None
        };
        executors.register(Arc::new(HttpEvidenceExecutor::new(
            policy,
            Arc::new(SubjectHttpProbeProvider::new(HttpProbeMethod::Get)),
        )?))?;

        let unsupported_actions = StandardWebActionKind::all()
            .into_iter()
            .filter(|kind| !executors.contains(kind.executor_id()))
            .map(|kind| kind.action_id().to_owned())
            .collect();

        Ok(StandardWebDecisionRuntime {
            target: self.target,
            subject: subject.clone(),
            installation,
            api_reasoning_installation,
            unsupported_actions,
            knowledge,
            decision_loop,
            runner: DecisionRunnerAdapter::new(executors),
            experience: self.experience,
            session: DecisionSession::new(subject),
            budget: self.runtime_budget,
            usage: RuntimeUsage::default(),
            started: false,
        })
    }
}

/// Single-use target runtime for evidence collection and deterministic decisions.
///
/// # Examples
///
/// ```rust,no_run
/// use url::Url;
/// use venom_scanner::StandardWebDecisionRuntime;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let target = Url::parse("https://example.test/")?;
/// let mut runtime = StandardWebDecisionRuntime::builder(target)
///     .planning_budget(100)
///     .risk_limit(40)
///     .max_action_cycles(8)
///     .enable_api_reasoning()
///     .build()?;
///
/// let report = runtime.analyze().await?;
/// println!("terminal command: {:?}", report.terminal());
/// # Ok(())
/// # }
/// ```
pub struct StandardWebDecisionRuntime {
    target: Url,
    subject: EntityId,
    installation: StandardWebDecisionInstallReport,
    api_reasoning_installation: Option<StandardApiInstallReport>,
    unsupported_actions: BTreeSet<String>,
    knowledge: KnowledgeBase,
    decision_loop: DecisionLoop,
    runner: DecisionRunnerAdapter,
    experience: ExperienceStore,
    session: DecisionSession,
    budget: RuntimeBudget,
    usage: RuntimeUsage,
    started: bool,
}

impl StandardWebDecisionRuntime {
    /// Starts a target-scoped runtime builder.
    pub fn builder(target: Url) -> StandardWebDecisionRuntimeBuilder {
        StandardWebDecisionRuntimeBuilder::new(target)
    }

    /// Returns the authorized target supplied by the host.
    pub fn target(&self) -> &Url {
        &self.target
    }

    /// Returns the stable endpoint subject used by every runtime layer.
    pub fn subject(&self) -> &EntityId {
        &self.subject
    }

    /// Returns the standard profile installation receipt.
    pub fn installation(&self) -> StandardWebDecisionInstallReport {
        self.installation
    }

    /// Returns the passive API reasoning installation receipt when enabled.
    pub fn api_reasoning_installation(&self) -> Option<StandardApiInstallReport> {
        self.api_reasoning_installation
    }

    /// Returns actions omitted because no executor was installed for them.
    pub fn unsupported_actions(&self) -> &BTreeSet<String> {
        &self.unsupported_actions
    }

    /// Returns the runtime knowledge base for audit and reporting.
    pub fn knowledge(&self) -> &KnowledgeBase {
        &self.knowledge
    }

    /// Returns learned target-scoped outcomes.
    pub fn experience(&self) -> &ExperienceStore {
        &self.experience
    }

    /// Returns the replayable session state.
    pub fn session(&self) -> &DecisionSession {
        &self.session
    }

    /// Returns the immutable resource envelope for this session.
    pub const fn budget(&self) -> RuntimeBudget {
        self.budget
    }

    /// Returns current resource accounting, including failed request attempts.
    pub fn usage(&self) -> &RuntimeUsage {
        &self.usage
    }

    /// Returns whether execution has been attempted.
    pub fn has_started(&self) -> bool {
        self.started
    }

    /// Consumes the runtime and returns its learned experience.
    pub fn into_experience(self) -> ExperienceStore {
        self.experience
    }

    /// Collects bootstrap evidence and drives commands to a terminal state.
    ///
    /// The runtime is single-use even when execution returns an error. This
    /// prevents a caller from replaying a partially committed network session
    /// under the same deterministic case identities.
    pub async fn analyze(
        &mut self,
    ) -> Result<StandardWebDecisionRunReport, StandardWebDecisionRuntimeError> {
        if self.started {
            return Err(StandardWebDecisionRuntimeError::AlreadyStarted);
        }
        self.started = true;
        let started_at = tokio::time::Instant::now();
        let deadline = started_at.checked_add(self.budget.max_wall_time());
        let mut turns = Vec::new();

        let bootstrap_case = VerificationCase::new(
            BOOTSTRAP_CASE_ID,
            self.subject.clone(),
            BOOTSTRAP_ACTION_ID,
            BOOTSTRAP_HYPOTHESIS_ID,
        )?;
        let bootstrap_command = DecisionLoopCommand::ExecuteAction {
            case: bootstrap_case,
            executor: Some(HTTP_EVIDENCE_EXECUTOR_ID.to_owned()),
            origin: DecisionActionOrigin::Bootstrap,
            delay_ms: None,
        };
        let bootstrap_limits = match self.reserve_execution(&bootstrap_command, started_at) {
            Ok(limits) => limits,
            Err(limit) => {
                return Ok(self.limit_report(None, turns, limit, started_at));
            },
        };
        let bootstrap_result = match deadline {
            Some(deadline) => tokio::time::timeout_at(
                deadline,
                self.runner.execute_command_with_limits(
                    &bootstrap_command,
                    &self.knowledge,
                    bootstrap_limits,
                ),
            )
            .await
            .map_err(|_| ()),
            None => Ok(self
                .runner
                .execute_command_with_limits(&bootstrap_command, &self.knowledge, bootstrap_limits)
                .await),
        };
        let bootstrap = match bootstrap_result {
            Ok(result) => {
                self.refresh_elapsed(started_at);
                result?
            },
            Err(()) => {
                let limit = self.wall_limit(started_at);
                return Ok(self.limit_report(None, turns, limit, started_at));
            },
        };
        let bootstrap = self.record_response_usage(bootstrap)?;
        let bootstrap = Some(bootstrap);

        let mut command = DecisionLoopCommand::Replan;
        let terminal = loop {
            match &command {
                DecisionLoopCommand::Replan => {
                    if let Some(limit) = self.wall_limit_if_reached(started_at) {
                        return Ok(self.limit_report(bootstrap, turns, limit, started_at));
                    }
                    let planning = self.decision_loop.plan_next_with_suppressed_actions(
                        &self.knowledge,
                        &self.experience,
                        &mut self.session,
                        &self.unsupported_actions,
                    )?;
                    command = planning.command().clone();
                    turns.push(StandardWebDecisionRuntimeTurn::Planning(Box::new(planning)));
                    if is_terminal(&command) {
                        break command.clone();
                    }
                    if let Some(limit) = self.wall_limit_if_reached(started_at) {
                        return Ok(self.limit_report(bootstrap, turns, limit, started_at));
                    }
                },
                DecisionLoopCommand::ExecuteAction { .. }
                | DecisionLoopCommand::CollectActiveEvidence { .. } => {
                    let previous_stage = execution_stage(&command)
                        .expect("execution commands always have a verification stage");
                    let completed_action_id = execution_action_id(&command)
                        .expect("execution commands always have an action identity")
                        .to_owned();
                    let limits = match self.reserve_execution(&command, started_at) {
                        Ok(limits) => limits,
                        Err(limit) => {
                            return Ok(self.limit_report(bootstrap, turns, limit, started_at));
                        },
                    };
                    let evidence_result = match deadline {
                        Some(deadline) => tokio::time::timeout_at(
                            deadline,
                            self.runner.execute_session_command_with_limits(
                                &command,
                                &self.knowledge,
                                &self.session,
                                limits,
                            ),
                        )
                        .await
                        .map_err(|_| ()),
                        None => Ok(self
                            .runner
                            .execute_session_command_with_limits(
                                &command,
                                &self.knowledge,
                                &self.session,
                                limits,
                            )
                            .await),
                    };
                    let evidence = match evidence_result {
                        Ok(result) => {
                            self.refresh_elapsed(started_at);
                            result?
                        },
                        Err(()) => {
                            let limit = self.wall_limit(started_at);
                            return Ok(self.limit_report(bootstrap, turns, limit, started_at));
                        },
                    };
                    let evidence = self.record_response_usage(evidence)?;
                    let runner_turn = self.runner.resume_session_command(
                        &self.decision_loop,
                        &command,
                        &self.knowledge,
                        &mut self.experience,
                        &mut self.session,
                        evidence,
                    );
                    self.refresh_elapsed(started_at);
                    let runner_turn = runner_turn?;
                    match runner_turn {
                        DecisionRunnerTurn::Planning(planning) => {
                            command = planning.command().clone();
                            turns.push(StandardWebDecisionRuntimeTurn::Planning(planning));
                        },
                        DecisionRunnerTurn::Outcome { evidence, decision } => {
                            command = decision.command().clone();
                            let progressed =
                                outcome_made_progress(previous_stage, &command, decision.as_ref());
                            self.usage.record_execution_progress(progressed);
                            turns.push(StandardWebDecisionRuntimeTurn::Outcome {
                                evidence,
                                decision,
                            });
                            if is_terminal(&command) {
                                break command.clone();
                            }
                            if self.usage.consecutive_no_progress_turns()
                                >= self.budget.max_consecutive_no_progress_turns()
                                && !progressed
                            {
                                let limit = RuntimeLimitExceeded::new(
                                    RuntimeBudgetDimension::ConsecutiveNoProgressTurns,
                                    u64::from(self.budget.max_consecutive_no_progress_turns()),
                                    u64::from(self.usage.consecutive_no_progress_turns()),
                                    Some(completed_action_id),
                                );
                                return Ok(self.limit_report(bootstrap, turns, limit, started_at));
                            }
                            if let Some(limit) = self.wall_limit_if_reached(started_at) {
                                return Ok(self.limit_report(bootstrap, turns, limit, started_at));
                            }
                        },
                        DecisionRunnerTurn::Terminal(terminal) => break terminal,
                    }
                },
                DecisionLoopCommand::Complete { .. }
                | DecisionLoopCommand::AwaitHumanReview { .. }
                | DecisionLoopCommand::Halt { .. } => break command.clone(),
            }
        };

        self.refresh_elapsed(started_at);

        Ok(StandardWebDecisionRunReport {
            bootstrap,
            turns,
            terminal,
            usage: self.usage.clone(),
            limit_exceeded: None,
        })
    }

    fn reserve_execution(
        &mut self,
        command: &DecisionLoopCommand,
        started_at: tokio::time::Instant,
    ) -> Result<DecisionExecutionLimits, RuntimeLimitExceeded> {
        if let Some(limit) = self.wall_limit_if_reached(started_at) {
            return Err(limit);
        }
        let (action_id, stage, origin) = execution_metadata(command)
            .expect("runtime reserves resources only for execution commands");

        if self.usage.total_requests() >= self.budget.max_total_requests() {
            return Err(RuntimeLimitExceeded::new(
                RuntimeBudgetDimension::TotalRequests,
                u64::from(self.budget.max_total_requests()),
                u64::from(self.usage.total_requests()).saturating_add(1),
                Some(action_id.to_owned()),
            ));
        }
        if self.usage.response_bytes() >= self.budget.max_response_bytes() {
            return Err(RuntimeLimitExceeded::new(
                RuntimeBudgetDimension::ResponseBytes,
                self.budget.max_response_bytes(),
                self.usage.response_bytes(),
                Some(action_id.to_owned()),
            ));
        }
        if stage == DecisionExecutionStage::Active
            && self.usage.active_verifications() >= self.budget.max_active_verifications()
        {
            return Err(RuntimeLimitExceeded::new(
                RuntimeBudgetDimension::ActiveVerifications,
                u64::from(self.budget.max_active_verifications()),
                u64::from(self.usage.active_verifications()).saturating_add(1),
                Some(action_id.to_owned()),
            ));
        }
        let attempts = self.usage.same_action_attempts(action_id);
        if attempts >= self.budget.max_same_action_attempts() {
            return Err(RuntimeLimitExceeded::new(
                RuntimeBudgetDimension::SameActionAttempts,
                u64::from(self.budget.max_same_action_attempts()),
                u64::from(attempts).saturating_add(1),
                Some(action_id.to_owned()),
            ));
        }

        self.usage.reserve_request(action_id, stage, origin);
        let remaining = self
            .budget
            .max_response_bytes()
            .saturating_sub(self.usage.response_bytes());
        Ok(DecisionExecutionLimits::new().with_max_response_body_bytes(remaining))
    }

    fn record_response_usage(
        &mut self,
        receipt: DecisionEvidenceReceipt,
    ) -> Result<DecisionEvidenceReceipt, StandardWebDecisionRuntimeError> {
        let response_body_bytes =
            HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED.into_knowledge();
        let correlated: Vec<_> = receipt
            .evidence()
            .iter()
            .filter(|evidence| {
                evidence.source().correlation_id() == Some(receipt.case().id())
                    && evidence.predicate() == &response_body_bytes
            })
            .filter_map(|evidence| match evidence.value() {
                EvidenceValue::Unsigned(bytes) => Some(*bytes),
                _ => None,
            })
            .collect();
        if correlated.len() != 1 {
            return Err(StandardWebDecisionRuntimeError::ResponseUsageEvidence {
                case_id: receipt.case().id().to_owned(),
                predicate: HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED.dotted(),
                observations: correlated.len(),
                receipt: Box::new(receipt),
            });
        }
        self.usage.record_response_bytes(correlated[0]);
        Ok(receipt)
    }

    fn refresh_elapsed(&mut self, started_at: tokio::time::Instant) {
        self.usage.set_elapsed(started_at.elapsed());
    }

    fn wall_limit_if_reached(
        &mut self,
        started_at: tokio::time::Instant,
    ) -> Option<RuntimeLimitExceeded> {
        self.refresh_elapsed(started_at);
        (started_at.elapsed() >= self.budget.max_wall_time()).then(|| self.wall_limit(started_at))
    }

    fn wall_limit(&mut self, started_at: tokio::time::Instant) -> RuntimeLimitExceeded {
        self.refresh_elapsed(started_at);
        RuntimeLimitExceeded::new(
            RuntimeBudgetDimension::WallTime,
            self.budget.max_wall_time_ms(),
            self.usage.elapsed_ms().max(self.budget.max_wall_time_ms()),
            None,
        )
    }

    fn limit_report(
        &mut self,
        bootstrap: Option<DecisionEvidenceReceipt>,
        turns: Vec<StandardWebDecisionRuntimeTurn>,
        limit: RuntimeLimitExceeded,
        started_at: tokio::time::Instant,
    ) -> StandardWebDecisionRunReport {
        self.refresh_elapsed(started_at);
        self.session.halt_for_runtime_budget();
        StandardWebDecisionRunReport {
            bootstrap,
            turns,
            terminal: DecisionLoopCommand::Halt {
                reason: crate::DecisionStopReason::RuntimeBudgetLimit,
            },
            usage: self.usage.clone(),
            limit_exceeded: Some(limit),
        }
    }
}

fn execution_metadata(
    command: &DecisionLoopCommand,
) -> Option<(&str, DecisionExecutionStage, Option<DecisionActionOrigin>)> {
    match command {
        DecisionLoopCommand::ExecuteAction { case, origin, .. } => Some((
            case.action_id(),
            DecisionExecutionStage::Passive,
            Some(*origin),
        )),
        DecisionLoopCommand::CollectActiveEvidence { case } => {
            Some((case.action_id(), DecisionExecutionStage::Active, None))
        },
        DecisionLoopCommand::Replan
        | DecisionLoopCommand::Complete { .. }
        | DecisionLoopCommand::AwaitHumanReview { .. }
        | DecisionLoopCommand::Halt { .. } => None,
    }
}

fn execution_stage(command: &DecisionLoopCommand) -> Option<DecisionExecutionStage> {
    execution_metadata(command).map(|(_, stage, _)| stage)
}

fn execution_action_id(command: &DecisionLoopCommand) -> Option<&str> {
    execution_metadata(command).map(|(action_id, _, _)| action_id)
}

fn is_terminal(command: &DecisionLoopCommand) -> bool {
    matches!(
        command,
        DecisionLoopCommand::Complete { .. }
            | DecisionLoopCommand::AwaitHumanReview { .. }
            | DecisionLoopCommand::Halt { .. }
    )
}

fn outcome_made_progress(
    previous_stage: DecisionExecutionStage,
    next_command: &DecisionLoopCommand,
    outcome: &DecisionOutcomeReport,
) -> bool {
    let hypothesis_changed = matches!(
        outcome.hypothesis_write(),
        Some(KnowledgeWrite::Inserted | KnowledgeWrite::Updated)
    );
    let escalated_to_active = previous_stage == DecisionExecutionStage::Passive
        && matches!(
            next_command,
            DecisionLoopCommand::CollectActiveEvidence { .. }
        );
    let conclusive = matches!(
        outcome.verification().outcome().status(),
        OutcomeStatus::Success | OutcomeStatus::FalsePositive | OutcomeStatus::ConfirmedNegative
    );
    hypothesis_changed || escalated_to_active || conclusive
}

#[cfg(test)]
#[path = "web_runtime_tests.rs"]
mod tests;
