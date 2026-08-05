//! Host-facing runtime for the standard deterministic web decision stack.
//!
//! ## Runtime scope
//!
//! - **Build:** default via `scanning`.
//! - **Execution:** Surface B — this is `StandardWebDecisionRuntime`.
//! - **Default `venom scan`:** no (host/library and `examples/decision_scan.rs`).
//! - **Support:** implemented and tested.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! The runtime owns composition and bounded command driving. Domain layers
//! remain independently testable and the caller remains responsible for
//! target authorization and HTTP evidence policy.

use std::{collections::BTreeSet, future::Future, sync::Arc, time::Duration};

use thiserror::Error;
use tokio_util::sync::CancellationToken;
use url::Url;
use venom_core::{
    EntityId, EvidenceValue, HttpEvidencePredicate, OutcomeStatus, ReasoningModelError,
};

use crate::{
    http_evidence::HttpRequestBroker, runtime_budget::RequestAccountingBroker, AdaptationLimits,
    BenefitScore, DecisionActionOrigin, DecisionEvidenceReceipt, DecisionExecutionFailureReceipt,
    DecisionExecutionLimits, DecisionExecutionStage, DecisionExecutorRegistry, DecisionLoop,
    DecisionLoopCommand, DecisionLoopConfig, DecisionLoopError, DecisionOutcomeReport,
    DecisionPlanningReport, DecisionReasoningCommitReceipt, DecisionRunnerAdapter,
    DecisionRunnerError, DecisionRunnerTurn, DecisionSession, ExperiencePolicy, ExperienceStore,
    ExperienceStoreError, HttpEvidenceError, HttpEvidenceExecutor, HttpEvidencePolicy,
    HttpHeaderPayloadBinding, HttpProbe, HttpProbeMethod, KnowledgeBase, KnowledgeWrite,
    PlannerError, PlanningContext, RiskScore, RuntimeBudget, RuntimeBudgetDimension,
    RuntimeLimitExceeded, RuntimeUsage, StandardApiInstallReport, StandardApiReasoning,
    StandardApiReasoningError, StandardWebActionKind, StandardWebDecisionError,
    StandardWebDecisionInstallReport, StandardWebDecisionProfile, SubjectHttpProbeProvider,
    TransportDispatchAudit, VerificationCase, VerificationError, HTTP_EVIDENCE_EXECUTOR_ID,
};

mod api_visibility;

pub use api_visibility::{
    ApiVisibilityContextProbe, ApiVisibilityDifferentialAudit,
    ApiVisibilityDifferentialDisposition, ApiVisibilityDifferentialRequest,
    ApiVisibilityDifferentialRequestError, ApiVisibilityInconclusiveReason, ApiVisibilityLeg,
    ApiVisibilityLegReceipt, RuntimeApiVisibilityError, RuntimeApiVisibilityExecutionError,
    RuntimeApiVisibilityRunReport,
};

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

    /// A non-execution command reached the transport-accounting boundary.
    #[error("runtime resource accounting requires an execution command")]
    ExecutionMetadataUnavailable,

    /// Execution failed after the single-use runtime had started.
    ///
    /// The receipt preserves every earlier completed turn and the resource
    /// accounting snapshot observed at the failure boundary. The nested source
    /// retains any current execution, evidence, or reasoning receipt.
    #[error("standard web decision runtime failed after it started: {source}")]
    RunFailed {
        /// Completed audit history and final resource usage before the error.
        receipt: Box<StandardWebDecisionFailureReceipt>,
        /// Typed failure raised at the current runtime boundary.
        #[source]
        source: Box<StandardWebDecisionRuntimeError>,
    },
}

impl StandardWebDecisionRuntimeError {
    /// Returns completed audit history captured when a started run failed.
    pub fn failure_receipt(&self) -> Option<&StandardWebDecisionFailureReceipt> {
        match self {
            Self::RunFailed { receipt, .. } => Some(receipt),
            _ => None,
        }
    }

    /// Takes completed audit history captured when a started run failed.
    pub fn into_failure_receipt(self) -> Option<StandardWebDecisionFailureReceipt> {
        match self {
            Self::RunFailed { receipt, .. } => Some(*receipt),
            _ => None,
        }
    }

    /// Returns an executor-reported pre-commit failure receipt, when applicable.
    pub fn execution_failure(&self) -> Option<&DecisionExecutionFailureReceipt> {
        match self {
            Self::Runner(source) => source.execution_failure(),
            Self::RunFailed { source, .. } => source.execution_failure(),
            _ => None,
        }
    }

    /// Takes ownership of an executor-reported failure receipt without cloning it.
    pub fn into_execution_failure(self) -> Option<DecisionExecutionFailureReceipt> {
        match self {
            Self::Runner(source) => source.into_execution_failure(),
            Self::RunFailed { source, .. } => source.into_execution_failure(),
            _ => None,
        }
    }

    /// Returns evidence committed before this runtime error, when applicable.
    pub fn committed_evidence(&self) -> Option<&DecisionEvidenceReceipt> {
        match self {
            Self::Runner(source) => source.committed_evidence(),
            Self::ResponseUsageEvidence { receipt, .. } => Some(receipt),
            Self::RunFailed { source, .. } => source.committed_evidence(),
            _ => None,
        }
    }

    /// Takes ownership of evidence committed before this error without cloning it.
    pub fn into_committed_evidence(self) -> Option<DecisionEvidenceReceipt> {
        match self {
            Self::Runner(source) => source.into_committed_evidence(),
            Self::ResponseUsageEvidence { receipt, .. } => Some(*receipt),
            Self::RunFailed { source, .. } => source.into_committed_evidence(),
            _ => None,
        }
    }

    /// Returns reasoning committed before a later planning failure, when applicable.
    pub fn committed_reasoning(&self) -> Option<&DecisionReasoningCommitReceipt> {
        match self {
            Self::Decision(source) => source.committed_reasoning(),
            Self::Runner(source) => source.committed_reasoning(),
            Self::RunFailed { source, .. } => source.committed_reasoning(),
            _ => None,
        }
    }

    /// Takes a post-reasoning planning receipt without cloning it.
    pub fn into_committed_reasoning(self) -> Option<DecisionReasoningCommitReceipt> {
        match self {
            Self::Decision(source) => source.into_committed_reasoning(),
            Self::Runner(source) => source.into_committed_reasoning(),
            Self::RunFailed { source, .. } => source.into_committed_reasoning(),
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

/// Completed audit history retained when a started runtime returns an error.
///
/// This process-local receipt covers work completed before the failing
/// boundary. Cause-specific receipts for the current boundary remain available
/// through [`StandardWebDecisionRuntimeError`] accessors.
#[derive(Debug)]
pub struct StandardWebDecisionFailureReceipt {
    bootstrap: Option<DecisionEvidenceReceipt>,
    completed_turns: Vec<StandardWebDecisionRuntimeTurn>,
    usage: RuntimeUsage,
    transport: TransportDispatchAudit,
}

impl StandardWebDecisionFailureReceipt {
    /// Returns bootstrap evidence committed before the later failure.
    pub fn bootstrap(&self) -> Option<&DecisionEvidenceReceipt> {
        self.bootstrap.as_ref()
    }

    /// Returns planning and outcome turns completed before the later failure.
    pub fn completed_turns(&self) -> &[StandardWebDecisionRuntimeTurn] {
        &self.completed_turns
    }

    /// Returns resource accounting observed at the failure boundary.
    pub fn usage(&self) -> &RuntimeUsage {
        &self.usage
    }

    /// Returns bounded per-dispatch transport receipts at the failure boundary.
    pub fn transport(&self) -> &TransportDispatchAudit {
        &self.transport
    }
}

/// Complete audit trail from bootstrap evidence to a terminal command.
#[derive(Debug)]
pub struct StandardWebDecisionRunReport {
    bootstrap: Option<DecisionEvidenceReceipt>,
    turns: Vec<StandardWebDecisionRuntimeTurn>,
    unverified_evidence: Option<DecisionEvidenceReceipt>,
    terminal: DecisionLoopCommand,
    usage: RuntimeUsage,
    transport: TransportDispatchAudit,
    limit_exceeded: Option<RuntimeLimitExceeded>,
    execution_failure: Option<DecisionExecutionFailureReceipt>,
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

    /// Returns evidence durably committed before verification was skipped.
    ///
    /// This is populated when execution committed its evidence batch before
    /// host cancellation or a response-byte threshold crossing halted the
    /// turn. The receipt stays outside [`Self::outcome_reports`] because no
    /// verifier outcome exists for this batch.
    pub fn unverified_evidence(&self) -> Option<&DecisionEvidenceReceipt> {
        self.unverified_evidence.as_ref()
    }

    /// Returns the command that ended the session.
    pub fn terminal(&self) -> &DecisionLoopCommand {
        &self.terminal
    }

    /// Returns the final resource accounting snapshot.
    pub fn usage(&self) -> &RuntimeUsage {
        &self.usage
    }

    /// Returns bounded, dispatch-ordered transport receipts for this run.
    pub fn transport(&self) -> &TransportDispatchAudit {
        &self.transport
    }

    /// Returns the structured runtime limit when the resource envelope stopped execution.
    pub fn limit_exceeded(&self) -> Option<&RuntimeLimitExceeded> {
        self.limit_exceeded.as_ref()
    }

    /// Returns the transport execution receipt when a broker-owned resource
    /// limit refused a dispatch after the semantic action had started.
    pub fn execution_failure(&self) -> Option<&DecisionExecutionFailureReceipt> {
        self.execution_failure.as_ref()
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
    payload_binding: Option<HttpHeaderPayloadBinding>,
    cancellation: CancellationToken,
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
            payload_binding: None,
            cancellation: CancellationToken::new(),
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

    /// Binds a header-valued payload strategy to the runtime's HTTP evidence
    /// executor.
    ///
    /// The bound executor shares the runtime's metered request broker, so any
    /// control or candidate artifact it derives and dispatches is accounted like
    /// every other request. This is strictly opt-in: without a binding the
    /// runtime materializes and dispatches no payload artifacts.
    pub fn with_payload_binding(mut self, binding: HttpHeaderPayloadBinding) -> Self {
        self.payload_binding = Some(binding);
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

    /// Replaces the host-owned cancellation token for this runtime.
    ///
    /// Cancellation is reported independently from wall-time and transport
    /// request timeouts. The host should retain a clone when it needs to stop
    /// [`StandardWebDecisionRuntime::analyze`] from another task.
    pub fn cancellation_token(mut self, cancellation: CancellationToken) -> Self {
        self.cancellation = cancellation;
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

    /// Sets the cumulative transport-delivered response-body threshold.
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

        let request_accounting = RequestAccountingBroker::new(self.runtime_budget);
        let requests = HttpRequestBroker::new_metered(policy, request_accounting.clone())?;
        let profile = StandardWebDecisionProfile::new_with_request_broker(requests.clone())?;
        let installation = profile.install(&knowledge, &mut decision_loop, &mut executors)?;
        let api_reasoning_installation = if self.api_reasoning_enabled {
            let profile = StandardApiReasoning::new()?;
            Some(profile.install(&knowledge, decision_loop.rules_mut())?)
        } else {
            None
        };
        let http_evidence = HttpEvidenceExecutor::new_with_request_broker(
            requests.clone(),
            Arc::new(SubjectHttpProbeProvider::new(HttpProbeMethod::Get)),
        )?;
        let http_evidence = match self.payload_binding {
            Some(binding) => http_evidence.with_payload_binding(binding),
            None => http_evidence,
        };
        executors.register(Arc::new(http_evidence))?;

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
            requests,
            request_accounting,
            usage: RuntimeUsage::default(),
            cancellation: self.cancellation,
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
    requests: HttpRequestBroker,
    request_accounting: RequestAccountingBroker,
    usage: RuntimeUsage,
    cancellation: CancellationToken,
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

    /// Returns a clone of the host-owned cancellation token.
    ///
    /// Cancelling the returned token stops this single-use runtime at its next
    /// async or deterministic planning boundary.
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
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

        if self.cancellation.is_cancelled() {
            return Ok(self.cancellation_report(None, turns, None, started_at));
        }

        let bootstrap_case = match VerificationCase::new(
            BOOTSTRAP_CASE_ID,
            self.subject.clone(),
            BOOTSTRAP_ACTION_ID,
            BOOTSTRAP_HYPOTHESIS_ID,
        ) {
            Ok(case) => case,
            Err(source) => {
                return Err(self.run_failed(None, turns, source.into(), started_at));
            },
        };
        let bootstrap_command = DecisionLoopCommand::ExecuteAction {
            case: bootstrap_case,
            executor: Some(HTTP_EVIDENCE_EXECUTOR_ID.to_owned()),
            origin: DecisionActionOrigin::Bootstrap,
            delay_ms: None,
        };
        let (bootstrap_action_id, bootstrap_stage) = match execution_metadata(&bootstrap_command) {
            Ok(metadata) => metadata,
            Err(source) => {
                return Err(self.run_failed(None, turns, source, started_at));
            },
        };
        let bootstrap_limits =
            match self.reserve_execution(bootstrap_action_id, bootstrap_stage, started_at) {
                Ok(limits) => limits,
                Err(limit) => {
                    if self.cancellation.is_cancelled() {
                        return Ok(self.cancellation_report(None, turns, None, started_at));
                    }
                    return Ok(self.limit_report(None, turns, limit, started_at));
                },
            };
        if self.cancellation.is_cancelled() {
            return Ok(self.cancellation_report(None, turns, None, started_at));
        }
        let bootstrap_result = await_execution(
            &self.cancellation,
            deadline,
            self.runner.execute_command_with_limits(
                &bootstrap_command,
                &self.knowledge,
                bootstrap_limits,
            ),
        )
        .await;
        let bootstrap = match bootstrap_result {
            RuntimeExecution::Completed(Ok(receipt)) => {
                self.refresh_elapsed(started_at);
                receipt
            },
            RuntimeExecution::Completed(Err(error)) => {
                self.refresh_elapsed(started_at);
                if let Some(limit) = error.runtime_limit().cloned() {
                    let failure = error.into_execution_failure();
                    return Ok(
                        self.limit_report_with_failure(None, turns, limit, failure, started_at)
                    );
                }
                return Err(self.run_failed(None, turns, error.into(), started_at));
            },
            RuntimeExecution::Cancelled => {
                return Ok(self.cancellation_report(None, turns, None, started_at));
            },
            RuntimeExecution::WallTimeExceeded => {
                let limit = self.wall_limit(started_at);
                return Ok(self.limit_report(None, turns, limit, started_at));
            },
        };
        let bootstrap = match self.validate_response_usage_evidence(bootstrap) {
            Ok(receipt) => receipt,
            Err(source) => {
                let committed_bootstrap = source.committed_evidence().cloned();
                return Err(self.run_failed(committed_bootstrap, turns, source, started_at));
            },
        };
        if let Some(limit) = self.response_limit_if_exceeded(BOOTSTRAP_ACTION_ID) {
            return Ok(self.limit_report(Some(bootstrap), turns, limit, started_at));
        }
        let bootstrap = Some(bootstrap);

        if self.cancellation.is_cancelled() {
            return Ok(self.cancellation_report(bootstrap, turns, None, started_at));
        }

        let mut command = DecisionLoopCommand::Replan;
        let terminal = loop {
            match &command {
                DecisionLoopCommand::Replan => {
                    if self.cancellation.is_cancelled() {
                        return Ok(self.cancellation_report(bootstrap, turns, None, started_at));
                    }
                    if let Some(limit) = self.wall_limit_if_reached(started_at) {
                        return Ok(self.limit_report(bootstrap, turns, limit, started_at));
                    }
                    let planning = match self.decision_loop.plan_next_with_suppressed_actions(
                        &self.knowledge,
                        &self.experience,
                        &mut self.session,
                        &self.unsupported_actions,
                    ) {
                        Ok(planning) => planning,
                        Err(source) => {
                            return Err(self.run_failed(
                                bootstrap,
                                turns,
                                source.into(),
                                started_at,
                            ));
                        },
                    };
                    command = planning.command().clone();
                    turns.push(StandardWebDecisionRuntimeTurn::Planning(Box::new(planning)));
                    if self.cancellation.is_cancelled() {
                        return Ok(self.cancellation_report(bootstrap, turns, None, started_at));
                    }
                    if is_terminal(&command) {
                        break command.clone();
                    }
                    if let Some(limit) = self.wall_limit_if_reached(started_at) {
                        return Ok(self.limit_report(bootstrap, turns, limit, started_at));
                    }
                },
                DecisionLoopCommand::ExecuteAction { .. }
                | DecisionLoopCommand::CollectActiveEvidence { .. } => {
                    if self.cancellation.is_cancelled() {
                        return Ok(self.cancellation_report(bootstrap, turns, None, started_at));
                    }
                    let (action_id, previous_stage) = match execution_metadata(&command) {
                        Ok(metadata) => metadata,
                        Err(source) => {
                            return Err(self.run_failed(bootstrap, turns, source, started_at));
                        },
                    };
                    let completed_action_id = action_id.to_owned();
                    let limits =
                        match self.reserve_execution(action_id, previous_stage, started_at) {
                            Ok(limits) => limits,
                            Err(limit) => {
                                if self.cancellation.is_cancelled() {
                                    return Ok(self
                                        .cancellation_report(bootstrap, turns, None, started_at));
                                }
                                return Ok(self.limit_report(bootstrap, turns, limit, started_at));
                            },
                        };
                    if self.cancellation.is_cancelled() {
                        return Ok(self.cancellation_report(bootstrap, turns, None, started_at));
                    }
                    let evidence_result = await_execution(
                        &self.cancellation,
                        deadline,
                        self.runner.execute_session_command_with_limits(
                            &command,
                            &self.knowledge,
                            &self.session,
                            limits,
                        ),
                    )
                    .await;
                    let evidence = match evidence_result {
                        RuntimeExecution::Completed(Ok(receipt)) => {
                            self.refresh_elapsed(started_at);
                            receipt
                        },
                        RuntimeExecution::Completed(Err(error)) => {
                            self.refresh_elapsed(started_at);
                            if let Some(limit) = error.runtime_limit().cloned() {
                                let failure = error.into_execution_failure();
                                return Ok(self.limit_report_with_failure(
                                    bootstrap, turns, limit, failure, started_at,
                                ));
                            }
                            return Err(self.run_failed(
                                bootstrap,
                                turns,
                                error.into(),
                                started_at,
                            ));
                        },
                        RuntimeExecution::Cancelled => {
                            return Ok(self.cancellation_report(bootstrap, turns, None, started_at));
                        },
                        RuntimeExecution::WallTimeExceeded => {
                            let limit = self.wall_limit(started_at);
                            return Ok(self.limit_report(bootstrap, turns, limit, started_at));
                        },
                    };
                    let evidence = match self.validate_response_usage_evidence(evidence) {
                        Ok(receipt) => receipt,
                        Err(source) => {
                            return Err(self.run_failed(bootstrap, turns, source, started_at));
                        },
                    };
                    if let Some(limit) = self.response_limit_if_exceeded(&completed_action_id) {
                        return Ok(self.limit_report_with_unverified_evidence(
                            bootstrap, turns, evidence, limit, started_at,
                        ));
                    }
                    if self.cancellation.is_cancelled() {
                        return Ok(self.cancellation_report(
                            bootstrap,
                            turns,
                            Some(evidence),
                            started_at,
                        ));
                    }
                    let runner_turn = self.runner.resume_session_command(
                        &self.decision_loop,
                        &command,
                        &self.knowledge,
                        &mut self.experience,
                        &mut self.session,
                        evidence,
                    );
                    self.refresh_elapsed(started_at);
                    let runner_turn = match runner_turn {
                        Ok(turn) => turn,
                        Err(source) => {
                            return Err(self.run_failed(
                                bootstrap,
                                turns,
                                source.into(),
                                started_at,
                            ));
                        },
                    };
                    match runner_turn {
                        DecisionRunnerTurn::Planning(planning) => {
                            command = planning.command().clone();
                            turns.push(StandardWebDecisionRuntimeTurn::Planning(planning));
                            if is_terminal(&command) {
                                break command.clone();
                            }
                            if self.cancellation.is_cancelled() {
                                return Ok(
                                    self.cancellation_report(bootstrap, turns, None, started_at)
                                );
                            }
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
                            if self.cancellation.is_cancelled() {
                                return Ok(
                                    self.cancellation_report(bootstrap, turns, None, started_at)
                                );
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
            unverified_evidence: None,
            terminal,
            usage: self.usage.clone(),
            transport: self.request_accounting.dispatch_audit(),
            limit_exceeded: None,
            execution_failure: None,
        })
    }

    fn run_failed(
        &mut self,
        bootstrap: Option<DecisionEvidenceReceipt>,
        completed_turns: Vec<StandardWebDecisionRuntimeTurn>,
        source: StandardWebDecisionRuntimeError,
        started_at: tokio::time::Instant,
    ) -> StandardWebDecisionRuntimeError {
        self.refresh_elapsed(started_at);
        StandardWebDecisionRuntimeError::RunFailed {
            receipt: Box::new(StandardWebDecisionFailureReceipt {
                bootstrap,
                completed_turns,
                usage: self.usage.clone(),
                transport: self.request_accounting.dispatch_audit(),
            }),
            source: Box::new(source),
        }
    }

    fn reserve_execution(
        &mut self,
        action_id: &str,
        stage: DecisionExecutionStage,
        started_at: tokio::time::Instant,
    ) -> Result<DecisionExecutionLimits, RuntimeLimitExceeded> {
        if let Some(limit) = self.wall_limit_if_reached(started_at) {
            return Err(limit);
        }
        self.sync_request_accounting();
        let preflight = self.request_accounting.preflight(action_id, stage)?;
        let attempts = self.usage.same_action_attempts(action_id);
        if attempts >= self.budget.max_same_action_attempts() {
            return Err(RuntimeLimitExceeded::new(
                RuntimeBudgetDimension::SameActionAttempts,
                u64::from(self.budget.max_same_action_attempts()),
                u64::from(attempts).saturating_add(1),
                Some(action_id.to_owned()),
            ));
        }

        self.usage.reserve_action_attempt(action_id);
        Ok(DecisionExecutionLimits::new()
            .with_max_response_body_bytes(preflight.remaining_response_bytes()))
    }

    fn validate_response_usage_evidence(
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
        Ok(receipt)
    }

    fn response_limit_if_exceeded(&mut self, action_id: &str) -> Option<RuntimeLimitExceeded> {
        self.sync_request_accounting();
        let observed = self.usage.response_bytes();
        (observed > self.budget.max_response_bytes()).then(|| {
            RuntimeLimitExceeded::new(
                RuntimeBudgetDimension::ResponseBytes,
                self.budget.max_response_bytes(),
                observed,
                Some(action_id.to_owned()),
            )
        })
    }

    fn sync_request_accounting(&mut self) {
        self.usage
            .sync_request_accounting(self.request_accounting.snapshot());
    }

    fn refresh_elapsed(&mut self, started_at: tokio::time::Instant) {
        self.sync_request_accounting();
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
        self.limit_report_with_failure(bootstrap, turns, limit, None, started_at)
    }

    fn limit_report_with_failure(
        &mut self,
        bootstrap: Option<DecisionEvidenceReceipt>,
        turns: Vec<StandardWebDecisionRuntimeTurn>,
        limit: RuntimeLimitExceeded,
        execution_failure: Option<DecisionExecutionFailureReceipt>,
        started_at: tokio::time::Instant,
    ) -> StandardWebDecisionRunReport {
        self.refresh_elapsed(started_at);
        self.session.halt_for_runtime_budget();
        StandardWebDecisionRunReport {
            bootstrap,
            turns,
            unverified_evidence: None,
            terminal: DecisionLoopCommand::Halt {
                reason: crate::DecisionStopReason::RuntimeBudgetLimit,
            },
            usage: self.usage.clone(),
            transport: self.request_accounting.dispatch_audit(),
            limit_exceeded: Some(limit),
            execution_failure,
        }
    }

    fn limit_report_with_unverified_evidence(
        &mut self,
        bootstrap: Option<DecisionEvidenceReceipt>,
        turns: Vec<StandardWebDecisionRuntimeTurn>,
        evidence: DecisionEvidenceReceipt,
        limit: RuntimeLimitExceeded,
        started_at: tokio::time::Instant,
    ) -> StandardWebDecisionRunReport {
        self.refresh_elapsed(started_at);
        self.session.halt_for_runtime_budget();
        StandardWebDecisionRunReport {
            bootstrap,
            turns,
            unverified_evidence: Some(evidence),
            terminal: DecisionLoopCommand::Halt {
                reason: crate::DecisionStopReason::RuntimeBudgetLimit,
            },
            usage: self.usage.clone(),
            transport: self.request_accounting.dispatch_audit(),
            limit_exceeded: Some(limit),
            execution_failure: None,
        }
    }

    fn cancellation_report(
        &mut self,
        bootstrap: Option<DecisionEvidenceReceipt>,
        turns: Vec<StandardWebDecisionRuntimeTurn>,
        unverified_evidence: Option<DecisionEvidenceReceipt>,
        started_at: tokio::time::Instant,
    ) -> StandardWebDecisionRunReport {
        self.refresh_elapsed(started_at);
        self.session.halt_for_host_cancellation();
        StandardWebDecisionRunReport {
            bootstrap,
            turns,
            unverified_evidence,
            terminal: DecisionLoopCommand::Halt {
                reason: crate::DecisionStopReason::CancelledByHost,
            },
            usage: self.usage.clone(),
            transport: self.request_accounting.dispatch_audit(),
            limit_exceeded: None,
            execution_failure: None,
        }
    }
}

enum RuntimeExecution<T> {
    Completed(T),
    Cancelled,
    WallTimeExceeded,
}

async fn await_execution<F, T>(
    cancellation: &CancellationToken,
    deadline: Option<tokio::time::Instant>,
    execution: F,
) -> RuntimeExecution<T>
where
    F: Future<Output = T>,
{
    tokio::pin!(execution);
    match deadline {
        Some(deadline) => {
            tokio::select! {
                // A ready execution result wins so a receipt produced by an
                // already-completed evidence commit is never discarded. When
                // both stop signals are ready, explicit host cancellation is
                // more specific than the wall-time fallback.
                biased;
                result = &mut execution => RuntimeExecution::Completed(result),
                () = cancellation.cancelled() => RuntimeExecution::Cancelled,
                () = tokio::time::sleep_until(deadline) => RuntimeExecution::WallTimeExceeded,
            }
        },
        None => {
            tokio::select! {
                biased;
                result = &mut execution => RuntimeExecution::Completed(result),
                () = cancellation.cancelled() => RuntimeExecution::Cancelled,
            }
        },
    }
}

fn execution_metadata(
    command: &DecisionLoopCommand,
) -> Result<(&str, DecisionExecutionStage), StandardWebDecisionRuntimeError> {
    match command {
        DecisionLoopCommand::ExecuteAction { case, .. } => {
            Ok((case.action_id(), DecisionExecutionStage::Passive))
        },
        DecisionLoopCommand::CollectActiveEvidence { case } => {
            Ok((case.action_id(), DecisionExecutionStage::Active))
        },
        DecisionLoopCommand::Replan
        | DecisionLoopCommand::Complete { .. }
        | DecisionLoopCommand::AwaitHumanReview { .. }
        | DecisionLoopCommand::Halt { .. } => {
            Err(StandardWebDecisionRuntimeError::ExecutionMetadataUnavailable)
        },
    }
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
