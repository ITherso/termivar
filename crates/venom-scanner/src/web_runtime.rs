//! Host-facing runtime for the standard deterministic web decision stack.
//!
//! The runtime owns composition and bounded command driving. Domain layers
//! remain independently testable and the caller remains responsible for
//! target authorization and HTTP evidence policy.

use std::{collections::BTreeSet, sync::Arc};

use thiserror::Error;
use url::Url;
use venom_core::{EntityId, ReasoningModelError};

use crate::{
    AdaptationLimits, BenefitScore, DecisionActionOrigin, DecisionEvidenceReceipt,
    DecisionExecutorRegistry, DecisionLoop, DecisionLoopCommand, DecisionLoopConfig,
    DecisionLoopError, DecisionOutcomeReport, DecisionPlanningReport, DecisionRunnerAdapter,
    DecisionRunnerError, DecisionRunnerTurn, DecisionSession, ExperiencePolicy, ExperienceStore,
    ExperienceStoreError, HttpEvidenceError, HttpEvidenceExecutor, HttpEvidencePolicy, HttpProbe,
    HttpProbeMethod, KnowledgeBase, PlannerError, PlanningContext, RiskScore,
    StandardWebActionKind, StandardWebDecisionError, StandardWebDecisionInstallReport,
    StandardWebDecisionProfile, SubjectHttpProbeProvider, VerificationCase, VerificationError,
    HTTP_EVIDENCE_EXECUTOR_ID,
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

    /// An executor lookup, request, evidence commit, or runner transition failed.
    #[error(transparent)]
    Runner(#[from] DecisionRunnerError),
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
    bootstrap: DecisionEvidenceReceipt,
    turns: Vec<StandardWebDecisionRuntimeTurn>,
    terminal: DecisionLoopCommand,
}

impl StandardWebDecisionRunReport {
    /// Returns the initial GET evidence committed before reasoning starts.
    pub fn bootstrap(&self) -> &DecisionEvidenceReceipt {
        &self.bootstrap
    }

    /// Returns non-terminal planning and outcome turns in execution order.
    pub fn turns(&self) -> &[StandardWebDecisionRuntimeTurn] {
        &self.turns
    }

    /// Returns the command that ended the session.
    pub fn terminal(&self) -> &DecisionLoopCommand {
        &self.terminal
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
        }
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
            unsupported_actions,
            knowledge,
            decision_loop,
            runner: DecisionRunnerAdapter::new(executors),
            experience: self.experience,
            session: DecisionSession::new(subject),
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
    unsupported_actions: BTreeSet<String>,
    knowledge: KnowledgeBase,
    decision_loop: DecisionLoop,
    runner: DecisionRunnerAdapter,
    experience: ExperienceStore,
    session: DecisionSession,
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
        let bootstrap = self
            .runner
            .execute_command(&bootstrap_command, &self.knowledge)
            .await?;

        let mut turns = Vec::new();
        let mut command = DecisionLoopCommand::Replan;
        let terminal = loop {
            match &command {
                DecisionLoopCommand::Replan => {
                    let planning = self.decision_loop.plan_next_with_suppressed_actions(
                        &self.knowledge,
                        &self.experience,
                        &mut self.session,
                        &self.unsupported_actions,
                    )?;
                    command = planning.command().clone();
                    turns.push(StandardWebDecisionRuntimeTurn::Planning(Box::new(planning)));
                },
                DecisionLoopCommand::ExecuteAction { .. }
                | DecisionLoopCommand::CollectActiveEvidence { .. } => {
                    match self
                        .runner
                        .drive_command(
                            &self.decision_loop,
                            &command,
                            &self.knowledge,
                            &mut self.experience,
                            &mut self.session,
                        )
                        .await?
                    {
                        DecisionRunnerTurn::Planning(planning) => {
                            command = planning.command().clone();
                            turns.push(StandardWebDecisionRuntimeTurn::Planning(planning));
                        },
                        DecisionRunnerTurn::Outcome { evidence, decision } => {
                            command = decision.command().clone();
                            turns.push(StandardWebDecisionRuntimeTurn::Outcome {
                                evidence,
                                decision,
                            });
                        },
                        DecisionRunnerTurn::Terminal(terminal) => break terminal,
                    }
                },
                DecisionLoopCommand::Complete { .. }
                | DecisionLoopCommand::AwaitHumanReview { .. }
                | DecisionLoopCommand::Halt { .. } => break command.clone(),
            }
        };

        Ok(StandardWebDecisionRunReport {
            bootstrap,
            turns,
            terminal,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::Mutex,
    };
    use venom_core::{HypothesisState, OutcomeStatus};

    use super::*;
    use crate::{ExclusionReason, StandardWebActionKind};

    async fn serve(
        response: &'static [u8],
        request_count: usize,
    ) -> (Url, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let methods = Arc::new(Mutex::new(Vec::new()));
        let recorded = methods.clone();
        tokio::spawn(async move {
            for _ in 0..request_count {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0_u8; 2048];
                let bytes = stream.read(&mut request).await.unwrap();
                let method = String::from_utf8_lossy(&request[..bytes])
                    .split_whitespace()
                    .next()
                    .unwrap()
                    .to_owned();
                recorded.lock().await.push(method);
                stream.write_all(response).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        (
            Url::parse(&format!("http://{address}/admin")).unwrap(),
            methods,
        )
    }

    #[test]
    fn builder_validates_limits_and_exposes_executor_gaps() {
        let target = Url::parse("https://example.test/app").unwrap();
        assert!(matches!(
            StandardWebDecisionRuntime::builder(target.clone())
                .risk_limit(0)
                .build(),
            Err(StandardWebDecisionRuntimeError::Planner(_))
        ));
        assert!(matches!(
            StandardWebDecisionRuntime::builder(target.clone())
                .max_action_cycles(0)
                .build(),
            Err(StandardWebDecisionRuntimeError::Decision(_))
        ));

        let runtime = StandardWebDecisionRuntime::builder(target).build().unwrap();
        assert_eq!(runtime.decision_loop.planner().len(), 9);
        assert_eq!(runtime.runner.executors().len(), 6);
        assert_eq!(runtime.unsupported_actions().len(), 4);
        assert!(runtime
            .unsupported_actions()
            .contains(StandardWebActionKind::NginxConfiguration.action_id()));
        assert!(!runtime
            .unsupported_actions()
            .contains(StandardWebActionKind::HttpBasicAuthBoundary.action_id()));
    }

    #[test]
    fn builder_rejects_a_target_outside_custom_policy() {
        let target = Url::parse("https://example.test/app").unwrap();
        let policy =
            HttpEvidencePolicy::for_origin(Url::parse("https://different.test/").unwrap()).unwrap();

        assert!(matches!(
            StandardWebDecisionRuntime::builder(target)
                .http_policy(policy)
                .build(),
            Err(StandardWebDecisionRuntimeError::Http(
                HttpEvidenceError::TargetOutsidePolicy { .. }
            ))
        ));
    }

    #[tokio::test]
    async fn runtime_drives_basic_evidence_to_a_confirmed_outcome_once() {
        let response = b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"admin\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let (target, methods) = serve(response, 2).await;
        let mut runtime = StandardWebDecisionRuntime::builder(target).build().unwrap();

        let report = runtime.analyze().await.unwrap();

        assert!(matches!(
            report.terminal(),
            DecisionLoopCommand::Complete { .. }
        ));
        let outcomes: Vec<_> = report.outcome_reports().collect();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(
            outcomes[0].verification().outcome().status(),
            OutcomeStatus::Success
        );
        let hypothesis_id = outcomes[0].verification().case().hypothesis_id();
        assert_eq!(
            runtime
                .knowledge()
                .hypothesis(hypothesis_id)
                .unwrap()
                .state(),
            HypothesisState::Confirmed
        );
        assert_eq!(&*methods.lock().await, &["GET", "HEAD"]);
        assert!(matches!(
            runtime.analyze().await,
            Err(StandardWebDecisionRuntimeError::AlreadyStarted)
        ));
    }

    #[tokio::test]
    async fn unavailable_executor_is_reported_as_a_policy_suppression() {
        let response =
            b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let (target, methods) = serve(response, 1).await;
        let mut runtime = StandardWebDecisionRuntime::builder(target).build().unwrap();

        let report = runtime.analyze().await.unwrap();

        assert!(matches!(
            report.terminal(),
            DecisionLoopCommand::Halt {
                reason: crate::DecisionStopReason::NoEligibleAction
            }
        ));
        let planning = report.planning_reports().next().unwrap();
        let nginx = planning
            .plan()
            .excluded()
            .iter()
            .find(|excluded| {
                excluded.action_id() == StandardWebActionKind::NginxConfiguration.action_id()
            })
            .unwrap();
        assert!(matches!(nginx.reason(), ExclusionReason::PolicySuppressed));
        assert_eq!(&*methods.lock().await, &["GET"]);
    }
}
