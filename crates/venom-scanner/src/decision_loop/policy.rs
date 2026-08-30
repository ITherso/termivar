//! Deterministic reasoning, planning, verification, and adaptation policy.

use super::*;

/// Deterministic coordinator for one evidence-to-command cycle.
///
/// # Example
///
/// ```rust
/// use venom_scanner::{
///     AdaptationLimits, BenefitScore, DecisionLoop, DecisionLoopConfig, ExperiencePolicy,
///     PlanningContext, RiskScore,
/// };
///
/// let planning = PlanningContext::new(
///     BenefitScore::from_percent(80)?,
///     100,
///     RiskScore::from_percent(40)?,
/// );
/// let config = DecisionLoopConfig::new(
///     planning,
///     AdaptationLimits::default(),
///     ExperiencePolicy::default(),
///     32,
/// )?;
/// let decision_loop = DecisionLoop::new(config);
/// assert!(decision_loop.planner().is_empty());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct DecisionLoop {
    config: DecisionLoopConfig,
    rules: RuleEngine,
    planner: AttackPlanner,
    verification: VerificationPipeline,
    adaptive: AdaptivePipeline,
}

impl DecisionLoop {
    /// Creates an empty coordinator with explicit limits.
    pub fn new(config: DecisionLoopConfig) -> Self {
        Self {
            config,
            rules: RuleEngine::new(),
            planner: AttackPlanner::new(),
            verification: VerificationPipeline::default(),
            adaptive: AdaptivePipeline::new(),
        }
    }

    /// Creates a coordinator from independently configured subsystems.
    pub fn with_components(
        config: DecisionLoopConfig,
        rules: RuleEngine,
        planner: AttackPlanner,
        verification: VerificationPipeline,
        adaptive: AdaptivePipeline,
    ) -> Self {
        Self {
            config,
            rules,
            planner,
            verification,
            adaptive,
        }
    }

    /// Returns the immutable configuration.
    pub fn config(&self) -> DecisionLoopConfig {
        self.config
    }

    /// Returns the reasoning registry.
    pub fn rules(&self) -> &RuleEngine {
        &self.rules
    }

    /// Returns the mutable reasoning registry.
    pub fn rules_mut(&mut self) -> &mut RuleEngine {
        &mut self.rules
    }

    /// Returns the attack planner.
    pub fn planner(&self) -> &AttackPlanner {
        &self.planner
    }

    /// Returns the mutable attack planner.
    pub fn planner_mut(&mut self) -> &mut AttackPlanner {
        &mut self.planner
    }

    /// Returns the verification pipeline.
    pub fn verification(&self) -> &VerificationPipeline {
        &self.verification
    }

    /// Returns the mutable verification pipeline.
    pub fn verification_mut(&mut self) -> &mut VerificationPipeline {
        &mut self.verification
    }

    /// Returns adaptive policy.
    pub fn adaptive(&self) -> &AdaptivePipeline {
        &self.adaptive
    }

    /// Returns mutable adaptive policy.
    pub fn adaptive_mut(&mut self) -> &mut AdaptivePipeline {
        &mut self.adaptive
    }

    /// Applies reasoning, utility planning, and target-scoped suppressions.
    pub fn plan_next(
        &self,
        knowledge: &KnowledgeBase,
        experience: &ExperienceStore,
        session: &mut DecisionSession,
    ) -> Result<DecisionPlanningReport, DecisionLoopError> {
        self.plan_next_with_suppressed_actions(knowledge, experience, session, &BTreeSet::new())
    }

    /// Applies reasoning and planning while honoring host policy suppressions.
    ///
    /// Explicit suppressions are combined with experience and adaptive-session
    /// suppressions. They remain visible as policy exclusions in the returned
    /// planner audit record. A host that later submits passive or active
    /// evidence must use the matching suppression-aware submission method so
    /// adaptive execution is reauthorized against current policy.
    pub fn plan_next_with_suppressed_actions(
        &self,
        knowledge: &KnowledgeBase,
        experience: &ExperienceStore,
        session: &mut DecisionSession,
        host_suppressed_actions: &BTreeSet<String>,
    ) -> Result<DecisionPlanningReport, DecisionLoopError> {
        self.plan_next_with_suppressed_actions_before_commit(
            knowledge,
            experience,
            session,
            host_suppressed_actions,
            |_| {},
        )
    }

    pub(crate) fn plan_next_with_action_suppressions(
        &self,
        knowledge: &KnowledgeBase,
        experience: &ExperienceStore,
        session: &mut DecisionSession,
        host_suppressions: &ActionSuppressionContext,
    ) -> Result<DecisionPlanningReport, DecisionLoopError> {
        self.plan_next_with_action_suppressions_before_commit(
            knowledge,
            experience,
            session,
            host_suppressions,
            |_| {},
        )
    }

    fn plan_next_with_suppressed_actions_before_commit<F>(
        &self,
        knowledge: &KnowledgeBase,
        experience: &ExperienceStore,
        session: &mut DecisionSession,
        host_suppressed_actions: &BTreeSet<String>,
        before_session_commit: F,
    ) -> Result<DecisionPlanningReport, DecisionLoopError>
    where
        F: FnMut(&KnowledgeSnapshot),
    {
        self.plan_next_with_action_suppressions_before_commit(
            knowledge,
            experience,
            session,
            &ActionSuppressionContext::policy_only(host_suppressed_actions),
            before_session_commit,
        )
    }

    fn plan_next_with_action_suppressions_before_commit<F>(
        &self,
        knowledge: &KnowledgeBase,
        experience: &ExperienceStore,
        session: &mut DecisionSession,
        host_suppressions: &ActionSuppressionContext,
        mut before_session_commit: F,
    ) -> Result<DecisionPlanningReport, DecisionLoopError>
    where
        F: FnMut(&KnowledgeSnapshot),
    {
        require_state(session, "plan", |state| {
            matches!(state, DecisionLoopState::Ready)
        })?;
        if session.action_cycles >= self.config.max_action_cycles {
            let mut candidate_session = session.clone();
            let reason = DecisionStopReason::ActionCycleLimit;
            candidate_session.state = DecisionLoopState::Halted { reason };
            let snapshot = knowledge.snapshot_for_subject(candidate_session.subject());
            let suppressions = combined_suppressions(
                experience,
                &candidate_session,
                self.config.experience,
                host_suppressions,
            );
            let (policy_authorized_plan, plan) = self
                .planner
                .plan_snapshot_with_action_suppressions_and_baseline(
                    &snapshot,
                    self.config.planning,
                    &suppressions,
                )?;
            let report = DecisionPlanningReport {
                rule_applications: Vec::new(),
                plan,
                policy_authorized_plan,
                suppressed_actions: suppressions.policy_suppressed_actions().clone(),
                session_transition: DecisionSessionTransition::new(
                    session.transition_summary(),
                    candidate_session.transition_summary(),
                ),
                command: DecisionLoopCommand::Halt { reason },
            };
            before_session_commit(&snapshot);
            knowledge
                .commit_if_snapshot_current(&snapshot, || *session = candidate_session)
                .map_err(|source| DecisionLoopError::StalePlanningSnapshot { source })?;
            return Ok(report);
        }

        let applications = self.rules.apply(knowledge, session.subject())?;
        let snapshot = knowledge.snapshot_for_subject(session.subject());
        let reasoning_changed = applications.iter().any(|application| {
            application
                .write()
                .is_some_and(|write| write != KnowledgeWrite::Unchanged)
        });
        let mut candidate_session = session.clone();
        let planning = (|| -> Result<
            (
                AttackPlan,
                AttackPlan,
                BTreeSet<String>,
                DecisionSessionTransition,
                DecisionLoopCommand,
            ),
            DecisionLoopError,
        > {
            let suppressions = combined_suppressions(
                experience,
                &candidate_session,
                self.config.experience,
                host_suppressions,
            );
            let (policy_authorized_plan, plan) = self
                .planner
                .plan_snapshot_with_action_suppressions_and_baseline(
                    &snapshot,
                    self.config.planning,
                    &suppressions,
                )?;
            let command = if let Some(step) = plan.steps().first() {
                let case = next_case(
                    &candidate_session,
                    step.action_id(),
                    step.confidence_hypothesis_id(),
                    step.verification_target(),
                    step.payload_strategy().cloned(),
                    "planned",
                )?;
                issue_action(
                    &mut candidate_session,
                    self.config.max_action_cycles,
                    case,
                    Some(step.executor().to_owned()),
                    DecisionActionOrigin::Planned,
                    None,
                )
            } else {
                let reason = DecisionStopReason::NoEligibleAction;
                candidate_session.state = DecisionLoopState::Halted { reason };
                DecisionLoopCommand::Halt { reason }
            };
            let session_transition = DecisionSessionTransition::new(
                session.transition_summary(),
                candidate_session.transition_summary(),
            );
            Ok((
                policy_authorized_plan,
                plan,
                suppressions.policy_suppressed_actions().clone(),
                session_transition,
                command,
            ))
        })();

        match planning {
            Ok((policy_authorized_plan, plan, suppressed_actions, session_transition, command)) => {
                before_session_commit(&snapshot);
                let commit = knowledge.commit_if_snapshot_current(&snapshot, || {
                    *session = candidate_session;
                });
                match commit {
                    Ok(()) => Ok(DecisionPlanningReport {
                        rule_applications: applications,
                        plan,
                        policy_authorized_plan,
                        suppressed_actions,
                        session_transition,
                        command,
                    }),
                    Err(source) if reasoning_changed => {
                        Err(DecisionLoopError::PlanningAfterReasoningCommit {
                            receipt: Box::new(DecisionReasoningCommitReceipt {
                                subject: session.subject().clone(),
                                planner_subject_revision: snapshot.subject_revision(),
                                planner_ontology_revision: snapshot.ontology_revision(),
                                rule_applications: applications,
                            }),
                            source: Box::new(DecisionLoopError::StalePlanningSnapshot { source }),
                        })
                    },
                    Err(source) => Err(DecisionLoopError::StalePlanningSnapshot { source }),
                }
            },
            Err(source) if reasoning_changed => {
                Err(DecisionLoopError::PlanningAfterReasoningCommit {
                    receipt: Box::new(DecisionReasoningCommitReceipt {
                        subject: session.subject().clone(),
                        planner_subject_revision: snapshot.subject_revision(),
                        planner_ontology_revision: snapshot.ontology_revision(),
                        rule_applications: applications,
                    }),
                    source: Box::new(source),
                })
            },
            Err(source) => Err(source),
        }
    }

    /// Evaluates evidence produced by the outstanding action.
    pub fn submit_passive(
        &self,
        knowledge: &KnowledgeBase,
        experience: &mut ExperienceStore,
        session: &mut DecisionSession,
    ) -> Result<DecisionOutcomeReport, DecisionLoopError> {
        self.submit_passive_with_optional_suppressions(knowledge, experience, session, None)
    }

    /// Evaluates passive evidence under an explicit current host policy.
    ///
    /// Adaptive directives that continue automated work require this explicit
    /// context, even when the set is empty. This prevents replay or a mixed
    /// planning/submission API from silently forgetting host authority.
    pub fn submit_passive_with_suppressed_actions(
        &self,
        knowledge: &KnowledgeBase,
        experience: &mut ExperienceStore,
        session: &mut DecisionSession,
        host_suppressed_actions: &BTreeSet<String>,
    ) -> Result<DecisionOutcomeReport, DecisionLoopError> {
        let suppressions = ActionSuppressionContext::policy_only(host_suppressed_actions);
        self.submit_passive_with_action_suppressions(knowledge, experience, session, &suppressions)
    }

    pub(crate) fn submit_passive_with_action_suppressions(
        &self,
        knowledge: &KnowledgeBase,
        experience: &mut ExperienceStore,
        session: &mut DecisionSession,
        host_suppressions: &ActionSuppressionContext,
    ) -> Result<DecisionOutcomeReport, DecisionLoopError> {
        self.submit_passive_with_optional_suppressions(
            knowledge,
            experience,
            session,
            Some(host_suppressions),
        )
    }

    fn submit_passive_with_optional_suppressions(
        &self,
        knowledge: &KnowledgeBase,
        experience: &mut ExperienceStore,
        session: &mut DecisionSession,
        host_suppressions: Option<&ActionSuppressionContext>,
    ) -> Result<DecisionOutcomeReport, DecisionLoopError> {
        let case = match session.state() {
            DecisionLoopState::AwaitingPassive { case } => case.clone(),
            state => {
                return Err(DecisionLoopError::InvalidTransition {
                    operation: "submit passive evidence",
                    state: state.name(),
                })
            },
        };
        let snapshot = knowledge.snapshot_for_subject(session.subject());
        self.validate_outstanding_case_authority(&snapshot, &case)?;
        let verification = self
            .verification
            .passive()
            .verify_snapshot(&case, &snapshot)?;
        self.finalize_outcome(
            knowledge,
            experience,
            session,
            verification,
            &snapshot,
            host_suppressions,
        )
    }

    /// Evaluates evidence produced by an explicit active verification probe.
    pub fn submit_active(
        &self,
        knowledge: &KnowledgeBase,
        experience: &mut ExperienceStore,
        session: &mut DecisionSession,
        baseline: &KnowledgeSnapshot,
        after_probe: &KnowledgeSnapshot,
    ) -> Result<DecisionOutcomeReport, DecisionLoopError> {
        self.submit_active_with_optional_suppressions(
            knowledge,
            experience,
            session,
            baseline,
            after_probe,
            None,
        )
    }

    /// Evaluates active evidence under an explicit current host policy.
    ///
    /// See [`Self::submit_passive_with_suppressed_actions`] for why adaptive
    /// execution requires an explicit, replay-time host authority context.
    pub fn submit_active_with_suppressed_actions(
        &self,
        knowledge: &KnowledgeBase,
        experience: &mut ExperienceStore,
        session: &mut DecisionSession,
        baseline: &KnowledgeSnapshot,
        after_probe: &KnowledgeSnapshot,
        host_suppressed_actions: &BTreeSet<String>,
    ) -> Result<DecisionOutcomeReport, DecisionLoopError> {
        let suppressions = ActionSuppressionContext::policy_only(host_suppressed_actions);
        self.submit_active_with_action_suppressions(
            knowledge,
            experience,
            session,
            ActiveEvidenceSnapshots::new(baseline, after_probe),
            &suppressions,
        )
    }

    pub(crate) fn submit_active_with_action_suppressions(
        &self,
        knowledge: &KnowledgeBase,
        experience: &mut ExperienceStore,
        session: &mut DecisionSession,
        snapshots: ActiveEvidenceSnapshots<'_>,
        host_suppressions: &ActionSuppressionContext,
    ) -> Result<DecisionOutcomeReport, DecisionLoopError> {
        self.submit_active_with_optional_suppressions(
            knowledge,
            experience,
            session,
            snapshots.baseline,
            snapshots.after_probe,
            Some(host_suppressions),
        )
    }

    fn submit_active_with_optional_suppressions(
        &self,
        knowledge: &KnowledgeBase,
        experience: &mut ExperienceStore,
        session: &mut DecisionSession,
        baseline: &KnowledgeSnapshot,
        after_probe: &KnowledgeSnapshot,
        host_suppressions: Option<&ActionSuppressionContext>,
    ) -> Result<DecisionOutcomeReport, DecisionLoopError> {
        let case = match session.state() {
            DecisionLoopState::AwaitingActive { case } => case.clone(),
            state => {
                return Err(DecisionLoopError::InvalidTransition {
                    operation: "submit active evidence",
                    state: state.name(),
                })
            },
        };
        self.validate_outstanding_case_authority(after_probe, &case)?;
        let verification =
            self.verification
                .active()
                .verify_snapshots(&case, baseline, after_probe)?;
        self.finalize_outcome(
            knowledge,
            experience,
            session,
            verification,
            after_probe,
            host_suppressions,
        )
    }

    fn finalize_outcome(
        &self,
        knowledge: &KnowledgeBase,
        experience: &mut ExperienceStore,
        session: &mut DecisionSession,
        verification: VerificationReport,
        snapshot: &KnowledgeSnapshot,
        host_suppressions: Option<&ActionSuppressionContext>,
    ) -> Result<DecisionOutcomeReport, DecisionLoopError> {
        let before = session.transition_summary();
        let outcome = verification.outcome();
        let mut candidate_experience = experience.clone();
        let experience_write = candidate_experience.observe(outcome.clone())?;
        let empty_host_suppressions = ActionSuppressionContext::default();
        let suppressions = combined_suppressions(
            &candidate_experience,
            session,
            self.config.experience,
            host_suppressions.unwrap_or(&empty_host_suppressions),
        );
        let mut candidate_session = session.clone();
        // Defense must not participate in adaptive winner selection: removing
        // a higher-priority rule there could promote a lower-priority action
        // that the no-defense baseline never selected. The typed defense set
        // stays alongside this baseline decision and the transition below can
        // only suppress its selected schedule/retry/active continuation.
        let adaptive = self.adaptive.decide_and_record_with_suppressed_actions(
            outcome,
            snapshot,
            &mut candidate_session.adaptation,
            self.config.adaptation,
            suppressions.policy_suppressed_actions(),
        )?;
        if host_suppressions.is_none()
            && !matches!(
                adaptive.directive(),
                PipelineDirective::Complete
                    | PipelineDirective::AwaitHumanReview
                    | PipelineDirective::Halt
            )
        {
            let action_id = match adaptive.directive() {
                PipelineDirective::ScheduleAction { action_id } => action_id.as_str(),
                _ => outcome.action_id(),
            };
            return Err(
                DecisionLoopError::AdaptiveExecutionRequiresHostPolicyContext {
                    action_id: action_id.to_owned(),
                },
            );
        }
        let authorization_snapshot = verification.prospective_snapshot(snapshot)?;
        let command = transition_from_adaptive(
            &mut candidate_session,
            self.config.max_action_cycles,
            &self.planner,
            self.config.planning,
            &authorization_snapshot,
            verification.case(),
            outcome,
            adaptive.directive(),
            &suppressions,
        )?;
        let hypothesis_write = verification.apply(knowledge)?;
        let session_transition =
            DecisionSessionTransition::new(before, candidate_session.transition_summary());

        *experience = candidate_experience;
        *session = candidate_session;
        Ok(DecisionOutcomeReport {
            verification,
            adaptive,
            experience_write,
            hypothesis_write,
            session_transition,
            command,
        })
    }

    fn validate_outstanding_case_authority(
        &self,
        snapshot: &KnowledgeSnapshot,
        case: &VerificationCase,
    ) -> Result<(), DecisionLoopError> {
        let action = self.planner.action(case.action_id()).ok_or_else(|| {
            DecisionLoopError::UnregisteredDecisionAction {
                action_id: case.action_id().to_owned(),
            }
        })?;
        if !case.applies_hypothesis_transition() {
            return Ok(());
        }
        let authorized_target = action
            .confidence_source()
            .select(snapshot.hypotheses())
            .and_then(|motivation| {
                action
                    .verification_target()
                    .resolve(snapshot.hypotheses(), motivation.id())
            })
            .and_then(|target| target.hypothesis_id().map(str::to_owned));
        if authorized_target.as_deref() != Some(case.hypothesis_id()) {
            return Err(DecisionLoopError::DecisionCaseAuthorityExceeded {
                action_id: case.action_id().to_owned(),
            });
        }
        Ok(())
    }

    pub(crate) fn validate_execution_command_authority(
        &self,
        knowledge: &KnowledgeBase,
        command: &DecisionLoopCommand,
    ) -> Result<(), DecisionLoopError> {
        match command {
            DecisionLoopCommand::ExecuteAction { case, origin, .. }
                if !matches!(origin, DecisionActionOrigin::Bootstrap) =>
            {
                let snapshot = knowledge.snapshot_for_subject(case.subject());
                self.validate_outstanding_case_authority(&snapshot, case)
            },
            DecisionLoopCommand::CollectActiveEvidence { case } => {
                let snapshot = knowledge.snapshot_for_subject(case.subject());
                self.validate_outstanding_case_authority(&snapshot, case)
            },
            DecisionLoopCommand::ExecuteAction { .. }
            | DecisionLoopCommand::Replan
            | DecisionLoopCommand::Complete { .. }
            | DecisionLoopCommand::AwaitHumanReview { .. }
            | DecisionLoopCommand::Halt { .. } => Ok(()),
        }
    }
}

fn require_state(
    session: &DecisionSession,
    operation: &'static str,
    predicate: impl FnOnce(&DecisionLoopState) -> bool,
) -> Result<(), DecisionLoopError> {
    if predicate(session.state()) {
        Ok(())
    } else {
        Err(DecisionLoopError::InvalidTransition {
            operation,
            state: session.state.name(),
        })
    }
}

fn combined_suppressions(
    experience: &ExperienceStore,
    session: &DecisionSession,
    policy: ExperiencePolicy,
    host_suppressions: &ActionSuppressionContext,
) -> ActionSuppressionContext {
    let mut suppressions = experience.suppressed_actions(session.subject(), policy);
    suppressions.extend(session.adaptation.suppressed_actions().iter().cloned());
    suppressions.extend(
        host_suppressions
            .policy_suppressed_actions()
            .iter()
            .cloned(),
    );
    ActionSuppressionContext::new(
        suppressions,
        host_suppressions.defense_suppressed_actions().clone(),
    )
}

fn next_case(
    session: &DecisionSession,
    action_id: &str,
    motivation_hypothesis_id: &str,
    verification_target: &ResolvedVerificationTarget,
    payload_strategy: Option<PayloadStrategyRef>,
    origin: &str,
) -> Result<VerificationCase, DecisionLoopError> {
    let (hypothesis_id, applies_hypothesis_transition) = match verification_target {
        ResolvedVerificationTarget::Hypothesis(hypothesis_id) => (hypothesis_id.as_str(), true),
        ResolvedVerificationTarget::KnowledgeOnly => (motivation_hypothesis_id, false),
    };
    next_case_with_policy(
        session,
        action_id,
        hypothesis_id,
        applies_hypothesis_transition,
        payload_strategy,
        origin,
    )
}

fn next_case_with_policy(
    session: &DecisionSession,
    action_id: &str,
    hypothesis_id: &str,
    applies_hypothesis_transition: bool,
    payload_strategy: Option<PayloadStrategyRef>,
    origin: &str,
) -> Result<VerificationCase, DecisionLoopError> {
    let next_cycle = session
        .action_cycles
        .checked_add(1)
        .ok_or(DecisionLoopError::ActionCycleOverflow)?;
    let case = VerificationCase::new(
        format!("case:decision:{next_cycle}:{origin}:{action_id}"),
        session.subject.clone(),
        action_id,
        hypothesis_id,
    )?
    .with_payload_strategy(payload_strategy);
    Ok(if applies_hypothesis_transition {
        case
    } else {
        case.without_hypothesis_transition()
    })
}

fn issue_action(
    session: &mut DecisionSession,
    max_action_cycles: u32,
    case: VerificationCase,
    executor: Option<String>,
    origin: DecisionActionOrigin,
    delay_ms: Option<u64>,
) -> DecisionLoopCommand {
    if session.action_cycles >= max_action_cycles {
        let reason = DecisionStopReason::ActionCycleLimit;
        session.state = DecisionLoopState::Halted { reason };
        return DecisionLoopCommand::Halt { reason };
    }
    session.action_cycles += 1;
    session.state = DecisionLoopState::AwaitingPassive { case: case.clone() };
    DecisionLoopCommand::ExecuteAction {
        case,
        executor,
        origin,
        delay_ms,
    }
}

#[allow(clippy::too_many_arguments)]
fn transition_from_adaptive(
    session: &mut DecisionSession,
    max_action_cycles: u32,
    planner: &AttackPlanner,
    planning_context: PlanningContext,
    snapshot: &KnowledgeSnapshot,
    current_case: &VerificationCase,
    outcome: &Outcome,
    directive: &PipelineDirective,
    suppressions: &ActionSuppressionContext,
) -> Result<DecisionLoopCommand, DecisionLoopError> {
    match directive {
        PipelineDirective::Complete => {
            session.state = DecisionLoopState::Completed;
            Ok(DecisionLoopCommand::Complete {
                case: current_case.clone(),
            })
        },
        PipelineDirective::ScheduleAction { action_id } => {
            if session.action_cycles >= max_action_cycles {
                let reason = DecisionStopReason::ActionCycleLimit;
                session.state = DecisionLoopState::Halted { reason };
                return Ok(DecisionLoopCommand::Halt { reason });
            }
            if suppressions
                .defense_suppressed_actions()
                .contains(action_id)
            {
                session.state = DecisionLoopState::Ready;
                return Ok(DecisionLoopCommand::Replan);
            }
            let step = authorize_adaptive_action(
                planner,
                snapshot,
                planning_context,
                suppressions,
                action_id,
                true,
            )?;
            let case = next_case(
                session,
                step.action_id(),
                step.confidence_hypothesis_id(),
                step.verification_target(),
                step.payload_strategy().cloned(),
                "adaptive",
            )?;
            Ok(issue_action(
                session,
                max_action_cycles,
                case,
                Some(step.executor().to_owned()),
                DecisionActionOrigin::Adaptive,
                None,
            ))
        },
        PipelineDirective::Replan { .. } => {
            session.state = DecisionLoopState::Ready;
            Ok(DecisionLoopCommand::Replan)
        },
        PipelineDirective::Throttle {
            delay_ms,
            retry_current_action: true,
        } => {
            if session.action_cycles >= max_action_cycles {
                let reason = DecisionStopReason::ActionCycleLimit;
                session.state = DecisionLoopState::Halted { reason };
                return Ok(DecisionLoopCommand::Halt { reason });
            }
            if suppressions
                .defense_suppressed_actions()
                .contains(outcome.action_id())
            {
                session.state = DecisionLoopState::Ready;
                return Ok(DecisionLoopCommand::Replan);
            }
            let step = authorize_adaptive_action(
                planner,
                snapshot,
                planning_context,
                suppressions,
                outcome.action_id(),
                false,
            )?;
            let case = next_case_with_policy(
                session,
                outcome.action_id(),
                current_case.hypothesis_id(),
                current_case.applies_hypothesis_transition(),
                current_case.payload_strategy().cloned(),
                "retry",
            )?;
            Ok(issue_action(
                session,
                max_action_cycles,
                case,
                Some(step.executor().to_owned()),
                DecisionActionOrigin::Retry,
                Some(*delay_ms),
            ))
        },
        PipelineDirective::Throttle {
            retry_current_action: false,
            ..
        } => {
            session.state = DecisionLoopState::Ready;
            Ok(DecisionLoopCommand::Replan)
        },
        PipelineDirective::AwaitActiveVerification => {
            if suppressions
                .defense_suppressed_actions()
                .contains(current_case.action_id())
            {
                session.state = DecisionLoopState::Ready;
                return Ok(DecisionLoopCommand::Replan);
            }
            authorize_adaptive_action(
                planner,
                snapshot,
                planning_context,
                suppressions,
                current_case.action_id(),
                false,
            )?;
            let case = current_case.clone();
            session.state = DecisionLoopState::AwaitingActive { case: case.clone() };
            Ok(DecisionLoopCommand::CollectActiveEvidence { case })
        },
        PipelineDirective::AwaitHumanReview => {
            let case = current_case.clone();
            let reason = DecisionStopReason::HumanReview;
            session.state = DecisionLoopState::Halted { reason };
            Ok(DecisionLoopCommand::AwaitHumanReview { case })
        },
        PipelineDirective::Halt => {
            let reason = DecisionStopReason::AdaptationLimit;
            session.state = DecisionLoopState::Halted { reason };
            Ok(DecisionLoopCommand::Halt { reason })
        },
    }
}

fn authorize_adaptive_action(
    planner: &AttackPlanner,
    snapshot: &KnowledgeSnapshot,
    planning_context: PlanningContext,
    suppressions: &ActionSuppressionContext,
    action_id: &str,
    preserve_scheduled_target_errors: bool,
) -> Result<crate::PlanStep, DecisionLoopError> {
    planner
        .authorize_scheduled_action_with_context(
            snapshot,
            planning_context,
            suppressions,
            action_id,
        )
        .map_err(|error| match error {
            ScheduledActionAuthorizationError::Planner(source) => {
                DecisionLoopError::Planner(source)
            },
            ScheduledActionAuthorizationError::Unregistered { action_id } => {
                DecisionLoopError::UnregisteredDecisionAction { action_id }
            },
            ScheduledActionAuthorizationError::HasPrerequisites { action_id } => {
                DecisionLoopError::AdaptiveActionRequiresPlanning { action_id }
            },
            ScheduledActionAuthorizationError::Excluded { action_id, reason } => {
                if reason == crate::ExclusionReason::DefenseSuppressed {
                    return DecisionLoopError::DefenseSuppressedAction { action_id };
                }
                if preserve_scheduled_target_errors {
                    match reason {
                        crate::ExclusionReason::NoEligibleHypothesis => {
                            return DecisionLoopError::NoEligibleScheduledMotivationHypothesis {
                                action_id,
                            };
                        },
                        crate::ExclusionReason::NoEligibleVerificationTarget => {
                            return DecisionLoopError::NoEligibleScheduledVerificationTarget {
                                action_id,
                            };
                        },
                        _ => {},
                    }
                }
                DecisionLoopError::IneligibleAdaptiveAction { action_id }
            },
        })
}
