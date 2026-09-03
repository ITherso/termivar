use std::collections::{BTreeMap, BTreeSet};

use termivar_core::EntityId;

use crate::{
    knowledge::{KnowledgeBase, KnowledgeSnapshot},
    rules::ExpressionEvaluation,
};

use crate::planner::{
    model::{
        AttackAction, AttackPlan, ExcludedAction, ExclusionReason, PlanStep, PlannerWrite,
        PlanningContext, ResolvedVerificationTarget,
    },
    policy::{ActionSuppressionContext, ScheduledActionAuthorizationError},
    scoring::UtilityBreakdown,
    PlannerError,
};

#[derive(Debug, Clone)]
struct EligibleCandidate {
    action: AttackAction,
    confidence_hypothesis_id: String,
    verification_target: ResolvedVerificationTarget,
    requirements: ExpressionEvaluation,
    utility: UtilityBreakdown,
}

type CandidateEligibility = Result<EligibleCandidate, ExclusionReason>;

/// Deterministic utility planner for declarative attack actions.
#[derive(Debug, Clone, Default)]
pub struct AttackPlanner {
    actions: BTreeMap<String, AttackAction>,
}

impl AttackPlanner {
    /// Creates an empty planner.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an idempotent action definition.
    pub fn register(&mut self, action: AttackAction) -> Result<PlannerWrite, PlannerError> {
        if let Some(existing) = self.actions.get(action.id()) {
            return if existing == &action {
                Ok(PlannerWrite::Unchanged)
            } else {
                Err(PlannerError::ActionIdentityConflict {
                    id: action.id().to_owned(),
                })
            };
        }
        self.actions.insert(action.id().to_owned(), action);
        Ok(PlannerWrite::Inserted)
    }

    /// Returns a registered action definition by stable identity.
    pub fn action(&self, action_id: &str) -> Option<&AttackAction> {
        self.actions.get(action_id)
    }

    /// Returns the number of registered action identities.
    pub fn len(&self) -> usize {
        self.actions.len()
    }

    /// Returns whether no actions are registered.
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// Produces a plan from one internally consistent knowledge snapshot.
    pub fn plan(
        &self,
        knowledge: &KnowledgeBase,
        subject: &EntityId,
        context: PlanningContext,
    ) -> Result<AttackPlan, PlannerError> {
        let snapshot = knowledge.snapshot_for_subject(subject);
        self.plan_snapshot(&snapshot, context)
    }

    /// Produces a plan while excluding actions suppressed by adaptive policy.
    pub fn plan_with_suppressed(
        &self,
        knowledge: &KnowledgeBase,
        subject: &EntityId,
        context: PlanningContext,
        suppressed_actions: &BTreeSet<String>,
    ) -> Result<AttackPlan, PlannerError> {
        let snapshot = knowledge.snapshot_for_subject(subject);
        self.plan_snapshot_with_suppressed(&snapshot, context, suppressed_actions)
    }

    /// Produces a plan from an explicit immutable snapshot.
    pub fn plan_snapshot(
        &self,
        snapshot: &KnowledgeSnapshot,
        context: PlanningContext,
    ) -> Result<AttackPlan, PlannerError> {
        self.plan_snapshot_with_suppressed(snapshot, context, &BTreeSet::new())
    }

    /// Produces a plan from a snapshot and an explicit policy suppression set.
    pub fn plan_snapshot_with_suppressed(
        &self,
        snapshot: &KnowledgeSnapshot,
        context: PlanningContext,
        suppressed_actions: &BTreeSet<String>,
    ) -> Result<AttackPlan, PlannerError> {
        self.plan_snapshot_with_action_suppressions(
            snapshot,
            context,
            &ActionSuppressionContext::policy_only(suppressed_actions),
        )
    }

    /// Produces a plan distinguishing policy suppression from defense suppression.
    ///
    /// A defense-suppressed action is excluded with
    /// [`ExclusionReason::DefenseSuppressed`], never conflated with an adaptive
    /// or operator [`ExclusionReason::PolicySuppressed`]. A defense-suppressed
    /// action never becomes a plan step, so it never reaches an executor. The
    /// defense set filters the policy-authorized baseline and cannot refill
    /// budget with a candidate that baseline excluded.
    pub fn plan_snapshot_with_defense_suppressed(
        &self,
        snapshot: &KnowledgeSnapshot,
        context: PlanningContext,
        policy_suppressed_actions: &BTreeSet<String>,
        defense_suppressed_actions: &BTreeSet<String>,
    ) -> Result<AttackPlan, PlannerError> {
        self.plan_snapshot_with_action_suppressions(
            snapshot,
            context,
            &ActionSuppressionContext::new(
                policy_suppressed_actions.clone(),
                defense_suppressed_actions.clone(),
            ),
        )
    }

    pub(crate) fn plan_snapshot_with_action_suppressions(
        &self,
        snapshot: &KnowledgeSnapshot,
        context: PlanningContext,
        suppressions: &ActionSuppressionContext,
    ) -> Result<AttackPlan, PlannerError> {
        self.plan_snapshot_with_action_suppressions_and_baseline(snapshot, context, suppressions)
            .map(|(_, filtered)| filtered)
    }

    pub(crate) fn plan_snapshot_with_action_suppressions_and_baseline(
        &self,
        snapshot: &KnowledgeSnapshot,
        context: PlanningContext,
        suppressions: &ActionSuppressionContext,
    ) -> Result<(AttackPlan, AttackPlan), PlannerError> {
        let baseline = self.plan_snapshot_with_policy_suppressed(
            snapshot,
            context,
            suppressions.policy_suppressed_actions(),
        )?;
        let filtered = baseline
            .clone()
            .into_defense_filtered(suppressions.defense_suppressed_actions());
        Ok((baseline, filtered))
    }

    fn plan_snapshot_with_policy_suppressed(
        &self,
        snapshot: &KnowledgeSnapshot,
        context: PlanningContext,
        policy_suppressed_actions: &BTreeSet<String>,
    ) -> Result<AttackPlan, PlannerError> {
        self.validate_dependencies()?;

        let mut eligible = BTreeMap::<String, EligibleCandidate>::new();
        let mut exclusions = BTreeMap::<String, ExclusionReason>::new();
        for action in self.actions.values() {
            let suppression = policy_suppressed_actions
                .contains(action.id())
                .then_some(ExclusionReason::PolicySuppressed);
            match evaluate_candidate(action, snapshot, context, suppression)? {
                Ok(candidate) => {
                    eligible.insert(action.id.clone(), candidate);
                },
                Err(reason) => {
                    exclusions.insert(action.id.clone(), reason);
                },
            }
        }

        let mut ranked: Vec<String> = eligible.keys().cloned().collect();
        ranked.sort_by(|left, right| {
            eligible[right]
                .utility
                .score
                .cmp(&eligible[left].utility.score)
                .then_with(|| left.cmp(right))
        });

        let mut selected = BTreeSet::<String>::new();
        let mut ordered = Vec::<String>::new();
        let mut total_cost = 0_u64;
        for action_id in ranked {
            if selected.contains(&action_id) {
                continue;
            }
            let mut closure = Vec::new();
            let mut visiting = BTreeSet::new();
            if let Some(unavailable) = build_eligible_closure(
                &action_id,
                &eligible,
                &selected,
                &mut visiting,
                &mut closure,
            ) {
                exclusions.insert(
                    action_id.clone(),
                    ExclusionReason::DependencyUnavailable {
                        prerequisite: unavailable,
                    },
                );
                continue;
            }
            let required = closure.iter().fold(0_u64, |sum, id| {
                sum + u64::from(eligible[id].action.cost.units())
            });
            let remaining = context.budget.saturating_sub(total_cost);
            if required > remaining {
                exclusions.insert(
                    action_id,
                    ExclusionReason::BudgetExceeded {
                        required,
                        remaining,
                    },
                );
                continue;
            }
            for id in closure {
                if selected.insert(id.clone()) {
                    total_cost += u64::from(eligible[&id].action.cost.units());
                    ordered.push(id);
                }
            }
        }

        let steps = ordered
            .into_iter()
            .enumerate()
            .map(|(position, id)| plan_step(position, &eligible[&id]))
            .collect();
        let mut excluded = Vec::new();
        for id in self.actions.keys().filter(|id| !selected.contains(*id)) {
            let reason = exclusions
                .remove(id)
                .ok_or_else(|| PlannerError::IncompleteDecision {
                    action_id: id.clone(),
                })?;
            excluded.push(ExcludedAction {
                action_id: id.clone(),
                reason,
            });
        }

        Ok(AttackPlan {
            subject: snapshot.subject().clone(),
            context,
            total_cost,
            steps,
            excluded,
        })
    }

    /// Re-applies planner authority to one registered action before immediate
    /// adaptive dispatch.
    ///
    /// Unlike normal planning this does not rank the action against unrelated
    /// candidates. It does validate the complete registered graph, then applies
    /// the same suppression, requirement, risk, confidence, verification-target,
    /// and minimum-utility checks as [`Self::plan_snapshot_with_suppressed`]. A
    /// direct adaptive dispatch cannot safely satisfy a prerequisite closure,
    /// because the session does not preserve proof that those actions completed;
    /// such actions therefore fail closed. The requested action's own cost must
    /// fit the complete planning budget.
    #[cfg(test)]
    pub(crate) fn authorize_scheduled_action(
        &self,
        snapshot: &KnowledgeSnapshot,
        context: PlanningContext,
        policy_suppressed_actions: &BTreeSet<String>,
        action_id: &str,
    ) -> Result<PlanStep, ScheduledActionAuthorizationError> {
        self.authorize_scheduled_action_with_context(
            snapshot,
            context,
            &ActionSuppressionContext::policy_only(policy_suppressed_actions),
            action_id,
        )
    }

    pub(crate) fn authorize_scheduled_action_with_context(
        &self,
        snapshot: &KnowledgeSnapshot,
        context: PlanningContext,
        suppressions: &ActionSuppressionContext,
        action_id: &str,
    ) -> Result<PlanStep, ScheduledActionAuthorizationError> {
        self.validate_dependencies()?;
        let action = self.actions.get(action_id).ok_or_else(|| {
            ScheduledActionAuthorizationError::Unregistered {
                action_id: action_id.to_owned(),
            }
        })?;
        let suppression = if suppressions
            .defense_suppressed_actions()
            .contains(action_id)
        {
            Some(ExclusionReason::DefenseSuppressed)
        } else if suppressions.policy_suppressed_actions().contains(action_id) {
            Some(ExclusionReason::PolicySuppressed)
        } else {
            None
        };
        let candidate = match evaluate_candidate(action, snapshot, context, suppression)? {
            Ok(candidate) => candidate,
            Err(reason) => {
                return Err(ScheduledActionAuthorizationError::Excluded {
                    action_id: action_id.to_owned(),
                    reason,
                })
            },
        };
        if !candidate.action.prerequisites.is_empty() {
            return Err(ScheduledActionAuthorizationError::HasPrerequisites {
                action_id: action_id.to_owned(),
            });
        }
        let required = u64::from(candidate.action.cost.units());
        if required > context.budget {
            return Err(ScheduledActionAuthorizationError::Excluded {
                action_id: action_id.to_owned(),
                reason: ExclusionReason::BudgetExceeded {
                    required,
                    remaining: context.budget,
                },
            });
        }
        Ok(plan_step(0, &candidate))
    }

    fn validate_dependencies(&self) -> Result<(), PlannerError> {
        for action in self.actions.values() {
            for prerequisite in &action.prerequisites {
                if !self.actions.contains_key(prerequisite) {
                    return Err(PlannerError::UnknownPrerequisite {
                        action_id: action.id.clone(),
                        prerequisite: prerequisite.clone(),
                    });
                }
            }
        }
        let mut visiting = BTreeSet::new();
        let mut visited = BTreeSet::new();
        for action_id in self.actions.keys() {
            visit_dependency(action_id, &self.actions, &mut visiting, &mut visited)?;
        }
        Ok(())
    }
}

fn evaluate_candidate(
    action: &AttackAction,
    snapshot: &KnowledgeSnapshot,
    context: PlanningContext,
    suppression: Option<ExclusionReason>,
) -> Result<CandidateEligibility, PlannerError> {
    if let Some(reason) = suppression {
        return Ok(Err(reason));
    }
    let requirements = action.requirements.evaluate(snapshot)?;
    if !requirements.matched() {
        return Ok(Err(ExclusionReason::RequirementsNotMet));
    }
    if action.risk > context.maximum_risk {
        return Ok(Err(ExclusionReason::RiskLimitExceeded {
            actual: action.risk,
            maximum: context.maximum_risk,
        }));
    }
    let Some(hypothesis) = action.confidence_source.select(snapshot.hypotheses()) else {
        return Ok(Err(ExclusionReason::NoEligibleHypothesis));
    };
    let Some(verification_target) = action
        .verification_target
        .resolve(snapshot.hypotheses(), hypothesis.id())
    else {
        return Ok(Err(ExclusionReason::NoEligibleVerificationTarget));
    };
    let utility = UtilityBreakdown::calculate(
        action.gain,
        hypothesis.posterior(),
        context.business_value,
        action.cost,
        action.risk,
    );
    if utility.score < context.minimum_utility {
        return Ok(Err(ExclusionReason::BelowMinimumUtility {
            actual: utility.score,
            minimum: context.minimum_utility,
        }));
    }
    Ok(Ok(EligibleCandidate {
        action: action.clone(),
        confidence_hypothesis_id: hypothesis.id().to_owned(),
        verification_target,
        requirements,
        utility,
    }))
}

fn plan_step(position: usize, candidate: &EligibleCandidate) -> PlanStep {
    PlanStep {
        position,
        action_id: candidate.action.id.clone(),
        executor: candidate.action.executor.clone(),
        payload_strategy: candidate.action.payload_strategy.clone(),
        prerequisites: candidate.action.prerequisites.clone(),
        confidence_hypothesis_id: candidate.confidence_hypothesis_id.clone(),
        verification_target: candidate.verification_target.clone(),
        requirements: candidate.requirements.clone(),
        utility: candidate.utility,
    }
}

fn visit_dependency(
    action_id: &str,
    actions: &BTreeMap<String, AttackAction>,
    visiting: &mut BTreeSet<String>,
    visited: &mut BTreeSet<String>,
) -> Result<(), PlannerError> {
    if visited.contains(action_id) {
        return Ok(());
    }
    if !visiting.insert(action_id.to_owned()) {
        return Err(PlannerError::DependencyCycle {
            action_id: action_id.to_owned(),
        });
    }
    for prerequisite in &actions[action_id].prerequisites {
        visit_dependency(prerequisite, actions, visiting, visited)?;
    }
    visiting.remove(action_id);
    visited.insert(action_id.to_owned());
    Ok(())
}

fn build_eligible_closure(
    action_id: &str,
    eligible: &BTreeMap<String, EligibleCandidate>,
    selected: &BTreeSet<String>,
    visiting: &mut BTreeSet<String>,
    ordered: &mut Vec<String>,
) -> Option<String> {
    if selected.contains(action_id) || ordered.iter().any(|id| id == action_id) {
        return None;
    }
    let Some(candidate) = eligible.get(action_id) else {
        return Some(action_id.to_owned());
    };
    visiting.insert(action_id.to_owned());
    for prerequisite in &candidate.action.prerequisites {
        if !eligible.contains_key(prerequisite) {
            return Some(prerequisite.clone());
        }
        if !visiting.contains(prerequisite) {
            if let Some(unavailable) =
                build_eligible_closure(prerequisite, eligible, selected, visiting, ordered)
            {
                return Some(unavailable);
            }
        }
    }
    visiting.remove(action_id);
    ordered.push(action_id.to_owned());
    None
}
