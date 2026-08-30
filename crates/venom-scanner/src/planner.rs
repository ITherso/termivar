//! Deterministic, budget-aware attack planning.
//!
//! ## Runtime scope
//!
//! - **Build:** always/default.
//! - **Execution:** Surface B (deterministic decision runtime).
//! - **Default `venom scan`:** yes, through `StandardWebDecisionRuntime`.
//! - **Support:** implemented and tested.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! The planner ranks declarative actions but never executes them. It consumes
//! one immutable knowledge snapshot, evaluates action requirements, derives
//! confidence from Bayesian hypotheses, and emits an explainable plan.

use thiserror::Error;

use crate::rules::RuleEngineError;

#[cfg(test)]
use std::collections::{BTreeMap, BTreeSet};
#[cfg(test)]
use venom_core::{EntityId, EvidenceValue, Hypothesis, HypothesisStrength, Probability};

#[cfg(test)]
use crate::{knowledge::KnowledgeBase, payload_strategy::PayloadStrategyRef, rules::Expression};

mod model;
mod policy;
mod scoring;
mod selection;

pub use model::{
    AttackAction, AttackPlan, ExcludedAction, ExclusionReason, HypothesisSelector, PlanStep,
    PlannerWrite, PlanningContext, RequiredStrength, ResolvedVerificationTarget,
    VerificationTarget,
};
pub(crate) use policy::{ActionSuppressionContext, ScheduledActionAuthorizationError};
pub use scoring::{ActionCost, BenefitScore, RiskScore, UtilityBreakdown, UtilityScore};
pub use selection::AttackPlanner;

/// Validation and consistency failures raised by the attack planner.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PlannerError {
    /// A required identifier or executor name was empty.
    #[error("{field} must not be empty")]
    EmptyValue { field: &'static str },

    /// A normalized benefit exceeded 10,000 basis points.
    #[error("benefit score {0} exceeds 10,000 basis points")]
    BenefitOutOfRange(u16),

    /// Risk must be in the inclusive `1..=10_000` range.
    #[error("risk score {0} must be between 1 and 10,000 basis points")]
    RiskOutOfRange(u16),

    /// Estimated action cost must be positive.
    #[error("action cost must be greater than zero")]
    ZeroCost,

    /// An action listed itself as a prerequisite.
    #[error("action {action_id} cannot depend on itself")]
    SelfDependency { action_id: String },

    /// An action referenced a prerequisite that is not registered.
    #[error("action {action_id} references unknown prerequisite {prerequisite}")]
    UnknownPrerequisite {
        /// Action containing the reference.
        action_id: String,
        /// Missing action identity.
        prerequisite: String,
    },

    /// The action dependency graph contains a cycle.
    #[error("action dependency cycle includes {action_id}")]
    DependencyCycle { action_id: String },

    /// An action identity was reused with different semantics.
    #[error("action identity {id} already has a different definition")]
    ActionIdentityConflict { id: String },

    /// Internal selection accounting omitted a registered action.
    #[error("planner produced no selection decision for action {action_id}")]
    IncompleteDecision { action_id: String },

    /// Expression evaluation failed.
    #[error(transparent)]
    Rule(#[from] RuleEngineError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        EvidenceCalibration, EvidenceSelector, ExperiencePolicy, ExperienceStore,
        HypothesisConclusion, KnowledgeLayer, ReasoningRule, RuleEngine,
    };
    use venom_core::{
        BayesianEvidence, ConfidenceScore, Evidence, EvidenceKind, EvidenceSource, HypothesisState,
        KnowledgePredicate, Outcome, OutcomeStatus, VerificationStage,
    };

    fn subject() -> EntityId {
        EntityId::new("endpoint:https://example.test").unwrap()
    }

    fn stack_predicate() -> KnowledgePredicate {
        KnowledgePredicate::new("stack", "framework").unwrap()
    }

    fn stack_value() -> EvidenceValue {
        EvidenceValue::Text("Laravel".into())
    }

    fn knowledge_with_hypothesis(posterior_signal: (u8, u8)) -> KnowledgeBase {
        let knowledge = KnowledgeBase::new();
        let evidence = Evidence::new(
            subject(),
            EvidenceKind::Technology,
            KnowledgePredicate::new("technology", "framework").unwrap(),
            stack_value(),
            EvidenceSource::new("discovery", "framework-header").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );
        knowledge.insert_evidence(evidence.clone()).unwrap();
        let mut hypothesis = Hypothesis::with_id(
            "hypothesis:laravel",
            subject(),
            stack_predicate(),
            stack_value(),
            Probability::from_percent(50).unwrap(),
        )
        .unwrap();
        hypothesis
            .observe(
                BayesianEvidence::new(
                    evidence.id().clone(),
                    Probability::from_percent(posterior_signal.0).unwrap(),
                    Probability::from_percent(posterior_signal.1).unwrap(),
                    "framework fingerprint",
                )
                .unwrap(),
            )
            .unwrap();
        hypothesis.set_strength(HypothesisStrength::Strong);
        hypothesis.set_state(HypothesisState::Supported);
        knowledge.upsert_hypothesis(hypothesis).unwrap();
        knowledge
    }

    fn action(id: &str, gain: u8, cost: u32, risk: u8, prerequisites: &[&str]) -> AttackAction {
        AttackAction::new(
            id,
            format!("plugin.{id}"),
            Expression::equals(KnowledgeLayer::Hypothesis, stack_predicate(), stack_value()),
            HypothesisSelector::new(
                stack_predicate(),
                stack_value(),
                Probability::from_percent(50).unwrap(),
                RequiredStrength::Strong,
            ),
            BenefitScore::from_percent(gain).unwrap(),
            ActionCost::new(cost).unwrap(),
            RiskScore::from_percent(risk).unwrap(),
            prerequisites.iter().map(|value| (*value).into()).collect(),
        )
        .unwrap()
    }

    fn context(budget: u64) -> PlanningContext {
        PlanningContext::new(
            BenefitScore::from_percent(90).unwrap(),
            budget,
            RiskScore::from_percent(80).unwrap(),
        )
    }

    #[test]
    fn utility_uses_fixed_point_formula() {
        let utility = UtilityBreakdown::calculate(
            BenefitScore::from_percent(80).unwrap(),
            Probability::from_percent(75).unwrap(),
            BenefitScore::from_percent(90).unwrap(),
            ActionCost::new(100).unwrap(),
            RiskScore::from_percent(20).unwrap(),
        );

        assert_eq!(utility.score().units(), 270_000_000);
        let encoded = serde_json::to_value(utility).unwrap();
        assert_eq!(
            serde_json::from_value::<UtilityBreakdown>(encoded.clone()).unwrap(),
            utility
        );
        let mut tampered = encoded;
        tampered["score"] = serde_json::json!(1);
        assert!(serde_json::from_value::<UtilityBreakdown>(tampered).is_err());
    }

    #[test]
    fn planner_orders_equal_utility_by_action_id() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let mut planner = AttackPlanner::new();
        planner.register(action("zeta", 80, 10, 20, &[])).unwrap();
        planner.register(action("alpha", 80, 10, 20, &[])).unwrap();

        let first = planner.plan(&knowledge, &subject(), context(100)).unwrap();
        let second = planner.plan(&knowledge, &subject(), context(100)).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.steps()[0].action_id(), "alpha");
        assert_eq!(first.steps()[1].action_id(), "zeta");
        assert_eq!(first.total_cost(), 20);
    }

    #[test]
    fn registration_order_cannot_change_dependency_or_suppression_semantics() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let actions = [
            action("root", 60, 10, 20, &[]),
            action("dependent", 90, 10, 20, &["root"]),
            action("independent", 70, 10, 20, &[]),
            action("knowledge-only", 50, 10, 20, &[])
                .with_verification_target(VerificationTarget::KnowledgeOnly),
        ];
        let mut forward = AttackPlanner::new();
        let mut reverse = AttackPlanner::new();
        for action in &actions {
            forward.register(action.clone()).unwrap();
        }
        for action in actions.iter().rev() {
            reverse.register(action.clone()).unwrap();
        }
        let suppressions = BTreeSet::from(["independent".to_owned()]);

        let forward_plan = forward
            .plan_with_suppressed(&knowledge, &subject(), context(100), &suppressions)
            .unwrap();
        let reverse_plan = reverse
            .plan_with_suppressed(&knowledge, &subject(), context(100), &suppressions)
            .unwrap();

        assert_eq!(forward_plan, reverse_plan);
        let positions: BTreeMap<_, _> = forward_plan
            .steps()
            .iter()
            .map(|step| (step.action_id(), step.position()))
            .collect();
        assert!(positions["root"] < positions["dependent"]);
        assert!(!positions.contains_key("independent"));
        assert_eq!(
            forward_plan
                .excluded()
                .iter()
                .find(|excluded| excluded.action_id() == "independent")
                .unwrap()
                .reason(),
            &ExclusionReason::PolicySuppressed
        );
    }

    #[test]
    fn defense_filter_is_exact_baseline_subsequence_without_budget_refill() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let snapshot = knowledge.snapshot_for_subject(&subject());
        let mut planner = AttackPlanner::new();
        for id in ["alpha", "beta", "gamma"] {
            planner.register(action(id, 80, 10, 20, &[])).unwrap();
        }
        let baseline = planner.plan_snapshot(&snapshot, context(20)).unwrap();
        assert_eq!(
            baseline
                .steps()
                .iter()
                .map(PlanStep::action_id)
                .collect::<Vec<_>>(),
            ["alpha", "beta"]
        );
        assert_eq!(baseline.excluded()[0].action_id(), "gamma");
        let expected_beta = baseline.steps()[1].clone();

        let budget_only_suppression = baseline
            .clone()
            .into_defense_filtered(&BTreeSet::from(["gamma".to_owned()]));
        assert_eq!(budget_only_suppression, baseline);
        assert_eq!(
            serde_json::to_vec(&budget_only_suppression).unwrap(),
            serde_json::to_vec(&baseline).unwrap()
        );

        let suppressions =
            ActionSuppressionContext::new(BTreeSet::new(), BTreeSet::from(["alpha".to_owned()]));
        let filtered = planner
            .plan_snapshot_with_action_suppressions(&snapshot, context(20), &suppressions)
            .unwrap();

        assert_eq!(
            filtered
                .steps()
                .iter()
                .map(PlanStep::action_id)
                .collect::<Vec<_>>(),
            ["beta"]
        );
        assert_eq!(filtered.total_cost(), 10);
        assert_eq!(filtered.steps()[0].position(), 0);
        assert_eq!(filtered.steps()[0].executor(), expected_beta.executor());
        assert_eq!(filtered.steps()[0].utility(), expected_beta.utility());
        assert_eq!(
            filtered.steps()[0].requirements(),
            expected_beta.requirements()
        );
        assert!(filtered
            .excluded()
            .iter()
            .any(|entry| entry.action_id() == "alpha"
                && entry.reason() == &ExclusionReason::DefenseSuppressed));
        assert!(filtered
            .excluded()
            .iter()
            .any(|entry| entry.action_id() == "gamma"
                && matches!(entry.reason(), ExclusionReason::BudgetExceeded { .. })));
    }

    #[test]
    fn defense_filter_cascades_dependencies_and_preserves_retained_metadata() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let snapshot = knowledge.snapshot_for_subject(&subject());
        let strategy = PayloadStrategyRef::new("independent.strategy", 4).unwrap();
        let mut planner = AttackPlanner::new();
        planner.register(action("root", 80, 10, 20, &[])).unwrap();
        planner
            .register(action("dependent", 90, 10, 20, &["root"]))
            .unwrap();
        planner
            .register(
                action("independent", 70, 10, 20, &[]).with_payload_strategy(strategy.clone()),
            )
            .unwrap();
        let baseline = planner.plan_snapshot(&snapshot, context(100)).unwrap();
        let expected = baseline
            .steps()
            .iter()
            .find(|step| step.action_id() == "independent")
            .unwrap()
            .clone();

        let filtered = baseline
            .clone()
            .into_defense_filtered(&BTreeSet::from(["root".to_owned()]));

        assert_eq!(
            filtered
                .steps()
                .iter()
                .map(PlanStep::action_id)
                .collect::<Vec<_>>(),
            ["independent"]
        );
        let retained = &filtered.steps()[0];
        assert_eq!(retained.executor(), expected.executor());
        assert_eq!(retained.payload_strategy(), Some(&strategy));
        assert_eq!(retained.prerequisites(), expected.prerequisites());
        assert_eq!(
            retained.confidence_hypothesis_id(),
            expected.confidence_hypothesis_id()
        );
        assert_eq!(
            retained.verification_target(),
            expected.verification_target()
        );
        assert_eq!(retained.requirements(), expected.requirements());
        assert_eq!(retained.utility(), expected.utility());
        assert!(filtered.excluded().iter().any(|entry| {
            entry.action_id() == "dependent"
                && entry.reason()
                    == &ExclusionReason::DependencyUnavailable {
                        prerequisite: "root".to_owned(),
                    }
        }));
    }

    #[test]
    fn empty_defense_context_is_exact_planner_compatibility_path() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let snapshot = knowledge.snapshot_for_subject(&subject());
        let mut planner = AttackPlanner::new();
        planner.register(action("alpha", 80, 10, 20, &[])).unwrap();

        let baseline = planner.plan_snapshot(&snapshot, context(100)).unwrap();
        let compatibility = planner
            .plan_snapshot_with_action_suppressions(
                &snapshot,
                context(100),
                &ActionSuppressionContext::default(),
            )
            .unwrap();

        assert_eq!(compatibility, baseline);
        assert_eq!(
            serde_json::to_vec(&compatibility).unwrap(),
            serde_json::to_vec(&baseline).unwrap()
        );
    }

    #[test]
    fn defense_precedes_policy_for_scheduled_authorization() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let snapshot = knowledge.snapshot_for_subject(&subject());
        let mut planner = AttackPlanner::new();
        planner.register(action("direct", 80, 10, 20, &[])).unwrap();
        let both = BTreeSet::from(["direct".to_owned()]);

        let policy_baseline = planner
            .plan_snapshot_with_defense_suppressed(&snapshot, context(100), &both, &BTreeSet::new())
            .unwrap();
        let defense_filtered = planner
            .plan_snapshot_with_defense_suppressed(&snapshot, context(100), &both, &both)
            .unwrap();
        assert_eq!(defense_filtered, policy_baseline);
        assert_eq!(
            serde_json::to_vec(&defense_filtered).unwrap(),
            serde_json::to_vec(&policy_baseline).unwrap()
        );
        assert_eq!(
            defense_filtered.excluded()[0].reason(),
            &ExclusionReason::PolicySuppressed
        );

        let denied = planner
            .authorize_scheduled_action_with_context(
                &snapshot,
                context(100),
                &ActionSuppressionContext::new(both.clone(), both),
                "direct",
            )
            .unwrap_err();

        assert!(matches!(
            denied,
            ScheduledActionAuthorizationError::Excluded {
                reason: ExclusionReason::DefenseSuppressed,
                ..
            }
        ));
    }

    #[test]
    fn scheduled_action_authorization_reuses_exact_planner_eligibility_and_policy() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let selected = action("direct", 80, 10, 20, &[])
            .with_payload_strategy(PayloadStrategyRef::new("direct.strategy", 2).unwrap())
            .with_verification_target(VerificationTarget::KnowledgeOnly);
        let mut planner = AttackPlanner::new();
        planner.register(selected).unwrap();
        let snapshot = knowledge.snapshot_for_subject(&subject());
        let exact_context = PlanningContext::new(
            BenefitScore::from_percent(90).unwrap(),
            10,
            RiskScore::from_percent(20).unwrap(),
        );

        let planned = planner.plan_snapshot(&snapshot, exact_context).unwrap();
        let authorized = planner
            .authorize_scheduled_action(&snapshot, exact_context, &BTreeSet::new(), "direct")
            .unwrap();

        assert_eq!(&authorized, &planned.steps()[0]);
        assert_eq!(authorized.executor(), "plugin.direct");
        assert_eq!(
            authorized.payload_strategy(),
            Some(&PayloadStrategyRef::new("direct.strategy", 2).unwrap())
        );
        assert_eq!(
            authorized.verification_target(),
            &ResolvedVerificationTarget::KnowledgeOnly
        );
        assert!(!authorized
            .verification_target()
            .applies_hypothesis_transition());
    }

    #[test]
    fn minimum_utility_exact_boundary_remains_eligible() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let mut planner = AttackPlanner::new();
        planner.register(action("direct", 80, 10, 20, &[])).unwrap();
        let snapshot = knowledge.snapshot_for_subject(&subject());
        let base_context = context(100);
        let score = planner
            .authorize_scheduled_action(&snapshot, base_context, &BTreeSet::new(), "direct")
            .unwrap()
            .utility()
            .score();

        planner
            .authorize_scheduled_action(
                &snapshot,
                base_context.with_minimum_utility(score),
                &BTreeSet::new(),
                "direct",
            )
            .unwrap();
        assert!(matches!(
            planner.authorize_scheduled_action(
                &snapshot,
                base_context.with_minimum_utility(UtilityScore::from_units(
                    score.units().checked_add(1).unwrap(),
                )),
                &BTreeSet::new(),
                "direct",
            ),
            Err(ScheduledActionAuthorizationError::Excluded {
                reason: ExclusionReason::BelowMinimumUtility { .. },
                ..
            })
        ));
    }

    #[test]
    fn scheduled_action_authorization_enforces_suppression_budget_and_risk_boundaries() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let mut planner = AttackPlanner::new();
        planner.register(action("direct", 80, 10, 20, &[])).unwrap();
        let snapshot = knowledge.snapshot_for_subject(&subject());
        let exact_context = PlanningContext::new(
            BenefitScore::from_percent(90).unwrap(),
            10,
            RiskScore::from_percent(20).unwrap(),
        );

        planner
            .authorize_scheduled_action(&snapshot, exact_context, &BTreeSet::new(), "direct")
            .unwrap();
        let suppressed = planner
            .authorize_scheduled_action(
                &snapshot,
                exact_context,
                &BTreeSet::from(["direct".to_owned()]),
                "direct",
            )
            .unwrap_err();
        assert!(matches!(
            suppressed,
            ScheduledActionAuthorizationError::Excluded {
                action_id,
                reason: ExclusionReason::PolicySuppressed,
            } if action_id == "direct"
        ));

        let budget = planner
            .authorize_scheduled_action(
                &snapshot,
                PlanningContext::new(
                    BenefitScore::from_percent(90).unwrap(),
                    9,
                    RiskScore::from_percent(20).unwrap(),
                ),
                &BTreeSet::new(),
                "direct",
            )
            .unwrap_err();
        assert!(matches!(
            budget,
            ScheduledActionAuthorizationError::Excluded {
                action_id,
                reason: ExclusionReason::BudgetExceeded {
                    required: 10,
                    remaining: 9,
                },
            } if action_id == "direct"
        ));

        let risk = planner
            .authorize_scheduled_action(
                &snapshot,
                PlanningContext::new(
                    BenefitScore::from_percent(90).unwrap(),
                    10,
                    RiskScore::from_percent(19).unwrap(),
                ),
                &BTreeSet::new(),
                "direct",
            )
            .unwrap_err();
        assert!(matches!(
            risk,
            ScheduledActionAuthorizationError::Excluded {
                action_id,
                reason: ExclusionReason::RiskLimitExceeded { .. },
            } if action_id == "direct"
        ));
    }

    #[test]
    fn scheduled_action_authorization_fails_closed_on_registry_and_dependency_graphs() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let snapshot = knowledge.snapshot_for_subject(&subject());
        let mut planner = AttackPlanner::new();
        planner.register(action("base", 40, 5, 10, &[])).unwrap();
        planner
            .register(action("dependent", 80, 5, 10, &["base"]))
            .unwrap();

        assert!(matches!(
            planner.authorize_scheduled_action(
                &snapshot,
                context(10),
                &BTreeSet::new(),
                "unknown",
            ),
            Err(ScheduledActionAuthorizationError::Unregistered { action_id })
                if action_id == "unknown"
        ));
        assert!(matches!(
            planner.authorize_scheduled_action(
                &snapshot,
                context(10),
                &BTreeSet::new(),
                "dependent",
            ),
            Err(ScheduledActionAuthorizationError::HasPrerequisites { action_id })
                if action_id == "dependent"
        ));
        assert!(matches!(
            planner.authorize_scheduled_action(
                &snapshot,
                context(10),
                &BTreeSet::from(["dependent".to_owned()]),
                "dependent",
            ),
            Err(ScheduledActionAuthorizationError::Excluded {
                action_id,
                reason: ExclusionReason::PolicySuppressed,
            }) if action_id == "dependent"
        ));

        let mut invalid = AttackPlanner::new();
        invalid
            .register(action("invalid", 80, 5, 10, &["missing"]))
            .unwrap();
        invalid.register(action("direct", 80, 5, 10, &[])).unwrap();
        assert!(matches!(
            invalid.authorize_scheduled_action(&snapshot, context(10), &BTreeSet::new(), "direct",),
            Err(ScheduledActionAuthorizationError::Planner(
                PlannerError::UnknownPrerequisite { .. }
            ))
        ));
    }

    #[test]
    fn scheduled_action_authorization_reuses_requirement_target_and_utility_checks() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let snapshot = knowledge.snapshot_for_subject(&subject());
        let unmet = AttackAction::new(
            "unmet",
            "plugin.unmet",
            Expression::exists(
                KnowledgeLayer::Evidence,
                KnowledgePredicate::new("authentication", "mfa").unwrap(),
            ),
            HypothesisSelector::new(
                stack_predicate(),
                stack_value(),
                Probability::from_percent(50).unwrap(),
                RequiredStrength::Strong,
            ),
            BenefitScore::from_percent(80).unwrap(),
            ActionCost::new(10).unwrap(),
            RiskScore::from_percent(10).unwrap(),
            BTreeSet::new(),
        )
        .unwrap();
        let missing_motivation = AttackAction::new(
            "missing-motivation",
            "plugin.missing-motivation",
            Expression::equals(KnowledgeLayer::Hypothesis, stack_predicate(), stack_value()),
            HypothesisSelector::new(
                KnowledgePredicate::new("auth", "missing-motivation").unwrap(),
                EvidenceValue::Boolean(true),
                Probability::from_percent(50).unwrap(),
                RequiredStrength::Any,
            ),
            BenefitScore::from_percent(80).unwrap(),
            ActionCost::new(10).unwrap(),
            RiskScore::from_percent(10).unwrap(),
            BTreeSet::new(),
        )
        .unwrap();
        let missing_target = action("missing-target", 80, 10, 10, &[]).with_verification_target(
            VerificationTarget::Distinct(HypothesisSelector::new(
                KnowledgePredicate::new("auth", "mechanism").unwrap(),
                EvidenceValue::Text("missing".to_owned()),
                Probability::from_percent(50).unwrap(),
                RequiredStrength::Any,
            )),
        );
        let mut planner = AttackPlanner::new();
        planner.register(unmet).unwrap();
        planner.register(missing_motivation).unwrap();
        planner.register(missing_target).unwrap();
        planner
            .register(action("low-utility", 80, 10, 10, &[]))
            .unwrap();

        assert!(matches!(
            planner.authorize_scheduled_action(&snapshot, context(100), &BTreeSet::new(), "unmet",),
            Err(ScheduledActionAuthorizationError::Excluded {
                reason: ExclusionReason::RequirementsNotMet,
                ..
            })
        ));
        assert!(matches!(
            planner.authorize_scheduled_action(
                &snapshot,
                context(100),
                &BTreeSet::new(),
                "missing-motivation",
            ),
            Err(ScheduledActionAuthorizationError::Excluded {
                reason: ExclusionReason::NoEligibleHypothesis,
                ..
            })
        ));
        assert!(matches!(
            planner.authorize_scheduled_action(
                &snapshot,
                context(100),
                &BTreeSet::new(),
                "missing-target",
            ),
            Err(ScheduledActionAuthorizationError::Excluded {
                reason: ExclusionReason::NoEligibleVerificationTarget,
                ..
            })
        ));
        assert!(matches!(
            planner.authorize_scheduled_action(
                &snapshot,
                context(100).with_minimum_utility(UtilityScore::from_units(u64::MAX)),
                &BTreeSet::new(),
                "low-utility",
            ),
            Err(ScheduledActionAuthorizationError::Excluded {
                reason: ExclusionReason::BelowMinimumUtility { .. },
                ..
            })
        ));
    }

    #[test]
    fn replanning_excludes_policy_suppressed_actions() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let mut planner = AttackPlanner::new();
        planner.register(action("zeta", 80, 10, 20, &[])).unwrap();
        planner.register(action("alpha", 80, 10, 20, &[])).unwrap();

        let plan = planner
            .plan_with_suppressed(
                &knowledge,
                &subject(),
                context(100),
                &BTreeSet::from(["alpha".into()]),
            )
            .unwrap();

        assert_eq!(plan.steps().len(), 1);
        assert_eq!(plan.steps()[0].action_id(), "zeta");
        assert_eq!(plan.excluded()[0].action_id(), "alpha");
        assert_eq!(
            plan.excluded()[0].reason(),
            &ExclusionReason::PolicySuppressed
        );
    }

    #[test]
    fn planner_consumes_suppressions_derived_from_experience() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let evidence_id = knowledge.snapshot_for_subject(&subject()).evidence()[0]
            .id()
            .clone();
        let mut experience = ExperienceStore::new();
        for attempt in 0..10 {
            experience
                .observe(
                    Outcome::verified(
                        format!("case:alpha:{attempt}"),
                        subject(),
                        "alpha",
                        "hypothesis:laravel",
                        "verify.alpha",
                        VerificationStage::Active,
                        OutcomeStatus::ConfirmedNegative,
                        Probability::from_percent(80).unwrap(),
                        "active negative control rejected alpha",
                        BTreeSet::from([evidence_id.clone()]),
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        let suppressed = experience.suppressed_actions(&subject(), ExperiencePolicy::default());
        let mut planner = AttackPlanner::new();
        planner.register(action("alpha", 80, 10, 20, &[])).unwrap();
        planner.register(action("zeta", 80, 10, 20, &[])).unwrap();

        let plan = planner
            .plan_with_suppressed(&knowledge, &subject(), context(100), &suppressed)
            .unwrap();

        assert_eq!(plan.steps().len(), 1);
        assert_eq!(plan.steps()[0].action_id(), "zeta");
        assert_eq!(plan.excluded()[0].action_id(), "alpha");
        assert_eq!(
            plan.excluded()[0].reason(),
            &ExclusionReason::PolicySuppressed
        );
    }

    #[test]
    fn planner_places_prerequisites_before_high_utility_action() {
        let knowledge = knowledge_with_hypothesis((90, 10));
        let mut planner = AttackPlanner::new();
        planner
            .register(action("discovery", 10, 10, 40, &[]))
            .unwrap();
        planner
            .register(action("active.verify", 95, 30, 10, &["discovery"]))
            .unwrap();

        let plan = planner.plan(&knowledge, &subject(), context(40)).unwrap();

        assert_eq!(plan.steps()[0].action_id(), "discovery");
        assert_eq!(plan.steps()[1].action_id(), "active.verify");
        assert_eq!(plan.total_cost(), 40);
    }

    #[test]
    fn budget_exclusion_includes_dependency_closure_cost() {
        let knowledge = knowledge_with_hypothesis((90, 10));
        let mut planner = AttackPlanner::new();
        planner
            .register(action("discovery", 10, 10, 40, &[]))
            .unwrap();
        planner
            .register(action("active.verify", 95, 30, 10, &["discovery"]))
            .unwrap();

        let plan = planner.plan(&knowledge, &subject(), context(35)).unwrap();

        assert_eq!(plan.steps().len(), 1);
        assert_eq!(plan.steps()[0].action_id(), "discovery");
        let active = plan
            .excluded()
            .iter()
            .find(|excluded| excluded.action_id() == "active.verify")
            .unwrap();
        assert_eq!(
            active.reason(),
            &ExclusionReason::BudgetExceeded {
                required: 40,
                remaining: 35,
            }
        );
    }

    #[test]
    fn risk_and_confidence_filters_are_explainable() {
        let knowledge = knowledge_with_hypothesis((60, 40));
        let mut planner = AttackPlanner::new();
        planner.register(action("risky", 90, 10, 90, &[])).unwrap();
        let strict_confidence = AttackAction::new(
            "uncertain",
            "plugin.uncertain",
            Expression::equals(KnowledgeLayer::Hypothesis, stack_predicate(), stack_value()),
            HypothesisSelector::new(
                stack_predicate(),
                stack_value(),
                Probability::from_percent(90).unwrap(),
                RequiredStrength::Strong,
            ),
            BenefitScore::from_percent(80).unwrap(),
            ActionCost::new(10).unwrap(),
            RiskScore::from_percent(10).unwrap(),
            BTreeSet::new(),
        )
        .unwrap();
        planner.register(strict_confidence).unwrap();
        let unmet = AttackAction::new(
            "unmet",
            "plugin.unmet",
            Expression::exists(
                KnowledgeLayer::Evidence,
                KnowledgePredicate::new("authentication", "mfa").unwrap(),
            ),
            HypothesisSelector::new(
                stack_predicate(),
                stack_value(),
                Probability::from_percent(50).unwrap(),
                RequiredStrength::Strong,
            ),
            BenefitScore::from_percent(80).unwrap(),
            ActionCost::new(10).unwrap(),
            RiskScore::from_percent(10).unwrap(),
            BTreeSet::new(),
        )
        .unwrap();
        planner.register(unmet).unwrap();

        let plan = planner.plan(&knowledge, &subject(), context(100)).unwrap();

        assert!(plan.steps().is_empty());
        assert!(matches!(
            plan.excluded()[0].reason(),
            ExclusionReason::RiskLimitExceeded { .. } | ExclusionReason::NoEligibleHypothesis
        ));
        assert!(plan
            .excluded()
            .iter()
            .any(|excluded| matches!(excluded.reason(), ExclusionReason::NoEligibleHypothesis)));
        assert!(plan.excluded().iter().any(|excluded| matches!(
            excluded.reason(),
            ExclusionReason::RiskLimitExceeded { .. }
        )));
        assert!(plan
            .excluded()
            .iter()
            .any(|excluded| matches!(excluded.reason(), ExclusionReason::RequirementsNotMet)));
    }

    #[test]
    fn dependency_validation_rejects_unknown_and_cycles() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let mut unknown = AttackPlanner::new();
        unknown
            .register(action("dependent", 80, 10, 20, &["missing"]))
            .unwrap();
        assert!(matches!(
            unknown.plan(&knowledge, &subject(), context(100)),
            Err(PlannerError::UnknownPrerequisite { .. })
        ));

        let mut cyclic = AttackPlanner::new();
        cyclic.register(action("a", 80, 10, 20, &["b"])).unwrap();
        cyclic.register(action("b", 80, 10, 20, &["a"])).unwrap();
        assert!(matches!(
            cyclic.plan(&knowledge, &subject(), context(100)),
            Err(PlannerError::DependencyCycle { .. })
        ));
    }

    #[test]
    fn ineligible_dependency_blocks_dependent_action() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let blocked = AttackAction::new(
            "blocked",
            "plugin.blocked",
            Expression::exists(
                KnowledgeLayer::Evidence,
                KnowledgePredicate::new("authentication", "mfa").unwrap(),
            ),
            HypothesisSelector::new(
                stack_predicate(),
                stack_value(),
                Probability::from_percent(50).unwrap(),
                RequiredStrength::Strong,
            ),
            BenefitScore::from_percent(80).unwrap(),
            ActionCost::new(10).unwrap(),
            RiskScore::from_percent(10).unwrap(),
            BTreeSet::new(),
        )
        .unwrap();
        let mut planner = AttackPlanner::new();
        planner.register(blocked).unwrap();
        planner
            .register(action("dependent", 90, 10, 10, &["blocked"]))
            .unwrap();

        let plan = planner.plan(&knowledge, &subject(), context(100)).unwrap();

        assert!(plan.steps().is_empty());
        let dependent = plan
            .excluded()
            .iter()
            .find(|excluded| excluded.action_id() == "dependent")
            .unwrap();
        assert_eq!(
            dependent.reason(),
            &ExclusionReason::DependencyUnavailable {
                prerequisite: "blocked".into(),
            }
        );
    }

    #[test]
    fn action_registration_and_wire_invariants_are_enforced() {
        let action = action("sqli.verify", 80, 10, 20, &[]);
        let encoded = serde_json::to_value(&action).unwrap();
        assert!(encoded.get("verification_target").is_none());
        assert!(encoded.get("payload_claim_policy_guard").is_none());
        assert_eq!(
            serde_json::from_value::<AttackAction>(encoded).unwrap(),
            action
        );
        assert!(ActionCost::new(0).is_err());
        assert!(RiskScore::from_basis_points(0).is_err());
        assert!(BenefitScore::from_basis_points(10_001).is_err());

        let mut planner = AttackPlanner::new();
        assert_eq!(
            planner.register(action.clone()).unwrap(),
            PlannerWrite::Inserted
        );
        assert_eq!(
            planner.register(action.clone()).unwrap(),
            PlannerWrite::Unchanged
        );
        assert!(matches!(
            planner.register(
                action
                    .clone()
                    .with_verification_target(VerificationTarget::KnowledgeOnly)
            ),
            Err(PlannerError::ActionIdentityConflict { .. })
        ));
        let conflicting = AttackAction::new(
            action.id(),
            "plugin.other",
            action.requirements.clone(),
            action.confidence_source.clone(),
            action.gain,
            action.cost,
            action.risk,
            BTreeSet::new(),
        )
        .unwrap();
        assert!(matches!(
            planner.register(conflicting),
            Err(PlannerError::ActionIdentityConflict { .. })
        ));
    }

    #[test]
    fn verification_targets_round_trip_and_reserved_typos_fail_closed() {
        let knowledge_only = action("form.discover", 80, 10, 20, &[])
            .with_verification_target(VerificationTarget::KnowledgeOnly);
        let encoded = serde_json::to_value(&knowledge_only).unwrap();
        assert_eq!(encoded["verification_target"], "knowledge_only");
        assert_eq!(encoded["payload_claim_policy_guard"], true);
        let mut unguarded = encoded.clone();
        unguarded
            .as_object_mut()
            .unwrap()
            .remove("payload_claim_policy_guard");
        assert!(serde_json::from_value::<AttackAction>(unguarded).is_err());
        assert_eq!(
            serde_json::from_value::<AttackAction>(encoded).unwrap(),
            knowledge_only
        );

        let distinct_selector = HypothesisSelector::new(
            KnowledgePredicate::new("auth", "mechanism").unwrap(),
            EvidenceValue::Text("http-basic".to_owned()),
            Probability::from_percent(60).unwrap(),
            RequiredStrength::Any,
        );
        let distinct = action("auth.verify", 80, 10, 20, &[])
            .with_verification_target(VerificationTarget::Distinct(distinct_selector));
        assert_eq!(
            serde_json::from_value::<AttackAction>(serde_json::to_value(&distinct).unwrap())
                .unwrap(),
            distinct
        );

        let mut misspelled = serde_json::to_value(action("typo", 80, 10, 20, &[])).unwrap();
        misspelled["verification_targte"] = serde_json::json!("knowledge_only");
        assert!(serde_json::from_value::<AttackAction>(misspelled).is_err());
    }

    #[test]
    fn planner_separates_confidence_from_resolved_verification_target() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let target_predicate = KnowledgePredicate::new("auth", "mechanism").unwrap();
        let target_value = EvidenceValue::Text("http-basic".to_owned());
        let mut target = Hypothesis::with_id(
            "hypothesis:http-basic",
            subject(),
            target_predicate.clone(),
            target_value.clone(),
            Probability::from_percent(80).unwrap(),
        )
        .unwrap();
        target.set_strength(HypothesisStrength::Strong);
        target.set_state(HypothesisState::Supported);
        knowledge.upsert_hypothesis(target).unwrap();

        let mut planner = AttackPlanner::new();
        planner
            .register(action("motivation", 80, 10, 20, &[]))
            .unwrap();
        planner
            .register(
                action("distinct", 80, 10, 20, &[]).with_verification_target(
                    VerificationTarget::Distinct(HypothesisSelector::new(
                        target_predicate,
                        target_value,
                        Probability::from_percent(60).unwrap(),
                        RequiredStrength::Any,
                    )),
                ),
            )
            .unwrap();
        planner
            .register(
                action("knowledge-only", 80, 10, 20, &[])
                    .with_verification_target(VerificationTarget::KnowledgeOnly),
            )
            .unwrap();

        let plan = planner.plan(&knowledge, &subject(), context(100)).unwrap();
        let step = |action_id| {
            plan.steps()
                .iter()
                .find(|step| step.action_id() == action_id)
                .unwrap()
        };

        for action_id in ["motivation", "distinct", "knowledge-only"] {
            assert_eq!(
                step(action_id).confidence_hypothesis_id(),
                "hypothesis:laravel"
            );
        }
        assert_eq!(
            step("motivation").verification_target().hypothesis_id(),
            Some("hypothesis:laravel")
        );
        assert_eq!(
            step("distinct").verification_target().hypothesis_id(),
            Some("hypothesis:http-basic")
        );
        assert_eq!(
            step("knowledge-only").verification_target(),
            &ResolvedVerificationTarget::KnowledgeOnly
        );
        assert!(!step("knowledge-only")
            .verification_target()
            .applies_hypothesis_transition());
    }

    #[test]
    fn missing_distinct_verification_target_is_excluded_fail_closed() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let distinct_action = action("distinct", 80, 10, 20, &[]).with_verification_target(
            VerificationTarget::Distinct(HypothesisSelector::new(
                KnowledgePredicate::new("auth", "mechanism").unwrap(),
                EvidenceValue::Text("http-basic".to_owned()),
                Probability::from_percent(60).unwrap(),
                RequiredStrength::Any,
            )),
        );
        let mut planner = AttackPlanner::new();
        planner.register(distinct_action).unwrap();

        let plan = planner.plan(&knowledge, &subject(), context(100)).unwrap();

        assert!(plan.steps().is_empty());
        assert_eq!(
            plan.excluded()[0].reason(),
            &ExclusionReason::NoEligibleVerificationTarget
        );

        let same_as_motivation = action("same-target", 80, 10, 20, &[]).with_verification_target(
            VerificationTarget::Distinct(HypothesisSelector::new(
                stack_predicate(),
                stack_value(),
                Probability::from_percent(50).unwrap(),
                RequiredStrength::Strong,
            )),
        );
        let mut planner = AttackPlanner::new();
        planner.register(same_as_motivation).unwrap();
        let plan = planner.plan(&knowledge, &subject(), context(100)).unwrap();
        assert!(plan.steps().is_empty());
        assert_eq!(
            plan.excluded()[0].reason(),
            &ExclusionReason::NoEligibleVerificationTarget
        );
    }

    #[test]
    fn planner_carries_exact_strategy_revision_without_exposing_payloads() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let strategy = PayloadStrategyRef::new("visibility.control-pair", 2).unwrap();
        let selected =
            action("visibility.compare", 80, 10, 20, &[]).with_payload_strategy(strategy.clone());
        let legacy = action("legacy.observe", 70, 10, 20, &[]);

        let legacy_wire = serde_json::to_value(&legacy).unwrap();
        assert!(legacy_wire.get("payload_strategy").is_none());
        assert!(serde_json::from_value::<AttackAction>(legacy_wire)
            .unwrap()
            .payload_strategy()
            .is_none());
        let mut misspelled = serde_json::to_value(&legacy).unwrap();
        misspelled["payload_stratgey"] = serde_json::json!({
            "id": "visibility.control-pair",
            "revision": 1
        });
        assert!(serde_json::from_value::<AttackAction>(misspelled).is_err());
        let mut extended = serde_json::to_value(&legacy).unwrap();
        extended["future_extension"] = serde_json::json!({"accepted": true});
        assert!(serde_json::from_value::<AttackAction>(extended).is_ok());

        let selected_wire = serde_json::to_value(&selected).unwrap();
        assert_eq!(selected_wire["payload_strategy"]["revision"], 2);
        assert_eq!(
            serde_json::from_value::<AttackAction>(selected_wire).unwrap(),
            selected
        );

        let mut planner = AttackPlanner::new();
        planner.register(selected.clone()).unwrap();
        let plan = planner.plan(&knowledge, &subject(), context(100)).unwrap();
        assert_eq!(plan.steps()[0].payload_strategy(), Some(&strategy));
        assert_eq!(
            planner
                .action("visibility.compare")
                .and_then(AttackAction::payload_strategy),
            Some(&strategy)
        );

        let conflicting = action("visibility.compare", 80, 10, 20, &[])
            .with_payload_strategy(PayloadStrategyRef::new("visibility.control-pair", 3).unwrap());
        assert!(matches!(
            planner.register(conflicting),
            Err(PlannerError::ActionIdentityConflict { .. })
        ));
    }

    #[test]
    fn planner_accepts_hypotheses_materialized_by_rule_contracts() {
        let knowledge = KnowledgeBase::new();
        let evidence_predicate = KnowledgePredicate::new("technology", "framework").unwrap();
        knowledge
            .insert_evidence(Evidence::new(
                subject(),
                EvidenceKind::Technology,
                evidence_predicate.clone(),
                stack_value(),
                EvidenceSource::new("discovery", "framework-header").unwrap(),
                ConfidenceScore::from_percent(90).unwrap(),
            ))
            .unwrap();
        let calibration = EvidenceCalibration::new(
            EvidenceSelector::equals(evidence_predicate.clone(), stack_value()),
            Probability::from_percent(80).unwrap(),
            Probability::from_percent(20).unwrap(),
            "framework fingerprint",
        )
        .unwrap();
        let conclusion = HypothesisConclusion::new(
            stack_predicate(),
            stack_value(),
            Probability::from_percent(50).unwrap(),
            HypothesisStrength::Strong,
            HypothesisState::Supported,
            vec![calibration],
        )
        .unwrap();
        let rule = ReasoningRule::new(
            "detect.laravel",
            Expression::equals(KnowledgeLayer::Evidence, evidence_predicate, stack_value()),
            conclusion,
        )
        .unwrap();
        let mut rules = RuleEngine::new();
        rules.register(rule).unwrap();
        rules.apply(&knowledge, &subject()).unwrap();

        let mut planner = AttackPlanner::new();
        planner
            .register(action("laravel.verify", 80, 10, 20, &[]))
            .unwrap();
        let plan = planner.plan(&knowledge, &subject(), context(100)).unwrap();

        assert_eq!(plan.steps().len(), 1);
        assert_eq!(plan.steps()[0].action_id(), "laravel.verify");
        assert_eq!(
            plan.steps()[0].confidence_hypothesis_id(),
            "rule:14:detect.laravel:endpoint:https://example.test"
        );
    }
}
