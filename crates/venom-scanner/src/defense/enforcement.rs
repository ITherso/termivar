//! Default-off enforcement of defense-aware planning.
//!
//! This is the only place defense evidence is allowed to change the *real* plan,
//! and only when explicitly enabled. It reuses the side-effect-free shadow layer
//! to decide what to suppress, then applies those suppressions to the planner
//! through the distinct [`crate::planner::ExclusionReason::DefenseSuppressed`]
//! path — never by selecting an action, never by raising utility, and never by
//! reaching into any store.
//!
//! Release discipline: [`DefensePlanningPolicy`] is off by default. While
//! disabled, this returns the exact plan the planner would produce with no
//! defense influence, byte for byte.

use std::collections::BTreeSet;

use venom_core::EntityId;

use crate::knowledge::KnowledgeSnapshot;
use crate::planner::{AttackAction, AttackPlan, AttackPlanner, PlannerError, PlanningContext};

use super::shadow_planning::{
    defense_aware_shadow_plan, DefenseInteractionClass, ResourceDefenseSignal,
};

/// Whether observed defense is allowed to change the real plan.
///
/// Off by default. Enabling it is an explicit, per-release decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DefensePlanningPolicy {
    enabled: bool,
}

impl DefensePlanningPolicy {
    /// The default policy: defense observations never change the plan.
    pub const fn disabled() -> Self {
        Self { enabled: false }
    }

    /// A policy that lets defense observations suppress candidates.
    pub const fn enabled() -> Self {
        Self { enabled: true }
    }

    /// Builds a policy from an explicit flag value.
    pub const fn from_enabled(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Returns whether enforcement is enabled.
    pub const fn is_enabled(self) -> bool {
        self.enabled
    }
}

/// Produces the real plan, applying defense suppression only when enabled.
///
/// While the policy is disabled the result is byte-for-byte the plan
/// [`AttackPlanner::plan_snapshot`] produces, with no defense influence. When
/// enabled, actions the resource-scoped defense signal suppresses are excluded
/// with [`crate::planner::ExclusionReason::DefenseSuppressed`] and never become
/// plan steps, so a defense-denied action never reaches an executor. Defense
/// never adds an action, raises utility, or reorders otherwise-eligible steps —
/// it can only remove suppressed candidates.
pub fn defense_aware_plan(
    policy: DefensePlanningPolicy,
    planner: &AttackPlanner,
    snapshot: &KnowledgeSnapshot,
    subject: &EntityId,
    context: PlanningContext,
    signal: &ResourceDefenseSignal,
    classify: impl Fn(&AttackAction) -> DefenseInteractionClass,
) -> Result<AttackPlan, PlannerError> {
    if !policy.enabled {
        return planner.plan_snapshot(snapshot, context);
    }

    // Reuse the shadow layer so enforcement and explanation share one policy.
    let shadow = defense_aware_shadow_plan(planner, snapshot, subject, context, signal, classify)?;
    let defense_suppressed: BTreeSet<String> = shadow
        .delta()
        .suppressed()
        .iter()
        .map(|action| action.action_id().to_owned())
        .collect();

    planner.plan_snapshot_with_defense_suppressed(
        snapshot,
        context,
        &BTreeSet::new(),
        &defense_suppressed,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use venom_core::{
        BayesianEvidence, ConfidenceScore, Evidence, EvidenceKind, EvidenceSource, EvidenceValue,
        Hypothesis, HypothesisState, HypothesisStrength, KnowledgePredicate, Probability,
    };

    use super::*;
    use crate::defense::shadow_planning::ResourceDefenseObservation;
    use crate::defense::state::DefenseState;
    use crate::knowledge::KnowledgeBase;
    use crate::planner::{
        ActionCost, BenefitScore, ExclusionReason, HypothesisSelector, RequiredStrength, RiskScore,
    };
    use crate::{Expression, KnowledgeLayer};

    fn subject() -> EntityId {
        EntityId::new("endpoint:https://example.test/api/admin").unwrap()
    }

    fn other_subject() -> EntityId {
        EntityId::new("endpoint:https://example.test/public").unwrap()
    }

    fn stack_predicate() -> KnowledgePredicate {
        KnowledgePredicate::new("stack", "framework").unwrap()
    }

    fn stack_value() -> EvidenceValue {
        EvidenceValue::Text("Laravel".into())
    }

    fn knowledge_with_hypothesis() -> KnowledgeBase {
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
                    Probability::from_percent(80).unwrap(),
                    Probability::from_percent(20).unwrap(),
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

    fn action(id: &str, gain: u8) -> AttackAction {
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
            ActionCost::new(10).unwrap(),
            RiskScore::from_percent(20).unwrap(),
            BTreeSet::new(),
        )
        .unwrap()
    }

    fn classify(action: &AttackAction) -> DefenseInteractionClass {
        match action.id() {
            "local.report" => DefenseInteractionClass::LocalOnly,
            "passive.discovery" => DefenseInteractionClass::Passive,
            "active.verify" => DefenseInteractionClass::ActiveVerification,
            "mutating.fuzz" => DefenseInteractionClass::Mutating,
            other => panic!("unclassified test action {other}"),
        }
    }

    fn planner() -> AttackPlanner {
        let mut planner = AttackPlanner::new();
        planner.register(action("local.report", 60)).unwrap();
        planner.register(action("passive.discovery", 58)).unwrap();
        planner.register(action("active.verify", 54)).unwrap();
        planner.register(action("mutating.fuzz", 52)).unwrap();
        planner
    }

    fn context() -> PlanningContext {
        PlanningContext::new(
            BenefitScore::from_percent(90).unwrap(),
            1_000,
            RiskScore::from_percent(80).unwrap(),
        )
    }

    fn backoff_signal(resource: EntityId) -> ResourceDefenseSignal {
        let state = DefenseState::observe(429, &[], "slow down");
        let evidence = vec![venom_core::EvidenceId::parse("defense/e1").unwrap()];
        ResourceDefenseSignal::aggregate(
            resource,
            &[ResourceDefenseObservation::new(&state, None, evidence)],
        )
    }

    fn snapshot() -> KnowledgeSnapshot {
        // One knowledge base per test so plans built from it share evidence ids.
        knowledge_with_hypothesis().snapshot_for_subject(&subject())
    }

    fn plan_with(
        snapshot: &KnowledgeSnapshot,
        policy: DefensePlanningPolicy,
        signal: &ResourceDefenseSignal,
    ) -> AttackPlan {
        defense_aware_plan(
            policy,
            &planner(),
            snapshot,
            &subject(),
            context(),
            signal,
            classify,
        )
        .unwrap()
    }

    fn baseline_plan(snapshot: &KnowledgeSnapshot) -> AttackPlan {
        planner().plan_snapshot(snapshot, context()).unwrap()
    }

    fn step_ids(plan: &AttackPlan) -> BTreeSet<&str> {
        plan.steps().iter().map(|step| step.action_id()).collect()
    }

    #[test]
    fn disabled_flag_preserves_existing_plan_byte_for_byte() {
        // Even a Halt-level signal changes nothing while enforcement is off.
        let strong = {
            let first = DefenseState::observe(403, &[], "forbidden");
            let second = DefenseState::observe(406, &[], "not acceptable");
            ResourceDefenseSignal::aggregate(
                subject(),
                &[
                    ResourceDefenseObservation::new(&first, None, Vec::new()),
                    ResourceDefenseObservation::new(&second, None, Vec::new()),
                ],
            )
        };
        let snapshot = snapshot();
        assert_eq!(
            plan_with(&snapshot, DefensePlanningPolicy::disabled(), &strong),
            baseline_plan(&snapshot)
        );
        assert_eq!(
            plan_with(&snapshot, DefensePlanningPolicy::default(), &strong),
            baseline_plan(&snapshot)
        );
    }

    #[test]
    fn enabled_flag_suppresses_defense_actions_with_a_distinct_reason() {
        let plan = plan_with(
            &snapshot(),
            DefensePlanningPolicy::enabled(),
            &backoff_signal(subject()),
        );
        // Active and mutating work is suppressed; passive and local remain.
        assert!(!step_ids(&plan).contains("active.verify"));
        assert!(!step_ids(&plan).contains("mutating.fuzz"));
        assert!(step_ids(&plan).contains("passive.discovery"));
        assert!(step_ids(&plan).contains("local.report"));

        // The exclusion reason is distinct from a policy suppression.
        let reasons: Vec<_> = plan
            .excluded()
            .iter()
            .filter(|excluded| {
                excluded.action_id() == "active.verify" || excluded.action_id() == "mutating.fuzz"
            })
            .map(|excluded| excluded.reason().clone())
            .collect();
        assert_eq!(reasons.len(), 2);
        assert!(reasons
            .iter()
            .all(|reason| *reason == ExclusionReason::DefenseSuppressed));
    }

    #[test]
    fn defense_suppressed_strategy_never_reaches_a_plan_step() {
        // A defense-suppressed action is never a step, so it is never turned into
        // a command and never reaches an executor.
        let plan = plan_with(
            &snapshot(),
            DefensePlanningPolicy::enabled(),
            &backoff_signal(subject()),
        );
        for step in plan.steps() {
            assert_ne!(step.action_id(), "active.verify");
            assert_ne!(step.action_id(), "mutating.fuzz");
        }
    }

    #[test]
    fn enabled_but_unrelated_resource_preserves_the_plan() {
        let snapshot = snapshot();
        let plan = plan_with(
            &snapshot,
            DefensePlanningPolicy::enabled(),
            &backoff_signal(other_subject()),
        );
        assert_eq!(plan, baseline_plan(&snapshot));
    }

    #[test]
    fn enabled_but_proceed_preserves_the_plan() {
        let snapshot = snapshot();
        let proceed = ResourceDefenseSignal::proceed(subject());
        assert_eq!(
            plan_with(&snapshot, DefensePlanningPolicy::enabled(), &proceed),
            baseline_plan(&snapshot)
        );
    }

    #[test]
    fn enforcement_is_deterministic() {
        let snapshot = snapshot();
        let signal = backoff_signal(subject());
        assert_eq!(
            plan_with(&snapshot, DefensePlanningPolicy::enabled(), &signal),
            plan_with(&snapshot, DefensePlanningPolicy::enabled(), &signal)
        );
    }

    #[test]
    fn policy_is_disabled_by_default() {
        assert!(!DefensePlanningPolicy::default().is_enabled());
    }

    #[test]
    fn disabled_policy_does_not_evaluate_or_require_defense_metadata() {
        // While disabled, enforcement must fully bypass the defense path: it must
        // not classify actions or consult the signal, even if a Halt-level signal
        // is present. A classifier that panics if called proves the bypass.
        let snapshot = snapshot();
        let panicking_classifier = |_: &AttackAction| -> DefenseInteractionClass {
            panic!("disabled policy classified an action")
        };

        let halt = {
            let first = DefenseState::observe(403, &[], "forbidden");
            let second = DefenseState::observe(406, &[], "not acceptable");
            ResourceDefenseSignal::aggregate(
                subject(),
                &[
                    ResourceDefenseObservation::new(&first, None, Vec::new()),
                    ResourceDefenseObservation::new(&second, None, Vec::new()),
                ],
            )
        };

        let plan = defense_aware_plan(
            DefensePlanningPolicy::disabled(),
            &planner(),
            &snapshot,
            &subject(),
            context(),
            &halt,
            panicking_classifier,
        )
        .unwrap();
        assert_eq!(plan, baseline_plan(&snapshot));
    }

    #[test]
    fn defense_suppression_is_not_recorded_as_execution_failure() {
        // A defense-suppressed action is a planning exclusion, not an execution
        // outcome: it appears only in `excluded` with the DefenseSuppressed
        // reason, and never as a plan step. Because it is never dispatched, it can
        // never be recorded as a failed execution, blocked request, or
        // verification failure. The reason is also distinct from an adaptive or
        // operator policy suppression, so downstream learning never conflates them.
        let snapshot = snapshot();
        let plan = plan_with(
            &snapshot,
            DefensePlanningPolicy::enabled(),
            &backoff_signal(subject()),
        );

        let suppressed: Vec<String> = plan
            .excluded()
            .iter()
            .filter(|excluded| excluded.reason() == &ExclusionReason::DefenseSuppressed)
            .map(|excluded| excluded.action_id().to_owned())
            .collect();
        assert!(suppressed.contains(&"active.verify".to_owned()));

        let steps = step_ids(&plan);
        for action_id in &suppressed {
            assert!(
                !steps.contains(action_id.as_str()),
                "{action_id} was suppressed yet reached a plan step"
            );
        }
        assert!(plan
            .excluded()
            .iter()
            .all(|excluded| excluded.reason() != &ExclusionReason::PolicySuppressed));
    }
}
