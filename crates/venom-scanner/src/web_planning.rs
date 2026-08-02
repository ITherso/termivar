//! Standard planner actions driven by web reasoning hypotheses.
//!
//! The profile declares executor-routable candidates and utility metadata. It
//! never performs network I/O and remains opt-in for every host application.

use std::collections::BTreeSet;

use serde::Serialize;
use thiserror::Error;
use venom_core::{
    EvidenceValue, PredicateDescriptor, Probability, ReasoningModelError, WebKnowledgePredicate,
};

use crate::{
    planner::{
        ActionCost, AttackAction, AttackPlanner, BenefitScore, HypothesisSelector, PlannerError,
        PlannerWrite, RequiredStrength, RiskScore,
    },
    rules::{Expression, KnowledgeLayer},
};

pub use crate::web_actions::{
    StandardWebActionKind, STANDARD_WEB_ACTION_COUNT, STANDARD_WEB_DISCOVERY_ACTIONS,
    STANDARD_WEB_DISCOVERY_ACTION_COUNT,
};

/// Failures while constructing or installing the standard action profile.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StandardWebPlanningError {
    /// A reasoning value used by an action selector was invalid.
    #[error(transparent)]
    Reasoning(#[from] ReasoningModelError),

    /// An action definition or planner identity conflicted.
    #[error(transparent)]
    Planner(#[from] PlannerError),
}

/// Count of new actions written by an idempotent profile installation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct StandardWebAttackInstallReport {
    actions_inserted: usize,
}

impl StandardWebAttackInstallReport {
    /// Returns the number of newly registered action identities.
    pub fn actions_inserted(self) -> usize {
        self.actions_inserted
    }
}

/// Validated utility-planner actions for the standard web reasoning profile.
///
/// Hosts must register the executor IDs returned by
/// [`StandardWebActionKind::executor_id`] before a selected command is handed
/// to the decision runner. Keeping executor ownership outside this profile
/// preserves the planner/execution boundary.
///
/// # Examples
///
/// ```rust
/// use venom_scanner::{AttackPlanner, StandardWebAttackProfile};
///
/// let profile = StandardWebAttackProfile::new()?;
/// let mut planner = AttackPlanner::new();
/// let installed = profile.install(&mut planner)?;
///
/// assert_eq!(installed.actions_inserted(), profile.actions().len());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct StandardWebAttackProfile {
    actions: Vec<AttackAction>,
}

impl StandardWebAttackProfile {
    /// Builds and validates every standard action definition.
    pub fn new() -> Result<Self, StandardWebPlanningError> {
        let actions = StandardWebActionKind::all()
            .into_iter()
            .map(build_action)
            .collect::<Result<Vec<_>, _>>()?;
        debug_assert_eq!(actions.len(), STANDARD_WEB_ACTION_COUNT);
        Ok(Self { actions })
    }

    /// Installs every action idempotently after preflighting identity conflicts.
    pub fn install(
        &self,
        planner: &mut AttackPlanner,
    ) -> Result<StandardWebAttackInstallReport, StandardWebPlanningError> {
        let mut prospective = planner.clone();
        let mut actions_inserted = 0;
        for action in &self.actions {
            actions_inserted += usize::from(matches!(
                prospective.register(action.clone())?,
                PlannerWrite::Inserted
            ));
        }
        *planner = prospective;
        Ok(StandardWebAttackInstallReport { actions_inserted })
    }

    /// Returns actions in stable declaration order.
    pub fn actions(&self) -> &[AttackAction] {
        &self.actions
    }

    /// Returns the distinct executor identities required by this profile.
    pub fn executor_ids(&self) -> BTreeSet<&str> {
        self.actions.iter().map(AttackAction::executor).collect()
    }
}

struct ActionDefinition {
    predicate: PredicateDescriptor,
    value: &'static str,
    minimum_posterior: u8,
    required_strength: RequiredStrength,
    gain: u8,
    cost: u32,
    risk: u8,
    prerequisites: &'static [StandardWebActionKind],
}

fn build_action(kind: StandardWebActionKind) -> Result<AttackAction, StandardWebPlanningError> {
    let definition = action_definition(kind);
    let predicate = definition.predicate.into_knowledge();
    let value = EvidenceValue::Text(definition.value.to_owned());
    let prerequisites = definition
        .prerequisites
        .iter()
        .map(|kind| kind.action_id().to_owned())
        .collect();
    Ok(AttackAction::new(
        kind.action_id(),
        kind.executor_id(),
        Expression::equals(KnowledgeLayer::Hypothesis, predicate.clone(), value.clone()),
        HypothesisSelector::new(
            predicate,
            value,
            Probability::from_percent(definition.minimum_posterior)?,
            definition.required_strength,
        ),
        BenefitScore::from_percent(definition.gain)?,
        ActionCost::new(definition.cost)?,
        RiskScore::from_percent(definition.risk)?,
        prerequisites,
    )?)
}

fn action_definition(kind: StandardWebActionKind) -> ActionDefinition {
    match kind {
        StandardWebActionKind::NginxConfiguration => ActionDefinition {
            predicate: WebKnowledgePredicate::TECHNOLOGY_WEB_SERVER,
            value: "nginx",
            minimum_posterior: 70,
            required_strength: RequiredStrength::Any,
            gain: 55,
            cost: 20,
            risk: 8,
            prerequisites: &[],
        },
        StandardWebActionKind::ApacheConfiguration => ActionDefinition {
            predicate: WebKnowledgePredicate::TECHNOLOGY_WEB_SERVER,
            value: "apache-http-server",
            minimum_posterior: 70,
            required_strength: RequiredStrength::Any,
            gain: 55,
            cost: 20,
            risk: 8,
            prerequisites: &[],
        },
        StandardWebActionKind::PhpInputDiscovery => ActionDefinition {
            predicate: WebKnowledgePredicate::TECHNOLOGY_LANGUAGE,
            value: "php",
            minimum_posterior: 70,
            required_strength: RequiredStrength::Any,
            gain: 65,
            cost: 35,
            risk: 12,
            prerequisites: &[],
        },
        StandardWebActionKind::LaravelRouteDiscovery => ActionDefinition {
            predicate: WebKnowledgePredicate::TECHNOLOGY_FRAMEWORK,
            value: "laravel",
            minimum_posterior: 80,
            required_strength: RequiredStrength::Strong,
            gain: 70,
            cost: 40,
            risk: 10,
            prerequisites: &[],
        },
        StandardWebActionKind::LaravelInputAnalysis => ActionDefinition {
            predicate: WebKnowledgePredicate::TECHNOLOGY_FRAMEWORK,
            value: "laravel",
            minimum_posterior: 80,
            required_strength: RequiredStrength::Strong,
            gain: 95,
            cost: 35,
            risk: 15,
            prerequisites: &[StandardWebActionKind::LaravelRouteDiscovery],
        },
        StandardWebActionKind::LivewireComponentDiscovery => ActionDefinition {
            predicate: WebKnowledgePredicate::TECHNOLOGY_UI_FRAMEWORK,
            value: "livewire",
            minimum_posterior: 60,
            required_strength: RequiredStrength::Any,
            gain: 90,
            cost: 35,
            risk: 15,
            prerequisites: &[],
        },
        StandardWebActionKind::SanctumAuthBoundary => ActionDefinition {
            predicate: WebKnowledgePredicate::AUTHENTICATION_MECHANISM,
            value: "sanctum",
            minimum_posterior: 50,
            required_strength: RequiredStrength::Any,
            gain: 95,
            cost: 60,
            risk: 35,
            prerequisites: &[],
        },
        StandardWebActionKind::HttpBasicAuthBoundary => ActionDefinition {
            predicate: WebKnowledgePredicate::AUTHENTICATION_MECHANISM,
            value: "http-basic",
            minimum_posterior: 90,
            required_strength: RequiredStrength::Strong,
            gain: 75,
            cost: 25,
            risk: 20,
            prerequisites: &[],
        },
        StandardWebActionKind::HttpBearerAuthBoundary => ActionDefinition {
            predicate: WebKnowledgePredicate::AUTHENTICATION_MECHANISM,
            value: "http-bearer",
            minimum_posterior: 90,
            required_strength: RequiredStrength::Strong,
            gain: 90,
            cost: 35,
            risk: 25,
            prerequisites: &[],
        },
    }
}

#[cfg(test)]
mod tests {
    use venom_core::{
        ConfidenceScore, EntityId, Evidence, EvidenceKind, EvidenceSource, Hypothesis,
        HypothesisState, HypothesisStrength, KnowledgePredicate,
    };

    use super::*;
    #[cfg(feature = "scanning")]
    use crate::{
        AdaptationLimits, DecisionLoop, DecisionLoopCommand, DecisionLoopConfig, DecisionSession,
        ExperiencePolicy, ExperienceStore,
    };
    use crate::{ExclusionReason, KnowledgeBase, PlanningContext, StandardWebReasoning};

    fn subject() -> EntityId {
        EntityId::new("endpoint:https://example.test").unwrap()
    }

    fn evidence(namespace: &str, name: &str, value: &str) -> Evidence {
        Evidence::new(
            subject(),
            EvidenceKind::Technology,
            KnowledgePredicate::new(namespace, name).unwrap(),
            EvidenceValue::Text(value.to_owned()),
            EvidenceSource::new("http.evidence", "test-observation").unwrap(),
            ConfidenceScore::MAX,
        )
    }

    fn planning_context(budget: u64, maximum_risk: u8) -> PlanningContext {
        PlanningContext::new(
            BenefitScore::from_percent(90).unwrap(),
            budget,
            RiskScore::from_percent(maximum_risk).unwrap(),
        )
    }

    fn reason(knowledge: &KnowledgeBase) -> (crate::RuleEngine, AttackPlanner) {
        let mut rules = crate::RuleEngine::new();
        StandardWebReasoning::new()
            .unwrap()
            .install(knowledge, &mut rules)
            .unwrap();
        rules.apply(knowledge, &subject()).unwrap();
        let mut planner = AttackPlanner::new();
        StandardWebAttackProfile::new()
            .unwrap()
            .install(&mut planner)
            .unwrap();
        (rules, planner)
    }

    #[test]
    fn profile_installs_idempotently_with_distinct_executor_contracts() {
        let profile = StandardWebAttackProfile::new().unwrap();
        let mut planner = AttackPlanner::new();

        let first = profile.install(&mut planner).unwrap();
        let second = profile.install(&mut planner).unwrap();

        assert_eq!(first.actions_inserted(), STANDARD_WEB_ACTION_COUNT);
        assert_eq!(second, StandardWebAttackInstallReport::default());
        assert_eq!(planner.len(), STANDARD_WEB_ACTION_COUNT);
        assert_eq!(profile.executor_ids().len(), STANDARD_WEB_ACTION_COUNT);
        assert_eq!(
            StandardWebActionKind::LaravelRouteDiscovery.executor_id(),
            "web.probe.laravel-routes"
        );
    }

    #[test]
    fn laravel_and_sanctum_hypotheses_produce_dependency_safe_plan() {
        let knowledge = KnowledgeBase::new();
        knowledge
            .insert_evidence_batch(vec![
                evidence("http.cookie", "name", "laravel_session"),
                evidence("http.cookie", "name", "XSRF-TOKEN"),
            ])
            .unwrap();
        let (_, planner) = reason(&knowledge);

        let plan = planner
            .plan(&knowledge, &subject(), planning_context(200, 100))
            .unwrap();
        let selected: Vec<_> = plan.steps().iter().map(|step| step.action_id()).collect();

        assert_eq!(
            selected,
            vec![
                StandardWebActionKind::LaravelRouteDiscovery.action_id(),
                StandardWebActionKind::LaravelInputAnalysis.action_id(),
                StandardWebActionKind::SanctumAuthBoundary.action_id(),
            ]
        );
        assert_eq!(
            plan.steps()[0].executor(),
            StandardWebActionKind::LaravelRouteDiscovery.executor_id()
        );
        assert!(plan.steps()[1]
            .prerequisites()
            .contains(StandardWebActionKind::LaravelRouteDiscovery.action_id()));
        assert_eq!(
            plan.steps()[0].utility().confidence(),
            plan.steps()[1].utility().confidence()
        );
    }

    #[test]
    fn low_risk_and_budget_policies_explain_exclusions() {
        let knowledge = KnowledgeBase::new();
        knowledge
            .insert_evidence_batch(vec![
                evidence("http.cookie", "name", "laravel_session"),
                evidence("http.cookie", "name", "XSRF-TOKEN"),
            ])
            .unwrap();
        let (_, planner) = reason(&knowledge);

        let plan = planner
            .plan(&knowledge, &subject(), planning_context(60, 30))
            .unwrap();
        let sanctum = plan
            .excluded()
            .iter()
            .find(|item| item.action_id() == StandardWebActionKind::SanctumAuthBoundary.action_id())
            .unwrap();
        let input = plan
            .excluded()
            .iter()
            .find(|item| {
                item.action_id() == StandardWebActionKind::LaravelInputAnalysis.action_id()
            })
            .unwrap();

        assert!(matches!(
            sanctum.reason(),
            ExclusionReason::RiskLimitExceeded { .. }
        ));
        assert!(matches!(
            input.reason(),
            ExclusionReason::BudgetExceeded { .. }
        ));
        assert_eq!(
            plan.steps()[0].action_id(),
            StandardWebActionKind::LaravelRouteDiscovery.action_id()
        );
    }

    #[test]
    fn unrelated_stack_does_not_activate_framework_or_auth_actions() {
        let knowledge = KnowledgeBase::new();
        knowledge
            .insert_evidence(evidence("http.header", "server", "nginx/1.26"))
            .unwrap();
        let (_, planner) = reason(&knowledge);

        let plan = planner
            .plan(&knowledge, &subject(), planning_context(200, 100))
            .unwrap();

        assert_eq!(plan.steps().len(), 1);
        assert_eq!(
            plan.steps()[0].action_id(),
            StandardWebActionKind::NginxConfiguration.action_id()
        );
        assert!(plan
            .excluded()
            .iter()
            .all(|item| matches!(item.reason(), ExclusionReason::RequirementsNotMet)));
    }

    #[test]
    fn weak_laravel_claim_cannot_unlock_strong_actions() {
        let knowledge = KnowledgeBase::new();
        let mut weak = Hypothesis::with_id(
            "manual:weak-laravel",
            subject(),
            KnowledgePredicate::new("technology", "framework").unwrap(),
            EvidenceValue::Text("laravel".to_owned()),
            Probability::from_percent(90).unwrap(),
        )
        .unwrap();
        weak.set_strength(HypothesisStrength::Weak);
        weak.set_state(HypothesisState::Supported);
        knowledge.upsert_hypothesis(weak).unwrap();
        let mut planner = AttackPlanner::new();
        StandardWebAttackProfile::new()
            .unwrap()
            .install(&mut planner)
            .unwrap();

        let plan = planner
            .plan(&knowledge, &subject(), planning_context(200, 100))
            .unwrap();

        assert!(plan.steps().is_empty());
        for kind in [
            StandardWebActionKind::LaravelRouteDiscovery,
            StandardWebActionKind::LaravelInputAnalysis,
        ] {
            assert!(matches!(
                plan.excluded()
                    .iter()
                    .find(|item| item.action_id() == kind.action_id())
                    .unwrap()
                    .reason(),
                ExclusionReason::NoEligibleHypothesis
            ));
        }
    }

    #[test]
    #[cfg(feature = "scanning")]
    fn decision_loop_emits_executor_selected_from_reasoning() {
        let knowledge = KnowledgeBase::new();
        knowledge
            .insert_evidence_batch(vec![
                evidence("http.cookie", "name", "laravel_session"),
                evidence("http.cookie", "name", "XSRF-TOKEN"),
            ])
            .unwrap();
        let config = DecisionLoopConfig::new(
            planning_context(200, 100),
            AdaptationLimits::default(),
            ExperiencePolicy::new(3).unwrap(),
            8,
        )
        .unwrap();
        let mut decision_loop = DecisionLoop::new(config);
        StandardWebReasoning::new()
            .unwrap()
            .install(&knowledge, decision_loop.rules_mut())
            .unwrap();
        StandardWebAttackProfile::new()
            .unwrap()
            .install(decision_loop.planner_mut())
            .unwrap();
        let experience = ExperienceStore::new();
        let mut session = DecisionSession::new(subject());

        let report = decision_loop
            .plan_next(&knowledge, &experience, &mut session)
            .unwrap();

        assert_eq!(
            report.rule_applications().len(),
            crate::STANDARD_WEB_RULE_COUNT
        );
        assert!(matches!(
            report.command(),
            DecisionLoopCommand::ExecuteAction {
                executor: Some(executor),
                ..
            } if executor == StandardWebActionKind::LaravelRouteDiscovery.executor_id()
        ));
        assert_eq!(
            report.plan().steps()[0].action_id(),
            StandardWebActionKind::LaravelRouteDiscovery.action_id()
        );
    }
}
