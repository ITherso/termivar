//! Side-effect-free, defense-aware shadow planning.
//!
//! This layer shows how the current plan *would* change under an observed
//! defensive posture, without changing anything. It filters one already
//! authorized plan into a dependency-safe subsequence and computes an
//! explainable delta against the current plan. It never issues a
//! request, mutates the planner, runtime, knowledge, or experience state, or
//! reorders the real plan.
//!
//! Defense evidence is not a second planner: it never adds an action and never
//! raises an action's utility. For each *existing* candidate it only decides to
//! allow, deprioritize, or suppress. The per-observation recommendation is the
//! existing [`recommend`] policy — this module reuses it and adds only the
//! resource-scoped aggregation and the monotonic class mapping.

use std::collections::{BTreeMap, BTreeSet};

use venom_core::{EntityId, EvidenceId};

use crate::knowledge::KnowledgeSnapshot;
use crate::planner::{AttackAction, AttackPlan, AttackPlanner, PlannerError, PlanningContext};

use super::policy::{recommend, DefenseResponse};
use super::state::DefenseState;
use super::transition::DefenseTransition;

/// Closed classification of how an action interacts with a target.
///
/// The suppression layer classifies actions through this typed metadata, never
/// through action-id or name string matching. The caller supplies the mapping
/// because only the host knows what each of its actions does; this module owns
/// the exhaustive class-to-decision mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DefenseInteractionClass {
    /// Local analysis, reporting, audit, or human review — no network I/O.
    LocalOnly,
    /// Passive discovery that reads without probing behavior.
    Passive,
    /// Behavioral observation of the target.
    Behavioral,
    /// A differential read comparing two views of the same resource.
    DifferentialRead,
    /// An explicit active verification probe.
    ActiveVerification,
    /// A mutating or fuzzing interaction.
    Mutating,
}

/// What defense recommends doing with one existing candidate.
///
/// Ordering is meaningful: a more restrictive decision is greater.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InteractionDecision {
    /// Keep the action unchanged.
    Allow,
    /// Keep the action but lower its priority (a soft, advisory signal).
    Deprioritize,
    /// Remove the action from the shadow plan.
    Suppress,
}

/// The monotonic, exhaustive mapping from a recommendation and an interaction
/// class to a decision. This is the single place the mapping lives.
///
/// Monotonicity: for a fixed class, the decision never weakens as the
/// recommendation escalates `Proceed < Observe < Backoff < Reconsider < Halt`.
/// Defense never allows less than the response requires and never adds work.
pub const fn decide(
    response: DefenseResponse,
    class: DefenseInteractionClass,
) -> InteractionDecision {
    use DefenseInteractionClass::{
        ActiveVerification, Behavioral, DifferentialRead, LocalOnly, Mutating, Passive,
    };
    use DefenseResponse::{Backoff, Halt, Observe, Proceed, Reconsider};
    use InteractionDecision::{Allow, Deprioritize, Suppress};

    match (response, class) {
        (Proceed, _) => Allow,
        (_, LocalOnly) => Allow,

        (Observe, ActiveVerification | Mutating) => Deprioritize,
        (Observe, _) => Allow,

        (Backoff, ActiveVerification | Mutating) => Suppress,
        (Backoff, DifferentialRead) => Deprioritize,
        (Backoff, _) => Allow,

        (Reconsider, ActiveVerification | Mutating) => Suppress,
        (Reconsider, Behavioral | DifferentialRead) => Deprioritize,
        (Reconsider, Passive) => Allow,

        // Halt suppresses every network-producing class; LocalOnly handled above.
        (Halt, _) => Suppress,
    }
}

/// A stable, replay-safe explanation code for one decision.
///
/// Codes are stable identifiers, not free text; [`render_explanation`] maps them
/// to human-readable prose.
pub const fn explanation_code(
    response: DefenseResponse,
    decision: InteractionDecision,
) -> &'static str {
    use DefenseResponse::{Backoff, Halt, Observe, Reconsider};
    use InteractionDecision::{Deprioritize, Suppress};

    match (response, decision) {
        (Observe, Deprioritize) => "defense.observe.deprioritize",
        (Backoff, Deprioritize) => "defense.backoff.deprioritize",
        (Backoff, Suppress) => "defense.backoff.suppress",
        (Reconsider, Deprioritize) => "defense.reconsider.deprioritize",
        (Reconsider, Suppress) => "defense.reconsider.suppress",
        (Halt, Suppress) => "defense.halt.suppress",
        _ => "defense.none",
    }
}

/// Renders a stable explanation code as human-readable prose.
pub fn render_explanation(code: &str) -> &'static str {
    match code {
        "defense.observe.deprioritize" => {
            "defensive infrastructure was observed; active work is deprioritized"
        },
        "defense.backoff.deprioritize" => {
            "rate limiting is in effect; differential reads are deprioritized"
        },
        "defense.backoff.suppress" => {
            "rate limiting is in effect; active verification and mutation are suppressed"
        },
        "defense.reconsider.deprioritize" => {
            "the candidate provoked a block; behavioral and differential work is deprioritized"
        },
        "defense.reconsider.suppress" => {
            "the candidate provoked a block; active verification and mutation are suppressed"
        },
        "defense.halt.suppress" => {
            "a standing block or challenge halts all network-producing actions"
        },
        "defense.dependency.suppress" => {
            "an action was suppressed because a required prerequisite was removed"
        },
        _ => "no defensive adjustment",
    }
}

/// One observed response leg for a resource, with its supporting evidence.
#[derive(Debug, Clone)]
pub struct ResourceDefenseObservation<'obs> {
    state: &'obs DefenseState,
    transition: Option<&'obs DefenseTransition>,
    evidence_ids: Vec<EvidenceId>,
}

impl<'obs> ResourceDefenseObservation<'obs> {
    /// Records one observation and the evidence ids that support it.
    pub fn new(
        state: &'obs DefenseState,
        transition: Option<&'obs DefenseTransition>,
        evidence_ids: Vec<EvidenceId>,
    ) -> Self {
        Self {
            state,
            transition,
            evidence_ids,
        }
    }
}

/// A resource-scoped, corroborated defense signal.
///
/// The response is the aggregate of the per-observation [`recommend`] policy,
/// with one corroboration rule: a single standing-block recommendation is not
/// enough to halt, so an uncorroborated `Halt` is treated as `Observe`.
/// Rate-limit `Backoff` and transition-driven `Reconsider` are self-corroborated
/// and honored as-is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceDefenseSignal {
    resource: EntityId,
    response: DefenseResponse,
    supporting_evidence_ids: Vec<EvidenceId>,
}

impl ResourceDefenseSignal {
    /// A neutral signal that recommends proceeding.
    pub fn proceed(resource: EntityId) -> Self {
        Self {
            resource,
            response: DefenseResponse::Proceed,
            supporting_evidence_ids: Vec::new(),
        }
    }

    /// Aggregates the observations for one resource into a single signal.
    ///
    /// Aggregation is order-independent: the response is the maximum of the
    /// corroborated per-observation recommendations, and the evidence set is
    /// sorted and de-duplicated.
    pub fn aggregate(resource: EntityId, observations: &[ResourceDefenseObservation<'_>]) -> Self {
        let mut responses = Vec::with_capacity(observations.len());
        let mut evidence_ids = Vec::new();
        for observation in observations {
            responses.push(recommend(observation.state, observation.transition));
            evidence_ids.extend(observation.evidence_ids.iter().cloned());
        }

        let standing_blocks = responses
            .iter()
            .filter(|response| **response == DefenseResponse::Halt)
            .count();
        let response = responses
            .iter()
            .map(|response| downgrade_uncorroborated_halt(*response, standing_blocks))
            .max()
            .unwrap_or(DefenseResponse::Proceed);

        evidence_ids.sort();
        evidence_ids.dedup();

        Self {
            resource,
            response,
            supporting_evidence_ids: evidence_ids,
        }
    }

    /// Returns the resource this signal is scoped to.
    pub fn resource(&self) -> &EntityId {
        &self.resource
    }

    /// Returns the aggregated recommendation.
    pub const fn response(&self) -> DefenseResponse {
        self.response
    }

    /// Returns the sorted, de-duplicated supporting evidence ids.
    pub fn supporting_evidence_ids(&self) -> &[EvidenceId] {
        &self.supporting_evidence_ids
    }
}

/// A single standing-block recommendation is not enough to halt; it needs at
/// least two corroborating observations. An uncorroborated `Halt` is treated as
/// `Observe`. `Backoff` (rate limit) and `Reconsider` (transition) are
/// self-corroborated and pass through unchanged.
const fn downgrade_uncorroborated_halt(
    response: DefenseResponse,
    standing_blocks: usize,
) -> DefenseResponse {
    match response {
        DefenseResponse::Halt if standing_blocks < 2 => DefenseResponse::Observe,
        other => other,
    }
}

/// One action kept but deprioritized in the shadow plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanAdjustment {
    action_id: String,
    interaction_class: DefenseInteractionClass,
    recommendation: DefenseResponse,
    supporting_evidence_ids: Vec<EvidenceId>,
    explanation_code: &'static str,
}

/// One action removed from the shadow plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuppressedAction {
    action_id: String,
    interaction_class: DefenseInteractionClass,
    recommendation: DefenseResponse,
    supporting_evidence_ids: Vec<EvidenceId>,
    explanation_code: &'static str,
}

macro_rules! adjustment_accessors {
    ($ty:ty) => {
        impl $ty {
            /// Returns the affected action identity.
            pub fn action_id(&self) -> &str {
                &self.action_id
            }

            /// Returns the action's interaction class.
            pub const fn interaction_class(&self) -> DefenseInteractionClass {
                self.interaction_class
            }

            /// Returns the recommendation that drove the decision.
            pub const fn recommendation(&self) -> DefenseResponse {
                self.recommendation
            }

            /// Returns the evidence ids supporting the decision.
            pub fn supporting_evidence_ids(&self) -> &[EvidenceId] {
                &self.supporting_evidence_ids
            }

            /// Returns the stable explanation code.
            pub const fn explanation_code(&self) -> &'static str {
                self.explanation_code
            }
        }
    };
}

adjustment_accessors!(PlanAdjustment);
adjustment_accessors!(SuppressedAction);

/// The explainable difference the defense signal makes to the current plan.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ShadowPlanDelta {
    unchanged: Vec<String>,
    deprioritized: Vec<PlanAdjustment>,
    suppressed: Vec<SuppressedAction>,
}

impl ShadowPlanDelta {
    /// Returns the current-plan actions left unchanged.
    pub fn unchanged(&self) -> &[String] {
        &self.unchanged
    }

    /// Returns the current-plan actions kept but deprioritized.
    pub fn deprioritized(&self) -> &[PlanAdjustment] {
        &self.deprioritized
    }

    /// Returns the current-plan actions removed from the shadow plan.
    pub fn suppressed(&self) -> &[SuppressedAction] {
        &self.suppressed
    }

    /// Returns whether the signal changed nothing (no suppression or
    /// deprioritization).
    pub fn is_empty(&self) -> bool {
        self.deprioritized.is_empty() && self.suppressed.is_empty()
    }
}

/// The current plan, the defense-aware shadow plan, and the delta between them.
#[derive(Debug, Clone)]
pub struct DefenseAwareShadowPlan {
    current: AttackPlan,
    shadow: AttackPlan,
    delta: ShadowPlanDelta,
}

impl DefenseAwareShadowPlan {
    /// Returns the real current plan (never mutated by this module).
    pub const fn current(&self) -> &AttackPlan {
        &self.current
    }

    /// Returns the read-only, defense-aware shadow plan.
    pub const fn shadow(&self) -> &AttackPlan {
        &self.shadow
    }

    /// Returns the explainable delta.
    pub const fn delta(&self) -> &ShadowPlanDelta {
        &self.delta
    }
}

/// Computes the current plan, a defense-aware shadow plan, and their delta.
///
/// This is pure and side-effect-free: it uses the planner's read-only snapshot
/// seam, issues no request, and mutates no planner, runtime, knowledge, or
/// experience state. The signal applies only when it is scoped to `subject` and
/// recommends more than `Proceed`; otherwise the shadow plan equals the current
/// plan and the delta is empty. The shadow plan is always an order-preserving,
/// dependency-safe subsequence — it never replans or introduces a new action.
pub fn defense_aware_shadow_plan(
    planner: &AttackPlanner,
    snapshot: &KnowledgeSnapshot,
    subject: &EntityId,
    context: PlanningContext,
    signal: &ResourceDefenseSignal,
    classify: impl Fn(&AttackAction) -> DefenseInteractionClass,
) -> Result<DefenseAwareShadowPlan, PlannerError> {
    let current = planner.plan_snapshot(snapshot, context)?;
    if current.subject() != subject {
        return Ok(DefenseAwareShadowPlan {
            shadow: current.clone(),
            current,
            delta: ShadowPlanDelta::default(),
        });
    }

    Ok(defense_aware_shadow_plan_from_current(
        current, planner, signal, classify,
    ))
}

/// Filters an already-authorized plan into its defense-aware shadow.
///
/// Keeping this seam separate is important for runtime composition: a host can
/// pass the exact plan already recorded in its planning report rather than ask
/// the planner to reproduce a decision from potentially different context.
/// The returned shadow is therefore always a subsequence of `current`.
pub(crate) fn defense_aware_shadow_plan_from_current(
    current: AttackPlan,
    planner: &AttackPlanner,
    signal: &ResourceDefenseSignal,
    classify: impl Fn(&AttackAction) -> DefenseInteractionClass,
) -> DefenseAwareShadowPlan {
    let subject = current.subject();

    let applies = signal.resource == *subject && signal.response != DefenseResponse::Proceed;

    let mut class_by_action: BTreeMap<String, DefenseInteractionClass> = BTreeMap::new();
    let mut suppressed_ids: BTreeSet<String> = BTreeSet::new();
    if applies {
        let candidate_ids = current
            .steps()
            .iter()
            .map(|step| step.action_id().to_owned());
        for action_id in candidate_ids {
            if let Some(action) = planner.action(&action_id) {
                let class = classify(action);
                class_by_action.insert(action_id.clone(), class);
                if decide(signal.response, class) == InteractionDecision::Suppress {
                    suppressed_ids.insert(action_id);
                }
            }
        }
    }

    let shadow = current.clone().into_defense_filtered(&suppressed_ids);
    let delta = build_delta(&current, &shadow, &class_by_action, signal);

    DefenseAwareShadowPlan {
        current,
        shadow,
        delta,
    }
}

fn build_delta(
    current: &AttackPlan,
    shadow: &AttackPlan,
    class_by_action: &BTreeMap<String, DefenseInteractionClass>,
    signal: &ResourceDefenseSignal,
) -> ShadowPlanDelta {
    let mut delta = ShadowPlanDelta::default();
    let retained: BTreeSet<_> = shadow.steps().iter().map(|step| step.action_id()).collect();
    for step in current.steps() {
        let action_id = step.action_id();
        let Some(class) = class_by_action.get(action_id).copied() else {
            delta.unchanged.push(action_id.to_owned());
            continue;
        };
        let decision = decide(signal.response, class);
        if !retained.contains(action_id) {
            delta.suppressed.push(SuppressedAction {
                action_id: action_id.to_owned(),
                interaction_class: class,
                recommendation: signal.response,
                supporting_evidence_ids: signal.supporting_evidence_ids.clone(),
                explanation_code: if decision == InteractionDecision::Suppress {
                    explanation_code(signal.response, decision)
                } else {
                    "defense.dependency.suppress"
                },
            });
            continue;
        }
        match decision {
            InteractionDecision::Allow => delta.unchanged.push(action_id.to_owned()),
            InteractionDecision::Deprioritize => delta.deprioritized.push(PlanAdjustment {
                action_id: action_id.to_owned(),
                interaction_class: class,
                recommendation: signal.response,
                supporting_evidence_ids: signal.supporting_evidence_ids.clone(),
                explanation_code: explanation_code(
                    signal.response,
                    InteractionDecision::Deprioritize,
                ),
            }),
            InteractionDecision::Suppress => delta.suppressed.push(SuppressedAction {
                action_id: action_id.to_owned(),
                interaction_class: class,
                recommendation: signal.response,
                supporting_evidence_ids: signal.supporting_evidence_ids.clone(),
                explanation_code: explanation_code(signal.response, InteractionDecision::Suppress),
            }),
        }
    }
    delta
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use venom_core::{
        BayesianEvidence, ConfidenceScore, Evidence, EvidenceKind, EvidenceSource, EvidenceValue,
        Hypothesis, HypothesisState, HypothesisStrength, KnowledgePredicate, Probability,
    };

    use super::*;
    use crate::knowledge::KnowledgeBase;
    use crate::planner::{
        ActionCost, BenefitScore, HypothesisSelector, RequiredStrength, RiskScore,
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

    fn class_of(id: &str) -> DefenseInteractionClass {
        // The host classifies its own actions; the library never string-matches.
        match id {
            "local.report" => DefenseInteractionClass::LocalOnly,
            "passive.discovery" => DefenseInteractionClass::Passive,
            "behavioral.observe" => DefenseInteractionClass::Behavioral,
            "differential.read" => DefenseInteractionClass::DifferentialRead,
            "active.verify" => DefenseInteractionClass::ActiveVerification,
            "mutating.fuzz" => DefenseInteractionClass::Mutating,
            other => panic!("unclassified test action {other}"),
        }
    }

    fn classify(action: &AttackAction) -> DefenseInteractionClass {
        class_of(action.id())
    }

    fn full_planner() -> AttackPlanner {
        let mut planner = AttackPlanner::new();
        planner.register(action("local.report", 60)).unwrap();
        planner.register(action("passive.discovery", 58)).unwrap();
        planner.register(action("behavioral.observe", 56)).unwrap();
        planner.register(action("differential.read", 54)).unwrap();
        planner.register(action("active.verify", 52)).unwrap();
        planner.register(action("mutating.fuzz", 50)).unwrap();
        planner
    }

    fn context() -> PlanningContext {
        PlanningContext::new(
            BenefitScore::from_percent(90).unwrap(),
            1_000,
            RiskScore::from_percent(80).unwrap(),
        )
    }

    fn evidence_id(value: &str) -> EvidenceId {
        EvidenceId::parse(value).unwrap()
    }

    fn signal(
        resource: EntityId,
        response: DefenseResponse,
        evidence: &[&str],
    ) -> ResourceDefenseSignal {
        // A signal always carries sorted, de-duplicated evidence, exactly as
        // `aggregate` produces it.
        let mut supporting_evidence_ids: Vec<EvidenceId> =
            evidence.iter().map(|id| evidence_id(id)).collect();
        supporting_evidence_ids.sort();
        supporting_evidence_ids.dedup();
        ResourceDefenseSignal {
            resource,
            response,
            supporting_evidence_ids,
        }
    }

    fn shadow(signal: &ResourceDefenseSignal) -> DefenseAwareShadowPlan {
        let knowledge = knowledge_with_hypothesis();
        let snapshot = knowledge.snapshot_for_subject(&subject());
        defense_aware_shadow_plan(
            &full_planner(),
            &snapshot,
            &subject(),
            context(),
            signal,
            classify,
        )
        .unwrap()
    }

    fn suppressed_ids(plan: &DefenseAwareShadowPlan) -> BTreeSet<&str> {
        plan.delta()
            .suppressed()
            .iter()
            .map(SuppressedAction::action_id)
            .collect()
    }

    fn deprioritized_ids(plan: &DefenseAwareShadowPlan) -> BTreeSet<&str> {
        plan.delta()
            .deprioritized()
            .iter()
            .map(PlanAdjustment::action_id)
            .collect()
    }

    fn shadow_step_ids(plan: &DefenseAwareShadowPlan) -> BTreeSet<&str> {
        plan.shadow()
            .steps()
            .iter()
            .map(|step| step.action_id())
            .collect()
    }

    #[test]
    fn decision_mapping_is_monotonic_per_class() {
        let responses = [
            DefenseResponse::Proceed,
            DefenseResponse::Observe,
            DefenseResponse::Backoff,
            DefenseResponse::Reconsider,
            DefenseResponse::Halt,
        ];
        for class in [
            DefenseInteractionClass::LocalOnly,
            DefenseInteractionClass::Passive,
            DefenseInteractionClass::Behavioral,
            DefenseInteractionClass::DifferentialRead,
            DefenseInteractionClass::ActiveVerification,
            DefenseInteractionClass::Mutating,
        ] {
            let mut previous = InteractionDecision::Allow;
            for response in responses {
                let decision = decide(response, class);
                assert!(
                    decision >= previous,
                    "decision weakened for {class:?} at {response:?}"
                );
                previous = decision;
            }
        }
        // Defense never suppresses local-only work.
        for response in responses {
            assert_eq!(
                decide(response, DefenseInteractionClass::LocalOnly),
                InteractionDecision::Allow
            );
        }
    }

    #[test]
    fn proceed_produces_zero_delta() {
        let plan = shadow(&signal(subject(), DefenseResponse::Proceed, &[]));
        assert!(plan.delta().is_empty());
        assert_eq!(shadow_step_ids(&plan), {
            let knowledge = knowledge_with_hypothesis();
            let snapshot = knowledge.snapshot_for_subject(&subject());
            full_planner()
                .plan_snapshot(&snapshot, context())
                .unwrap()
                .steps()
                .iter()
                .map(|step| step.action_id().to_owned())
                .collect::<BTreeSet<_>>()
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
        });
    }

    #[test]
    fn observe_never_suppresses_passive_actions() {
        let plan = shadow(&signal(subject(), DefenseResponse::Observe, &["e1"]));
        assert!(plan.delta().suppressed().is_empty());
        assert!(deprioritized_ids(&plan).contains("active.verify"));
        assert!(deprioritized_ids(&plan).contains("mutating.fuzz"));
        assert!(plan
            .delta()
            .unchanged()
            .contains(&"passive.discovery".to_owned()));
        assert!(plan
            .delta()
            .unchanged()
            .contains(&"local.report".to_owned()));
        // Nothing suppressed means the shadow plan keeps every step.
        assert!(shadow_step_ids(&plan).contains("active.verify"));
    }

    #[test]
    fn backoff_suppresses_active_but_preserves_local_analysis() {
        let plan = shadow(&signal(subject(), DefenseResponse::Backoff, &["e1"]));
        assert!(suppressed_ids(&plan).contains("active.verify"));
        assert!(suppressed_ids(&plan).contains("mutating.fuzz"));
        assert!(deprioritized_ids(&plan).contains("differential.read"));
        assert!(plan
            .delta()
            .unchanged()
            .contains(&"local.report".to_owned()));
        assert!(plan
            .delta()
            .unchanged()
            .contains(&"passive.discovery".to_owned()));
        // Suppressed actions leave the shadow plan; local analysis stays.
        assert!(!shadow_step_ids(&plan).contains("active.verify"));
        assert!(!shadow_step_ids(&plan).contains("mutating.fuzz"));
        assert!(shadow_step_ids(&plan).contains("local.report"));
    }

    #[test]
    fn halt_suppresses_network_actions_only() {
        let plan = shadow(&signal(subject(), DefenseResponse::Halt, &["e1"]));
        for network in [
            "passive.discovery",
            "behavioral.observe",
            "differential.read",
            "active.verify",
            "mutating.fuzz",
        ] {
            assert!(
                suppressed_ids(&plan).contains(network),
                "{network} not suppressed"
            );
            assert!(!shadow_step_ids(&plan).contains(network));
        }
        assert!(plan
            .delta()
            .unchanged()
            .contains(&"local.report".to_owned()));
        assert!(shadow_step_ids(&plan).contains("local.report"));
    }

    #[test]
    fn unrelated_resource_defense_does_not_change_plan() {
        // Defense observed on another resource must not touch this plan.
        let plan = shadow(&signal(other_subject(), DefenseResponse::Halt, &["e1"]));
        assert!(plan.delta().is_empty());
        assert!(shadow_step_ids(&plan).contains("active.verify"));
    }

    #[test]
    fn single_403_does_not_suppress_active_actions() {
        let state = DefenseState::observe(403, &[], "forbidden");
        let observation = ResourceDefenseObservation::new(&state, None, vec![evidence_id("e1")]);
        let aggregated = ResourceDefenseSignal::aggregate(subject(), &[observation]);
        // A single standing block is downgraded below suppression.
        assert_eq!(aggregated.response(), DefenseResponse::Observe);

        let plan = shadow(&aggregated);
        assert!(plan.delta().suppressed().is_empty());
        assert!(deprioritized_ids(&plan).contains("active.verify"));
    }

    #[test]
    fn repeated_standing_blocks_escalate_to_halt() {
        let first = DefenseState::observe(403, &[], "forbidden");
        let second = DefenseState::observe(406, &[], "not acceptable");
        let observations = [
            ResourceDefenseObservation::new(&first, None, vec![evidence_id("e1")]),
            ResourceDefenseObservation::new(&second, None, vec![evidence_id("e2")]),
        ];
        let aggregated = ResourceDefenseSignal::aggregate(subject(), &observations);
        assert_eq!(aggregated.response(), DefenseResponse::Halt);
    }

    #[test]
    fn timeout_does_not_change_shadow_plan() {
        // A non-response contributes no observation, so the signal is Proceed.
        let aggregated = ResourceDefenseSignal::aggregate(subject(), &[]);
        assert_eq!(aggregated.response(), DefenseResponse::Proceed);
        let plan = shadow(&aggregated);
        assert!(plan.delta().is_empty());
    }

    #[test]
    fn shadow_delta_references_supporting_evidence() {
        let plan = shadow(&signal(subject(), DefenseResponse::Backoff, &["e2", "e1"]));
        let expected: Vec<EvidenceId> = vec![evidence_id("e1"), evidence_id("e2")];
        let suppressed = plan
            .delta()
            .suppressed()
            .iter()
            .find(|item| item.action_id() == "active.verify")
            .expect("active.verify suppressed");
        assert_eq!(suppressed.supporting_evidence_ids(), expected.as_slice());
        assert_eq!(suppressed.explanation_code(), "defense.backoff.suppress");
        assert!(!render_explanation(suppressed.explanation_code()).is_empty());
    }

    #[test]
    fn shadow_planning_is_deterministic_under_evidence_ordering() {
        let rate_limited = DefenseState::observe(429, &[], "slow down");
        let fingerprinted = DefenseState::observe(200, &[("CF-RAY", "x")], "ok");
        let forward = [
            ResourceDefenseObservation::new(&rate_limited, None, vec![evidence_id("e1")]),
            ResourceDefenseObservation::new(&fingerprinted, None, vec![evidence_id("e2")]),
        ];
        let reversed = [
            ResourceDefenseObservation::new(&fingerprinted, None, vec![evidence_id("e2")]),
            ResourceDefenseObservation::new(&rate_limited, None, vec![evidence_id("e1")]),
        ];
        let a = ResourceDefenseSignal::aggregate(subject(), &forward);
        let b = ResourceDefenseSignal::aggregate(subject(), &reversed);
        assert_eq!(a, b);
        assert_eq!(shadow(&a).delta(), shadow(&b).delta());
    }

    #[test]
    fn shadow_planner_never_adds_actions_absent_from_current_candidates() {
        let knowledge = knowledge_with_hypothesis();
        let snapshot = knowledge.snapshot_for_subject(&subject());
        let planner = full_planner();
        let plan = defense_aware_shadow_plan(
            &planner,
            &snapshot,
            &subject(),
            context(),
            &signal(subject(), DefenseResponse::Reconsider, &["e1"]),
            classify,
        )
        .unwrap();

        let candidates: BTreeSet<&str> = plan
            .current()
            .steps()
            .iter()
            .map(|step| step.action_id())
            .chain(
                plan.current()
                    .excluded()
                    .iter()
                    .map(|excluded| excluded.action_id()),
            )
            .collect();
        for shadow_step in plan.shadow().steps() {
            assert!(
                candidates.contains(shadow_step.action_id()),
                "shadow introduced a non-candidate action {}",
                shadow_step.action_id()
            );
        }
    }

    #[test]
    fn shadow_from_current_never_refills_freed_budget() {
        let knowledge = knowledge_with_hypothesis();
        let snapshot = knowledge.snapshot_for_subject(&subject());
        let mut planner = AttackPlanner::new();
        planner.register(action("active.verify", 95)).unwrap();
        planner.register(action("local.report", 90)).unwrap();
        planner.register(action("passive.discovery", 80)).unwrap();
        let constrained = PlanningContext::new(
            BenefitScore::from_percent(90).unwrap(),
            20,
            RiskScore::from_percent(80).unwrap(),
        );
        let current = planner.plan_snapshot(&snapshot, constrained).unwrap();
        assert_eq!(
            current
                .steps()
                .iter()
                .map(|step| step.action_id())
                .collect::<Vec<_>>(),
            ["active.verify", "local.report"]
        );
        assert!(current
            .excluded()
            .iter()
            .any(|entry| entry.action_id() == "passive.discovery"));

        let result = defense_aware_shadow_plan_from_current(
            current.clone(),
            &planner,
            &signal(subject(), DefenseResponse::Backoff, &["e1"]),
            |action| {
                assert_ne!(
                    action.id(),
                    "passive.discovery",
                    "baseline-excluded action reached the defense classifier"
                );
                classify(action)
            },
        );

        assert_eq!(result.current(), &current);
        assert_eq!(
            result
                .shadow()
                .steps()
                .iter()
                .map(|step| step.action_id())
                .collect::<Vec<_>>(),
            ["local.report"]
        );
        assert!(!result
            .shadow()
            .steps()
            .iter()
            .any(|step| step.action_id() == "passive.discovery"));
    }
}
