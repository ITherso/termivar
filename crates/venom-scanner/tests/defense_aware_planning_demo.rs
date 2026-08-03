//! Deterministic, public-API demonstration of the defense-aware planning arc.
//!
//! One target, one fixed scenario, three plans shown side by side:
//!
//! 1. the current plan with enforcement **off** (the real plan today);
//! 2. the side-effect-free **shadow** plan and its explainable delta;
//! 3. the plan with enforcement **on**, where defense-suppressed actions are
//!    excluded with a distinct reason.
//!
//! The test renders a human-readable summary (visible with `--nocapture`) and
//! asserts the guarantees: the disabled plan is untouched, the shadow and the
//! enforced plan agree on what to suppress, and a suppressed action never becomes
//! a plan step — so it never reaches an executor.

use std::collections::BTreeSet;

use venom_core::{
    BayesianEvidence, ConfidenceScore, EntityId, Evidence, EvidenceId, EvidenceKind,
    EvidenceSource, EvidenceValue, Hypothesis, HypothesisState, HypothesisStrength,
    KnowledgePredicate, Probability,
};
use venom_scanner::defense::shadow_planning::render_explanation;
use venom_scanner::{
    defense_aware_plan, defense_aware_shadow_plan, ActionCost, AttackAction, AttackPlan,
    AttackPlanner, BenefitScore, DefenseAwareShadowPlan, DefenseInteractionClass,
    DefensePlanningPolicy, DefenseState, ExclusionReason, Expression, HypothesisSelector,
    KnowledgeBase, KnowledgeLayer, KnowledgeSnapshot, PlanningContext, RequiredStrength,
    ResourceDefenseObservation, ResourceDefenseSignal, RiskScore,
};

const TARGET: &str = "endpoint:https://example.test/api/admin";

fn subject() -> EntityId {
    EntityId::new(TARGET).unwrap()
}

fn stack_predicate() -> KnowledgePredicate {
    KnowledgePredicate::new("stack", "framework").unwrap()
}

fn stack_value() -> EvidenceValue {
    EvidenceValue::Text("Laravel".into())
}

/// A knowledge base holding one strong, supported framework hypothesis so the
/// discovery actions are eligible.
fn scenario_snapshot() -> (KnowledgeBase, KnowledgeSnapshot) {
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

    let snapshot = knowledge.snapshot_for_subject(&subject());
    (knowledge, snapshot)
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

fn planner() -> AttackPlanner {
    let mut planner = AttackPlanner::new();
    planner.register(action("local.report", 60)).unwrap();
    planner.register(action("passive.discovery", 58)).unwrap();
    planner.register(action("active.verify", 54)).unwrap();
    planner.register(action("mutating.fuzz", 52)).unwrap();
    planner
}

/// The host classifies its own actions through typed metadata; the defense
/// library never inspects action-id strings.
fn classify(action: &AttackAction) -> DefenseInteractionClass {
    match action.id() {
        "local.report" => DefenseInteractionClass::LocalOnly,
        "passive.discovery" => DefenseInteractionClass::Passive,
        "active.verify" => DefenseInteractionClass::ActiveVerification,
        "mutating.fuzz" => DefenseInteractionClass::Mutating,
        other => panic!("unclassified demo action {other}"),
    }
}

fn context() -> PlanningContext {
    PlanningContext::new(
        BenefitScore::from_percent(90).unwrap(),
        1_000,
        RiskScore::from_percent(80).unwrap(),
    )
}

/// A rate-limit response on the target, projected into a Backoff signal with two
/// supporting evidence ids.
fn rate_limit_signal() -> ResourceDefenseSignal {
    let state = DefenseState::observe(429, &[("Retry-After", "30")], "slow down");
    let evidence = vec![
        EvidenceId::parse("defense/status/e1").unwrap(),
        EvidenceId::parse("defense/rate-limit/e2").unwrap(),
    ];
    ResourceDefenseSignal::aggregate(
        subject(),
        &[ResourceDefenseObservation::new(&state, None, evidence)],
    )
}

fn step_ids(plan: &AttackPlan) -> Vec<&str> {
    plan.steps().iter().map(|step| step.action_id()).collect()
}

fn render(off: &AttackPlan, shadow: &DefenseAwareShadowPlan, on: &AttackPlan) -> String {
    let mut out = String::new();
    out.push_str("== Defense-aware planning demo ==\n");
    out.push_str(&format!("target: {TARGET}\n\n"));

    out.push_str("[1] enforcement OFF (real plan today):\n");
    for step in off.steps() {
        out.push_str(&format!("    {}. {}\n", step.position(), step.action_id()));
    }

    out.push_str("\n[2] shadow delta (side-effect-free):\n");
    for suppressed in shadow.delta().suppressed() {
        out.push_str(&format!(
            "    suppress {:<18} class={:?} rec={:?} why={} [{}] evidence={:?}\n",
            suppressed.action_id(),
            suppressed.interaction_class(),
            suppressed.recommendation(),
            render_explanation(suppressed.explanation_code()),
            suppressed.explanation_code(),
            suppressed
                .supporting_evidence_ids()
                .iter()
                .map(EvidenceId::as_str)
                .collect::<Vec<_>>(),
        ));
    }
    for adjustment in shadow.delta().deprioritized() {
        out.push_str(&format!(
            "    deprioritize {:<14} class={:?} why={}\n",
            adjustment.action_id(),
            adjustment.interaction_class(),
            render_explanation(adjustment.explanation_code()),
        ));
    }
    for unchanged in shadow.delta().unchanged() {
        out.push_str(&format!("    keep     {unchanged}\n"));
    }

    out.push_str("\n[3] enforcement ON (real plan under the flag):\n");
    for step in on.steps() {
        out.push_str(&format!("    {}. {}\n", step.position(), step.action_id()));
    }
    for excluded in on.excluded() {
        out.push_str(&format!(
            "    excluded {:<18} reason={:?}\n",
            excluded.action_id(),
            excluded.reason(),
        ));
    }
    out
}

#[test]
fn defense_aware_planning_arc_is_explainable_and_safe() {
    let (_knowledge, snapshot) = scenario_snapshot();
    let planner = planner();
    let signal = rate_limit_signal();

    // [1] Enforcement off: the real plan today.
    let off = defense_aware_plan(
        DefensePlanningPolicy::disabled(),
        &planner,
        &snapshot,
        &subject(),
        context(),
        &signal,
        classify,
    )
    .unwrap();

    // [2] The side-effect-free shadow and its explainable delta.
    let shadow = defense_aware_shadow_plan(
        &planner,
        &snapshot,
        &subject(),
        context(),
        &signal,
        classify,
    )
    .unwrap();

    // [3] Enforcement on: the real plan under the flag.
    let on = defense_aware_plan(
        DefensePlanningPolicy::enabled(),
        &planner,
        &snapshot,
        &subject(),
        context(),
        &signal,
        classify,
    )
    .unwrap();

    // Human-readable demonstration (see it with `--nocapture`).
    let rendered = render(&off, &shadow, &on);
    println!("{rendered}");

    // --- Guarantees ---------------------------------------------------------

    // Disabled enforcement leaves the plan untouched: all four candidates run.
    assert_eq!(
        step_ids(&off),
        [
            "local.report",
            "passive.discovery",
            "active.verify",
            "mutating.fuzz"
        ]
    );
    assert!(off.excluded().is_empty());
    // The disabled plan equals the shadow's own current plan byte for byte.
    assert_eq!(&off, shadow.current());

    // A rate limit recommends Backoff: active verification and mutation are
    // suppressed; passive and local analysis are kept.
    let shadow_suppressed: BTreeSet<&str> = shadow
        .delta()
        .suppressed()
        .iter()
        .map(|action| action.action_id())
        .collect();
    assert_eq!(
        shadow_suppressed,
        BTreeSet::from(["active.verify", "mutating.fuzz"])
    );
    assert!(shadow
        .delta()
        .unchanged()
        .iter()
        .any(|id| id == "local.report"));
    // The delta carries provenance: each suppression references its evidence.
    for suppressed in shadow.delta().suppressed() {
        assert!(!suppressed.supporting_evidence_ids().is_empty());
        assert_eq!(suppressed.explanation_code(), "defense.backoff.suppress");
    }

    // Enabled enforcement drops exactly those actions, with a distinct reason.
    assert_eq!(step_ids(&on), ["local.report", "passive.discovery"]);
    let enforced_suppressed: BTreeSet<&str> = on
        .excluded()
        .iter()
        .filter(|excluded| excluded.reason() == &ExclusionReason::DefenseSuppressed)
        .map(|excluded| excluded.action_id())
        .collect();
    // Shadow and enforcement agree: explanation and runtime share one policy.
    assert_eq!(enforced_suppressed, shadow_suppressed);

    // Proof: a suppressed action never becomes a plan step, so it is never turned
    // into a command and never reaches an executor.
    let enforced_steps: BTreeSet<&str> = step_ids(&on).into_iter().collect();
    for suppressed in &enforced_suppressed {
        assert!(
            !enforced_steps.contains(suppressed),
            "{suppressed} was suppressed yet reached a plan step"
        );
    }

    // Determinism: the same scenario yields the same enforced plan.
    let repeat = defense_aware_plan(
        DefensePlanningPolicy::enabled(),
        &planner,
        &snapshot,
        &subject(),
        context(),
        &signal,
        classify,
    )
    .unwrap();
    assert_eq!(on, repeat);
}
