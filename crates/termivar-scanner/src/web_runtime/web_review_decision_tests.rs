//! Native review decision-profile regression tests.

use std::collections::BTreeSet;

use termivar_core::{
    ConfidenceScore, EntityId, Evidence, EvidenceKind, EvidenceSource, EvidenceValue,
    HttpEvidencePredicate, Hypothesis, HypothesisState, HypothesisStrength, OutcomeStatus,
    Probability,
};
use url::Url;

use crate::{
    payload_strategies::{
        CORS_ORIGIN_PAIR_ID, CORS_ORIGIN_PAIR_REVISION, EXTERNAL_URL_QUERY_PAIR_ID,
        EXTERNAL_URL_QUERY_PAIR_REVISION, SSTI_ARITHMETIC_EXPRESSION_PAIR_ID,
        SSTI_ARITHMETIC_EXPRESSION_PAIR_REVISION, XSS_ATTRIBUTE_BOUNDARY_QUERY_PAIR_ID,
        XSS_ATTRIBUTE_BOUNDARY_QUERY_PAIR_REVISION, XSS_JAVASCRIPT_LEXICAL_BOUNDARY_QUERY_PAIR_ID,
        XSS_JAVASCRIPT_LEXICAL_BOUNDARY_QUERY_PAIR_REVISION, XSS_STRUCTURAL_QUERY_PAIR_ID,
        XSS_STRUCTURAL_QUERY_PAIR_REVISION,
    },
    web_actions::NativeWebReviewActionKind,
    AdaptationLimits, AttackAction, BenefitScore, DecisionLoopConfig, ExperiencePolicy,
    HttpEvidencePolicy, HypothesisSelector, KnowledgeBase, KnowledgeLayer, PayloadStrategyRef,
    PlanningContext, RequiredStrength, ResolvedVerificationTarget, RiskScore,
    StandardWebDecisionProfile, VerificationCase, VerificationTarget,
};

use super::*;

fn subject() -> EntityId {
    EntityId::new("endpoint:https://example.test/").unwrap()
}

fn decision_loop() -> DecisionLoop {
    DecisionLoop::new(
        DecisionLoopConfig::new(
            PlanningContext::new(
                BenefitScore::from_percent(80).unwrap(),
                14,
                RiskScore::from_percent(10).unwrap(),
            ),
            AdaptationLimits::default(),
            ExperiencePolicy::default(),
            4,
        )
        .unwrap(),
    )
}

fn response_status(correlation_id: &str, component: &str, status: u64) -> Evidence {
    Evidence::new(
        subject(),
        EvidenceKind::Http,
        HttpEvidencePredicate::RESPONSE_STATUS.into(),
        EvidenceValue::Unsigned(status),
        EvidenceSource::new("web.review.test-executor", component)
            .unwrap()
            .with_correlation_id(correlation_id)
            .unwrap(),
        ConfidenceScore::MAX,
    )
}

fn review_response_marker(correlation_id: &str, component: &str) -> Evidence {
    Evidence::new(
        subject(),
        EvidenceKind::Custom("web-review-observation".to_owned()),
        native_web_review_response_marker_predicate(),
        EvidenceValue::Text("active-candidate".to_owned()),
        EvidenceSource::new("web.review.test-executor", component)
            .unwrap()
            .with_correlation_id(correlation_id)
            .unwrap(),
        ConfidenceScore::MAX,
    )
}

#[cfg(feature = "authorization-review")]
fn authorization_terminal_marker(correlation_id: &str) -> Evidence {
    Evidence::new(
        subject(),
        EvidenceKind::Custom("authorization-review-phase".to_owned()),
        crate::web_actions::authorization_review_phase_terminal_predicate(),
        EvidenceValue::Boolean(true),
        EvidenceSource::new("web.review.test-executor", "phase-terminal")
            .unwrap()
            .with_correlation_id(correlation_id)
            .unwrap(),
        ConfidenceScore::MAX,
    )
}

fn expected_strategy(kind: NativeWebReviewActionKind) -> Option<PayloadStrategyRef> {
    let (id, revision) = match kind {
        NativeWebReviewActionKind::CorsPolicyPair => {
            (CORS_ORIGIN_PAIR_ID, CORS_ORIGIN_PAIR_REVISION)
        },
        NativeWebReviewActionKind::RedirectReflectionQueryPair => {
            (EXTERNAL_URL_QUERY_PAIR_ID, EXTERNAL_URL_QUERY_PAIR_REVISION)
        },
        NativeWebReviewActionKind::ReflectionContextQueryPair => (
            REFLECTION_MARKER_QUERY_PAIR_ID,
            REFLECTION_MARKER_QUERY_PAIR_REVISION,
        ),
        NativeWebReviewActionKind::SqlStructuralQueryPair
        | NativeWebReviewActionKind::SqlStructuralQueryReplayPair => (
            SQL_QUOTE_BALANCE_QUERY_PAIR_ID,
            SQL_QUOTE_BALANCE_QUERY_PAIR_REVISION,
        ),
        NativeWebReviewActionKind::SstiStructuralQueryPair
        | NativeWebReviewActionKind::SstiStructuralQueryReplayPair => (
            SSTI_ARITHMETIC_EXPRESSION_PAIR_ID,
            SSTI_ARITHMETIC_EXPRESSION_PAIR_REVISION,
        ),
        NativeWebReviewActionKind::XssStructuralQueryPair => (
            XSS_STRUCTURAL_QUERY_PAIR_ID,
            XSS_STRUCTURAL_QUERY_PAIR_REVISION,
        ),
        NativeWebReviewActionKind::XssAttributeBoundaryQueryPair => (
            XSS_ATTRIBUTE_BOUNDARY_QUERY_PAIR_ID,
            XSS_ATTRIBUTE_BOUNDARY_QUERY_PAIR_REVISION,
        ),
        NativeWebReviewActionKind::XssScriptLexicalBoundaryQueryPair => (
            XSS_JAVASCRIPT_LEXICAL_BOUNDARY_QUERY_PAIR_ID,
            XSS_JAVASCRIPT_LEXICAL_BOUNDARY_QUERY_PAIR_REVISION,
        ),
        #[cfg(feature = "normalization-resilience")]
        NativeWebReviewActionKind::NormalizationResilienceQueryPair => (
            NORMALIZATION_RESILIENCE_QUERY_PAIR_ID,
            NORMALIZATION_RESILIENCE_QUERY_PAIR_REVISION,
        ),
        #[cfg(feature = "authorization-review")]
        NativeWebReviewActionKind::ResourceAuthorizationDifferential => return None,
        #[cfg(feature = "openapi-review")]
        NativeWebReviewActionKind::OpenApiDocumentReplay => return None,
        #[cfg(feature = "rest-review")]
        NativeWebReviewActionKind::RestReadOnlyReplay => return None,
    };
    Some(PayloadStrategyRef::new(id, revision).unwrap())
}

#[test]
fn profile_definitions_are_deterministic_exact_and_knowledge_only() {
    let first = NativeWebReviewDecisionProfile::new().unwrap();
    let second = NativeWebReviewDecisionProfile::new().unwrap();

    assert_eq!(first.reasoning_rules, second.reasoning_rules);
    assert_eq!(first.actions, second.actions);
    assert_eq!(first.active_rules, second.active_rules);
    assert_eq!(first.actions.len(), NATIVE_WEB_REVIEW_ACTION_COUNT);
    assert_eq!(
        first.active_rules.len(),
        NATIVE_WEB_REVIEW_ACTIVE_RULE_COUNT
    );

    for kind in NativeWebReviewActionKind::all() {
        let action = first
            .actions
            .iter()
            .find(|action| action.id() == kind.action_id())
            .unwrap();
        assert_eq!(action.executor(), kind.executor_id());
        assert_eq!(action.payload_strategy(), expected_strategy(kind).as_ref());
        assert_eq!(
            action.verification_target(),
            &VerificationTarget::KnowledgeOnly
        );
        assert_eq!(
            action.cost().units(),
            u32::try_from(kind.maximum_requests_per_case()).unwrap()
        );
        assert_eq!(action.risk(), kind.risk());
        assert!(action.prerequisites().is_empty());

        let rule = first
            .active_rules
            .iter()
            .find(|rule| {
                rule.action_id() == Some(kind.action_id())
                    && rule.outcome() == OutcomeStatus::Success
            })
            .unwrap();
        assert_eq!(rule.stage(), VerificationStage::Active);
        assert_eq!(rule.outcome(), OutcomeStatus::Success);
        assert!(rule.requires_case_correlated_evidence());
    }
}

#[test]
fn subject_specific_profile_is_ordered_exact_and_rejects_duplicates() {
    let requested = [
        NativeWebReviewActionKind::SqlStructuralQueryReplayPair,
        NativeWebReviewActionKind::SqlStructuralQueryPair,
    ];
    let profile = NativeWebReviewDecisionProfile::for_actions(requested).unwrap();
    assert_eq!(
        profile.actions().collect::<Vec<_>>(),
        [
            NativeWebReviewActionKind::SqlStructuralQueryPair,
            NativeWebReviewActionKind::SqlStructuralQueryReplayPair,
        ]
    );
    assert_eq!(profile.actions.len(), 2);
    assert_eq!(profile.active_rules.len(), 2);
    assert_eq!(profile.reasoning_rules.len(), 1);

    assert!(matches!(
        NativeWebReviewDecisionProfile::for_actions([
            NativeWebReviewActionKind::CorsPolicyPair,
            NativeWebReviewActionKind::CorsPolicyPair,
        ]),
        Err(NativeWebReviewDecisionError::DuplicateAction { action_id })
            if action_id == NativeWebReviewActionKind::CorsPolicyPair.action_id()
    ));
}

#[test]
fn empty_subject_specific_profile_intentionally_installs_nothing() {
    let profile = NativeWebReviewDecisionProfile::for_actions([]).unwrap();
    assert_eq!(profile.actions().len(), 0);
    assert!(profile.actions.is_empty());
    assert!(profile.active_rules.is_empty());
    assert!(profile.reasoning_rules.is_empty());

    let mut decision_loop = decision_loop();
    assert_eq!(
        profile.install(&mut decision_loop).unwrap(),
        NativeWebReviewDecisionInstallReport::default()
    );
    assert!(decision_loop.rules().is_empty());
    assert!(decision_loop.planner().is_empty());
    assert!(decision_loop.verification().active().is_empty());
}

#[test]
fn standard_web_decision_profile_excludes_native_review_definitions() {
    let policy =
        HttpEvidencePolicy::for_origin(Url::parse("https://example.test/").unwrap()).unwrap();
    let standard = StandardWebDecisionProfile::new(policy).unwrap();
    let action_ids = NativeWebReviewActionKind::all()
        .into_iter()
        .map(NativeWebReviewActionKind::action_id)
        .collect::<BTreeSet<_>>();

    assert!(standard
        .planning()
        .actions()
        .iter()
        .all(|action| !action_ids.contains(action.id())));
    assert!(standard
        .reasoning()
        .rules()
        .iter()
        .all(|rule| rule.id() != WEB_REVIEW_ELIGIBLE_RULE_ID));
    assert!(standard
        .verification()
        .rules()
        .iter()
        .all(|rule| rule.action_id().is_none_or(|id| !action_ids.contains(id))));
}

#[test]
fn install_is_atomic_and_idempotent() {
    let profile = NativeWebReviewDecisionProfile::new().unwrap();
    let mut decision_loop = decision_loop();

    let first = profile.install(&mut decision_loop).unwrap();
    let second = profile.install(&mut decision_loop).unwrap();

    assert_eq!(
        first.reasoning_rules_inserted,
        NATIVE_WEB_REVIEW_REASONING_RULE_COUNT
    );
    assert_eq!(first.actions_inserted, NATIVE_WEB_REVIEW_ACTION_COUNT);
    assert_eq!(
        first.active_rules_inserted,
        NATIVE_WEB_REVIEW_ACTIVE_RULE_COUNT
    );
    assert_eq!(
        first.passive_rules_inserted,
        NATIVE_WEB_REVIEW_PASSIVE_RULE_COUNT
    );
    assert_eq!(second, NativeWebReviewDecisionInstallReport::default());
    assert_eq!(
        decision_loop.rules().len(),
        NATIVE_WEB_REVIEW_REASONING_RULE_COUNT
    );
    assert_eq!(
        decision_loop.planner().len(),
        NATIVE_WEB_REVIEW_ACTION_COUNT
    );
    assert_eq!(
        decision_loop.verification().passive().len(),
        NATIVE_WEB_REVIEW_PASSIVE_RULE_COUNT
    );
    assert_eq!(
        decision_loop.verification().active().len(),
        NATIVE_WEB_REVIEW_ACTIVE_RULE_COUNT
    );
}

#[cfg(feature = "authorization-review")]
#[test]
fn authorization_passive_terminal_rule_is_exact_action_and_case_scoped() {
    const RULE_ID: &str = "web.review.verify.passive.authorization-resource-terminal@1";
    const CASE_ID: &str = "case:authorization-terminal";
    const OTHER_CASE_ID: &str = "case:authorization-terminal-other";
    const HYPOTHESIS_ID: &str = "hypothesis:authorization-terminal";

    let authorization = NativeWebReviewActionKind::ResourceAuthorizationDifferential;
    let profile = NativeWebReviewDecisionProfile::for_actions([authorization]).unwrap();
    assert_eq!(profile.passive_rules.len(), 1);
    let rule = &profile.passive_rules[0];
    assert_eq!(rule.id(), RULE_ID);
    assert_eq!(rule.stage(), VerificationStage::Passive);
    assert_eq!(rule.outcome(), OutcomeStatus::Blocked);
    assert_eq!(rule.action_id(), Some(authorization.action_id()));
    assert!(rule.requires_case_correlated_evidence());
    assert_eq!(
        rule.condition(),
        &Expression::equals(
            KnowledgeLayer::Evidence,
            crate::web_actions::authorization_review_phase_terminal_predicate(),
            EvidenceValue::Boolean(true),
        )
    );
    assert_ne!(rule.outcome(), OutcomeStatus::Success);
    assert_eq!(rule.outcome().hypothesis_state(), None);

    let mut decision_loop = decision_loop();
    let first = profile.install(&mut decision_loop).unwrap();
    assert_eq!(first.passive_rules_inserted, 1);
    assert_eq!(decision_loop.verification().passive().len(), 1);

    let knowledge = KnowledgeBase::new();
    let mut hypothesis = Hypothesis::with_id(
        HYPOTHESIS_ID,
        subject(),
        eligible_predicate(),
        EvidenceValue::Boolean(true),
        Probability::from_percent(99).unwrap(),
    )
    .unwrap();
    hypothesis.set_strength(HypothesisStrength::Weak);
    hypothesis.set_state(HypothesisState::Supported);
    knowledge.upsert_hypothesis(hypothesis).unwrap();

    let authorization_case =
        VerificationCase::new(CASE_ID, subject(), authorization.action_id(), HYPOTHESIS_ID)
            .unwrap()
            .without_hypothesis_transition();
    let without_terminal = decision_loop
        .verification()
        .passive()
        .verify(&knowledge, &authorization_case)
        .unwrap();
    assert_eq!(without_terminal.outcome().status(), OutcomeStatus::Unknown);

    let terminal = authorization_terminal_marker(CASE_ID);
    let terminal_id = terminal.id().clone();
    knowledge.insert_evidence(terminal).unwrap();
    let blocked = decision_loop
        .verification()
        .passive()
        .verify(&knowledge, &authorization_case)
        .unwrap();
    assert_eq!(blocked.outcome().status(), OutcomeStatus::Blocked);
    assert_eq!(blocked.outcome().verifier_rule_id(), Some(RULE_ID));
    assert!(blocked.outcome().evidence_ids().contains(&terminal_id));
    assert_eq!(blocked.apply(&knowledge).unwrap(), None);
    assert_eq!(
        knowledge.hypothesis(HYPOTHESIS_ID).unwrap().state(),
        HypothesisState::Supported
    );

    let other_action_case = VerificationCase::new(
        CASE_ID,
        subject(),
        NativeWebReviewActionKind::CorsPolicyPair.action_id(),
        HYPOTHESIS_ID,
    )
    .unwrap()
    .without_hypothesis_transition();
    let other_action = decision_loop
        .verification()
        .passive()
        .verify(&knowledge, &other_action_case)
        .unwrap();
    assert_eq!(other_action.outcome().status(), OutcomeStatus::Unknown);

    let other_case = VerificationCase::new(
        OTHER_CASE_ID,
        subject(),
        authorization.action_id(),
        HYPOTHESIS_ID,
    )
    .unwrap()
    .without_hypothesis_transition();
    let uncorrelated = decision_loop
        .verification()
        .passive()
        .verify(&knowledge, &other_case)
        .unwrap();
    assert_eq!(uncorrelated.outcome().status(), OutcomeStatus::Unknown);
}

#[cfg(feature = "rest-review")]
#[test]
fn rest_action_requires_replay_stable_catalog_and_has_exact_terminal_rules() {
    let rest = NativeWebReviewActionKind::RestReadOnlyReplay;
    let profile = NativeWebReviewDecisionProfile::for_actions([rest]).unwrap();
    assert_eq!(profile.reasoning_rules.len(), 1);
    assert_eq!(profile.actions.len(), 1);
    assert_eq!(profile.passive_rules.len(), 2);
    assert_eq!(profile.active_rules.len(), 2);
    assert!(profile.actions[0].prerequisites().is_empty());

    for (stage, id) in [
        (
            VerificationStage::Passive,
            "web.review.verify.passive.rest-readonly-terminal@1",
        ),
        (
            VerificationStage::Active,
            "web.review.verify.active.rest-readonly-terminal@1",
        ),
    ] {
        let rule = profile
            .passive_rules
            .iter()
            .chain(profile.active_rules.iter())
            .find(|rule| rule.id() == id)
            .unwrap();
        assert_eq!(rule.stage(), stage);
        assert_eq!(rule.outcome(), OutcomeStatus::Blocked);
        assert_eq!(rule.action_id(), Some(rest.action_id()));
        assert!(rule.requires_case_correlated_evidence());
        assert_eq!(
            rule.condition(),
            &Expression::equals(
                KnowledgeLayer::Evidence,
                crate::web_actions::rest_review_phase_terminal_predicate(),
                EvidenceValue::Boolean(true),
            )
        );
    }

    let mut loop_ = decision_loop();
    profile.install(&mut loop_).unwrap();
    let knowledge = KnowledgeBase::new();
    knowledge
        .insert_evidence(response_status("case:bootstrap", "bootstrap", 200))
        .unwrap();
    loop_.rules().apply(&knowledge, &subject()).unwrap();
    assert!(loop_
        .planner()
        .plan(
            &knowledge,
            &subject(),
            PlanningContext::new(
                BenefitScore::from_percent(80).unwrap(),
                100,
                RiskScore::from_percent(10).unwrap(),
            ),
        )
        .unwrap()
        .steps()
        .is_empty());

    let ready = Evidence::new(
        subject(),
        EvidenceKind::Custom("openapi-review".to_owned()),
        crate::web_actions::rest_review_catalog_ready_predicate(),
        EvidenceValue::Boolean(true),
        EvidenceSource::new("http.openapi-review", "rest-catalog-ready")
            .unwrap()
            .with_correlation_id("case:openapi-replay")
            .unwrap(),
        ConfidenceScore::MAX,
    );
    knowledge.insert_evidence(ready).unwrap();
    loop_.rules().apply(&knowledge, &subject()).unwrap();
    let plan = loop_
        .planner()
        .plan(
            &knowledge,
            &subject(),
            PlanningContext::new(
                BenefitScore::from_percent(80).unwrap(),
                100,
                RiskScore::from_percent(10).unwrap(),
            ),
        )
        .unwrap();
    assert_eq!(plan.steps().len(), 1);
    assert_eq!(plan.steps()[0].action_id(), rest.action_id());
}

#[test]
fn planner_conflict_rolls_back_preflighted_reasoning_and_verification() {
    let profile = NativeWebReviewDecisionProfile::new().unwrap();
    let mut decision_loop = decision_loop();
    let kind = NativeWebReviewActionKind::CorsPolicyPair;
    let predicate = eligible_predicate();
    let conflict = AttackAction::new(
        kind.action_id(),
        "host.conflicting-executor",
        Expression::equals(
            KnowledgeLayer::Hypothesis,
            predicate.clone(),
            EvidenceValue::Boolean(true),
        ),
        HypothesisSelector::new(
            predicate,
            EvidenceValue::Boolean(true),
            Probability::from_percent(50).unwrap(),
            RequiredStrength::Any,
        ),
        BenefitScore::from_percent(10).unwrap(),
        ActionCost::new(1).unwrap(),
        RiskScore::from_percent(1).unwrap(),
        BTreeSet::new(),
    )
    .unwrap();
    decision_loop
        .planner_mut()
        .register(conflict.clone())
        .unwrap();

    assert!(matches!(
        profile.install(&mut decision_loop),
        Err(NativeWebReviewDecisionError::Planning(
            PlannerError::ActionIdentityConflict { .. }
        ))
    ));
    assert!(decision_loop.rules().is_empty());
    assert_eq!(decision_loop.planner().len(), 1);
    assert_eq!(
        decision_loop.planner().action(kind.action_id()),
        Some(&conflict)
    );
    assert!(decision_loop.verification().active().is_empty());
}

#[test]
fn correlated_response_status_materializes_only_a_generic_supported_eligibility() {
    const PLANNING_COST_BUDGET: u64 = 14;
    const NATIVE_ACTION_COST: u64 = 2;
    let profile = NativeWebReviewDecisionProfile::new().unwrap();
    let mut decision_loop = decision_loop();
    profile.install(&mut decision_loop).unwrap();
    let knowledge = KnowledgeBase::new();

    let empty_plan = decision_loop
        .planner()
        .plan(
            &knowledge,
            &subject(),
            PlanningContext::new(
                BenefitScore::from_percent(80).unwrap(),
                PLANNING_COST_BUDGET,
                RiskScore::from_percent(10).unwrap(),
            ),
        )
        .unwrap();
    assert!(empty_plan.steps().is_empty());

    let status = response_status("case:bootstrap", "bootstrap-status", 200);
    let status_id = status.id().clone();
    knowledge.insert_evidence(status).unwrap();
    decision_loop.rules().apply(&knowledge, &subject()).unwrap();

    let hypothesis = knowledge
        .hypotheses_for_subject(&subject())
        .into_iter()
        .find(|hypothesis| hypothesis.predicate() == &eligible_predicate())
        .unwrap();
    assert_eq!(
        hypothesis.predicate().dotted(),
        WEB_REVIEW_ELIGIBLE_PREDICATE
    );
    assert_eq!(hypothesis.value(), &EvidenceValue::Boolean(true));
    assert_eq!(hypothesis.state(), HypothesisState::Supported);
    assert_eq!(hypothesis.strength(), HypothesisStrength::Weak);
    assert_eq!(hypothesis.belief().evidence().len(), 1);
    assert_eq!(hypothesis.belief().evidence()[0].evidence_id(), &status_id);
    let source = knowledge
        .evidence_for_subject(&subject())
        .into_iter()
        .find(|evidence| evidence.id() == &status_id)
        .unwrap();
    assert_eq!(source.source().correlation_id(), Some("case:bootstrap"));

    let plan = decision_loop
        .planner()
        .plan(
            &knowledge,
            &subject(),
            PlanningContext::new(
                BenefitScore::from_percent(80).unwrap(),
                PLANNING_COST_BUDGET,
                RiskScore::from_percent(10).unwrap(),
            ),
        )
        .unwrap();
    // This test exercises the complete closed catalog under an intentionally
    // smaller planner budget. Catalog membership does not override action cost.
    let budgeted_action_count = usize::try_from(PLANNING_COST_BUDGET / NATIVE_ACTION_COST)
        .unwrap()
        .min(NATIVE_WEB_REVIEW_ACTION_COUNT);
    assert_eq!(profile.actions().count(), NATIVE_WEB_REVIEW_ACTION_COUNT);
    assert_eq!(plan.steps().len(), budgeted_action_count);
    assert!(plan.steps().iter().all(|step| matches!(
        step.verification_target(),
        ResolvedVerificationTarget::KnowledgeOnly
    )));
}

#[test]
fn passive_is_unknown_and_only_fresh_case_correlated_review_marker_succeeds() {
    let profile = NativeWebReviewDecisionProfile::new().unwrap();
    let mut decision_loop = decision_loop();
    profile.install(&mut decision_loop).unwrap();

    for (index, kind) in NativeWebReviewActionKind::all().into_iter().enumerate() {
        let case_id = format!("case:web-review:{index}");
        let hypothesis_id = format!("hypothesis:web-review:{index}");
        let case = VerificationCase::new(&case_id, subject(), kind.action_id(), &hypothesis_id)
            .unwrap()
            .with_payload_strategy(expected_strategy(kind))
            .without_hypothesis_transition();
        let knowledge = KnowledgeBase::new();
        let mut hypothesis = Hypothesis::with_id(
            &hypothesis_id,
            subject(),
            eligible_predicate(),
            EvidenceValue::Boolean(true),
            Probability::from_percent(99).unwrap(),
        )
        .unwrap();
        hypothesis.set_strength(HypothesisStrength::Weak);
        hypothesis.set_state(HypothesisState::Supported);
        knowledge.upsert_hypothesis(hypothesis).unwrap();
        knowledge
            .insert_evidence(response_status(&case_id, "passive-status", 200))
            .unwrap();
        let baseline = knowledge.snapshot_for_subject(&subject());

        let passive = decision_loop
            .verification()
            .verify_snapshots(&case, &baseline, None)
            .unwrap();
        assert_eq!(passive.passive().outcome().status(), OutcomeStatus::Unknown);
        assert!(passive.requires_active());

        let no_fresh = decision_loop
            .verification()
            .active()
            .verify_snapshots(&case, &baseline, &baseline)
            .unwrap();
        assert_eq!(no_fresh.outcome().status(), OutcomeStatus::Unknown);

        knowledge
            .insert_evidence(response_status("case:other", "wrong-case-status", 201))
            .unwrap();
        let wrong_case = knowledge.snapshot_for_subject(&subject());
        let uncorrelated = decision_loop
            .verification()
            .active()
            .verify_snapshots(&case, &baseline, &wrong_case)
            .unwrap();
        assert_eq!(uncorrelated.outcome().status(), OutcomeStatus::Unknown);

        let active_status = response_status(&case_id, "active-status", 202);
        knowledge.insert_evidence(active_status).unwrap();
        let status_only = knowledge.snapshot_for_subject(&subject());
        let incomplete = decision_loop
            .verification()
            .active()
            .verify_snapshots(&case, &baseline, &status_only)
            .unwrap();
        assert_eq!(incomplete.outcome().status(), OutcomeStatus::Unknown);

        let marker = review_response_marker(&case_id, "active-marker");
        let marker_id = marker.id().clone();
        knowledge.insert_evidence(marker).unwrap();
        let after_active = knowledge.snapshot_for_subject(&subject());
        let active = decision_loop
            .verification()
            .active()
            .verify_snapshots(&case, &baseline, &after_active)
            .unwrap();

        assert_eq!(active.outcome().status(), OutcomeStatus::Success);
        assert!(active.outcome().evidence_ids().contains(&marker_id));
        assert!(!case.applies_hypothesis_transition());
        assert_eq!(active.apply(&knowledge).unwrap(), None);
        assert_eq!(
            knowledge.hypothesis(&hypothesis_id).unwrap().state(),
            HypothesisState::Supported
        );
    }
}
