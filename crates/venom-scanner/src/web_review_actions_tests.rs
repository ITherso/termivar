use std::collections::BTreeSet;

use crate::{
    planner::VerificationTarget, web_actions::StandardWebActionKind,
    web_planning::StandardWebAttackProfile,
};

use super::{
    NativeWebReviewActionKind, NativeWebReviewDifferentialInput, NativeWebReviewRequestLeg,
    NATIVE_WEB_REVIEW_ACTION_COUNT, NATIVE_WEB_REVIEW_ACTIVE_REQUESTS_PER_CASE,
    NATIVE_WEB_REVIEW_REQUESTS_PER_CASE,
};

#[test]
fn native_action_identities_are_stable_unique_and_deterministic() {
    let expected = [
        (
            NativeWebReviewActionKind::CorsPolicyPair,
            "web.review.cors.policy-pair@1",
            "web.review.probe.cors-policy-pair@1",
            "cors-policy-pair",
        ),
        (
            NativeWebReviewActionKind::RedirectReflectionQueryPair,
            "web.review.redirect-reflection.query-pair@1",
            "web.review.probe.redirect-reflection-query-pair@1",
            "redirect-reflection-query-pair",
        ),
    ];

    assert_eq!(
        NativeWebReviewActionKind::all().len(),
        NATIVE_WEB_REVIEW_ACTION_COUNT
    );
    assert_eq!(
        NativeWebReviewActionKind::all(),
        expected.map(|entry| entry.0)
    );

    let mut action_ids = BTreeSet::new();
    let mut executor_ids = BTreeSet::new();
    let mut slugs = BTreeSet::new();
    for (kind, action_id, executor_id, slug) in expected {
        assert_eq!(kind.action_id(), action_id);
        assert_eq!(kind.executor_id(), executor_id);
        assert_eq!(kind.slug(), slug);
        assert!(action_ids.insert(kind.action_id()));
        assert!(executor_ids.insert(kind.executor_id()));
        assert!(slugs.insert(kind.slug()));
    }
}

#[test]
fn every_native_action_is_low_risk_and_irrevocably_knowledge_only() {
    let expected_risk_basis_points = [500, 800];

    for (kind, expected_risk) in NativeWebReviewActionKind::all()
        .into_iter()
        .zip(expected_risk_basis_points)
    {
        assert_eq!(kind.risk().basis_points(), expected_risk);
        assert!(kind.risk().basis_points() <= 1_000);
        assert_eq!(
            kind.verification_target(),
            VerificationTarget::KnowledgeOnly
        );
    }
}

#[test]
fn request_relationship_is_exactly_passive_control_then_active_candidate() {
    let expected_legs = [
        NativeWebReviewRequestLeg::PassiveControl,
        NativeWebReviewRequestLeg::ActiveCandidate,
    ];

    for kind in NativeWebReviewActionKind::all() {
        assert_eq!(kind.request_legs(), &expected_legs);
        assert_eq!(
            kind.maximum_requests_per_case(),
            NATIVE_WEB_REVIEW_REQUESTS_PER_CASE
        );
        assert_eq!(
            kind.maximum_active_requests_per_case(),
            NATIVE_WEB_REVIEW_ACTIVE_REQUESTS_PER_CASE
        );
        assert_eq!(
            kind.request_legs()
                .iter()
                .filter(|leg| leg.is_active())
                .count(),
            1
        );
    }

    assert_eq!(
        NativeWebReviewActionKind::CorsPolicyPair.differential_input(),
        NativeWebReviewDifferentialInput::OriginHeader
    );
    assert_eq!(
        NativeWebReviewActionKind::RedirectReflectionQueryPair.differential_input(),
        NativeWebReviewDifferentialInput::SingleQueryParameter
    );
}

#[test]
fn native_review_actions_are_absent_from_the_default_standard_catalog() {
    let native_ids = NativeWebReviewActionKind::all()
        .into_iter()
        .map(NativeWebReviewActionKind::action_id)
        .collect::<BTreeSet<_>>();
    let standard_ids = StandardWebActionKind::all()
        .into_iter()
        .map(StandardWebActionKind::action_id)
        .collect::<BTreeSet<_>>();

    assert!(native_ids.is_disjoint(&standard_ids));

    let standard_profile = StandardWebAttackProfile::new().unwrap();
    assert!(standard_profile
        .actions()
        .iter()
        .all(|action| !native_ids.contains(action.id())));
}
