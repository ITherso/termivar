use termivar_core::{
    ApiEvidencePredicate, ApiKnowledgePredicate, ApiSurfaceKind, ApiVisibilityBoundaryKind,
    ApiVisibilityComparison, ApiVisibilityDimension, ApiVisibilityObservation,
    ApiVisibilityPairKind, ApiVisibilityResult, ConfidenceScore, EntityId, EvidenceValue,
    HypothesisState, HypothesisStrength, KnowledgePredicate, Probability,
};
use url::Url;

use super::*;
use crate::{
    EvidenceCalibration, EvidenceSelector, Expression, HypothesisConclusion, KnowledgeLayer,
    KnowledgeWrite, ReasoningRule, RuleEngineError,
};

fn runtime(api_reasoning: bool) -> StandardWebDecisionRuntime {
    let builder = StandardWebDecisionRuntime::builder(
        Url::parse("https://example.test/api/accounts/42").unwrap(),
    );
    if api_reasoning {
        builder.enable_api_reasoning().build().unwrap()
    } else {
        builder.build().unwrap()
    }
}

fn resource() -> EntityId {
    EntityId::new("resource:account-42").unwrap()
}

fn observation(
    id: &str,
    pair: ApiVisibilityPairKind,
    result: ApiVisibilityResult,
) -> ApiVisibilityObservation {
    ApiVisibilityComparison::new(
        id,
        ApiSurfaceKind::JsonHttp,
        pair,
        result,
        ApiVisibilityDimension::Fields,
        "anonymous-view",
        "member-view",
        resource().as_str(),
    )
    .unwrap()
    .with_observed_at_ms(1_800_000_000_000)
    .to_observation("host.api-comparator", ConfidenceScore::MAX)
    .unwrap()
}

#[test]
fn disabled_profile_rejects_ingress_and_review_before_any_write() {
    let mut runtime = runtime(false);
    let before = runtime.knowledge().stats();

    assert!(matches!(
        runtime.ingest_api_visibility(
            observation(
                "comparison-disabled",
                ApiVisibilityPairKind::AuthorizationContext,
                ApiVisibilityResult::Different,
            ),
            &resource(),
        ),
        Err(RuntimeApiVisibilityError::ApiReasoningDisabled)
    ));
    assert!(matches!(
        runtime.api_visibility_reviews(&resource(), &ApiVisibilityReviewQuery::default()),
        Err(RuntimeApiVisibilityError::ApiReasoningDisabled)
    ));
    assert_eq!(runtime.knowledge().stats(), before);
    assert_eq!(runtime.usage(), &crate::RuntimeUsage::default());
    assert!(!runtime.has_started());
}

#[test]
fn enabled_profile_ingests_isolated_reviews_and_replays_idempotently() {
    let mut runtime = runtime(true);
    let initial_session = runtime.session().clone();
    let observation = observation(
        "comparison-enabled",
        ApiVisibilityPairKind::AuthorizationContext,
        ApiVisibilityResult::Different,
    );

    let first = runtime
        .ingest_api_visibility(observation.clone(), &resource())
        .unwrap();
    assert_eq!(first.commit().evidence_write(), KnowledgeWrite::Inserted);
    assert_eq!(first.commit().relation_write(), KnowledgeWrite::Inserted);
    assert_ne!(first.commit().comparison_subject(), runtime.subject());

    let replay = runtime
        .ingest_api_visibility(observation, &resource())
        .unwrap();
    assert_eq!(replay.commit().evidence_write(), KnowledgeWrite::Unchanged);
    assert_eq!(replay.commit().relation_write(), KnowledgeWrite::Unchanged);
    assert!(replay
        .applications()
        .iter()
        .filter_map(crate::RuleApplication::write)
        .all(|write| write == KnowledgeWrite::Unchanged));

    let page = runtime
        .api_visibility_reviews(&resource(), &ApiVisibilityReviewQuery::default())
        .unwrap();
    assert_eq!(page.reviews().len(), 1);
    let review = &page.reviews()[0];
    assert_eq!(review.resource_scope(), &resource());
    assert_eq!(review.boundary_hypotheses().len(), 1);
    assert_eq!(
        review.boundary_hypotheses()[0].value(),
        &EvidenceValue::from(ApiVisibilityBoundaryKind::AuthorizationContext)
    );

    let endpoint = runtime.knowledge().snapshot_for_subject(runtime.subject());
    assert!(endpoint.hypotheses().iter().all(|hypothesis| {
        hypothesis.predicate() != &ApiKnowledgePredicate::VISIBILITY_BOUNDARY.into_knowledge()
    }));
    assert_eq!(runtime.session(), &initial_session);
    assert!(runtime.experience().is_empty());
    assert_eq!(runtime.usage(), &crate::RuntimeUsage::default());
    assert!(!runtime.has_started());
}

#[test]
fn resource_mismatch_is_rejected_before_storage() {
    let mut runtime = runtime(true);
    let before = runtime.knowledge().stats();
    let other = EntityId::new("resource:account-7").unwrap();

    let error = runtime
        .ingest_api_visibility(
            observation(
                "comparison-wrong-resource",
                ApiVisibilityPairKind::UiApi,
                ApiVisibilityResult::Different,
            ),
            &other,
        )
        .unwrap_err();

    assert!(matches!(
        error,
        RuntimeApiVisibilityError::Observation(ApiObservationError::ResourceMismatch { .. })
    ));
    assert_eq!(runtime.knowledge().stats(), before);
}

#[test]
fn post_commit_reasoning_failure_preserves_the_observation_receipt() {
    let mut runtime = runtime(true);
    let comparison_predicate = ApiEvidencePredicate::JSON_UI_API_DIFFERENCE.into_knowledge();
    let unrelated = KnowledgePredicate::new("test", "unrelated").unwrap();
    runtime
        .decision_loop
        .rules_mut()
        .register(
            ReasoningRule::new(
                "000.runtime-invalid-calibration",
                Expression::exists(KnowledgeLayer::Evidence, comparison_predicate),
                HypothesisConclusion::new(
                    KnowledgePredicate::new("test", "result").unwrap(),
                    EvidenceValue::Boolean(true),
                    Probability::from_percent(10).unwrap(),
                    HypothesisStrength::Weak,
                    HypothesisState::Supported,
                    vec![EvidenceCalibration::new(
                        EvidenceSelector::exists(unrelated),
                        Probability::from_percent(90).unwrap(),
                        Probability::from_percent(10).unwrap(),
                        "deliberately cannot bind the paired comparison",
                    )
                    .unwrap()],
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();

    let error = runtime
        .ingest_api_visibility(
            observation(
                "comparison-post-commit",
                ApiVisibilityPairKind::UiApi,
                ApiVisibilityResult::Different,
            ),
            &resource(),
        )
        .unwrap_err();

    assert!(matches!(
        &error,
        RuntimeApiVisibilityError::Observation(source)
            if matches!(source.reasoning_source(), Some(RuleEngineError::MissingCalibratedEvidence { .. }))
    ));
    let commit = error.committed_observation().unwrap();
    assert_eq!(commit.evidence_write(), KnowledgeWrite::Inserted);
    assert_eq!(commit.relation_write(), KnowledgeWrite::Inserted);
    assert!(runtime.knowledge().evidence(commit.evidence_id()).is_some());
    assert!(runtime.knowledge().relation(commit.relation_id()).is_some());

    let owned = error.into_committed_observation().unwrap();
    assert_eq!(owned.evidence_write(), KnowledgeWrite::Inserted);
}
