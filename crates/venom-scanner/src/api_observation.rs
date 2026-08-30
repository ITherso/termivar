//! Host-facing ingestion and projection for paired API visibility observations.
//!
//! ## Runtime scope
//!
//! - **Build:** always/default.
//! - **Execution:** Surface B support (paired API visibility workflow); host-facing.
//! - **Default `venom scan`:** no.
//! - **Support:** implemented and tested.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! This module bridges the evidence and decision engines without moving
//! network, credential, comparison, or planning policy into reasoning. The
//! authorized host establishes that two views describe the same logical
//! resource before it constructs an [`venom_core::ApiVisibilityObservation`].

use crate::knowledge::MAX_KNOWLEDGE_RELATION_ID_BYTES;

mod cursor;
mod ingest;
mod model;
mod query;
mod review;

pub use cursor::ApiVisibilityReviewCursor;
pub use ingest::ingest_api_visibility_observation;
pub use model::{ApiObservationCommitReceipt, ApiObservationError, ApiObservationReceipt};
pub use query::{
    api_visibility_reviews_for_resource, api_visibility_reviews_for_resource_v2,
    ApiVisibilityReviewPage, ApiVisibilityReviewQuery,
};
#[cfg(feature = "scanning")]
pub(crate) use review::api_visibility_review_for_commit;
pub use review::{ApiVisibilityReview, ApiVisibilityReviewDisposition};

#[cfg(test)]
use crate::{
    knowledge::{KnowledgeBase, KnowledgeBaseError, KnowledgeWrite},
    rules::{hypothesis_id_for_rule, RuleApplication, RuleEngine, RuleEngineError},
};
#[cfg(test)]
use venom_core::{
    ApiEvidencePredicate, ApiKnowledgePredicate, ApiVisibilityBoundaryKind, ApiVisibilityDimension,
    ApiVisibilityObservation, ConfidenceScore, EntityId, Evidence, EvidenceId, EvidenceKind,
    EvidenceValue, Hypothesis, KnowledgePredicate, RelationId, RelationKind,
};

const API_VISIBILITY_RELATION: &str = "api.visibility.resource-scope";
const API_VISIBILITY_EVIDENCE_KIND: &str = "api.visibility-comparison";
const API_VISIBILITY_SOURCE_METHOD: &str = "paired-api-visibility";
const COMPARISON_SUBJECT_PREFIX: &str = "api-comparison:";
const COMPARISON_EVIDENCE_PREFIX: &str = "api-comparison-evidence:";
const COMPARISON_RELATION_PREFIX: &str = "api-comparison-scope:";
const UI_API_BOUNDARY_RULE: &str = "api.visibility.ui-api.paired-difference";
const AUTHORIZATION_BOUNDARY_RULE: &str = "api.visibility.authorization-context.paired-difference";
const API_VISIBILITY_REVIEW_CURSOR_PREFIX: &str = "venom-api-review-v2:";
const API_VISIBILITY_REVIEW_CURSOR_DOMAIN: &[u8] = b"venom.api-visibility.review-cursor.v2\0";
const API_VISIBILITY_REVIEW_RESOURCE_DIGEST_HEX_BYTES: usize = 64;

/// Default number of incoming resource relations scanned by one review page.
pub const DEFAULT_API_VISIBILITY_REVIEW_SCAN_LIMIT: u16 = 128;
/// Hard ceiling for incoming resource relations scanned by one review page.
pub const HARD_MAX_API_VISIBILITY_REVIEW_SCAN_LIMIT: u16 = 1_024;
/// Hard byte ceiling for the producer component stored in a reviewable observation.
pub const MAX_API_VISIBILITY_SOURCE_COMPONENT_BYTES: usize = 256;
/// Hard byte ceiling for one boundary-hypothesis explanation in a review page.
pub const MAX_API_VISIBILITY_REVIEW_RATIONALE_BYTES: usize = 1_024;
/// Hard byte ceiling for one serialized resource-bound review cursor.
pub const MAX_API_VISIBILITY_REVIEW_CURSOR_BYTES: usize = API_VISIBILITY_REVIEW_CURSOR_PREFIX.len()
    + API_VISIBILITY_REVIEW_RESOURCE_DIGEST_HEX_BYTES
    + 1
    + (MAX_KNOWLEDGE_RELATION_ID_BYTES * 2);

#[cfg(test)]
mod tests {
    use venom_core::{
        ApiSurfaceKind, ApiVisibilityComparison, ApiVisibilityPairKind, ApiVisibilityResult,
        BayesianEvidence, EvidenceSource, HypothesisState, HypothesisStrength, Probability,
    };

    use super::*;
    use crate::{
        api_reasoning::StandardApiReasoning,
        rules::{
            EvidenceCalibration, EvidenceSelector, Expression, HypothesisConclusion,
            KnowledgeLayer, ReasoningRule,
        },
    };

    fn resource() -> EntityId {
        EntityId::new("resource:account-42").unwrap()
    }

    fn comparison(
        id: &str,
        result: ApiVisibilityResult,
        pair: ApiVisibilityPairKind,
    ) -> ApiVisibilityObservation {
        comparison_with_source(id, result, pair, "host.api-comparator")
    }

    fn comparison_with_source(
        id: &str,
        result: ApiVisibilityResult,
        pair: ApiVisibilityPairKind,
        source_component: impl Into<String>,
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
        .with_observed_at_ms(1_000)
        .to_observation(source_component, ConfidenceScore::MAX)
        .unwrap()
    }

    fn installed() -> (KnowledgeBase, RuleEngine) {
        let knowledge = KnowledgeBase::new();
        let mut rules = RuleEngine::new();
        StandardApiReasoning::new()
            .unwrap()
            .install(&knowledge, &mut rules)
            .unwrap();
        (knowledge, rules)
    }

    fn insert_forged_boundary(
        knowledge: &KnowledgeBase,
        evidence: &Evidence,
        rule_id: &str,
        boundary: ApiVisibilityBoundaryKind,
    ) {
        let mut hypothesis = Hypothesis::with_id(
            hypothesis_id_for_rule(rule_id, evidence.subject()),
            evidence.subject().clone(),
            ApiKnowledgePredicate::VISIBILITY_BOUNDARY.into_knowledge(),
            EvidenceValue::from(boundary),
            Probability::from_percent(10).unwrap(),
        )
        .unwrap();
        hypothesis
            .observe(
                BayesianEvidence::new(
                    evidence.id().clone(),
                    Probability::from_percent(98).unwrap(),
                    Probability::from_percent(2).unwrap(),
                    "deliberately forged boundary",
                )
                .unwrap(),
            )
            .unwrap();
        hypothesis.set_strength(HypothesisStrength::Weak);
        hypothesis.set_state(HypothesisState::Supported);
        knowledge.upsert_hypothesis(hypothesis).unwrap();
    }

    #[test]
    fn different_comparison_commits_and_projects_only_the_boundary() {
        let (knowledge, rules) = installed();
        let receipt = ingest_api_visibility_observation(
            comparison(
                "different",
                ApiVisibilityResult::Different,
                ApiVisibilityPairKind::AuthorizationContext,
            ),
            &resource(),
            &knowledge,
            &rules,
        )
        .unwrap();

        assert_eq!(receipt.commit().evidence_write(), KnowledgeWrite::Inserted);
        assert_eq!(receipt.commit().relation_write(), KnowledgeWrite::Inserted);
        let page = api_visibility_reviews_for_resource(
            &knowledge,
            &resource(),
            &ApiVisibilityReviewQuery::default(),
        );
        let reviews = page.reviews();
        assert_eq!(reviews.len(), 1);
        assert_eq!(
            reviews[0].disposition(),
            ApiVisibilityReviewDisposition::AwaitHumanReview
        );
        assert_eq!(reviews[0].boundary_hypotheses().len(), 1);
        let boundary = &reviews[0].boundary_hypotheses()[0];
        assert_eq!(
            boundary.value(),
            &EvidenceValue::from(ApiVisibilityBoundaryKind::AuthorizationContext)
        );
        assert_eq!(boundary.state(), HypothesisState::Supported);
        assert!(knowledge
            .hypotheses_for_subject(receipt.commit().comparison_subject())
            .iter()
            .any(|hypothesis| hypothesis.predicate()
                == &ApiKnowledgePredicate::SURFACE_KIND.into_knowledge()));
    }

    #[test]
    fn equivalent_comparison_has_a_surface_but_no_boundary() {
        let (knowledge, rules) = installed();
        let receipt = ingest_api_visibility_observation(
            comparison(
                "equivalent",
                ApiVisibilityResult::Equivalent,
                ApiVisibilityPairKind::UiApi,
            ),
            &resource(),
            &knowledge,
            &rules,
        )
        .unwrap();

        let hypotheses = knowledge.hypotheses_for_subject(receipt.commit().comparison_subject());
        assert!(hypotheses.iter().any(|hypothesis| hypothesis.predicate()
            == &ApiKnowledgePredicate::SURFACE_KIND.into_knowledge()));
        assert!(!hypotheses.iter().any(|hypothesis| hypothesis.predicate()
            == &ApiKnowledgePredicate::VISIBILITY_BOUNDARY.into_knowledge()));
        let page = api_visibility_reviews_for_resource(
            &knowledge,
            &resource(),
            &ApiVisibilityReviewQuery::default(),
        );
        let reviews = page.reviews();
        assert_eq!(reviews.len(), 1);
        assert_eq!(
            reviews[0].disposition(),
            ApiVisibilityReviewDisposition::NoDifferenceObserved
        );
        assert!(reviews[0].boundary_hypotheses().is_empty());
    }

    #[test]
    fn difference_without_reasoning_remains_explicitly_unresolved() {
        let knowledge = KnowledgeBase::new();
        let rules = RuleEngine::new();
        ingest_api_visibility_observation(
            comparison(
                "difference-without-rules",
                ApiVisibilityResult::Different,
                ApiVisibilityPairKind::AuthorizationContext,
            ),
            &resource(),
            &knowledge,
            &rules,
        )
        .unwrap();

        let page = api_visibility_reviews_for_resource(
            &knowledge,
            &resource(),
            &ApiVisibilityReviewQuery::default(),
        );
        assert_eq!(page.reviews().len(), 1);
        assert!(page.reviews()[0].boundary_hypotheses().is_empty());
        assert_eq!(
            page.reviews()[0].disposition(),
            ApiVisibilityReviewDisposition::UnresolvedDifference
        );
    }

    #[test]
    fn equivalent_evidence_cannot_be_projected_as_a_forged_boundary() {
        let (knowledge, rules) = installed();
        let receipt = ingest_api_visibility_observation(
            comparison(
                "equivalent-forgery",
                ApiVisibilityResult::Equivalent,
                ApiVisibilityPairKind::UiApi,
            ),
            &resource(),
            &knowledge,
            &rules,
        )
        .unwrap();
        let evidence = knowledge.evidence(receipt.commit().evidence_id()).unwrap();
        insert_forged_boundary(
            &knowledge,
            &evidence,
            UI_API_BOUNDARY_RULE,
            ApiVisibilityBoundaryKind::UiApi,
        );

        let page = api_visibility_reviews_for_resource(
            &knowledge,
            &resource(),
            &ApiVisibilityReviewQuery::default(),
        );
        assert_eq!(page.reviews().len(), 1);
        assert!(page.reviews()[0].boundary_hypotheses().is_empty());
    }

    #[test]
    fn authorization_evidence_ignores_a_forged_ui_boundary() {
        let (knowledge, rules) = installed();
        let receipt = ingest_api_visibility_observation(
            comparison(
                "pair-forgery",
                ApiVisibilityResult::Different,
                ApiVisibilityPairKind::AuthorizationContext,
            ),
            &resource(),
            &knowledge,
            &rules,
        )
        .unwrap();
        let evidence = knowledge.evidence(receipt.commit().evidence_id()).unwrap();
        insert_forged_boundary(
            &knowledge,
            &evidence,
            UI_API_BOUNDARY_RULE,
            ApiVisibilityBoundaryKind::UiApi,
        );

        let page = api_visibility_reviews_for_resource(
            &knowledge,
            &resource(),
            &ApiVisibilityReviewQuery::default(),
        );
        let boundaries = page.reviews()[0].boundary_hypotheses();
        assert_eq!(boundaries.len(), 1);
        assert_eq!(
            boundaries[0].value(),
            &EvidenceValue::from(ApiVisibilityBoundaryKind::AuthorizationContext)
        );
    }

    #[test]
    fn nonweak_boundary_is_not_promoted_to_human_review() {
        let knowledge = KnowledgeBase::new();
        let rules = RuleEngine::new();
        let receipt = ingest_api_visibility_observation(
            comparison(
                "strong-boundary-forgery",
                ApiVisibilityResult::Different,
                ApiVisibilityPairKind::AuthorizationContext,
            ),
            &resource(),
            &knowledge,
            &rules,
        )
        .unwrap();
        let evidence = knowledge.evidence(receipt.commit().evidence_id()).unwrap();
        insert_forged_boundary(
            &knowledge,
            &evidence,
            AUTHORIZATION_BOUNDARY_RULE,
            ApiVisibilityBoundaryKind::AuthorizationContext,
        );
        let mut forged = knowledge
            .hypotheses_for_subject(evidence.subject())
            .into_iter()
            .next()
            .unwrap();
        forged.set_strength(HypothesisStrength::Strong);
        knowledge.upsert_hypothesis(forged).unwrap();

        let page = api_visibility_reviews_for_resource(
            &knowledge,
            &resource(),
            &ApiVisibilityReviewQuery::default(),
        );
        assert!(page.reviews()[0].boundary_hypotheses().is_empty());
        assert_eq!(
            page.reviews()[0].disposition(),
            ApiVisibilityReviewDisposition::UnresolvedDifference
        );
    }

    #[test]
    fn exact_replay_is_idempotent_across_storage_and_reasoning() {
        let (knowledge, rules) = installed();
        let observation = comparison(
            "replay",
            ApiVisibilityResult::Different,
            ApiVisibilityPairKind::UiApi,
        );
        ingest_api_visibility_observation(observation.clone(), &resource(), &knowledge, &rules)
            .unwrap();
        let replay =
            ingest_api_visibility_observation(observation, &resource(), &knowledge, &rules)
                .unwrap();

        assert_eq!(replay.commit().evidence_write(), KnowledgeWrite::Unchanged);
        assert_eq!(replay.commit().relation_write(), KnowledgeWrite::Unchanged);
        assert!(replay
            .applications()
            .iter()
            .filter_map(RuleApplication::write)
            .all(|write| write == KnowledgeWrite::Unchanged));
        assert_eq!(
            api_visibility_reviews_for_resource(
                &knowledge,
                &resource(),
                &ApiVisibilityReviewQuery::default(),
            )
            .reviews()
            .len(),
            1
        );
    }

    #[test]
    fn observation_and_review_debug_output_redacts_opaque_identifiers() {
        let (knowledge, rules) = installed();
        let receipt = ingest_api_visibility_observation(
            comparison(
                "debug-redaction",
                ApiVisibilityResult::Different,
                ApiVisibilityPairKind::UiApi,
            ),
            &resource(),
            &knowledge,
            &rules,
        )
        .unwrap();
        let receipt_debug = format!("{receipt:?}");
        for opaque in [
            receipt.commit().comparison_subject().as_str(),
            receipt.commit().resource_scope().as_str(),
            receipt.commit().evidence_id().as_str(),
            receipt.commit().relation_id().as_str(),
        ] {
            assert!(!receipt_debug.contains(opaque));
        }
        assert!(receipt_debug.contains("application_count"));
        assert!(receipt_debug.contains("<redacted>"));

        let page = api_visibility_reviews_for_resource(
            &knowledge,
            &resource(),
            &ApiVisibilityReviewQuery::default(),
        );
        let review = &page.reviews()[0];
        let review_debug = format!("{review:?}");
        let page_debug = format!("{page:?}");
        for debug in [&review_debug, &page_debug] {
            for opaque in [
                review.resource_scope().as_str(),
                review.comparison_subject().as_str(),
                review.relation_id().as_str(),
                review.evidence().id().as_str(),
            ] {
                assert!(!debug.contains(opaque));
            }
            assert!(debug.contains("<redacted>"));
        }
    }

    #[test]
    fn resource_mismatch_fails_before_any_write() {
        let (knowledge, rules) = installed();
        let expected = EntityId::new("resource:another-account").unwrap();
        let error = ingest_api_visibility_observation(
            comparison(
                "wrong-resource",
                ApiVisibilityResult::Different,
                ApiVisibilityPairKind::UiApi,
            ),
            &expected,
            &knowledge,
            &rules,
        )
        .unwrap_err();

        assert!(matches!(
            &error,
            ApiObservationError::ResourceMismatch { .. }
        ));
        let display = error.to_string();
        let debug = format!("{error:?}");
        for opaque in [expected.as_str(), "resource:account-42"] {
            assert!(!display.contains(opaque));
            assert!(!debug.contains(opaque));
        }
        assert_eq!(
            display,
            "API visibility observation resource does not match expected resource"
        );
        assert!(debug.contains("<redacted>"));
        assert!(error.committed_observation().is_none());
        let stats = knowledge.stats();
        assert_eq!(stats.evidence, 0);
        assert_eq!(stats.relations, 0);
        assert_eq!(stats.hypotheses, 0);
    }

    #[test]
    fn post_commit_reasoning_error_carries_the_commit_receipt() {
        let knowledge = KnowledgeBase::new();
        let mut rules = RuleEngine::new();
        let comparison_predicate = ApiEvidencePredicate::JSON_UI_API_DIFFERENCE.into_knowledge();
        let unrelated = KnowledgePredicate::new("test", "unrelated").unwrap();
        rules
            .register(
                ReasoningRule::new(
                    "000.invalid-calibration",
                    Expression::exists(KnowledgeLayer::Evidence, comparison_predicate),
                    HypothesisConclusion::new(
                        KnowledgePredicate::new("test", "result").unwrap(),
                        EvidenceValue::Boolean(true),
                        Probability::from_percent(10).unwrap(),
                        venom_core::HypothesisStrength::Weak,
                        HypothesisState::Supported,
                        vec![EvidenceCalibration::new(
                            EvidenceSelector::exists(unrelated),
                            Probability::from_percent(90).unwrap(),
                            Probability::from_percent(10).unwrap(),
                            "deliberately cannot bind the matched comparison",
                        )
                        .unwrap()],
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        let error = ingest_api_visibility_observation(
            comparison(
                "post-commit-error",
                ApiVisibilityResult::Different,
                ApiVisibilityPairKind::UiApi,
            ),
            &resource(),
            &knowledge,
            &rules,
        )
        .unwrap_err();

        assert!(matches!(
            error.reasoning_source(),
            Some(RuleEngineError::MissingCalibratedEvidence { .. })
        ));
        let commit = error.committed_observation().unwrap();
        assert_eq!(commit.evidence_write(), KnowledgeWrite::Inserted);
        assert_eq!(commit.relation_write(), KnowledgeWrite::Inserted);
        assert!(knowledge.evidence(commit.evidence_id()).is_some());
        assert!(knowledge.relation(commit.relation_id()).is_some());
    }

    #[test]
    fn resource_projection_is_stable_and_ignores_noncanonical_relations() {
        let (knowledge, rules) = installed();
        for observation in [
            comparison(
                "second",
                ApiVisibilityResult::Different,
                ApiVisibilityPairKind::AuthorizationContext,
            ),
            comparison(
                "first",
                ApiVisibilityResult::Equivalent,
                ApiVisibilityPairKind::UiApi,
            ),
        ] {
            ingest_api_visibility_observation(observation, &resource(), &knowledge, &rules)
                .unwrap();
        }

        let unrelated = Evidence::new(
            EntityId::new("not-a-comparison").unwrap(),
            EvidenceKind::Custom(API_VISIBILITY_EVIDENCE_KIND.to_owned()),
            ApiEvidencePredicate::JSON_UI_API_DIFFERENCE.into_knowledge(),
            EvidenceValue::from(ApiVisibilityDimension::Fields),
            EvidenceSource::new("forged", API_VISIBILITY_SOURCE_METHOD).unwrap(),
            ConfidenceScore::MAX,
        );
        let unrelated_id = unrelated.id().clone();
        let unrelated_subject = unrelated.subject().clone();
        knowledge.insert_evidence(unrelated).unwrap();
        knowledge
            .upsert_relation(venom_core::KnowledgeRelation::new(
                unrelated_subject,
                resource(),
                RelationKind::Custom(API_VISIBILITY_RELATION.to_owned()),
                ConfidenceScore::MAX,
                unrelated_id,
            ))
            .unwrap();

        let query = ApiVisibilityReviewQuery::default();
        let first = api_visibility_reviews_for_resource(&knowledge, &resource(), &query);
        let second = api_visibility_reviews_for_resource(&knowledge, &resource(), &query);
        assert_eq!(first, second);
        assert_eq!(first.reviews().len(), 2);
        assert!(first
            .reviews()
            .windows(2)
            .all(|pair| pair[0].relation_id() < pair[1].relation_id()));
        assert!(first.reviews().iter().all(|review| {
            review.evidence().subject() == review.comparison_subject()
                && review.resource_scope() == &resource()
        }));
    }

    #[test]
    fn oversized_observation_provenance_is_rejected_before_commit() {
        let knowledge = KnowledgeBase::new();
        let rules = RuleEngine::new();
        let observation = comparison_with_source(
            "oversized-source",
            ApiVisibilityResult::Different,
            ApiVisibilityPairKind::UiApi,
            "s".repeat(MAX_API_VISIBILITY_SOURCE_COMPONENT_BYTES + 1),
        );

        assert!(matches!(
            ingest_api_visibility_observation(observation, &resource(), &knowledge, &rules),
            Err(ApiObservationError::ObservationLimitExceeded {
                field: "source.component",
                ..
            })
        ));
        let stats = knowledge.stats();
        assert_eq!(stats.evidence, 0);
        assert_eq!(stats.relations, 0);
    }

    #[test]
    fn projection_rejects_oversized_records_from_direct_store_writers() {
        let knowledge = KnowledgeBase::new();
        let observation = comparison_with_source(
            "direct-oversized-source",
            ApiVisibilityResult::Different,
            ApiVisibilityPairKind::UiApi,
            "s".repeat(MAX_API_VISIBILITY_SOURCE_COMPONENT_BYTES + 1),
        );
        let (evidence, relation) = observation.into_parts();
        knowledge
            .insert_evidence_with_relation(evidence, relation)
            .unwrap();

        let page = api_visibility_reviews_for_resource(
            &knowledge,
            &resource(),
            &ApiVisibilityReviewQuery::default(),
        );
        assert_eq!(page.scanned_relations(), 1);
        assert!(page.reviews().is_empty());
    }

    #[test]
    fn projection_does_not_clone_an_oversized_boundary_rationale() {
        let (knowledge, rules) = installed();
        let receipt = ingest_api_visibility_observation(
            comparison(
                "oversized-rationale",
                ApiVisibilityResult::Different,
                ApiVisibilityPairKind::UiApi,
            ),
            &resource(),
            &knowledge,
            &rules,
        )
        .unwrap();
        let evidence = knowledge.evidence(receipt.commit().evidence_id()).unwrap();
        let mut hypothesis = Hypothesis::with_id(
            hypothesis_id_for_rule(UI_API_BOUNDARY_RULE, evidence.subject()),
            evidence.subject().clone(),
            ApiKnowledgePredicate::VISIBILITY_BOUNDARY.into_knowledge(),
            EvidenceValue::from(ApiVisibilityBoundaryKind::UiApi),
            Probability::from_percent(10).unwrap(),
        )
        .unwrap();
        hypothesis
            .observe(
                BayesianEvidence::new(
                    evidence.id().clone(),
                    Probability::from_percent(98).unwrap(),
                    Probability::from_percent(2).unwrap(),
                    "r".repeat(MAX_API_VISIBILITY_REVIEW_RATIONALE_BYTES + 1),
                )
                .unwrap(),
            )
            .unwrap();
        hypothesis.set_strength(HypothesisStrength::Strong);
        hypothesis.set_state(HypothesisState::Supported);
        knowledge.upsert_hypothesis(hypothesis).unwrap();

        let page = api_visibility_reviews_for_resource(
            &knowledge,
            &resource(),
            &ApiVisibilityReviewQuery::default(),
        );
        assert_eq!(page.reviews().len(), 1);
        assert!(page.reviews()[0].boundary_hypotheses().is_empty());
    }

    #[test]
    fn review_query_is_strict_and_enforces_the_compiled_ceiling() {
        assert!(matches!(
            ApiVisibilityReviewQuery::new(0),
            Err(ApiObservationError::ZeroReviewScanLimit)
        ));
        assert!(matches!(
            ApiVisibilityReviewQuery::new(HARD_MAX_API_VISIBILITY_REVIEW_SCAN_LIMIT + 1),
            Err(ApiObservationError::ReviewScanLimitExceeded { .. })
        ));
        assert!(
            serde_json::from_value::<ApiVisibilityReviewQuery>(serde_json::json!({
                "scan_limit": 0
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<ApiVisibilityReviewQuery>(serde_json::json!({
                "scan_limit": 1,
                "unexpected": true
            }))
            .is_err()
        );
        let oversized_cursor =
            RelationId::parse("r".repeat(MAX_KNOWLEDGE_RELATION_ID_BYTES + 1)).unwrap();
        assert!(matches!(
            ApiVisibilityReviewQuery::new(1)
                .unwrap()
                .after_relation_id(oversized_cursor.clone()),
            Err(ApiObservationError::ReviewCursorTooLong { .. })
        ));
        assert!(
            serde_json::from_value::<ApiVisibilityReviewQuery>(serde_json::json!({
                "after_relation_id": oversized_cursor,
                "scan_limit": 1
            }))
            .is_err()
        );

        let cursor = RelationId::parse("relation:cursor").unwrap();
        let query = ApiVisibilityReviewQuery::new(7)
            .unwrap()
            .after_relation_id(cursor.clone())
            .unwrap();
        let decoded: ApiVisibilityReviewQuery =
            serde_json::from_value(serde_json::to_value(&query).unwrap()).unwrap();
        assert_eq!(decoded, query);
        assert_eq!(decoded.after(), Some(&cursor));
        assert_eq!(decoded.scan_limit(), 7);
        let debug = format!("{decoded:?}");
        assert!(!debug.contains(cursor.as_str()));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn resource_bound_cursor_round_trips_and_paginates_same_resource() {
        let (knowledge, rules) = installed();
        for id in ["cursor-page-a", "cursor-page-b", "cursor-page-c"] {
            ingest_api_visibility_observation(
                comparison(
                    id,
                    ApiVisibilityResult::Different,
                    ApiVisibilityPairKind::UiApi,
                ),
                &resource(),
                &knowledge,
                &rules,
            )
            .unwrap();
        }

        let first =
            api_visibility_reviews_for_resource_v2(&knowledge, &resource(), None, 1).unwrap();
        assert_eq!(first.scanned_relations(), 1);
        assert_eq!(first.reviews().len(), 1);
        let cursor = first.next_cursor().unwrap().unwrap();
        let decoded: ApiVisibilityReviewCursor =
            serde_json::from_value(serde_json::to_value(&cursor).unwrap()).unwrap();
        assert_eq!(decoded, cursor);
        assert_eq!(decoded.version(), 2);

        let second =
            api_visibility_reviews_for_resource_v2(&knowledge, &resource(), Some(&decoded), 1)
                .unwrap();
        assert_eq!(second.scanned_relations(), 1);
        assert_eq!(second.reviews().len(), 1);
        assert_ne!(
            first.reviews()[0].relation_id(),
            second.reviews()[0].relation_id()
        );
    }

    #[test]
    fn resource_bound_cursor_rejects_cross_resource_replay_without_leaking_ids() {
        let source = resource();
        let target = EntityId::new("resource:another-sensitive-account").unwrap();
        let relation = RelationId::parse("relation:sensitive-position").unwrap();
        let cursor = ApiVisibilityReviewCursor::new(&source, relation.clone()).unwrap();
        let error = api_visibility_reviews_for_resource_v2(
            &KnowledgeBase::new(),
            &target,
            Some(&cursor),
            1,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ApiObservationError::ResourceBoundReviewCursorMismatch
        ));
        for output in [error.to_string(), format!("{error:?}")] {
            assert!(!output.contains(source.as_str()));
            assert!(!output.contains(target.as_str()));
            assert!(!output.contains(relation.as_str()));
            assert!(!output.contains(cursor.as_str()));
        }
    }

    #[test]
    fn resource_bound_cursor_rejects_malformed_versioned_and_oversized_tokens() {
        assert!(matches!(
            ApiVisibilityReviewCursor::parse("not-a-review-cursor"),
            Err(ApiObservationError::InvalidResourceBoundReviewCursor { .. })
        ));
        assert!(matches!(
            ApiVisibilityReviewCursor::parse("venom-api-review-v3:payload"),
            Err(ApiObservationError::UnsupportedResourceBoundReviewCursorVersion)
        ));
        assert!(matches!(
            ApiVisibilityReviewCursor::parse(
                "x".repeat(MAX_API_VISIBILITY_REVIEW_CURSOR_BYTES + 1)
            ),
            Err(ApiObservationError::ResourceBoundReviewCursorTooLong { .. })
        ));

        let cursor = ApiVisibilityReviewCursor::new(
            &resource(),
            RelationId::parse("relation:cursor").unwrap(),
        )
        .unwrap();
        let mut uppercase = cursor.as_str().to_owned();
        uppercase.pop();
        uppercase.push('A');
        assert!(matches!(
            ApiVisibilityReviewCursor::parse(uppercase),
            Err(ApiObservationError::InvalidResourceBoundReviewCursor { .. })
        ));
        let mut odd = cursor.as_str().to_owned();
        odd.pop();
        assert!(
            serde_json::from_value::<ApiVisibilityReviewCursor>(serde_json::json!(odd)).is_err()
        );
    }

    #[test]
    fn resource_bound_cursor_serialization_is_transparent_and_debug_is_redacted() {
        let resource = resource();
        let relation = RelationId::parse("relation:sensitive-cursor").unwrap();
        let cursor = ApiVisibilityReviewCursor::new(&resource, relation.clone()).unwrap();

        assert_eq!(
            serde_json::to_value(&cursor).unwrap(),
            serde_json::Value::String(cursor.as_str().to_owned())
        );
        assert!(!cursor.as_str().contains(resource.as_str()));
        assert!(!cursor.as_str().contains(relation.as_str()));
        for output in [format!("{cursor:?}"), cursor.to_string()] {
            assert!(output.contains("<redacted>"));
            assert!(!output.contains(cursor.as_str()));
            assert!(!output.contains(resource.as_str()));
            assert!(!output.contains(relation.as_str()));
        }
    }

    #[test]
    fn legacy_review_query_wire_shape_remains_unchanged() {
        let cursor = RelationId::parse("relation:legacy-cursor").unwrap();
        let query = ApiVisibilityReviewQuery::new(7)
            .unwrap()
            .after_relation_id(cursor)
            .unwrap();

        assert_eq!(
            serde_json::to_value(query).unwrap(),
            serde_json::json!({
                "after_relation_id": "relation:legacy-cursor",
                "scan_limit": 7
            })
        );
    }

    #[test]
    fn review_pages_advance_by_the_last_scanned_relation() {
        let (knowledge, rules) = installed();
        for id in ["page-a", "page-b", "page-c"] {
            ingest_api_visibility_observation(
                comparison(
                    id,
                    ApiVisibilityResult::Different,
                    ApiVisibilityPairKind::UiApi,
                ),
                &resource(),
                &knowledge,
                &rules,
            )
            .unwrap();
        }

        let mut query = ApiVisibilityReviewQuery::new(1).unwrap();
        let mut seen = Vec::new();
        loop {
            let page = api_visibility_reviews_for_resource(&knowledge, &resource(), &query);
            assert_eq!(page.scanned_relations(), 1);
            assert_eq!(page.reviews().len(), 1);
            seen.push(page.reviews()[0].relation_id().clone());
            let Some(cursor) = page.next_after_relation_id().cloned() else {
                break;
            };
            query = ApiVisibilityReviewQuery::new(1)
                .unwrap()
                .after_relation_id(cursor)
                .unwrap();
        }

        assert_eq!(seen.len(), 3);
        assert!(seen.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn rejected_relations_consume_the_page_scan_budget() {
        let (knowledge, rules) = installed();
        let invalid = Evidence::new(
            EntityId::new("invalid-comparison").unwrap(),
            EvidenceKind::Custom(API_VISIBILITY_EVIDENCE_KIND.to_owned()),
            ApiEvidencePredicate::JSON_UI_API_DIFFERENCE.into_knowledge(),
            EvidenceValue::from(ApiVisibilityDimension::Fields),
            EvidenceSource::new("untrusted", API_VISIBILITY_SOURCE_METHOD).unwrap(),
            ConfidenceScore::MAX,
        );
        let invalid_id = invalid.id().clone();
        let invalid_subject = invalid.subject().clone();
        knowledge.insert_evidence(invalid).unwrap();
        knowledge
            .upsert_relation(venom_core::KnowledgeRelation::with_id(
                RelationId::parse("000-invalid-relation").unwrap(),
                invalid_subject,
                resource(),
                RelationKind::Custom(API_VISIBILITY_RELATION.to_owned()),
                ConfidenceScore::MAX,
                invalid_id,
            ))
            .unwrap();
        ingest_api_visibility_observation(
            comparison(
                "valid-after-invalid",
                ApiVisibilityResult::Different,
                ApiVisibilityPairKind::UiApi,
            ),
            &resource(),
            &knowledge,
            &rules,
        )
        .unwrap();

        let first_query = ApiVisibilityReviewQuery::new(1).unwrap();
        let first = api_visibility_reviews_for_resource(&knowledge, &resource(), &first_query);
        assert_eq!(first.scanned_relations(), 1);
        assert!(first.reviews().is_empty());
        let cursor = first.next_after_relation_id().cloned().unwrap();
        assert_eq!(cursor.as_str(), "000-invalid-relation");
        let page_debug = format!("{first:?}");
        assert!(!page_debug.contains(cursor.as_str()));
        assert!(page_debug.contains("<redacted>"));

        let second_query = ApiVisibilityReviewQuery::new(1)
            .unwrap()
            .after_relation_id(cursor)
            .unwrap();
        let second = api_visibility_reviews_for_resource(&knowledge, &resource(), &second_query);
        assert_eq!(second.scanned_relations(), 1);
        assert_eq!(second.reviews().len(), 1);
        assert!(second.next_after_relation_id().is_none());
    }

    #[test]
    fn oversized_relation_is_rejected_before_it_can_reach_review_projection() {
        let knowledge = KnowledgeBase::new();
        let relation = venom_core::KnowledgeRelation::with_id(
            RelationId::parse("r".repeat(crate::knowledge::MAX_KNOWLEDGE_RELATION_ID_BYTES + 1))
                .unwrap(),
            EntityId::new("comparison:oversized-relation").unwrap(),
            resource(),
            RelationKind::Custom(API_VISIBILITY_RELATION.to_owned()),
            ConfidenceScore::MAX,
            EvidenceId::parse("evidence:oversized-relation").unwrap(),
        );

        assert!(matches!(
            knowledge.upsert_relation(relation),
            Err(KnowledgeBaseError::RelationLimitExceeded { field: "id", .. })
        ));
        let page = api_visibility_reviews_for_resource(
            &knowledge,
            &resource(),
            &ApiVisibilityReviewQuery::default(),
        );
        assert_eq!(page.scanned_relations(), 0);
        assert!(page.reviews().is_empty());
        assert!(page.next_after_relation_id().is_none());
    }
}
