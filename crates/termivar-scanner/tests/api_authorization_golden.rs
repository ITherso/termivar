use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use termivar_core::{
    ApiKnowledgePredicate, ApiSurfaceKind, ApiVisibilityBoundaryKind, ApiVisibilityDimension,
    ApiVisibilityPairKind, ApiVisibilityResult, ConfidenceScore, EntityId, EvidenceValue,
    HypothesisState, HypothesisStrength,
};
use termivar_scanner::{
    api_visibility_reviews_for_resource, ingest_api_visibility_observation, ApiComparisonProfile,
    ApiVisibilityComparator, ApiVisibilityReviewDisposition, ApiVisibilityReviewQuery,
    JsonPathPattern, KnowledgeBase, KnowledgeWrite, PathDigest, ProfiledApiVisibilityComparison,
    RuleEngine, StandardApiReasoning, MAX_API_VISIBILITY_REVIEW_RATIONALE_BYTES,
};

const OBSERVED_AT_MS: u64 = 1_800_000_000_000;
const MAX_DIFF_PATHS: u16 = 8;
const FIXTURES: &[&str] = &[
    include_str!("fixtures/api_authorization/ui_api.json"),
    include_str!("fixtures/api_authorization/anonymous_authenticated.json"),
    include_str!("fixtures/api_authorization/owner_unrelated.json"),
    include_str!("fixtures/api_authorization/read_write_capability.json"),
];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExpectedDiffCategory {
    Added,
    Removed,
    ChangedValue,
}

#[derive(Debug, Deserialize)]
struct GoldenFixture {
    name: String,
    comparison_id: String,
    pair: ApiVisibilityPairKind,
    dimension: ApiVisibilityDimension,
    baseline_context: String,
    candidate_context: String,
    resource_scope: String,
    expected_category: ExpectedDiffCategory,
    expected_path: String,
    expected_path_digest: String,
    expected_projection_policy_id: String,
    expected_comparison_subject: String,
    expected_envelope_sha256: String,
    expected_omitted_diff_count: u32,
    forbidden_values: Vec<String>,
    baseline: Value,
    candidate: Value,
}

fn fixture(encoded: &str) -> GoldenFixture {
    serde_json::from_str(encoded).unwrap()
}

fn profile() -> ApiComparisonProfile {
    ApiComparisonProfile::new(
        Vec::new(),
        ["/meta/request_id", "/meta/timestamp"]
            .into_iter()
            .map(|path| JsonPathPattern::new(path).unwrap())
            .collect(),
        Vec::new(),
        MAX_DIFF_PATHS,
    )
    .unwrap()
}

fn compare(fixture: &GoldenFixture) -> ProfiledApiVisibilityComparison {
    let comparator = ApiVisibilityComparator::default();
    let profile = profile();
    let baseline = comparator
        .capture_profiled_view(
            &profile,
            &fixture.baseline_context,
            &fixture.resource_scope,
            ApiSurfaceKind::JsonHttp,
            200,
            &fixture.baseline,
        )
        .unwrap();
    let candidate = comparator
        .capture_profiled_view(
            &profile,
            &fixture.candidate_context,
            &fixture.resource_scope,
            ApiSurfaceKind::JsonHttp,
            200,
            &fixture.candidate,
        )
        .unwrap();
    comparator
        .compare_profiled(
            &profile,
            &fixture.comparison_id,
            fixture.pair,
            fixture.dimension,
            &baseline,
            &candidate,
            OBSERVED_AT_MS,
        )
        .unwrap()
}

fn expected_boundary(pair: ApiVisibilityPairKind) -> ApiVisibilityBoundaryKind {
    match pair {
        ApiVisibilityPairKind::UiApi => ApiVisibilityBoundaryKind::UiApi,
        ApiVisibilityPairKind::AuthorizationContext => {
            ApiVisibilityBoundaryKind::AuthorizationContext
        },
        _ => panic!("golden fixture uses an unsupported visibility pair"),
    }
}

fn retained_diff_count(comparison: &ProfiledApiVisibilityComparison) -> usize {
    let diff = comparison.diff();
    diff.added_path_hashes().len()
        + diff.removed_path_hashes().len()
        + diff.changed_type_path_hashes().len()
        + diff.changed_value_path_hashes().len()
}

fn assert_expected_explanation(
    fixture: &GoldenFixture,
    comparison: &ProfiledApiVisibilityComparison,
) {
    let expected = PathDigest::for_pattern(&JsonPathPattern::new(&fixture.expected_path).unwrap());
    assert_eq!(expected.to_string(), fixture.expected_path_digest);
    assert_eq!(
        comparison.projection_policy_id().to_string(),
        fixture.expected_projection_policy_id
    );
    assert_eq!(
        comparison.comparison().subject().to_string(),
        fixture.expected_comparison_subject
    );
    assert_eq!(
        format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(comparison).unwrap())
        ),
        fixture.expected_envelope_sha256
    );
    let diff = comparison.diff();
    let observed = match fixture.expected_category {
        ExpectedDiffCategory::Added => diff.added_path_hashes(),
        ExpectedDiffCategory::Removed => diff.removed_path_hashes(),
        ExpectedDiffCategory::ChangedValue => diff.changed_value_path_hashes(),
    };

    assert_eq!(observed, [expected], "fixture {}", fixture.name);
    assert_eq!(
        retained_diff_count(comparison),
        1,
        "fixture {}",
        fixture.name
    );
    assert!(retained_diff_count(comparison) <= usize::from(MAX_DIFF_PATHS));
    assert_eq!(
        diff.omitted_diff_count(),
        fixture.expected_omitted_diff_count,
        "fixture {}",
        fixture.name
    );

    let serialized = serde_json::to_string(comparison).unwrap();
    let debug = format!("{comparison:?}");
    assert!(!serialized.contains(&fixture.expected_path));
    assert!(!debug.contains(&fixture.expected_path));
    for forbidden in &fixture.forbidden_values {
        assert!(!serialized.contains(forbidden), "fixture {}", fixture.name);
        assert!(!debug.contains(forbidden), "fixture {}", fixture.name);
    }
}

#[test]
fn authorization_golden_scenarios_end_in_review_without_a_vulnerability_verdict() {
    for encoded in FIXTURES {
        let fixture = fixture(encoded);
        let comparison = compare(&fixture);
        let replay = compare(&fixture);
        assert_eq!(comparison, replay, "fixture {}", fixture.name);
        assert_eq!(
            comparison.comparison().subject(),
            replay.comparison().subject(),
            "fixture {}",
            fixture.name
        );
        assert_eq!(
            comparison.comparison().result(),
            ApiVisibilityResult::Different,
            "fixture {}",
            fixture.name
        );
        assert_expected_explanation(&fixture, &comparison);

        let resource = EntityId::new(&fixture.resource_scope).unwrap();
        let knowledge = KnowledgeBase::new();
        let mut rules = RuleEngine::new();
        StandardApiReasoning::new()
            .unwrap()
            .install(&knowledge, &mut rules)
            .unwrap();
        let observation = comparison
            .to_observation("golden.api-comparator", ConfidenceScore::MAX)
            .unwrap();
        assert_eq!(
            observation.evidence().subject(),
            &comparison.comparison().subject()
        );
        let first =
            ingest_api_visibility_observation(observation.clone(), &resource, &knowledge, &rules)
                .unwrap();

        let page = api_visibility_reviews_for_resource(
            &knowledge,
            &resource,
            &ApiVisibilityReviewQuery::default(),
        );
        assert_eq!(page.reviews().len(), 1, "fixture {}", fixture.name);
        let review = &page.reviews()[0];
        assert_eq!(review.evidence().id(), first.commit().evidence_id());
        assert_eq!(
            review.comparison_subject(),
            first.commit().comparison_subject()
        );
        assert_eq!(
            review.disposition(),
            ApiVisibilityReviewDisposition::AwaitHumanReview
        );
        assert!(serde_json::to_value(review)
            .unwrap()
            .get("disposition")
            .is_none());

        assert_eq!(review.boundary_hypotheses().len(), 1);
        let boundary = &review.boundary_hypotheses()[0];
        assert_eq!(
            boundary.predicate(),
            &ApiKnowledgePredicate::VISIBILITY_BOUNDARY.into_knowledge()
        );
        assert_eq!(boundary.strength(), HypothesisStrength::Weak);
        assert_eq!(boundary.state(), HypothesisState::Supported);
        assert_eq!(
            boundary.value(),
            &EvidenceValue::from(expected_boundary(fixture.pair))
        );
        assert_eq!(boundary.belief().evidence().len(), 1);
        assert_eq!(
            boundary.belief().evidence()[0].evidence_id(),
            review.evidence().id()
        );
        assert!(
            boundary.belief().evidence()[0].rationale().len()
                <= MAX_API_VISIBILITY_REVIEW_RATIONALE_BYTES
        );

        let hypotheses = knowledge.hypotheses_for_subject(review.comparison_subject());
        assert_eq!(hypotheses.len(), 2, "fixture {}", fixture.name);
        assert!(hypotheses.iter().all(|hypothesis| {
            hypothesis.predicate() == &ApiKnowledgePredicate::SURFACE_KIND.into_knowledge()
                || hypothesis.predicate()
                    == &ApiKnowledgePredicate::VISIBILITY_BOUNDARY.into_knowledge()
        }));
        assert!(hypotheses.iter().all(|hypothesis| !matches!(
            hypothesis.state(),
            HypothesisState::Confirmed | HypothesisState::Rejected
        )));

        let replay_receipt =
            ingest_api_visibility_observation(observation, &resource, &knowledge, &rules).unwrap();
        assert_eq!(
            replay_receipt.commit().evidence_write(),
            KnowledgeWrite::Unchanged
        );
        assert_eq!(
            replay_receipt.commit().relation_write(),
            KnowledgeWrite::Unchanged
        );
    }
}

#[test]
fn equivalent_and_unreasoned_differences_never_auto_escalate() {
    let fixture = fixture(FIXTURES[0]);
    let comparator = ApiVisibilityComparator::default();
    let profile = profile();
    let baseline = comparator
        .capture_profiled_view(
            &profile,
            &fixture.baseline_context,
            &fixture.resource_scope,
            ApiSurfaceKind::JsonHttp,
            200,
            &fixture.baseline,
        )
        .unwrap();
    let equivalent_candidate = comparator
        .capture_profiled_view(
            &profile,
            &fixture.candidate_context,
            &fixture.resource_scope,
            ApiSurfaceKind::JsonHttp,
            200,
            &fixture.baseline,
        )
        .unwrap();
    let equivalent = comparator
        .compare_profiled(
            &profile,
            "golden:equivalent-control",
            fixture.pair,
            fixture.dimension,
            &baseline,
            &equivalent_candidate,
            OBSERVED_AT_MS,
        )
        .unwrap();
    assert_eq!(
        equivalent.comparison().result(),
        ApiVisibilityResult::Equivalent
    );
    assert!(equivalent.diff().is_empty());

    let resource = EntityId::new(&fixture.resource_scope).unwrap();
    let equivalent_knowledge = KnowledgeBase::new();
    let mut installed_rules = RuleEngine::new();
    StandardApiReasoning::new()
        .unwrap()
        .install(&equivalent_knowledge, &mut installed_rules)
        .unwrap();
    ingest_api_visibility_observation(
        equivalent
            .to_observation("golden.api-comparator", ConfidenceScore::MAX)
            .unwrap(),
        &resource,
        &equivalent_knowledge,
        &installed_rules,
    )
    .unwrap();
    let equivalent_page = api_visibility_reviews_for_resource(
        &equivalent_knowledge,
        &resource,
        &ApiVisibilityReviewQuery::default(),
    );
    assert_eq!(
        equivalent_page.reviews()[0].disposition(),
        ApiVisibilityReviewDisposition::NoDifferenceObserved
    );

    let difference = compare(&fixture);
    let unresolved_knowledge = KnowledgeBase::new();
    ingest_api_visibility_observation(
        difference
            .to_observation("golden.api-comparator", ConfidenceScore::MAX)
            .unwrap(),
        &resource,
        &unresolved_knowledge,
        &RuleEngine::new(),
    )
    .unwrap();
    let unresolved_page = api_visibility_reviews_for_resource(
        &unresolved_knowledge,
        &resource,
        &ApiVisibilityReviewQuery::default(),
    );
    assert_eq!(
        unresolved_page.reviews()[0].disposition(),
        ApiVisibilityReviewDisposition::UnresolvedDifference
    );
    assert!(unresolved_page.reviews()[0]
        .boundary_hypotheses()
        .is_empty());
}
