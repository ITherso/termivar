use serde_json::json;
use venom_core::{
    ApiSurfaceKind, ApiVisibilityDimension, ApiVisibilityPairKind, ApiVisibilityResult,
};

use super::*;

fn path(value: &str) -> JsonPathPattern {
    JsonPathPattern::new(value).unwrap()
}

fn profile(
    selected: &[&str],
    ignored: &[&str],
    unordered: &[&str],
    max_diff_paths: u16,
) -> ApiComparisonProfile {
    ApiComparisonProfile::new(
        selected.iter().map(|value| path(value)).collect(),
        ignored.iter().map(|value| path(value)).collect(),
        unordered.iter().map(|value| path(value)).collect(),
        max_diff_paths,
    )
    .unwrap()
}

fn view(
    comparator: &ApiVisibilityComparator,
    profile: &ApiComparisonProfile,
    context: &str,
    snapshot: &Value,
) -> ProfiledApiVisibilityView {
    comparator
        .capture_profiled_view(
            profile,
            context,
            "resource:account-42",
            ApiSurfaceKind::JsonHttp,
            200,
            snapshot,
        )
        .unwrap()
}

fn compare(
    comparator: &ApiVisibilityComparator,
    profile: &ApiComparisonProfile,
    dimension: ApiVisibilityDimension,
    baseline: &ProfiledApiVisibilityView,
    candidate: &ProfiledApiVisibilityView,
) -> ProfiledApiVisibilityComparison {
    comparator
        .compare_profiled(
            profile,
            "comparison:fixture-17",
            ApiVisibilityPairKind::AuthorizationContext,
            dimension,
            baseline,
            candidate,
            42,
        )
        .unwrap()
}

#[test]
fn json_pointer_accepts_root_escapes_and_wildcard_extension() {
    assert!(path("").tokens.is_empty());
    let escaped = path("/a~1b/~0key/0");
    assert_eq!(escaped.tokens, ["a/b", "~key", "0"]);
    assert_eq!(escaped.as_str(), "/a~1b/~0key/0");
    assert_eq!(path("/items/*/id").tokens, ["items", "*", "id"]);
}

#[test]
fn json_pointer_rejects_relative_fragment_invalid_escape_and_excessive_size() {
    for invalid in ["a/b", "#/a", "/a~2b", "/a~"] {
        assert!(matches!(
            JsonPathPattern::new(invalid),
            Err(ProfiledApiVisibilityError::InvalidPathPattern { .. })
        ));
    }
    assert!(matches!(
        JsonPathPattern::new(format!(
            "/{}",
            "x".repeat(HARD_MAX_API_COMPARISON_PATH_BYTES)
        )),
        Err(ProfiledApiVisibilityError::PathTooLong { .. })
    ));
}

#[test]
fn profile_normalizes_order_duplicates_and_covered_descendants() {
    let first = profile(&["/data/name", "/data", "/data", "/z"], &["/meta"], &[], 7);
    let second = profile(&["/z", "/data"], &["/meta/request", "/meta"], &[], 7);

    assert_eq!(first, second);
    assert_eq!(first.selected_paths().len(), 2);
    assert_eq!(first.ignored_paths(), &[path("/meta")]);
    assert_eq!(first.projection_policy_id(), second.projection_policy_id());
}

#[test]
fn profile_rejects_selected_path_inside_ignored_subtree() {
    assert!(matches!(
        ApiComparisonProfile::new(
            vec![path("/data/private/id")],
            vec![path("/data/private")],
            vec![],
            8
        ),
        Err(ProfiledApiVisibilityError::ConflictingPathPolicy)
    ));
    assert!(
        ApiComparisonProfile::new(vec![path("/data")], vec![path("/data/private")], vec![], 8,)
            .is_ok()
    );
}

#[test]
fn selected_projection_ignores_unselected_volatile_fields() {
    let comparator = ApiVisibilityComparator::default();
    let profile = profile(&["/data"], &[], &[], 16);
    let baseline = view(
        &comparator,
        &profile,
        "anonymous",
        &json!({"data":{"id":1},"meta":{"timestamp":1}}),
    );
    let candidate = view(
        &comparator,
        &profile,
        "member",
        &json!({"data":{"id":1},"meta":{"timestamp":999}}),
    );

    let comparison = compare(
        &comparator,
        &profile,
        ApiVisibilityDimension::Resources,
        &baseline,
        &candidate,
    );
    assert_eq!(
        comparison.comparison().result(),
        ApiVisibilityResult::Equivalent
    );
    assert!(comparison.diff().is_empty());
}

#[test]
fn ignored_pointer_prunes_only_its_exact_subtree() {
    let comparator = ApiVisibilityComparator::default();
    let profile = profile(&[], &["/meta/request_id"], &[], 16);
    let baseline = view(
        &comparator,
        &profile,
        "anonymous",
        &json!({"meta":{"request_id":"a","request_idx":1}}),
    );
    let ignored_only = view(
        &comparator,
        &profile,
        "member",
        &json!({"meta":{"request_id":"b","request_idx":1}}),
    );
    let retained_change = view(
        &comparator,
        &profile,
        "other",
        &json!({"meta":{"request_id":"b","request_idx":2}}),
    );

    assert_eq!(
        compare(
            &comparator,
            &profile,
            ApiVisibilityDimension::Resources,
            &baseline,
            &ignored_only,
        )
        .comparison()
        .result(),
        ApiVisibilityResult::Equivalent
    );
    assert_eq!(
        compare(
            &comparator,
            &profile,
            ApiVisibilityDimension::Resources,
            &baseline,
            &retained_change,
        )
        .comparison()
        .result(),
        ApiVisibilityResult::Different
    );
}

#[test]
fn escaped_pointer_tokens_match_literal_slash_and_tilde_keys() {
    let comparator = ApiVisibilityComparator::default();
    let profile = profile(&["/a~1b/~0token"], &[], &[], 16);
    let baseline = view(
        &comparator,
        &profile,
        "anonymous",
        &json!({"a/b":{"~token":"one","other":1}}),
    );
    let candidate = view(
        &comparator,
        &profile,
        "member",
        &json!({"a/b":{"~token":"two","other":999}}),
    );
    let comparison = compare(
        &comparator,
        &profile,
        ApiVisibilityDimension::Resources,
        &baseline,
        &candidate,
    );

    assert_eq!(
        comparison.comparison().result(),
        ApiVisibilityResult::Different
    );
    assert_eq!(
        comparison.diff().changed_value_path_hashes(),
        &[PathDigest::for_pattern(&path("/a~1b/~0token"))]
    );
}

#[test]
fn selected_missing_path_is_reported_as_added() {
    let comparator = ApiVisibilityComparator::default();
    let profile = profile(&["/data/user/login"], &[], &[], 16);
    let baseline = view(&comparator, &profile, "anonymous", &json!({"data":{}}));
    let candidate = view(
        &comparator,
        &profile,
        "member",
        &json!({"data":{"user":{"login":"ada"}}}),
    );
    let comparison = compare(
        &comparator,
        &profile,
        ApiVisibilityDimension::Fields,
        &baseline,
        &candidate,
    );

    assert!(comparison
        .diff()
        .added_path_hashes()
        .contains(&PathDigest::for_pattern(&path("/data/user/login"))));
}

#[test]
fn field_diff_classifies_added_removed_and_type_changed_paths() {
    let comparator = ApiVisibilityComparator::default();
    let profile = ApiComparisonProfile::default();
    let baseline = view(
        &comparator,
        &profile,
        "anonymous",
        &json!({"removed":1,"typed":1,"stable":true}),
    );
    let candidate = view(
        &comparator,
        &profile,
        "member",
        &json!({"added":1,"typed":"1","stable":false}),
    );
    let comparison = compare(
        &comparator,
        &profile,
        ApiVisibilityDimension::Fields,
        &baseline,
        &candidate,
    );

    assert_eq!(
        comparison.diff().added_path_hashes(),
        &[PathDigest::for_pattern(&path("/added"))]
    );
    assert_eq!(
        comparison.diff().removed_path_hashes(),
        &[PathDigest::for_pattern(&path("/removed"))]
    );
    assert_eq!(
        comparison.diff().changed_type_path_hashes(),
        &[PathDigest::for_pattern(&path("/typed"))]
    );
    assert!(comparison.diff().changed_value_path_hashes().is_empty());
    assert_eq!(comparison.diff().retained_diff_count(), 3);
    assert_eq!(
        comparison.explanation_disposition(),
        VisibilityExplanationDisposition::PathSummary {
            retained: 3,
            omitted: 0,
        }
    );
}

#[test]
fn resource_diff_reports_value_change_without_retaining_value() {
    let comparator = ApiVisibilityComparator::default();
    let profile = ApiComparisonProfile::default();
    let baseline_secret = "baseline-secret-value";
    let candidate_secret = "candidate-secret-value";
    let baseline = view(
        &comparator,
        &profile,
        "anonymous",
        &json!({"token":baseline_secret}),
    );
    let candidate = view(
        &comparator,
        &profile,
        "member",
        &json!({"token":candidate_secret}),
    );
    let comparison = compare(
        &comparator,
        &profile,
        ApiVisibilityDimension::Resources,
        &baseline,
        &candidate,
    );

    assert_eq!(
        comparison.diff().changed_value_path_hashes(),
        &[PathDigest::for_pattern(&path("/token"))]
    );
    let output = format!(
        "{:?} {}",
        comparison,
        serde_json::to_string(&comparison).unwrap()
    );
    assert!(!output.contains(baseline_secret));
    assert!(!output.contains(candidate_secret));
    assert!(!format!("{comparison:?}").contains("/token"));
}

#[test]
fn diff_limit_is_global_and_reports_exact_omission_count() {
    let comparator = ApiVisibilityComparator::default();
    let profile = profile(&[], &[], &[], 2);
    let baseline = view(
        &comparator,
        &profile,
        "anonymous",
        &json!({"a":1,"b":1,"c":1}),
    );
    let candidate = view(&comparator, &profile, "member", &json!({"d":1,"e":1}));
    let comparison = compare(
        &comparator,
        &profile,
        ApiVisibilityDimension::Fields,
        &baseline,
        &candidate,
    );
    let retained = comparison.diff().added_path_hashes().len()
        + comparison.diff().removed_path_hashes().len()
        + comparison.diff().changed_type_path_hashes().len()
        + comparison.diff().changed_value_path_hashes().len();

    assert_eq!(retained, 2);
    assert_eq!(comparison.diff().omitted_diff_count(), 3);
}

#[test]
fn profile_mismatch_fails_closed() {
    let comparator = ApiVisibilityComparator::default();
    let first_profile = profile(&[], &["/timestamp"], &[], 16);
    let second_profile = profile(&[], &["/nonce"], &[], 16);
    let baseline = view(&comparator, &first_profile, "anonymous", &json!({"id":1}));
    let candidate = view(&comparator, &second_profile, "member", &json!({"id":1}));

    assert!(matches!(
        comparator.compare_profiled(
            &first_profile,
            "comparison",
            ApiVisibilityPairKind::AuthorizationContext,
            ApiVisibilityDimension::Fields,
            &baseline,
            &candidate,
            42,
        ),
        Err(ProfiledApiVisibilityError::ProjectionPolicyMismatch)
    ));
}

#[test]
fn same_fixture_same_profile_same_identity_and_explanation() {
    let comparator = ApiVisibilityComparator::default();
    let profile = profile(&[], &["/volatile"], &[], 16);
    let baseline = view(
        &comparator,
        &profile,
        "anonymous",
        &json!({"z":1,"data":{"id":1},"volatile":"a"}),
    );
    let candidate = view(
        &comparator,
        &profile,
        "member",
        &json!({"data":{"id":2},"z":1,"volatile":"b"}),
    );
    let first = compare(
        &comparator,
        &profile,
        ApiVisibilityDimension::Resources,
        &baseline,
        &candidate,
    );
    let replay = compare(
        &comparator,
        &profile,
        ApiVisibilityDimension::Resources,
        &baseline,
        &candidate,
    );

    assert_eq!(first, replay);
    assert_eq!(first.comparison().subject(), replay.comparison().subject());
    assert_eq!(
        serde_json::to_string(&first).unwrap(),
        serde_json::to_string(&replay).unwrap()
    );
}

#[test]
fn profiled_report_round_trip_preserves_replay_metadata() {
    let comparator = ApiVisibilityComparator::default();
    let profile = profile(&["/data"], &["/data/nonce"], &[], 9);
    let baseline = view(
        &comparator,
        &profile,
        "anonymous",
        &json!({"data":{"id":1,"nonce":"a"}}),
    );
    let candidate = view(
        &comparator,
        &profile,
        "member",
        &json!({"data":{"id":2,"nonce":"b"}}),
    );
    let comparison = compare(
        &comparator,
        &profile,
        ApiVisibilityDimension::Resources,
        &baseline,
        &candidate,
    );
    let encoded = serde_json::to_value(&comparison).unwrap();
    let decoded: ProfiledApiVisibilityComparison = serde_json::from_value(encoded.clone()).unwrap();

    assert_eq!(decoded, comparison);
    assert_eq!(encoded["comparator_version"], "v3");
    assert_eq!(encoded["canonicalization_version"], "v2");
    assert_eq!(
        decoded.projection_policy_id(),
        profile.projection_policy_id()
    );
    assert_eq!(decoded.limits(), comparator.limits());
    let mut tampered = encoded.clone();
    tampered["projection_policy_id"] = json!("0".repeat(64));
    assert!(serde_json::from_value::<ProfiledApiVisibilityComparison>(tampered).is_err());
    let mut legacy_v2 = encoded.clone();
    let policy_id = encoded["projection_policy_id"].as_str().unwrap();
    legacy_v2["comparator_version"] = json!("v2");
    legacy_v2["comparison"]["comparison_id"] =
        json!(format!("profiled:v2:v2:{policy_id}:{}", "0".repeat(64)));
    let error = serde_json::from_value::<ProfiledApiVisibilityComparison>(legacy_v2).unwrap_err();
    assert!(error.to_string().contains("unsupported comparator version"));
    assert!(
        serde_json::from_value::<ProfiledApiVisibilityComparison>(json!({
            "unknown": true
        }))
        .is_err()
    );
}

#[test]
fn profiled_report_rejects_unsorted_and_duplicate_diff_paths() {
    let comparator = ApiVisibilityComparator::default();
    let profile = ApiComparisonProfile::default();
    let baseline = view(&comparator, &profile, "anonymous", &json!({"data":{}}));
    let candidate = view(
        &comparator,
        &profile,
        "member",
        &json!({"data":{"alpha":1,"beta":2}}),
    );
    let comparison = compare(
        &comparator,
        &profile,
        ApiVisibilityDimension::Fields,
        &baseline,
        &candidate,
    );
    let encoded = serde_json::to_value(comparison).unwrap();
    assert_eq!(
        encoded["diff"]["added_path_hashes"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    let mut unsorted = encoded.clone();
    unsorted["diff"]["added_path_hashes"]
        .as_array_mut()
        .unwrap()
        .swap(0, 1);
    let error = serde_json::from_value::<ProfiledApiVisibilityComparison>(unsorted).unwrap_err();
    assert!(error.to_string().contains("must be sorted and unique"));

    let mut duplicated = encoded;
    let paths = duplicated["diff"]["added_path_hashes"]
        .as_array_mut()
        .unwrap();
    paths[1] = paths[0].clone();
    let error = serde_json::from_value::<ProfiledApiVisibilityComparison>(duplicated).unwrap_err();
    assert!(error.to_string().contains("must be sorted and unique"));
}

#[test]
fn profile_and_view_debug_redact_paths_handles_and_indexes() {
    let comparator = ApiVisibilityComparator::default();
    let profile = profile(&["/secret/path"], &[], &[], 16);
    let view = view(
        &comparator,
        &profile,
        "sensitive-context-handle",
        &json!({"secret":{"path":"value"}}),
    );
    let debug = format!("{profile:?} {view:?}");

    assert!(!debug.contains("/secret/path"));
    assert!(!debug.contains("sensitive-context-handle"));
    assert!(!debug.contains("resource:account-42"));
    assert!(debug.matches("<redacted>").count() >= 5);
}

#[test]
fn ordered_and_unordered_array_semantics_are_explicit() {
    let comparator = ApiVisibilityComparator::default();
    let ordered = ApiComparisonProfile::default();
    let unordered = profile(&[], &[], &["/items"], 16);
    let left = json!({"items":[{"id":1},{"id":2}]});
    let right = json!({"items":[{"id":2},{"id":1}]});

    let ordered_result = compare(
        &comparator,
        &ordered,
        ApiVisibilityDimension::Resources,
        &view(&comparator, &ordered, "anonymous", &left),
        &view(&comparator, &ordered, "member", &right),
    );
    let unordered_result = compare(
        &comparator,
        &unordered,
        ApiVisibilityDimension::Resources,
        &view(&comparator, &unordered, "anonymous", &left),
        &view(&comparator, &unordered, "member", &right),
    );

    assert_eq!(
        ordered_result.comparison().result(),
        ApiVisibilityResult::Different
    );
    assert!(ordered_result.diff().is_empty());
    assert_eq!(
        ordered_result.explanation_disposition(),
        VisibilityExplanationDisposition::DifferenceWithoutPathSummary
    );
    assert_eq!(
        unordered_result.comparison().result(),
        ApiVisibilityResult::Equivalent
    );
    assert_eq!(
        unordered_result.explanation_disposition(),
        VisibilityExplanationDisposition::NoDifference
    );
}

#[test]
fn zero_diff_quota_reports_omitted_path_summary() {
    let comparator = ApiVisibilityComparator::default();
    let profile = profile(&[], &[], &[], 0);
    let baseline = view(&comparator, &profile, "anonymous", &json!({}));
    let candidate = view(&comparator, &profile, "member", &json!({"added":true}));
    let comparison = compare(
        &comparator,
        &profile,
        ApiVisibilityDimension::Fields,
        &baseline,
        &candidate,
    );

    assert_eq!(
        comparison.comparison().result(),
        ApiVisibilityResult::Different
    );
    assert_eq!(comparison.diff().retained_diff_count(), 0);
    assert_eq!(comparison.diff().omitted_diff_count(), 1);
    assert_eq!(
        comparison.explanation_disposition(),
        VisibilityExplanationDisposition::PathSummary {
            retained: 0,
            omitted: 1,
        }
    );
}

#[test]
fn wildcard_projection_uses_structural_array_paths() {
    let comparator = ApiVisibilityComparator::default();
    let profile = profile(&["/data/*/id"], &[], &[], 16);
    let baseline = view(
        &comparator,
        &profile,
        "anonymous",
        &json!({"data":[{"id":1,"secret":"a"}]}),
    );
    let candidate = view(
        &comparator,
        &profile,
        "member",
        &json!({"data":[{"id":2,"secret":"b"}]}),
    );
    let comparison = compare(
        &comparator,
        &profile,
        ApiVisibilityDimension::Resources,
        &baseline,
        &candidate,
    );

    assert_eq!(
        comparison.diff().changed_value_path_hashes(),
        &[PathDigest::for_pattern(&path("/data/*/id"))]
    );
    assert!(!comparison
        .diff()
        .changed_value_path_hashes()
        .contains(&PathDigest::for_pattern(&path("/data/*/secret"))));
}

#[test]
fn profile_metadata_is_part_of_comparison_identity() {
    let comparator = ApiVisibilityComparator::default();
    let first_profile = profile(&[], &[], &[], 8);
    let second_profile = profile(&[], &[], &[], 9);
    let snapshot = json!({"id":1});
    let first = compare(
        &comparator,
        &first_profile,
        ApiVisibilityDimension::Fields,
        &view(&comparator, &first_profile, "anonymous", &snapshot),
        &view(&comparator, &first_profile, "member", &snapshot),
    );
    let second = compare(
        &comparator,
        &second_profile,
        ApiVisibilityDimension::Fields,
        &view(&comparator, &second_profile, "anonymous", &snapshot),
        &view(&comparator, &second_profile, "member", &snapshot),
    );

    assert_ne!(first.comparison().subject(), second.comparison().subject());
}

#[test]
fn profile_deserialization_is_bounded_and_rejects_unknown_fields() {
    let encoded = serde_json::to_value(ApiComparisonProfile::default()).unwrap();
    assert_eq!(
        serde_json::from_value::<ApiComparisonProfile>(encoded.clone()).unwrap(),
        ApiComparisonProfile::default()
    );

    let mut unknown = encoded.clone();
    unknown["extra"] = json!(true);
    assert!(serde_json::from_value::<ApiComparisonProfile>(unknown).is_err());

    let mut legacy_v2 = encoded.clone();
    legacy_v2["algorithm_version"] = json!("v2");
    assert!(serde_json::from_value::<ApiComparisonProfile>(legacy_v2).is_err());

    let mut excessive = encoded;
    excessive["max_diff_paths"] = json!(u64::from(HARD_MAX_API_VISIBILITY_DIFF_PATHS) + 1);
    assert!(serde_json::from_value::<ApiComparisonProfile>(excessive).is_err());
}

#[test]
fn same_status_with_different_bodies_is_equivalent_without_path_diff() {
    let comparator = ApiVisibilityComparator::default();
    let profile = ApiComparisonProfile::default();
    let baseline = comparator
        .capture_profiled_view(
            &profile,
            "anonymous",
            "resource:account-42",
            ApiSurfaceKind::JsonHttp,
            200,
            &json!({"id":1}),
        )
        .unwrap();
    let candidate = comparator
        .capture_profiled_view(
            &profile,
            "member",
            "resource:account-42",
            ApiSurfaceKind::JsonHttp,
            200,
            &json!({"different":{"shape":true}}),
        )
        .unwrap();
    let comparison = compare(
        &comparator,
        &profile,
        ApiVisibilityDimension::Status,
        &baseline,
        &candidate,
    );

    assert_eq!(
        comparison.comparison().result(),
        ApiVisibilityResult::Equivalent
    );
    assert!(comparison.diff().is_empty());
    assert_eq!(
        comparison.explanation_disposition(),
        VisibilityExplanationDisposition::NoDifference
    );
}

#[test]
fn status_comparison_retains_metadata_without_fabricating_path_diff() {
    let comparator = ApiVisibilityComparator::default();
    let profile = ApiComparisonProfile::default();
    let baseline = comparator
        .capture_profiled_view(
            &profile,
            "anonymous",
            "resource:account-42",
            ApiSurfaceKind::JsonHttp,
            200,
            &json!({"id":1}),
        )
        .unwrap();
    let candidate = comparator
        .capture_profiled_view(
            &profile,
            "member",
            "resource:account-42",
            ApiSurfaceKind::JsonHttp,
            403,
            &json!({"different":{"shape":true}}),
        )
        .unwrap();
    let comparison = compare(
        &comparator,
        &profile,
        ApiVisibilityDimension::Status,
        &baseline,
        &candidate,
    );

    assert_eq!(
        comparison.comparison().result(),
        ApiVisibilityResult::Different
    );
    assert!(comparison.diff().is_empty());
    assert_eq!(comparison.diff().retained_diff_count(), 0);
    assert_eq!(
        comparison.explanation_disposition(),
        VisibilityExplanationDisposition::DifferenceWithoutPathSummary
    );
    assert_eq!(
        comparison.comparator_version(),
        CURRENT_API_COMPARISON_ALGORITHM_VERSION
    );
}

#[test]
fn v3_envelope_rejects_result_and_dimension_incompatible_diffs() {
    let comparator = ApiVisibilityComparator::default();
    let profile = ApiComparisonProfile::default();
    let baseline = comparator
        .capture_profiled_view(
            &profile,
            "anonymous",
            "resource:account-42",
            ApiSurfaceKind::JsonHttp,
            200,
            &json!({"id":1}),
        )
        .unwrap();
    let same_status = comparator
        .capture_profiled_view(
            &profile,
            "member",
            "resource:account-42",
            ApiSurfaceKind::JsonHttp,
            200,
            &json!({"id":"one"}),
        )
        .unwrap();
    let different_status = comparator
        .capture_profiled_view(
            &profile,
            "reviewer",
            "resource:account-42",
            ApiSurfaceKind::JsonHttp,
            403,
            &json!({"id":"one"}),
        )
        .unwrap();

    let mut equivalent = serde_json::to_value(compare(
        &comparator,
        &profile,
        ApiVisibilityDimension::Status,
        &baseline,
        &same_status,
    ))
    .unwrap();
    equivalent["diff"]["omitted_diff_count"] = json!(1);
    assert!(serde_json::from_value::<ProfiledApiVisibilityComparison>(equivalent).is_err());

    let mut status = serde_json::to_value(compare(
        &comparator,
        &profile,
        ApiVisibilityDimension::Status,
        &baseline,
        &different_status,
    ))
    .unwrap();
    status["diff"]["added_path_hashes"] = json!(["0".repeat(64)]);
    assert!(serde_json::from_value::<ProfiledApiVisibilityComparison>(status).is_err());

    let mut fields = serde_json::to_value(compare(
        &comparator,
        &profile,
        ApiVisibilityDimension::Fields,
        &baseline,
        &same_status,
    ))
    .unwrap();
    fields["diff"]["changed_value_path_hashes"] = json!(["0".repeat(64)]);
    let error = serde_json::from_value::<ProfiledApiVisibilityComparison>(fields).unwrap_err();
    assert!(error
        .to_string()
        .contains("incompatible with v3 result semantics"));
}

#[test]
fn legacy_signatures_and_wire_contract_remain_unchanged() {
    let comparator = ApiVisibilityComparator::default();
    let legacy = comparator
        .capture_view(
            "anonymous",
            "resource:account-42",
            ApiSurfaceKind::JsonHttp,
            200,
            &json!({"id":1,"profile":{"name":"Ada","active":true}}),
        )
        .unwrap();
    assert_eq!(
        encode_digest(legacy.resource_signature),
        "8e64fa181aa9dfce7b39e25228deba942d785ad4949a6582a5f51d8d2d303252"
    );
    assert_eq!(
        encode_digest(legacy.field_signature),
        "34505502879340f165f465b93d10ec584ecdc808c3435421992d0bec3fc1bbc1"
    );

    let limits = serde_json::to_value(comparator.limits()).unwrap();
    assert_eq!(limits.as_object().unwrap().len(), 4);
    let baseline = comparator
        .capture_view(
            "anonymous",
            "resource:account-42",
            ApiSurfaceKind::JsonHttp,
            200,
            &json!({"id":1}),
        )
        .unwrap();
    let candidate = comparator
        .capture_view(
            "member",
            "resource:account-42",
            ApiSurfaceKind::JsonHttp,
            200,
            &json!({"id":2}),
        )
        .unwrap();
    let comparison = comparator
        .compare(
            "legacy-comparison",
            ApiVisibilityPairKind::AuthorizationContext,
            ApiVisibilityDimension::Resources,
            &baseline,
            &candidate,
            42,
        )
        .unwrap();
    let comparison_wire = serde_json::to_value(comparison).unwrap();
    assert_eq!(comparison_wire.as_object().unwrap().len(), 9);
    assert!(comparison_wire.get("comparator_version").is_none());
    assert!(comparison_wire.get("diff").is_none());
}
