use serde_json::{json, Map};
use venom_core::{ApiEvidencePredicate, ConfidenceScore, EvidenceValue};

use super::*;

fn comparator() -> ApiVisibilityComparator {
    ApiVisibilityComparator::default()
}

fn view(
    comparator: &ApiVisibilityComparator,
    context: &str,
    status: u16,
    snapshot: &Value,
) -> ApiVisibilityView {
    comparator
        .capture_view(
            context,
            "resource:account-list",
            ApiSurfaceKind::JsonHttp,
            status,
            snapshot,
        )
        .unwrap()
}

fn compare(
    comparator: &ApiVisibilityComparator,
    dimension: ApiVisibilityDimension,
    baseline: &ApiVisibilityView,
    candidate: &ApiVisibilityView,
) -> ApiVisibilityComparison {
    comparator
        .compare(
            "comparison:test:1",
            ApiVisibilityPairKind::AuthorizationContext,
            dimension,
            baseline,
            candidate,
            1_000,
        )
        .unwrap()
}

#[test]
fn object_insertion_order_never_changes_either_signature() {
    let comparator = comparator();
    let mut left = Map::new();
    left.insert("z".to_owned(), json!({"b": 2, "a": 1}));
    left.insert("a".to_owned(), json!([true, false]));
    let mut right = Map::new();
    right.insert("a".to_owned(), json!([true, false]));
    right.insert("z".to_owned(), json!({"a": 1, "b": 2}));

    let baseline = view(&comparator, "anonymous", 200, &Value::Object(left));
    let candidate = view(&comparator, "member", 200, &Value::Object(right));

    assert_eq!(baseline.resource_signature, candidate.resource_signature);
    assert_eq!(baseline.field_signature, candidate.field_signature);
    assert_eq!(
        compare(
            &comparator,
            ApiVisibilityDimension::Resources,
            &baseline,
            &candidate,
        )
        .result(),
        ApiVisibilityResult::Equivalent
    );
}

#[test]
fn arrays_preserve_order_and_duplicate_elements() {
    let comparator = comparator();
    let original = view(&comparator, "a", 200, &json!([{"a": 1}, {"b": 2}]));
    let reordered = view(&comparator, "b", 200, &json!([{"b": 2}, {"a": 1}]));
    let duplicate = view(
        &comparator,
        "c",
        200,
        &json!([{"a": 1}, {"b": 2}, {"b": 2}]),
    );

    assert_ne!(original.resource_signature, reordered.resource_signature);
    assert_ne!(original.field_signature, reordered.field_signature);
    assert_ne!(original.resource_signature, duplicate.resource_signature);
    assert_ne!(original.field_signature, duplicate.field_signature);
}

#[test]
fn fields_compare_schema_and_keys_without_scalar_values() {
    let comparator = comparator();
    let baseline = view(
        &comparator,
        "anonymous",
        200,
        &json!({"id": 1, "profile": {"name": "Ada", "active": true}}),
    );
    let same_schema = view(
        &comparator,
        "member",
        403,
        &json!({"profile": {"active": false, "name": "Lin"}, "id": 999}),
    );
    let extra_field = view(
        &comparator,
        "admin",
        200,
        &json!({"id": 1, "profile": {"name": "Ada", "active": true, "role": "admin"}}),
    );
    let changed_type = view(
        &comparator,
        "service",
        200,
        &json!({"id": "1", "profile": {"name": "Ada", "active": true}}),
    );

    assert_eq!(
        compare(
            &comparator,
            ApiVisibilityDimension::Fields,
            &baseline,
            &same_schema,
        )
        .result(),
        ApiVisibilityResult::Equivalent
    );
    assert_eq!(
        compare(
            &comparator,
            ApiVisibilityDimension::Fields,
            &baseline,
            &extra_field,
        )
        .result(),
        ApiVisibilityResult::Different
    );
    assert_eq!(
        compare(
            &comparator,
            ApiVisibilityDimension::Fields,
            &baseline,
            &changed_type,
        )
        .result(),
        ApiVisibilityResult::Different
    );
}

#[test]
fn resources_compare_complete_canonical_values() {
    let comparator = comparator();
    let baseline = view(&comparator, "anonymous", 200, &json!({"id": 1}));
    let candidate = view(&comparator, "member", 200, &json!({"id": 2}));

    assert_eq!(
        compare(
            &comparator,
            ApiVisibilityDimension::Fields,
            &baseline,
            &candidate,
        )
        .result(),
        ApiVisibilityResult::Equivalent
    );
    assert_eq!(
        compare(
            &comparator,
            ApiVisibilityDimension::Resources,
            &baseline,
            &candidate,
        )
        .result(),
        ApiVisibilityResult::Different
    );
}

#[test]
fn status_comparison_is_exact_and_independent_from_json() {
    let comparator = comparator();
    let baseline = view(&comparator, "anonymous", 200, &json!({"id": 1}));
    let different_json = view(&comparator, "member", 200, &json!({"id": 2}));
    let different_status = view(&comparator, "admin", 201, &json!({"id": 1}));

    assert_eq!(
        compare(
            &comparator,
            ApiVisibilityDimension::Status,
            &baseline,
            &different_json,
        )
        .result(),
        ApiVisibilityResult::Equivalent
    );
    assert_eq!(
        compare(
            &comparator,
            ApiVisibilityDimension::Status,
            &baseline,
            &different_status,
        )
        .result(),
        ApiVisibilityResult::Different
    );
}

#[test]
fn mismatched_scope_surface_context_and_policy_fail_closed() {
    let comparator = comparator();
    let baseline = view(&comparator, "anonymous", 200, &json!({}));
    let same_context = view(&comparator, "anonymous", 200, &json!({}));
    assert!(matches!(
        comparator.compare(
            "comparison",
            ApiVisibilityPairKind::AuthorizationContext,
            ApiVisibilityDimension::Fields,
            &baseline,
            &same_context,
            1,
        ),
        Err(ApiVisibilityEvidenceError::IdenticalContexts)
    ));

    let other_scope = comparator
        .capture_view(
            "member",
            "resource:other",
            ApiSurfaceKind::JsonHttp,
            200,
            &json!({}),
        )
        .unwrap();
    assert!(matches!(
        comparator.compare(
            "comparison",
            ApiVisibilityPairKind::AuthorizationContext,
            ApiVisibilityDimension::Fields,
            &baseline,
            &other_scope,
            1,
        ),
        Err(ApiVisibilityEvidenceError::ResourceScopeMismatch)
    ));

    let other_surface = comparator
        .capture_view(
            "member",
            "resource:account-list",
            ApiSurfaceKind::GraphQl,
            200,
            &json!({}),
        )
        .unwrap();
    assert!(matches!(
        comparator.compare(
            "comparison",
            ApiVisibilityPairKind::AuthorizationContext,
            ApiVisibilityDimension::Fields,
            &baseline,
            &other_surface,
            1,
        ),
        Err(ApiVisibilityEvidenceError::SurfaceMismatch)
    ));

    let strict = ApiVisibilityComparator::new(ApiVisibilityLimits::new(8, 8, 8, 256).unwrap());
    let strict_view = strict
        .capture_view(
            "member",
            "resource:account-list",
            ApiSurfaceKind::JsonHttp,
            200,
            &json!({}),
        )
        .unwrap();
    assert!(matches!(
        comparator.compare(
            "comparison",
            ApiVisibilityPairKind::AuthorizationContext,
            ApiVisibilityDimension::Fields,
            &baseline,
            &strict_view,
            1,
        ),
        Err(ApiVisibilityEvidenceError::LimitsMismatch)
    ));
}

#[test]
fn every_runtime_limit_and_hard_ceiling_is_enforced() {
    assert!(matches!(
        ApiVisibilityLimits::new(0, 1, 1, 1),
        Err(ApiVisibilityEvidenceError::ZeroLimit {
            dimension: "max_depth"
        })
    ));
    assert!(matches!(
        ApiVisibilityLimits::new(HARD_MAX_API_VISIBILITY_DEPTH + 1, 1, 1, 1),
        Err(ApiVisibilityEvidenceError::HardLimitExceeded {
            dimension: "max_depth",
            ..
        })
    ));
    assert!(matches!(
        ApiVisibilityLimits::new(1, HARD_MAX_API_VISIBILITY_NODES + 1, 1, 1),
        Err(ApiVisibilityEvidenceError::HardLimitExceeded {
            dimension: "max_nodes",
            ..
        })
    ));
    assert!(matches!(
        ApiVisibilityLimits::new(1, 1, HARD_MAX_API_VISIBILITY_FIELDS + 1, 1),
        Err(ApiVisibilityEvidenceError::HardLimitExceeded {
            dimension: "max_fields",
            ..
        })
    ));
    assert!(matches!(
        ApiVisibilityLimits::new(1, 1, 1, HARD_MAX_API_VISIBILITY_CANONICAL_BYTES + 1,),
        Err(ApiVisibilityEvidenceError::HardLimitExceeded {
            dimension: "max_canonical_bytes",
            ..
        })
    ));
    assert!(ApiVisibilityLimits::new(
        HARD_MAX_API_VISIBILITY_DEPTH,
        HARD_MAX_API_VISIBILITY_NODES,
        HARD_MAX_API_VISIBILITY_FIELDS,
        HARD_MAX_API_VISIBILITY_CANONICAL_BYTES,
    )
    .is_ok());

    let depth = ApiVisibilityComparator::new(ApiVisibilityLimits::new(2, 10, 10, 512).unwrap());
    assert!(matches!(
        depth.capture_view(
            "a",
            "scope",
            ApiSurfaceKind::JsonHttp,
            200,
            &json!({"a": {"b": 1}})
        ),
        Err(ApiVisibilityEvidenceError::DepthLimitExceeded { .. })
    ));

    let nodes = ApiVisibilityComparator::new(ApiVisibilityLimits::new(8, 2, 10, 512).unwrap());
    assert!(matches!(
        nodes.capture_view(
            "a",
            "scope",
            ApiSurfaceKind::JsonHttp,
            200,
            &json!([null, null])
        ),
        Err(ApiVisibilityEvidenceError::NodeLimitExceeded { .. })
    ));

    let fields = ApiVisibilityComparator::new(ApiVisibilityLimits::new(8, 10, 1, 512).unwrap());
    assert!(matches!(
        fields.capture_view(
            "a",
            "scope",
            ApiSurfaceKind::JsonHttp,
            200,
            &json!({"a": 1, "b": 2})
        ),
        Err(ApiVisibilityEvidenceError::FieldLimitExceeded { .. })
    ));

    let bytes = ApiVisibilityComparator::new(ApiVisibilityLimits::new(8, 10, 10, 1).unwrap());
    assert!(matches!(
        bytes.capture_view(
            "a",
            "scope",
            ApiSurfaceKind::JsonHttp,
            200,
            &json!("secret")
        ),
        Err(ApiVisibilityEvidenceError::CanonicalBytesLimitExceeded { .. })
    ));
}

#[test]
fn limits_round_trip_and_reject_unknown_or_unsafe_wire_values() {
    let limits = ApiVisibilityLimits::default();
    let encoded = serde_json::to_value(limits).unwrap();
    assert_eq!(
        serde_json::from_value::<ApiVisibilityLimits>(encoded.clone()).unwrap(),
        limits
    );

    let mut unknown = encoded.clone();
    unknown["max_nodez"] = json!(1);
    assert!(serde_json::from_value::<ApiVisibilityLimits>(unknown).is_err());

    let mut unsafe_limit = encoded;
    unsafe_limit["max_nodes"] = json!(u64::from(HARD_MAX_API_VISIBILITY_NODES) + 1);
    assert!(serde_json::from_value::<ApiVisibilityLimits>(unsafe_limit).is_err());
}

#[test]
fn capture_rejects_invalid_status_and_opaque_handles() {
    let comparator = comparator();
    assert!(matches!(
        comparator.capture_view(" ", "scope", ApiSurfaceKind::JsonHttp, 200, &json!({})),
        Err(ApiVisibilityEvidenceError::EmptyHandle { .. })
    ));
    assert!(matches!(
        comparator.capture_view(
            "context",
            "x".repeat(MAX_OPAQUE_HANDLE_BYTES + 1),
            ApiSurfaceKind::JsonHttp,
            200,
            &json!({}),
        ),
        Err(ApiVisibilityEvidenceError::HandleTooLong { .. })
    ));
    assert!(matches!(
        comparator.capture_view("context", "scope", ApiSurfaceKind::JsonHttp, 99, &json!({})),
        Err(ApiVisibilityEvidenceError::InvalidHttpStatus { status: 99 })
    ));
}

#[test]
fn replay_is_stable_and_raw_json_never_enters_output_or_debug() {
    let comparator = comparator();
    let secret = "do-not-persist-this-token";
    let baseline = view(
        &comparator,
        "anonymous-handle",
        200,
        &json!({"token": secret, "items": [1, 2]}),
    );
    let candidate = view(
        &comparator,
        "member-handle",
        200,
        &json!({"token": "another-secret", "items": [1, 2, 3]}),
    );
    let debug = format!("{baseline:?}");
    let resource_signature = baseline
        .resource_signature
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let field_signature = baseline
        .field_signature
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert!(!debug.contains(secret));
    assert!(!debug.contains(&resource_signature));
    assert!(!debug.contains(&field_signature));
    assert_eq!(debug.matches("<redacted>").count(), 2);

    let first = comparator
        .compare(
            "comparison:replay:7",
            ApiVisibilityPairKind::AuthorizationContext,
            ApiVisibilityDimension::Resources,
            &baseline,
            &candidate,
            42,
        )
        .unwrap();
    let replay = comparator
        .compare(
            "comparison:replay:7",
            ApiVisibilityPairKind::AuthorizationContext,
            ApiVisibilityDimension::Resources,
            &baseline,
            &candidate,
            42,
        )
        .unwrap();
    assert_eq!(first, replay);
    assert_eq!(first.result(), ApiVisibilityResult::Different);

    let observation = first
        .to_observation("api.visibility.comparator", ConfidenceScore::MAX)
        .unwrap();
    assert_eq!(
        observation.evidence().predicate(),
        &ApiEvidencePredicate::JSON_AUTHORIZATION_CONTEXT_DIFFERENCE.into_knowledge()
    );
    assert_eq!(
        observation.evidence().value(),
        &EvidenceValue::Text("resources".to_owned())
    );
    let (evidence, relation) = observation.into_parts();
    let persisted = format!(
        "{} {}",
        serde_json::to_string(&evidence).unwrap(),
        serde_json::to_string(&relation).unwrap()
    );
    assert!(!persisted.contains(secret));
    assert!(!persisted.contains("another-secret"));
}
