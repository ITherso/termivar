//! Pure bounded policy/saved-reader checks. These do not exercise callback
//! HTTP, generate authorization transactions, redeem codes or mint authority.

use termivar_scanner::{
    reporting::comparison::{compare_reports, import_assessment_summary, ComparisonFormat},
    supplied_session_review::{SuppliedSessionPolicy, SuppliedSessionPolicyVersion},
};

/// Deliberately smaller than the general rendered-report input ceiling.
pub const MAX_SUPPLIED_SESSION_FUZZ_INPUT_BYTES: usize = 64 * 1024;

/// Repeated parsing and self-partition conservation over inert supplied bytes.
pub fn check_supplied_session_inputs(data: &[u8]) {
    if data.len() > MAX_SUPPLIED_SESSION_FUZZ_INPUT_BYTES {
        return;
    }
    let target = url::Url::parse("https://session-fuzz.invalid/app/").unwrap();
    let first = SuppliedSessionPolicy::parse_toml(&target, data);
    let second = SuppliedSessionPolicy::parse_toml(&target, data);
    match (first, second) {
        (Ok(first), Ok(second)) => {
            assert_eq!(first.policy_reference(), second.policy_reference());
            assert_eq!(first.version(), second.version());
            assert!(first.resource_count() <= 4 && first.max_session_requests() <= 9);
            assert!(
                first.max_total_response_bytes() <= 262144
                    && first.max_response_body_bytes() <= 65536
            );
            assert!((1..=10000).contains(&first.max_wall_time_ms()));
            if first.version() == SuppliedSessionPolicyVersion::V7 {
                assert!((1..=3).contains(&first.resource_count()));
                assert_eq!(
                    usize::from(first.max_session_requests()),
                    2 + 2 * first.resource_count()
                );
                assert!(first.max_session_requests() < 9);
            }
        },
        (Err(first), Err(second)) => assert_eq!(first, second),
        _ => panic!("identical policy bytes must have deterministic admission"),
    }
    let first = import_assessment_summary(data);
    let second = import_assessment_summary(data);
    assert_eq!(first, second);
    if let Ok(summary) = first {
        // A separate bounded JSON tree supplies source array cardinality,
        // rather than the comparison implementation generating its oracle.
        let source: serde_json::Value = serde_json::from_slice(data).unwrap();
        let items = source["items"].as_array().unwrap();
        assert_eq!(summary.item_count(), items.len() as u64);
        let compared = compare_reports(data, data, ComparisonFormat::Json).unwrap();
        assert!(
            compared.len() <= 1024 * 1024,
            "small input must retain bounded comparison detail"
        );
        assert_eq!(
            compared,
            compare_reports(data, data, ComparisonFormat::Json).unwrap()
        );
        let result: serde_json::Value = serde_json::from_str(&compared).unwrap();
        for group in ["only_in_after", "only_in_before", "changed"] {
            assert!(result[group].as_array().unwrap().is_empty());
        }
        assert_eq!(result["unchanged"].as_array().unwrap().len(), items.len());
    }
}
