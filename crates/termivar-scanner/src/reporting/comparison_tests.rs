use super::*;
use serde_json::json;
use sha2::{Digest, Sha256};

const SAMPLE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/examples/first-use/assessment.json"
));
const BUNDLE_SAMPLE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/examples/report-bundle/assessment-001/assessment.json"
));

fn item(identity: u32) -> Value {
    json!({
        "schema":"venom-assessment-item/v1", "capability_id":"test.observation@1",
        "subject_reference":"subject-0000", "title":"A bounded observation",
        "disposition":"informational", "claim_basis":"observation", "severity":null,
        "confidence_ppm":1_000_000, "fingerprint":format!("sha256:{identity:064x}"),
        "evidence_count":1, "redacted_summary":"A synthetic offline test observation.",
        "category":"test", "cwe":null,
        "remediation":{"id":"test.remediation@1","summary":"Review the observation."},
        "evidence_references":["evidence-0000"], "control_evidence_references":[],
        "candidate_evidence_references":[], "case_reference":null,
        "outcome_reference":null, "verification_stage":null
    })
}

fn report(items: Vec<Value>) -> Value {
    json!({
        "schema":"venom-rendered-assessment/v1", "source_schema":"venom-assessment-run/v1",
        "run_schema":"venom-run/v1", "profile_schema":"venom.scan-profile/v1",
        "profile":"web-review", "status":"complete", "subject_count":2,
        "item_count":items.len(), "items":items
    })
}

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn compare(before: &Value, after: &Value) -> Value {
    serde_json::from_str(
        &compare_reports(&bytes(before), &bytes(after), ComparisonFormat::Json).unwrap(),
    )
    .unwrap()
}

fn reject(value: &Value) {
    assert!(compare_reports(&bytes(value), SAMPLE, ComparisonFormat::Json).is_err());
}

fn group(result: &Value, name: &str) -> Vec<Value> {
    result[name].as_array().unwrap().clone()
}

fn synthetic_wordfence_notice_id(
    message: &str,
    party: &str,
    notice: &str,
    license: &str,
    license_url: &str,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"termivar.wordfence-v3.notice/v1\0");
    for value in [message, party, notice, license, license_url] {
        digest.update(u64::try_from(value.len()).unwrap().to_be_bytes());
        digest.update(value.as_bytes());
    }
    let digest = digest.finalize();
    format!("wordfence-notice-sha256:{digest:x}")
}

#[test]
fn genuine_sample_identity_raw_hashes_and_assurance_are_preserved() {
    let output = compare_reports(SAMPLE, SAMPLE, ComparisonFormat::Json).unwrap();
    let document: Value = serde_json::from_str(&output).unwrap();
    assert_eq!(document["schema"], "termivar-report-comparison/v1");
    assert_eq!(document["scope_assurance"], "operator-declared");
    assert_eq!(document["coverage_equivalence"], "not-established");
    assert_eq!(
        document["source_authenticity"],
        "not-established-by-parsing"
    );
    assert_eq!(
        document["before"]["sha256"],
        "b8e6d5c720bca98b629a7be11340092e0d02c0aea2c12f30afaeaee0d125477f"
    );
    assert_eq!(document["before"], document["after"]);
    assert_eq!(group(&document, "unchanged").len(), 4);
    for name in ["only_in_before", "only_in_after", "changed"] {
        assert!(group(&document, name).is_empty());
    }
    assert_eq!(
        output,
        compare_reports(SAMPLE, SAMPLE, ComparisonFormat::Json).unwrap()
    );
}

#[test]
fn imported_summary_reuses_the_strict_parser_without_changing_comparison() {
    let comparison = compare_reports(BUNDLE_SAMPLE, BUNDLE_SAMPLE, ComparisonFormat::Json).unwrap();
    let summary = import_assessment_summary(BUNDLE_SAMPLE).unwrap();

    assert_eq!(summary.schema(), "venom-rendered-assessment/v1");
    assert_eq!(summary.profile(), "web-review");
    assert_eq!(summary.status(), "complete");
    assert_eq!(summary.subject_count(), 1);
    assert_eq!(summary.item_count(), 4);
    assert_eq!(
        compare_reports(BUNDLE_SAMPLE, BUNDLE_SAMPLE, ComparisonFormat::Json).unwrap(),
        comparison
    );
}

#[test]
fn imported_summary_accepts_a_complete_empty_assessment() {
    let empty = bytes(&report(Vec::new()));
    let summary = import_assessment_summary(&empty).unwrap();

    assert_eq!(summary.schema(), "venom-rendered-assessment/v1");
    assert_eq!(summary.profile(), "web-review");
    assert_eq!(summary.status(), "complete");
    assert_eq!(summary.subject_count(), 2);
    assert_eq!(summary.item_count(), 0);
}

#[test]
fn imported_summary_preserves_duplicate_and_unsupported_error_classes() {
    let valid = String::from_utf8(bytes(&report(Vec::new()))).unwrap();
    let duplicate_key = valid.replacen('{', "{\"schema\":\"venom-rendered-assessment/v1\",", 1);
    assert_eq!(
        import_assessment_summary(duplicate_key.as_bytes()),
        Err(ComparisonError::InvalidJson)
    );

    let mut duplicate_identity = report(vec![item(1), item(1)]);
    duplicate_identity["item_count"] = json!(2);
    assert_eq!(
        import_assessment_summary(&bytes(&duplicate_identity)),
        Err(ComparisonError::AmbiguousIdentity)
    );

    let mut unsupported = report(Vec::new());
    unsupported["schema"] = json!("termivar-rendered-assessment/v2");
    assert_eq!(
        import_assessment_summary(&bytes(&unsupported)),
        Err(ComparisonError::UnsupportedDocument)
    );
}

#[test]
fn imported_summary_is_deterministic_for_arbitrary_bounded_bytes() {
    let mut state = 0x51a7_9e3d_u32;
    for length in (0..=4096).step_by(29) {
        let mut bytes = Vec::with_capacity(length);
        for _ in 0..length {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            bytes.push((state >> 24) as u8);
        }
        let first = std::panic::catch_unwind(|| import_assessment_summary(&bytes))
            .expect("bounded assessment import must not panic");
        assert_eq!(first, import_assessment_summary(&bytes));
    }
}

#[test]
fn four_groups_are_exclusive_identity_based_and_reversal_swaps_sides() {
    let mut changed = item(2);
    changed["title"] = json!("A different display title");
    let before = report(vec![item(4), item(2), item(1)]);
    let after = report(vec![item(3), changed, item(1)]);
    let forward = compare(&before, &after);
    let reverse = compare(&after, &before);
    for name in ["only_in_before", "only_in_after", "changed", "unchanged"] {
        assert_eq!(group(&forward, name).len(), 1);
    }
    assert_eq!(forward["changed"][0]["changed_fields"], json!(["title"]));
    assert_eq!(
        forward["changed"][0]["before"],
        reverse["changed"][0]["after"]
    );
    assert_eq!(
        forward["changed"][0]["after"],
        reverse["changed"][0]["before"]
    );
    assert_eq!(
        forward["only_in_before"][0]["fingerprint"],
        reverse["only_in_after"][0]["fingerprint"]
    );
    assert_eq!(
        forward["only_in_after"][0]["fingerprint"],
        reverse["only_in_before"][0]["fingerprint"]
    );
    assert_eq!(group(&forward, "unchanged"), group(&reverse, "unchanged"));
    let mut identities = std::collections::BTreeSet::new();
    for name in ["only_in_before", "only_in_after", "changed", "unchanged"] {
        for item in group(&forward, name) {
            assert!(identities.insert(item["fingerprint"].as_str().unwrap().to_owned()));
        }
    }
    assert_eq!(identities.len(), 4);
}

#[test]
fn ordering_formatting_and_local_reference_renumbering_do_not_change_projection() {
    let mut old = item(1);
    old["evidence_count"] = json!(2);
    old["evidence_references"] = json!(["evidence-0000", "evidence-0001"]);
    let mut new = old.clone();
    new["subject_reference"] = json!("subject-0001");
    new["evidence_references"] = json!(["evidence-9000", "evidence-8000"]);
    let before = report(vec![old, item(2)]);
    let after = report(vec![item(2), new]);
    let output: Value = serde_json::from_str(
        &compare_reports(
            &bytes(&before),
            &serde_json::to_vec_pretty(&after).unwrap(),
            ComparisonFormat::Json,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(group(&output, "unchanged").len(), 2);
    assert!(group(&output, "changed").is_empty());
    assert_ne!(output["before"]["sha256"], output["after"]["sha256"]);
    let mut reordered = after.clone();
    reordered["items"].as_array_mut().unwrap().reverse();
    assert_eq!(
        group(&output, "unchanged"),
        group(&compare(&before, &reordered), "unchanged")
    );
}

#[test]
fn all_projected_display_fields_and_meaningful_evidence_changes_are_visible() {
    let original = item(1);
    for (field, replacement, expected) in [
        ("title", json!("Changed title"), "title"),
        ("category", json!("changed"), "category"),
        ("severity", json!("high"), "severity"),
        ("cwe", json!("CWE-200"), "cwe"),
        ("confidence_ppm", json!(100), "confidence_ppm"),
        (
            "redacted_summary",
            json!("Different observation."),
            "redacted_summary",
        ),
        (
            "remediation",
            json!({"id":"changed@1","summary":"Changed guidance."}),
            "remediation",
        ),
    ] {
        let mut changed = original.clone();
        changed[field] = replacement;
        assert_eq!(
            compare(&report(vec![original.clone()]), &report(vec![changed]))["changed"][0]
                ["changed_fields"],
            json!([expected]),
            "{field}"
        );
    }
    let mut differential = original.clone();
    differential["claim_basis"] = json!("differential");
    differential["disposition"] = json!("needs_review");
    assert_eq!(
        compare(&report(vec![original.clone()]), &report(vec![differential]))["changed"][0]
            ["changed_fields"],
        json!(["disposition", "claim_basis"])
    );
    let mut extra = original.clone();
    extra["evidence_count"] = json!(2);
    extra["evidence_references"] = json!(["evidence-0000", "evidence-0001"]);
    assert_eq!(
        compare(&report(vec![original]), &report(vec![extra]))["changed"][0]["changed_fields"],
        json!(["evidence"])
    );
}

#[test]
fn verifier_and_matched_pair_reference_labels_are_local_not_identity() {
    let mut verified = item(1);
    verified["disposition"] = json!("confirmed");
    verified["claim_basis"] = json!("verifier_transition");
    verified["case_reference"] = json!("case-0000");
    verified["outcome_reference"] = json!("outcome-0000");
    verified["verification_stage"] = json!("active");
    let mut renumbered = verified.clone();
    renumbered["case_reference"] = json!("case-0123");
    renumbered["outcome_reference"] = json!("outcome-0124");
    let result = compare(&report(vec![verified.clone()]), &report(vec![renumbered]));
    assert_eq!(group(&result, "unchanged").len(), 1);
    assert_eq!(result["unchanged"][0]["before"]["disposition"], "confirmed");
    verified["verification_stage"] = json!("passive");
    assert_eq!(
        group(
            &compare(&report(vec![verified.clone()]), &report(vec![verified])),
            "unchanged"
        )
        .len(),
        1
    );
    let mut paired = item(2);
    paired["disposition"] = json!("needs_review");
    paired["claim_basis"] = json!("differential");
    paired["evidence_references"] = json!([]);
    paired["control_evidence_references"] = json!(["evidence-0001"]);
    paired["candidate_evidence_references"] = json!(["evidence-0002"]);
    paired["evidence_count"] = json!(2);
    assert_eq!(
        group(
            &compare(&report(vec![paired.clone()]), &report(vec![paired])),
            "unchanged"
        )
        .len(),
        1
    );
}

#[test]
fn duplicate_and_conflicting_fingerprints_fail_within_and_across_inputs() {
    let mut conflict = item(1);
    conflict["capability_id"] = json!("other.capability@1");
    for second in [item(1), conflict.clone()] {
        assert_eq!(
            compare_reports(
                &bytes(&report(vec![item(1), second])),
                SAMPLE,
                ComparisonFormat::Json
            ),
            Err(ComparisonError::AmbiguousIdentity)
        );
    }
    assert_eq!(
        compare_reports(
            &bytes(&report(vec![item(1)])),
            &bytes(&report(vec![conflict])),
            ComparisonFormat::Json
        ),
        Err(ComparisonError::AmbiguousIdentity)
    );
    let result = compare(&report(vec![item(1)]), &report(vec![item(2)]));
    assert_eq!(group(&result, "only_in_before").len(), 1);
    assert_eq!(group(&result, "only_in_after").len(), 1);
}

#[test]
fn completed_empty_documents_have_four_empty_groups() {
    let empty = report(vec![]);
    let result = compare(&empty, &empty);
    for name in ["only_in_before", "only_in_after", "changed", "unchanged"] {
        assert!(group(&result, name).is_empty());
    }
}

#[test]
fn unsupported_incomplete_unknown_fields_and_inconsistent_root_counts_fail() {
    let valid = report(vec![item(1)]);
    for (field, replacement) in [
        ("schema", json!("decision-scan/v1")),
        ("source_schema", json!("venom-assessment-run/v2")),
        ("run_schema", json!("venom-run/v2")),
        ("profile_schema", json!("venom.scan-profile/v2")),
        ("profile", json!("baseline")),
        ("status", json!("incomplete")),
        ("subject_count", json!(0)),
        ("subject_count", json!(1025)),
        ("subject_count", json!(-1)),
        ("item_count", json!(2)),
        ("item_count", json!("1")),
        ("items", json!({})),
        ("unexpected", json!(true)),
        ("ssrf_oast_review", json!({})),
        ("schema", Value::Null),
    ] {
        let mut value = valid.clone();
        value[field] = replacement;
        reject(&value);
    }
    for field in valid.as_object().unwrap().keys() {
        let mut value = valid.clone();
        value.as_object_mut().unwrap().remove(field);
        reject(&value);
    }
    for value in [
        json!([]),
        json!(false),
        Value::Null,
        json!({"schema_version":"decision-scan/v1"}),
        json!({"schema_version":"web-assessment/v2","disposition":"incomplete"}),
    ] {
        reject(&value);
    }
}

#[test]
fn malformed_json_duplicate_keys_escaped_duplicates_and_resource_bounds_fail_closed() {
    for raw in [
        &b""[..],
        b"{",
        b"{} {}",
        b"{\"a\":1,\"a\":2}",
        b"{\"schema\":1,\"\\u0073chema\":2}",
        b"{\"x\":{\"a\":1,\"a\":2}}",
        b"[[[[[[[[[0]]]]]]]]]",
        b"{\"x\":1.5}",
        b"{\"x\":1e999}",
        b"{\"x\":\"\xff\"}",
    ] {
        assert_eq!(
            compare_reports(raw, SAMPLE, ComparisonFormat::Json),
            Err(ComparisonError::InvalidJson)
        );
    }
    let oversized = vec![b' '; MAX_COMPARISON_INPUT_BYTES + 1];
    assert_eq!(
        compare_reports(&oversized, SAMPLE, ComparisonFormat::Json),
        Err(ComparisonError::InputLimitExceeded)
    );
    let mut width = serde_json::Map::new();
    for index in 0..33 {
        width.insert(format!("field-{index}"), json!(index));
    }
    assert_eq!(
        compare_reports(
            &bytes(&Value::Object(width)),
            SAMPLE,
            ComparisonFormat::Json
        ),
        Err(ComparisonError::InvalidJson)
    );
    assert_eq!(
        compare_reports(
            &bytes(&json!({"x".repeat(129):0})),
            SAMPLE,
            ComparisonFormat::Json
        ),
        Err(ComparisonError::InvalidJson)
    );
}

#[test]
fn item_field_shape_enums_digest_reference_and_linkage_mutations_are_rejected() {
    for (field, replacement) in [
        ("schema", json!("venom-assessment-item/v2")),
        ("fingerprint", json!("sha512:00")),
        ("fingerprint", json!(format!("sha256:{}", "A".repeat(64)))),
        ("fingerprint", json!(format!("sha256:{}", "0".repeat(63)))),
        ("disposition", json!("resolved")),
        ("disposition", json!("confirmed")),
        ("claim_basis", json!("unknown")),
        ("claim_basis", json!("differential")),
        ("severity", json!("catastrophic")),
        ("severity", json!(42)),
        ("confidence_ppm", json!(1_000_001)),
        ("confidence_ppm", json!(-1)),
        ("evidence_count", json!(0)),
        (
            "evidence_references",
            json!(["evidence-0000", "evidence-0000"]),
        ),
        ("evidence_references", json!(["evidence-00a0"])),
        ("evidence_references", json!([false])),
        ("evidence_references", json!(null)),
        ("subject_reference", json!("subject-0002")),
        ("subject_reference", json!("subject-00000")),
        ("subject_reference", json!("subject-4294967296")),
        ("subject_reference", json!("subject-001")),
        ("subject_reference", json!("raw-subject")),
        ("case_reference", json!("bad-case")),
        ("case_reference", json!("case-0000")),
        ("outcome_reference", json!("bad-outcome")),
        ("outcome_reference", json!("outcome-0000")),
        ("verification_stage", json!("active")),
        ("verification_stage", json!("unknown")),
        (
            "remediation",
            json!({"id":"test@1","summary":"text","extra":true}),
        ),
        ("remediation", json!(false)),
        ("cwe", json!("")),
        ("title", json!("")),
        ("capability_id", json!("x".repeat(129))),
    ] {
        let mut value = item(1);
        value[field] = replacement;
        reject(&report(vec![value]));
    }
    let base = item(1);
    for key in base.as_object().unwrap().keys() {
        let mut value = base.clone();
        value.as_object_mut().unwrap().remove(key);
        reject(&report(vec![value]));
    }
    reject(&report(vec![Value::Null]));
    let mut duplicate = item(1);
    duplicate["control_evidence_references"] = json!(["evidence-0000"]);
    duplicate["evidence_count"] = json!(2);
    reject(&report(vec![duplicate]));
}

#[test]
fn exact_item_string_evidence_and_input_byte_limits_are_enforced() {
    let mut maximum = item(1);
    maximum["title"] = json!("x".repeat(import::MAX_DISPLAY_BYTES));
    maximum["capability_id"] = json!("x".repeat(import::MAX_IDENTIFIER_BYTES));
    maximum["evidence_count"] = json!(import::MAX_REFERENCES);
    maximum["evidence_references"] = json!((0..import::MAX_REFERENCES)
        .map(|index| format!("evidence-{index:04}"))
        .collect::<Vec<_>>());
    let valid = report(vec![maximum.clone()]);
    assert_eq!(group(&compare(&valid, &valid), "unchanged").len(), 1);
    maximum["title"] = json!("x".repeat(import::MAX_DISPLAY_BYTES + 1));
    reject(&report(vec![maximum.clone()]));
    maximum["title"] = json!("é".repeat(import::MAX_DISPLAY_BYTES / 2 + 1));
    reject(&report(vec![maximum.clone()]));
    maximum["title"] = json!("short");
    maximum["evidence_references"]
        .as_array_mut()
        .unwrap()
        .push(json!("evidence-0256"));
    maximum["evidence_count"] = json!(257);
    reject(&report(vec![maximum]));
    let mut padded = bytes(&report(vec![]));
    padded.resize(MAX_COMPARISON_INPUT_BYTES, b' ');
    assert!(compare_reports(&padded, &padded, ComparisonFormat::Json).is_ok());
    let at_limit = report((0..import::MAX_ITEMS as u32).map(item).collect());
    assert_eq!(
        import::parse(&bytes(&at_limit)).unwrap().items.len(),
        import::MAX_ITEMS
    );
    reject(&report((0..=import::MAX_ITEMS as u32).map(item).collect()));
}

#[test]
fn hostile_imported_text_is_inert_and_output_limit_never_returns_partial_document() {
    let hostile = "</script><script>alert(1)</script> [link](https://invalid.test) \x60 \x60\x60 | \u{202e}\n\u{0000}";
    let mut value = item(1);
    value["title"] = json!(hostile);
    value["redacted_summary"] = json!(hostile);
    value["remediation"]["summary"] = json!(hostile);
    let input = report(vec![value]);
    let document = compare_documents(
        import::parse(&bytes(&input)).unwrap(),
        import::parse(&bytes(&input)).unwrap(),
    )
    .unwrap();
    for format in [
        ComparisonFormat::Json,
        ComparisonFormat::Markdown,
        ComparisonFormat::Html,
    ] {
        let full = render(&document, format, super::super::MAX_RENDERED_REPORT_BYTES).unwrap();
        assert!(!full.contains('\u{202e}'));
        assert!(!full.contains('\u{0000}'));
        assert_eq!(render(&document, format, full.len()).unwrap(), full);
        assert_eq!(
            render(&document, format, full.len() - 1),
            Err(ComparisonError::OutputLimitExceeded)
        );
        assert_eq!(
            render(&document, format, 0),
            Err(ComparisonError::OutputLimitExceeded)
        );
    }
    assert_eq!(
        compare(&input, &input)["unchanged"][0]["before"]["title"],
        hostile
    );
    let markdown = render(&document, ComparisonFormat::Markdown, usize::MAX).unwrap();
    assert!(markdown.contains("Imported claims are not endorsed"));
    assert!(markdown.contains("\\u{202E}"));
    assert!(!render(&document, ComparisonFormat::Html, usize::MAX)
        .unwrap()
        .contains("<script>alert(1)</script>"));
}

#[test]
fn matched_evidence_total_256_is_accepted_but_257_is_rejected() {
    let mut matched = item(1);
    matched["disposition"] = json!("needs_review");
    matched["claim_basis"] = json!("differential");
    matched["evidence_references"] = json!([]);
    matched["control_evidence_references"] = json!((0..128)
        .map(|index| format!("evidence-{index:04}"))
        .collect::<Vec<_>>());
    matched["candidate_evidence_references"] = json!((128..256)
        .map(|index| format!("evidence-{index:04}"))
        .collect::<Vec<_>>());
    matched["evidence_count"] = json!(256);
    let valid = report(vec![matched.clone()]);
    let compared = compare(&valid, &valid);
    assert_eq!(group(&compared, "unchanged").len(), 1);
    assert_eq!(
        compared["unchanged"][0]["before"]["evidence"]["evidence_count"],
        256
    );
    assert_eq!(
        compared["unchanged"][0]["before"]["evidence"]["control_reference_count"],
        128
    );
    assert_eq!(
        compared["unchanged"][0]["before"]["evidence"]["candidate_reference_count"],
        128
    );

    // Both component sets still fit individually; the combined item does not.
    matched["candidate_evidence_references"]
        .as_array_mut()
        .unwrap()
        .push(json!("evidence-0256"));
    matched["evidence_count"] = json!(257);
    assert_eq!(
        compare_reports(
            &bytes(&report(vec![matched])),
            SAMPLE,
            ComparisonFormat::Json
        ),
        Err(ComparisonError::InvalidDocument),
    );
}

#[test]
fn every_static_error_is_source_free_and_parent_render_errors_map_without_data() {
    for error in [
        ComparisonError::InputLimitExceeded,
        ComparisonError::InvalidJson,
        ComparisonError::InvalidDocument,
        ComparisonError::UnsupportedDocument,
        ComparisonError::AmbiguousIdentity,
        ComparisonError::OutputLimitExceeded,
        ComparisonError::Serialization,
    ] {
        assert!(!error.to_string().is_empty());
        assert!(error.source().is_none());
    }
    assert_eq!(
        ComparisonError::from(ReportError::Serialization),
        ComparisonError::Serialization
    );
    assert_eq!(
        ComparisonError::from(ReportError::OutputLimitExceeded { limit: 1 }),
        ComparisonError::OutputLimitExceeded
    );
}

#[test]
fn projection_encoding_failures_are_static_and_produce_no_partial_metadata() {
    struct InvalidProjection;
    impl Serialize for InvalidProjection {
        fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("synthetic projection failure"))
        }
    }
    let mut output = RenderBuffer::new(100);
    assert_eq!(
        write_projection(&mut output, &InvalidProjection),
        Err(ComparisonError::Serialization)
    );
    assert_eq!(
        write_projection(&mut output, &Value::Null),
        Err(ComparisonError::Serialization)
    );
    assert!(output.finish().is_empty());
}

#[test]
fn json_has_all_interpretation_limits_and_markdown_shares_unchanged_projection() {
    let value = report(vec![item(1)]);
    let result = compare(&value, &value);
    assert_eq!(result["interpretation_limits"].as_array().unwrap().len(), 4);
    assert!(result["interpretation_limits"][1]
        .as_str()
        .unwrap()
        .contains("not mean fixed"));
    assert!(result["interpretation_limits"][2]
        .as_str()
        .unwrap()
        .contains("does not establish"));
    let markdown =
        compare_reports(&bytes(&value), &bytes(&value), ComparisonFormat::Markdown).unwrap();
    assert_eq!(markdown.matches("A bounded observation").count(), 1);
    assert!(markdown.contains("Shared comparable projection"));
    assert!(!markdown.contains("Changed fields:"));
    let changed = compare_documents(
        import::parse(&bytes(&value)).unwrap(),
        import::parse(&bytes(&report(vec![item(2)]))).unwrap(),
    )
    .unwrap();
    let markdown = render(&changed, ComparisonFormat::Markdown, 100_000).unwrap();
    assert_eq!(markdown.matches("Not present in this input.").count(), 2);
    assert!(!markdown.contains("Changed fields:"));

    let mut edited = item(1);
    edited["title"] = json!("Edited display title");
    let markdown = compare_reports(
        &bytes(&value),
        &bytes(&report(vec![edited])),
        ComparisonFormat::Markdown,
    )
    .unwrap();
    assert!(markdown.contains("- Changed fields: `title`"));
}

fn audit_fixtures() -> Vec<(&'static str, &'static str, Value)> {
    vec![
        (
            "openapi_review",
            "api.openapi-contract-observed@1",
            json!({
                "schema":"security.openapi-review-audit/v1", "capability_id":"api.openapi-contract-observed@1",
                "outcome":"not_eligible", "candidate_source":"conventional_openapi_json",
                "request_count":0, "active_verification_count":0, "version":null, "semantic_digest":null,
                "path_count":0, "operation_count":0, "get_operation_count":0, "write_operation_count":0,
                "path_parameter_count":0, "query_parameter_count":0, "explicit_auth_operation_count":0,
                "anonymous_operation_count":0, "url_like_operation_count":0, "multipart_operation_count":0,
                "deprecated_operation_count":0, "replay_matched":false, "item_projected":false
            }),
        ),
        (
            "rest_review",
            "api.rest-readonly-surface-observed@1",
            json!({
                "schema":"security.rest-readonly-review-audit/v1", "capability_id":"api.rest-readonly-surface-observed@1",
                "enabled":true, "method":"get", "outcome":"not_eligible", "request_count":0,
                "active_verification_count":0, "eligible_operation_count":0, "documented_response":null,
                "observed_media":"unknown", "replay_stable":false, "item_projected":false
            }),
        ),
        (
            "authorization_review",
            "authorization.resource-cross-principal-equivalence@1",
            json!({
                "schema":"security.authorization-review-audit/v1", "capability_id":"authorization.resource-cross-principal-equivalence@1",
                "policy_id":format!("authorization-policy-sha256:{}", "0".repeat(64)),
                "selected_path_count":1, "ignored_path_count":0, "request_count":0, "outcome":"not_eligible",
                "primary_stable":null, "peer_stable":null, "cross_resources_equivalent":null, "item_projected":false
            }),
        ),
        (
            "wordpress_review",
            "technology.wordpress-surface-observed@1",
            json!({
                "schema":"security.wordpress-review-audit/v1",
                "capability_id":"technology.wordpress-surface-observed@1",
                "catalog_status":"catalogue_not_supplied",
                "signal_count":0,
                "evidence_reference_count":0,
                "additional_request_count":0,
                "item_projected":false,
                "component_count":0,
                "advisory_count":0,
                "components":[],
                "advisories":[]
            }),
        ),
    ]
}

#[test]
fn all_current_optional_audits_are_feature_independent_bounded_display_snapshots() {
    for (name, _, audit) in audit_fixtures() {
        let mut document = report(vec![]);
        document[name] = audit.clone();
        let result = compare(&document, &document);
        assert_eq!(result["before"]["optional_audits"][name], audit);
        let comparison = compare(&report(vec![]), &document);
        assert_ne!(
            comparison["before"]["optional_audits"],
            comparison["after"]["optional_audits"]
        );
        for group_name in ["only_in_before", "only_in_after", "changed", "unchanged"] {
            assert!(group(&comparison, group_name).is_empty());
        }
        for key in audit.as_object().unwrap().keys() {
            let mut absent = document.clone();
            absent[name].as_object_mut().unwrap().remove(key);
            reject(&absent);
        }
        for (key, value) in [
            ("schema", json!("unsupported/v2")),
            ("capability_id", json!("wrong@1")),
            ("outcome", json!("unknown")),
            ("request_count", json!(5)),
            ("request_count", json!(false)),
            ("item_projected", json!(true)),
            ("item_projected", json!("false")),
            ("extra", json!("untrusted extension text")),
        ] {
            let mut invalid = document.clone();
            invalid[name][key] = value;
            reject(&invalid);
        }
        document[name] = Value::Null;
        reject(&document);
    }
}

fn evaluated_wordpress_audit() -> Value {
    json!({
        "schema":"security.wordpress-review-audit/v1",
        "capability_id":"technology.wordpress-surface-observed@1",
        "catalog_status":"evaluated",
        "catalog":{"id":"wordpress-security-advisories","revision":"2026-08-01","retrieved_on":"2026-08-01"},
        "signal_count":1,
        "evidence_reference_count":1,
        "additional_request_count":0,
        "item_projected":true,
        "component_count":1,
        "advisory_count":1,
        "components":[{
            "identity":{"kind":"core","slug":"wordpress"},
            "evidence_class":"conflicting",
            "identity_sources":["generator_metadata","operator_context"],
            "confidence_classes":["public_declaration","operator_assertion"],
            "versions":[
                {"value":"6.9.4","source":"generator_metadata","confidence":"public_declaration"},
                {"value":"6.9.5","source":"operator_context","confidence":"operator_assertion"}
            ],
            "activation":"active"
        }],
        "advisories":[{
            "id":"GHSA-fpp7-x2x2-2mjf",
            "component":{"kind":"core","slug":"wordpress"},
            "source":{
                "reference":"https://github.com/advisories/GHSA-fpp7-x2x2-2mjf",
                "revision":"github-advisory-2026-08-01",
                "retrieved_on":"2026-08-01",
                "usage_basis":"Locally supplied curated record; no catalogue network lookup was performed."
            },
            "cve":"CVE-2026-1234",
            "summary":"A bounded advisory summary <script>inert()</script>",
            "affected_ranges":[{
                "lower":{"declared":"6.9.0","inclusive":true},
                "upper":{"declared":"6.9.5","inclusive":false}
            }],
            "fixed_versions":["6.9.5"],
            "prerequisites":[
                {"kind":"hosting_os","expected":"linux","outcome":"matched_on_supplied_facts"},
                {"kind":"patch","expected":"not_applied","patch_id":"upstream-fix","outcome":"unknown"}
            ],
            "remediation":"Review the supplied upstream remediation guidance.",
            "component_evidence":"conflicting",
            "version_relation":"unknown",
            "applicability":"indeterminate_missing_evidence",
            "exploit_execution":"not_performed",
            "impact_validation":"not_performed"
        }]
    })
}

fn evaluated_wordpress_audit_v2() -> Value {
    json!({
        "schema":"security.wordpress-review-audit/v2",
        "capability_id":"technology.wordpress-surface-observed@1",
        "catalog_status":"evaluated",
        "catalog":{"id":"synthetic-profiled-wordpress-catalog","revision":"v2-r1","retrieved_on":"2026-09-07"},
        "signal_count":1,
        "evidence_reference_count":1,
        "additional_request_count":0,
        "item_projected":true,
        "component_count":1,
        "advisory_count":1,
        "components":[{
            "identity":{"kind":"core","slug":"wordpress"},
            "evidence_class":"observed_hint",
            "identity_sources":["generator_metadata","operator_context"],
            "confidence_classes":["public_declaration","operator_assertion"],
            "versions":[
                {"value":"2.4.0-beta1","source":"generator_metadata","confidence":"public_declaration"},
                {"value":"2.4.0+beta1","source":"operator_context","confidence":"operator_assertion"}
            ],
            "activation":"active"
        }],
        "advisories":[{
            "id":"SYNTHETIC-PROFILED-CORE-1",
            "component":{"kind":"core","slug":"wordpress"},
            "source":{
                "reference":"https://example.test/advisories/profiled-core-1",
                "revision":"v2-r1",
                "retrieved_on":"2026-09-07",
                "usage_basis":"Synthetic comparison-reader contract record."
            },
            "cve":null,
            "summary":"Synthetic PHP-subset profile record",
            "affected_ranges":[{
                "lower":{"declared":"2.4.0-beta0","inclusive":true},
                "upper":{"declared":"2.4.0","inclusive":false}
            }],
            "fixed_versions":["2.4.0"],
            "prerequisites":[],
            "remediation":null,
            "comparison_profile":"php-release-subset/v1",
            "version_resolution":"supported_equivalent",
            "version_resolution_reason":"equivalent_supported_versions",
            "component_evidence":"observed_hint",
            "version_relation":"within_declared_range",
            "applicability":"candidate_match_on_declared_facts",
            "exploit_execution":"not_performed",
            "impact_validation":"not_performed"
        }]
    })
}

fn saved_inventory_wordpress_audit_v3() -> Value {
    json!({
        "schema":"security.wordpress-review-audit/v3",
        "capability_id":"technology.wordpress-surface-observed@1",
        "catalog_status":"catalogue_not_supplied",
        "inventory_import":{
            "coverage":{"core":"not_supplied","plugins":"supplied","themes":"not_supplied"},
            "component_count":1,
            "limitations":[],
            "inputs":[{
                "class":"wp_cli_plugins_json",
                "byte_length":71,
                "sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            }]
        },
        "signal_count":0,
        "evidence_reference_count":0,
        "additional_request_count":0,
        "item_projected":false,
        "component_count":1,
        "advisory_count":0,
        "components":[{
            "identity":{"kind":"plugin","slug":"synthetic-plugin"},
            "evidence_class":"operator_supplied",
            "identity_sources":["operator_context"],
            "confidence_classes":["operator_assertion"],
            "versions":[{
                "value":"1.2.3-vendor",
                "source":"operator_context",
                "confidence":"operator_assertion"
            }],
            "activation":"active",
            "inventory_status":"active"
        }],
        "advisories":[]
    })
}

fn wordfence_external_wordpress_audit_v4() -> Value {
    json!({
        "schema":"security.wordpress-review-audit/v4",
        "capability_id":"technology.wordpress-surface-observed@1",
        "catalog_status":"evaluated",
        "inventory_import":{
            "coverage":{"core":"not_supplied","plugins":"supplied","themes":"not_supplied"},
            "component_count":1,
            "limitations":[],
            "inputs":[{
                "class":"wp_cli_plugins_json",
                "byte_length":71,
                "sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            }]
        },
        "external_review":{
            "source_namespace":"wordfence-intelligence",
            "source_format":"wordfence-v3-production",
            "mapping_revision":"termivar-wordfence-v3-production/v1",
            "comparison_policy":"wordfence-v3/source-semantics-unresolved/v1",
            "input":{
                "byte_length":3883,
                "sha256":"d9ed3140f44ae1e0a3746beb9937de2d829d28c068101120a9104c3349901db7",
                "semantic_sha256":"1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            },
            "counts":{
                "parsed_records":2,
                "software_associations":3,
                "selected_associations":1,
                "evaluable_associations":0,
                "unsupported_associations":1,
                "excluded_associations":2
            },
            "notices":[{
                "id":"wordfence-notice-sha256:4ffcd7a3223d808b0f98dd5b51a4bd63a0db073c993b646ec09ae152fefc28d8",
                "message":"Synthetic rights message.",
                "party":"termivar_fixture_author",
                "notice":"Synthetic fixture notice.",
                "license":"Synthetic fixture licence terms.",
                "license_url":"https://example.invalid/fixture-terms"
            }],
            "evaluations":[{
                "key":{
                    "source_namespace":"wordfence-intelligence",
                    "upstream_id":"00000000-0000-4000-8000-000000000001",
                    "component":{"kind":"plugin","slug":"termivar-fixture-component"}
                },
                "title":"[SYNTHETIC] Multi-component fixture advisory",
                "display_name":"[SYNTHETIC] Fixture Plugin",
                "informational":false,
                "description":"Fictional bounded parser data, not a vulnerability claim.",
                "references":["https://example.invalid/fixture-advisory"],
                "record_reference":"https://example.invalid/fixture-advisory",
                "cwe":null,
                "cvss":null,
                "cve":null,
                "cve_link":null,
                "researchers":["Synthetic Fixture Author"],
                "source_dates":{
                    "published":"2026-01-02 03:04:05",
                    "updated":"2026-02-03 04:05:06"
                },
                "affected_ranges":[{
                    "label":"[1.0.0, 1.2.3]",
                    "from_kind":"declared",
                    "from_version":"1.0.0",
                    "from_inclusive":true,
                    "to_kind":"declared",
                    "to_version":"1.2.3",
                    "to_inclusive":true
                }],
                "source_patched":true,
                "source_patched_versions":["1.2.4"],
                "source_remediation":"Review the source-declared version through the normal update process.",
                "notice_ids":["wordfence-notice-sha256:4ffcd7a3223d808b0f98dd5b51a4bd63a0db073c993b646ec09ae152fefc28d8"],
                "component_evidence":"operator_supplied",
                "version_evidence_resolution":{
                    "status":"single_declaration",
                    "evidence_row_count":1,
                    "distinct_spelling_count":1
                },
                "version_relation":"source_comparison_semantics_unresolved",
                "applicability":"indeterminate_unsupported",
                "execution":{
                    "exploit_execution":"not_performed",
                    "impact_validation":"not_performed"
                }
            }]
        },
        "signal_count":0,
        "evidence_reference_count":0,
        "additional_request_count":0,
        "item_projected":false,
        "component_count":1,
        "advisory_count":0,
        "components":[{
            "identity":{"kind":"plugin","slug":"termivar-fixture-component"},
            "evidence_class":"operator_supplied",
            "identity_sources":["operator_context"],
            "confidence_classes":["operator_assertion"],
            "versions":[{
                "value":"1.1.0",
                "source":"operator_context",
                "confidence":"operator_assertion"
            }],
            "activation":"active",
            "inventory_status":"active"
        }],
        "advisories":[]
    })
}

fn wordfence_external_wordpress_audit_v5() -> Value {
    let mut audit = wordfence_external_wordpress_audit_v4();
    audit["schema"] = json!("security.wordpress-review-audit/v5");
    let external = &mut audit["external_review"];
    external["comparison_policy"] = json!("termivar.wordfence-v3-explicit-interpretation/v1");
    external["comparison_profile"] = json!("numeric-dotted/v1");
    external["policy_selection"] = json!("explicit_operator");
    external["source_semantics_assurance"] = json!("not_established");
    external["counts"] = json!({
        "parsed_records":2,
        "software_associations":3,
        "selected_associations":1,
        "evaluable_associations":1,
        "unsupported_associations":0,
        "excluded_associations":2,
        "within_associations":1,
        "outside_associations":0,
        "indeterminate_associations":0,
        "selected_ranges":1,
        "evaluated_ranges":1,
        "containing_ranges":1,
        "noncontaining_ranges":0,
        "unsupported_ranges":0,
        "invalid_ranges":0,
        "not_evaluated_ranges":0,
        "partial_range_coverage_associations":0
    });
    let evaluation = &mut external["evaluations"][0];
    evaluation["version_evidence_resolution"]["semantic_status"] = json!("supported_equivalent");
    evaluation["version_evidence_resolution"]["semantic_reason"] =
        json!("single_supported_version");
    evaluation["range_evaluations"] = json!([{
        "relation":"contains",
        "reason":"selected_version_within_bounds"
    }]);
    evaluation["version_relation"] = json!("within_supported_range_under_selected_policy");
    evaluation["version_relation_reason"] = json!("containing_range");
    evaluation["applicability"] = json!("version_match_under_selected_policy");
    audit
}

fn make_wordfence_v5_indeterminate(
    audit: &mut Value,
    relation_reason: &str,
    range_relation: Option<(&str, &str)>,
) {
    let external = &mut audit["external_review"];
    external["counts"]["evaluable_associations"] = json!(0);
    external["counts"]["unsupported_associations"] = json!(1);
    external["counts"]["within_associations"] = json!(0);
    external["counts"]["indeterminate_associations"] = json!(1);
    external["counts"]["evaluated_ranges"] = json!(0);
    external["counts"]["containing_ranges"] = json!(0);
    external["counts"]["noncontaining_ranges"] = json!(0);
    external["counts"]["unsupported_ranges"] = json!(0);
    external["counts"]["invalid_ranges"] = json!(0);
    external["counts"]["not_evaluated_ranges"] = json!(0);
    let evaluation = &mut external["evaluations"][0];
    evaluation["version_relation"] = json!("indeterminate");
    evaluation["version_relation_reason"] = json!(relation_reason);
    evaluation["applicability"] = json!("indeterminate");
    match range_relation {
        Some((relation, reason)) => {
            evaluation["range_evaluations"] = json!([{
                "relation": relation,
                "reason": reason
            }]);
            external["counts"][match relation {
                "unsupported" => "unsupported_ranges",
                "invalid_under_profile" => "invalid_ranges",
                "not_evaluated" => "not_evaluated_ranges",
                _ => panic!("unsupported indeterminate range relation"),
            }] = json!(1);
        },
        None => {
            evaluation["affected_ranges"] = json!([]);
            evaluation["range_evaluations"] = json!([]);
            external["counts"]["selected_ranges"] = json!(0);
        },
    }
}

fn wordfence_external_wordpress_audit_v4_with_notices(count: usize) -> Value {
    let mut audit = wordfence_external_wordpress_audit_v4();
    let mut notices = Vec::with_capacity(count);
    let mut notice_ids = Vec::with_capacity(count);
    for index in 0..count {
        let message = format!("Synthetic rights message {index}.");
        let party = format!("synthetic_party_{index}");
        let notice = format!("Synthetic fixture notice {index}.");
        let license = format!("Synthetic fixture licence terms {index}.");
        let license_url = format!("https://example.invalid/fixture-terms/{index}");
        let id = synthetic_wordfence_notice_id(&message, &party, &notice, &license, &license_url);
        notice_ids.push(id.clone());
        notices.push(json!({
            "id":id,
            "message":message,
            "party":party,
            "notice":notice,
            "license":license,
            "license_url":license_url
        }));
    }
    audit["external_review"]["notices"] = json!(notices);
    audit["external_review"]["evaluations"][0]["notice_ids"] = json!(notice_ids);
    audit
}

fn wordpress_document(audit: Value) -> Value {
    let items = if audit["item_projected"] == json!(true) {
        let mut observed = item(1);
        observed["capability_id"] = json!("technology.wordpress-surface-observed@1");
        vec![observed]
    } else {
        Vec::new()
    };
    let mut document = report(items);
    document["wordpress_review"] = audit;
    document
}

fn wordpress_comparison(comparison: &Value) -> &Value {
    comparison
        .get("wordpress_review_comparison")
        .expect("a supplied WordPress audit has a semantic comparison")
}

#[test]
fn wordpress_comparison_is_additive_and_self_comparison_is_unchanged() {
    let without_wordpress = compare(&report(Vec::new()), &report(Vec::new()));
    assert!(without_wordpress
        .get("wordpress_review_comparison")
        .is_none());

    for audit in [evaluated_wordpress_audit(), evaluated_wordpress_audit_v2()] {
        let document = wordpress_document(audit);
        let comparison = compare(&document, &document);
        let wordpress = wordpress_comparison(&comparison);
        assert_eq!(
            wordpress["schema"],
            "termivar-wordpress-review-comparison/v1"
        );
        assert_eq!(wordpress["status"], "compared");
        assert!(wordpress.get("reason").is_none());
        assert_eq!(wordpress["components"]["paired_unchanged_count"], 1);
        assert_eq!(wordpress["advisories"]["paired_unchanged_count"], 1);
        for entity in ["components", "advisories"] {
            for class in ["paired_changed", "only_in_before", "only_in_after"] {
                assert!(wordpress[entity][class].as_array().unwrap().is_empty());
            }
        }
        assert_eq!(group(&comparison, "unchanged").len(), 1);
        assert!(group(&comparison, "changed").is_empty());
    }
}

#[test]
fn wordpress_set_like_order_does_not_create_semantic_changes() {
    let mut before = evaluated_wordpress_audit_v2();
    before["advisories"][0]["affected_ranges"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "lower":{"declared":"3.0.0","inclusive":true},
            "upper":{"declared":"4.0.0","inclusive":false}
        }));
    let mut after = before.clone();
    after["components"][0]["versions"]
        .as_array_mut()
        .unwrap()
        .reverse();
    after["advisories"][0]["affected_ranges"]
        .as_array_mut()
        .unwrap()
        .reverse();
    let comparison = compare(&wordpress_document(before), &wordpress_document(after));
    let wordpress = wordpress_comparison(&comparison);
    assert_eq!(wordpress["components"]["paired_unchanged_count"], 1);
    assert_eq!(wordpress["advisories"]["paired_unchanged_count"], 1);
    assert!(wordpress["components"]["paired_changed"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(wordpress["advisories"]["paired_changed"]
        .as_array()
        .unwrap()
        .is_empty());

    let mut before = wordfence_external_wordpress_audit_v4();
    before["external_review"]["evaluations"][0]["references"]
        .as_array_mut()
        .unwrap()
        .push(json!("https://example.invalid/another-reference"));
    before["external_review"]["evaluations"][0]["record_reference"] =
        json!("https://example.invalid/another-reference");
    let mut after = before.clone();
    after["external_review"]["evaluations"][0]["references"]
        .as_array_mut()
        .unwrap()
        .reverse();
    let comparison = compare(&wordpress_document(before), &wordpress_document(after));
    let wordpress = wordpress_comparison(&comparison);
    assert_eq!(wordpress["components"]["paired_unchanged_count"], 1);
    assert_eq!(wordpress["advisories"]["paired_unchanged_count"], 1);
}

#[test]
fn wordpress_component_and_advisory_changes_use_independent_dimensions() {
    let before = wordpress_document(saved_inventory_wordpress_audit_v3());
    let mut after = before.clone();
    after["wordpress_review"]["components"][0]["versions"][0]["value"] = json!("2.0.0");
    after["wordpress_review"]["components"][0]["activation"] = json!("inactive");
    after["wordpress_review"]["components"][0]["inventory_status"] = json!("inactive");
    let comparison = compare(&before, &after);
    assert_eq!(
        wordpress_comparison(&comparison)["components"]["paired_changed"][0]["changed_dimensions"],
        json!(["component_evidence"])
    );

    let base = wordpress_document(evaluated_wordpress_audit_v2());
    for (field, replacement, expected) in [
        (
            "affected_ranges",
            json!([{
                "lower":{"declared":"2.3.0","inclusive":true},
                "upper":{"declared":"2.4.0","inclusive":false}
            }]),
            json!(["affected_ranges"]),
        ),
        (
            "fixed_versions",
            json!(["2.4.1"]),
            json!(["source_fix_information"]),
        ),
    ] {
        let mut after = base.clone();
        after["wordpress_review"]["advisories"][0][field] = replacement;
        let comparison = compare(&base, &after);
        assert_eq!(
            wordpress_comparison(&comparison)["advisories"]["paired_changed"][0]
                ["changed_dimensions"],
            expected,
            "{field}"
        );
    }

    let mut revision = base.clone();
    revision["wordpress_review"]["advisories"][0]["source"]["revision"] = json!("v2-r2");
    let comparison = compare(&base, &revision);
    assert_eq!(
        wordpress_comparison(&comparison)["advisories"]["paired_changed"][0]["changed_dimensions"],
        json!(["source_provenance"])
    );
    assert_eq!(
        wordpress_comparison(&comparison)["provenance"]["status"],
        "unchanged"
    );

    let mut catalog_revision = base.clone();
    catalog_revision["wordpress_review"]["catalog"]["revision"] = json!("v2-r2");
    let comparison = compare(&base, &catalog_revision);
    assert_eq!(
        wordpress_comparison(&comparison)["provenance"]["changed_fields"],
        json!(["catalog"])
    );
    assert_eq!(
        wordpress_comparison(&comparison)["advisories"]["paired_unchanged_count"],
        1
    );
}

#[test]
fn wordpress_methodology_and_applicability_changes_are_not_conflated() {
    let mut numeric = evaluated_wordpress_audit_v2();
    numeric["components"][0]["identity_sources"] = json!(["generator_metadata"]);
    numeric["components"][0]["confidence_classes"] = json!(["public_declaration"]);
    numeric["components"][0]["versions"] = json!([{
        "value":"1.0",
        "source":"generator_metadata",
        "confidence":"public_declaration"
    }]);
    numeric["components"][0]["activation"] = Value::Null;
    numeric["advisories"][0]["affected_ranges"] = json!([{
        "lower":{"declared":"0.9","inclusive":true},
        "upper":{"declared":"2.0","inclusive":false}
    }]);
    numeric["advisories"][0]["fixed_versions"] = json!(["2.0"]);
    numeric["advisories"][0]["comparison_profile"] = json!("numeric-dotted/v1");
    numeric["advisories"][0]["version_resolution"] = json!("supported_equivalent");
    numeric["advisories"][0]["version_resolution_reason"] = json!("single_supported_version");
    let mut php = numeric.clone();
    php["advisories"][0]["comparison_profile"] = json!("php-release-subset/v1");
    let numeric = wordpress_document(numeric);
    let php = wordpress_document(php);
    let comparison = compare(&numeric, &php);
    assert_eq!(
        wordpress_comparison(&comparison)["advisories"]["paired_changed"][0]["changed_dimensions"],
        json!(["comparison_methodology"])
    );

    let mut before = evaluated_wordpress_audit_v2();
    before["advisories"][0]["prerequisites"] = json!([{
        "kind":"hosting_os",
        "expected":"linux",
        "outcome":"unknown"
    }]);
    before["advisories"][0]["applicability"] = json!("indeterminate_missing_evidence");
    let mut after = before.clone();
    after["advisories"][0]["prerequisites"][0]["outcome"] = json!("matched_on_supplied_facts");
    after["advisories"][0]["applicability"] = json!("candidate_match_on_declared_facts");
    let comparison = compare(&wordpress_document(before), &wordpress_document(after));
    assert_eq!(
        wordpress_comparison(&comparison)["advisories"]["paired_changed"][0]["changed_dimensions"],
        json!(["applicability", "evaluation_basis"])
    );
}

#[test]
fn wordpress_simultaneous_and_missing_audit_changes_preserve_uncertainty() {
    let before = wordpress_document(evaluated_wordpress_audit_v2());
    let mut after = before.clone();
    after["wordpress_review"]["components"][0]["activation"] = Value::Null;
    after["wordpress_review"]["advisories"][0]["summary"] = json!("Updated supplied prose");
    let comparison = compare(&before, &after);
    let wordpress = wordpress_comparison(&comparison);
    assert_eq!(
        wordpress["components"]["paired_changed"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        wordpress["advisories"]["paired_changed"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        wordpress["components"]["paired_changed"][0]["changed_dimensions"],
        json!(["component_evidence"])
    );
    assert_eq!(
        wordpress["advisories"]["paired_changed"][0]["changed_dimensions"],
        json!(["advisory_content"])
    );

    let absent = report(Vec::new());
    let forward = compare(&absent, &before);
    let reverse = compare(&before, &absent);
    for (comparison, reason) in [
        (&forward, "before_audit_missing"),
        (&reverse, "after_audit_missing"),
    ] {
        let wordpress = wordpress_comparison(comparison);
        assert_eq!(wordpress["status"], "not_compared");
        assert_eq!(wordpress["reason"], reason);
        assert_eq!(wordpress["coverage"]["status"], "coverage_changed");
        for entity in ["components", "advisories"] {
            assert_eq!(wordpress[entity]["paired_unchanged_count"], 0);
            for class in ["paired_changed", "only_in_before", "only_in_after"] {
                assert!(wordpress[entity][class].as_array().unwrap().is_empty());
            }
        }
    }
}

#[test]
fn wordpress_advisory_keys_require_namespace_upstream_id_and_component() {
    let before = wordpress_document(evaluated_wordpress_audit());
    let mut namespace_after = before.clone();
    namespace_after["wordpress_review"]["catalog"]["id"] = json!("another-reviewed-catalog");
    let mut upstream_after = before.clone();
    upstream_after["wordpress_review"]["advisories"][0]["id"] = json!("SYNTHETIC-DIFFERENT-ID");
    let mut plugin_before = before.clone();
    plugin_before["wordpress_review"]["components"][0]["identity"] =
        json!({"kind":"plugin","slug":"shared-component"});
    plugin_before["wordpress_review"]["advisories"][0]["component"] =
        json!({"kind":"plugin","slug":"shared-component"});
    let mut theme_after = plugin_before.clone();
    theme_after["wordpress_review"]["components"][0]["identity"]["kind"] = json!("theme");
    theme_after["wordpress_review"]["advisories"][0]["component"]["kind"] = json!("theme");

    for (before, after) in [
        (&before, &namespace_after),
        (&before, &upstream_after),
        (&plugin_before, &theme_after),
    ] {
        let comparison = compare(before, after);
        let advisories = &wordpress_comparison(&comparison)["advisories"];
        assert!(advisories["paired_changed"].as_array().unwrap().is_empty());
        assert_eq!(advisories["only_in_before"].as_array().unwrap().len(), 1);
        assert_eq!(advisories["only_in_after"].as_array().unwrap().len(), 1);
        assert_eq!(
            advisories["only_in_before"][0]["interpretation"],
            "present_only_in_the_supplied_before_audit_not_verified_remediation"
        );
        assert_eq!(
            advisories["only_in_after"][0]["interpretation"],
            "present_only_in_the_supplied_after_audit_not_verified_newness"
        );
        let reversed = compare(after, before);
        let reversed = &wordpress_comparison(&reversed)["advisories"];
        assert_eq!(
            advisories["only_in_before"][0]["key"],
            reversed["only_in_after"][0]["key"]
        );
        assert_eq!(
            advisories["only_in_after"][0]["key"],
            reversed["only_in_before"][0]["key"]
        );
    }

    let mut title_only = before.clone();
    title_only["wordpress_review"]["advisories"][0]["summary"] =
        json!("Different supplied title-like prose");
    let comparison = compare(&before, &title_only);
    let advisories = &wordpress_comparison(&comparison)["advisories"];
    assert_eq!(advisories["paired_changed"].as_array().unwrap().len(), 1);
    assert!(advisories["only_in_before"].as_array().unwrap().is_empty());
    assert!(advisories["only_in_after"].as_array().unwrap().is_empty());
}

#[test]
fn wordpress_v4_distinguishes_raw_input_bytes_from_selected_semantics() {
    let before = wordpress_document(wordfence_external_wordpress_audit_v4());
    let mut after = before.clone();
    after["wordpress_review"]["external_review"]["input"]["sha256"] =
        json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let comparison = compare(&before, &after);
    let wordpress = wordpress_comparison(&comparison);
    assert_eq!(
        wordpress["provenance"]["status"],
        "input_bytes_changed_without_selected_semantic_change"
    );
    assert_eq!(wordpress["components"]["paired_unchanged_count"], 1);
    assert_eq!(wordpress["advisories"]["paired_unchanged_count"], 1);
    assert_eq!(wordpress["methodology"]["status"], "unchanged");
}

#[test]
fn wordpress_v5_self_compare_and_profile_change_preserve_external_identity() {
    let numeric = wordpress_document(wordfence_external_wordpress_audit_v5());
    let self_comparison = compare(&numeric, &numeric);
    let wordpress = wordpress_comparison(&self_comparison);
    assert_eq!(wordpress["methodology"]["status"], "unchanged");
    assert_eq!(wordpress["components"]["paired_unchanged_count"], 1);
    assert_eq!(wordpress["advisories"]["paired_unchanged_count"], 1);
    assert!(wordpress["advisories"]["paired_changed"]
        .as_array()
        .unwrap()
        .is_empty());

    let mut php = numeric.clone();
    php["wordpress_review"]["external_review"]["comparison_profile"] =
        json!("php-release-subset/v1");
    let comparison = compare(&numeric, &php);
    let wordpress = wordpress_comparison(&comparison);
    assert_eq!(wordpress["methodology"]["status"], "changed");
    assert_eq!(wordpress["components"]["paired_unchanged_count"], 1);
    assert_eq!(wordpress["advisories"]["paired_unchanged_count"], 1);
    for side in ["only_in_before", "only_in_after"] {
        assert!(wordpress["advisories"][side].as_array().unwrap().is_empty());
    }
}

#[test]
fn wordpress_v4_to_v5_is_methodology_and_evaluation_change_not_add_remove() {
    let unresolved = wordpress_document(wordfence_external_wordpress_audit_v4());
    let evaluated = wordpress_document(wordfence_external_wordpress_audit_v5());
    let comparison = compare(&unresolved, &evaluated);
    let wordpress = wordpress_comparison(&comparison);

    assert_eq!(wordpress["methodology"]["status"], "changed");
    assert_eq!(wordpress["components"]["paired_unchanged_count"], 1);
    assert_eq!(wordpress["advisories"]["paired_unchanged_count"], 0);
    assert_eq!(
        wordpress["advisories"]["paired_changed"][0]["changed_dimensions"],
        json!(["applicability", "evaluation_basis"])
    );
    assert!(wordpress["advisories"]["only_in_before"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(wordpress["advisories"]["only_in_after"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn wordpress_v5_recomputes_profile_resolution_ranges_and_counters() {
    let valid = wordpress_document(wordfence_external_wordpress_audit_v5());
    assert_eq!(
        wordpress_comparison(&compare(&valid, &valid))["advisories"]["paired_unchanged_count"],
        1
    );

    for field in [
        "comparison_profile",
        "policy_selection",
        "source_semantics_assurance",
    ] {
        let mut missing = valid.clone();
        missing["wordpress_review"]["external_review"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        reject(&missing);
    }
    for field in ["range_evaluations", "version_relation_reason"] {
        let mut missing = valid.clone();
        missing["wordpress_review"]["external_review"]["evaluations"][0]
            .as_object_mut()
            .unwrap()
            .remove(field);
        reject(&missing);
    }
    for field in ["semantic_status", "semantic_reason"] {
        let mut missing = valid.clone();
        missing["wordpress_review"]["external_review"]["evaluations"][0]
            ["version_evidence_resolution"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        reject(&missing);
    }

    for (path, replacement) in [
        (
            vec!["external_review", "comparison_policy"],
            json!("wordfence-v3/source-semantics-unresolved/v1"),
        ),
        (
            vec!["external_review", "comparison_profile"],
            json!("semver/v1"),
        ),
        (
            vec!["external_review", "policy_selection"],
            json!("inferred"),
        ),
        (
            vec!["external_review", "source_semantics_assurance"],
            json!("established"),
        ),
        (
            vec!["external_review", "counts", "within_associations"],
            json!(0),
        ),
        (
            vec!["external_review", "counts", "evaluated_ranges"],
            json!(0),
        ),
        (
            vec![
                "external_review",
                "counts",
                "partial_range_coverage_associations",
            ],
            json!(1),
        ),
        (
            vec![
                "external_review",
                "evaluations",
                "0",
                "version_evidence_resolution",
                "semantic_status",
            ],
            json!("conflicting"),
        ),
        (
            vec![
                "external_review",
                "evaluations",
                "0",
                "version_evidence_resolution",
                "semantic_reason",
            ],
            json!("equivalent_supported_versions"),
        ),
        (
            vec![
                "external_review",
                "evaluations",
                "0",
                "range_evaluations",
                "0",
                "relation",
            ],
            json!("does_not_contain"),
        ),
        (
            vec![
                "external_review",
                "evaluations",
                "0",
                "range_evaluations",
                "0",
                "reason",
            ],
            json!("selected_version_outside_bounds"),
        ),
        (
            vec![
                "external_review",
                "evaluations",
                "0",
                "version_relation_reason",
            ],
            json!("all_ranges_outside"),
        ),
        (
            vec!["external_review", "evaluations", "0", "applicability"],
            json!("no_version_match_under_selected_policy"),
        ),
    ] {
        let mut invalid = valid.clone();
        let mut cursor = &mut invalid["wordpress_review"];
        for segment in &path[..path.len() - 1] {
            cursor = if let Ok(index) = segment.parse::<usize>() {
                &mut cursor[index]
            } else {
                &mut cursor[*segment]
            };
        }
        cursor[path[path.len() - 1]] = replacement;
        reject(&invalid);
    }

    let mut source_bound_changed_without_evaluation = valid.clone();
    source_bound_changed_without_evaluation["wordpress_review"]["external_review"]["evaluations"]
        [0]["affected_ranges"][0]["to_version"] = json!("1.0.1");
    reject(&source_bound_changed_without_evaluation);
}

#[test]
fn wordpress_v5_import_rejects_cartesian_interpretation_work_over_budget() {
    // Each association requires 16 range visits, 16 patched-version parses,
    // and 16 * 16 contradiction checks. 342 associations therefore require
    // 98,496 operations, above the existing 98,304-operation ceiling.
    const ASSOCIATION_COUNT: usize = 342;
    const RANGE_COUNT: usize = 16;
    const PATCHED_VERSION_COUNT: usize = 16;

    let mut audit = wordfence_external_wordpress_audit_v5();
    let external = &mut audit["external_review"];
    let base = external["evaluations"][0].clone();
    let ranges = (0..RANGE_COUNT)
        .map(|index| {
            json!({
                "label":format!("[1.0.0, 1.2.{index}]"),
                "from_kind":"declared",
                "from_version":"1.0.0",
                "from_inclusive":true,
                "to_kind":"declared",
                "to_version":format!("1.2.{index}"),
                "to_inclusive":true
            })
        })
        .collect::<Vec<_>>();
    let patched_versions = (0..PATCHED_VERSION_COUNT)
        .map(|index| format!("2.0.{index}"))
        .collect::<Vec<_>>();
    let range_evaluations = (0..RANGE_COUNT)
        .map(|_| {
            json!({
                "relation":"contains",
                "reason":"selected_version_within_bounds"
            })
        })
        .collect::<Vec<_>>();
    let evaluations = (0..ASSOCIATION_COUNT)
        .map(|index| {
            let mut evaluation = base.clone();
            evaluation["key"]["upstream_id"] =
                json!(format!("00000000-0000-4000-8000-{index:012x}"));
            evaluation["affected_ranges"] = json!(ranges);
            evaluation["source_patched_versions"] = json!(patched_versions);
            evaluation["range_evaluations"] = json!(range_evaluations);
            evaluation
        })
        .collect::<Vec<_>>();
    external["evaluations"] = json!(evaluations);
    external["counts"] = json!({
        "parsed_records":ASSOCIATION_COUNT,
        "software_associations":ASSOCIATION_COUNT,
        "selected_associations":ASSOCIATION_COUNT,
        "evaluable_associations":ASSOCIATION_COUNT,
        "unsupported_associations":0,
        "excluded_associations":0,
        "within_associations":ASSOCIATION_COUNT,
        "outside_associations":0,
        "indeterminate_associations":0,
        "selected_ranges":ASSOCIATION_COUNT * RANGE_COUNT,
        "evaluated_ranges":ASSOCIATION_COUNT * RANGE_COUNT,
        "containing_ranges":ASSOCIATION_COUNT * RANGE_COUNT,
        "noncontaining_ranges":0,
        "unsupported_ranges":0,
        "invalid_ranges":0,
        "not_evaluated_ranges":0,
        "partial_range_coverage_associations":0
    });

    reject(&wordpress_document(audit));
}

#[test]
fn wordpress_v5_accepts_recomputed_outside_and_indeterminate_results() {
    let mut outside = wordfence_external_wordpress_audit_v5();
    outside["components"][0]["versions"][0]["value"] = json!("2.0.0");
    let external = &mut outside["external_review"];
    external["counts"]["within_associations"] = json!(0);
    external["counts"]["outside_associations"] = json!(1);
    external["counts"]["containing_ranges"] = json!(0);
    external["counts"]["noncontaining_ranges"] = json!(1);
    let evaluation = &mut external["evaluations"][0];
    evaluation["range_evaluations"][0] = json!({
        "relation":"does_not_contain",
        "reason":"selected_version_outside_bounds"
    });
    evaluation["version_relation"] = json!("outside_declared_ranges_under_selected_policy");
    evaluation["version_relation_reason"] = json!("all_ranges_outside");
    evaluation["applicability"] = json!("no_version_match_under_selected_policy");
    let outside = wordpress_document(outside);
    assert_eq!(
        wordpress_comparison(&compare(&outside, &outside))["advisories"]["paired_unchanged_count"],
        1
    );

    let mut unsupported = wordfence_external_wordpress_audit_v5();
    unsupported["components"][0]["versions"][0]["value"] = json!("2.0-vendor");
    let external = &mut unsupported["external_review"];
    external["counts"]["evaluable_associations"] = json!(0);
    external["counts"]["unsupported_associations"] = json!(1);
    external["counts"]["within_associations"] = json!(0);
    external["counts"]["indeterminate_associations"] = json!(1);
    external["counts"]["evaluated_ranges"] = json!(0);
    external["counts"]["containing_ranges"] = json!(0);
    external["counts"]["not_evaluated_ranges"] = json!(1);
    let evaluation = &mut external["evaluations"][0];
    evaluation["version_evidence_resolution"]["semantic_status"] = json!("unsupported");
    evaluation["version_evidence_resolution"]["semantic_reason"] =
        json!("unsupported_version_evidence");
    evaluation["range_evaluations"][0] = json!({
        "relation":"not_evaluated",
        "reason":"unsupported_version_evidence"
    });
    evaluation["version_relation"] = json!("indeterminate");
    evaluation["version_relation_reason"] = json!("unsupported_version_evidence");
    evaluation["applicability"] = json!("indeterminate");
    let unsupported = wordpress_document(unsupported);
    assert_eq!(
        wordpress_comparison(&compare(&unsupported, &unsupported))["advisories"]
            ["paired_unchanged_count"],
        1
    );
}

#[test]
fn wordpress_v5_imports_typed_missing_conflicting_and_range_boundary_results() {
    let mut missing = wordfence_external_wordpress_audit_v5();
    missing["components"][0]["versions"] = json!([]);
    let resolution =
        &mut missing["external_review"]["evaluations"][0]["version_evidence_resolution"];
    *resolution = json!({
        "status":"missing",
        "evidence_row_count":0,
        "distinct_spelling_count":0,
        "semantic_status":"missing",
        "semantic_reason":"no_version_evidence"
    });
    make_wordfence_v5_indeterminate(
        &mut missing,
        "missing_version_evidence",
        Some(("not_evaluated", "missing_version_evidence")),
    );

    let mut conflicting = wordfence_external_wordpress_audit_v5();
    conflicting
        .as_object_mut()
        .unwrap()
        .remove("inventory_import");
    conflicting["components"][0] = json!({
        "identity":{"kind":"core","slug":"wordpress"},
        "evidence_class":"observed_hint",
        "identity_sources":["generator_metadata","operator_context"],
        "confidence_classes":["public_declaration","operator_assertion"],
        "versions":[
            {"value":"1.0.0","source":"generator_metadata","confidence":"public_declaration"},
            {"value":"1.1.0","source":"operator_context","confidence":"operator_assertion"}
        ],
        "activation":null
    });
    conflicting["signal_count"] = json!(1);
    conflicting["evidence_reference_count"] = json!(1);
    conflicting["item_projected"] = json!(true);
    conflicting["external_review"]["evaluations"][0]["key"]["component"] =
        json!({"kind":"core","slug":"wordpress"});
    conflicting["external_review"]["evaluations"][0]["component_evidence"] = json!("observed_hint");
    conflicting["external_review"]["evaluations"][0]["version_evidence_resolution"] = json!({
        "status":"multiple_distinct_declarations",
        "evidence_row_count":2,
        "distinct_spelling_count":2,
        "semantic_status":"conflicting",
        "semantic_reason":"conflicting_version_evidence"
    });
    make_wordfence_v5_indeterminate(
        &mut conflicting,
        "conflicting_version_evidence",
        Some(("not_evaluated", "conflicting_version_evidence")),
    );

    let mut unsupported_lower = wordfence_external_wordpress_audit_v5();
    unsupported_lower["external_review"]["evaluations"][0]["affected_ranges"][0]["from_version"] =
        json!("vendor");
    make_wordfence_v5_indeterminate(
        &mut unsupported_lower,
        "unsupported_affected_range",
        Some(("unsupported", "unsupported_lower_bound")),
    );

    let mut unsupported_upper = wordfence_external_wordpress_audit_v5();
    unsupported_upper["external_review"]["evaluations"][0]["affected_ranges"][0]["to_version"] =
        json!("vendor");
    make_wordfence_v5_indeterminate(
        &mut unsupported_upper,
        "unsupported_affected_range",
        Some(("unsupported", "unsupported_upper_bound")),
    );

    let mut empty_exclusive = wordfence_external_wordpress_audit_v5();
    let range = &mut empty_exclusive["external_review"]["evaluations"][0]["affected_ranges"][0];
    range["from_version"] = json!("1.1.0");
    range["from_inclusive"] = json!(false);
    range["to_version"] = json!("1.1.0");
    range["to_inclusive"] = json!(true);
    make_wordfence_v5_indeterminate(
        &mut empty_exclusive,
        "invalid_affected_range",
        Some(("invalid_under_profile", "empty_exclusive_interval")),
    );

    let mut missing_ranges = wordfence_external_wordpress_audit_v5();
    make_wordfence_v5_indeterminate(&mut missing_ranges, "missing_affected_ranges", None);

    for (label, audit) in [
        ("missing", missing),
        ("conflicting", conflicting),
        ("unsupported lower", unsupported_lower),
        ("unsupported upper", unsupported_upper),
        ("empty exclusive", empty_exclusive),
        ("missing ranges", missing_ranges),
    ] {
        let document = wordpress_document(audit);
        assert!(
            import::parse(&bytes(&document)).is_ok(),
            "{label} v5 document was rejected"
        );
        assert_eq!(
            wordpress_comparison(&compare(&document, &document))["advisories"]
                ["paired_unchanged_count"],
            1,
            "{label}"
        );
    }
}

#[test]
fn wordpress_structured_markdown_and_html_keep_hostile_values_inert() {
    let before = wordpress_document(evaluated_wordpress_audit());
    let mut after = before.clone();
    after["wordpress_review"]["advisories"][0]["summary"] =
        json!("</script><script>alert('wordpress')</script>");

    let markdown =
        compare_reports(&bytes(&before), &bytes(&after), ComparisonFormat::Markdown).unwrap();
    assert!(markdown.contains("## WordPress review differences"));
    assert!(markdown.contains("advisory_content"));
    assert!(markdown.contains("does not rerun the scan"));

    let html = compare_reports(&bytes(&before), &bytes(&after), ComparisonFormat::Html).unwrap();
    let prerendered = html.split("<script>").next().unwrap();
    assert!(prerendered.contains("id=\"wordpress-review-differences\""));
    assert!(prerendered.contains("Changed WordPress dimensions"));
    assert!(prerendered.contains("advisory_content"));
    assert!(prerendered
        .contains("&lt;/script&gt;&lt;script&gt;alert(&#39;wordpress&#39;)&lt;/script&gt;"));
    assert!(!prerendered.contains("<script>alert('wordpress')</script>"));
    assert_eq!(html.matches("<script>").count(), 1);
    assert_eq!(html.matches("</script>").count(), 1);
    assert!(html.contains("default-src 'none'"));
    assert!(html.contains("connect-src 'none'"));
    assert!(html.contains("script-src 'sha256-"));
    assert!(!html.contains("innerHTML"));
    assert!(html.contains(".textContent"));
}

#[test]
fn wordpress_v4_external_review_is_strict_feature_independent_and_raw_free() {
    let audit = wordfence_external_wordpress_audit_v4();
    let mut document = report(vec![]);
    document["wordpress_review"] = audit.clone();
    let comparison = compare(&document, &document);
    assert!(group(&comparison, "unchanged").is_empty());
    assert_eq!(
        comparison["before"]["optional_audits"]["wordpress_review"],
        audit
    );

    for (path, replacement) in [
        (
            vec!["external_review", "source_namespace"],
            json!("unclassified-provider"),
        ),
        (
            vec!["external_review", "source_format"],
            json!("wordfence-v3-scanner"),
        ),
        (vec!["external_review", "mapping_revision"], json!("latest")),
        (
            vec!["external_review", "comparison_policy"],
            json!("php-release-subset/v1"),
        ),
        (
            vec!["external_review", "input", "sha256"],
            json!("D9ED3140F44AE1E0A3746BEB9937DE2D829D28C068101120A9104C3349901DB7"),
        ),
        (
            vec!["external_review", "counts", "evaluable_associations"],
            json!(1),
        ),
        (
            vec!["external_review", "counts", "excluded_associations"],
            json!(1),
        ),
        (
            vec!["external_review", "evaluations", "0", "version_relation"],
            json!("within_declared_range"),
        ),
        (
            vec!["external_review", "evaluations", "0", "applicability"],
            json!("candidate_match_on_declared_facts"),
        ),
        (
            vec![
                "external_review",
                "evaluations",
                "0",
                "version_evidence_resolution",
                "status",
            ],
            json!("multiple_distinct_declarations"),
        ),
        (
            vec![
                "external_review",
                "evaluations",
                "0",
                "version_evidence_resolution",
                "evidence_row_count",
            ],
            json!(0),
        ),
    ] {
        let mut invalid = document.clone();
        let mut cursor = &mut invalid["wordpress_review"];
        for segment in &path[..path.len() - 1] {
            cursor = if let Ok(index) = segment.parse::<usize>() {
                &mut cursor[index]
            } else {
                &mut cursor[*segment]
            };
        }
        cursor[path[path.len() - 1]] = replacement;
        reject(&invalid);
    }

    let mut missing = document.clone();
    missing["wordpress_review"]
        .as_object_mut()
        .unwrap()
        .remove("external_review");
    reject(&missing);

    let mut unexpected = document.clone();
    unexpected["wordpress_review"]["external_review"]["retrieved_on"] = json!("2026-09-07");
    reject(&unexpected);

    let mut oversized_evaluation_object = document.clone();
    oversized_evaluation_object["wordpress_review"]["external_review"]["evaluations"][0]
        ["unexpected_24th_field"] = json!(true);
    reject(&oversized_evaluation_object);

    let mut unused_notice = document.clone();
    unused_notice["wordpress_review"]["external_review"]["evaluations"][0]["notice_ids"] =
        json!([]);
    reject(&unused_notice);

    let mut notice_identity_mismatch = document.clone();
    notice_identity_mismatch["wordpress_review"]["external_review"]["notices"][0]["message"] =
        json!("Changed without changing the content-derived notice identifier.");
    reject(&notice_identity_mismatch);

    let mut duplicate = document;
    let evaluation = duplicate["wordpress_review"]["external_review"]["evaluations"][0].clone();
    duplicate["wordpress_review"]["external_review"]["evaluations"]
        .as_array_mut()
        .unwrap()
        .push(evaluation);
    duplicate["wordpress_review"]["external_review"]["counts"] = json!({
        "parsed_records":2,
        "software_associations":4,
        "selected_associations":2,
        "evaluable_associations":0,
        "unsupported_associations":2,
        "excluded_associations":2
    });
    reject(&duplicate);
}

#[test]
fn wordpress_v4_external_counts_preserve_the_source_record_envelope() {
    for (parsed_records, software_associations, excluded_associations) in
        [(0_u64, 1_u64, 0_u64), (1, 2_049, 2_048)]
    {
        let mut document = report(vec![]);
        document["wordpress_review"] = wordfence_external_wordpress_audit_v4();
        let counts = &mut document["wordpress_review"]["external_review"]["counts"];
        counts["parsed_records"] = json!(parsed_records);
        counts["software_associations"] = json!(software_associations);
        counts["excluded_associations"] = json!(excluded_associations);
        reject(&document);
    }
}

#[test]
fn wordpress_v4_v5_defiant_attribution_requires_the_exact_safe_record_link() {
    for mut audit in [
        wordfence_external_wordpress_audit_v4(),
        wordfence_external_wordpress_audit_v5(),
    ] {
        let notice = &mut audit["external_review"]["notices"][0];
        notice["party"] = json!("defiant");
        let id = synthetic_wordfence_notice_id(
            notice["message"].as_str().unwrap(),
            notice["party"].as_str().unwrap(),
            notice["notice"].as_str().unwrap(),
            notice["license"].as_str().unwrap(),
            notice["license_url"].as_str().unwrap(),
        );
        notice["id"] = json!(id.clone());
        let evaluation = &mut audit["external_review"]["evaluations"][0];
        evaluation["notice_ids"] = json!([id]);
        evaluation["references"] = json!([
            "https://example.invalid/fixture-advisory",
            "http://www.wordfence.com/threat-intel/vulnerabilities/synthetic-fixture"
        ]);
        evaluation["record_reference"] =
            json!("http://www.wordfence.com/threat-intel/vulnerabilities/synthetic-fixture");
        let mut valid = report(vec![]);
        valid["wordpress_review"] = audit;
        assert!(group(&compare(&valid, &valid), "unchanged").is_empty());

        let mut https_valid = valid.clone();
        https_valid["wordpress_review"]["external_review"]["evaluations"][0]["references"] = json!([
            "https://www.wordfence.com/threat-intel/vulnerabilities/synthetic-fixture?source=api-test"
        ]);
        https_valid["wordpress_review"]["external_review"]["evaluations"][0]["record_reference"] = json!(
            "https://www.wordfence.com/threat-intel/vulnerabilities/synthetic-fixture?source=api-test"
        );
        assert!(group(&compare(&https_valid, &https_valid), "unchanged").is_empty());

        for hostile in [
            Value::Null,
            json!("ftp://www.wordfence.com/threat-intel/vulnerabilities/synthetic-fixture"),
            json!("https://wordfence.com/threat-intel/vulnerabilities/synthetic-fixture"),
            json!("https://user@www.wordfence.com/threat-intel/vulnerabilities/synthetic-fixture"),
            json!("https://www.wordfence.com:8443/threat-intel/vulnerabilities/synthetic-fixture"),
            json!("https://www.wordfence.com/help/synthetic-fixture"),
            json!("https://www.wordfence.com/threat-intel/vulnerabilities/synthetic-fixture?source="),
            json!("https://www.wordfence.com/threat-intel/vulnerabilities/synthetic-fixture?source=api-test&source=other"),
            json!("https://www.wordfence.com/threat-intel/vulnerabilities/synthetic-fixture?source=api-test&extra=1"),
            json!("https://www.wordfence.com/threat-intel/vulnerabilities/synthetic-fixture?source=api%2Dtest"),
            json!("https://www.wordfence.com/threat-intel/vulnerabilities/synthetic-fixture?source=api-test#part"),
            json!("https://www.wordfence.com/threat-intel/vulnerabilities/synthetic-fixture\" onmouseover=\"x"),
        ] {
            let mut invalid = valid.clone();
            invalid["wordpress_review"]["external_review"]["evaluations"][0]["references"] =
                json!([hostile.clone()]);
            invalid["wordpress_review"]["external_review"]["evaluations"][0]
                ["record_reference"] = hostile;
            reject(&invalid);
        }
    }
}

#[test]
fn wordpress_v4_notice_party_limit_matches_the_producer_record_contract() {
    let mut supported = report(vec![]);
    supported["wordpress_review"] = wordfence_external_wordpress_audit_v4_with_notices(15);
    assert!(group(&compare(&supported, &supported), "unchanged").is_empty());

    let mut unsupported = report(vec![]);
    unsupported["wordpress_review"] = wordfence_external_wordpress_audit_v4_with_notices(16);
    reject(&unsupported);
}

#[test]
fn wordpress_v4_inventory_is_independently_optional_but_identity_bound() {
    let mut audit = wordfence_external_wordpress_audit_v4();
    audit.as_object_mut().unwrap().remove("inventory_import");
    audit["signal_count"] = json!(1);
    audit["evidence_reference_count"] = json!(1);
    audit["item_projected"] = json!(true);
    audit["components"][0] = json!({
        "identity":{"kind":"core","slug":"wordpress"},
        "evidence_class":"observed_hint",
        "identity_sources":["generator_metadata"],
        "confidence_classes":["public_declaration"],
        "versions":[{
            "value":"1.0",
            "source":"generator_metadata",
            "confidence":"public_declaration"
        }],
        "activation":null
    });
    audit["external_review"]["evaluations"][0]["key"]["component"] =
        json!({"kind":"core","slug":"wordpress"});
    audit["external_review"]["evaluations"][0]["component_evidence"] = json!("observed_hint");
    let mut observed = item(1);
    observed["capability_id"] = json!("technology.wordpress-surface-observed@1");
    let mut document = report(vec![observed]);
    document["wordpress_review"] = audit;
    assert_eq!(group(&compare(&document, &document), "unchanged").len(), 1);

    let mut unbound = document;
    unbound["wordpress_review"]["external_review"]["evaluations"][0]["key"]["component"] =
        json!({"kind":"theme","slug":"unobserved-theme"});
    reject(&unbound);
}

#[test]
fn wordpress_v4_version_evidence_resolution_is_comparator_neutral_and_recomputed() {
    let mut missing = report(vec![]);
    missing["wordpress_review"] = wordfence_external_wordpress_audit_v4();
    missing["wordpress_review"]["components"][0]["versions"] = json!([]);
    missing["wordpress_review"]["external_review"]["evaluations"][0]
        ["version_evidence_resolution"] = json!({
        "status":"missing",
        "evidence_row_count":0,
        "distinct_spelling_count":0
    });
    assert!(group(&compare(&missing, &missing), "unchanged").is_empty());

    let mut observed = item(1);
    observed["capability_id"] = json!("technology.wordpress-surface-observed@1");
    let mut repeated = report(vec![observed]);
    repeated["wordpress_review"] = wordfence_external_wordpress_audit_v4();
    repeated["wordpress_review"]["signal_count"] = json!(1);
    repeated["wordpress_review"]["evidence_reference_count"] = json!(1);
    repeated["wordpress_review"]["item_projected"] = json!(true);
    repeated["wordpress_review"]["components"][0]["evidence_class"] = json!("observed_hint");
    repeated["wordpress_review"]["components"][0]["identity_sources"] =
        json!(["same_origin_asset_path", "operator_context"]);
    repeated["wordpress_review"]["components"][0]["confidence_classes"] =
        json!(["structural_hint", "operator_assertion"]);
    repeated["wordpress_review"]["components"][0]["versions"] = json!([
        {
            "value":"1.1.0",
            "source":"same_origin_asset_path",
            "confidence":"structural_hint"
        },
        {
            "value":"1.1.0",
            "source":"operator_context",
            "confidence":"operator_assertion"
        }
    ]);
    repeated["wordpress_review"]["external_review"]["evaluations"][0]["component_evidence"] =
        json!("observed_hint");
    repeated["wordpress_review"]["external_review"]["evaluations"][0]
        ["version_evidence_resolution"] = json!({
        "status":"repeated_exact_declaration",
        "evidence_row_count":2,
        "distinct_spelling_count":1
    });
    assert_eq!(group(&compare(&repeated, &repeated), "unchanged").len(), 1);

    let mut distinct = repeated.clone();
    distinct["wordpress_review"]["components"][0]["versions"][1]["value"] = json!("1.1.0.0");
    distinct["wordpress_review"]["external_review"]["evaluations"][0]
        ["version_evidence_resolution"] = json!({
        "status":"multiple_distinct_declarations",
        "evidence_row_count":2,
        "distinct_spelling_count":2
    });
    assert_eq!(group(&compare(&distinct, &distinct), "unchanged").len(), 1);

    let mut forged = distinct;
    forged["wordpress_review"]["external_review"]["evaluations"][0]
        ["version_evidence_resolution"]["distinct_spelling_count"] = json!(1);
    reject(&forged);
}

#[test]
fn wordpress_v4_reader_matches_external_source_edge_contracts() {
    let mut audit = wordfence_external_wordpress_audit_v4();
    audit["external_review"]["evaluations"][0]["cve"] = json!("CVE-2099-1234");
    audit["external_review"]["evaluations"][0]["affected_ranges"] = json!([]);
    audit["external_review"]["evaluations"][0]["title"] = json!("Synthetic\nTitle");
    audit["external_review"]["evaluations"][0]["display_name"] = json!("Synthetic\tComponent");
    audit["external_review"]["evaluations"][0]["description"] = json!("Synthetic\rdescription");
    audit["external_review"]["evaluations"][0]["source_remediation"] = json!("");
    audit["external_review"]["evaluations"][0]["researchers"] = json!(["Synthetic\tResearcher"]);
    audit["external_review"]["evaluations"][0]["cwe"] = json!({
        "id":9999,
        "name":"Synthetic\tCWE",
        "description":"Synthetic\rCWE detail"
    });
    audit["external_review"]["evaluations"][0]["cvss"] = json!({
        "vector":"CVSS:3.1/AV:N\n",
        "score":"5.3",
        "rating":"medium"
    });
    let mut document = report(vec![]);
    document["wordpress_review"] = audit;
    assert!(group(&compare(&document, &document), "unchanged").is_empty());

    let mut orphan_link = document.clone();
    orphan_link["wordpress_review"]["external_review"]["evaluations"][0]["cve"] = Value::Null;
    orphan_link["wordpress_review"]["external_review"]["evaluations"][0]["cve_link"] =
        json!("https://example.invalid/CVE-2099-1234");
    reject(&orphan_link);

    let mut uppercase_uuid = document.clone();
    uppercase_uuid["wordpress_review"]["external_review"]["evaluations"][0]["key"]["upstream_id"] =
        json!("00000000-0000-4000-8000-00000000000A");
    reject(&uppercase_uuid);

    let mut invalid_date = document;
    invalid_date["wordpress_review"]["external_review"]["evaluations"][0]["source_dates"]
        ["published"] = json!("2026-02-30 03:04:05");
    reject(&invalid_date);

    let mut disallowed_control = report(vec![]);
    disallowed_control["wordpress_review"] = wordfence_external_wordpress_audit_v4();
    disallowed_control["wordpress_review"]["external_review"]["evaluations"][0]["title"] =
        json!("Synthetic\u{1}Title");
    reject(&disallowed_control);
}

#[test]
fn wordpress_v3_saved_inventory_is_strict_and_feature_independent() {
    let audit = saved_inventory_wordpress_audit_v3();
    let mut document = report(vec![]);
    document["wordpress_review"] = audit.clone();

    let comparison = compare(&document, &document);
    assert!(group(&comparison, "unchanged").is_empty());
    assert_eq!(
        comparison["before"]["optional_audits"]["wordpress_review"],
        audit
    );

    for mutation in [
        ("component_count", json!(0)),
        ("inputs", json!([])),
        (
            "inputs",
            json!([{
                "class":"wp_cli_plugins_json",
                "byte_length":71,
                "sha256":"0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"
            }]),
        ),
        (
            "inputs",
            json!([{
                "class":"arbitrary_path",
                "byte_length":71,
                "sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            }]),
        ),
    ] {
        let mut invalid = document.clone();
        invalid["wordpress_review"]["inventory_import"][mutation.0] = mutation.1;
        reject(&invalid);
    }

    let mut coverage_mismatch = document.clone();
    coverage_mismatch["wordpress_review"]["inventory_import"]["coverage"]["plugins"] =
        json!("not_supplied");
    reject(&coverage_mismatch);

    let mut status_outside_supplied_category = document.clone();
    status_outside_supplied_category["wordpress_review"]["inventory_import"]["coverage"] =
        json!({"core":"not_supplied","plugins":"not_supplied","themes":"supplied"});
    status_outside_supplied_category["wordpress_review"]["inventory_import"]["inputs"][0]
        ["class"] = json!("wp_cli_themes_json");
    reject(&status_outside_supplied_category);

    let mut operator_without_inventory_status = document.clone();
    operator_without_inventory_status["wordpress_review"]["inventory_import"]["component_count"] =
        json!(0);
    operator_without_inventory_status["wordpress_review"]["components"][0]
        .as_object_mut()
        .unwrap()
        .remove("inventory_status");
    reject(&operator_without_inventory_status);

    let mut status_mismatch = document.clone();
    status_mismatch["wordpress_review"]["components"][0]["inventory_status"] = json!("parent");
    reject(&status_mismatch);

    let mut forged_observed_inventory = document.clone();
    forged_observed_inventory["wordpress_review"]["components"][0]["identity_sources"] =
        json!(["same_origin_asset_path"]);
    forged_observed_inventory["wordpress_review"]["components"][0]["confidence_classes"] =
        json!(["structural_hint"]);
    forged_observed_inventory["wordpress_review"]["components"][0]["evidence_class"] =
        json!("observed_hint");
    forged_observed_inventory["wordpress_review"]["components"][0]["versions"][0]["source"] =
        json!("same_origin_asset_path");
    forged_observed_inventory["wordpress_review"]["components"][0]["versions"][0]["confidence"] =
        json!("structural_hint");
    reject(&forged_observed_inventory);

    let mut missing_inventory = document;
    missing_inventory["wordpress_review"]
        .as_object_mut()
        .unwrap()
        .remove("inventory_import");
    reject(&missing_inventory);
}

#[test]
fn wordpress_v3_legacy_catalogue_retains_numeric_conflict_semantics() {
    let mut audit = saved_inventory_wordpress_audit_v3();
    audit["signal_count"] = json!(1);
    audit["evidence_reference_count"] = json!(1);
    audit["item_projected"] = json!(true);
    audit["inventory_import"]["coverage"] =
        json!({"core":"supplied","plugins":"not_supplied","themes":"not_supplied"});
    audit["inventory_import"]["inputs"] = json!([{
        "class":"wp_cli_core_version_file",
        "byte_length":6,
        "sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }]);
    audit["components"][0] = json!({
        "identity":{"kind":"core","slug":"wordpress"},
        "evidence_class":"conflicting",
        "identity_sources":["generator_metadata","operator_context"],
        "confidence_classes":["public_declaration","operator_assertion"],
        "versions":[
            {"value":"6.9.4","source":"generator_metadata","confidence":"public_declaration"},
            {"value":"6.9.5","source":"operator_context","confidence":"operator_assertion"}
        ],
        "activation":null,
        "inventory_status":"core_version_supplied"
    });
    let mut observed = item(1);
    observed["capability_id"] = json!("technology.wordpress-surface-observed@1");
    let mut document = report(vec![observed]);
    document["wordpress_review"] = audit;
    assert_eq!(group(&compare(&document, &document), "unchanged").len(), 1);

    let mut hidden_conflict = document;
    hidden_conflict["wordpress_review"]["components"][0]["evidence_class"] = json!("observed_hint");
    reject(&hidden_conflict);
}

#[test]
fn wordpress_audit_is_strict_feature_independent_and_visible_in_all_comparisons() {
    let audit = evaluated_wordpress_audit();
    let mut observed = item(1);
    observed["capability_id"] = json!("technology.wordpress-surface-observed@1");
    let mut after = report(vec![observed]);
    after["wordpress_review"] = audit.clone();
    let mut before = after.clone();
    before["wordpress_review"]["catalog"]["revision"] = json!("2026-07-31");

    let comparison = compare(&before, &after);
    assert_eq!(
        comparison["before"]["optional_audits"]["wordpress_review"]["catalog"]["revision"],
        "2026-07-31"
    );
    assert_eq!(
        comparison["after"]["optional_audits"]["wordpress_review"],
        audit
    );
    assert_eq!(group(&comparison, "unchanged").len(), 1);

    let markdown =
        compare_reports(&bytes(&before), &bytes(&after), ComparisonFormat::Markdown).unwrap();
    assert!(markdown.contains("wordpress_review"));
    assert!(markdown.contains("2026-07-31"));
    assert!(markdown.contains("2026-08-01"));

    let html = compare_reports(&bytes(&before), &bytes(&after), ComparisonFormat::Html).unwrap();
    assert!(html.contains("Optional audit: wordpress_review"));
    assert!(html.contains("2026-07-31"));
    assert!(html.contains("2026-08-01"));
    assert!(!html.contains("<script>inert()</script>"));
    assert!(html.contains("&lt;script&gt;inert()&lt;/script&gt;"));

    let mut unsupported_version = after.clone();
    unsupported_version["wordpress_review"]["components"][0]["versions"][0]["value"] =
        json!("6.9-RC1");
    unsupported_version["wordpress_review"]["advisories"][0]["version_relation"] =
        json!("unsupported");
    unsupported_version["wordpress_review"]["advisories"][0]["applicability"] =
        json!("indeterminate_unsupported");
    assert_eq!(
        group(
            &compare(&unsupported_version, &unsupported_version),
            "unchanged"
        )
        .len(),
        1
    );

    let mut no_declared_ranges = after.clone();
    no_declared_ranges["wordpress_review"]["advisories"][0]["affected_ranges"] = json!([]);
    assert_eq!(
        group(
            &compare(&no_declared_ranges, &no_declared_ranges),
            "unchanged"
        )
        .len(),
        1
    );

    for mutation in [
        ("exploit_execution", json!("performed")),
        ("impact_validation", json!("performed")),
        ("version_relation", json!("php_version_compare")),
    ] {
        let mut invalid = after.clone();
        invalid["wordpress_review"]["advisories"][0][mutation.0] = mutation.1;
        reject(&invalid);
    }
    let mut invalid = after.clone();
    invalid["wordpress_review"]["advisories"][0]["source"]["unexpected"] = json!(true);
    reject(&invalid);
    let mut invalid = after.clone();
    invalid["wordpress_review"]["advisories"][0]["source"]["reference"] =
        json!("http://insecure.invalid/advisory");
    reject(&invalid);
    let mut invalid = after.clone();
    invalid["wordpress_review"]["catalog"]["retrieved_on"] = json!("2026-02-30");
    reject(&invalid);
    let mut invalid = after.clone();
    invalid["wordpress_review"]["catalog_status"] = json!("catalogue_not_supplied");
    reject(&invalid);
    let mut invalid = after.clone();
    invalid["wordpress_review"]["advisories"][0]["applicability"] =
        json!("candidate_match_on_declared_facts");
    reject(&invalid);
    let mut mixed = after.clone();
    mixed["wordpress_review"]["advisories"][0]["prerequisites"] = json!([
        {
            "kind":"hosting_os",
            "expected":"windows",
            "outcome":"contradicted_on_supplied_facts"
        },
        {
            "kind":"unsupported",
            "expected":"vendor_specific_runtime_state",
            "outcome":"unsupported"
        }
    ]);
    mixed["wordpress_review"]["advisories"][0]["applicability"] =
        json!("contradicted_by_declared_facts");
    assert_eq!(group(&compare(&mixed, &mixed), "unchanged").len(), 1);
    mixed["wordpress_review"]["advisories"][0]["applicability"] =
        json!("indeterminate_unsupported");
    reject(&mixed);
    for (kind, outcome) in [
        ("unsupported", "matched_on_supplied_facts"),
        ("hosting_os", "unsupported"),
    ] {
        let mut invalid = after.clone();
        invalid["wordpress_review"]["advisories"][0]["prerequisites"] = json!([{
            "kind": kind,
            "expected": if kind == "unsupported" { "vendor_specific" } else { "linux" },
            "outcome": outcome
        }]);
        invalid["wordpress_review"]["advisories"][0]["applicability"] = if outcome == "unsupported"
        {
            json!("indeterminate_unsupported")
        } else {
            json!("candidate_match_on_declared_facts")
        };
        reject(&invalid);
    }
    let mut invalid = after.clone();
    let duplicate = invalid["wordpress_review"]["components"][0].clone();
    invalid["wordpress_review"]["components"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    invalid["wordpress_review"]["component_count"] = json!(2);
    reject(&invalid);
    let mut invalid = after;
    invalid["wordpress_review"]["components"][0]["versions"][0]["value"] = json!("");
    reject(&invalid);
}

#[test]
fn wordpress_v1_reader_keeps_its_preprofile_component_acceptance_contract() {
    let mut audit = evaluated_wordpress_audit();
    audit["components"][0]["identity"] =
        json!({"kind":"plugin","slug":"historical-reader-fixture"});
    audit["components"][0]["evidence_class"] = json!("observed_hint");
    audit["components"][0]["identity_sources"] = json!(["same_origin_asset_path"]);
    audit["components"][0]["confidence_classes"] = json!(["structural_hint"]);
    for version in audit["components"][0]["versions"].as_array_mut().unwrap() {
        version["source"] = json!("same_origin_asset_path");
        version["confidence"] = json!("structural_hint");
    }
    audit["components"][0]["activation"] = json!("active");
    audit["advisories"][0]["component"] =
        json!({"kind":"plugin","slug":"historical-reader-fixture"});

    let mut observed = item(1);
    observed["capability_id"] = json!("technology.wordpress-surface-observed@1");
    let mut document = report(vec![observed]);
    document["wordpress_review"] = audit;
    assert_eq!(group(&compare(&document, &document), "unchanged").len(), 1);

    let mut operator_only = document.clone();
    operator_only["wordpress_review"]["components"][0]["evidence_class"] =
        json!("operator_supplied");
    operator_only["wordpress_review"]["components"][0]["identity_sources"] =
        json!(["operator_context"]);
    operator_only["wordpress_review"]["components"][0]["confidence_classes"] =
        json!(["operator_assertion"]);
    for version in operator_only["wordpress_review"]["components"][0]["versions"]
        .as_array_mut()
        .unwrap()
    {
        version["source"] = json!("operator_context");
        version["confidence"] = json!("operator_assertion");
    }
    assert_eq!(
        group(&compare(&operator_only, &operator_only), "unchanged").len(),
        1
    );
}

#[test]
fn wordpress_v2_audit_is_profiled_strict_and_feature_independent() {
    let audit = evaluated_wordpress_audit_v2();
    let mut observed = item(1);
    observed["capability_id"] = json!("technology.wordpress-surface-observed@1");
    let mut document = report(vec![observed]);
    document["wordpress_review"] = audit.clone();

    let comparison = compare(&document, &document);
    assert_eq!(group(&comparison, "unchanged").len(), 1);
    assert_eq!(
        comparison["before"]["optional_audits"]["wordpress_review"],
        audit
    );

    let mut reordered = document.clone();
    reordered["wordpress_review"]["components"][0]["versions"]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert_eq!(
        group(&compare(&reordered, &reordered), "unchanged").len(),
        1
    );

    for field in [
        "comparison_profile",
        "version_resolution",
        "version_resolution_reason",
    ] {
        let mut missing = document.clone();
        missing["wordpress_review"]["advisories"][0]
            .as_object_mut()
            .unwrap()
            .remove(field);
        reject(&missing);
    }
    for (field, value) in [
        ("comparison_profile", json!("semver/v1")),
        ("version_resolution", json!("resolved")),
        (
            "version_resolution_reason",
            json!("equivalent_supported_versions_unknown"),
        ),
        ("component_evidence", json!("conflicting")),
        ("version_relation", json!("outside_declared_ranges")),
        ("applicability", json!("indeterminate_missing_evidence")),
    ] {
        let mut invalid = document.clone();
        invalid["wordpress_review"]["advisories"][0][field] = value;
        reject(&invalid);
    }
    let mut mismatched_reason = document.clone();
    mismatched_reason["wordpress_review"]["advisories"][0]["version_resolution_reason"] =
        json!("single_supported_version");
    reject(&mismatched_reason);

    let mut numeric_profile_with_php_endpoints = document.clone();
    numeric_profile_with_php_endpoints["wordpress_review"]["advisories"][0]["comparison_profile"] =
        json!("numeric-dotted/v1");
    reject(&numeric_profile_with_php_endpoints);

    let mut legacy_component_conflict = document.clone();
    legacy_component_conflict["wordpress_review"]["components"][0]["evidence_class"] =
        json!("conflicting");
    reject(&legacy_component_conflict);

    let mut version_source_not_declared = document.clone();
    version_source_not_declared["wordpress_review"]["components"][0]["identity_sources"] =
        json!(["operator_context"]);
    version_source_not_declared["wordpress_review"]["components"][0]["confidence_classes"] =
        json!(["operator_assertion"]);
    reject(&version_source_not_declared);

    let mut confidence_class_not_declared = document.clone();
    confidence_class_not_declared["wordpress_review"]["components"][0]["confidence_classes"] =
        json!(["public_declaration"]);
    reject(&confidence_class_not_declared);

    let mut asset_path_version = document.clone();
    asset_path_version["wordpress_review"]["components"][0]["identity_sources"] =
        json!(["same_origin_asset_path", "operator_context"]);
    asset_path_version["wordpress_review"]["components"][0]["confidence_classes"] =
        json!(["structural_hint", "operator_assertion"]);
    asset_path_version["wordpress_review"]["components"][0]["versions"][0]["source"] =
        json!("same_origin_asset_path");
    asset_path_version["wordpress_review"]["components"][0]["versions"][0]["confidence"] =
        json!("structural_hint");
    reject(&asset_path_version);

    let mut plugin_generator_version = document.clone();
    plugin_generator_version["wordpress_review"]["components"][0]["identity"] =
        json!({"kind":"plugin","slug":"sample-plugin"});
    plugin_generator_version["wordpress_review"]["advisories"][0]["component"] =
        json!({"kind":"plugin","slug":"sample-plugin"});
    reject(&plugin_generator_version);

    let mut plugin_generator_without_version = document.clone();
    plugin_generator_without_version["wordpress_review"]["components"][0]["identity"] =
        json!({"kind":"plugin","slug":"sample-plugin"});
    plugin_generator_without_version["wordpress_review"]["components"][0]["versions"] = json!([]);
    plugin_generator_without_version["wordpress_review"]["advisories"][0]["component"] =
        json!({"kind":"plugin","slug":"sample-plugin"});
    plugin_generator_without_version["wordpress_review"]["advisories"][0]["version_resolution"] =
        json!("missing");
    plugin_generator_without_version["wordpress_review"]["advisories"][0]
        ["version_resolution_reason"] = json!("no_version_evidence");
    plugin_generator_without_version["wordpress_review"]["advisories"][0]["version_relation"] =
        json!("unknown");
    plugin_generator_without_version["wordpress_review"]["advisories"][0]["applicability"] =
        json!("indeterminate_missing_evidence");
    reject(&plugin_generator_without_version);

    let mut activation_without_context = document.clone();
    activation_without_context["wordpress_review"]["components"][0]["identity_sources"] =
        json!(["generator_metadata"]);
    activation_without_context["wordpress_review"]["components"][0]["confidence_classes"] =
        json!(["public_declaration"]);
    activation_without_context["wordpress_review"]["components"][0]["versions"] = json!([{
        "value":"2.4.0-beta1",
        "source":"generator_metadata",
        "confidence":"public_declaration"
    }]);
    activation_without_context["wordpress_review"]["advisories"][0]["version_resolution_reason"] =
        json!("single_supported_version");
    reject(&activation_without_context);

    let mut context_only_signal_claim = document.clone();
    context_only_signal_claim["wordpress_review"]["components"][0]["evidence_class"] =
        json!("operator_supplied");
    context_only_signal_claim["wordpress_review"]["components"][0]["identity_sources"] =
        json!(["operator_context"]);
    context_only_signal_claim["wordpress_review"]["components"][0]["confidence_classes"] =
        json!(["operator_assertion"]);
    for version in context_only_signal_claim["wordpress_review"]["components"][0]["versions"]
        .as_array_mut()
        .unwrap()
    {
        version["source"] = json!("operator_context");
        version["confidence"] = json!("operator_assertion");
    }
    context_only_signal_claim["wordpress_review"]["advisories"][0]["component_evidence"] =
        json!("operator_supplied");
    reject(&context_only_signal_claim);

    let mut duplicate_range = document.clone();
    let range = duplicate_range["wordpress_review"]["advisories"][0]["affected_ranges"][0].clone();
    duplicate_range["wordpress_review"]["advisories"][0]["affected_ranges"]
        .as_array_mut()
        .unwrap()
        .push(range);
    reject(&duplicate_range);

    let mut duplicate_prerequisite = document.clone();
    duplicate_prerequisite["wordpress_review"]["advisories"][0]["prerequisites"] = json!([
        {
            "kind":"hosting_os",
            "expected":"linux",
            "outcome":"matched_on_supplied_facts"
        },
        {
            "kind":"hosting_os",
            "expected":"linux",
            "outcome":"matched_on_supplied_facts"
        }
    ]);
    reject(&duplicate_prerequisite);

    let mut unsupported = document.clone();
    unsupported["wordpress_review"]["components"][0]["versions"] = json!([{
        "value":"2.4.0-vendor1",
        "source":"generator_metadata",
        "confidence":"public_declaration"
    }]);
    unsupported["wordpress_review"]["components"][0]["evidence_class"] = json!("observed_hint");
    unsupported["wordpress_review"]["components"][0]["identity_sources"] =
        json!(["generator_metadata"]);
    unsupported["wordpress_review"]["components"][0]["confidence_classes"] =
        json!(["public_declaration"]);
    unsupported["wordpress_review"]["components"][0]["activation"] = Value::Null;
    unsupported["wordpress_review"]["advisories"][0]["version_resolution"] = json!("unsupported");
    unsupported["wordpress_review"]["advisories"][0]["version_resolution_reason"] =
        json!("unsupported_version_evidence");
    unsupported["wordpress_review"]["advisories"][0]["version_relation"] = json!("unsupported");
    unsupported["wordpress_review"]["advisories"][0]["applicability"] =
        json!("indeterminate_unsupported");
    assert_eq!(
        group(&compare(&unsupported, &unsupported), "unchanged").len(),
        1
    );

    let mut multiple_unsupported = document.clone();
    multiple_unsupported["wordpress_review"]["components"][0]["versions"] = json!([
        {
            "value":"2.4.0-vendor-a",
            "source":"generator_metadata",
            "confidence":"public_declaration"
        },
        {
            "value":"2.4.0-vendor-b",
            "source":"operator_context",
            "confidence":"operator_assertion"
        }
    ]);
    multiple_unsupported["wordpress_review"]["advisories"][0]["version_resolution"] =
        json!("unsupported");
    multiple_unsupported["wordpress_review"]["advisories"][0]["version_resolution_reason"] =
        json!("unsupported_version_evidence");
    multiple_unsupported["wordpress_review"]["advisories"][0]["version_relation"] =
        json!("unsupported");
    multiple_unsupported["wordpress_review"]["advisories"][0]["applicability"] =
        json!("indeterminate_unsupported");
    assert_eq!(
        group(
            &compare(&multiple_unsupported, &multiple_unsupported),
            "unchanged"
        )
        .len(),
        1
    );

    let mut v1_observed = item(1);
    v1_observed["capability_id"] = json!("technology.wordpress-surface-observed@1");
    let mut v1_with_profile_fields = report(vec![v1_observed]);
    let mut v1_audit = evaluated_wordpress_audit();
    v1_audit["advisories"][0]["comparison_profile"] = json!("numeric-dotted/v1");
    v1_with_profile_fields["wordpress_review"] = v1_audit;
    reject(&v1_with_profile_fields);

    let mut unexpected = document;
    unexpected["wordpress_review"]["advisories"][0]["comparison_rule"] = json!("execute");
    reject(&unexpected);
}

#[test]
fn wordpress_v2_profiles_drive_resolution_and_range_semantics_explicitly() {
    let mut php = evaluated_wordpress_audit_v2();
    php["components"][0]["versions"] = json!([{
        "value":"1.0",
        "source":"generator_metadata",
        "confidence":"public_declaration"
    }]);
    php["components"][0]["evidence_class"] = json!("observed_hint");
    php["components"][0]["identity_sources"] = json!(["generator_metadata"]);
    php["components"][0]["confidence_classes"] = json!(["public_declaration"]);
    php["components"][0]["activation"] = Value::Null;
    php["advisories"][0]["affected_ranges"] = json!([{
        "lower":{"declared":"1.0.0","inclusive":true},
        "upper":{"declared":"1.0.0","inclusive":true}
    }]);
    php["advisories"][0]["fixed_versions"] = json!(["1.0.0"]);
    php["advisories"][0]["version_resolution_reason"] = json!("single_supported_version");
    php["advisories"][0]["version_relation"] = json!("outside_declared_ranges");
    php["advisories"][0]["applicability"] = json!("contradicted_by_declared_facts");

    let mut observed = item(1);
    observed["capability_id"] = json!("technology.wordpress-surface-observed@1");
    let mut php_document = report(vec![observed.clone()]);
    php_document["wordpress_review"] = php.clone();
    assert_eq!(
        group(&compare(&php_document, &php_document), "unchanged").len(),
        1
    );

    let mut numeric = php;
    numeric["advisories"][0]["comparison_profile"] = json!("numeric-dotted/v1");
    numeric["advisories"][0]["version_relation"] = json!("within_declared_range");
    numeric["advisories"][0]["applicability"] = json!("candidate_match_on_declared_facts");
    let mut numeric_document = report(vec![observed]);
    numeric_document["wordpress_review"] = numeric;
    assert_eq!(
        group(&compare(&numeric_document, &numeric_document), "unchanged").len(),
        1
    );

    let mut wrong_php_relation = php_document;
    wrong_php_relation["wordpress_review"]["advisories"][0]["version_relation"] =
        json!("within_declared_range");
    wrong_php_relation["wordpress_review"]["advisories"][0]["applicability"] =
        json!("candidate_match_on_declared_facts");
    reject(&wrong_php_relation);

    let mut aliases = evaluated_wordpress_audit_v2();
    aliases["components"][0]["versions"] = json!([
        {"value":"1.0-alpha1","source":"generator_metadata","confidence":"public_declaration"},
        {"value":"1.0a1","source":"operator_context","confidence":"operator_assertion"}
    ]);
    aliases["advisories"][0]["affected_ranges"] = json!([{
        "lower":{"declared":"1.0-alpha0","inclusive":true},
        "upper":{"declared":"1.0","inclusive":false}
    }]);
    aliases["advisories"][0]["fixed_versions"] = json!(["1.0"]);
    let mut aliases_document = report(vec![item(1)]);
    aliases_document["items"][0]["capability_id"] =
        json!("technology.wordpress-surface-observed@1");
    aliases_document["wordpress_review"] = aliases.clone();
    assert_eq!(
        group(&compare(&aliases_document, &aliases_document), "unchanged").len(),
        1
    );

    aliases["advisories"][0]["fixed_versions"] = json!(["1.0-alpha1", "1.0a1"]);
    aliases_document["wordpress_review"] = aliases;
    reject(&aliases_document);
}

#[test]
fn wordpress_audit_methodology_changes_are_visible_without_changing_item_identity() {
    let mut observed = item(1);
    observed["capability_id"] = json!("technology.wordpress-surface-observed@1");
    let mut before = report(vec![observed.clone()]);
    before["wordpress_review"] = evaluated_wordpress_audit();
    let mut after = report(vec![observed]);
    after["wordpress_review"] = evaluated_wordpress_audit_v2();

    let comparison = compare(&before, &after);
    assert_eq!(group(&comparison, "unchanged").len(), 1);
    assert!(group(&comparison, "changed").is_empty());
    assert_eq!(
        comparison["before"]["optional_audits"]["wordpress_review"]["schema"],
        "security.wordpress-review-audit/v1"
    );
    assert_eq!(
        comparison["after"]["optional_audits"]["wordpress_review"]["advisories"][0]
            ["comparison_profile"],
        "php-release-subset/v1"
    );

    let markdown =
        compare_reports(&bytes(&before), &bytes(&after), ComparisonFormat::Markdown).unwrap();
    assert!(markdown.contains("security.wordpress-review-audit/v1"));
    assert!(markdown.contains("security.wordpress-review-audit/v2"));
    assert!(markdown.contains("php-release-subset/v1"));
    assert!(!markdown.contains("Fixed"));
    assert!(!markdown.contains("Verified remediated"));

    let html = compare_reports(&bytes(&before), &bytes(&after), ComparisonFormat::Html).unwrap();
    assert!(html.contains("security.wordpress-review-audit/v1"));
    assert!(html.contains("security.wordpress-review-audit/v2"));
    assert!(html.contains("php-release-subset/v1"));
}

#[test]
fn audit_optional_values_and_positive_count_consistency_are_strict() {
    for (name, capability, mut audit) in audit_fixtures() {
        let mut observed = item(1);
        observed["capability_id"] = json!(capability);
        audit["item_projected"] = json!(true);
        match name {
            "openapi_review" => {
                audit["outcome"] = json!("document_observed");
                audit["request_count"] = json!(2);
                audit["active_verification_count"] = json!(1);
                audit["version"] = json!("3.1");
                audit["semantic_digest"] =
                    json!(format!("openapi-catalog-sha256:{}", "a".repeat(64)));
                audit["path_count"] = json!(1);
                audit["operation_count"] = json!(1);
                audit["get_operation_count"] = json!(1);
                audit["replay_matched"] = json!(true);
            },
            "rest_review" => {
                audit["outcome"] = json!("surface_observed");
                audit["request_count"] = json!(2);
                audit["active_verification_count"] = json!(1);
                audit["eligible_operation_count"] = json!(1);
                audit["replay_stable"] = json!(true);
                audit["documented_response"] = json!("json_compatible");
                audit["observed_media"] = json!("json_compatible");
                audit["selected_operation_identity"] =
                    json!(format!("openapi-operation-sha256:{}", "b".repeat(64)));
                audit["status_class"] = json!(2);
            },
            "wordpress_review" => {
                audit["signal_count"] = json!(1);
                audit["evidence_reference_count"] = json!(1);
                audit["component_count"] = json!(1);
                audit["components"] = json!([{
                    "identity":{"kind":"core","slug":"wordpress"},
                    "evidence_class":"observed_hint",
                    "identity_sources":["generator_metadata"],
                    "confidence_classes":["public_declaration"],
                    "versions":[{
                        "value":"6.9.4",
                        "source":"generator_metadata",
                        "confidence":"public_declaration"
                    }],
                    "activation":null
                }]);
            },
            _ => {
                audit["outcome"] = json!("stable_cross_principal_equivalence");
                audit["request_count"] = json!(4);
                audit["primary_stable"] = json!(true);
                audit["peer_stable"] = json!(true);
                audit["cross_resources_equivalent"] = json!(true);
                observed["claim_basis"] = json!("differential");
                observed["disposition"] = json!("needs_review");
            },
        }
        let mut document = report(vec![observed.clone()]);
        document[name] = audit.clone();
        assert_eq!(
            group(&compare(&document, &document), "unchanged").len(),
            1,
            "{name}"
        );
        let mut duplicate = observed;
        duplicate["fingerprint"] = json!(format!("sha256:{:064x}", 2));
        let mut two = report(vec![document["items"][0].clone(), duplicate]);
        two[name] = audit.clone();
        reject(&two);
        let mut no_item = report(vec![]);
        no_item[name] = audit;
        reject(&no_item);
        let mutations = match name {
            "openapi_review" => vec![
                ("candidate_source", json!("unknown")),
                ("version", json!("3.1.0")),
                ("semantic_digest", json!("bad")),
                ("active_verification_count", json!(2)),
                ("operation_count", json!(4_294_967_296_u64)),
                ("replay_matched", json!(false)),
            ],
            "rest_review" => vec![
                ("enabled", json!(false)),
                ("method", json!("post")),
                ("request_count", json!(1)),
                ("eligible_operation_count", json!(0)),
                ("selected_operation_identity", Value::Null),
                ("selected_operation_identity", json!("bad")),
                ("documented_response", json!("other")),
                ("observed_media", json!("other")),
                ("status_class", json!(0)),
                ("status_class", json!(6)),
                ("status_class", Value::Null),
                ("replay_stable", json!(false)),
            ],
            _ => vec![
                ("policy_id", json!("bad")),
                ("selected_path_count", json!(0)),
                ("selected_path_count", json!(9)),
                ("ignored_path_count", json!(17)),
                ("request_count", json!(3)),
                ("primary_stable", json!("true")),
                ("peer_stable", json!(1)),
                ("cross_resources_equivalent", json!([])),
            ],
        };
        for (key, value) in mutations {
            let mut invalid = document.clone();
            invalid[name][key] = value;
            reject(&invalid);
        }
        if name == "rest_review" {
            let mut missing = document.clone();
            missing.as_object_mut().unwrap().remove(name);
            reject(&missing);
            document[name]
                .as_object_mut()
                .unwrap()
                .remove("selected_operation_identity");
            reject(&document);
        }
    }
}

#[cfg(feature = "scanning")]
#[test]
fn wire_import_limits_stay_pinned_to_authoritative_rendered_contract_limits() {
    assert_eq!(
        MAX_COMPARISON_INPUT_BYTES,
        super::super::MAX_RENDERED_REPORT_BYTES
    );
    assert_eq!(
        import::MAX_ITEMS,
        crate::web_runtime::MAX_ASSESSMENT_RUN_ITEMS
    );
    assert_eq!(
        import::MAX_REFERENCES,
        crate::web_runtime::MAX_ASSESSMENT_ITEM_EVIDENCE_REFERENCES
    );
    assert_eq!(
        import::MAX_IDENTIFIER_BYTES,
        crate::web_runtime::MAX_ASSESSMENT_CAPABILITY_ID_BYTES
    );
    assert_eq!(
        import::MAX_DISPLAY_BYTES,
        crate::web_runtime::MAX_ASSESSMENT_DISPLAY_BYTES
    );
}
