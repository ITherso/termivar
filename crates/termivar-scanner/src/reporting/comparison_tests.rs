use super::*;
use serde_json::json;

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
