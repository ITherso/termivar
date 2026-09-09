#![cfg(feature = "wordpress-review")]

use serde_json::{json, Map, Value};
use termivar_scanner::wordpress_review::{
    evaluate_wordpress_review, parse_wordfence_v3_production, parse_wordpress_context,
    WordPressComparisonProfile, WordPressExternalAdvisoryEvaluation,
    WordPressExternalApplicability, WordPressExternalRangeReason, WordPressExternalRangeRelation,
    WordPressExternalVersionRelation, WordPressExternalVersionRelationReason,
    WordPressReviewInputs, WordfenceV3IdentityMapping, WordfenceV3ProductionError,
};

#[test]
fn source_identities_are_partitioned_without_turning_candidates_into_conclusions() {
    let document = identity_partition_document();
    let import = parse_wordfence_v3_production(document.as_slice()).expect("identity corpus");

    assert_eq!(import.record_count(), 6);
    assert_eq!(import.software_association_count(), 6);
    assert_eq!(import.affected_range_count(), 6);
    assert_eq!(
        import.mapping_revision(),
        "termivar-wordfence-v3-production/v2"
    );
    assert_eq!(
        import.resource_policy(),
        "termivar.wordfence-v3-bounded-capacity/v1"
    );
    assert_eq!(import.identity_counts().exact(), 1);
    assert_eq!(import.identity_counts().candidate(), 2);
    assert_eq!(import.identity_counts().ambiguous(), 2);
    assert_eq!(import.identity_counts().unresolved(), 1);

    let unresolved = import
        .records()
        .iter()
        .flat_map(|record| record.unresolved_software())
        .collect::<Vec<_>>();
    assert_eq!(unresolved.len(), 1);
    assert_eq!(
        unresolved[0].source_component().slug(),
        "https://example.invalid/plugins/opaque_name"
    );

    let context = parse_wordpress_context(
        br#"{
          "schema":"security.wordpress-context/v1",
          "root":"https://example.test/",
          "components":[
            {"kind":"plugin","slug":"stable-plugin","version":"9.9"},
            {"kind":"plugin","slug":"candidate-inside","version":"1.5"},
            {"kind":"plugin","slug":"candidate-outside","version":"9.9"},
            {"kind":"plugin","slug":"collision-plugin","version":"1.5"}
          ]
        }"#,
    )
    .expect("fixed operator context");
    let result = evaluate_wordpress_review(
        &[],
        &WordPressReviewInputs::new(Some(context), None)
            .with_wordfence_v3_catalog(import)
            .expect("external catalogue")
            .with_external_version_profile(WordPressComparisonProfile::NumericDottedV1)
            .expect("explicit local interpretation"),
    )
    .expect("identity-limited review");
    let external = result.external_review().expect("external review");
    let counts = external.counts();

    assert!(external.requires_audit_v6());
    assert_eq!(
        external.identity_mapping_policy(),
        "termivar.wordfence-v3-exact-plus-ascii-lowercase-candidate/v1"
    );
    assert_eq!(external.identity_source_assurance(), "not_established");
    assert_eq!(counts.software_associations(), 6);
    assert_eq!(counts.exact_identity_associations(), 1);
    assert_eq!(counts.candidate_identity_associations(), 2);
    assert_eq!(counts.ambiguous_identity_associations(), 2);
    assert_eq!(counts.unresolved_identity_associations(), 1);
    assert_eq!(counts.selected_associations(), 5);
    assert_eq!(counts.excluded_associations(), 1);
    assert_eq!(counts.mapped_unselected_associations(), 0);
    assert_eq!(counts.evaluable_associations(), 1);
    assert_eq!(counts.within_associations(), 0);
    assert_eq!(counts.outside_associations(), 1);
    assert_eq!(counts.indeterminate_associations(), 4);
    assert_eq!(counts.unsupported_associations(), 4);
    assert_eq!(counts.selected_ranges(), 5);
    assert_eq!(counts.evaluated_ranges(), 1);
    assert_eq!(counts.noncontaining_ranges(), 1);
    assert_eq!(counts.not_evaluated_ranges(), 4);

    let limitations = external.identity_limitations();
    assert_eq!(limitations.len(), 1);
    assert_eq!(
        limitations[0].upstream_id(),
        "00000000-0000-4000-8000-000000000206"
    );
    assert_eq!(
        limitations[0].source_component().slug(),
        "https://example.invalid/plugins/opaque_name"
    );
    assert_eq!(limitations[0].affected_ranges().len(), 1);
    assert_eq!(limitations[0].source_patched_versions().len(), 0);

    let exact = external
        .evaluations()
        .iter()
        .find(|row| row.key().source_component().slug() == "stable-plugin")
        .expect("exact row");
    assert_eq!(exact.identity_mapping(), WordfenceV3IdentityMapping::Exact);
    assert_eq!(
        exact.version_relation(),
        WordPressExternalVersionRelation::OutsideDeclaredRangesUnderSelectedPolicy
    );
    assert_eq!(
        exact.applicability(),
        WordPressExternalApplicability::NoVersionMatchUnderSelectedPolicy
    );

    for candidate_slug in ["Candidate-Inside", "Candidate-Outside"] {
        let candidate = external
            .evaluations()
            .iter()
            .find(|row| row.key().source_component().slug() == candidate_slug)
            .unwrap_or_else(|| panic!("missing candidate row {candidate_slug}"));
        assert_identity_limited(
            candidate,
            WordfenceV3IdentityMapping::AsciiCaseFoldCandidate,
            None,
            WordPressExternalVersionRelationReason::IdentityMappingCandidate,
            WordPressExternalRangeReason::IdentityMappingCandidate,
        );
    }

    for ambiguous_slug in ["Collision-Plugin", "COLLISION-PLUGIN"] {
        let ambiguous = external
            .evaluations()
            .iter()
            .find(|row| row.key().source_component().slug() == ambiguous_slug)
            .unwrap_or_else(|| panic!("missing ambiguous row {ambiguous_slug}"));
        assert_identity_limited(
            ambiguous,
            WordfenceV3IdentityMapping::AsciiCaseFoldAmbiguous,
            Some(2),
            WordPressExternalVersionRelationReason::IdentityMappingAmbiguous,
            WordPressExternalRangeReason::IdentityMappingAmbiguous,
        );
    }
}

#[test]
fn absent_profile_preserves_the_unresolved_source_policy_for_every_selected_identity() {
    let import = parse_wordfence_v3_production(identity_partition_document().as_slice())
        .expect("identity corpus");
    let context = parse_wordpress_context(
        br#"{
          "schema":"security.wordpress-context/v1",
          "root":"https://example.test/",
          "components":[
            {"kind":"plugin","slug":"stable-plugin","version":"1.5"},
            {"kind":"plugin","slug":"candidate-inside","version":"1.5"},
            {"kind":"plugin","slug":"candidate-outside","version":"9.9"},
            {"kind":"plugin","slug":"collision-plugin","version":"1.5"}
          ]
        }"#,
    )
    .expect("fixed operator context");
    let result = evaluate_wordpress_review(
        &[],
        &WordPressReviewInputs::new(Some(context), None)
            .with_wordfence_v3_catalog(import)
            .expect("external catalogue"),
    )
    .expect("unselected-policy review");
    let external = result.external_review().expect("external review");

    assert_eq!(external.counts().selected_associations(), 5);
    assert_eq!(external.counts().evaluable_associations(), 0);
    assert_eq!(external.counts().unsupported_associations(), 5);
    assert_eq!(external.counts().within_associations(), 0);
    assert_eq!(external.counts().outside_associations(), 0);
    assert_eq!(external.counts().indeterminate_associations(), 0);
    assert_eq!(external.identity_limitations().len(), 1);
    assert!(external.evaluations().iter().all(|row| {
        row.range_evaluations().is_none()
            && row.version_relation()
                == WordPressExternalVersionRelation::SourceComparisonSemanticsUnresolved
            && row.version_relation_reason()
                == WordPressExternalVersionRelationReason::SourceComparisonSemanticsUnresolved
            && row.applicability() == WordPressExternalApplicability::IndeterminateUnsupported
    }));
}

#[test]
fn observed_production_shape_fits_the_expanded_finite_limits_and_limit_plus_one_fails() {
    let observed_shape = capacity_document(102, 102, 2_530);
    let import =
        parse_wordfence_v3_production(observed_shape.as_slice()).expect("observed-shape corpus");
    let association = &import.records()[0].software()[0];

    assert_eq!(import.record_count(), 1);
    assert_eq!(import.software_association_count(), 1);
    assert_eq!(import.affected_range_count(), 102);
    assert_eq!(association.affected_ranges().len(), 102);
    assert_eq!(association.patched_versions().len(), 102);
    assert_eq!(import.identity_counts().exact(), 1);
    assert_eq!(
        import.resource_policy(),
        "termivar.wordfence-v3-bounded-capacity/v2"
    );

    let excessive_ranges = capacity_document(129, 1, 64);
    assert_eq!(
        parse_wordfence_v3_production(excessive_ranges.as_slice()),
        Err(WordfenceV3ProductionError::StructuralLimitExceeded)
    );
    let excessive_patches = capacity_document(1, 129, 64);
    assert_eq!(
        parse_wordfence_v3_production(excessive_patches.as_slice()),
        Err(WordfenceV3ProductionError::StructuralLimitExceeded)
    );
}

fn assert_identity_limited(
    actual: &WordPressExternalAdvisoryEvaluation,
    expected_mapping: WordfenceV3IdentityMapping,
    expected_collision_count: Option<usize>,
    expected_reason: WordPressExternalVersionRelationReason,
    expected_range_reason: WordPressExternalRangeReason,
) {
    assert_eq!(actual.identity_mapping(), expected_mapping);
    assert_eq!(
        actual.identity_collision_raw_count(),
        expected_collision_count
    );
    assert_eq!(
        actual.version_relation(),
        WordPressExternalVersionRelation::Indeterminate
    );
    assert_eq!(actual.version_relation_reason(), expected_reason);
    assert_eq!(
        actual.applicability(),
        WordPressExternalApplicability::Indeterminate
    );
    let actual_ranges = actual
        .range_evaluations()
        .expect("identity-limited range coverage");
    assert_eq!(actual_ranges.len(), 1);
    assert!(actual_ranges.iter().all(|range| {
        range.relation() == WordPressExternalRangeRelation::NotEvaluated
            && range.reason() == expected_range_reason
    }));
}

fn identity_partition_document() -> Vec<u8> {
    let cases = [
        (
            "00000000-0000-4000-8000-000000000201",
            "stable-plugin",
            "1.0",
            "2.0",
        ),
        (
            "00000000-0000-4000-8000-000000000202",
            "Candidate-Inside",
            "1.0",
            "2.0",
        ),
        (
            "00000000-0000-4000-8000-000000000203",
            "Candidate-Outside",
            "1.0",
            "2.0",
        ),
        (
            "00000000-0000-4000-8000-000000000204",
            "Collision-Plugin",
            "1.0",
            "2.0",
        ),
        (
            "00000000-0000-4000-8000-000000000205",
            "COLLISION-PLUGIN",
            "3.0",
            "4.0",
        ),
        (
            "00000000-0000-4000-8000-000000000206",
            "https://example.invalid/plugins/opaque_name",
            "1.0",
            "2.0",
        ),
    ];
    let mut root = Map::new();
    for (id, slug, lower, upper) in cases {
        root.insert(
            id.to_owned(),
            source_record(id, slug, lower, upper, "Synthetic identity acceptance row."),
        );
    }
    serde_json::to_vec(&Value::Object(root)).expect("literal identity corpus")
}

fn capacity_document(
    range_count: usize,
    patched_count: usize,
    description_bytes: usize,
) -> Vec<u8> {
    let id = "00000000-0000-4000-8000-000000000299";
    let mut ranges = Map::new();
    for index in 0..range_count {
        ranges.insert(
            format!("range-{index:03}"),
            json!({
                "from_version": format!("1.{index}.0"),
                "from_inclusive": true,
                "to_version": format!("1.{index}.1"),
                "to_inclusive": false
            }),
        );
    }
    let patches = (0..patched_count)
        .map(|index| format!("9.{index}.0"))
        .collect::<Vec<_>>();
    let mut record = source_record(
        id,
        "capacity-plugin",
        "1.0",
        "2.0",
        &"d".repeat(description_bytes),
    );
    let software = record["software"]
        .as_array_mut()
        .expect("literal software array");
    software[0]["affected_versions"] = Value::Object(ranges);
    software[0]["patched"] = Value::Bool(true);
    software[0]["patched_versions"] = json!(patches);
    let mut root = Map::new();
    root.insert(id.to_owned(), record);
    serde_json::to_vec(&Value::Object(root)).expect("literal capacity corpus")
}

fn source_record(id: &str, slug: &str, lower: &str, upper: &str, description: &str) -> Value {
    json!({
        "id": id,
        "title": "[SYNTHETIC] Identity and capacity acceptance",
        "software": [{
            "type": "plugin",
            "name": "[SYNTHETIC] Acceptance component",
            "slug": slug,
            "affected_versions": {
                "declared interval": {
                    "from_version": lower,
                    "from_inclusive": true,
                    "to_version": upper,
                    "to_inclusive": true
                }
            },
            "patched": false,
            "patched_versions": [],
            "remediation": "Synthetic source guidance; verify independently."
        }],
        "informational": false,
        "description": description,
        "references": ["https://example.invalid/termivar/identity-capacity-acceptance"],
        "cwe": null,
        "cvss": null,
        "cve": null,
        "cve_link": null,
        "researchers": [],
        "published": null,
        "updated": null,
        "copyrights": null
    })
}
