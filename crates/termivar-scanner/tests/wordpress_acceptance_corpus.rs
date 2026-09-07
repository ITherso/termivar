#![cfg(feature = "wordpress-review")]

use std::{fmt::Write as _, time::Instant};

use termivar_scanner::wordpress_review::{
    evaluate_wordpress_review, parse_wordfence_v3_production, parse_wordpress_advisory_catalog,
    parse_wordpress_context, parse_wordpress_saved_inventory, WordPressActivationState,
    WordPressApplicability, WordPressComponentKind, WordPressComponentSignal,
    WordPressExecutionStatus, WordPressExternalApplicability,
    WordPressExternalVersionEvidenceStatus, WordPressExternalVersionRelation,
    WordPressInventoryCategoryStatus, WordPressInventoryEntryStatus, WordPressLocalInputClass,
    WordPressLocalInputProvenance, WordPressPrerequisiteOutcome, WordPressReviewInputs,
    WordPressVersionRelation, WordPressVersionResolution, WordPressVersionResolutionReason,
    MAX_WORDFENCE_V3_RETAINED_BYTES,
};
use url::Url;

const REVIEWED_CONTEXT: &[u8] =
    include_bytes!("fixtures/wordpress_acceptance/reviewed-context.synthetic.json");
const REVIEWED_CATALOG: &[u8] =
    include_bytes!("fixtures/wordpress_acceptance/reviewed-catalog.synthetic.json");
const HOLDOUT_CONTEXT: &[u8] =
    include_bytes!("fixtures/wordpress_acceptance/holdout-context.synthetic.json");
const HOLDOUT_CATALOG: &[u8] =
    include_bytes!("fixtures/wordpress_acceptance/holdout-catalog.synthetic.json");
const INVENTORY_PLUGINS: &[u8] =
    include_bytes!("fixtures/wordpress_acceptance/inventory-plugins.synthetic.json");
const INVENTORY_THEMES: &[u8] =
    include_bytes!("fixtures/wordpress_acceptance/inventory-themes.synthetic.json");

#[test]
fn reviewed_corpus_matches_independently_written_outcomes_and_denominators() {
    let context = parse_wordpress_context(REVIEWED_CONTEXT).expect("reviewed context");
    let catalog = parse_wordpress_advisory_catalog(REVIEWED_CATALOG).expect("reviewed catalog");
    let result = evaluate_wordpress_review(
        &[],
        &WordPressReviewInputs::new(Some(context), Some(catalog)),
    )
    .expect("reviewed evaluation");

    let literal_expectations = [
        (
            "REVIEWED-CANDIDATE",
            WordPressVersionRelation::WithinDeclaredRange,
            WordPressVersionResolution::SupportedEquivalent,
            WordPressVersionResolutionReason::SingleSupportedVersion,
            WordPressApplicability::CandidateMatchOnDeclaredFacts,
        ),
        (
            "REVIEWED-MISSING-VERSION",
            WordPressVersionRelation::Unknown,
            WordPressVersionResolution::Missing,
            WordPressVersionResolutionReason::NoVersionEvidence,
            WordPressApplicability::IndeterminateMissingEvidence,
        ),
        (
            "REVIEWED-UNKNOWN-PREREQUISITE",
            WordPressVersionRelation::WithinDeclaredRange,
            WordPressVersionResolution::SupportedEquivalent,
            WordPressVersionResolutionReason::SingleSupportedVersion,
            WordPressApplicability::IndeterminateMissingEvidence,
        ),
        (
            "REVIEWED-UNSUPPORTED-VERSION",
            WordPressVersionRelation::Unsupported,
            WordPressVersionResolution::Unsupported,
            WordPressVersionResolutionReason::UnsupportedVersionEvidence,
            WordPressApplicability::IndeterminateUnsupported,
        ),
    ];

    assert_eq!(result.components().len(), 4);
    assert_eq!(result.advisories().len(), literal_expectations.len());
    for (id, relation, resolution, reason, applicability) in literal_expectations {
        let actual = result
            .advisories()
            .iter()
            .find(|evaluation| evaluation.record().id() == id)
            .unwrap_or_else(|| panic!("missing independently expected record {id}"));
        assert_eq!(actual.version_relation(), relation, "record {id}");
        assert_eq!(actual.version_resolution(), Some(resolution), "record {id}");
        assert_eq!(
            actual.version_resolution_reason(),
            Some(reason),
            "record {id}"
        );
        assert_eq!(actual.applicability(), applicability, "record {id}");
        assert_eq!(
            actual.exploit_execution(),
            WordPressExecutionStatus::NotPerformed
        );
        assert_eq!(
            actual.impact_validation(),
            WordPressExecutionStatus::NotPerformed
        );
    }

    let denominators = result
        .advisories()
        .iter()
        .fold([0_usize; 4], |mut counts, row| {
            let index = match row.applicability() {
                WordPressApplicability::CandidateMatchOnDeclaredFacts => 0,
                WordPressApplicability::ContradictedByDeclaredFacts => 1,
                WordPressApplicability::IndeterminateMissingEvidence => 2,
                WordPressApplicability::IndeterminateUnsupported => 3,
            };
            counts[index] += 1;
            counts
        });
    assert_eq!(denominators, [1, 0, 2, 1]);

    let same_slug_kinds = result
        .components()
        .iter()
        .filter(|component| component.identity().slug() == "shared-slug")
        .map(|component| component.identity().kind())
        .collect::<Vec<_>>();
    assert_eq!(
        same_slug_kinds,
        [
            WordPressComponentKind::Plugin,
            WordPressComponentKind::Theme
        ]
    );

    let unknown_prerequisite = result
        .advisories()
        .iter()
        .find(|evaluation| evaluation.record().id() == "REVIEWED-UNKNOWN-PREREQUISITE")
        .expect("unknown-prerequisite record");
    assert_eq!(unknown_prerequisite.prerequisites().len(), 1);
    assert_eq!(
        unknown_prerequisite.prerequisites()[0].outcome(),
        WordPressPrerequisiteOutcome::Unknown
    );
    let candidate = result
        .advisories()
        .iter()
        .find(|evaluation| evaluation.record().id() == "REVIEWED-CANDIDATE")
        .expect("candidate record");
    assert_eq!(candidate.record().affected_range_count(), 2);
    assert_eq!(candidate.record().cve(), None);
}

#[test]
fn holdout_corpus_preserves_conflict_and_contradiction_as_distinct_outcomes() {
    let context = parse_wordpress_context(HOLDOUT_CONTEXT).expect("holdout context");
    let catalog = parse_wordpress_advisory_catalog(HOLDOUT_CATALOG).expect("holdout catalog");
    let generator = WordPressComponentSignal::generator_metadata(Some("6.8.3"))
        .expect("bounded generator signal");
    let result = evaluate_wordpress_review(
        &[generator],
        &WordPressReviewInputs::new(Some(context), Some(catalog)),
    )
    .expect("holdout evaluation");

    let conflict = result
        .advisories()
        .iter()
        .find(|evaluation| evaluation.record().id() == "HOLDOUT-CONFLICTING-CORE")
        .expect("conflicting holdout record");
    assert_eq!(
        conflict.version_relation(),
        WordPressVersionRelation::Unknown
    );
    assert_eq!(
        conflict.version_resolution(),
        Some(WordPressVersionResolution::Conflicting)
    );
    assert_eq!(
        conflict.version_resolution_reason(),
        Some(WordPressVersionResolutionReason::ConflictingVersionEvidence)
    );
    assert_eq!(
        conflict.applicability(),
        WordPressApplicability::IndeterminateMissingEvidence
    );

    let contradicted = result
        .advisories()
        .iter()
        .find(|evaluation| evaluation.record().id() == "HOLDOUT-CONTRADICTED-ACTIVATION")
        .expect("contradicted holdout record");
    assert_eq!(
        contradicted.version_relation(),
        WordPressVersionRelation::WithinDeclaredRange
    );
    assert_eq!(contradicted.prerequisites().len(), 1);
    assert_eq!(
        contradicted.prerequisites()[0].outcome(),
        WordPressPrerequisiteOutcome::ContradictedOnSuppliedFacts
    );
    assert_eq!(
        contradicted.applicability(),
        WordPressApplicability::ContradictedByDeclaredFacts
    );

    let denominators = result
        .advisories()
        .iter()
        .fold([0_usize; 4], |mut counts, row| {
            let index = match row.applicability() {
                WordPressApplicability::CandidateMatchOnDeclaredFacts => 0,
                WordPressApplicability::ContradictedByDeclaredFacts => 1,
                WordPressApplicability::IndeterminateMissingEvidence => 2,
                WordPressApplicability::IndeterminateUnsupported => 3,
            };
            counts[index] += 1;
            counts
        });
    assert_eq!(denominators, [0, 1, 1, 0]);
}

#[test]
fn saved_inventory_corpus_retains_missing_categories_and_nonordinary_statuses() {
    let root = Url::parse("https://example.test/").expect("literal root");
    let plugins_only =
        parse_wordpress_saved_inventory(root.clone(), Some(INVENTORY_PLUGINS), None, None)
            .expect("plugins-only inventory");
    assert_eq!(
        plugins_only.summary().coverage().plugins(),
        WordPressInventoryCategoryStatus::Supplied
    );
    assert_eq!(
        plugins_only.summary().coverage().themes(),
        WordPressInventoryCategoryStatus::NotSupplied
    );
    assert_eq!(
        plugins_only.summary().coverage().core(),
        WordPressInventoryCategoryStatus::NotSupplied
    );
    assert_eq!(plugins_only.summary().component_count(), 3);
    assert_eq!(plugins_only.summary().limitations().len(), 1);
    assert_eq!(
        plugins_only.summary().limitations()[0].status(),
        WordPressInventoryEntryStatus::DropIn
    );

    let inventory = parse_wordpress_saved_inventory(
        root,
        Some(INVENTORY_PLUGINS),
        Some(INVENTORY_THEMES),
        None,
    )
    .expect("combined inventory");
    let provenance = vec![
        WordPressLocalInputProvenance::new(
            WordPressLocalInputClass::PluginsJson,
            INVENTORY_PLUGINS.len(),
            [0x11; 32],
        ),
        WordPressLocalInputProvenance::new(
            WordPressLocalInputClass::ThemesJson,
            INVENTORY_THEMES.len(),
            [0x22; 32],
        ),
    ];
    let result = evaluate_wordpress_review(
        &[],
        &WordPressReviewInputs::from_saved_inventory(inventory, None, provenance)
            .expect("inventory provenance"),
    )
    .expect("inventory evaluation");

    let shared = result
        .components()
        .iter()
        .filter(|component| component.identity().slug() == "shared-slug")
        .collect::<Vec<_>>();
    assert_eq!(shared.len(), 2);
    assert_eq!(shared[0].identity().kind(), WordPressComponentKind::Plugin);
    assert_eq!(
        shared[0].activation(),
        Some(WordPressActivationState::Active)
    );
    assert_eq!(shared[1].identity().kind(), WordPressComponentKind::Theme);
    assert_eq!(
        shared[1].inventory_status(),
        Some(WordPressInventoryEntryStatus::Parent)
    );
    assert_eq!(shared[1].activation(), None);

    let must_use = result
        .components()
        .iter()
        .find(|component| component.identity().slug() == "must-use-plugin")
        .expect("must-use component");
    assert_eq!(
        must_use.inventory_status(),
        Some(WordPressInventoryEntryStatus::MustUse)
    );
    assert!(must_use.versions().is_empty());

    let network_active = result
        .components()
        .iter()
        .find(|component| component.identity().slug() == "network-plugin")
        .expect("network-active component");
    assert_eq!(
        network_active.inventory_status(),
        Some(WordPressInventoryEntryStatus::NetworkActive)
    );
    assert_eq!(
        network_active.activation(),
        Some(WordPressActivationState::NetworkActive)
    );
}

#[test]
fn removing_supported_facts_never_increases_candidate_certainty() {
    let catalog = parse_wordpress_advisory_catalog(REVIEWED_CATALOG).expect("reviewed catalog");
    let cases = [
        (
            "full declaration",
            Some("2.4.0-beta1"),
            Some("active"),
            true,
            WordPressApplicability::CandidateMatchOnDeclaredFacts,
        ),
        (
            "activation removed",
            Some("2.4.0-beta1"),
            None,
            true,
            WordPressApplicability::IndeterminateMissingEvidence,
        ),
        (
            "version removed",
            None,
            Some("active"),
            true,
            WordPressApplicability::IndeterminateMissingEvidence,
        ),
        (
            "component removed",
            None,
            None,
            false,
            WordPressApplicability::IndeterminateMissingEvidence,
        ),
    ];

    for (label, version, activation, include_component, expected) in cases {
        let context = candidate_context(version, activation, include_component);
        let result = evaluate_wordpress_review(
            &[],
            &WordPressReviewInputs::new(
                Some(parse_wordpress_context(&context).expect(label)),
                Some(catalog.clone()),
            ),
        )
        .expect(label);
        let candidate = result
            .advisories()
            .iter()
            .find(|evaluation| evaluation.record().id() == "REVIEWED-CANDIDATE")
            .expect("candidate record");
        assert_eq!(candidate.applicability(), expected, "{label}");
    }
}

#[test]
fn large_external_snapshot_selects_one_relevant_record_without_semantic_order_drift() {
    const RECORDS: usize = 4_096;
    const SELECTED_INDEX: usize = 2_048;

    let forward_bytes = large_wordfence_snapshot(RECORDS, SELECTED_INDEX, false);
    let reverse_bytes = large_wordfence_snapshot(RECORDS, SELECTED_INDEX, true);
    assert_eq!(forward_bytes.len(), 3_092_717);
    assert_eq!(forward_bytes.len(), reverse_bytes.len());
    assert_ne!(forward_bytes, reverse_bytes);

    let parse_started = Instant::now();
    let forward =
        parse_wordfence_v3_production(forward_bytes.as_bytes()).expect("forward external snapshot");
    let forward_parse_elapsed = parse_started.elapsed();
    let reverse_parse_started = Instant::now();
    let reverse =
        parse_wordfence_v3_production(reverse_bytes.as_bytes()).expect("reverse external snapshot");
    let reverse_parse_elapsed = reverse_parse_started.elapsed();

    assert_eq!(forward.record_count(), RECORDS);
    assert_eq!(forward.software_association_count(), RECORDS);
    assert_eq!(forward.affected_range_count(), RECORDS);
    assert_eq!(forward.byte_length(), forward_bytes.len() as u64);
    assert_eq!(
        hex_digest(forward.sha256()),
        "4353196bb306a67085941d738b0be8fc72d8a1bbfa78174db15ea0acd221f0e5"
    );
    assert_eq!(forward.byte_length(), reverse.byte_length());
    assert_ne!(forward.sha256(), reverse.sha256());
    assert_eq!(forward.semantic_sha256(), reverse.semantic_sha256());
    assert_eq!(forward.retained_bytes(), reverse.retained_bytes());
    assert!(forward.retained_bytes() < MAX_WORDFENCE_V3_RETAINED_BYTES);

    let context = parse_wordpress_context(
        br#"{
          "schema":"security.wordpress-context/v1",
          "root":"https://example.test/",
          "components":[
            {"kind":"plugin","slug":"selected-plugin","version":"1.5.0"}
          ]
        }"#,
    )
    .expect("selected component context");
    let evaluation_started = Instant::now();
    let result = evaluate_wordpress_review(
        &[],
        &WordPressReviewInputs::new(Some(context.clone()), None)
            .with_wordfence_v3_catalog(forward)
            .expect("external input"),
    )
    .expect("external evaluation");
    let forward_evaluation_elapsed = evaluation_started.elapsed();
    let reverse_result = evaluate_wordpress_review(
        &[],
        &WordPressReviewInputs::new(Some(context), None)
            .with_wordfence_v3_catalog(reverse)
            .expect("reverse external input"),
    )
    .expect("reverse external evaluation");

    let external = result.external_review().expect("external review");
    let reverse_external = reverse_result
        .external_review()
        .expect("reverse external review");
    let counts = external.counts();
    assert_eq!(counts.parsed_records(), 4_096);
    assert_eq!(counts.software_associations(), 4_096);
    assert_eq!(counts.selected_associations(), 1);
    assert_eq!(counts.evaluable_associations(), 0);
    assert_eq!(counts.unsupported_associations(), 1);
    assert_eq!(counts.excluded_associations(), 4_095);
    assert_eq!(external.evaluations().len(), 1);
    assert_eq!(external.notices().len(), 1);
    assert_eq!(
        external.evaluations()[0].key().upstream_id(),
        selected_uuid(SELECTED_INDEX)
    );
    assert_eq!(
        external.evaluations()[0].key().component().slug(),
        "selected-plugin"
    );
    assert_eq!(
        external.evaluations()[0]
            .version_evidence_resolution()
            .status(),
        WordPressExternalVersionEvidenceStatus::SingleDeclaration
    );
    assert_eq!(
        external.evaluations()[0].version_relation(),
        WordPressExternalVersionRelation::SourceComparisonSemanticsUnresolved
    );
    assert_eq!(
        external.evaluations()[0].applicability(),
        WordPressExternalApplicability::IndeterminateUnsupported
    );
    assert_eq!(external.retained_bytes(), reverse_external.retained_bytes());
    assert_eq!(
        external.semantic_sha256(),
        reverse_external.semantic_sha256()
    );
    assert_eq!(external.counts(), reverse_external.counts());
    assert_eq!(external.notices(), reverse_external.notices());
    assert_eq!(external.evaluations(), reverse_external.evaluations());

    let selected_projection = format!(
        "{}|{}|{}|{}|{}",
        external.evaluations()[0].key().upstream_id(),
        external.evaluations()[0].key().component().slug(),
        external.evaluations()[0].title(),
        external.evaluations()[0].description(),
        external.evaluations()[0].source_remediation(),
    );
    assert_eq!(selected_projection.len(), 197);

    eprintln!(
        "stage-e external import observations (non-contract timing): raw_bytes={} retained_bytes={} selected_projection_bytes={} forward_parse_ms={} reverse_parse_ms={} evaluate_ms={}",
        forward_bytes.len(),
        external.retained_bytes(),
        selected_projection.len(),
        forward_parse_elapsed.as_millis(),
        reverse_parse_elapsed.as_millis(),
        forward_evaluation_elapsed.as_millis(),
    );
}

fn candidate_context(
    version: Option<&str>,
    activation: Option<&str>,
    include_component: bool,
) -> Vec<u8> {
    let components = if include_component {
        vec![serde_json::json!({
            "kind": "plugin",
            "slug": "shared-slug",
            "version": version,
            "activation": activation,
        })]
    } else {
        Vec::new()
    };
    serde_json::to_vec(&serde_json::json!({
        "schema": "security.wordpress-context/v1",
        "root": "https://example.test/",
        "components": components,
    }))
    .expect("literal context serialization")
}

fn selected_uuid(index: usize) -> String {
    format!("00000000-0000-4000-8000-{index:012x}")
}

fn hex_digest(digest: &[u8; 32]) -> String {
    digest
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            write!(hex, "{byte:02x}").expect("write to String");
            hex
        })
}

fn large_wordfence_snapshot(record_count: usize, selected_index: usize, reverse: bool) -> String {
    let mut document = String::with_capacity(record_count * 700);
    document.push('{');
    let indices: Box<dyn Iterator<Item = usize>> = if reverse {
        Box::new((0..record_count).rev())
    } else {
        Box::new(0..record_count)
    };
    for (position, index) in indices.enumerate() {
        if position != 0 {
            document.push(',');
        }
        let id = selected_uuid(index);
        let selected = index == selected_index;
        let slug = if selected {
            "selected-plugin".to_owned()
        } else {
            format!("irrelevant-{index:04}")
        };
        let copyrights = if selected {
            r#"{"message":"Original synthetic Stage E notice.","stage_e_fixture":{"notice":"Synthetic fixture material.","license":"Original synthetic data retained for repository testing.","license_url":"https://example.invalid/stage-e/fixture-license"}}"#
        } else {
            "null"
        };
        write!(
            document,
            r#""{id}":{{"id":"{id}","title":"[SYNTHETIC] External record {index:04}","software":[{{"type":"plugin","name":"[SYNTHETIC] Component {index:04}","slug":"{slug}","affected_versions":{{"[1.0.0, 2.0.0)":{{"from_version":"1.0.0","from_inclusive":true,"to_version":"2.0.0","to_inclusive":false}}}},"patched":false,"patched_versions":[],"remediation":"Synthetic source guidance; verify independently."}}],"informational":false,"description":"Original synthetic record for bounded Stage E selection tests.","references":["https://example.invalid/stage-e/{id}"],"cwe":null,"cvss":null,"cve":null,"cve_link":null,"researchers":[],"published":null,"updated":null,"copyrights":{copyrights}}}"#
        )
        .expect("write to String");
    }
    document.push('}');
    document
}
