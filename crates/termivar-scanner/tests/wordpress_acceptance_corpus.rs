#![cfg(feature = "wordpress-review")]

use std::{
    env,
    fmt::Write as _,
    fs::{File, OpenOptions},
    io::{self, Cursor, Read, Write as IoWrite},
    time::{Duration, Instant},
};

use serde::Serialize;
use termivar_scanner::wordpress_review::{
    evaluate_wordpress_review, parse_wordfence_v3_production, parse_wordpress_advisory_catalog,
    parse_wordpress_context, parse_wordpress_saved_inventory, WordPressActivationState,
    WordPressApplicability, WordPressComparisonProfile, WordPressComponentKind,
    WordPressComponentSignal, WordPressExecutionStatus, WordPressExternalApplicability,
    WordPressExternalRangeReason, WordPressExternalRangeRelation,
    WordPressExternalVersionEvidenceStatus, WordPressExternalVersionRelation,
    WordPressExternalVersionRelationReason, WordPressInventoryCategoryStatus,
    WordPressInventoryEntryStatus, WordPressLocalInputClass, WordPressLocalInputProvenance,
    WordPressPrerequisiteOutcome, WordPressReviewError, WordPressReviewInputs,
    WordPressVersionRelation, WordPressVersionResolution, WordPressVersionResolutionReason,
    WordfenceV3ProductionError, MAX_WORDFENCE_V3_RETAINED_BYTES,
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

#[test]
fn streaming_external_input_retries_interruptions_and_reaches_tail_relevant_record() {
    const RECORDS: usize = 33;
    const SELECTED_INDEX: usize = RECORDS - 1;

    let document = large_wordfence_snapshot(RECORDS, SELECTED_INDEX, false);
    let mut reader = InterruptingChunkReader::new(document.as_bytes(), 17);
    let import =
        parse_wordfence_v3_production(&mut reader).expect("bounded interrupted external input");

    assert_eq!(reader.bytes_returned, document.len());
    assert!(reader.interruptions > 0);
    assert_eq!(import.record_count(), RECORDS);
    assert_eq!(
        import
            .records()
            .last()
            .expect("last parsed record")
            .upstream_id(),
        selected_uuid(SELECTED_INDEX)
    );

    let result = evaluate_wordpress_review(
        &[],
        &WordPressReviewInputs::new(Some(resource_probe_context()), None)
            .with_wordfence_v3_catalog(import)
            .expect("external catalogue")
            .with_external_version_profile(WordPressComparisonProfile::NumericDottedV1)
            .expect("explicit numeric profile"),
    )
    .expect("tail-selected external evaluation");
    let external = result.external_review().expect("external review");
    assert_eq!(external.counts().selected_associations(), 1);
    assert_eq!(external.counts().evaluable_associations(), 1);
    assert_eq!(external.counts().within_associations(), 1);
    assert_eq!(external.counts().outside_associations(), 0);
    assert_eq!(external.counts().indeterminate_associations(), 0);
    assert_eq!(external.evaluations().len(), 1);
    let evaluation = &external.evaluations()[0];
    assert_eq!(
        evaluation.key().upstream_id(),
        selected_uuid(SELECTED_INDEX)
    );
    assert_eq!(
        evaluation.version_relation(),
        WordPressExternalVersionRelation::WithinSupportedRangeUnderSelectedPolicy
    );
    assert_eq!(
        evaluation.version_relation_reason(),
        WordPressExternalVersionRelationReason::ContainingRange
    );
    assert_eq!(
        evaluation.applicability(),
        WordPressExternalApplicability::VersionMatchUnderSelectedPolicy
    );
    assert_eq!(
        evaluation
            .range_evaluations()
            .expect("profiled ranges")
            .iter()
            .map(|range| (range.relation(), range.reason()))
            .collect::<Vec<_>>(),
        [(
            WordPressExternalRangeRelation::Contains,
            WordPressExternalRangeReason::SelectedVersionWithinBounds,
        )]
    );
}

#[test]
fn external_streaming_read_failure_never_returns_a_partial_import() {
    let document = large_wordfence_snapshot(8, 7, false);
    let failure_offset = document.len() - 31;
    let mut reader = FailingChunkReader {
        bytes: document.as_bytes(),
        offset: 0,
        failure_offset,
        maximum_chunk: 23,
    };

    assert_eq!(
        parse_wordfence_v3_production(&mut reader),
        Err(WordfenceV3ProductionError::ReadFailed)
    );
    assert_eq!(reader.offset, failure_offset);
}

#[test]
fn missing_external_version_has_one_deterministic_indeterminate_outcome() {
    let document = large_wordfence_snapshot(2, 1, false);
    let import = parse_wordfence_v3_production(document.as_bytes()).expect("external input");
    let context = parse_wordpress_context(
        br#"{
          "schema":"security.wordpress-context/v1",
          "root":"https://example.test/",
          "components":[{"kind":"plugin","slug":"selected-plugin"}]
        }"#,
    )
    .expect("versionless selected component");
    let inputs = WordPressReviewInputs::new(Some(context), None)
        .with_wordfence_v3_catalog(import)
        .expect("external catalogue")
        .with_external_version_profile(WordPressComparisonProfile::NumericDottedV1)
        .expect("explicit numeric profile");

    let first = evaluate_wordpress_review(&[], &inputs).expect("first evaluation");
    let second = evaluate_wordpress_review(&[], &inputs).expect("second evaluation");
    assert_eq!(first, second);

    let external = first.external_review().expect("external review");
    assert_eq!(external.counts().selected_associations(), 1);
    assert_eq!(external.counts().evaluable_associations(), 0);
    assert_eq!(external.counts().within_associations(), 0);
    assert_eq!(external.counts().outside_associations(), 0);
    assert_eq!(external.counts().indeterminate_associations(), 1);
    let evaluation = &external.evaluations()[0];
    assert_eq!(
        evaluation.version_relation(),
        WordPressExternalVersionRelation::Indeterminate
    );
    assert_eq!(
        evaluation.version_relation_reason(),
        WordPressExternalVersionRelationReason::MissingVersionEvidence
    );
    assert_eq!(
        evaluation.applicability(),
        WordPressExternalApplicability::Indeterminate
    );
    assert_eq!(
        evaluation
            .range_evaluations()
            .expect("profiled ranges")
            .iter()
            .map(|range| (range.relation(), range.reason()))
            .collect::<Vec<_>>(),
        [(
            WordPressExternalRangeRelation::NotEvaluated,
            WordPressExternalRangeReason::MissingVersionEvidence,
        )]
    );
}

/// Native-CI resource probe invoked as a fresh process by the external
/// acceptance harness. Input generation and OS peak-memory observation stay
/// outside this child; the child only performs the real bounded import and
/// pure explicit-policy evaluation.
#[test]
#[ignore = "invoked directly by the WordPress resource acceptance harness"]
fn resource_measurement_case() {
    let case_value =
        env::var("TERMIVAR_WORDPRESS_RESOURCE_CASE").expect("resource probe case is required");
    let (case, expectation) = resource_probe_case(&case_value);
    let result = if expectation == ResourceProbeExpectation::Baseline {
        ResourceProbeResult::baseline(case)
    } else {
        execute_resource_probe(case)
    };

    publish_resource_probe_result(&result);
    assert_resource_probe_expectation(expectation, &result);
}

const RESOURCE_PROBE_SCHEMA: &str = "termivar-wordpress-resource-probe/v1";
const RESOURCE_PROBE_RESULT_LIMIT: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResourceProbeExpectation {
    Baseline,
    Completed,
    RetainedDataTooLarge,
    InputTooLarge,
    RecordTooLarge,
    MalformedJson,
    DuplicateKey,
    UnsupportedValue,
    ResultLimitExceeded,
}

#[derive(Debug, Serialize)]
struct ResourceProbeResult {
    schema: &'static str,
    case: &'static str,
    status: &'static str,
    error_code: Option<&'static str>,
    input_bytes: Option<u64>,
    parse_elapsed_ns: Option<u64>,
    evaluation_elapsed_ns: Option<u64>,
    parsed_records: Option<usize>,
    software_associations: Option<usize>,
    affected_ranges: Option<usize>,
    retained_bytes: Option<usize>,
    selected_associations: Option<usize>,
    evaluable_associations: Option<usize>,
    within_associations: Option<usize>,
    outside_associations: Option<usize>,
    indeterminate_associations: Option<usize>,
    excluded_associations: Option<usize>,
    selected_ranges: Option<usize>,
    evaluated_ranges: Option<usize>,
}

struct ParsedProbeMetadata {
    input_bytes: u64,
    parse_elapsed: Duration,
    parsed_records: usize,
    software_associations: usize,
    affected_ranges: usize,
    retained_bytes: usize,
}

impl ResourceProbeResult {
    const fn baseline(case: &'static str) -> Self {
        Self {
            schema: RESOURCE_PROBE_SCHEMA,
            case,
            status: "baseline",
            error_code: None,
            input_bytes: None,
            parse_elapsed_ns: None,
            evaluation_elapsed_ns: None,
            parsed_records: None,
            software_associations: None,
            affected_ranges: None,
            retained_bytes: None,
            selected_associations: None,
            evaluable_associations: None,
            within_associations: None,
            outside_associations: None,
            indeterminate_associations: None,
            excluded_associations: None,
            selected_ranges: None,
            evaluated_ranges: None,
        }
    }

    fn parse_rejected(
        case: &'static str,
        input_bytes: u64,
        parse_elapsed: Duration,
        error: WordfenceV3ProductionError,
    ) -> Self {
        Self {
            schema: RESOURCE_PROBE_SCHEMA,
            case,
            status: "rejected",
            error_code: Some(wordfence_error_code(error)),
            input_bytes: Some(input_bytes),
            parse_elapsed_ns: Some(duration_ns(parse_elapsed)),
            evaluation_elapsed_ns: None,
            parsed_records: None,
            software_associations: None,
            affected_ranges: None,
            retained_bytes: None,
            selected_associations: None,
            evaluable_associations: None,
            within_associations: None,
            outside_associations: None,
            indeterminate_associations: None,
            excluded_associations: None,
            selected_ranges: None,
            evaluated_ranges: None,
        }
    }

    fn evaluation_rejected(
        case: &'static str,
        parsed: &ParsedProbeMetadata,
        evaluation_elapsed: Duration,
        error: WordPressReviewError,
    ) -> Self {
        Self {
            schema: RESOURCE_PROBE_SCHEMA,
            case,
            status: "rejected",
            error_code: Some(review_error_code(error)),
            input_bytes: Some(parsed.input_bytes),
            parse_elapsed_ns: Some(duration_ns(parsed.parse_elapsed)),
            evaluation_elapsed_ns: Some(duration_ns(evaluation_elapsed)),
            parsed_records: Some(parsed.parsed_records),
            software_associations: Some(parsed.software_associations),
            affected_ranges: Some(parsed.affected_ranges),
            retained_bytes: Some(parsed.retained_bytes),
            selected_associations: None,
            evaluable_associations: None,
            within_associations: None,
            outside_associations: None,
            indeterminate_associations: None,
            excluded_associations: None,
            selected_ranges: None,
            evaluated_ranges: None,
        }
    }
}

fn resource_probe_case(value: &str) -> (&'static str, ResourceProbeExpectation) {
    match value {
        "baseline" => ("baseline", ResourceProbeExpectation::Baseline),
        "sparse-small" => ("sparse-small", ResourceProbeExpectation::Completed),
        "sparse-4096" => ("sparse-4096", ResourceProbeExpectation::Completed),
        "sparse-16384" => ("sparse-16384", ResourceProbeExpectation::Completed),
        "sparse-32768" => ("sparse-32768", ResourceProbeExpectation::Completed),
        "sparse-65536" => (
            "sparse-65536",
            ResourceProbeExpectation::RetainedDataTooLarge,
        ),
        "sparse-81920" => (
            "sparse-81920",
            ResourceProbeExpectation::RetainedDataTooLarge,
        ),
        "dense-4096" => ("dense-4096", ResourceProbeExpectation::Completed),
        "dense-4097" => ("dense-4097", ResourceProbeExpectation::ResultLimitExceeded),
        "record-over-limit" => (
            "record-over-limit",
            ResourceProbeExpectation::RecordTooLarge,
        ),
        "title-field-limit-plus-one" => (
            "title-field-limit-plus-one",
            ResourceProbeExpectation::UnsupportedValue,
        ),
        "input-limit-plus-one" => (
            "input-limit-plus-one",
            ResourceProbeExpectation::InputTooLarge,
        ),
        "late-malformed" => ("late-malformed", ResourceProbeExpectation::MalformedJson),
        "duplicate-id" => ("duplicate-id", ResourceProbeExpectation::DuplicateKey),
        _ => panic!("resource probe case is not in the closed acceptance set"),
    }
}

fn execute_resource_probe(case: &'static str) -> ResourceProbeResult {
    let input_path = env::var_os("TERMIVAR_WORDPRESS_RESOURCE_INPUT")
        .expect("resource probe input is required for this case");
    let input = File::open(&input_path).expect("resource probe input could not be opened");
    let input_metadata = input
        .metadata()
        .expect("resource probe input metadata could not be read");
    assert!(
        input_metadata.is_file(),
        "resource probe input must be a regular file"
    );
    let input_bytes = input_metadata.len();

    let parse_started = Instant::now();
    let import = match parse_wordfence_v3_production(input) {
        Ok(import) => import,
        Err(error) => {
            return ResourceProbeResult::parse_rejected(
                case,
                input_bytes,
                parse_started.elapsed(),
                error,
            );
        },
    };
    let parse_elapsed = parse_started.elapsed();
    assert_eq!(
        import.byte_length(),
        input_bytes,
        "resource probe input changed while it was being read"
    );
    let parsed = ParsedProbeMetadata {
        input_bytes,
        parse_elapsed,
        parsed_records: import.record_count(),
        software_associations: import.software_association_count(),
        affected_ranges: import.affected_range_count(),
        retained_bytes: import.retained_bytes(),
    };
    let inputs = WordPressReviewInputs::new(Some(resource_probe_context()), None)
        .with_wordfence_v3_catalog(import)
        .expect("resource probe external catalogue")
        .with_external_version_profile(WordPressComparisonProfile::NumericDottedV1)
        .expect("resource probe explicit numeric profile");

    let evaluation_started = Instant::now();
    let result = match evaluate_wordpress_review(&[], &inputs) {
        Ok(result) => result,
        Err(error) => {
            return ResourceProbeResult::evaluation_rejected(
                case,
                &parsed,
                evaluation_started.elapsed(),
                error,
            );
        },
    };
    let evaluation_elapsed = evaluation_started.elapsed();
    let external = result
        .external_review()
        .expect("resource probe external review");
    let counts = external.counts();
    assert_eq!(
        external.comparison_profile(),
        Some(WordPressComparisonProfile::NumericDottedV1)
    );
    let relation_counts =
        external
            .evaluations()
            .iter()
            .fold([0_usize; 3], |mut totals, evaluation| {
                let index = match evaluation.version_relation() {
                    WordPressExternalVersionRelation::WithinSupportedRangeUnderSelectedPolicy => 0,
                    WordPressExternalVersionRelation::OutsideDeclaredRangesUnderSelectedPolicy => 1,
                    WordPressExternalVersionRelation::Indeterminate => 2,
                    WordPressExternalVersionRelation::SourceComparisonSemanticsUnresolved => {
                        panic!("explicit resource probe returned the unresolved source policy")
                    },
                };
                totals[index] += 1;
                totals
            });
    assert_eq!(
        relation_counts,
        [
            counts.within_associations(),
            counts.outside_associations(),
            counts.indeterminate_associations(),
        ]
    );
    assert_eq!(
        counts.evaluable_associations(),
        counts.within_associations() + counts.outside_associations()
    );
    assert_eq!(
        counts.selected_associations(),
        counts.evaluable_associations() + counts.indeterminate_associations()
    );
    ResourceProbeResult {
        schema: RESOURCE_PROBE_SCHEMA,
        case,
        status: "completed",
        error_code: None,
        input_bytes: Some(parsed.input_bytes),
        parse_elapsed_ns: Some(duration_ns(parsed.parse_elapsed)),
        evaluation_elapsed_ns: Some(duration_ns(evaluation_elapsed)),
        parsed_records: Some(parsed.parsed_records),
        software_associations: Some(parsed.software_associations),
        affected_ranges: Some(parsed.affected_ranges),
        retained_bytes: Some(parsed.retained_bytes),
        selected_associations: Some(counts.selected_associations()),
        evaluable_associations: Some(counts.evaluable_associations()),
        within_associations: Some(counts.within_associations()),
        outside_associations: Some(counts.outside_associations()),
        indeterminate_associations: Some(counts.indeterminate_associations()),
        excluded_associations: Some(counts.excluded_associations()),
        selected_ranges: Some(counts.selected_ranges()),
        evaluated_ranges: Some(counts.evaluated_ranges()),
    }
}

fn resource_probe_context() -> termivar_scanner::wordpress_review::WordPressContext {
    parse_wordpress_context(
        br#"{
          "schema":"security.wordpress-context/v1",
          "root":"https://example.test/",
          "components":[
            {"kind":"plugin","slug":"selected-plugin","version":"1.5"}
          ]
        }"#,
    )
    .expect("fixed resource probe context")
}

fn publish_resource_probe_result(result: &ResourceProbeResult) {
    let encoded = serde_json::to_vec(result).expect("resource probe result serialization");
    assert!(
        encoded
            .len()
            .checked_add(1)
            .is_some_and(|length| length <= RESOURCE_PROBE_RESULT_LIMIT),
        "resource probe result exceeds its byte limit"
    );
    let output_path = env::var_os("TERMIVAR_WORDPRESS_RESOURCE_OUTPUT")
        .expect("resource probe output is required");
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
        .expect("resource probe output could not be created");
    output
        .write_all(&encoded)
        .expect("resource probe output could not be written");
    output
        .write_all(b"\n")
        .expect("resource probe output newline could not be written");
    output
        .sync_all()
        .expect("resource probe output could not be synchronized");

    println!(
        "TERMIVAR_WORDPRESS_RESOURCE_RESULT={}",
        std::str::from_utf8(&encoded).expect("JSON output is UTF-8")
    );
}

fn assert_resource_probe_expectation(
    expectation: ResourceProbeExpectation,
    result: &ResourceProbeResult,
) {
    match expectation {
        ResourceProbeExpectation::Baseline => {
            assert_eq!(result.status, "baseline");
            assert_eq!(result.error_code, None);
        },
        ResourceProbeExpectation::Completed => {
            assert_eq!(result.status, "completed");
            assert_eq!(result.error_code, None);
        },
        ResourceProbeExpectation::RetainedDataTooLarge => {
            assert_eq!(result.status, "rejected");
            assert_eq!(result.error_code, Some("retained_data_too_large"));
            assert!(result.evaluation_elapsed_ns.is_none());
        },
        ResourceProbeExpectation::InputTooLarge => {
            assert_eq!(result.status, "rejected");
            assert_eq!(result.error_code, Some("input_too_large"));
            assert!(result.evaluation_elapsed_ns.is_none());
        },
        ResourceProbeExpectation::RecordTooLarge => {
            assert_eq!(result.status, "rejected");
            assert_eq!(result.error_code, Some("record_too_large"));
            assert!(result.evaluation_elapsed_ns.is_none());
        },
        ResourceProbeExpectation::MalformedJson => {
            assert_eq!(result.status, "rejected");
            assert_eq!(result.error_code, Some("malformed_json"));
            assert!(result.evaluation_elapsed_ns.is_none());
        },
        ResourceProbeExpectation::DuplicateKey => {
            assert_eq!(result.status, "rejected");
            assert_eq!(result.error_code, Some("duplicate_key"));
            assert!(result.evaluation_elapsed_ns.is_none());
        },
        ResourceProbeExpectation::UnsupportedValue => {
            assert_eq!(result.status, "rejected");
            assert_eq!(result.error_code, Some("unsupported_value"));
            assert!(result.evaluation_elapsed_ns.is_none());
        },
        ResourceProbeExpectation::ResultLimitExceeded => {
            assert_eq!(result.status, "rejected");
            assert_eq!(result.error_code, Some("result_limit_exceeded"));
            assert!(result.evaluation_elapsed_ns.is_some());
        },
    }
}

const fn wordfence_error_code(error: WordfenceV3ProductionError) -> &'static str {
    match error {
        WordfenceV3ProductionError::ReadFailed => "read_failed",
        WordfenceV3ProductionError::EmptyInput => "empty_input",
        WordfenceV3ProductionError::InputTooLarge => "input_too_large",
        WordfenceV3ProductionError::RecordTooLarge => "record_too_large",
        WordfenceV3ProductionError::MalformedJson => "malformed_json",
        WordfenceV3ProductionError::DuplicateKey => "duplicate_key",
        WordfenceV3ProductionError::StructuralLimitExceeded => "structural_limit_exceeded",
        WordfenceV3ProductionError::UnsupportedValue => "unsupported_value",
        WordfenceV3ProductionError::ConflictingIdentity => "conflicting_identity",
        WordfenceV3ProductionError::RetainedDataTooLarge => "retained_data_too_large",
    }
}

const fn review_error_code(error: WordPressReviewError) -> &'static str {
    match error {
        WordPressReviewError::ContextTooLarge => "context_too_large",
        WordPressReviewError::CatalogTooLarge => "catalog_too_large",
        WordPressReviewError::InventoryTooLarge => "inventory_too_large",
        WordPressReviewError::EmptyInput => "empty_input",
        WordPressReviewError::DuplicateKey => "duplicate_key",
        WordPressReviewError::JsonLimitExceeded => "json_limit_exceeded",
        WordPressReviewError::MalformedJson => "malformed_json",
        WordPressReviewError::UnsupportedSchema => "unsupported_schema",
        WordPressReviewError::InvalidContext => "invalid_context",
        WordPressReviewError::InvalidInventory => "invalid_inventory",
        WordPressReviewError::InventoryComponentLimitExceeded => {
            "inventory_component_limit_exceeded"
        },
        WordPressReviewError::InvalidInventoryProvenance => "invalid_inventory_provenance",
        WordPressReviewError::InvalidCatalog => "invalid_catalog",
        WordPressReviewError::ConflictingAdvisoryInputs => "conflicting_advisory_inputs",
        WordPressReviewError::ExternalVersionProfileRequiresWordfenceV3 => {
            "external_version_profile_requires_wordfence_v3"
        },
        WordPressReviewError::InvalidExternalCatalog => "invalid_external_catalog",
        WordPressReviewError::InvalidComponentIdentity => "invalid_component_identity",
        WordPressReviewError::DuplicateComponent => "duplicate_component",
        WordPressReviewError::DuplicateAdvisory => "duplicate_advisory",
        WordPressReviewError::InvalidVersionRange => "invalid_version_range",
        WordPressReviewError::SignalLimitExceeded => "signal_limit_exceeded",
        WordPressReviewError::ResultLimitExceeded => "result_limit_exceeded",
        WordPressReviewError::EvaluationLimitExceeded => "evaluation_limit_exceeded",
    }
}

fn duration_ns(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).expect("resource probe duration fits u64 nanoseconds")
}

struct InterruptingChunkReader<'a> {
    cursor: Cursor<&'a [u8]>,
    maximum_chunk: usize,
    interrupt_next: bool,
    interruptions: usize,
    bytes_returned: usize,
}

impl<'a> InterruptingChunkReader<'a> {
    fn new(bytes: &'a [u8], maximum_chunk: usize) -> Self {
        Self {
            cursor: Cursor::new(bytes),
            maximum_chunk,
            interrupt_next: true,
            interruptions: 0,
            bytes_returned: 0,
        }
    }
}

impl Read for InterruptingChunkReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.interrupt_next {
            self.interrupt_next = false;
            self.interruptions += 1;
            return Err(io::ErrorKind::Interrupted.into());
        }
        self.interrupt_next = true;
        let maximum = buffer.len().min(self.maximum_chunk);
        let read = self.cursor.read(&mut buffer[..maximum])?;
        self.bytes_returned += read;
        Ok(read)
    }
}

struct FailingChunkReader<'a> {
    bytes: &'a [u8],
    offset: usize,
    failure_offset: usize,
    maximum_chunk: usize,
}

impl Read for FailingChunkReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.offset == self.failure_offset {
            return Err(io::Error::other("synthetic bounded read failure"));
        }
        let available = self.failure_offset - self.offset;
        let count = buffer.len().min(self.maximum_chunk).min(available);
        buffer[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
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
