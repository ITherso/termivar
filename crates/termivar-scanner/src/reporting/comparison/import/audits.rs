//! Exact optional audit wire inventories; these snapshots are not evidence authority.

use super::super::{
    ImportedWordPressAudit, WordPressAdvisoryKey, WordPressComponentKey,
    WORDPRESS_DISCOVERY_OBSERVATION_CAPABILITY,
};
use super::{
    array, boolean, check, digest, keys, number, object, optional_boolean, optional_text,
    optional_token, required, string, text, token, ComparisonError, ImportedItem, Value,
    MAX_IDENTIFIER_BYTES, MAX_LEGACY_AUDIT_TEXT_BYTES,
};
use crate::wordpress_version::{
    checked_accumulate_external_interpretation_work, ProfiledVersionKey, WordPressComparisonProfile,
};
use serde_json::Map;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

pub(super) const REST_CAPABILITY: &str = "api.rest-readonly-surface-observed@1";
pub(super) const WORDPRESS_CAPABILITY: &str = "technology.wordpress-surface-observed@1";
const OPENAPI_CAPABILITY: &str = "api.openapi-contract-observed@1";
const AUTHORIZATION_CAPABILITY: &str = "authorization.resource-cross-principal-equivalence@1";
const MAX_WORDPRESS_SIGNALS: u64 = 256;
const WORDPRESS_DISCOVERY_AUDIT_SCHEMA_V1: &str = "security.wordpress-discovery-audit/v1";
const WORDPRESS_DISCOVERY_AUDIT_SCHEMA_V2: &str = "security.wordpress-discovery-audit/v2";
const WORDPRESS_DISCOVERY_AUDIT_SCHEMA_V3: &str = "security.wordpress-discovery-audit/v3";
const WORDPRESS_DISCOVERY_CAPABILITY: &str = "technology.wordpress-metadata-discovery@1";
const WORDPRESS_DISCOVERY_POLICY_V1: &str = "termivar.wordpress-metadata-discovery/v1";
const WORDPRESS_DISCOVERY_POLICY_V2: &str =
    "termivar.wordpress-deployment-aware-metadata-discovery/v1";
const WORDPRESS_DISCOVERY_POLICY_V3: &str = "termivar.wordpress-page-scoped-metadata-discovery/v1";
const WORDPRESS_LAYOUT_SCHEMA: &str = "security.wordpress-layout/v1";
const MAX_WORDPRESS_LAYOUT_BYTES: u64 = 16 * 1024;
const WORDPRESS_DISCOVERY_REFERENCE_BYTES: usize = "sha256:".len() + 64;
const MAX_WORDPRESS_DISCOVERY_SOURCES: usize = 32;
const MAX_WORDPRESS_DISCOVERY_REQUESTS: u64 = 12;
const MAX_WORDPRESS_PAGE_DISCOVERY_REQUESTS: u64 = 3;
const MAX_WORDPRESS_PAGE_DISCOVERY_CANDIDATES: u64 = 4_096;
const MAX_WORDPRESS_PAGE_DISCOVERY_INTERPRETED_BYTES: u64 = 768 * 1024;
const MAX_WORDPRESS_DISCOVERY_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_WORDPRESS_DISCOVERY_REST_REQUESTS: u64 = 1;
const MAX_WORDPRESS_DISCOVERY_THEME_REQUESTS: u64 = 3;
const MAX_WORDPRESS_DISCOVERY_PLUGIN_REQUESTS: u64 = 8;
const MAX_WORDPRESS_DISCOVERY_OMITTED_CANDIDATES: u64 = 4_064;
const MAX_WORDPRESS_DISCOVERY_NAMESPACES: usize = 64;
const MAX_WORDPRESS_DISCOVERY_METADATA_BYTES: usize = 256;
const MAX_WORDPRESS_DISCOVERY_VERSION_BYTES: usize = 64;
const MAX_WORDPRESS_DISCOVERY_NAMESPACE_BYTES: usize = 128;
// These stable wire bounds mirror the feature-owned evaluator constants. The
// importer is intentionally available without `wordpress-review`, so it cannot
// depend on that feature-gated module directly.
const MAX_WORDPRESS_CONTEXT_COMPONENTS: usize = 256;
const MAX_WORDPRESS_RESULT_COMPONENTS: usize =
    MAX_WORDPRESS_SIGNALS as usize + MAX_WORDPRESS_CONTEXT_COMPONENTS;
const MAX_WORDPRESS_RESULT_VERSION_EVIDENCE: usize =
    MAX_WORDPRESS_SIGNALS as usize + MAX_WORDPRESS_CONTEXT_COMPONENTS;
const MAX_WORDPRESS_ADVISORIES: usize = 4_096;
const MAX_WORDPRESS_RANGES: usize = 16;
const MAX_WORDPRESS_FIXED_VERSIONS: usize = 16;
const MAX_WORDPRESS_PREREQUISITES: usize = 8;
const MAX_WORDPRESS_VERSION_RESOLUTION_WORK: usize = MAX_WORDPRESS_RESULT_VERSION_EVIDENCE * 2;
const MAX_WORDPRESS_EVALUATION_WORK: usize =
    MAX_WORDPRESS_ADVISORIES * (MAX_WORDPRESS_RANGES + MAX_WORDPRESS_PREREQUISITES);
const MAX_WORDPRESS_SAVED_INVENTORY_BYTES: u64 = 1024 * 1024;
const MAX_WORDPRESS_INVENTORY_INPUTS: usize = 3;
const MAX_WORDPRESS_INVENTORY_VERSION_BYTES: usize = 64;
const MAX_WORDPRESS_INVENTORY_LABEL_BYTES: usize = 64;
const MAX_WORDPRESS_COMPONENT_SLUG_BYTES: usize = 64;
const MAX_WORDFENCE_V3_INPUT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_WORDFENCE_V3_RECORDS: u64 = 100_000;
const MAX_WORDFENCE_V3_ASSOCIATIONS: u64 = 200_000;
const MAX_WORDFENCE_V3_SOFTWARE_PER_RECORD: u64 = 2_048;
const MAX_WORDFENCE_V3_EVALUATIONS: usize = MAX_WORDPRESS_ADVISORIES;
const MAX_WORDFENCE_V3_IDENTITY_LIMITATION_PROJECTIONS: u64 = 64;
const MAX_WORDFENCE_V3_RANGES_V1: usize = 64;
const MAX_WORDFENCE_V3_RANGES_V2: usize = 128;
const MAX_WORDFENCE_V3_PATCHED_VERSIONS_V1: usize = 64;
const MAX_WORDFENCE_V3_PATCHED_VERSIONS_V2: usize = 128;
const MAX_WORDFENCE_V3_REFERENCES: usize = 64;
const MAX_WORDFENCE_V3_RESEARCHERS: usize = 64;
const MAX_WORDFENCE_V3_NOTICES: usize = MAX_WORDPRESS_ADVISORIES;
// Mirrors the feature-owned Production parser's per-record rights-party cap.
const MAX_WORDFENCE_V3_NOTICE_PARTIES: usize = 15;
const MAX_WORDFENCE_V3_TITLE_BYTES: usize = 1_024;
const MAX_WORDFENCE_V3_NAME_BYTES: usize = 1_024;
const MAX_WORDFENCE_V3_RESEARCHER_BYTES: usize = 512;
const MAX_WORDFENCE_V3_CVE_BYTES: usize = 32;
const MAX_WORDFENCE_V3_SOURCE_SLUG_BYTES: usize = 128;
const MAX_WORDFENCE_V3_RETAINED_BYTES_V1: u64 = 64 * 1024 * 1024;
const MAX_WORDFENCE_V3_RETAINED_BYTES_V2: u64 = 128 * 1024 * 1024;
const MAX_WORDFENCE_V3_RETAINED_BYTES_V3: u64 = 160 * 1024 * 1024;
const MAX_WORDFENCE_V3_DESCRIPTION_BYTES_V1: usize = 2_048;
const MAX_WORDFENCE_V3_DESCRIPTION_BYTES_V2: usize = 4_096;
const WORDFENCE_V3_MAPPING_REVISION_V1: &str = "termivar-wordfence-v3-production/v1";
const WORDFENCE_V3_MAPPING_REVISION_V2: &str = "termivar-wordfence-v3-production/v2";
const WORDFENCE_V3_IDENTITY_MAPPING_POLICY: &str =
    "termivar.wordfence-v3-exact-plus-ascii-lowercase-candidate/v1";
const WORDFENCE_V3_RESOURCE_POLICY_V1: &str = "termivar.wordfence-v3-bounded-capacity/v1";
const WORDFENCE_V3_RESOURCE_POLICY_V2: &str = "termivar.wordfence-v3-bounded-capacity/v2";
const WORDFENCE_V3_RESOURCE_POLICY_V3: &str = "termivar.wordfence-v3-bounded-capacity/v3";

#[derive(Clone, Copy, Eq, PartialEq)]
enum WordPressAuditSchema {
    V1,
    V2,
    V3,
    V4,
    V5,
    V6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExternalIdentityMapping {
    Exact,
    AsciiCaseFoldCandidate,
    AsciiCaseFoldAmbiguous,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExternalResourcePolicy {
    V1,
    V2,
    V3,
}

impl ExternalResourcePolicy {
    const fn ranges(self) -> usize {
        match self {
            Self::V1 => MAX_WORDFENCE_V3_RANGES_V1,
            Self::V2 | Self::V3 => MAX_WORDFENCE_V3_RANGES_V2,
        }
    }

    const fn patched_versions(self) -> usize {
        match self {
            Self::V1 => MAX_WORDFENCE_V3_PATCHED_VERSIONS_V1,
            Self::V2 | Self::V3 => MAX_WORDFENCE_V3_PATCHED_VERSIONS_V2,
        }
    }

    const fn retained_bytes(self) -> u64 {
        match self {
            Self::V1 => MAX_WORDFENCE_V3_RETAINED_BYTES_V1,
            Self::V2 => MAX_WORDFENCE_V3_RETAINED_BYTES_V2,
            Self::V3 => MAX_WORDFENCE_V3_RETAINED_BYTES_V3,
        }
    }

    const fn description_bytes(self) -> usize {
        match self {
            Self::V1 => MAX_WORDFENCE_V3_DESCRIPTION_BYTES_V1,
            Self::V2 | Self::V3 => MAX_WORDFENCE_V3_DESCRIPTION_BYTES_V2,
        }
    }

    const fn expanded(self) -> bool {
        !matches!(self, Self::V1)
    }
}

fn v6_identity_contract_is_valid(
    mapping_revision: &str,
    resource_policy: ExternalResourcePolicy,
    identity_counts: [u64; 4],
    associations: u64,
) -> bool {
    let partition_matches = identity_counts
        .into_iter()
        .try_fold(0_u64, |total, count| total.checked_add(count))
        == Some(associations);
    let mapping_matches = match mapping_revision {
        WORDFENCE_V3_MAPPING_REVISION_V1 => identity_counts == [associations, 0, 0, 0],
        WORDFENCE_V3_MAPPING_REVISION_V2 => identity_counts[1..].iter().any(|count| *count > 0),
        _ => false,
    };
    let v6_is_required =
        mapping_revision == WORDFENCE_V3_MAPPING_REVISION_V2 || resource_policy.expanded();
    partition_matches && mapping_matches && v6_is_required
}

struct ImportedWordPressComponent {
    versions: Vec<String>,
    evidence_class: String,
    profiled_evidence: &'static str,
    observed_source: bool,
    operator_source: bool,
    inventory_component: bool,
}

struct ProfiledRange {
    lower: Option<(ProfiledVersionKey, bool)>,
    upper: Option<(ProfiledVersionKey, bool)>,
}

type ImportedExternalRangeEndpoint<'a> = (&'a str, &'a str, bool);
type ImportedExternalRange<'a> = (
    ImportedExternalRangeEndpoint<'a>,
    ImportedExternalRangeEndpoint<'a>,
);

#[derive(Clone)]
struct ProfiledResolution {
    status: &'static str,
    reason: &'static str,
    selected: Option<ProfiledVersionKey>,
}

#[derive(Clone, Copy)]
struct ExternalEvaluationContract {
    schema: WordPressAuditSchema,
    resource_policy: ExternalResourcePolicy,
    profile: Option<WordPressComparisonProfile>,
}

#[derive(Default)]
struct ImportedIdentityGroup {
    source_spellings: std::collections::BTreeSet<String>,
    mappings: Vec<(ExternalIdentityMapping, Option<u64>)>,
}

struct ImportedPrerequisite<'a> {
    identity: (String, String, Option<String>),
    outcome: &'a str,
}

pub(super) fn validate(
    name: &str,
    value: &Value,
    items: &BTreeMap<String, ImportedItem>,
) -> Result<Option<ImportedWordPressAudit>, ComparisonError> {
    let fields = object(value)?;
    match name {
        "openapi_review" => {
            openapi(fields, count(items, OPENAPI_CAPABILITY))?;
            Ok(None)
        },
        "rest_review" => {
            rest(fields, count(items, REST_CAPABILITY))?;
            Ok(None)
        },
        "authorization_review" => {
            authorization(fields, count(items, AUTHORIZATION_CAPABILITY))?;
            Ok(None)
        },
        "wordpress_review" => {
            wordpress(fields, count(items, WORDPRESS_CAPABILITY))?;
            Ok(Some(wordpress_comparison_snapshot(fields)?))
        },
        _ => Err(ComparisonError::InvalidDocument),
    }
}

pub(super) fn validate_wordpress_discovery(
    value: &Value,
    items: &BTreeMap<String, ImportedItem>,
) -> Result<(), ComparisonError> {
    let fields = object(value)?;
    let schema = string(fields, "schema")?;
    let (deployment_aware, page_scoped) = match schema {
        WORDPRESS_DISCOVERY_AUDIT_SCHEMA_V1 => (false, false),
        WORDPRESS_DISCOVERY_AUDIT_SCHEMA_V2 => (true, false),
        WORDPRESS_DISCOVERY_AUDIT_SCHEMA_V3 => (true, true),
        _ => return Err(ComparisonError::InvalidDocument),
    };
    let required_fields = [
        "schema",
        "capability_id",
        "policy_id",
        "selected",
        "method",
        "credential_mode",
        "seed_count",
        "candidate_count",
        "candidate_limit_reached",
        "omitted_candidate_count",
        "attempted_request_count",
        "completed_response_count",
        "committed_response_count",
        "response_bytes",
        "source_count",
        "sources",
    ];
    if deployment_aware {
        let mut required = required_fields.to_vec();
        required.push("layout");
        if page_scoped {
            required.push("page_collection");
        }
        keys(fields, &required, &[])?;
    } else {
        keys(fields, &required_fields, &[])?;
    }
    check(string(fields, "capability_id")? == WORDPRESS_DISCOVERY_CAPABILITY)?;
    check(
        string(fields, "policy_id")?
            == match (deployment_aware, page_scoped) {
                (false, false) => WORDPRESS_DISCOVERY_POLICY_V1,
                (true, false) => WORDPRESS_DISCOVERY_POLICY_V2,
                (true, true) => WORDPRESS_DISCOVERY_POLICY_V3,
                _ => return Err(ComparisonError::InvalidDocument),
            },
    )?;
    check(boolean(fields, "selected")?)?;
    check(string(fields, "method")? == "get")?;
    check(string(fields, "credential_mode")? == "anonymous")?;
    let seed_count = number(fields, "seed_count", MAX_WORDPRESS_DISCOVERY_SOURCES as u64)?;
    let candidate_count = number(
        fields,
        "candidate_count",
        MAX_WORDPRESS_DISCOVERY_SOURCES as u64,
    )?;
    let attempted = number(
        fields,
        "attempted_request_count",
        MAX_WORDPRESS_DISCOVERY_REQUESTS,
    )?;
    let completed = number(
        fields,
        "completed_response_count",
        MAX_WORDPRESS_DISCOVERY_REQUESTS,
    )?;
    let committed = number(
        fields,
        "committed_response_count",
        MAX_WORDPRESS_DISCOVERY_REQUESTS,
    )?;
    let page_collection = fields
        .get("page_collection")
        .map(validate_wordpress_page_collection)
        .transpose()?;
    check(page_scoped == page_collection.is_some())?;
    let page_committed = page_collection
        .as_ref()
        .map_or(0, |pages| pages.committed_response_count);
    let total_committed = committed
        .checked_add(page_committed)
        .ok_or(ComparisonError::InvalidDocument)?;
    let discovery_items = items
        .values()
        .filter(|item| item.capability_id == WORDPRESS_DISCOVERY_OBSERVATION_CAPABILITY)
        .collect::<Vec<_>>();
    check(
        (discovery_items.len() == 1) == (total_committed > 0)
            && discovery_items.first().is_none_or(|item| {
                let projection = &item.projection;
                projection.title == "WordPress metadata-source response outcome observed"
                    && projection.category == "wordpress-metadata-source-response"
                    && projection.disposition == "informational"
                    && projection.claim_basis == "observation"
                    && projection.severity.is_none()
                    && projection.cwe.is_none()
                    && projection.confidence_ppm == 550_000
                    && projection.redacted_summary
                        == "Bounded response evidence from selected public WordPress metadata sources was collected; usable metadata, installation authenticity, vulnerable-code reachability, and advisory impact were not established."
                    && projection.remediation.id == "wordpress-metadata-review"
                    && projection.remediation.summary
                        == "Confirm the installation inventory and source-qualified metadata before making a security or remediation decision."
                    && projection.evidence.evidence_count == total_committed
                    && projection.evidence.evidence_reference_count == total_committed as usize
                    && projection.evidence.control_reference_count == 0
                    && projection.evidence.candidate_reference_count == 0
                    && !projection.evidence.case_present
                    && !projection.evidence.outcome_present
                    && projection.evidence.verification_stage.is_none()
            }),
    )?;
    let response_bytes = number(fields, "response_bytes", u64::MAX)?;
    let candidate_limit_reached = boolean(fields, "candidate_limit_reached")?;
    let omitted_candidate_count = number(
        fields,
        "omitted_candidate_count",
        MAX_WORDPRESS_DISCOVERY_OMITTED_CANDIDATES,
    )?;
    let sources = array(fields, "sources")?;
    let layout = fields
        .get("layout")
        .map(validate_wordpress_discovery_layout)
        .transpose()?;
    check(deployment_aware == layout.is_some())?;
    check(
        seed_count <= MAX_WORDPRESS_DISCOVERY_SOURCES as u64
            && seed_count <= candidate_count
            && candidate_limit_reached == (omitted_candidate_count > 0)
            && (omitted_candidate_count == 0
                || candidate_count == MAX_WORDPRESS_DISCOVERY_SOURCES as u64)
            && candidate_count == sources.len() as u64
            && attempted <= candidate_count
            && completed <= attempted
            && committed == completed
            && number(
                fields,
                "source_count",
                MAX_WORDPRESS_DISCOVERY_SOURCES as u64,
            )? == sources.len() as u64,
    )?;
    let mut source_bytes = 0_u64;
    let mut evidence_references = 0_u64;
    let mut source_evidence_references = BTreeSet::new();
    let mut attempted_sources = 0_u64;
    let mut attempted_rest_sources = 0_u64;
    let mut attempted_theme_sources = 0_u64;
    let mut attempted_plugin_sources = 0_u64;
    let mut source_identities = std::collections::BTreeSet::new();
    for source in sources {
        let source = object(source)?;
        let kind = string(source, "kind")?;
        let (bytes, references, request_attempted, references_by_source, identity) =
            validate_wordpress_discovery_source(source, layout.as_ref(), page_collection.as_ref())?;
        source_bytes = source_bytes
            .checked_add(bytes)
            .ok_or(ComparisonError::InvalidDocument)?;
        evidence_references = evidence_references
            .checked_add(references)
            .ok_or(ComparisonError::InvalidDocument)?;
        attempted_sources = attempted_sources
            .checked_add(u64::from(request_attempted))
            .ok_or(ComparisonError::InvalidDocument)?;
        if request_attempted {
            match kind {
                "rest_index" => attempted_rest_sources += 1,
                "theme_stylesheet" => attempted_theme_sources += 1,
                "plugin_readme" => attempted_plugin_sources += 1,
                _ => return Err(ComparisonError::InvalidDocument),
            }
        }
        for reference in references_by_source {
            check(source_evidence_references.insert(reference))?;
        }
        check(source_identities.insert(identity))?;
    }
    check(
        source_bytes == response_bytes
            && evidence_references == committed
            && attempted_sources == attempted
            && attempted
                .checked_add(
                    page_collection
                        .as_ref()
                        .map_or(0, |pages| pages.attempted_request_count),
                )
                .is_some_and(|total| total <= MAX_WORDPRESS_DISCOVERY_REQUESTS)
            && page_collection.as_ref().is_none_or(|pages| {
                response_bytes
                    .checked_add(pages.response_bytes)
                    .is_some_and(|total| total <= MAX_WORDPRESS_DISCOVERY_RESPONSE_BYTES)
            })
            && wordpress_discovery_request_class_counts_valid(
                attempted_rest_sources,
                attempted_theme_sources,
                attempted_plugin_sources,
            ),
    )?;
    if let Some(page_collection) = &page_collection {
        for reference in &page_collection.evidence_references {
            check(source_evidence_references.insert(reference.clone()))?;
        }
    }
    check(
        discovery_items
            .first()
            .map_or(source_evidence_references.is_empty(), |item| {
                item.observation_evidence_references == source_evidence_references
            }),
    )
}

fn wordpress_discovery_request_class_counts_valid(rest: u64, themes: u64, plugins: u64) -> bool {
    rest <= MAX_WORDPRESS_DISCOVERY_REST_REQUESTS
        && themes <= MAX_WORDPRESS_DISCOVERY_THEME_REQUESTS
        && plugins <= MAX_WORDPRESS_DISCOVERY_PLUGIN_REQUESTS
}

struct ValidatedWordPressPageCollection {
    entry_page_reference: String,
    accepted_page_references: BTreeSet<String>,
    evidence_references: BTreeSet<String>,
    attempted_request_count: u64,
    committed_response_count: u64,
    response_bytes: u64,
}

fn validate_wordpress_page_collection(
    value: &Value,
) -> Result<ValidatedWordPressPageCollection, ComparisonError> {
    let fields = object(value)?;
    keys(
        fields,
        &[
            "mode",
            "entry_page_reference",
            "candidate_count",
            "selected_count",
            "omitted_candidate_count",
            "reused_response_count",
            "fetched_response_count",
            "not_observed_count",
            "rejected_response_count",
            "accepted_association_count",
            "rejected_association_count",
            "attempted_request_count",
            "completed_response_count",
            "committed_response_count",
            "interpreted_response_bytes",
            "response_bytes",
            "pages",
        ],
        &[],
    )?;
    let mode = token(fields, "mode", &["observed", "linked"])?;
    let entry_page_reference = text(
        fields,
        "entry_page_reference",
        WORDPRESS_DISCOVERY_REFERENCE_BYTES,
    )?;
    check(digest(entry_page_reference, "sha256:"))?;
    let candidate_count = number(
        fields,
        "candidate_count",
        MAX_WORDPRESS_PAGE_DISCOVERY_CANDIDATES,
    )?;
    let selected_count = number(
        fields,
        "selected_count",
        MAX_WORDPRESS_PAGE_DISCOVERY_REQUESTS,
    )?;
    let omitted_candidate_count = number(
        fields,
        "omitted_candidate_count",
        MAX_WORDPRESS_PAGE_DISCOVERY_CANDIDATES,
    )?;
    let reused_response_count = number(
        fields,
        "reused_response_count",
        MAX_WORDPRESS_PAGE_DISCOVERY_REQUESTS,
    )?;
    let fetched_response_count = number(
        fields,
        "fetched_response_count",
        MAX_WORDPRESS_PAGE_DISCOVERY_REQUESTS,
    )?;
    let not_observed_count = number(
        fields,
        "not_observed_count",
        MAX_WORDPRESS_PAGE_DISCOVERY_REQUESTS,
    )?;
    let rejected_response_count = number(
        fields,
        "rejected_response_count",
        MAX_WORDPRESS_PAGE_DISCOVERY_REQUESTS,
    )?;
    let accepted_association_count = number(
        fields,
        "accepted_association_count",
        MAX_WORDPRESS_PAGE_DISCOVERY_REQUESTS,
    )?;
    let rejected_association_count = number(
        fields,
        "rejected_association_count",
        MAX_WORDPRESS_PAGE_DISCOVERY_REQUESTS,
    )?;
    let attempted_request_count = number(
        fields,
        "attempted_request_count",
        MAX_WORDPRESS_PAGE_DISCOVERY_REQUESTS,
    )?;
    let completed_response_count = number(
        fields,
        "completed_response_count",
        MAX_WORDPRESS_PAGE_DISCOVERY_REQUESTS,
    )?;
    let committed_response_count = number(
        fields,
        "committed_response_count",
        MAX_WORDPRESS_PAGE_DISCOVERY_REQUESTS,
    )?;
    let interpreted_response_bytes = number(
        fields,
        "interpreted_response_bytes",
        MAX_WORDPRESS_PAGE_DISCOVERY_INTERPRETED_BYTES,
    )?;
    let response_bytes = number(fields, "response_bytes", u64::MAX)?;
    let pages = array(fields, "pages")?;
    check(
        selected_count == pages.len() as u64
            && candidate_count
                == selected_count
                    .checked_add(omitted_candidate_count)
                    .ok_or(ComparisonError::InvalidDocument)?
            && omitted_candidate_count <= MAX_WORDPRESS_PAGE_DISCOVERY_CANDIDATES
            && completed_response_count <= selected_count
            && committed_response_count == completed_response_count
            && (mode != "observed"
                || (attempted_request_count == 0
                    && fetched_response_count == 0
                    && response_bytes == 0)),
    )?;
    let mut attempted = 0_u64;
    let mut completed = 0_u64;
    let mut reused = 0_u64;
    let mut fetched = 0_u64;
    let mut not_observed = 0_u64;
    let mut accepted = 0_u64;
    let mut rejected = 0_u64;
    let mut interpreted_bytes = 0_u64;
    let mut transferred_bytes = 0_u64;
    let mut page_references = BTreeSet::new();
    let mut accepted_page_references = BTreeSet::new();
    let mut evidence_references = BTreeSet::new();
    for page in pages {
        let page = object(page)?;
        let validated = validate_wordpress_page_source(page)?;
        check(page_references.insert(validated.page_reference.clone()))?;
        if validated.association == "accepted" {
            check(accepted_page_references.insert(validated.page_reference.clone()))?;
            accepted += 1;
        } else if validated.association == "rejected" {
            rejected += 1;
        }
        attempted += u64::from(validated.request_attempted);
        completed += validated.evidence_references.len() as u64;
        reused += u64::from(
            validated.acquisition == "reused" && !validated.evidence_references.is_empty(),
        );
        fetched += u64::from(
            validated.acquisition == "fetched" && !validated.evidence_references.is_empty(),
        );
        not_observed += u64::from(validated.acquisition == "not_observed");
        interpreted_bytes = interpreted_bytes
            .checked_add(validated.interpreted_response_bytes)
            .ok_or(ComparisonError::InvalidDocument)?;
        transferred_bytes = transferred_bytes
            .checked_add(validated.response_bytes)
            .ok_or(ComparisonError::InvalidDocument)?;
        for reference in validated.evidence_references {
            check(evidence_references.insert(reference))?;
        }
    }
    check(
        attempted == attempted_request_count
            && completed == completed_response_count
            && reused == reused_response_count
            && fetched == fetched_response_count
            && not_observed == not_observed_count
            && accepted == accepted_association_count
            && rejected == rejected_response_count
            && rejected == rejected_association_count
            && interpreted_bytes == interpreted_response_bytes
            && transferred_bytes == response_bytes,
    )?;
    Ok(ValidatedWordPressPageCollection {
        entry_page_reference: entry_page_reference.to_owned(),
        accepted_page_references,
        evidence_references,
        attempted_request_count,
        committed_response_count,
        response_bytes,
    })
}

struct ValidatedWordPressPageSource {
    page_reference: String,
    acquisition: String,
    association: String,
    request_attempted: bool,
    interpreted_response_bytes: u64,
    response_bytes: u64,
    evidence_references: Vec<String>,
}

fn validate_wordpress_page_source(
    fields: &Map<String, Value>,
) -> Result<ValidatedWordPressPageSource, ComparisonError> {
    keys(
        fields,
        &[
            "page_reference",
            "acquisition",
            "association",
            "outcome",
            "request_attempted",
            "interpreted_response_bytes",
            "response_bytes",
            "evidence_reference_count",
            "evidence_references",
        ],
        &[],
    )?;
    let page_reference = text(
        fields,
        "page_reference",
        WORDPRESS_DISCOVERY_REFERENCE_BYTES,
    )?;
    check(digest(page_reference, "sha256:"))?;
    let acquisition = token(
        fields,
        "acquisition",
        &["reused", "fetched", "not_observed"],
    )?;
    let association = token(
        fields,
        "association",
        &["accepted", "rejected", "not_established"],
    )?;
    let outcome = token(
        fields,
        "outcome",
        &[
            "accepted",
            "no_component_signals",
            "not_observed",
            "incompatible_application",
            "soft_404",
            "login_response",
            "unsupported_content",
            "malformed",
            "truncated",
            "request_failed",
            "rate_limited",
            "budget_exhausted",
            "cancelled",
            "deadline_exceeded",
        ],
    )?;
    let request_attempted = boolean(fields, "request_attempted")?;
    let interpreted_response_bytes = number(fields, "interpreted_response_bytes", 256 * 1024)?;
    let response_bytes = number(fields, "response_bytes", u64::MAX)?;
    let evidence_reference_count = number(fields, "evidence_reference_count", 1)?;
    let evidence_values = array(fields, "evidence_references")?;
    check(evidence_values.len() as u64 == evidence_reference_count)?;
    let mut evidence_references = BTreeSet::new();
    for reference_value in evidence_values {
        let reference_value = reference_value
            .as_str()
            .ok_or(ComparisonError::InvalidDocument)?;
        super::reference(reference_value, "evidence")?;
        check(evidence_references.insert(reference_value.to_owned()))?;
    }
    check(
        (evidence_reference_count == 1 || interpreted_response_bytes == 0)
            && (request_attempted || response_bytes == 0)
            && match acquisition {
                "reused" => {
                    !request_attempted && response_bytes == 0 && evidence_reference_count == 1
                },
                "fetched" => request_attempted && evidence_reference_count == 1,
                "not_observed" => {
                    !request_attempted
                        && response_bytes == 0
                        && interpreted_response_bytes == 0
                        && evidence_reference_count == 0
                        && outcome == "not_observed"
                },
                _ => false,
            }
            && match association {
                "accepted" => outcome == "accepted" && evidence_reference_count == 1,
                "rejected" => {
                    !matches!(
                        outcome,
                        "accepted" | "no_component_signals" | "not_observed"
                    ) && evidence_reference_count == 1
                },
                "not_established" => {
                    matches!(outcome, "no_component_signals" | "not_observed")
                        && (outcome == "not_observed") != (evidence_reference_count == 1)
                },
                _ => false,
            },
    )?;
    Ok(ValidatedWordPressPageSource {
        page_reference: page_reference.to_owned(),
        acquisition: acquisition.to_owned(),
        association: association.to_owned(),
        request_attempted,
        interpreted_response_bytes,
        response_bytes,
        evidence_references: evidence_references.into_iter().collect(),
    })
}

struct ValidatedDiscoveryLayout {
    application_reference: String,
    exact_role_references: BTreeMap<String, String>,
    exact_role_bases: BTreeMap<String, String>,
    declaration: Option<Value>,
    roles: Vec<Value>,
    skipped_foreign_origin_count: u64,
    skipped_sibling_application_count: u64,
    conflicting_association_count: u64,
}

fn validate_wordpress_discovery_layout(
    value: &Value,
) -> Result<ValidatedDiscoveryLayout, ComparisonError> {
    let fields = object(value)?;
    keys(
        fields,
        &[
            "application_reference",
            "roles",
            "skipped_foreign_origin_count",
            "skipped_sibling_application_count",
            "conflicting_association_count",
        ],
        &["declaration"],
    )?;
    let application_reference = string(fields, "application_reference")?;
    check(digest(application_reference, "sha256:"))?;
    let layout_count_limit = u64::from(u16::MAX);
    let skipped_foreign_origin_count =
        number(fields, "skipped_foreign_origin_count", layout_count_limit)?;
    let skipped_sibling_application_count = number(
        fields,
        "skipped_sibling_application_count",
        layout_count_limit,
    )?;
    let conflicting_association_count =
        number(fields, "conflicting_association_count", layout_count_limit)?;
    let declaration = fields.get("declaration").cloned();
    if let Some(declaration) = declaration.as_ref() {
        let declaration = object(declaration)?;
        keys(declaration, &["schema", "byte_length", "sha256"], &[])?;
        check(string(declaration, "schema")? == WORDPRESS_LAYOUT_SCHEMA)?;
        let bytes = number(declaration, "byte_length", MAX_WORDPRESS_LAYOUT_BYTES)?;
        check(bytes > 0 && digest(string(declaration, "sha256")?, ""))?;
    }
    let roles = array(fields, "roles")?;
    let expected_roles = ["core", "themes", "plugins", "rest_index"];
    check(roles.len() == expected_roles.len())?;
    let mut exact_role_references = BTreeMap::new();
    let mut exact_role_bases = BTreeMap::new();
    let mut projected_roles = Vec::with_capacity(expected_roles.len());
    for (value, expected_role) in roles.iter().zip(expected_roles) {
        let role = object(value)?;
        keys(
            role,
            &["role", "status", "basis", "candidate_count"],
            &["reference"],
        )?;
        check(string(role, "role")? == expected_role)?;
        let status = token(role, "status", &["exact", "ambiguous", "unresolved"])?;
        let basis = token(
            role,
            "basis",
            &[
                "conventional_asset",
                "structured_advertisement",
                "operator_declaration",
                "none",
            ],
        )?;
        let candidate_count = number(role, "candidate_count", layout_count_limit)?;
        let reference = role
            .get("reference")
            .map(|_| text(role, "reference", WORDPRESS_DISCOVERY_REFERENCE_BYTES))
            .transpose()?;
        check(match expected_role {
            "rest_index" => matches!(
                basis,
                "structured_advertisement" | "operator_declaration" | "none"
            ),
            "core" | "themes" | "plugins" => {
                matches!(
                    basis,
                    "conventional_asset" | "operator_declaration" | "none"
                )
            },
            _ => false,
        })?;
        match status {
            "exact" => {
                let reference = reference.ok_or(ComparisonError::InvalidDocument)?;
                check(
                    candidate_count > 0
                        && basis != "none"
                        && digest(reference, "sha256:")
                        && exact_role_references
                            .insert(expected_role.to_owned(), reference.to_owned())
                            .is_none()
                        && exact_role_bases
                            .insert(expected_role.to_owned(), basis.to_owned())
                            .is_none(),
                )?;
            },
            "ambiguous" => check(reference.is_none() && candidate_count >= 2 && basis != "none")?,
            "unresolved" => check(reference.is_none() && candidate_count == 0 && basis == "none")?,
            _ => return Err(ComparisonError::InvalidDocument),
        }
        projected_roles.push(value.clone());
    }
    check(
        declaration.is_some()
            == projected_roles.iter().any(|role| {
                role.as_object()
                    .and_then(|fields| fields.get("basis"))
                    .and_then(Value::as_str)
                    == Some("operator_declaration")
            }),
    )?;
    Ok(ValidatedDiscoveryLayout {
        application_reference: application_reference.to_owned(),
        exact_role_references,
        exact_role_bases,
        declaration,
        roles: projected_roles,
        skipped_foreign_origin_count,
        skipped_sibling_application_count,
        conflicting_association_count,
    })
}

pub(super) fn attach_wordpress_discovery(
    wordpress: &mut ImportedWordPressAudit,
    discovery: &Value,
) -> Result<(), ComparisonError> {
    let fields = object(discovery)?;
    let layout = fields
        .get("layout")
        .map(validate_wordpress_discovery_layout)
        .transpose()?;
    let page_collection = fields
        .get("page_collection")
        .map(validate_wordpress_page_collection)
        .transpose()?;
    validate_wordpress_discovery_review_links(wordpress, fields, layout.as_ref())?;
    let attempted_request_count = number(
        fields,
        "attempted_request_count",
        MAX_WORDPRESS_DISCOVERY_REQUESTS,
    )?;
    let total_attempted_request_count = attempted_request_count
        .checked_add(
            page_collection
                .as_ref()
                .map_or(0, |pages| pages.attempted_request_count),
        )
        .ok_or(ComparisonError::InvalidDocument)?;
    check(
        number(
            object(&wordpress.coverage)?,
            "additional_request_count",
            MAX_WORDPRESS_DISCOVERY_REQUESTS,
        )? == total_attempted_request_count,
    )?;
    let mut methodology = selected_object(
        fields,
        &[
            "schema",
            "capability_id",
            "policy_id",
            "selected",
            "method",
            "credential_mode",
        ],
        &[],
    )?;
    let mut coverage = selected_object(
        fields,
        &[
            "seed_count",
            "candidate_count",
            "candidate_limit_reached",
            "omitted_candidate_count",
            "attempted_request_count",
            "completed_response_count",
            "committed_response_count",
            "response_bytes",
            "source_count",
        ],
        &[],
    )?;
    if let Some(layout) = &layout {
        let methodology_roles = layout
            .roles
            .iter()
            .map(|role| selected_object(object(role)?, &["role", "basis"], &[]))
            .collect::<Result<Vec<_>, ComparisonError>>()?;
        object_mut(&mut methodology)?.insert(
            "layout_roles".to_owned(),
            canonical_value(&Value::Array(methodology_roles))?,
        );

        let coverage_roles = layout
            .roles
            .iter()
            .map(|role| selected_object(object(role)?, &["role", "status", "candidate_count"], &[]))
            .collect::<Result<Vec<_>, ComparisonError>>()?;
        let coverage_fields = object_mut(&mut coverage)?;
        coverage_fields.insert(
            "layout_roles".to_owned(),
            canonical_value(&Value::Array(coverage_roles))?,
        );
        coverage_fields.insert(
            "skipped_foreign_origin_count".to_owned(),
            Value::from(layout.skipped_foreign_origin_count),
        );
        coverage_fields.insert(
            "skipped_sibling_application_count".to_owned(),
            Value::from(layout.skipped_sibling_application_count),
        );
        coverage_fields.insert(
            "conflicting_association_count".to_owned(),
            Value::from(layout.conflicting_association_count),
        );
    }
    if let Some(page_collection) = fields.get("page_collection") {
        let page_fields = object(page_collection)?;
        object_mut(&mut methodology)?.insert(
            "page_scope".to_owned(),
            selected_object(page_fields, &["mode"], &[])?,
        );
        object_mut(&mut coverage)?.insert(
            "page_scope".to_owned(),
            selected_object(
                page_fields,
                &[
                    "candidate_count",
                    "selected_count",
                    "omitted_candidate_count",
                    "reused_response_count",
                    "fetched_response_count",
                    "not_observed_count",
                    "rejected_response_count",
                    "accepted_association_count",
                    "rejected_association_count",
                    "attempted_request_count",
                    "completed_response_count",
                    "committed_response_count",
                    "interpreted_response_bytes",
                    "response_bytes",
                ],
                &[],
            )?,
        );
    }
    let mut source_outcomes = Vec::new();
    let mut component_metadata = BTreeMap::<WordPressComponentKey, Vec<Value>>::new();
    let mut rest_source_content = Vec::new();
    for source in array(fields, "sources")? {
        let source = object(source)?;
        source_outcomes.push(selected_object(
            source,
            &[
                "kind",
                "parent_depth",
                "outcome",
                "request_attempted",
                "response_bytes",
                "evidence_reference_count",
            ],
            &[
                ("component", source.get("component")),
                ("association", source.get("association")),
                ("resource_reference", source.get("resource_reference")),
                ("role_reference", source.get("role_reference")),
                (
                    "source_page_references",
                    source.get("source_page_references"),
                ),
            ],
        )?);
        if string(source, "kind")? == "rest_index" {
            let mut content = selected_object(
                source,
                &["kind"],
                &[
                    ("namespaces", source.get("namespaces")),
                    ("association", source.get("association")),
                    ("resource_reference", source.get("resource_reference")),
                    ("role_reference", source.get("role_reference")),
                    (
                        "source_page_references",
                        source.get("source_page_references"),
                    ),
                ],
            )?;
            if let Some(Value::Array(namespaces)) = content.get_mut("namespaces") {
                namespaces.sort_by_key(Value::to_string);
            }
            rest_source_content.push(content);
        } else if let Some(component) = source.get("component") {
            let key = comparison_component_key(object(component)?)?;
            let metadata = selected_object(
                source,
                &["kind", "parent_depth"],
                &[
                    ("association", source.get("association")),
                    ("resource_reference", source.get("resource_reference")),
                    ("role_reference", source.get("role_reference")),
                    (
                        "source_page_references",
                        source.get("source_page_references"),
                    ),
                    ("theme", source.get("theme")),
                    ("plugin", source.get("plugin")),
                ],
            )?;
            if object(&metadata)?.len() > 2 {
                if !wordpress.components.contains_key(&key)
                    && (string(source, "kind")? != "theme_stylesheet"
                        || number(source, "parent_depth", 1)? != 1)
                {
                    return Err(ComparisonError::InvalidDocument);
                }
                component_metadata.entry(key).or_default().push(metadata);
            }
        }
    }
    source_outcomes.sort_by_key(Value::to_string);
    object_mut(&mut coverage)?.insert("source_outcomes".to_owned(), Value::Array(source_outcomes));
    for (key, mut metadata) in component_metadata {
        metadata.sort_by_key(Value::to_string);
        wordpress
            .components
            .entry(key)
            .or_default()
            .insert("discovery_metadata".to_owned(), Value::Array(metadata));
    }
    rest_source_content.sort_by_key(Value::to_string);
    let mut discovery_source_content =
        Map::from_iter([("rest_indexes".to_owned(), Value::Array(rest_source_content))]);
    if let Some(page_collection) = fields.get("page_collection") {
        let page_fields = object(page_collection)?;
        let mut pages = array(page_fields, "pages")?
            .iter()
            .map(|page| {
                selected_object(
                    object(page)?,
                    &[
                        "page_reference",
                        "acquisition",
                        "association",
                        "outcome",
                        "request_attempted",
                        "interpreted_response_bytes",
                        "response_bytes",
                    ],
                    &[],
                )
            })
            .collect::<Result<Vec<_>, ComparisonError>>()?;
        pages.sort_by_key(Value::to_string);
        discovery_source_content.insert("pages".to_owned(), Value::Array(pages));
    }
    let discovery_source_content = Value::Object(discovery_source_content);
    if let Some(layout) = layout {
        wordpress.application_reference = Some(layout.application_reference.clone());
        let mut layout_provenance = Map::new();
        layout_provenance.insert(
            "application_reference".to_owned(),
            Value::String(layout.application_reference),
        );
        if let Some(declaration) = layout.declaration {
            layout_provenance.insert("declaration".to_owned(), canonical_value(&declaration)?);
        }
        object_mut(&mut wordpress.provenance)?.insert(
            "wordpress_layout".to_owned(),
            Value::Object(layout_provenance),
        );
    }
    if let Some(page_collection) = page_collection {
        object_mut(&mut wordpress.provenance)?.insert(
            "wordpress_page_scope".to_owned(),
            Value::Object(Map::from_iter([(
                "entry_page_reference".to_owned(),
                Value::String(page_collection.entry_page_reference),
            )])),
        );
    }
    object_mut(&mut wordpress.methodology)?.insert("wordpress_discovery".to_owned(), methodology);
    object_mut(&mut wordpress.coverage)?.insert("wordpress_discovery".to_owned(), coverage);
    wordpress.discovery_source_content = Some(discovery_source_content);
    Ok(())
}

fn validate_wordpress_discovery_review_links(
    wordpress: &ImportedWordPressAudit,
    discovery: &Map<String, Value>,
    layout: Option<&ValidatedDiscoveryLayout>,
) -> Result<(), ComparisonError> {
    let mut discovered = BTreeMap::new();
    let mut required_discovered = BTreeMap::new();
    for source in array(discovery, "sources")? {
        let source = object(source)?;
        let kind = string(source, "kind")?;
        let parent_depth = number(source, "parent_depth", 1)?;
        if parent_depth == 0 && matches!(kind, "theme_stylesheet" | "plugin_readme") {
            let component = comparison_component_key(object(required(source, "component")?)?)?;
            let dimensions = wordpress
                .components
                .get(&component)
                .ok_or(ComparisonError::InvalidDocument)?;
            let evidence = object(
                dimensions
                    .get("component_evidence")
                    .ok_or(ComparisonError::InvalidDocument)?,
            )?;
            check(
                array(evidence, "identity_sources")?
                    .iter()
                    .any(|source| source.as_str() == Some("same_origin_asset_path")),
            )?;
        }
        if kind != "theme_stylesheet" {
            continue;
        }
        let Some(theme) = source.get("theme") else {
            continue;
        };
        let theme = object(theme)?;
        let Some(version) = optional_text(theme, "version", MAX_WORDPRESS_DISCOVERY_VERSION_BYTES)?
        else {
            continue;
        };
        let component = comparison_component_key(object(required(source, "component")?)?)?;
        check(component.kind == "theme" && string(source, "outcome")? == "observed")?;
        if let Some(layout) = layout {
            let role_reference = optional_text(
                source,
                "role_reference",
                WORDPRESS_DISCOVERY_REFERENCE_BYTES,
            )?;
            if role_reference.is_none_or(|reference| {
                layout
                    .exact_role_references
                    .get("themes")
                    .map(String::as_str)
                    != Some(reference)
            }) {
                continue;
            }
        }
        check(discovered.insert(component.clone(), version).is_none())?;
        if layout.is_some() && parent_depth == 0 {
            check(required_discovered.insert(component, version).is_none())?;
        }
    }

    let mut reviewed = BTreeMap::new();
    for (key, dimensions) in &wordpress.components {
        let evidence = object(
            dimensions
                .get("component_evidence")
                .ok_or(ComparisonError::InvalidDocument)?,
        )?;
        for version in array(evidence, "versions")? {
            let version = object(version)?;
            if string(version, "source")? != "theme_stylesheet_declaration" {
                continue;
            }
            check(key.kind == "theme")?;
            check(
                reviewed
                    .insert(
                        key.clone(),
                        text(version, "value", MAX_WORDPRESS_DISCOVERY_VERSION_BYTES)?,
                    )
                    .is_none(),
            )?;
        }
    }
    if layout.is_some() {
        check(
            required_discovered
                .iter()
                .all(|(component, version)| reviewed.get(component) == Some(version))
                && reviewed
                    .iter()
                    .all(|(component, version)| discovered.get(component) == Some(version)),
        )
    } else {
        check(discovered == reviewed)
    }
}

fn validate_wordpress_discovery_source(
    fields: &Map<String, Value>,
    layout: Option<&ValidatedDiscoveryLayout>,
    page_collection: Option<&ValidatedWordPressPageCollection>,
) -> Result<(u64, u64, bool, Vec<String>, String), ComparisonError> {
    const REQUIRED_V1: [&str; 7] = [
        "kind",
        "parent_depth",
        "outcome",
        "request_attempted",
        "response_bytes",
        "evidence_reference_count",
        "evidence_references",
    ];
    const OPTIONAL_V1: [&str; 4] = ["component", "namespaces", "theme", "plugin"];
    if layout.is_some() {
        let mut required = REQUIRED_V1.to_vec();
        required.extend(["association", "resource_reference"]);
        if page_collection.is_some() {
            required.push("source_page_references");
        }
        let mut optional = OPTIONAL_V1.to_vec();
        optional.push("role_reference");
        keys(fields, &required, &optional)?;
    } else {
        keys(fields, &REQUIRED_V1, &OPTIONAL_V1)?;
    }
    let kind = token(
        fields,
        "kind",
        &["rest_index", "theme_stylesheet", "plugin_readme"],
    )?;
    let outcome = token(
        fields,
        "outcome",
        &[
            "observed",
            "no_metadata",
            "not_found",
            "unauthorized",
            "rate_limited",
            "redirect_observed",
            "unsupported_content",
            "invalid_advertisement",
            "malformed",
            "truncated",
            "request_failed",
            "budget_exhausted",
            "cancelled",
            "deadline_exceeded",
            "not_selected_by_limit",
            "not_attempted_after_throttle",
        ],
    )?;
    let parent_depth = number(fields, "parent_depth", 1)?;
    let request_attempted = boolean(fields, "request_attempted")?;
    let response_bytes = number(fields, "response_bytes", u64::MAX)?;
    let evidence_references = number(fields, "evidence_reference_count", 1)?;
    let references_by_source = array(fields, "evidence_references")?;
    check(references_by_source.len() as u64 == evidence_references)?;
    let mut unique_references = BTreeSet::new();
    for reference_value in references_by_source {
        let reference_value = reference_value
            .as_str()
            .ok_or(ComparisonError::InvalidDocument)?;
        super::reference(reference_value, "evidence")?;
        check(unique_references.insert(reference_value.to_owned()))?;
    }
    let component = fields.get("component").map(object).transpose()?;
    let namespaces = match fields.get("namespaces") {
        Some(value) => Some(value.as_array().ok_or(ComparisonError::InvalidDocument)?),
        None => None,
    };
    let theme = fields.get("theme").map(object).transpose()?;
    let plugin = fields.get("plugin").map(object).transpose()?;
    let source_page_references = match fields.get("source_page_references") {
        Some(value) => Some(value.as_array().ok_or(ComparisonError::InvalidDocument)?),
        None => None,
    };
    check(page_collection.is_some() == source_page_references.is_some())?;
    if let (Some(values), Some(page_collection)) = (source_page_references, page_collection) {
        check(!values.is_empty() && values.len() <= 4)?;
        let mut previous = None;
        for value in values {
            let reference = value.as_str().ok_or(ComparisonError::InvalidDocument)?;
            check(
                digest(reference, "sha256:")
                    && previous.is_none_or(|previous| previous < reference)
                    && (reference == page_collection.entry_page_reference
                        || page_collection.accepted_page_references.contains(reference)),
            )?;
            previous = Some(reference);
        }
    }
    if let Some(component) = component {
        keys(component, &["kind", "slug"], &[])?;
        let component_kind = token(component, "kind", &["core", "plugin", "theme"])?;
        let component_slug = text(component, "slug", MAX_IDENTIFIER_BYTES)?;
        check(
            valid_slug(component_slug)
                && ((component_kind == "core") == (component_slug == "wordpress")),
        )?;
    }
    if let Some(namespaces) = namespaces {
        check(namespaces.len() <= MAX_WORDPRESS_DISCOVERY_NAMESPACES)?;
        let mut unique = std::collections::BTreeSet::new();
        for namespace in namespaces {
            let namespace = namespace.as_str().ok_or(ComparisonError::InvalidDocument)?;
            check(valid_discovery_namespace(namespace) && unique.insert(namespace))?;
        }
    }
    if let Some(theme) = theme {
        discovery_metadata(
            theme,
            &[
                "name",
                "version",
                "template",
                "requires_wordpress",
                "requires_php",
                "tested_up_to",
            ],
        )?;
    }
    if let Some(plugin) = plugin {
        discovery_metadata(
            plugin,
            &[
                "name",
                "stable_tag",
                "requires_wordpress",
                "requires_php",
                "tested_up_to",
            ],
        )?;
    }
    let source_shape_valid = match kind {
        "rest_index" => {
            component.is_none() && parent_depth == 0 && theme.is_none() && plugin.is_none()
        },
        "theme_stylesheet" => {
            component.is_some_and(|value| string(value, "kind") == Ok("theme"))
                && parent_depth <= 1
                && namespaces.is_none()
                && plugin.is_none()
        },
        "plugin_readme" => {
            component.is_some_and(|value| string(value, "kind") == Ok("plugin"))
                && parent_depth == 0
                && namespaces.is_none()
                && theme.is_none()
        },
        _ => false,
    };
    let observed_shape_valid = match kind {
        "rest_index" => namespaces.is_some_and(|values| !values.is_empty()),
        "theme_stylesheet" => theme.is_some_and(|value| value.contains_key("name")),
        "plugin_readme" => plugin.is_some_and(|value| value.contains_key("name")),
        _ => false,
    };
    let completed_response = matches!(
        outcome,
        "observed"
            | "no_metadata"
            | "not_found"
            | "unauthorized"
            | "rate_limited"
            | "redirect_observed"
            | "unsupported_content"
            | "malformed"
            | "truncated"
    );
    let metadata_absent = namespaces.is_none() && theme.is_none() && plugin.is_none();
    let definitely_not_dispatched = matches!(
        outcome,
        "invalid_advertisement" | "not_selected_by_limit" | "not_attempted_after_throttle"
    );
    let deployment_identity = if let Some(layout) = layout {
        let association = token(
            fields,
            "association",
            &[
                "structured_advertisement",
                "operator_qualified_advertisement",
                "observed_conventional",
                "explicit_operator",
                "same_theme_base_parent",
                "invalid_advertisement",
            ],
        )?;
        let resource_reference = text(
            fields,
            "resource_reference",
            WORDPRESS_DISCOVERY_REFERENCE_BYTES,
        )?;
        check(digest(resource_reference, "sha256:"))?;
        let role_reference = fields
            .get("role_reference")
            .map(|_| {
                text(
                    fields,
                    "role_reference",
                    WORDPRESS_DISCOVERY_REFERENCE_BYTES,
                )
            })
            .transpose()?;
        check(role_reference.is_none_or(|reference| digest(reference, "sha256:")))?;
        let role = match kind {
            "rest_index" => "rest_index",
            "theme_stylesheet" => "themes",
            "plugin_readme" => "plugins",
            _ => return Err(ComparisonError::InvalidDocument),
        };
        let exact_role_bound = role_reference.is_some_and(|reference| {
            layout.exact_role_references.get(role).map(String::as_str) == Some(reference)
        });
        let binding_required = request_attempted
            || completed_response
            || theme.is_some()
            || plugin.is_some()
            || namespaces.is_some_and(|values| !values.is_empty());
        let association_valid = match association {
            "structured_advertisement" => {
                role == "rest_index"
                    && role_reference.is_some()
                    && layout.exact_role_bases.get(role).map(String::as_str)
                        == Some("structured_advertisement")
            },
            "operator_qualified_advertisement" => {
                role == "rest_index"
                    && role_reference.is_some()
                    && layout.exact_role_bases.get(role).map(String::as_str)
                        == Some("operator_declaration")
            },
            "observed_conventional" => {
                matches!(role, "themes" | "plugins")
                    && parent_depth == 0
                    && role_reference.is_some()
                    && layout.exact_role_bases.get(role).map(String::as_str)
                        == Some("conventional_asset")
            },
            "explicit_operator" => {
                matches!(role, "themes" | "plugins")
                    && parent_depth == 0
                    && role_reference.is_some()
                    && layout.exact_role_bases.get(role).map(String::as_str)
                        == Some("operator_declaration")
            },
            "same_theme_base_parent" => {
                role == "themes" && parent_depth == 1 && role_reference.is_some()
            },
            "invalid_advertisement" => {
                role == "rest_index"
                    && outcome == "invalid_advertisement"
                    && role_reference.is_none()
            },
            _ => return Err(ComparisonError::InvalidDocument),
        };
        check(
            association_valid
                && ((!binding_required && role_reference.is_none()) || exact_role_bound),
        )?;
        Some(resource_reference.to_owned())
    } else {
        None
    };
    check(
        source_shape_valid
            && evidence_references == u64::from(completed_response)
            && (!completed_response || request_attempted)
            && (request_attempted || response_bytes == 0)
            && (!definitely_not_dispatched || !request_attempted)
            && (if outcome == "observed" {
                observed_shape_valid
            } else {
                metadata_absent
            }),
    )?;
    let identity = if let Some(identity) = deployment_identity {
        identity
    } else {
        let component_identity = if let Some(value) = component {
            format!("{}:{}", string(value, "kind")?, string(value, "slug")?)
        } else {
            "none".to_owned()
        };
        format!("{kind}:{component_identity}:{parent_depth}")
    };
    Ok((
        response_bytes,
        evidence_references,
        request_attempted,
        unique_references.into_iter().collect(),
        identity,
    ))
}

fn discovery_metadata(
    fields: &Map<String, Value>,
    allowed: &[&str],
) -> Result<(), ComparisonError> {
    keys(fields, &[], allowed)?;
    check(!fields.is_empty())?;
    for (name, value) in fields {
        let value = value.as_str().ok_or(ComparisonError::InvalidDocument)?;
        check(if name == "version" {
            valid_discovery_version(value)
        } else {
            valid_discovery_metadata(value)
        })?;
    }
    Ok(())
}

fn valid_discovery_metadata(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_WORDPRESS_DISCOVERY_METADATA_BYTES
        && !value.chars().any(char::is_control)
}

fn valid_discovery_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_WORDPRESS_DISCOVERY_VERSION_BYTES
        && !value.chars().any(char::is_control)
}

fn valid_discovery_namespace(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_WORDPRESS_DISCOVERY_NAMESPACE_BYTES
        && value.is_ascii()
        && !value.chars().any(char::is_control)
}

fn object_mut(value: &mut Value) -> Result<&mut Map<String, Value>, ComparisonError> {
    value
        .as_object_mut()
        .ok_or(ComparisonError::InvalidDocument)
}

fn wordpress(fields: &serde_json::Map<String, Value>, count: usize) -> Result<(), ComparisonError> {
    keys(
        fields,
        &[
            "schema",
            "capability_id",
            "catalog_status",
            "signal_count",
            "evidence_reference_count",
            "additional_request_count",
            "item_projected",
            "component_count",
            "advisory_count",
            "components",
            "advisories",
        ],
        &[
            "catalog",
            "catalog_schema",
            "inventory_import",
            "external_review",
            "review_basis_schema",
        ],
    )?;
    let wire_schema = string(fields, "schema")?;
    let (schema, discovery_influenced) = match wire_schema {
        "security.wordpress-review-audit/v1" => (WordPressAuditSchema::V1, false),
        "security.wordpress-review-audit/v2" => (WordPressAuditSchema::V2, false),
        "security.wordpress-review-audit/v3" => (WordPressAuditSchema::V3, false),
        "security.wordpress-review-audit/v4" => (WordPressAuditSchema::V4, false),
        "security.wordpress-review-audit/v5" => (WordPressAuditSchema::V5, false),
        "security.wordpress-review-audit/v6" => (WordPressAuditSchema::V6, false),
        "security.wordpress-review-audit/v7" => (
            match string(fields, "review_basis_schema")? {
                "security.wordpress-review-audit/v1" => WordPressAuditSchema::V1,
                "security.wordpress-review-audit/v2" => WordPressAuditSchema::V2,
                "security.wordpress-review-audit/v3" => WordPressAuditSchema::V3,
                "security.wordpress-review-audit/v4" => WordPressAuditSchema::V4,
                "security.wordpress-review-audit/v5" => WordPressAuditSchema::V5,
                "security.wordpress-review-audit/v6" => WordPressAuditSchema::V6,
                _ => return Err(ComparisonError::InvalidDocument),
            },
            true,
        ),
        _ => return Err(ComparisonError::InvalidDocument),
    };
    check(discovery_influenced == fields.contains_key("review_basis_schema"))?;
    check(string(fields, "capability_id")? == WORDPRESS_CAPABILITY)?;
    let status = token(
        fields,
        "catalog_status",
        &["catalogue_not_supplied", "evaluated"],
    )?;
    match (status, fields.get("catalog"), schema) {
        (
            "catalogue_not_supplied",
            None,
            WordPressAuditSchema::V1 | WordPressAuditSchema::V2 | WordPressAuditSchema::V3,
        ) => {},
        (
            "evaluated",
            Some(value),
            WordPressAuditSchema::V1 | WordPressAuditSchema::V2 | WordPressAuditSchema::V3,
        ) => {
            catalog(object(value)?)?;
        },
        (
            "evaluated",
            None,
            WordPressAuditSchema::V4 | WordPressAuditSchema::V5 | WordPressAuditSchema::V6,
        ) => {},
        _ => return Err(ComparisonError::InvalidDocument),
    }
    check(schema != WordPressAuditSchema::V2 || status == "evaluated")?;
    let profiled = match schema {
        WordPressAuditSchema::V1 => {
            check(
                !fields.contains_key("catalog_schema") && !fields.contains_key("inventory_import"),
            )?;
            false
        },
        WordPressAuditSchema::V2 => {
            check(
                !fields.contains_key("catalog_schema") && !fields.contains_key("inventory_import"),
            )?;
            true
        },
        WordPressAuditSchema::V3 => {
            required(fields, "inventory_import")?;
            match status {
                "catalogue_not_supplied" => {
                    check(!fields.contains_key("catalog_schema"))?;
                    false
                },
                "evaluated" => match string(fields, "catalog_schema")? {
                    "security.wordpress-advisory-catalog/v1" => false,
                    "security.wordpress-advisory-catalog/v2" => true,
                    _ => return Err(ComparisonError::InvalidDocument),
                },
                _ => return Err(ComparisonError::InvalidDocument),
            }
        },
        WordPressAuditSchema::V4 | WordPressAuditSchema::V5 | WordPressAuditSchema::V6 => {
            check(
                status == "evaluated"
                    && !fields.contains_key("catalog")
                    && !fields.contains_key("catalog_schema"),
            )?;
            required(fields, "external_review")?;
            false
        },
    };
    let signal_count = number(fields, "signal_count", MAX_WORDPRESS_SIGNALS)?;
    let evidence_count = number(fields, "evidence_reference_count", MAX_WORDPRESS_SIGNALS)?;
    let additional_request_count = number(
        fields,
        "additional_request_count",
        MAX_WORDPRESS_DISCOVERY_REQUESTS,
    )?;
    check(discovery_influenced || additional_request_count == 0)?;
    let projected = boolean(fields, "item_projected")?;
    check(
        count <= 1
            && projected == (count == 1)
            && projected == (signal_count > 0)
            && projected == (evidence_count > 0),
    )?;

    let components = array(fields, "components")?;
    check(
        components.len() <= MAX_WORDPRESS_RESULT_COMPONENTS
            && number(
                fields,
                "component_count",
                MAX_WORDPRESS_RESULT_COMPONENTS as u64,
            )? == components.len() as u64,
    )?;
    let mut imported_components = BTreeMap::new();
    let mut version_count = 0_usize;
    for value in components {
        let (identity, component) =
            component(object(value)?, schema, profiled, discovery_influenced)?;
        version_count = version_count
            .checked_add(component.versions.len())
            .ok_or(ComparisonError::InvalidDocument)?;
        check(version_count <= MAX_WORDPRESS_RESULT_VERSION_EVIDENCE)?;
        check(imported_components.insert(identity, component).is_none())?;
    }
    if schema != WordPressAuditSchema::V1 || discovery_influenced {
        check(
            imported_components
                .values()
                .any(|component| component.observed_source)
                == (signal_count > 0),
        )?;
    }

    let advisories = array(fields, "advisories")?;
    check(
        advisories.len() <= MAX_WORDPRESS_ADVISORIES
            && number(fields, "advisory_count", MAX_WORDPRESS_ADVISORIES as u64)?
                == advisories.len() as u64
            && (status == "evaluated" || advisories.is_empty()),
    )?;
    let mut profiled_resolutions = BTreeMap::new();
    if profiled {
        let mut resolution_work = 0_usize;
        for (identity, component) in &imported_components {
            for profile in [
                WordPressComparisonProfile::NumericDottedV1,
                WordPressComparisonProfile::PhpReleaseSubsetV1,
            ] {
                resolution_work = resolution_work
                    .checked_add(component.versions.len())
                    .ok_or(ComparisonError::InvalidDocument)?;
                check(resolution_work <= MAX_WORDPRESS_VERSION_RESOLUTION_WORK)?;
                profiled_resolutions.insert(
                    (identity.clone(), profile),
                    resolve_profiled_component(component, profile)?,
                );
            }
        }
    }
    let mut advisory_ids = std::collections::BTreeSet::new();
    for value in advisories {
        let id = match (schema, profiled) {
            (WordPressAuditSchema::V1 | WordPressAuditSchema::V3, false) => {
                advisory_v1(object(value)?)?
            },
            (WordPressAuditSchema::V2 | WordPressAuditSchema::V3, true) => {
                advisory_v2(object(value)?, &imported_components, &profiled_resolutions)?
            },
            (
                WordPressAuditSchema::V4 | WordPressAuditSchema::V5 | WordPressAuditSchema::V6,
                false,
            ) => {
                return Err(ComparisonError::InvalidDocument);
            },
            _ => return Err(ComparisonError::InvalidDocument),
        };
        check(advisory_ids.insert(id))?;
    }
    if schema == WordPressAuditSchema::V3 {
        inventory_import(
            object(required(fields, "inventory_import")?)?,
            &imported_components,
        )?;
    }
    if matches!(
        schema,
        WordPressAuditSchema::V4 | WordPressAuditSchema::V5 | WordPressAuditSchema::V6
    ) {
        external_review(
            object(required(fields, "external_review")?)?,
            &imported_components,
            schema,
        )?;
        if let Some(value) = fields.get("inventory_import") {
            inventory_import(object(value)?, &imported_components)?;
        } else {
            check(
                imported_components
                    .values()
                    .all(|component| !component.inventory_component),
            )?;
        }
        check(advisories.is_empty())?;
    } else {
        check(!fields.contains_key("external_review"))?;
    }
    Ok(())
}

fn wordpress_comparison_snapshot(
    fields: &Map<String, Value>,
) -> Result<ImportedWordPressAudit, ComparisonError> {
    let schema = string(fields, "schema")?;
    let review_basis_schema = if schema == "security.wordpress-review-audit/v7" {
        string(fields, "review_basis_schema")?
    } else {
        schema
    };
    let inventory = fields.get("inventory_import").map(object).transpose()?;
    let external = fields.get("external_review").map(object).transpose()?;

    let methodology = selected_object(
        fields,
        &["schema", "review_basis_schema", "catalog_schema"],
        &[
            (
                "source_namespace",
                external.and_then(|value| value.get("source_namespace")),
            ),
            (
                "source_format",
                external.and_then(|value| value.get("source_format")),
            ),
            (
                "mapping_revision",
                external.and_then(|value| value.get("mapping_revision")),
            ),
            (
                "identity_mapping_policy",
                external.and_then(|value| value.get("identity_mapping_policy")),
            ),
            (
                "identity_source_assurance",
                external.and_then(|value| value.get("identity_source_assurance")),
            ),
            (
                "resource_policy",
                external.and_then(|value| value.get("resource_policy")),
            ),
            (
                "comparison_policy",
                external.and_then(|value| value.get("comparison_policy")),
            ),
            (
                "comparison_profile",
                external.and_then(|value| value.get("comparison_profile")),
            ),
            (
                "policy_selection",
                external.and_then(|value| value.get("policy_selection")),
            ),
            (
                "source_semantics_assurance",
                external.and_then(|value| value.get("source_semantics_assurance")),
            ),
        ],
    )?;

    let coverage = selected_object(
        fields,
        &[
            "catalog_status",
            "signal_count",
            "evidence_reference_count",
            "item_projected",
            "component_count",
            "advisory_count",
        ],
        &[
            (
                "additional_request_count",
                (schema == "security.wordpress-review-audit/v7")
                    .then(|| fields.get("additional_request_count"))
                    .flatten(),
            ),
            (
                "inventory_coverage",
                inventory.and_then(|value| value.get("coverage")),
            ),
            (
                "inventory_limitations",
                inventory.and_then(|value| value.get("limitations")),
            ),
            (
                "external_counts",
                external.and_then(|value| value.get("counts")),
            ),
        ],
    )?;

    let provenance = selected_object(
        fields,
        &["catalog"],
        &[
            (
                "inventory_inputs",
                inventory.and_then(|value| value.get("inputs")),
            ),
            (
                "external_input",
                external.and_then(|value| value.get("input")),
            ),
        ],
    )?;

    let mut components = BTreeMap::new();
    for component in array(fields, "components")? {
        let component = object(component)?;
        let key = comparison_component_key(object(required(component, "identity")?)?)?;
        let content = dimensions(&[(
            "component_evidence",
            selected_object(
                component,
                &[
                    "evidence_class",
                    "identity_sources",
                    "confidence_classes",
                    "versions",
                    "activation",
                    "inventory_status",
                ],
                &[],
            )?,
        )]);
        if components.insert(key, content).is_some() {
            return Err(ComparisonError::AmbiguousIdentity);
        }
    }

    let mut advisories = BTreeMap::new();
    if matches!(
        review_basis_schema,
        "security.wordpress-review-audit/v4"
            | "security.wordpress-review-audit/v5"
            | "security.wordpress-review-audit/v6"
    ) {
        let external = external.ok_or(ComparisonError::InvalidDocument)?;
        let namespace = string(external, "source_namespace")?;
        let allow_source_variants = review_basis_schema == "security.wordpress-review-audit/v6"
            && matches!(
                string(external, "resource_policy")?,
                WORDFENCE_V3_RESOURCE_POLICY_V2 | WORDFENCE_V3_RESOURCE_POLICY_V3
            );
        let mut source_variants = BTreeMap::new();
        let mut notices = BTreeMap::new();
        for notice in array(external, "notices")? {
            let notice = object(notice)?;
            notices.insert(
                string(notice, "id")?.to_owned(),
                canonical_value(&Value::Object(notice.clone()))?,
            );
        }
        for evaluation in array(external, "evaluations")? {
            let evaluation = object(evaluation)?;
            let wire_key = object(required(evaluation, "key")?)?;
            let component = if review_basis_schema == "security.wordpress-review-audit/v6" {
                comparison_component_key(object(required(wire_key, "source_component")?)?)?
            } else {
                comparison_component_key(object(required(wire_key, "component")?)?)?
            };
            let key = WordPressAdvisoryKey {
                source_kind: "external".to_owned(),
                source_namespace: namespace.to_owned(),
                upstream_id: string(wire_key, "upstream_id")?.to_owned(),
                component,
            };
            let mut bound_notices = Map::new();
            for notice_id in array(evaluation, "notice_ids")? {
                let notice_id = notice_id.as_str().ok_or(ComparisonError::InvalidDocument)?;
                let notice = notices
                    .get(notice_id)
                    .ok_or(ComparisonError::InvalidDocument)?;
                bound_notices.insert(notice_id.to_owned(), notice.clone());
            }
            let attribution = selected_object(
                evaluation,
                &[
                    "references",
                    "record_reference",
                    "cve_link",
                    "researchers",
                    "notice_ids",
                ],
                &[("notices", Some(&Value::Object(bound_notices)))],
            )?;
            let content = dimensions(&[
                (
                    "identity_mapping",
                    external_identity_mapping_projection(
                        evaluation,
                        wire_key,
                        review_basis_schema,
                    )?,
                ),
                (
                    "advisory_content",
                    selected_object(
                        evaluation,
                        &[
                            "title",
                            "display_name",
                            "informational",
                            "description",
                            "cwe",
                            "cvss",
                            "cve",
                        ],
                        &[],
                    )?,
                ),
                (
                    "affected_ranges",
                    selected_object(evaluation, &["affected_ranges"], &[])?,
                ),
                (
                    "source_fix_information",
                    selected_object(
                        evaluation,
                        &[
                            "source_patched",
                            "source_patched_versions",
                            "source_remediation",
                        ],
                        &[],
                    )?,
                ),
                (
                    "evaluation_basis",
                    selected_object(
                        evaluation,
                        &[
                            "component_evidence",
                            "version_evidence_resolution",
                            "version_relation",
                            "version_relation_reason",
                            "range_evaluations",
                            "execution",
                        ],
                        &[],
                    )?,
                ),
                (
                    "applicability",
                    selected_object(evaluation, &["applicability"], &[])?,
                ),
                (
                    "source_provenance",
                    selected_object(evaluation, &["source_dates"], &[])?,
                ),
                ("attribution", attribution),
            ]);
            if review_basis_schema == "security.wordpress-review-audit/v6" {
                collect_wordpress_advisory_projection(
                    &mut source_variants,
                    key,
                    string(wire_key, "source_association_fingerprint")?,
                    content,
                )?;
            } else if advisories.insert(key, content).is_some() {
                return Err(ComparisonError::AmbiguousIdentity);
            }
        }
        if review_basis_schema == "security.wordpress-review-audit/v6" {
            for limitation in array(external, "identity_limitations")? {
                let limitation = object(limitation)?;
                let wire_key = object(required(limitation, "key")?)?;
                let component =
                    comparison_component_key(object(required(wire_key, "source_component")?)?)?;
                let key = WordPressAdvisoryKey {
                    source_kind: "external".to_owned(),
                    source_namespace: namespace.to_owned(),
                    upstream_id: string(wire_key, "upstream_id")?.to_owned(),
                    component,
                };
                let mut bound_notices = Map::new();
                for notice_id in array(limitation, "notice_ids")? {
                    let notice_id = notice_id.as_str().ok_or(ComparisonError::InvalidDocument)?;
                    let notice = notices
                        .get(notice_id)
                        .ok_or(ComparisonError::InvalidDocument)?;
                    bound_notices.insert(notice_id.to_owned(), notice.clone());
                }
                let attribution = selected_object(
                    limitation,
                    &["references", "record_reference", "notice_ids"],
                    &[("notices", Some(&Value::Object(bound_notices)))],
                )?;
                let content = dimensions(&[
                    (
                        "identity_mapping",
                        selected_object(limitation, &["identity_resolution"], &[])?,
                    ),
                    (
                        "advisory_content",
                        selected_object(limitation, &["title", "display_name"], &[])?,
                    ),
                    (
                        "affected_ranges",
                        selected_object(limitation, &["affected_ranges"], &[])?,
                    ),
                    (
                        "source_fix_information",
                        selected_object(
                            limitation,
                            &[
                                "source_patched",
                                "source_patched_versions",
                                "source_remediation",
                            ],
                            &[],
                        )?,
                    ),
                    (
                        "evaluation_basis",
                        selected_object(
                            limitation,
                            &[
                                "range_evaluations",
                                "version_relation",
                                "version_relation_reason",
                                "execution",
                            ],
                            &[],
                        )?,
                    ),
                    (
                        "applicability",
                        selected_object(limitation, &["applicability"], &[])?,
                    ),
                    ("attribution", attribution),
                ]);
                collect_wordpress_advisory_projection(
                    &mut source_variants,
                    key,
                    string(wire_key, "source_association_fingerprint")?,
                    content,
                )?;
            }
        }
        finalize_wordpress_advisory_projections(
            &mut advisories,
            source_variants,
            allow_source_variants,
        )?;
    } else {
        let namespace = fields
            .get("catalog")
            .map(object)
            .transpose()?
            .map(|catalog| string(catalog, "id"))
            .transpose()?
            .unwrap_or("catalogue-not-supplied");
        for advisory in array(fields, "advisories")? {
            let advisory = object(advisory)?;
            let component = comparison_component_key(object(required(advisory, "component")?)?)?;
            let key = WordPressAdvisoryKey {
                source_kind: "termivar_catalog".to_owned(),
                source_namespace: namespace.to_owned(),
                upstream_id: string(advisory, "id")?.to_owned(),
                component,
            };
            let content = dimensions(&[
                (
                    "advisory_content",
                    selected_object(advisory, &["cve", "summary"], &[])?,
                ),
                (
                    "affected_ranges",
                    selected_object(advisory, &["affected_ranges"], &[])?,
                ),
                (
                    "source_fix_information",
                    selected_object(advisory, &["fixed_versions", "remediation"], &[])?,
                ),
                (
                    "comparison_methodology",
                    selected_object(advisory, &["comparison_profile"], &[])?,
                ),
                (
                    "evaluation_basis",
                    selected_object(
                        advisory,
                        &[
                            "component_evidence",
                            "version_resolution",
                            "version_resolution_reason",
                            "version_relation",
                            "prerequisites",
                            "exploit_execution",
                            "impact_validation",
                        ],
                        &[],
                    )?,
                ),
                (
                    "applicability",
                    selected_object(advisory, &["applicability"], &[])?,
                ),
                (
                    "source_provenance",
                    selected_object(advisory, &["source"], &[])?,
                ),
            ]);
            if advisories.insert(key, content).is_some() {
                return Err(ComparisonError::AmbiguousIdentity);
            }
        }
    }

    Ok(ImportedWordPressAudit {
        application_reference: None,
        coverage,
        inventory_coverage_recorded: inventory.is_some(),
        methodology,
        provenance,
        discovery_source_content: None,
        components,
        advisories,
    })
}

fn external_identity_mapping_projection(
    evaluation: &Map<String, Value>,
    wire_key: &Map<String, Value>,
    schema: &str,
) -> Result<Value, ComparisonError> {
    if schema == "security.wordpress-review-audit/v6" {
        return selected_object(
            evaluation,
            &["identity_mapping", "identity_collision_raw_count"],
            &[("canonical_component", wire_key.get("component"))],
        );
    }
    let mut projection = Map::new();
    projection.insert(
        "identity_mapping".to_owned(),
        Value::String("exact".to_owned()),
    );
    projection.insert(
        "canonical_component".to_owned(),
        canonical_value(required(wire_key, "component")?)?,
    );
    Ok(Value::Object(projection))
}

fn collect_wordpress_advisory_projection(
    source_variants: &mut BTreeMap<WordPressAdvisoryKey, BTreeMap<String, BTreeMap<String, Value>>>,
    key: WordPressAdvisoryKey,
    source_association_fingerprint: &str,
    content: BTreeMap<String, Value>,
) -> Result<(), ComparisonError> {
    if source_variants
        .entry(key)
        .or_default()
        .insert(source_association_fingerprint.to_owned(), content)
        .is_some()
    {
        return Err(ComparisonError::AmbiguousIdentity);
    }
    Ok(())
}

fn finalize_wordpress_advisory_projections(
    advisories: &mut BTreeMap<WordPressAdvisoryKey, BTreeMap<String, Value>>,
    source_variants: BTreeMap<WordPressAdvisoryKey, BTreeMap<String, BTreeMap<String, Value>>>,
    allow_source_variants: bool,
) -> Result<(), ComparisonError> {
    for (key, variants) in source_variants {
        let content = if variants.len() == 1 {
            variants
                .into_values()
                .next()
                .ok_or(ComparisonError::InvalidDocument)?
        } else {
            check(allow_source_variants)?;
            let mut grouped = BTreeMap::new();
            grouped.insert(
                "source_association_variants".to_owned(),
                Value::Array(
                    variants
                        .into_values()
                        .map(wordpress_advisory_content_value)
                        .collect(),
                ),
            );
            grouped
        };
        if advisories.insert(key, content).is_some() {
            return Err(ComparisonError::AmbiguousIdentity);
        }
    }
    Ok(())
}

fn wordpress_advisory_content_value(content: BTreeMap<String, Value>) -> Value {
    Value::Object(content.into_iter().collect())
}

fn comparison_component_key(
    fields: &Map<String, Value>,
) -> Result<WordPressComponentKey, ComparisonError> {
    Ok(WordPressComponentKey {
        kind: string(fields, "kind")?.to_owned(),
        slug: string(fields, "slug")?.to_owned(),
    })
}

fn dimensions(values: &[(&str, Value)]) -> BTreeMap<String, Value> {
    values
        .iter()
        .filter(|(_, value)| value.as_object().is_none_or(|fields| !fields.is_empty()))
        .map(|(name, value)| ((*name).to_owned(), value.clone()))
        .collect()
}

fn selected_object(
    fields: &Map<String, Value>,
    direct_names: &[&str],
    additional: &[(&str, Option<&Value>)],
) -> Result<Value, ComparisonError> {
    let mut selected = Map::new();
    for name in direct_names {
        if let Some(value) = fields.get(*name) {
            selected.insert((*name).to_owned(), canonical_value(value)?);
        }
    }
    for (name, value) in additional {
        if let Some(value) = value {
            selected.insert((*name).to_owned(), canonical_value(value)?);
        }
    }
    Ok(Value::Object(selected))
}

fn canonical_value(value: &Value) -> Result<Value, ComparisonError> {
    match value {
        Value::Array(values) => {
            let values = values
                .iter()
                .map(canonical_value)
                .collect::<Result<Vec<_>, _>>()?;
            let mut keyed = values
                .into_iter()
                .map(|value| {
                    serde_json::to_string(&value)
                        .map(|key| (key, value))
                        .map_err(|_| ComparisonError::Serialization)
                })
                .collect::<Result<Vec<_>, _>>()?;
            keyed.sort_by(|left, right| left.0.cmp(&right.0));
            Ok(Value::Array(
                keyed.into_iter().map(|(_, value)| value).collect(),
            ))
        },
        Value::Object(fields) => {
            let mut result = Map::new();
            for (name, value) in fields {
                result.insert(name.clone(), canonical_value(value)?);
            }
            Ok(Value::Object(result))
        },
        _ => Ok(value.clone()),
    }
}

fn catalog(fields: &serde_json::Map<String, Value>) -> Result<(), ComparisonError> {
    keys(fields, &["id", "revision", "retrieved_on"], &[])?;
    identifier(text(fields, "id", MAX_IDENTIFIER_BYTES)?)?;
    identifier(text(fields, "revision", MAX_IDENTIFIER_BYTES)?)?;
    date(text(fields, "retrieved_on", MAX_IDENTIFIER_BYTES)?)
}

fn component(
    fields: &serde_json::Map<String, Value>,
    schema: WordPressAuditSchema,
    profiled: bool,
    discovery_influenced: bool,
) -> Result<(String, ImportedWordPressComponent), ComparisonError> {
    keys(
        fields,
        &[
            "identity",
            "evidence_class",
            "identity_sources",
            "confidence_classes",
            "versions",
            "activation",
        ],
        &["inventory_status"],
    )?;
    let identity = component_identity(object(required(fields, "identity")?)?)?;
    let evidence_class = token(
        fields,
        "evidence_class",
        &[
            "observed_hint",
            "operator_supplied",
            "conflicting",
            "unknown",
        ],
    )?;
    let evidence_sources: &[&str] = if discovery_influenced {
        &[
            "generator_metadata",
            "same_origin_asset_path",
            "theme_stylesheet_declaration",
            "operator_context",
        ]
    } else {
        &[
            "generator_metadata",
            "same_origin_asset_path",
            "operator_context",
        ]
    };
    token_array(
        fields,
        "identity_sources",
        evidence_sources,
        evidence_sources.len(),
    )?;
    let identity_sources = array(fields, "identity_sources")?;
    let identity_sources = identity_sources
        .iter()
        .map(|value| value.as_str().ok_or(ComparisonError::InvalidDocument))
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    if schema != WordPressAuditSchema::V1 || discovery_influenced {
        check(!identity_sources.contains("generator_metadata") || identity == "core:wordpress")?;
    }
    check(
        !identity_sources.contains("theme_stylesheet_declaration")
            || identity.starts_with("theme:"),
    )?;
    let profiled_evidence = if identity_sources.iter().any(|value| {
        matches!(
            *value,
            "generator_metadata" | "same_origin_asset_path" | "theme_stylesheet_declaration"
        )
    }) {
        "observed_hint"
    } else if identity_sources
        .iter()
        .any(|value| *value == "operator_context")
    {
        "operator_supplied"
    } else {
        "unknown"
    };
    token_array(
        fields,
        "confidence_classes",
        &[
            "public_declaration",
            "structural_hint",
            "operator_assertion",
        ],
        3,
    )?;
    let confidence_classes = array(fields, "confidence_classes")?
        .iter()
        .map(|value| value.as_str().ok_or(ComparisonError::InvalidDocument))
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    let expected_confidence_classes = identity_sources
        .iter()
        .map(|source| match *source {
            "generator_metadata" => Ok("public_declaration"),
            "same_origin_asset_path" => Ok("structural_hint"),
            "theme_stylesheet_declaration" => Ok("public_declaration"),
            "operator_context" => Ok("operator_assertion"),
            _ => Err(ComparisonError::InvalidDocument),
        })
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    if schema != WordPressAuditSchema::V1 || discovery_influenced {
        check(confidence_classes == expected_confidence_classes)?;
    }

    let versions = array(fields, "versions")?;
    check(versions.len() <= MAX_WORDPRESS_RESULT_VERSION_EVIDENCE)?;
    let mut unique_versions = std::collections::BTreeSet::new();
    let mut version_values = Vec::with_capacity(versions.len());
    for value in versions {
        let version = object(value)?;
        keys(version, &["value", "source", "confidence"], &[])?;
        let value = source_version(text(version, "value", 64)?)?;
        let version_sources: &[&str] = if discovery_influenced {
            &[
                "generator_metadata",
                "same_origin_asset_path",
                "theme_stylesheet_declaration",
                "operator_context",
            ]
        } else if schema == WordPressAuditSchema::V2 {
            &["generator_metadata", "operator_context"]
        } else {
            &[
                "generator_metadata",
                "same_origin_asset_path",
                "operator_context",
            ]
        };
        let source = token(version, "source", version_sources)?;
        let confidence = token(
            version,
            "confidence",
            &[
                "public_declaration",
                "structural_hint",
                "operator_assertion",
            ],
        )?;
        check(
            confidence
                == match source {
                    "generator_metadata" => "public_declaration",
                    "same_origin_asset_path" => "structural_hint",
                    "theme_stylesheet_declaration" => "public_declaration",
                    "operator_context" => "operator_assertion",
                    _ => return Err(ComparisonError::InvalidDocument),
                },
        )?;
        check(source != "theme_stylesheet_declaration" || identity.starts_with("theme:"))?;
        if schema != WordPressAuditSchema::V1 || discovery_influenced {
            check(source != "generator_metadata" || identity == "core:wordpress")?;
            check(identity_sources.contains(source) && confidence_classes.contains(confidence))?;
        }
        check(unique_versions.insert((value, source)))?;
        version_values.push(value.to_owned());
    }
    let activation = optional_token(
        fields,
        "activation",
        &["active", "inactive", "network_active", "unknown"],
    )?;
    if schema != WordPressAuditSchema::V1 || discovery_influenced {
        check(activation.is_none() || identity_sources.contains("operator_context"))?;
    }
    if schema != WordPressAuditSchema::V1 || discovery_influenced {
        let expected_evidence = if profiled
            || matches!(
                schema,
                WordPressAuditSchema::V4 | WordPressAuditSchema::V5 | WordPressAuditSchema::V6
            ) {
            profiled_evidence
        } else {
            legacy_component_evidence(&version_values, profiled_evidence)?
        };
        check(evidence_class == expected_evidence)?;
    }
    let inventory_status = if matches!(
        schema,
        WordPressAuditSchema::V3
            | WordPressAuditSchema::V4
            | WordPressAuditSchema::V5
            | WordPressAuditSchema::V6
    ) {
        fields
            .get("inventory_status")
            .map(|_| {
                token(
                    fields,
                    "inventory_status",
                    &[
                        "core_version_supplied",
                        "active",
                        "inactive",
                        "active_network",
                        "must_use",
                        "parent",
                    ],
                )
            })
            .transpose()?
    } else {
        check(!fields.contains_key("inventory_status"))?;
        None
    };
    if let Some(status) = inventory_status {
        check(identity_sources.contains("operator_context"))?;
        let compatible = match status {
            "core_version_supplied" => identity == "core:wordpress" && activation.is_none(),
            "active" => {
                (identity.starts_with("plugin:") || identity.starts_with("theme:"))
                    && activation == Some("active")
            },
            "inactive" => {
                (identity.starts_with("plugin:") || identity.starts_with("theme:"))
                    && activation == Some("inactive")
            },
            "active_network" => {
                identity.starts_with("plugin:") && activation == Some("network_active")
            },
            "must_use" => identity.starts_with("plugin:") && activation.is_none(),
            "parent" => identity.starts_with("theme:") && activation.is_none(),
            _ => false,
        };
        check(compatible)?;
    }
    Ok((
        identity,
        ImportedWordPressComponent {
            versions: version_values,
            evidence_class: evidence_class.to_owned(),
            profiled_evidence,
            observed_source: profiled_evidence == "observed_hint",
            operator_source: identity_sources.contains("operator_context"),
            inventory_component: inventory_status.is_some(),
        },
    ))
}

fn external_review(
    fields: &serde_json::Map<String, Value>,
    components: &BTreeMap<String, ImportedWordPressComponent>,
    schema: WordPressAuditSchema,
) -> Result<(), ComparisonError> {
    let (profile, mapping_revision, resource_policy) = match schema {
        WordPressAuditSchema::V4 => {
            keys(
                fields,
                &[
                    "source_namespace",
                    "source_format",
                    "mapping_revision",
                    "comparison_policy",
                    "input",
                    "counts",
                    "notices",
                    "evaluations",
                ],
                &[],
            )?;
            check(
                string(fields, "comparison_policy")?
                    == "wordfence-v3/source-semantics-unresolved/v1",
            )?;
            (
                None,
                WORDFENCE_V3_MAPPING_REVISION_V1,
                ExternalResourcePolicy::V1,
            )
        },
        WordPressAuditSchema::V5 => {
            keys(
                fields,
                &[
                    "source_namespace",
                    "source_format",
                    "mapping_revision",
                    "comparison_policy",
                    "comparison_profile",
                    "policy_selection",
                    "source_semantics_assurance",
                    "input",
                    "counts",
                    "notices",
                    "evaluations",
                ],
                &[],
            )?;
            check(
                string(fields, "comparison_policy")?
                    == "termivar.wordfence-v3-explicit-interpretation/v1"
                    && string(fields, "policy_selection")? == "explicit_operator"
                    && string(fields, "source_semantics_assurance")? == "not_established",
            )?;
            (
                Some(
                    WordPressComparisonProfile::parse(string(fields, "comparison_profile")?)
                        .map_err(|_| ComparisonError::InvalidDocument)?,
                ),
                WORDFENCE_V3_MAPPING_REVISION_V1,
                ExternalResourcePolicy::V1,
            )
        },
        WordPressAuditSchema::V6 => {
            let profile = match string(fields, "comparison_policy")? {
                "wordfence-v3/source-semantics-unresolved/v1" => {
                    keys(
                        fields,
                        &[
                            "source_namespace",
                            "source_format",
                            "mapping_revision",
                            "identity_mapping_policy",
                            "identity_source_assurance",
                            "resource_policy",
                            "comparison_policy",
                            "input",
                            "counts",
                            "notices",
                            "evaluations",
                            "identity_limitations",
                        ],
                        &[],
                    )?;
                    None
                },
                "termivar.wordfence-v3-explicit-interpretation/v1" => {
                    keys(
                        fields,
                        &[
                            "source_namespace",
                            "source_format",
                            "mapping_revision",
                            "identity_mapping_policy",
                            "identity_source_assurance",
                            "resource_policy",
                            "comparison_policy",
                            "comparison_profile",
                            "policy_selection",
                            "source_semantics_assurance",
                            "input",
                            "counts",
                            "notices",
                            "evaluations",
                            "identity_limitations",
                        ],
                        &[],
                    )?;
                    check(
                        string(fields, "policy_selection")? == "explicit_operator"
                            && string(fields, "source_semantics_assurance")? == "not_established",
                    )?;
                    Some(
                        WordPressComparisonProfile::parse(string(fields, "comparison_profile")?)
                            .map_err(|_| ComparisonError::InvalidDocument)?,
                    )
                },
                _ => return Err(ComparisonError::InvalidDocument),
            };
            let mapping_revision = token(
                fields,
                "mapping_revision",
                &[
                    WORDFENCE_V3_MAPPING_REVISION_V1,
                    WORDFENCE_V3_MAPPING_REVISION_V2,
                ],
            )?;
            check(
                string(fields, "identity_mapping_policy")? == WORDFENCE_V3_IDENTITY_MAPPING_POLICY
                    && string(fields, "identity_source_assurance")? == "not_established",
            )?;
            let resource_policy = match string(fields, "resource_policy")? {
                WORDFENCE_V3_RESOURCE_POLICY_V1 => ExternalResourcePolicy::V1,
                WORDFENCE_V3_RESOURCE_POLICY_V2 => ExternalResourcePolicy::V2,
                WORDFENCE_V3_RESOURCE_POLICY_V3 => ExternalResourcePolicy::V3,
                _ => return Err(ComparisonError::InvalidDocument),
            };
            (profile, mapping_revision, resource_policy)
        },
        _ => return Err(ComparisonError::InvalidDocument),
    };
    let namespace = string(fields, "source_namespace")?;
    check(namespace == "wordfence-intelligence")?;
    check(string(fields, "source_format")? == "wordfence-v3-production")?;
    check(string(fields, "mapping_revision")? == mapping_revision)?;

    let input = object(required(fields, "input")?)?;
    if schema == WordPressAuditSchema::V6 {
        keys(
            input,
            &[
                "byte_length",
                "sha256",
                "semantic_sha256",
                "accounted_retained_bytes",
            ],
            &[],
        )?;
        check(
            number(
                input,
                "accounted_retained_bytes",
                resource_policy.retained_bytes(),
            )? > 0,
        )?;
    } else {
        keys(input, &["byte_length", "sha256", "semantic_sha256"], &[])?;
    }
    check(number(input, "byte_length", MAX_WORDFENCE_V3_INPUT_BYTES)? > 0)?;
    check(digest(string(input, "sha256")?, ""))?;
    check(digest(string(input, "semantic_sha256")?, ""))?;

    let counts = object(required(fields, "counts")?)?;
    let base_count_fields = [
        "parsed_records",
        "software_associations",
        "selected_associations",
        "evaluable_associations",
        "unsupported_associations",
        "excluded_associations",
    ];
    if profile.is_some() && schema == WordPressAuditSchema::V6 {
        keys(
            counts,
            &[
                "parsed_records",
                "software_associations",
                "exact_identity_associations",
                "candidate_identity_associations",
                "ambiguous_identity_associations",
                "unresolved_identity_associations",
                "projected_identity_limitations",
                "unprojected_identity_limitations",
                "selected_associations",
                "evaluable_associations",
                "unsupported_associations",
                "excluded_associations",
                "mapped_unselected_associations",
                "within_associations",
                "outside_associations",
                "indeterminate_associations",
                "selected_ranges",
                "evaluated_ranges",
                "containing_ranges",
                "noncontaining_ranges",
                "unsupported_ranges",
                "invalid_ranges",
                "not_evaluated_ranges",
                "partial_range_coverage_associations",
            ],
            &[],
        )?;
    } else if profile.is_some() {
        keys(
            counts,
            &[
                "parsed_records",
                "software_associations",
                "selected_associations",
                "evaluable_associations",
                "unsupported_associations",
                "excluded_associations",
                "within_associations",
                "outside_associations",
                "indeterminate_associations",
                "selected_ranges",
                "evaluated_ranges",
                "containing_ranges",
                "noncontaining_ranges",
                "unsupported_ranges",
                "invalid_ranges",
                "not_evaluated_ranges",
                "partial_range_coverage_associations",
            ],
            &[],
        )?;
    } else if schema == WordPressAuditSchema::V6 {
        keys(
            counts,
            &[
                "parsed_records",
                "software_associations",
                "exact_identity_associations",
                "candidate_identity_associations",
                "ambiguous_identity_associations",
                "unresolved_identity_associations",
                "projected_identity_limitations",
                "unprojected_identity_limitations",
                "selected_associations",
                "evaluable_associations",
                "unsupported_associations",
                "excluded_associations",
                "mapped_unselected_associations",
            ],
            &[],
        )?;
    } else {
        keys(counts, &base_count_fields, &[])?;
    }
    let parsed = number(counts, "parsed_records", MAX_WORDFENCE_V3_RECORDS)?;
    let associations = number(
        counts,
        "software_associations",
        MAX_WORDFENCE_V3_ASSOCIATIONS,
    )?;
    let selected = number(
        counts,
        "selected_associations",
        MAX_WORDFENCE_V3_ASSOCIATIONS,
    )?;
    let evaluable = number(
        counts,
        "evaluable_associations",
        MAX_WORDFENCE_V3_ASSOCIATIONS,
    )?;
    let unsupported = number(
        counts,
        "unsupported_associations",
        MAX_WORDFENCE_V3_ASSOCIATIONS,
    )?;
    let excluded = number(
        counts,
        "excluded_associations",
        MAX_WORDFENCE_V3_ASSOCIATIONS,
    )?;
    let mapped_unselected = if schema == WordPressAuditSchema::V6 {
        Some(number(
            counts,
            "mapped_unselected_associations",
            MAX_WORDFENCE_V3_ASSOCIATIONS,
        )?)
    } else {
        None
    };
    let identity_counts = if schema == WordPressAuditSchema::V6 {
        let values = [
            number(
                counts,
                "exact_identity_associations",
                MAX_WORDFENCE_V3_ASSOCIATIONS,
            )?,
            number(
                counts,
                "candidate_identity_associations",
                MAX_WORDFENCE_V3_ASSOCIATIONS,
            )?,
            number(
                counts,
                "ambiguous_identity_associations",
                MAX_WORDFENCE_V3_ASSOCIATIONS,
            )?,
            number(
                counts,
                "unresolved_identity_associations",
                MAX_WORDFENCE_V3_ASSOCIATIONS,
            )?,
        ];
        check(v6_identity_contract_is_valid(
            mapping_revision,
            resource_policy,
            values,
            associations,
        ))?;
        values
    } else {
        [associations, 0, 0, 0]
    };
    let identity_limitation_projection = if schema == WordPressAuditSchema::V6 {
        let projected = number(
            counts,
            "projected_identity_limitations",
            MAX_WORDFENCE_V3_IDENTITY_LIMITATION_PROJECTIONS,
        )?;
        let unprojected = number(
            counts,
            "unprojected_identity_limitations",
            MAX_WORDFENCE_V3_ASSOCIATIONS,
        )?;
        check(
            projected
                .checked_add(unprojected)
                .is_some_and(|value| value == identity_counts[3]),
        )?;
        Some(projected)
    } else {
        None
    };
    check(
        external_source_counts_are_valid(parsed, associations)
            && selected
                .checked_add(excluded)
                .is_some_and(|value| value == associations)
            && evaluable
                .checked_add(unsupported)
                .is_some_and(|value| value == selected)
            && mapped_unselected.is_none_or(|mapped| {
                mapped
                    .checked_add(identity_counts[3])
                    .is_some_and(|value| value == excluded)
            })
            && (profile.is_some() || (evaluable == 0 && unsupported == selected)),
    )?;

    let notices = array(fields, "notices")?;
    check(notices.len() <= MAX_WORDFENCE_V3_NOTICES)?;
    let mut notices_by_id = std::collections::BTreeMap::new();
    for value in notices {
        let notice = object(value)?;
        keys(
            notice,
            &["id", "message", "party", "notice", "license", "license_url"],
            &[],
        )?;
        let id = text(notice, "id", MAX_IDENTIFIER_BYTES)?;
        check(prefixed_digest(id, "wordfence-notice-sha256:"))?;
        let message = external_text(
            string(notice, "message")?,
            MAX_LEGACY_AUDIT_TEXT_BYTES,
            true,
        )?;
        let party = text(notice, "party", MAX_IDENTIFIER_BYTES)?;
        check(valid_external_identifier(party, MAX_IDENTIFIER_BYTES))?;
        check(
            notices_by_id
                .insert(id.to_owned(), party.to_owned())
                .is_none(),
        )?;
        let notice_text =
            external_text(string(notice, "notice")?, MAX_LEGACY_AUDIT_TEXT_BYTES, true)?;
        let license = external_text(
            string(notice, "license")?,
            MAX_LEGACY_AUDIT_TEXT_BYTES,
            true,
        )?;
        let license_url = text(notice, "license_url", MAX_LEGACY_AUDIT_TEXT_BYTES)?;
        inert_url(license_url)?;
        check(
            wordfence_notice_id(message, party, notice_text, license, license_url).as_deref()
                == Some(id),
        )?;
    }

    let evaluations = array(fields, "evaluations")?;
    check(
        evaluations.len() <= MAX_WORDFENCE_V3_EVALUATIONS
            && u64::try_from(evaluations.len()).ok() == Some(selected),
    )?;
    let mut identities = std::collections::BTreeSet::new();
    let mut referenced_notices = std::collections::BTreeSet::new();
    let mut imported_counts = ImportedExternalCounts::default();
    let mut selected_identity_counts = [0_u64; 3];
    let mut selected_identity_groups = BTreeMap::<String, ImportedIdentityGroup>::new();
    let mut profiled_resolutions = BTreeMap::new();
    if let Some(profile) = profile {
        let mut resolution_work = 0_usize;
        for (identity, component) in components {
            resolution_work = resolution_work
                .checked_add(component.versions.len())
                .ok_or(ComparisonError::InvalidDocument)?;
            check(resolution_work <= MAX_WORDPRESS_VERSION_RESOLUTION_WORK)?;
            profiled_resolutions.insert(
                identity.clone(),
                resolve_profiled_component(component, profile)?,
            );
        }
    }
    let mut interpretation_work = 0_usize;
    for value in evaluations {
        let fields = object(value)?;
        if profile.is_some() {
            let exact_identity = schema != WordPressAuditSchema::V6
                || string(fields, "identity_mapping")? == "exact";
            interpretation_work = if exact_identity {
                checked_accumulate_external_interpretation_work(
                    interpretation_work,
                    array(fields, "affected_ranges")?.len(),
                    array(fields, "source_patched_versions")?.len(),
                    MAX_WORDPRESS_EVALUATION_WORK,
                )
                .ok_or(ComparisonError::InvalidDocument)?
            } else {
                interpretation_work
                    .checked_add(array(fields, "affected_ranges")?.len())
                    .filter(|work| *work <= MAX_WORDPRESS_EVALUATION_WORK)
                    .ok_or(ComparisonError::InvalidDocument)?
            };
        }
        let evaluation = external_evaluation(
            fields,
            namespace,
            components,
            &notices_by_id,
            &mut referenced_notices,
            &profiled_resolutions,
            ExternalEvaluationContract {
                schema,
                resource_policy,
                profile,
            },
        )?;
        check(identities.insert(evaluation.identity.clone()))?;
        let identity_count_index = match evaluation.identity_mapping {
            ExternalIdentityMapping::Exact => 0,
            ExternalIdentityMapping::AsciiCaseFoldCandidate => 1,
            ExternalIdentityMapping::AsciiCaseFoldAmbiguous => 2,
        };
        selected_identity_counts[identity_count_index] = selected_identity_counts
            [identity_count_index]
            .checked_add(1)
            .ok_or(ComparisonError::InvalidDocument)?;
        let identity_group = selected_identity_groups
            .entry(evaluation.canonical_identity.clone())
            .or_default();
        identity_group
            .source_spellings
            .insert(evaluation.source_identity.clone());
        identity_group.mappings.push((
            evaluation.identity_mapping,
            evaluation.identity_collision_raw_count,
        ));
        imported_counts.record(&evaluation)?;
    }
    let identity_limitations: &[Value] = if schema == WordPressAuditSchema::V6 {
        array(fields, "identity_limitations")?.as_slice()
    } else {
        &[]
    };
    check(
        identity_limitations.len() <= MAX_WORDFENCE_V3_IDENTITY_LIMITATION_PROJECTIONS as usize
            && u64::try_from(identity_limitations.len()).ok()
                == identity_limitation_projection.or(Some(0)),
    )?;
    for value in identity_limitations {
        let identity = external_identity_limitation(
            object(value)?,
            namespace,
            &notices_by_id,
            &mut referenced_notices,
            resource_policy,
        )?;
        check(identities.insert(identity))?;
    }
    check(referenced_notices == notices_by_id.keys().cloned().collect())?;
    check(
        selected_identity_counts
            .iter()
            .zip(&identity_counts[..3])
            .all(|(selected, total)| selected <= total)
            && selected_identity_counts
                .into_iter()
                .try_fold(0_u64, |total, count| total.checked_add(count))
                == Some(selected),
    )?;
    for group in selected_identity_groups.values() {
        let distinct = u64::try_from(group.source_spellings.len())
            .map_err(|_| ComparisonError::InvalidDocument)?;
        check(
            group
                .mappings
                .iter()
                .all(|(mapping, collision_count)| match mapping {
                    ExternalIdentityMapping::Exact => collision_count.is_none(),
                    ExternalIdentityMapping::AsciiCaseFoldCandidate => {
                        distinct == 1 && collision_count.is_none()
                    },
                    ExternalIdentityMapping::AsciiCaseFoldAmbiguous => {
                        distinct >= 2 && *collision_count == Some(distinct)
                    },
                }),
        )?;
    }
    if profile.is_some() {
        let maximum_selected_ranges = u64::try_from(
            MAX_WORDFENCE_V3_EVALUATIONS
                .checked_mul(resource_policy.ranges())
                .ok_or(ComparisonError::InvalidDocument)?,
        )
        .map_err(|_| ComparisonError::InvalidDocument)?;
        check(
            number(counts, "within_associations", MAX_WORDFENCE_V3_ASSOCIATIONS)?
                == imported_counts.within
                && number(
                    counts,
                    "outside_associations",
                    MAX_WORDFENCE_V3_ASSOCIATIONS,
                )? == imported_counts.outside
                && number(
                    counts,
                    "indeterminate_associations",
                    MAX_WORDFENCE_V3_ASSOCIATIONS,
                )? == imported_counts.indeterminate
                && number(counts, "selected_ranges", maximum_selected_ranges)?
                    == imported_counts.selected_ranges
                && number(counts, "evaluated_ranges", maximum_selected_ranges)?
                    == imported_counts.evaluated_ranges
                && number(counts, "containing_ranges", maximum_selected_ranges)?
                    == imported_counts.containing_ranges
                && number(counts, "noncontaining_ranges", maximum_selected_ranges)?
                    == imported_counts.noncontaining_ranges
                && number(counts, "unsupported_ranges", maximum_selected_ranges)?
                    == imported_counts.unsupported_ranges
                && number(counts, "invalid_ranges", maximum_selected_ranges)?
                    == imported_counts.invalid_ranges
                && number(counts, "not_evaluated_ranges", maximum_selected_ranges)?
                    == imported_counts.not_evaluated_ranges
                && number(
                    counts,
                    "partial_range_coverage_associations",
                    MAX_WORDFENCE_V3_ASSOCIATIONS,
                )? == imported_counts.partial
                && evaluable == imported_counts.within + imported_counts.outside
                && unsupported == imported_counts.indeterminate
                && selected
                    == imported_counts.within
                        + imported_counts.outside
                        + imported_counts.indeterminate
                && imported_counts.evaluated_ranges
                    == imported_counts.containing_ranges + imported_counts.noncontaining_ranges
                && imported_counts.selected_ranges
                    == imported_counts.evaluated_ranges
                        + imported_counts.unsupported_ranges
                        + imported_counts.invalid_ranges
                        + imported_counts.not_evaluated_ranges
                && imported_counts.partial <= imported_counts.within,
        )?;
    }
    Ok(())
}

#[derive(Default)]
struct ImportedExternalCounts {
    within: u64,
    outside: u64,
    indeterminate: u64,
    selected_ranges: u64,
    evaluated_ranges: u64,
    containing_ranges: u64,
    noncontaining_ranges: u64,
    unsupported_ranges: u64,
    invalid_ranges: u64,
    not_evaluated_ranges: u64,
    partial: u64,
}

impl ImportedExternalCounts {
    fn record(&mut self, evaluation: &ImportedExternalEvaluation) -> Result<(), ComparisonError> {
        match evaluation.version_relation {
            "within_supported_range_under_selected_policy" => self.within += 1,
            "outside_declared_ranges_under_selected_policy" => self.outside += 1,
            "indeterminate" => self.indeterminate += 1,
            "source_comparison_semantics_unresolved" => return Ok(()),
            _ => return Err(ComparisonError::InvalidDocument),
        }
        if evaluation.version_relation_reason == Some("containing_range_with_partial_coverage") {
            self.partial += 1;
        }
        self.selected_ranges = self
            .selected_ranges
            .checked_add(evaluation.range_relations.len() as u64)
            .ok_or(ComparisonError::InvalidDocument)?;
        for relation in &evaluation.range_relations {
            match *relation {
                "contains" => {
                    self.containing_ranges += 1;
                    self.evaluated_ranges += 1;
                },
                "does_not_contain" => {
                    self.noncontaining_ranges += 1;
                    self.evaluated_ranges += 1;
                },
                "unsupported" => self.unsupported_ranges += 1,
                "invalid_under_profile" => self.invalid_ranges += 1,
                "not_evaluated" => self.not_evaluated_ranges += 1,
                _ => return Err(ComparisonError::InvalidDocument),
            }
        }
        Ok(())
    }
}

struct ImportedExternalEvaluation {
    identity: String,
    canonical_identity: String,
    source_identity: String,
    identity_mapping: ExternalIdentityMapping,
    identity_collision_raw_count: Option<u64>,
    version_relation: &'static str,
    version_relation_reason: Option<&'static str>,
    range_relations: Vec<&'static str>,
}

fn external_identity_limitation(
    fields: &serde_json::Map<String, Value>,
    namespace: &str,
    notices: &BTreeMap<String, String>,
    referenced_notices: &mut std::collections::BTreeSet<String>,
    resource_policy: ExternalResourcePolicy,
) -> Result<String, ComparisonError> {
    keys(
        fields,
        &[
            "key",
            "identity_resolution",
            "title",
            "display_name",
            "references",
            "record_reference",
            "affected_ranges",
            "range_evaluations",
            "source_patched",
            "source_patched_versions",
            "source_remediation",
            "notice_ids",
            "version_relation",
            "version_relation_reason",
            "applicability",
            "execution",
        ],
        &[],
    )?;
    let key = object(required(fields, "key")?)?;
    keys(
        key,
        &[
            "source_namespace",
            "upstream_id",
            "source_component",
            "source_association_fingerprint",
        ],
        &[],
    )?;
    check(string(key, "source_namespace")? == namespace)?;
    let upstream_id = text(key, "upstream_id", MAX_IDENTIFIER_BYTES)?;
    check(valid_uuid(upstream_id))?;
    let source_component =
        external_raw_source_identity(object(required(key, "source_component")?)?)?;
    let source_association_fingerprint = text(
        key,
        "source_association_fingerprint",
        "wordfence-source-association-sha256:".len() + 64,
    )?;
    check(prefixed_digest(
        source_association_fingerprint,
        "wordfence-source-association-sha256:",
    ))?;
    check(!raw_source_identity_can_map(&source_component))?;
    check(string(fields, "identity_resolution")? == "canonical_identity_unavailable")?;
    external_text(
        text(fields, "title", MAX_WORDFENCE_V3_TITLE_BYTES)?,
        MAX_WORDFENCE_V3_TITLE_BYTES,
        false,
    )?;
    let display_name = external_text(
        text(fields, "display_name", MAX_WORDFENCE_V3_NAME_BYTES)?,
        MAX_WORDFENCE_V3_NAME_BYTES,
        false,
    )?;
    let references = unique_urls(fields, "references", MAX_WORDFENCE_V3_REFERENCES)?;
    let record_reference = optional_text(fields, "record_reference", MAX_LEGACY_AUDIT_TEXT_BYTES)?;
    check(record_reference == external_record_reference(&references))?;

    let ranges = array(fields, "affected_ranges")?;
    let range_evaluations = array(fields, "range_evaluations")?;
    check(ranges.len() <= resource_policy.ranges() && ranges.len() == range_evaluations.len())?;
    let mut unique_ranges = std::collections::BTreeSet::new();
    for (range, evaluated) in ranges.iter().zip(range_evaluations) {
        let range = object(range)?;
        keys(
            range,
            &[
                "label",
                "from_kind",
                "from_version",
                "from_inclusive",
                "to_kind",
                "to_version",
                "to_inclusive",
            ],
            &[],
        )?;
        let label = external_text(text(range, "label", 256)?, 256, false)?;
        let expanded_source_values = resource_policy.expanded();
        external_range_endpoint(range, "from", expanded_source_values)?;
        external_range_endpoint(range, "to", expanded_source_values)?;
        check(unique_ranges.insert(label))?;
        let evaluated = object(evaluated)?;
        keys(evaluated, &["relation", "reason"], &[])?;
        check(
            string(evaluated, "relation")? == "not_evaluated"
                && string(evaluated, "reason")? == "canonical_identity_unavailable",
        )?;
    }

    let source_patched = boolean(fields, "source_patched")?;
    let source_patched_versions = unique_versions(
        fields,
        "source_patched_versions",
        resource_policy.patched_versions(),
        resource_policy.expanded(),
    )?;
    let source_remediation = external_text(
        string(fields, "source_remediation")?,
        MAX_LEGACY_AUDIT_TEXT_BYTES,
        true,
    )?;
    check(
        wordfence_source_association_fingerprint(
            &source_component,
            display_name,
            ranges,
            source_patched,
            &source_patched_versions,
            source_remediation,
        )? == source_association_fingerprint,
    )?;
    let notice_ids = array(fields, "notice_ids")?;
    check(notice_ids.len() <= MAX_WORDFENCE_V3_NOTICE_PARTIES)?;
    let mut local_notices = std::collections::BTreeSet::new();
    for value in notice_ids {
        let id = value.as_str().ok_or(ComparisonError::InvalidDocument)?;
        check(notices.contains_key(id) && local_notices.insert(id))?;
        referenced_notices.insert(id.to_owned());
    }
    let has_defiant_notice = notice_ids.iter().any(|value| {
        value
            .as_str()
            .and_then(|id| notices.get(id))
            .is_some_and(|party| party == "defiant")
    });
    check(
        !has_defiant_notice || record_reference.is_some_and(is_wordfence_vulnerability_reference),
    )?;
    check(
        string(fields, "version_relation")? == "not_evaluated"
            && string(fields, "version_relation_reason")? == "canonical_identity_unavailable"
            && string(fields, "applicability")? == "indeterminate",
    )?;
    let execution = object(required(fields, "execution")?)?;
    keys(execution, &["exploit_execution", "impact_validation"], &[])?;
    check(
        string(execution, "exploit_execution")? == "not_performed"
            && string(execution, "impact_validation")? == "not_performed",
    )?;
    Ok(format!(
        "{namespace}:{upstream_id}:{source_component}:{source_association_fingerprint}"
    ))
}

fn external_source_counts_are_valid(parsed_records: u64, software_associations: u64) -> bool {
    match parsed_records {
        0 => software_associations == 0,
        count => {
            software_associations >= count
                && count
                    .checked_mul(MAX_WORDFENCE_V3_SOFTWARE_PER_RECORD)
                    .is_some_and(|maximum| software_associations <= maximum)
        },
    }
}

fn external_identity_mapping(
    key: &serde_json::Map<String, Value>,
    evaluation: &serde_json::Map<String, Value>,
    canonical_identity: &str,
    source_identity: bool,
) -> Result<(String, ExternalIdentityMapping, Option<u64>), ComparisonError> {
    if !source_identity {
        return Ok((
            canonical_identity.to_owned(),
            ExternalIdentityMapping::Exact,
            None,
        ));
    }

    let source = object(required(key, "source_component")?)?;
    keys(source, &["kind", "slug"], &[])?;
    let source_kind = token(source, "kind", &["core", "plugin", "theme"])?;
    let source_slug = text(source, "slug", MAX_WORDFENCE_V3_SOURCE_SLUG_BYTES)?;
    check(valid_mapped_source_slug(source_slug))?;
    let canonical = canonical_identity
        .split_once(':')
        .ok_or(ComparisonError::InvalidDocument)?;
    let exact = (source_kind, source_slug) == canonical;
    let case_fold = source_kind == canonical.0
        && source_slug != canonical.1
        && source_slug.eq_ignore_ascii_case(canonical.1);
    let (mapping, collision_count) = match token(
        evaluation,
        "identity_mapping",
        &[
            "exact",
            "ascii_case_fold_candidate",
            "ascii_case_fold_ambiguous",
        ],
    )? {
        "exact" => {
            check(exact && !evaluation.contains_key("identity_collision_raw_count"))?;
            (ExternalIdentityMapping::Exact, None)
        },
        "ascii_case_fold_candidate" => {
            check(case_fold && !evaluation.contains_key("identity_collision_raw_count"))?;
            (ExternalIdentityMapping::AsciiCaseFoldCandidate, None)
        },
        "ascii_case_fold_ambiguous" => {
            let count = number(
                evaluation,
                "identity_collision_raw_count",
                MAX_WORDFENCE_V3_ASSOCIATIONS,
            )?;
            check(case_fold && count >= 2)?;
            (ExternalIdentityMapping::AsciiCaseFoldAmbiguous, Some(count))
        },
        _ => return Err(ComparisonError::InvalidDocument),
    };
    Ok((
        format!("{source_kind}:{source_slug}"),
        mapping,
        collision_count,
    ))
}

fn external_raw_source_identity(
    fields: &serde_json::Map<String, Value>,
) -> Result<String, ComparisonError> {
    keys(fields, &["kind", "slug"], &[])?;
    let kind = token(fields, "kind", &["core", "plugin", "theme"])?;
    let slug = text(fields, "slug", MAX_WORDFENCE_V3_SOURCE_SLUG_BYTES)?;
    check(valid_raw_source_slug(slug))?;
    Ok(format!("{kind}:{slug}"))
}

fn valid_mapped_source_slug(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_WORDFENCE_V3_SOURCE_SLUG_BYTES
        || !value.is_ascii()
        || value.starts_with('-')
        || value.ends_with('-')
        || value.contains("--")
    {
        return false;
    }
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn valid_raw_source_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_WORDFENCE_V3_SOURCE_SLUG_BYTES
        && value.is_ascii()
        && !value.bytes().any(|byte| byte.is_ascii_control())
        && value.bytes().any(|byte| byte.is_ascii_alphanumeric())
}

fn raw_source_identity_can_map(value: &str) -> bool {
    let Some((kind, slug)) = value.split_once(':') else {
        return false;
    };
    valid_mapped_source_slug(slug)
        && slug.len() <= MAX_WORDPRESS_COMPONENT_SLUG_BYTES
        && match kind {
            "core" => slug.eq_ignore_ascii_case("wordpress"),
            "plugin" | "theme" => !slug.eq_ignore_ascii_case("wordpress"),
            _ => false,
        }
}

fn external_evaluation(
    fields: &serde_json::Map<String, Value>,
    namespace: &str,
    components: &BTreeMap<String, ImportedWordPressComponent>,
    notices: &std::collections::BTreeMap<String, String>,
    referenced_notices: &mut std::collections::BTreeSet<String>,
    profiled_resolutions: &BTreeMap<String, ProfiledResolution>,
    contract: ExternalEvaluationContract,
) -> Result<ImportedExternalEvaluation, ComparisonError> {
    let ExternalEvaluationContract {
        schema,
        resource_policy,
        profile,
    } = contract;
    let common_fields = [
        "key",
        "title",
        "display_name",
        "informational",
        "description",
        "references",
        "record_reference",
        "cwe",
        "cvss",
        "cve",
        "cve_link",
        "researchers",
        "source_dates",
        "affected_ranges",
        "source_patched",
        "source_patched_versions",
        "source_remediation",
        "notice_ids",
        "component_evidence",
        "version_evidence_resolution",
        "version_relation",
        "applicability",
        "execution",
    ];
    if profile.is_some() && schema == WordPressAuditSchema::V6 {
        keys(
            fields,
            &[
                "key",
                "identity_mapping",
                "title",
                "display_name",
                "informational",
                "description",
                "references",
                "record_reference",
                "cwe",
                "cvss",
                "cve",
                "cve_link",
                "researchers",
                "source_dates",
                "affected_ranges",
                "range_evaluations",
                "source_patched",
                "source_patched_versions",
                "source_remediation",
                "notice_ids",
                "component_evidence",
                "version_evidence_resolution",
                "version_relation",
                "version_relation_reason",
                "applicability",
                "execution",
            ],
            &["identity_collision_raw_count"],
        )?;
    } else if profile.is_some() {
        keys(
            fields,
            &[
                "key",
                "title",
                "display_name",
                "informational",
                "description",
                "references",
                "record_reference",
                "cwe",
                "cvss",
                "cve",
                "cve_link",
                "researchers",
                "source_dates",
                "affected_ranges",
                "range_evaluations",
                "source_patched",
                "source_patched_versions",
                "source_remediation",
                "notice_ids",
                "component_evidence",
                "version_evidence_resolution",
                "version_relation",
                "version_relation_reason",
                "applicability",
                "execution",
            ],
            &[],
        )?;
    } else if schema == WordPressAuditSchema::V6 {
        keys(
            fields,
            &[
                "key",
                "identity_mapping",
                "title",
                "display_name",
                "informational",
                "description",
                "references",
                "record_reference",
                "cwe",
                "cvss",
                "cve",
                "cve_link",
                "researchers",
                "source_dates",
                "affected_ranges",
                "source_patched",
                "source_patched_versions",
                "source_remediation",
                "notice_ids",
                "component_evidence",
                "version_evidence_resolution",
                "version_relation",
                "applicability",
                "execution",
            ],
            &["identity_collision_raw_count"],
        )?;
    } else {
        keys(fields, &common_fields, &[])?;
    }
    let key = object(required(fields, "key")?)?;
    if schema == WordPressAuditSchema::V6 {
        keys(
            key,
            &[
                "source_namespace",
                "upstream_id",
                "component",
                "source_component",
                "source_association_fingerprint",
            ],
            &[],
        )?;
    } else {
        keys(key, &["source_namespace", "upstream_id", "component"], &[])?;
    }
    check(string(key, "source_namespace")? == namespace)?;
    let upstream_id = text(key, "upstream_id", MAX_IDENTIFIER_BYTES)?;
    check(valid_uuid(upstream_id))?;
    let component = component_identity(object(required(key, "component")?)?)?;
    let (source_component, identity_mapping, identity_collision_raw_count) =
        external_identity_mapping(key, fields, &component, schema == WordPressAuditSchema::V6)?;
    let source_association_fingerprint = if schema == WordPressAuditSchema::V6 {
        let fingerprint = text(
            key,
            "source_association_fingerprint",
            "wordfence-source-association-sha256:".len() + 64,
        )?;
        check(prefixed_digest(
            fingerprint,
            "wordfence-source-association-sha256:",
        ))?;
        Some(fingerprint)
    } else {
        None
    };
    let imported = components
        .get(&component)
        .ok_or(ComparisonError::InvalidDocument)?;

    external_text(
        text(fields, "title", MAX_WORDFENCE_V3_TITLE_BYTES)?,
        MAX_WORDFENCE_V3_TITLE_BYTES,
        false,
    )?;
    let display_name = external_text(
        text(fields, "display_name", MAX_WORDFENCE_V3_NAME_BYTES)?,
        MAX_WORDFENCE_V3_NAME_BYTES,
        false,
    )?;
    boolean(fields, "informational")?;
    external_text(
        string(fields, "description")?,
        resource_policy.description_bytes(),
        true,
    )?;
    let references = unique_urls(fields, "references", MAX_WORDFENCE_V3_REFERENCES)?;
    let record_reference = optional_text(fields, "record_reference", MAX_LEGACY_AUDIT_TEXT_BYTES)?;
    let expected_record_reference = external_record_reference(&references);
    check(record_reference == expected_record_reference)?;
    optional_cwe(
        required(fields, "cwe")?,
        resource_policy.description_bytes(),
    )?;
    optional_cvss(required(fields, "cvss")?)?;
    let cve = optional_text(fields, "cve", MAX_WORDFENCE_V3_CVE_BYTES)?;
    if let Some(cve) = cve {
        check(valid_wordfence_cve(cve))?;
    }
    let cve_link = optional_text(fields, "cve_link", MAX_LEGACY_AUDIT_TEXT_BYTES)?;
    if let Some(link) = cve_link {
        check(cve.is_some())?;
        inert_url(link)?;
    }
    text_array(
        fields,
        "researchers",
        MAX_WORDFENCE_V3_RESEARCHERS,
        MAX_WORDFENCE_V3_RESEARCHER_BYTES,
        !resource_policy.expanded(),
    )?;
    let source_dates = object(required(fields, "source_dates")?)?;
    keys(source_dates, &["published", "updated"], &[])?;
    optional_source_datetime(source_dates, "published")?;
    optional_source_datetime(source_dates, "updated")?;

    let ranges = array(fields, "affected_ranges")?;
    check(ranges.len() <= resource_policy.ranges())?;
    let mut unique_ranges = std::collections::BTreeSet::new();
    let mut imported_ranges = Vec::with_capacity(ranges.len());
    for value in ranges {
        let range = object(value)?;
        keys(
            range,
            &[
                "label",
                "from_kind",
                "from_version",
                "from_inclusive",
                "to_kind",
                "to_version",
                "to_inclusive",
            ],
            &[],
        )?;
        let label = external_text(text(range, "label", 256)?, 256, false)?;
        let source_version = resource_policy.expanded();
        let from = external_range_endpoint(range, "from", source_version)?;
        let to = external_range_endpoint(range, "to", source_version)?;
        check(unique_ranges.insert(label))?;
        imported_ranges.push((from, to));
    }

    let source_patched = boolean(fields, "source_patched")?;
    let source_patched_versions = unique_versions(
        fields,
        "source_patched_versions",
        resource_policy.patched_versions(),
        resource_policy.expanded(),
    )?;
    let source_remediation = external_text(
        string(fields, "source_remediation")?,
        MAX_LEGACY_AUDIT_TEXT_BYTES,
        true,
    )?;
    if let Some(fingerprint) = source_association_fingerprint {
        check(
            wordfence_source_association_fingerprint(
                &source_component,
                display_name,
                ranges,
                source_patched,
                &source_patched_versions,
                source_remediation,
            )? == fingerprint,
        )?;
    }
    let evaluation_notice_ids = array(fields, "notice_ids")?;
    check(evaluation_notice_ids.len() <= MAX_WORDFENCE_V3_NOTICE_PARTIES)?;
    let mut local_notices = std::collections::BTreeSet::new();
    for value in evaluation_notice_ids {
        let id = value.as_str().ok_or(ComparisonError::InvalidDocument)?;
        check(notices.contains_key(id) && local_notices.insert(id))?;
        referenced_notices.insert(id.to_owned());
    }
    let has_defiant_notice = evaluation_notice_ids.iter().any(|value| {
        value
            .as_str()
            .and_then(|id| notices.get(id))
            .is_some_and(|party| party == "defiant")
    });
    check(
        !has_defiant_notice || record_reference.is_some_and(is_wordfence_vulnerability_reference),
    )?;
    check(
        token(
            fields,
            "component_evidence",
            &[
                "observed_hint",
                "operator_supplied",
                "conflicting",
                "unknown",
            ],
        )? == imported.evidence_class.as_str(),
    )?;
    let semantic_profile = profile.filter(|_| identity_mapping == ExternalIdentityMapping::Exact);
    let semantic_resolution = external_version_evidence_resolution(
        object(required(fields, "version_evidence_resolution")?)?,
        imported,
        semantic_profile,
        semantic_profile.and_then(|_| profiled_resolutions.get(&component)),
    )?;
    let (version_relation, version_relation_reason, range_relations) = if let Some(profile) =
        profile
    {
        let rendered_ranges = array(fields, "range_evaluations")?;
        check(rendered_ranges.len() == imported_ranges.len())?;
        let mut range_relations = Vec::with_capacity(rendered_ranges.len());
        let mut range_reasons = Vec::with_capacity(rendered_ranges.len());
        let identity_limit_reason = match identity_mapping {
            ExternalIdentityMapping::Exact => None,
            ExternalIdentityMapping::AsciiCaseFoldCandidate => Some("identity_mapping_candidate"),
            ExternalIdentityMapping::AsciiCaseFoldAmbiguous => Some("identity_mapping_ambiguous"),
        };
        for (rendered, source) in rendered_ranges.iter().zip(&imported_ranges) {
            let rendered = object(rendered)?;
            keys(rendered, &["relation", "reason"], &[])?;
            let relation = token(
                rendered,
                "relation",
                &[
                    "contains",
                    "does_not_contain",
                    "not_evaluated",
                    "unsupported",
                    "invalid_under_profile",
                ],
            )?;
            let reason = token(
                rendered,
                "reason",
                &[
                    "selected_version_within_bounds",
                    "selected_version_outside_bounds",
                    "missing_version_evidence",
                    "conflicting_version_evidence",
                    "unsupported_version_evidence",
                    "unsupported_lower_bound",
                    "unsupported_upper_bound",
                    "unsupported_both_bounds",
                    "reversed_bounds",
                    "empty_exclusive_interval",
                    "identity_mapping_candidate",
                    "identity_mapping_ambiguous",
                ],
            )?;
            let expected = if let Some(reason) = identity_limit_reason {
                ("not_evaluated", reason)
            } else {
                external_profiled_range_result(
                    source.0,
                    source.1,
                    profile,
                    semantic_resolution
                        .as_ref()
                        .ok_or(ComparisonError::InvalidDocument)?,
                )?
            };
            check((relation, reason) == expected)?;
            range_relations.push(expected.0);
            range_reasons.push(expected.1);
        }
        let relation = token(
            fields,
            "version_relation",
            &[
                "within_supported_range_under_selected_policy",
                "outside_declared_ranges_under_selected_policy",
                "indeterminate",
            ],
        )?;
        let reason = token(
            fields,
            "version_relation_reason",
            &[
                "containing_range",
                "containing_range_with_partial_coverage",
                "all_ranges_outside",
                "missing_version_evidence",
                "conflicting_version_evidence",
                "unsupported_version_evidence",
                "missing_affected_ranges",
                "unsupported_affected_range",
                "invalid_affected_range",
                "source_patched_version_within_affected_range",
                "identity_mapping_candidate",
                "identity_mapping_ambiguous",
            ],
        )?;
        let applicability = token(
            fields,
            "applicability",
            &[
                "version_match_under_selected_policy",
                "no_version_match_under_selected_policy",
                "indeterminate",
            ],
        )?;
        let expected = if let Some(reason) = identity_limit_reason {
            ("indeterminate", reason, "indeterminate")
        } else {
            expected_external_association_result(
                semantic_resolution
                    .as_ref()
                    .ok_or(ComparisonError::InvalidDocument)?,
                &range_relations,
                &range_reasons,
                external_patched_version_conflicts(
                    &source_patched_versions,
                    &imported_ranges,
                    profile,
                )?,
            )?
        };
        check((relation, reason, applicability) == expected)?;
        (expected.0, Some(expected.1), range_relations)
    } else {
        check(
            string(fields, "version_relation")? == "source_comparison_semantics_unresolved"
                && string(fields, "applicability")? == "indeterminate_unsupported",
        )?;
        ("source_comparison_semantics_unresolved", None, Vec::new())
    };
    let execution = object(required(fields, "execution")?)?;
    keys(execution, &["exploit_execution", "impact_validation"], &[])?;
    check(
        string(execution, "exploit_execution")? == "not_performed"
            && string(execution, "impact_validation")? == "not_performed",
    )?;
    Ok(ImportedExternalEvaluation {
        identity: format!(
            "{namespace}:{upstream_id}:{source_component}:{}",
            source_association_fingerprint.unwrap_or("")
        ),
        canonical_identity: component,
        source_identity: source_component,
        identity_mapping,
        identity_collision_raw_count,
        version_relation,
        version_relation_reason,
        range_relations,
    })
}

fn external_version_evidence_resolution(
    fields: &serde_json::Map<String, Value>,
    component: &ImportedWordPressComponent,
    profile: Option<WordPressComparisonProfile>,
    precomputed: Option<&ProfiledResolution>,
) -> Result<Option<ProfiledResolution>, ComparisonError> {
    if profile.is_some() {
        keys(
            fields,
            &[
                "status",
                "evidence_row_count",
                "distinct_spelling_count",
                "semantic_status",
                "semantic_reason",
            ],
            &[],
        )?;
    } else {
        keys(
            fields,
            &["status", "evidence_row_count", "distinct_spelling_count"],
            &[],
        )?;
    }
    let status = token(
        fields,
        "status",
        &[
            "missing",
            "single_declaration",
            "repeated_exact_declaration",
            "multiple_distinct_declarations",
        ],
    )?;
    let evidence_row_count = number(
        fields,
        "evidence_row_count",
        MAX_WORDPRESS_RESULT_VERSION_EVIDENCE as u64,
    )?;
    let distinct_spelling_count = number(
        fields,
        "distinct_spelling_count",
        MAX_WORDPRESS_RESULT_VERSION_EVIDENCE as u64,
    )?;
    let actual_distinct = component
        .versions
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let expected_status = match (component.versions.len(), actual_distinct) {
        (0, 0) => "missing",
        (1, 1) => "single_declaration",
        (count, 1) if count > 1 => "repeated_exact_declaration",
        (count, distinct) if count > 1 && distinct > 1 => "multiple_distinct_declarations",
        _ => return Err(ComparisonError::InvalidDocument),
    };
    check(
        u64::try_from(component.versions.len()).ok() == Some(evidence_row_count)
            && u64::try_from(actual_distinct).ok() == Some(distinct_spelling_count)
            && status == expected_status,
    )?;
    if profile.is_none() {
        check(precomputed.is_none())?;
        return Ok(None);
    }
    let resolution = precomputed.ok_or(ComparisonError::InvalidDocument)?;
    check(
        token(
            fields,
            "semantic_status",
            &[
                "missing",
                "supported_equivalent",
                "conflicting",
                "unsupported",
            ],
        )? == resolution.status
            && token(
                fields,
                "semantic_reason",
                &[
                    "no_version_evidence",
                    "single_supported_version",
                    "equivalent_supported_versions",
                    "conflicting_version_evidence",
                    "unsupported_version_evidence",
                ],
            )? == resolution.reason,
    )?;
    Ok(Some(resolution.clone()))
}

fn external_profiled_range_result(
    from: (&str, &str, bool),
    to: (&str, &str, bool),
    profile: WordPressComparisonProfile,
    resolution: &ProfiledResolution,
) -> Result<(&'static str, &'static str), ComparisonError> {
    let lower = external_profiled_endpoint(from, profile);
    let upper = external_profiled_endpoint(to, profile);
    let (lower, upper) = match (lower, upper) {
        (Err(()), Err(())) => return Ok(("unsupported", "unsupported_both_bounds")),
        (Err(()), Ok(_)) => return Ok(("unsupported", "unsupported_lower_bound")),
        (Ok(_), Err(())) => return Ok(("unsupported", "unsupported_upper_bound")),
        (Ok(lower), Ok(upper)) => (lower, upper),
    };
    if let (Some((lower_version, lower_inclusive)), Some((upper_version, upper_inclusive))) =
        (&lower, &upper)
    {
        match profiled_compare(lower_version, upper_version)? {
            Ordering::Greater => return Ok(("invalid_under_profile", "reversed_bounds")),
            Ordering::Equal if !(*lower_inclusive && *upper_inclusive) => {
                return Ok(("invalid_under_profile", "empty_exclusive_interval"));
            },
            Ordering::Less | Ordering::Equal => {},
        }
    }
    let Some(version) = resolution.selected.as_ref() else {
        let reason = match resolution.status {
            "missing" => "missing_version_evidence",
            "conflicting" => "conflicting_version_evidence",
            "unsupported" => "unsupported_version_evidence",
            _ => return Err(ComparisonError::InvalidDocument),
        };
        return Ok(("not_evaluated", reason));
    };
    let above_lower = match &lower {
        None => true,
        Some((bound, inclusive)) => match profiled_compare(version, bound)? {
            Ordering::Greater => true,
            Ordering::Equal => *inclusive,
            Ordering::Less => false,
        },
    };
    let below_upper = match &upper {
        None => true,
        Some((bound, inclusive)) => match profiled_compare(version, bound)? {
            Ordering::Less => true,
            Ordering::Equal => *inclusive,
            Ordering::Greater => false,
        },
    };
    if above_lower && below_upper {
        Ok(("contains", "selected_version_within_bounds"))
    } else {
        Ok(("does_not_contain", "selected_version_outside_bounds"))
    }
}

fn external_profiled_endpoint(
    endpoint: (&str, &str, bool),
    profile: WordPressComparisonProfile,
) -> Result<Option<(ProfiledVersionKey, bool)>, ()> {
    match endpoint {
        ("any", "*", _) => Ok(None),
        ("declared", value, inclusive) => ProfiledVersionKey::parse(profile, value)
            .map(|version| Some((version, inclusive)))
            .map_err(|_| ()),
        _ => Err(()),
    }
}

fn external_patched_version_conflicts(
    patched_versions: &[&str],
    ranges: &[ImportedExternalRange<'_>],
    profile: WordPressComparisonProfile,
) -> Result<bool, ComparisonError> {
    for declared in patched_versions {
        let Ok(selected) = ProfiledVersionKey::parse(profile, declared) else {
            continue;
        };
        let resolution = ProfiledResolution {
            status: "supported_equivalent",
            reason: "single_supported_version",
            selected: Some(selected),
        };
        for (from, to) in ranges {
            if external_profiled_range_result(*from, *to, profile, &resolution)?.0 == "contains" {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn expected_external_association_result(
    resolution: &ProfiledResolution,
    range_relations: &[&str],
    range_reasons: &[&str],
    source_patched_version_conflict: bool,
) -> Result<(&'static str, &'static str, &'static str), ComparisonError> {
    check(range_relations.len() == range_reasons.len())?;
    let has_invalid = range_relations.contains(&"invalid_under_profile");
    let has_unsupported = range_relations.contains(&"unsupported");
    let has_containing = range_relations.contains(&"contains");
    let all_outside = !range_relations.is_empty()
        && range_relations
            .iter()
            .all(|relation| *relation == "does_not_contain");
    if has_invalid {
        return Ok(("indeterminate", "invalid_affected_range", "indeterminate"));
    }
    if source_patched_version_conflict {
        return Ok((
            "indeterminate",
            "source_patched_version_within_affected_range",
            "indeterminate",
        ));
    }
    match resolution.status {
        "missing" => Ok(("indeterminate", "missing_version_evidence", "indeterminate")),
        "conflicting" => Ok((
            "indeterminate",
            "conflicting_version_evidence",
            "indeterminate",
        )),
        "unsupported" => Ok((
            "indeterminate",
            "unsupported_version_evidence",
            "indeterminate",
        )),
        "supported_equivalent" if range_relations.is_empty() => {
            Ok(("indeterminate", "missing_affected_ranges", "indeterminate"))
        },
        "supported_equivalent" if has_containing => Ok((
            "within_supported_range_under_selected_policy",
            if has_unsupported {
                "containing_range_with_partial_coverage"
            } else {
                "containing_range"
            },
            "version_match_under_selected_policy",
        )),
        "supported_equivalent" if has_unsupported => Ok((
            "indeterminate",
            "unsupported_affected_range",
            "indeterminate",
        )),
        "supported_equivalent" if all_outside => Ok((
            "outside_declared_ranges_under_selected_policy",
            "all_ranges_outside",
            "no_version_match_under_selected_policy",
        )),
        _ => Err(ComparisonError::InvalidDocument),
    }
}

fn external_range_endpoint<'a>(
    fields: &'a serde_json::Map<String, Value>,
    prefix: &str,
    source_version: bool,
) -> Result<ImportedExternalRangeEndpoint<'a>, ComparisonError> {
    let kind_name = format!("{prefix}_kind");
    let version_name = format!("{prefix}_version");
    let inclusive_name = format!("{prefix}_inclusive");
    let kind = fields
        .get(&kind_name)
        .and_then(Value::as_str)
        .ok_or(ComparisonError::InvalidDocument)?;
    let version = fields
        .get(&version_name)
        .and_then(Value::as_str)
        .ok_or(ComparisonError::InvalidDocument)?;
    let inclusive = fields
        .get(&inclusive_name)
        .and_then(Value::as_bool)
        .ok_or(ComparisonError::InvalidDocument)?;
    check(matches!(kind, "any" | "declared"))?;
    check(
        (kind == "any" && version == "*")
            || (kind == "declared"
                && if source_version {
                    valid_external_source_version(version)
                } else {
                    valid_external_version(version)
                }),
    )?;
    Ok((kind, version, inclusive))
}

fn optional_cwe(value: &Value, description_limit: usize) -> Result<(), ComparisonError> {
    if value.is_null() {
        return Ok(());
    }
    let fields = object(value)?;
    keys(fields, &["id", "name", "description"], &[])?;
    check(number(fields, "id", u32::MAX.into())? > 0)?;
    external_text(
        text(fields, "name", MAX_WORDFENCE_V3_NAME_BYTES)?,
        MAX_WORDFENCE_V3_NAME_BYTES,
        false,
    )?;
    external_text(string(fields, "description")?, description_limit, true)?;
    Ok(())
}

fn optional_cvss(value: &Value) -> Result<(), ComparisonError> {
    if value.is_null() {
        return Ok(());
    }
    let fields = object(value)?;
    keys(fields, &["vector", "score", "rating"], &[])?;
    let vector = external_text(text(fields, "vector", 256)?, 256, false)?;
    check(vector.starts_with("CVSS:3.0/") || vector.starts_with("CVSS:3.1/"))?;
    check(valid_cvss_score(string(fields, "score")?))?;
    token(
        fields,
        "rating",
        &["none", "low", "medium", "high", "critical"],
    )?;
    Ok(())
}

fn unique_urls<'a>(
    fields: &'a serde_json::Map<String, Value>,
    name: &str,
    limit: usize,
) -> Result<std::collections::BTreeSet<&'a str>, ComparisonError> {
    let values = array(fields, name)?;
    check(values.len() <= limit)?;
    let mut unique = std::collections::BTreeSet::new();
    for value in values {
        let value = value.as_str().ok_or(ComparisonError::InvalidDocument)?;
        inert_url(value)?;
        check(unique.insert(value))?;
    }
    Ok(unique)
}

fn external_record_reference<'a>(
    references: &'a std::collections::BTreeSet<&str>,
) -> Option<&'a str> {
    references
        .iter()
        .copied()
        .filter(|reference| is_wordfence_vulnerability_reference(reference))
        .min()
        .or_else(|| {
            references
                .iter()
                .copied()
                .filter(|reference| is_strict_https_reference(reference))
                .min()
        })
}

fn is_strict_https_reference(value: &str) -> bool {
    url::Url::parse(value).ok().is_some_and(|url| {
        url.scheme() == "https"
            && url.has_host()
            && url.username().is_empty()
            && url.password().is_none()
            && url.port().is_none()
            && url.as_str() == value
    })
}

fn is_wordfence_vulnerability_reference(value: &str) -> bool {
    const PREFIX: &str = "/threat-intel/vulnerabilities/";
    url::Url::parse(value).ok().is_some_and(|url| {
        matches!(url.scheme(), "http" | "https")
            && url.host_str() == Some("www.wordfence.com")
            && url.username().is_empty()
            && url.password().is_none()
            && url.port().is_none()
            && url.as_str() == value
            && url.path().starts_with(PREFIX)
            && url.path().len() > PREFIX.len()
            && has_supported_wordfence_reference_query(&url)
            && url.fragment().is_none()
    })
}

fn has_supported_wordfence_reference_query(url: &url::Url) -> bool {
    const MAX_SOURCE_VALUE_BYTES: usize = 64;
    // Saved audits retain the importer's exact, deliberately narrow URL form.
    match url.query() {
        None => true,
        Some(query) => query.strip_prefix("source=").is_some_and(|value| {
            !value.is_empty()
                && value.len() <= MAX_SOURCE_VALUE_BYTES
                && value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
                })
        }),
    }
}

fn text_array(
    fields: &serde_json::Map<String, Value>,
    name: &str,
    limit: usize,
    text_limit: usize,
    require_unique: bool,
) -> Result<(), ComparisonError> {
    let values = array(fields, name)?;
    check(values.len() <= limit)?;
    let mut unique = std::collections::BTreeSet::new();
    for value in values {
        let value = value.as_str().ok_or(ComparisonError::InvalidDocument)?;
        external_text(value, text_limit, false)?;
        check(!require_unique || unique.insert(value))?;
    }
    Ok(())
}

fn unique_versions<'a>(
    fields: &'a serde_json::Map<String, Value>,
    name: &str,
    limit: usize,
    source_version: bool,
) -> Result<Vec<&'a str>, ComparisonError> {
    let values = array(fields, name)?;
    check(values.len() <= limit)?;
    let mut unique = std::collections::BTreeSet::new();
    let mut validated = Vec::with_capacity(values.len());
    for value in values {
        let value = value.as_str().ok_or(ComparisonError::InvalidDocument)?;
        check(
            (if source_version {
                valid_external_source_version(value)
            } else {
                valid_external_version(value)
            }) && unique.insert(value),
        )?;
        validated.push(value);
    }
    Ok(validated)
}

fn optional_source_datetime(
    fields: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<(), ComparisonError> {
    let value = required(fields, name)?;
    if value.is_null() {
        return Ok(());
    }
    source_datetime(value.as_str().ok_or(ComparisonError::InvalidDocument)?)
}

fn source_datetime(value: &str) -> Result<(), ComparisonError> {
    let bytes = value.as_bytes();
    check(
        bytes.len() == 19
            && bytes[4] == b'-'
            && bytes[7] == b'-'
            && bytes[10] == b' '
            && bytes[13] == b':'
            && bytes[16] == b':'
            && bytes.iter().enumerate().all(|(index, byte)| {
                matches!(index, 4 | 7 | 10 | 13 | 16) || byte.is_ascii_digit()
            }),
    )?;
    date(&value[..10])?;
    check(
        decimal(&bytes[11..13])? <= 23
            && decimal(&bytes[14..16])? <= 59
            && decimal(&bytes[17..19])? <= 59,
    )
}

fn inert_url(value: &str) -> Result<(), ComparisonError> {
    bounded_text(value, MAX_LEGACY_AUDIT_TEXT_BYTES)?;
    let url = url::Url::parse(value).map_err(|_| ComparisonError::InvalidDocument)?;
    check(
        matches!(url.scheme(), "http" | "https")
            && url.has_host()
            && url.username().is_empty()
            && url.password().is_none(),
    )
}

fn external_text(value: &str, maximum: usize, allow_empty: bool) -> Result<&str, ComparisonError> {
    check(
        (allow_empty || !value.is_empty())
            && value.len() <= maximum
            && !value.chars().any(|character| {
                character.is_control() && !matches!(character, '\n' | '\r' | '\t')
            }),
    )?;
    Ok(value)
}

fn valid_external_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn wordfence_notice_id(
    message: &str,
    party: &str,
    notice: &str,
    license: &str,
    license_url: &str,
) -> Option<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"termivar.wordfence-v3.notice/v1\0");
    for value in [message, party, notice, license, license_url] {
        hasher.update(u64::try_from(value.len()).ok()?.to_be_bytes());
        hasher.update(value.as_bytes());
    }
    let digest = hasher.finalize();
    Some(format!("wordfence-notice-sha256:{digest:x}"))
}

fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

fn valid_wordfence_cve(value: &str) -> bool {
    if value.len() > MAX_WORDFENCE_V3_CVE_BYTES {
        return false;
    }
    let mut parts = value.split('-');
    parts.next() == Some("CVE")
        && parts
            .next()
            .is_some_and(|year| year.len() == 4 && year.bytes().all(|byte| byte.is_ascii_digit()))
        && parts
            .next()
            .is_some_and(|id| id.len() >= 4 && id.bytes().all(|byte| byte.is_ascii_digit()))
        && parts.next().is_none()
}

fn valid_external_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_WORDPRESS_INVENTORY_VERSION_BYTES
        && value != "*"
        && value.is_ascii()
        && !value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

fn valid_external_source_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_WORDPRESS_INVENTORY_VERSION_BYTES
        && value != "*"
        && !value.chars().any(char::is_control)
        && !value.chars().next().is_some_and(char::is_whitespace)
        && !value.chars().next_back().is_some_and(char::is_whitespace)
}

fn wordfence_source_association_fingerprint(
    source_component: &str,
    display_name: &str,
    affected_ranges: &[Value],
    source_patched: bool,
    source_patched_versions: &[&str],
    source_remediation: &str,
) -> Result<String, ComparisonError> {
    let (kind, slug) = source_component
        .split_once(':')
        .ok_or(ComparisonError::InvalidDocument)?;
    let kind = match kind {
        "core" => 0_u8,
        "plugin" => 1_u8,
        "theme" => 2_u8,
        _ => return Err(ComparisonError::InvalidDocument),
    };

    let mut hasher = Sha256::new();
    hasher.update(b"termivar.wordfence-v3.source-association/v1\0");
    hasher.update([kind]);
    hash_wordfence_frame(&mut hasher, slug)?;
    hash_wordfence_frame(&mut hasher, display_name)?;
    let mut sorted_ranges = affected_ranges.iter().collect::<Vec<_>>();
    sorted_ranges.sort_by(|left, right| {
        let left = left.as_object().and_then(|fields| fields.get("label"));
        let right = right.as_object().and_then(|fields| fields.get("label"));
        left.and_then(Value::as_str)
            .cmp(&right.and_then(Value::as_str))
    });
    hash_wordfence_count(&mut hasher, sorted_ranges.len())?;
    for range in sorted_ranges {
        let range = object(range)?;
        hash_wordfence_frame(&mut hasher, string(range, "label")?)?;
        hash_wordfence_frame(&mut hasher, string(range, "from_version")?)?;
        hasher.update([u8::from(boolean(range, "from_inclusive")?)]);
        hash_wordfence_frame(&mut hasher, string(range, "to_version")?)?;
        hasher.update([u8::from(boolean(range, "to_inclusive")?)]);
    }
    hasher.update([u8::from(source_patched)]);
    let mut sorted_patched_versions = source_patched_versions.to_vec();
    sorted_patched_versions.sort_unstable();
    hash_wordfence_count(&mut hasher, sorted_patched_versions.len())?;
    for version in sorted_patched_versions {
        hash_wordfence_frame(&mut hasher, version)?;
    }
    hash_wordfence_frame(&mut hasher, source_remediation)?;
    let digest = hasher.finalize();
    Ok(format!("wordfence-source-association-sha256:{digest:x}"))
}

fn hash_wordfence_frame(hasher: &mut Sha256, value: &str) -> Result<(), ComparisonError> {
    hasher.update(
        u64::try_from(value.len())
            .map_err(|_| ComparisonError::InvalidDocument)?
            .to_be_bytes(),
    );
    hasher.update(value.as_bytes());
    Ok(())
}

fn hash_wordfence_count(hasher: &mut Sha256, count: usize) -> Result<(), ComparisonError> {
    hasher.update(
        u64::try_from(count)
            .map_err(|_| ComparisonError::InvalidDocument)?
            .to_be_bytes(),
    );
    Ok(())
}

fn valid_cvss_score(value: &str) -> bool {
    let mut parts = value.split('.');
    let Some(integer) = parts.next() else {
        return false;
    };
    let fraction = parts.next();
    if parts.next().is_some()
        || integer.is_empty()
        || !integer.bytes().all(|byte| byte.is_ascii_digit())
        || (integer.len() > 1 && integer.starts_with('0'))
        || fraction.is_some_and(|value| {
            value.len() != 1 || !value.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return false;
    }
    match integer.parse::<u8>() {
        Ok(0..=9) => true,
        Ok(10) => fraction.is_none_or(|value| value == "0"),
        _ => false,
    }
}

fn prefixed_digest(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|digest| digest.len() == 64 && digest.bytes().all(is_lowercase_hex))
}

fn is_lowercase_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn legacy_component_evidence(
    versions: &[String],
    source_evidence: &'static str,
) -> Result<&'static str, ComparisonError> {
    let mut supported = std::collections::BTreeSet::new();
    let mut unsupported = std::collections::BTreeSet::new();
    for version in versions {
        match numeric_components(version) {
            Ok(version) => {
                supported.insert(version);
            },
            Err(ComparisonError::InvalidDocument) => {
                unsupported.insert(version.as_str());
            },
            Err(error) => return Err(error),
        }
    }
    if supported.len() > 1
        || unsupported.len() > 1
        || (!supported.is_empty() && !unsupported.is_empty())
    {
        Ok("conflicting")
    } else {
        Ok(source_evidence)
    }
}

fn inventory_import(
    fields: &serde_json::Map<String, Value>,
    components: &BTreeMap<String, ImportedWordPressComponent>,
) -> Result<(), ComparisonError> {
    keys(
        fields,
        &["coverage", "component_count", "limitations", "inputs"],
        &[],
    )?;
    let coverage = object(required(fields, "coverage")?)?;
    keys(coverage, &["core", "plugins", "themes"], &[])?;
    let core = token(coverage, "core", &["supplied", "not_supplied"])?;
    let plugins = token(coverage, "plugins", &["supplied", "not_supplied"])?;
    let themes = token(coverage, "themes", &["supplied", "not_supplied"])?;

    let inputs = array(fields, "inputs")?;
    check(!inputs.is_empty() && inputs.len() <= MAX_WORDPRESS_INVENTORY_INPUTS)?;
    let mut classes = std::collections::BTreeSet::new();
    let mut total_bytes = 0_u64;
    for value in inputs {
        let input = object(value)?;
        keys(input, &["class", "byte_length", "sha256"], &[])?;
        let class = token(
            input,
            "class",
            &[
                "wp_cli_plugins_json",
                "wp_cli_themes_json",
                "wp_cli_core_version_file",
            ],
        )?;
        check(classes.insert(class))?;
        let byte_length = number(input, "byte_length", MAX_WORDPRESS_SAVED_INVENTORY_BYTES)?;
        check(byte_length > 0)?;
        if class == "wp_cli_core_version_file" {
            check(byte_length <= (MAX_WORDPRESS_INVENTORY_VERSION_BYTES + 2) as u64)?;
        }
        check(digest(string(input, "sha256")?, ""))?;
        total_bytes = total_bytes
            .checked_add(byte_length)
            .ok_or(ComparisonError::InvalidDocument)?;
        check(total_bytes <= MAX_WORDPRESS_SAVED_INVENTORY_BYTES)?;
    }
    check((core == "supplied") == classes.contains("wp_cli_core_version_file"))?;
    check((plugins == "supplied") == classes.contains("wp_cli_plugins_json"))?;
    check((themes == "supplied") == classes.contains("wp_cli_themes_json"))?;

    for (identity, component) in components {
        check(component.operator_source == component.inventory_component)?;
        if component.inventory_component {
            let category_supplied = if identity == "core:wordpress" {
                core == "supplied"
            } else if identity.starts_with("plugin:") {
                plugins == "supplied"
            } else if identity.starts_with("theme:") {
                themes == "supplied"
            } else {
                false
            };
            check(category_supplied)?;
        }
    }

    let inventory_component_count = components
        .values()
        .filter(|component| component.inventory_component)
        .count();
    check(
        number(
            fields,
            "component_count",
            MAX_WORDPRESS_CONTEXT_COMPONENTS as u64,
        )? == inventory_component_count as u64,
    )?;

    let limitations = array(fields, "limitations")?;
    check(
        inventory_component_count
            .checked_add(limitations.len())
            .is_some_and(|count| count <= MAX_WORDPRESS_CONTEXT_COMPONENTS),
    )?;
    let mut limitation_names = std::collections::BTreeSet::new();
    for value in limitations {
        let limitation = object(value)?;
        keys(
            limitation,
            &["declared_name", "status", "reason"],
            &["version"],
        )?;
        check(plugins == "supplied")?;
        let name = text(
            limitation,
            "declared_name",
            MAX_WORDPRESS_INVENTORY_LABEL_BYTES,
        )?;
        check(valid_inventory_label(name) && limitation_names.insert(name))?;
        if let Some(version) = limitation.get("version") {
            let version = version.as_str().ok_or(ComparisonError::InvalidDocument)?;
            check(valid_inventory_version(version))?;
        }
        check(token(limitation, "status", &["drop_in"])? == "drop_in")?;
        check(
            token(
                limitation,
                "reason",
                &["drop_in_identity_is_not_catalog_slug"],
            )? == "drop_in_identity_is_not_catalog_slug",
        )?;
    }
    Ok(())
}

fn valid_inventory_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_WORDPRESS_INVENTORY_LABEL_BYTES
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_inventory_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_WORDPRESS_INVENTORY_VERSION_BYTES
        && !value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

fn component_identity(fields: &serde_json::Map<String, Value>) -> Result<String, ComparisonError> {
    keys(fields, &["kind", "slug"], &[])?;
    let kind = token(fields, "kind", &["core", "plugin", "theme"])?;
    let slug = text(fields, "slug", 64)?;
    check(valid_slug(slug) && ((kind == "core") == (slug == "wordpress")))?;
    Ok(format!("{kind}:{slug}"))
}

fn advisory_v1(fields: &serde_json::Map<String, Value>) -> Result<String, ComparisonError> {
    keys(
        fields,
        &[
            "id",
            "component",
            "source",
            "cve",
            "summary",
            "affected_ranges",
            "fixed_versions",
            "prerequisites",
            "remediation",
            "component_evidence",
            "version_relation",
            "applicability",
            "exploit_execution",
            "impact_validation",
        ],
        &[],
    )?;
    let id = text(fields, "id", MAX_IDENTIFIER_BYTES)?;
    identifier(id)?;
    component_identity(object(required(fields, "component")?)?)?;
    advisory_source(object(required(fields, "source")?)?)?;
    if let Some(cve) = optional_text(fields, "cve", MAX_IDENTIFIER_BYTES)? {
        check(valid_cve(cve))?;
    }
    bounded_text(text(fields, "summary", 1_024)?, 1_024)?;
    if let Some(remediation) = optional_text(fields, "remediation", MAX_LEGACY_AUDIT_TEXT_BYTES)? {
        bounded_text(remediation, MAX_LEGACY_AUDIT_TEXT_BYTES)?;
    }

    let ranges = array(fields, "affected_ranges")?;
    check(ranges.len() <= MAX_WORDPRESS_RANGES)?;
    for value in ranges {
        affected_range_v1(object(value)?)?;
    }
    let fixed_versions = array(fields, "fixed_versions")?;
    check(fixed_versions.len() <= MAX_WORDPRESS_FIXED_VERSIONS)?;
    let mut fixed = std::collections::BTreeSet::new();
    for value in fixed_versions {
        let value = value.as_str().ok_or(ComparisonError::InvalidDocument)?;
        check(fixed.insert(numeric_components(value)?))?;
    }
    let prerequisites = array(fields, "prerequisites")?;
    check(prerequisites.len() <= MAX_WORDPRESS_PREREQUISITES)?;
    let mut prerequisite_outcomes = Vec::with_capacity(prerequisites.len());
    for value in prerequisites {
        prerequisite_outcomes.push(prerequisite(object(value)?)?.outcome);
    }
    let component_evidence = token(
        fields,
        "component_evidence",
        &[
            "observed_hint",
            "operator_supplied",
            "conflicting",
            "unknown",
        ],
    )?;
    let version_relation = token(
        fields,
        "version_relation",
        &[
            "within_declared_range",
            "outside_declared_ranges",
            "unknown",
            "unsupported",
        ],
    )?;
    let applicability = token(
        fields,
        "applicability",
        &[
            "candidate_match_on_declared_facts",
            "contradicted_by_declared_facts",
            "indeterminate_missing_evidence",
            "indeterminate_unsupported",
        ],
    )?;
    let expected_applicability = if version_relation == "outside_declared_ranges"
        || prerequisite_outcomes.contains(&"contradicted_on_supplied_facts")
    {
        "contradicted_by_declared_facts"
    } else if version_relation == "unsupported" || prerequisite_outcomes.contains(&"unsupported") {
        "indeterminate_unsupported"
    } else if matches!(component_evidence, "unknown" | "conflicting")
        || version_relation == "unknown"
        || prerequisite_outcomes.contains(&"unknown")
    {
        "indeterminate_missing_evidence"
    } else {
        "candidate_match_on_declared_facts"
    };
    check(applicability == expected_applicability)?;
    check(
        string(fields, "exploit_execution")? == "not_performed"
            && string(fields, "impact_validation")? == "not_performed",
    )?;
    Ok(id.to_owned())
}

fn advisory_v2(
    fields: &serde_json::Map<String, Value>,
    components: &BTreeMap<String, ImportedWordPressComponent>,
    resolutions: &BTreeMap<(String, WordPressComparisonProfile), ProfiledResolution>,
) -> Result<String, ComparisonError> {
    keys(
        fields,
        &[
            "id",
            "component",
            "source",
            "cve",
            "summary",
            "affected_ranges",
            "fixed_versions",
            "prerequisites",
            "remediation",
            "comparison_profile",
            "version_resolution",
            "version_resolution_reason",
            "component_evidence",
            "version_relation",
            "applicability",
            "exploit_execution",
            "impact_validation",
        ],
        &[],
    )?;
    let id = text(fields, "id", MAX_IDENTIFIER_BYTES)?;
    identifier(id)?;
    let component_identity = component_identity(object(required(fields, "component")?)?)?;
    advisory_source(object(required(fields, "source")?)?)?;
    if let Some(cve) = optional_text(fields, "cve", MAX_IDENTIFIER_BYTES)? {
        check(valid_cve(cve))?;
    }
    bounded_text(text(fields, "summary", 1_024)?, 1_024)?;
    if let Some(remediation) = optional_text(fields, "remediation", MAX_LEGACY_AUDIT_TEXT_BYTES)? {
        bounded_text(remediation, MAX_LEGACY_AUDIT_TEXT_BYTES)?;
    }

    let profile = WordPressComparisonProfile::parse(string(fields, "comparison_profile")?)
        .map_err(|_| ComparisonError::InvalidDocument)?;
    let ranges = array(fields, "affected_ranges")?;
    check(ranges.len() <= MAX_WORDPRESS_RANGES)?;
    let mut profiled_ranges = Vec::with_capacity(ranges.len());
    for value in ranges {
        let range = affected_range_v2(object(value)?, profile)?;
        check(
            !profiled_ranges
                .iter()
                .any(|existing| profiled_ranges_equivalent(existing, &range)),
        )?;
        profiled_ranges.push(range);
    }
    let fixed_versions = array(fields, "fixed_versions")?;
    check(fixed_versions.len() <= MAX_WORDPRESS_FIXED_VERSIONS)?;
    let mut fixed = Vec::<ProfiledVersionKey>::with_capacity(fixed_versions.len());
    for value in fixed_versions {
        let value = value.as_str().ok_or(ComparisonError::InvalidDocument)?;
        let version = parse_profiled_version(profile, value)?;
        check(
            !fixed
                .iter()
                .any(|existing| profiled_compare(existing, &version).ok() == Some(Ordering::Equal)),
        )?;
        fixed.push(version);
    }

    let prerequisites = array(fields, "prerequisites")?;
    check(prerequisites.len() <= MAX_WORDPRESS_PREREQUISITES)?;
    let mut prerequisite_outcomes = Vec::with_capacity(prerequisites.len());
    let mut prerequisite_identities = std::collections::BTreeSet::new();
    for value in prerequisites {
        let prerequisite = prerequisite(object(value)?)?;
        check(prerequisite_identities.insert(prerequisite.identity))?;
        prerequisite_outcomes.push(prerequisite.outcome);
    }

    let component = components.get(&component_identity);
    let expected_component_evidence = component.map_or("unknown", |value| value.profiled_evidence);
    let component_evidence = token(
        fields,
        "component_evidence",
        &[
            "observed_hint",
            "operator_supplied",
            "conflicting",
            "unknown",
        ],
    )?;
    check(component_evidence == expected_component_evidence)?;

    let missing_resolution = ProfiledResolution {
        status: "missing",
        reason: "no_version_evidence",
        selected: None,
    };
    let resolution = resolutions
        .get(&(component_identity, profile))
        .unwrap_or(&missing_resolution);
    let version_resolution = token(
        fields,
        "version_resolution",
        &[
            "missing",
            "supported_equivalent",
            "conflicting",
            "unsupported",
        ],
    )?;
    let version_resolution_reason = token(
        fields,
        "version_resolution_reason",
        &[
            "no_version_evidence",
            "single_supported_version",
            "equivalent_supported_versions",
            "conflicting_version_evidence",
            "unsupported_version_evidence",
        ],
    )?;
    check(
        version_resolution == resolution.status && version_resolution_reason == resolution.reason,
    )?;

    let expected_relation = profiled_version_relation(resolution, &profiled_ranges)?;
    let version_relation = token(
        fields,
        "version_relation",
        &[
            "within_declared_range",
            "outside_declared_ranges",
            "unknown",
            "unsupported",
        ],
    )?;
    check(version_relation == expected_relation)?;
    let applicability = token(
        fields,
        "applicability",
        &[
            "candidate_match_on_declared_facts",
            "contradicted_by_declared_facts",
            "indeterminate_missing_evidence",
            "indeterminate_unsupported",
        ],
    )?;
    let expected_applicability =
        expected_applicability(component_evidence, version_relation, &prerequisite_outcomes);
    check(applicability == expected_applicability)?;
    check(
        string(fields, "exploit_execution")? == "not_performed"
            && string(fields, "impact_validation")? == "not_performed",
    )?;
    Ok(id.to_owned())
}

fn expected_applicability(
    component_evidence: &str,
    version_relation: &str,
    prerequisite_outcomes: &[&str],
) -> &'static str {
    if version_relation == "outside_declared_ranges"
        || prerequisite_outcomes.contains(&"contradicted_on_supplied_facts")
    {
        "contradicted_by_declared_facts"
    } else if version_relation == "unsupported" || prerequisite_outcomes.contains(&"unsupported") {
        "indeterminate_unsupported"
    } else if matches!(component_evidence, "unknown" | "conflicting")
        || version_relation == "unknown"
        || prerequisite_outcomes.contains(&"unknown")
    {
        "indeterminate_missing_evidence"
    } else {
        "candidate_match_on_declared_facts"
    }
}

fn advisory_source(fields: &serde_json::Map<String, Value>) -> Result<(), ComparisonError> {
    keys(
        fields,
        &["reference", "revision", "retrieved_on", "usage_basis"],
        &[],
    )?;
    let reference = text(fields, "reference", MAX_LEGACY_AUDIT_TEXT_BYTES)?;
    let url = url::Url::parse(reference).map_err(|_| ComparisonError::InvalidDocument)?;
    check(
        url.scheme() == "https"
            && url.has_host()
            && url.username().is_empty()
            && url.password().is_none(),
    )?;
    identifier(text(fields, "revision", MAX_IDENTIFIER_BYTES)?)?;
    date(text(fields, "retrieved_on", MAX_IDENTIFIER_BYTES)?)?;
    bounded_text(text(fields, "usage_basis", 256)?, 256)?;
    Ok(())
}

fn affected_range_v1(fields: &serde_json::Map<String, Value>) -> Result<(), ComparisonError> {
    keys(fields, &["lower", "upper"], &[])?;
    let mut present = false;
    let mut lower = None;
    let mut upper = None;
    for name in ["lower", "upper"] {
        let value = required(fields, name)?;
        if !value.is_null() {
            present = true;
            let endpoint = object(value)?;
            keys(endpoint, &["declared", "inclusive"], &[])?;
            let endpoint = (
                numeric_components(text(endpoint, "declared", 64)?)?,
                boolean(endpoint, "inclusive")?,
            );
            if name == "lower" {
                lower = Some(endpoint);
            } else {
                upper = Some(endpoint);
            }
        }
    }
    check(present)?;
    if let (Some((lower, lower_inclusive)), Some((upper, upper_inclusive))) = (lower, upper) {
        check(lower < upper || (lower == upper && lower_inclusive && upper_inclusive))?;
    }
    Ok(())
}

fn affected_range_v2(
    fields: &serde_json::Map<String, Value>,
    profile: WordPressComparisonProfile,
) -> Result<ProfiledRange, ComparisonError> {
    keys(fields, &["lower", "upper"], &[])?;
    let mut present = false;
    let mut lower = None;
    let mut upper = None;
    for name in ["lower", "upper"] {
        let value = required(fields, name)?;
        if !value.is_null() {
            present = true;
            let endpoint = object(value)?;
            keys(endpoint, &["declared", "inclusive"], &[])?;
            let endpoint = (
                parse_profiled_version(profile, text(endpoint, "declared", 64)?)?,
                boolean(endpoint, "inclusive")?,
            );
            if name == "lower" {
                lower = Some(endpoint);
            } else {
                upper = Some(endpoint);
            }
        }
    }
    check(present)?;
    if let (Some((lower_version, lower_inclusive)), Some((upper_version, upper_inclusive))) =
        (&lower, &upper)
    {
        let ordering = profiled_compare(lower_version, upper_version)?;
        check(
            ordering == Ordering::Less
                || (ordering == Ordering::Equal && *lower_inclusive && *upper_inclusive),
        )?;
    }
    Ok(ProfiledRange { lower, upper })
}

fn parse_profiled_version(
    profile: WordPressComparisonProfile,
    value: &str,
) -> Result<ProfiledVersionKey, ComparisonError> {
    ProfiledVersionKey::parse(profile, value).map_err(|_| ComparisonError::InvalidDocument)
}

fn profiled_compare(
    left: &ProfiledVersionKey,
    right: &ProfiledVersionKey,
) -> Result<Ordering, ComparisonError> {
    left.compare(right)
        .map_err(|_| ComparisonError::InvalidDocument)
}

fn profiled_ranges_equivalent(left: &ProfiledRange, right: &ProfiledRange) -> bool {
    profiled_endpoints_equivalent(left.lower.as_ref(), right.lower.as_ref())
        && profiled_endpoints_equivalent(left.upper.as_ref(), right.upper.as_ref())
}

fn profiled_endpoints_equivalent(
    left: Option<&(ProfiledVersionKey, bool)>,
    right: Option<&(ProfiledVersionKey, bool)>,
) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some((left, left_inclusive)), Some((right, right_inclusive))) => {
            left_inclusive == right_inclusive
                && profiled_compare(left, right).ok() == Some(Ordering::Equal)
        },
        (None, Some(_)) | (Some(_), None) => false,
    }
}

fn resolve_profiled_component(
    component: &ImportedWordPressComponent,
    profile: WordPressComparisonProfile,
) -> Result<ProfiledResolution, ComparisonError> {
    if component.versions.is_empty() {
        return Ok(ProfiledResolution {
            status: "missing",
            reason: "no_version_evidence",
            selected: None,
        });
    }

    let mut supported = None::<ProfiledVersionKey>;
    let mut supported_conflict = false;
    let mut unsupported = false;
    for value in &component.versions {
        match ProfiledVersionKey::parse(profile, value) {
            Ok(version) => {
                if let Some(selected) = supported.as_ref() {
                    if profiled_compare(selected, &version).ok() != Some(Ordering::Equal) {
                        supported_conflict = true;
                    }
                } else {
                    supported = Some(version);
                }
            },
            Err(_) => {
                unsupported = true;
            },
        }
    }
    if supported_conflict {
        return Ok(ProfiledResolution {
            status: "conflicting",
            reason: "conflicting_version_evidence",
            selected: None,
        });
    }
    if unsupported || supported.is_none() {
        return Ok(ProfiledResolution {
            status: "unsupported",
            reason: "unsupported_version_evidence",
            selected: None,
        });
    }
    Ok(ProfiledResolution {
        status: "supported_equivalent",
        reason: if component.versions.len() == 1 {
            "single_supported_version"
        } else {
            "equivalent_supported_versions"
        },
        selected: supported,
    })
}

fn profiled_version_relation(
    resolution: &ProfiledResolution,
    ranges: &[ProfiledRange],
) -> Result<&'static str, ComparisonError> {
    match resolution.status {
        "missing" | "conflicting" => Ok("unknown"),
        "unsupported" => Ok("unsupported"),
        "supported_equivalent" => {
            let version = resolution
                .selected
                .as_ref()
                .ok_or(ComparisonError::InvalidDocument)?;
            if ranges.is_empty() {
                return Ok("unknown");
            }
            for range in ranges {
                let above_lower = match &range.lower {
                    None => true,
                    Some((lower, inclusive)) => match profiled_compare(version, lower)? {
                        Ordering::Greater => true,
                        Ordering::Equal => *inclusive,
                        Ordering::Less => false,
                    },
                };
                let below_upper = match &range.upper {
                    None => true,
                    Some((upper, inclusive)) => match profiled_compare(version, upper)? {
                        Ordering::Less => true,
                        Ordering::Equal => *inclusive,
                        Ordering::Greater => false,
                    },
                };
                if above_lower && below_upper {
                    return Ok("within_declared_range");
                }
            }
            Ok("outside_declared_ranges")
        },
        _ => Err(ComparisonError::InvalidDocument),
    }
}

fn prerequisite<'a>(
    fields: &'a serde_json::Map<String, Value>,
) -> Result<ImportedPrerequisite<'a>, ComparisonError> {
    keys(fields, &["kind", "expected", "outcome"], &["patch_id"])?;
    let kind = token(
        fields,
        "kind",
        &[
            "hosting_os",
            "multisite",
            "activation",
            "patch",
            "unsupported",
        ],
    )?;
    let expected = text(fields, "expected", MAX_IDENTIFIER_BYTES)?;
    let patch_id = match kind {
        "hosting_os" => {
            check(["linux", "windows", "macos", "bsd", "other"].contains(&expected))?;
            None
        },
        "multisite" => {
            check(["enabled", "disabled"].contains(&expected))?;
            None
        },
        "activation" => {
            check(["active", "inactive", "network_active"].contains(&expected))?;
            None
        },
        "patch" => {
            check(["applied", "not_applied"].contains(&expected))?;
            let patch_id = text(fields, "patch_id", MAX_IDENTIFIER_BYTES)?;
            identifier(patch_id)?;
            Some(patch_id.to_owned())
        },
        "unsupported" => {
            identifier(expected)?;
            None
        },
        _ => return Err(ComparisonError::InvalidDocument),
    };
    check((kind == "patch") == fields.contains_key("patch_id"))?;
    let outcome = token(
        fields,
        "outcome",
        &[
            "matched_on_supplied_facts",
            "contradicted_on_supplied_facts",
            "unknown",
            "unsupported",
        ],
    )?;
    check((kind == "unsupported") == (outcome == "unsupported"))?;
    Ok(ImportedPrerequisite {
        identity: (kind.to_owned(), expected.to_owned(), patch_id),
        outcome,
    })
}

fn token_array(
    fields: &serde_json::Map<String, Value>,
    name: &str,
    allowed: &[&str],
    limit: usize,
) -> Result<(), ComparisonError> {
    let values = array(fields, name)?;
    check(!values.is_empty() && values.len() <= limit)?;
    let mut unique = std::collections::BTreeSet::new();
    for value in values {
        let value = value.as_str().ok_or(ComparisonError::InvalidDocument)?;
        check(allowed.contains(&value) && unique.insert(value))?;
    }
    Ok(())
}

fn numeric_components(value: &str) -> Result<Vec<u32>, ComparisonError> {
    check(!value.is_empty() && value.len() <= 64)?;
    let mut components = value
        .split('.')
        .map(|part| {
            if part.is_empty()
                || !part.bytes().all(|byte| byte.is_ascii_digit())
                || (part.len() > 1 && part.starts_with('0'))
            {
                return Err(ComparisonError::InvalidDocument);
            }
            part.parse::<u32>()
                .map_err(|_| ComparisonError::InvalidDocument)
        })
        .collect::<Result<Vec<_>, _>>()?;
    check(!components.is_empty() && components.len() <= 8)?;
    while components.len() > 1 && components.last() == Some(&0) {
        components.pop();
    }
    Ok(components)
}

fn source_version(value: &str) -> Result<&str, ComparisonError> {
    bounded_text(value, 64)
}

fn bounded_text(value: &str, maximum: usize) -> Result<&str, ComparisonError> {
    check(!value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control))?;
    Ok(value)
}

fn identifier(value: &str) -> Result<(), ComparisonError> {
    check(
        !value.is_empty()
            && value.len() <= MAX_IDENTIFIER_BYTES
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
            }),
    )
}

fn date(value: &str) -> Result<(), ComparisonError> {
    let bytes = value.as_bytes();
    check(
        bytes.len() == 10
            && bytes[4] == b'-'
            && bytes[7] == b'-'
            && bytes
                .iter()
                .enumerate()
                .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit()),
    )?;
    let year = decimal(&bytes[0..4])?;
    let month = decimal(&bytes[5..7])?;
    let day = decimal(&bytes[8..10])?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let maximum = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err(ComparisonError::InvalidDocument),
    };
    check(day > 0 && day <= maximum)
}

fn decimal(bytes: &[u8]) -> Result<u32, ComparisonError> {
    bytes
        .iter()
        .try_fold(0_u32, |value, digit| {
            value.checked_mul(10)?.checked_add(u32::from(*digit - b'0'))
        })
        .ok_or(ComparisonError::InvalidDocument)
}

fn valid_slug(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 {
        return false;
    }
    let mut previous_hyphen = true;
    for byte in value.bytes() {
        match byte {
            b'a'..=b'z' | b'0'..=b'9' => previous_hyphen = false,
            b'-' if !previous_hyphen => previous_hyphen = true,
            _ => return false,
        }
    }
    !previous_hyphen
}

fn valid_cve(value: &str) -> bool {
    let mut parts = value.split('-');
    parts.next() == Some("CVE")
        && parts
            .next()
            .is_some_and(|year| year.len() == 4 && year.bytes().all(|byte| byte.is_ascii_digit()))
        && parts.next().is_some_and(|id| {
            (4..=10).contains(&id.len()) && id.bytes().all(|byte| byte.is_ascii_digit())
        })
        && parts.next().is_none()
}

fn count(items: &BTreeMap<String, ImportedItem>, capability: &str) -> usize {
    items
        .values()
        .filter(|item| item.capability_id == capability)
        .count()
}

fn openapi(fields: &serde_json::Map<String, Value>, count: usize) -> Result<(), ComparisonError> {
    keys(
        fields,
        &[
            "schema",
            "capability_id",
            "outcome",
            "candidate_source",
            "request_count",
            "active_verification_count",
            "version",
            "semantic_digest",
            "path_count",
            "operation_count",
            "get_operation_count",
            "write_operation_count",
            "path_parameter_count",
            "query_parameter_count",
            "explicit_auth_operation_count",
            "anonymous_operation_count",
            "url_like_operation_count",
            "multipart_operation_count",
            "deprecated_operation_count",
            "replay_matched",
            "item_projected",
        ],
        &[],
    )?;
    check(
        string(fields, "schema")? == "security.openapi-review-audit/v1"
            && string(fields, "capability_id")? == OPENAPI_CAPABILITY,
    )?;
    token(
        fields,
        "outcome",
        &[
            "not_eligible",
            "document_observed",
            "swagger_20_metadata_only",
            "unsupported_version",
            "replay_mismatch",
            "unsupported_media",
            "malformed",
            "limit_exceeded",
            "too_large",
            "redirect_observed",
            "rate_limited",
            "defensive_interference",
            "http_error",
            "truncated",
            "incomplete",
            "budget_exhausted",
            "cancelled",
        ],
    )?;
    token(
        fields,
        "candidate_source",
        &[
            "discovered_openapi_json",
            "discovered_openapi_yaml",
            "discovered_swagger_json",
            "discovered_swagger_yaml",
            "conventional_openapi_json",
        ],
    )?;
    number(fields, "request_count", 2)?;
    number(fields, "active_verification_count", 1)?;
    optional_token(fields, "version", &["3.0", "3.1"])?;
    if let Some(value) = optional_text(fields, "semantic_digest", MAX_IDENTIFIER_BYTES)? {
        check(digest(value, "openapi-catalog-sha256:"))?;
    }
    for field in [
        "path_count",
        "operation_count",
        "get_operation_count",
        "write_operation_count",
        "path_parameter_count",
        "query_parameter_count",
        "explicit_auth_operation_count",
        "anonymous_operation_count",
        "url_like_operation_count",
        "multipart_operation_count",
        "deprecated_operation_count",
    ] {
        number(fields, field, u64::from(u32::MAX))?;
    }
    let projected = boolean(fields, "item_projected")?;
    check(
        count <= 1 && projected == (count == 1) && boolean(fields, "replay_matched")? == projected,
    )
}

fn rest(fields: &serde_json::Map<String, Value>, count: usize) -> Result<(), ComparisonError> {
    keys(
        fields,
        &[
            "schema",
            "capability_id",
            "enabled",
            "method",
            "outcome",
            "request_count",
            "active_verification_count",
            "eligible_operation_count",
            "documented_response",
            "observed_media",
            "replay_stable",
            "item_projected",
        ],
        &["selected_operation_identity", "status_class"],
    )?;
    check(
        string(fields, "schema")? == "security.rest-readonly-review-audit/v1"
            && string(fields, "capability_id")? == REST_CAPABILITY
            && boolean(fields, "enabled")?
            && string(fields, "method")? == "get",
    )?;
    let outcome = token(
        fields,
        "outcome",
        &[
            "not_eligible",
            "surface_observed",
            "replay_mismatch",
            "complete_non_json",
            "redirect",
            "authentication_required",
            "forbidden",
            "not_found",
            "rate_limited",
            "defensive_interference",
            "server_error",
            "unsupported_media",
            "truncated",
            "incomplete",
            "cancelled",
            "budget_exhausted",
        ],
    )?;
    let requests = number(fields, "request_count", 2)?;
    let active = number(fields, "active_verification_count", 1)?;
    let eligible = number(fields, "eligible_operation_count", u64::from(u32::MAX))?;
    if fields.contains_key("selected_operation_identity") {
        check(digest(
            text(fields, "selected_operation_identity", MAX_IDENTIFIER_BYTES)?,
            "openapi-operation-sha256:",
        ))?;
    }
    optional_token(
        fields,
        "documented_response",
        &["json_compatible", "unknown"],
    )?;
    token(
        fields,
        "observed_media",
        &["json_compatible", "text", "unsupported", "unknown"],
    )?;
    if fields.contains_key("status_class") {
        check(number(fields, "status_class", 5)? >= 1)?;
    }
    let positive = outcome == "surface_observed";
    let projected = boolean(fields, "item_projected")?;
    check(
        active == u64::from(requests == 2)
            && count <= 1
            && projected == (count == 1)
            && positive == projected
            && boolean(fields, "replay_stable")? == positive
            && (!positive
                || (requests == 2
                    && active == 1
                    && eligible > 0
                    && fields.contains_key("selected_operation_identity"))),
    )
}

fn authorization(
    fields: &serde_json::Map<String, Value>,
    count: usize,
) -> Result<(), ComparisonError> {
    keys(
        fields,
        &[
            "schema",
            "capability_id",
            "policy_id",
            "selected_path_count",
            "ignored_path_count",
            "request_count",
            "outcome",
            "primary_stable",
            "peer_stable",
            "cross_resources_equivalent",
            "item_projected",
        ],
        &[],
    )?;
    check(
        string(fields, "schema")? == "security.authorization-review-audit/v1"
            && string(fields, "capability_id")? == AUTHORIZATION_CAPABILITY
            && digest(
                text(fields, "policy_id", MAX_IDENTIFIER_BYTES)?,
                "authorization-policy-sha256:",
            ),
    )?;
    check(number(fields, "selected_path_count", 8)? > 0)?;
    number(fields, "ignored_path_count", 16)?;
    let requests = number(fields, "request_count", 4)?;
    let outcome = token(
        fields,
        "outcome",
        &[
            "not_eligible",
            "primary_baseline_invalid",
            "primary_unstable",
            "peer_denied",
            "peer_unstable",
            "cross_status_different",
            "cross_fields_equivalent_only",
            "cross_resources_different",
            "stable_cross_principal_equivalence",
            "defensive_interference",
            "rate_limited",
            "redirect_observed",
            "unsupported_media",
            "malformed_json",
            "generic_json_error_envelope",
            "selected_path_missing",
            "truncated",
            "incomplete",
            "budget_exhausted",
            "cancelled",
            "contract_mismatch",
        ],
    )?;
    optional_boolean(fields, "primary_stable")?;
    optional_boolean(fields, "peer_stable")?;
    optional_boolean(fields, "cross_resources_equivalent")?;
    let positive = outcome == "stable_cross_principal_equivalence";
    check(
        count <= 1
            && boolean(fields, "item_projected")? == (count == 1)
            && positive == (count == 1)
            && (!positive || requests == 4),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opaque_reference(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn deployment_layout() -> Value {
        serde_json::json!({
            "application_reference": opaque_reference('a'),
            "declaration": {
                "schema": WORDPRESS_LAYOUT_SCHEMA,
                "byte_length": 123,
                "sha256": "b".repeat(64),
            },
            "roles": [
                {
                    "role": "core",
                    "status": "exact",
                    "basis": "operator_declaration",
                    "reference": opaque_reference('c'),
                    "candidate_count": 1,
                },
                {
                    "role": "themes",
                    "status": "ambiguous",
                    "basis": "conventional_asset",
                    "candidate_count": 2,
                },
                {
                    "role": "plugins",
                    "status": "unresolved",
                    "basis": "none",
                    "candidate_count": 0,
                },
                {
                    "role": "rest_index",
                    "status": "exact",
                    "basis": "structured_advertisement",
                    "reference": opaque_reference('d'),
                    "candidate_count": 1,
                },
            ],
            "skipped_foreign_origin_count": 2,
            "skipped_sibling_application_count": 3,
            "conflicting_association_count": 4,
        })
    }

    fn deployment_rest_source() -> Value {
        serde_json::json!({
            "kind": "rest_index",
            "association": "structured_advertisement",
            "resource_reference": opaque_reference('e'),
            "role_reference": opaque_reference('d'),
            "parent_depth": 0,
            "outcome": "observed",
            "request_attempted": true,
            "response_bytes": 321,
            "evidence_reference_count": 1,
            "evidence_references": ["evidence-0001"],
            "namespaces": ["wp/v2"],
        })
    }

    fn observed_page_collection() -> Value {
        serde_json::json!({
            "mode": "observed",
            "entry_page_reference": opaque_reference('8'),
            "candidate_count": 1,
            "selected_count": 1,
            "omitted_candidate_count": 0,
            "reused_response_count": 1,
            "fetched_response_count": 0,
            "not_observed_count": 0,
            "rejected_response_count": 0,
            "accepted_association_count": 1,
            "rejected_association_count": 0,
            "attempted_request_count": 0,
            "completed_response_count": 1,
            "committed_response_count": 1,
            "interpreted_response_bytes": 128,
            "response_bytes": 0,
            "pages": [{
                "page_reference": opaque_reference('9'),
                "acquisition": "reused",
                "association": "accepted",
                "outcome": "accepted",
                "request_attempted": false,
                "interpreted_response_bytes": 128,
                "response_bytes": 0,
                "evidence_reference_count": 1,
                "evidence_references": ["evidence-0001"],
            }],
        })
    }

    #[test]
    fn deployment_layout_and_source_require_exact_role_binding() {
        let layout = validate_wordpress_discovery_layout(&deployment_layout()).unwrap();
        let source = deployment_rest_source();
        let validated =
            validate_wordpress_discovery_source(source.as_object().unwrap(), Some(&layout), None)
                .unwrap();
        assert_eq!(validated.0, 321);
        assert_eq!(validated.1, 1);
        assert!(validated.2);
        assert_eq!(validated.4, opaque_reference('e'));

        for invalid in [
            {
                let mut value = source.clone();
                value.as_object_mut().unwrap().remove("association");
                value
            },
            {
                let mut value = source.clone();
                value["role_reference"] = Value::String(opaque_reference('f'));
                value
            },
            {
                let mut value = source.clone();
                value["resource_reference"] = Value::String(format!("sha256:{}", "A".repeat(64)));
                value
            },
            {
                let mut value = source.clone();
                value["association"] = Value::String("operator_qualified_advertisement".to_owned());
                value
            },
            {
                let mut value = source.clone();
                value["parent_depth"] = Value::from(1);
                value
            },
        ] {
            assert_eq!(
                validate_wordpress_discovery_source(
                    invalid.as_object().unwrap(),
                    Some(&layout),
                    None,
                ),
                Err(ComparisonError::InvalidDocument),
            );
        }

        let invalid_advertisement = serde_json::json!({
            "kind": "rest_index",
            "association": "invalid_advertisement",
            "resource_reference": opaque_reference('f'),
            "parent_depth": 0,
            "outcome": "invalid_advertisement",
            "request_attempted": false,
            "response_bytes": 0,
            "evidence_reference_count": 0,
            "evidence_references": [],
        });
        assert!(validate_wordpress_discovery_source(
            invalid_advertisement.as_object().unwrap(),
            Some(&layout),
            None,
        )
        .is_ok());
        let mut falsely_bound_invalid_advertisement = invalid_advertisement;
        falsely_bound_invalid_advertisement["role_reference"] =
            Value::String(opaque_reference('d'));
        assert_eq!(
            validate_wordpress_discovery_source(
                falsely_bound_invalid_advertisement.as_object().unwrap(),
                Some(&layout),
                None,
            ),
            Err(ComparisonError::InvalidDocument),
        );
    }

    #[test]
    fn page_scope_and_source_page_bindings_are_closed_and_reconciled() {
        let page_collection = observed_page_collection();
        let validated = validate_wordpress_page_collection(&page_collection).unwrap();
        assert_eq!(validated.attempted_request_count, 0);
        assert_eq!(validated.committed_response_count, 1);
        assert!(validated
            .accepted_page_references
            .contains(&opaque_reference('9')));

        let layout = validate_wordpress_discovery_layout(&deployment_layout()).unwrap();
        let mut source = deployment_rest_source();
        source["evidence_references"] = serde_json::json!(["evidence-0002"]);
        source["source_page_references"] = serde_json::json!([opaque_reference('8')]);
        validate_wordpress_discovery_source(
            source.as_object().unwrap(),
            Some(&layout),
            Some(&validated),
        )
        .unwrap();

        let mut unknown_page = source.clone();
        unknown_page["source_page_references"] = serde_json::json!([opaque_reference('7')]);
        assert!(matches!(
            validate_wordpress_discovery_source(
                unknown_page.as_object().unwrap(),
                Some(&layout),
                Some(&validated),
            ),
            Err(ComparisonError::InvalidDocument),
        ));

        for mut invalid in [
            {
                let mut value = page_collection.clone();
                value["pages"][0]["association"] = Value::String("rejected".to_owned());
                value
            },
            {
                let mut value = page_collection.clone();
                value["pages"][0]["evidence_references"] = serde_json::json!([]);
                value
            },
            {
                let mut value = page_collection.clone();
                value["candidate_count"] = serde_json::json!(2);
                value
            },
            {
                let mut value = page_collection.clone();
                value["mode"] = Value::String("linked".to_owned());
                value["attempted_request_count"] = serde_json::json!(1);
                value
            },
        ] {
            assert!(matches!(
                validate_wordpress_page_collection(&invalid),
                Err(ComparisonError::InvalidDocument)
            ));
            invalid = Value::Null;
            assert!(matches!(
                validate_wordpress_page_collection(&invalid),
                Err(ComparisonError::InvalidDocument)
            ));
        }
    }

    #[test]
    fn deployment_layout_rejects_unreachable_basis_and_declaration_shapes() {
        for invalid in [
            {
                let mut value = deployment_layout();
                value["roles"][0]["basis"] = Value::String("structured_advertisement".to_owned());
                value
            },
            {
                let mut value = deployment_layout();
                value["roles"][3]["basis"] = Value::String("conventional_asset".to_owned());
                value
            },
            {
                let mut value = deployment_layout();
                value.as_object_mut().unwrap().remove("declaration");
                value
            },
            {
                let mut value = deployment_layout();
                value["roles"][0]["basis"] = Value::String("conventional_asset".to_owned());
                value
            },
        ] {
            assert!(matches!(
                validate_wordpress_discovery_layout(&invalid),
                Err(ComparisonError::InvalidDocument),
            ));
        }
    }

    #[test]
    fn deployment_layout_counters_match_the_producer_u16_domain() {
        let mut above_old_reader_limit = deployment_layout();
        above_old_reader_limit["skipped_foreign_origin_count"] = Value::from(4_097);
        above_old_reader_limit["roles"][0]["candidate_count"] = Value::from(u16::MAX);
        assert!(validate_wordpress_discovery_layout(&above_old_reader_limit).is_ok());

        for field in [
            "skipped_foreign_origin_count",
            "skipped_sibling_application_count",
            "conflicting_association_count",
        ] {
            let mut over_limit = deployment_layout();
            over_limit[field] = Value::from(u64::from(u16::MAX) + 1);
            assert!(matches!(
                validate_wordpress_discovery_layout(&over_limit),
                Err(ComparisonError::InvalidDocument),
            ));
        }

        let mut candidate_over_limit = deployment_layout();
        candidate_over_limit["roles"][0]["candidate_count"] = Value::from(u64::from(u16::MAX) + 1);
        assert!(matches!(
            validate_wordpress_discovery_layout(&candidate_over_limit),
            Err(ComparisonError::InvalidDocument),
        ));
    }

    #[test]
    fn discovery_v1_source_shape_remains_exact_and_independent_of_v2_fields() {
        let legacy = serde_json::json!({
            "kind": "rest_index",
            "parent_depth": 0,
            "outcome": "not_found",
            "request_attempted": true,
            "response_bytes": 12,
            "evidence_reference_count": 1,
            "evidence_references": ["evidence-0001"],
        });
        assert_eq!(
            validate_wordpress_discovery_source(legacy.as_object().unwrap(), None, None)
                .unwrap()
                .4,
            "rest_index:none:0",
        );

        let mut v2_field_in_v1 = legacy;
        v2_field_in_v1["resource_reference"] = Value::String(opaque_reference('e'));
        assert_eq!(
            validate_wordpress_discovery_source(v2_field_in_v1.as_object().unwrap(), None, None,),
            Err(ComparisonError::InvalidDocument),
        );
    }

    #[test]
    fn deployment_projection_separates_scope_methodology_coverage_and_provenance() {
        let mut wordpress = ImportedWordPressAudit {
            application_reference: None,
            coverage: serde_json::json!({ "additional_request_count": 1 }),
            inventory_coverage_recorded: false,
            methodology: serde_json::json!({}),
            provenance: serde_json::json!({}),
            discovery_source_content: None,
            components: BTreeMap::new(),
            advisories: BTreeMap::new(),
        };
        let discovery = serde_json::json!({
            "schema": WORDPRESS_DISCOVERY_AUDIT_SCHEMA_V2,
            "capability_id": WORDPRESS_DISCOVERY_CAPABILITY,
            "policy_id": WORDPRESS_DISCOVERY_POLICY_V2,
            "selected": true,
            "method": "get",
            "credential_mode": "anonymous",
            "seed_count": 1,
            "candidate_count": 1,
            "candidate_limit_reached": false,
            "omitted_candidate_count": 0,
            "attempted_request_count": 1,
            "completed_response_count": 1,
            "committed_response_count": 1,
            "response_bytes": 321,
            "source_count": 1,
            "layout": deployment_layout(),
            "sources": [deployment_rest_source()],
        });

        attach_wordpress_discovery(&mut wordpress, &discovery).unwrap();
        assert_eq!(
            wordpress.application_reference.as_deref(),
            Some(opaque_reference('a').as_str()),
        );
        assert!(wordpress.methodology["wordpress_discovery"]["layout_roles"].is_array());
        assert_eq!(
            wordpress.coverage["wordpress_discovery"]["skipped_sibling_application_count"],
            3,
        );
        assert_eq!(
            wordpress.provenance["wordpress_layout"]["declaration"]["byte_length"],
            123,
        );
        let rest = &wordpress.discovery_source_content.as_ref().unwrap()["rest_indexes"][0];
        assert_eq!(rest["association"], "structured_advertisement");
        assert_eq!(rest["resource_reference"], opaque_reference('e'));
        assert_eq!(rest["role_reference"], opaque_reference('d'));
    }

    #[test]
    fn wordpress_discovery_request_class_count_contract_is_exact() {
        assert!(wordpress_discovery_request_class_counts_valid(1, 3, 8));
        assert!(!wordpress_discovery_request_class_counts_valid(2, 2, 8));
        assert!(!wordpress_discovery_request_class_counts_valid(0, 4, 8));
        assert!(!wordpress_discovery_request_class_counts_valid(0, 3, 9));
    }

    fn source_identity_fields(slug: &str, mapping: &str, collision: Option<u64>) -> (Value, Value) {
        let key = serde_json::json!({
            "source_component": { "kind": "plugin", "slug": slug }
        });
        let mut evaluation = serde_json::Map::new();
        evaluation.insert(
            "identity_mapping".to_owned(),
            Value::String(mapping.to_owned()),
        );
        if let Some(collision) = collision {
            evaluation.insert(
                "identity_collision_raw_count".to_owned(),
                Value::Number(collision.into()),
            );
        }
        (key, Value::Object(evaluation))
    }

    #[test]
    fn unsupported_audit_inventory_name_fails_closed() {
        assert_eq!(
            validate("future_audit", &serde_json::json!({}), &BTreeMap::new()),
            Err(ComparisonError::InvalidDocument),
        );
    }

    #[test]
    fn v6_source_identity_mapping_requires_exactly_supported_relationships() {
        let (key, evaluation) =
            source_identity_fields("Termivar-Fixture", "ascii_case_fold_candidate", None);
        assert_eq!(
            external_identity_mapping(
                key.as_object().unwrap(),
                evaluation.as_object().unwrap(),
                "plugin:termivar-fixture",
                true,
            ),
            Ok((
                "plugin:Termivar-Fixture".to_owned(),
                ExternalIdentityMapping::AsciiCaseFoldCandidate,
                None,
            )),
        );

        let (key, evaluation) =
            source_identity_fields("TERMIVAR-FIXTURE", "ascii_case_fold_ambiguous", Some(2));
        assert_eq!(
            external_identity_mapping(
                key.as_object().unwrap(),
                evaluation.as_object().unwrap(),
                "plugin:termivar-fixture",
                true,
            ),
            Ok((
                "plugin:TERMIVAR-FIXTURE".to_owned(),
                ExternalIdentityMapping::AsciiCaseFoldAmbiguous,
                Some(2),
            )),
        );

        for (slug, mapping, collision) in [
            ("Termivar-Fixture", "exact", None),
            ("Termivar-Fixture", "ascii_case_fold_candidate", Some(2)),
            ("Termivar-Fixture", "ascii_case_fold_ambiguous", Some(1)),
            ("different", "ascii_case_fold_candidate", None),
        ] {
            let (key, evaluation) = source_identity_fields(slug, mapping, collision);
            assert_eq!(
                external_identity_mapping(
                    key.as_object().unwrap(),
                    evaluation.as_object().unwrap(),
                    "plugin:termivar-fixture",
                    true,
                ),
                Err(ComparisonError::InvalidDocument),
            );
        }
    }

    #[test]
    fn v6_schema_requires_real_mapping_or_resource_expansion() {
        assert_eq!(
            ExternalResourcePolicy::V1.retained_bytes(),
            64 * 1024 * 1024
        );
        assert_eq!(
            ExternalResourcePolicy::V2.retained_bytes(),
            128 * 1024 * 1024
        );
        assert_eq!(
            ExternalResourcePolicy::V3.retained_bytes(),
            160 * 1024 * 1024
        );
        assert!(!ExternalResourcePolicy::V1.expanded());
        assert!(ExternalResourcePolicy::V2.expanded());
        assert!(ExternalResourcePolicy::V3.expanded());
        assert!(v6_identity_contract_is_valid(
            WORDFENCE_V3_MAPPING_REVISION_V1,
            ExternalResourcePolicy::V2,
            [3, 0, 0, 0],
            3,
        ));
        assert!(v6_identity_contract_is_valid(
            WORDFENCE_V3_MAPPING_REVISION_V1,
            ExternalResourcePolicy::V3,
            [3, 0, 0, 0],
            3,
        ));
        assert!(v6_identity_contract_is_valid(
            WORDFENCE_V3_MAPPING_REVISION_V2,
            ExternalResourcePolicy::V1,
            [1, 1, 1, 1],
            4,
        ));
        assert!(!v6_identity_contract_is_valid(
            WORDFENCE_V3_MAPPING_REVISION_V1,
            ExternalResourcePolicy::V1,
            [3, 0, 0, 0],
            3,
        ));
        assert!(!v6_identity_contract_is_valid(
            WORDFENCE_V3_MAPPING_REVISION_V1,
            ExternalResourcePolicy::V2,
            [2, 1, 0, 0],
            3,
        ));
        assert!(!v6_identity_contract_is_valid(
            WORDFENCE_V3_MAPPING_REVISION_V1,
            ExternalResourcePolicy::V3,
            [2, 1, 0, 0],
            3,
        ));
        assert!(!v6_identity_contract_is_valid(
            WORDFENCE_V3_MAPPING_REVISION_V2,
            ExternalResourcePolicy::V1,
            [4, 0, 0, 0],
            4,
        ));
    }
}
