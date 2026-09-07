//! Exact optional audit wire inventories; these snapshots are not evidence authority.

use super::{
    array, boolean, check, digest, keys, number, object, optional_boolean, optional_text,
    optional_token, required, string, text, token, ComparisonError, ImportedItem, Value,
    MAX_AUDIT_TEXT_BYTES, MAX_IDENTIFIER_BYTES,
};
use crate::wordpress_version::{ProfiledVersionKey, WordPressComparisonProfile};
use std::cmp::Ordering;
use std::collections::BTreeMap;

pub(super) const REST_CAPABILITY: &str = "api.rest-readonly-surface-observed@1";
pub(super) const WORDPRESS_CAPABILITY: &str = "technology.wordpress-surface-observed@1";
const OPENAPI_CAPABILITY: &str = "api.openapi-contract-observed@1";
const AUTHORIZATION_CAPABILITY: &str = "authorization.resource-cross-principal-equivalence@1";
const MAX_WORDPRESS_SIGNALS: u64 = 256;
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

#[derive(Clone, Copy, Eq, PartialEq)]
enum WordPressAuditSchema {
    V1,
    V2,
}

struct ImportedWordPressComponent {
    versions: Vec<String>,
    profiled_evidence: &'static str,
    observed_source: bool,
}

struct ProfiledRange {
    lower: Option<(ProfiledVersionKey, bool)>,
    upper: Option<(ProfiledVersionKey, bool)>,
}

struct ProfiledResolution {
    status: &'static str,
    reason: &'static str,
    selected: Option<ProfiledVersionKey>,
}

struct ImportedPrerequisite<'a> {
    identity: (String, String, Option<String>),
    outcome: &'a str,
}

pub(super) fn validate(
    name: &str,
    value: &Value,
    items: &BTreeMap<String, ImportedItem>,
) -> Result<(), ComparisonError> {
    let fields = object(value)?;
    match name {
        "openapi_review" => openapi(fields, count(items, OPENAPI_CAPABILITY)),
        "rest_review" => rest(fields, count(items, REST_CAPABILITY)),
        "authorization_review" => authorization(fields, count(items, AUTHORIZATION_CAPABILITY)),
        "wordpress_review" => wordpress(fields, count(items, WORDPRESS_CAPABILITY)),
        _ => Err(ComparisonError::InvalidDocument),
    }
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
        &["catalog"],
    )?;
    let schema = match string(fields, "schema")? {
        "security.wordpress-review-audit/v1" => WordPressAuditSchema::V1,
        "security.wordpress-review-audit/v2" => WordPressAuditSchema::V2,
        _ => return Err(ComparisonError::InvalidDocument),
    };
    check(string(fields, "capability_id")? == WORDPRESS_CAPABILITY)?;
    let status = token(
        fields,
        "catalog_status",
        &["catalogue_not_supplied", "evaluated"],
    )?;
    match (status, fields.get("catalog")) {
        ("catalogue_not_supplied", None) => {},
        ("evaluated", Some(value)) => catalog(object(value)?)?,
        _ => return Err(ComparisonError::InvalidDocument),
    }
    check(schema == WordPressAuditSchema::V1 || status == "evaluated")?;
    let signal_count = number(fields, "signal_count", MAX_WORDPRESS_SIGNALS)?;
    let evidence_count = number(fields, "evidence_reference_count", MAX_WORDPRESS_SIGNALS)?;
    check(number(fields, "additional_request_count", 0)? == 0)?;
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
        let (identity, component) = component(object(value)?, schema)?;
        version_count = version_count
            .checked_add(component.versions.len())
            .ok_or(ComparisonError::InvalidDocument)?;
        check(version_count <= MAX_WORDPRESS_RESULT_VERSION_EVIDENCE)?;
        check(imported_components.insert(identity, component).is_none())?;
    }
    if schema == WordPressAuditSchema::V2 {
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
    if schema == WordPressAuditSchema::V2 {
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
        let id = match schema {
            WordPressAuditSchema::V1 => advisory_v1(object(value)?)?,
            WordPressAuditSchema::V2 => {
                advisory_v2(object(value)?, &imported_components, &profiled_resolutions)?
            },
        };
        check(advisory_ids.insert(id))?;
    }
    Ok(())
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
        &[],
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
    token_array(
        fields,
        "identity_sources",
        &[
            "generator_metadata",
            "same_origin_asset_path",
            "operator_context",
        ],
        3,
    )?;
    let identity_sources = array(fields, "identity_sources")?;
    let identity_sources = identity_sources
        .iter()
        .map(|value| value.as_str().ok_or(ComparisonError::InvalidDocument))
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    if schema == WordPressAuditSchema::V2 {
        check(!identity_sources.contains("generator_metadata") || identity == "core:wordpress")?;
    }
    let profiled_evidence = if identity_sources
        .iter()
        .any(|value| matches!(*value, "generator_metadata" | "same_origin_asset_path"))
    {
        "observed_hint"
    } else if identity_sources
        .iter()
        .any(|value| *value == "operator_context")
    {
        "operator_supplied"
    } else {
        "unknown"
    };
    if schema == WordPressAuditSchema::V2 {
        check(evidence_class == profiled_evidence)?;
    }
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
            "operator_context" => Ok("operator_assertion"),
            _ => Err(ComparisonError::InvalidDocument),
        })
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    if schema == WordPressAuditSchema::V2 {
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
        let source = token(
            version,
            "source",
            if schema == WordPressAuditSchema::V2 {
                &["generator_metadata", "operator_context"]
            } else {
                &[
                    "generator_metadata",
                    "same_origin_asset_path",
                    "operator_context",
                ]
            },
        )?;
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
                    "operator_context" => "operator_assertion",
                    _ => return Err(ComparisonError::InvalidDocument),
                },
        )?;
        if schema == WordPressAuditSchema::V2 {
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
    if schema == WordPressAuditSchema::V2 {
        check(activation.is_none() || identity_sources.contains("operator_context"))?;
    }
    Ok((
        identity,
        ImportedWordPressComponent {
            versions: version_values,
            profiled_evidence,
            observed_source: profiled_evidence == "observed_hint",
        },
    ))
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
    if let Some(remediation) = optional_text(fields, "remediation", MAX_AUDIT_TEXT_BYTES)? {
        bounded_text(remediation, MAX_AUDIT_TEXT_BYTES)?;
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
    if let Some(remediation) = optional_text(fields, "remediation", MAX_AUDIT_TEXT_BYTES)? {
        bounded_text(remediation, MAX_AUDIT_TEXT_BYTES)?;
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
    let reference = text(fields, "reference", MAX_AUDIT_TEXT_BYTES)?;
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

    #[test]
    fn unsupported_audit_inventory_name_fails_closed() {
        assert_eq!(
            validate("future_audit", &serde_json::json!({}), &BTreeMap::new()),
            Err(ComparisonError::InvalidDocument),
        );
    }
}
