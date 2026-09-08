//! Exact optional audit wire inventories; these snapshots are not evidence authority.

use super::super::{ImportedWordPressAudit, WordPressAdvisoryKey, WordPressComponentKey};
use super::{
    array, boolean, check, digest, keys, number, object, optional_boolean, optional_text,
    optional_token, required, string, text, token, ComparisonError, ImportedItem, Value,
    MAX_AUDIT_TEXT_BYTES, MAX_IDENTIFIER_BYTES,
};
use crate::wordpress_version::{
    checked_accumulate_external_interpretation_work, ProfiledVersionKey, WordPressComparisonProfile,
};
use serde_json::Map;
use sha2::{Digest, Sha256};
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
const MAX_WORDPRESS_EVALUATION_WORK: usize =
    MAX_WORDPRESS_ADVISORIES * (MAX_WORDPRESS_RANGES + MAX_WORDPRESS_PREREQUISITES);
const MAX_WORDPRESS_SAVED_INVENTORY_BYTES: u64 = 1024 * 1024;
const MAX_WORDPRESS_INVENTORY_INPUTS: usize = 3;
const MAX_WORDPRESS_INVENTORY_VERSION_BYTES: usize = 64;
const MAX_WORDPRESS_INVENTORY_LABEL_BYTES: usize = 64;
const MAX_WORDFENCE_V3_INPUT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_WORDFENCE_V3_RECORDS: u64 = 100_000;
const MAX_WORDFENCE_V3_ASSOCIATIONS: u64 = 200_000;
const MAX_WORDFENCE_V3_SOFTWARE_PER_RECORD: u64 = 2_048;
const MAX_WORDFENCE_V3_EVALUATIONS: usize = MAX_WORDPRESS_ADVISORIES;
const MAX_WORDFENCE_V3_RANGES: usize = 64;
const MAX_WORDFENCE_V3_SELECTED_RANGES: u64 =
    (MAX_WORDFENCE_V3_EVALUATIONS * MAX_WORDFENCE_V3_RANGES) as u64;
const MAX_WORDFENCE_V3_PATCHED_VERSIONS: usize = 64;
const MAX_WORDFENCE_V3_REFERENCES: usize = 64;
const MAX_WORDFENCE_V3_RESEARCHERS: usize = 64;
const MAX_WORDFENCE_V3_NOTICES: usize = MAX_WORDPRESS_ADVISORIES;
// Mirrors the feature-owned Production parser's per-record rights-party cap.
const MAX_WORDFENCE_V3_NOTICE_PARTIES: usize = 15;
const MAX_WORDFENCE_V3_TITLE_BYTES: usize = 1_024;
const MAX_WORDFENCE_V3_NAME_BYTES: usize = 1_024;
const MAX_WORDFENCE_V3_RESEARCHER_BYTES: usize = 512;
const MAX_WORDFENCE_V3_CVE_BYTES: usize = 32;

#[derive(Clone, Copy, Eq, PartialEq)]
enum WordPressAuditSchema {
    V1,
    V2,
    V3,
    V4,
    V5,
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
        ],
    )?;
    let schema = match string(fields, "schema")? {
        "security.wordpress-review-audit/v1" => WordPressAuditSchema::V1,
        "security.wordpress-review-audit/v2" => WordPressAuditSchema::V2,
        "security.wordpress-review-audit/v3" => WordPressAuditSchema::V3,
        "security.wordpress-review-audit/v4" => WordPressAuditSchema::V4,
        "security.wordpress-review-audit/v5" => WordPressAuditSchema::V5,
        _ => return Err(ComparisonError::InvalidDocument),
    };
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
        ("evaluated", None, WordPressAuditSchema::V4 | WordPressAuditSchema::V5) => {},
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
        WordPressAuditSchema::V4 | WordPressAuditSchema::V5 => {
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
        let (identity, component) = component(object(value)?, schema, profiled)?;
        version_count = version_count
            .checked_add(component.versions.len())
            .ok_or(ComparisonError::InvalidDocument)?;
        check(version_count <= MAX_WORDPRESS_RESULT_VERSION_EVIDENCE)?;
        check(imported_components.insert(identity, component).is_none())?;
    }
    if schema != WordPressAuditSchema::V1 {
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
            (WordPressAuditSchema::V4 | WordPressAuditSchema::V5, false) => {
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
    if matches!(schema, WordPressAuditSchema::V4 | WordPressAuditSchema::V5) {
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
    let inventory = fields.get("inventory_import").map(object).transpose()?;
    let external = fields.get("external_review").map(object).transpose()?;

    let methodology = selected_object(
        fields,
        &["schema", "catalog_schema"],
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
        schema,
        "security.wordpress-review-audit/v4" | "security.wordpress-review-audit/v5"
    ) {
        let external = external.ok_or(ComparisonError::InvalidDocument)?;
        let namespace = string(external, "source_namespace")?;
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
            let component = comparison_component_key(object(required(wire_key, "component")?)?)?;
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
            if advisories.insert(key, content).is_some() {
                return Err(ComparisonError::AmbiguousIdentity);
            }
        }
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
        coverage,
        inventory_coverage_recorded: inventory.is_some(),
        methodology,
        provenance,
        components,
        advisories,
    })
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
    if schema != WordPressAuditSchema::V1 {
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
    if schema != WordPressAuditSchema::V1 {
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
        if schema != WordPressAuditSchema::V1 {
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
    if schema != WordPressAuditSchema::V1 {
        check(activation.is_none() || identity_sources.contains("operator_context"))?;
    }
    if schema != WordPressAuditSchema::V1 {
        let expected_evidence =
            if profiled || matches!(schema, WordPressAuditSchema::V4 | WordPressAuditSchema::V5) {
                profiled_evidence
            } else {
                legacy_component_evidence(&version_values, profiled_evidence)?
            };
        check(evidence_class == expected_evidence)?;
    }
    let inventory_status = if matches!(
        schema,
        WordPressAuditSchema::V3 | WordPressAuditSchema::V4 | WordPressAuditSchema::V5
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
    let profile = match schema {
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
            None
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
            Some(
                WordPressComparisonProfile::parse(string(fields, "comparison_profile")?)
                    .map_err(|_| ComparisonError::InvalidDocument)?,
            )
        },
        _ => return Err(ComparisonError::InvalidDocument),
    };
    let namespace = string(fields, "source_namespace")?;
    check(namespace == "wordfence-intelligence")?;
    check(string(fields, "source_format")? == "wordfence-v3-production")?;
    check(string(fields, "mapping_revision")? == "termivar-wordfence-v3-production/v1")?;

    let input = object(required(fields, "input")?)?;
    keys(input, &["byte_length", "sha256", "semantic_sha256"], &[])?;
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
    if profile.is_some() {
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
    check(
        external_source_counts_are_valid(parsed, associations)
            && selected
                .checked_add(excluded)
                .is_some_and(|value| value == associations)
            && evaluable
                .checked_add(unsupported)
                .is_some_and(|value| value == selected)
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
        let message = external_text(string(notice, "message")?, MAX_AUDIT_TEXT_BYTES, true)?;
        let party = text(notice, "party", MAX_IDENTIFIER_BYTES)?;
        check(valid_external_identifier(party, MAX_IDENTIFIER_BYTES))?;
        check(
            notices_by_id
                .insert(id.to_owned(), party.to_owned())
                .is_none(),
        )?;
        let notice_text = external_text(string(notice, "notice")?, MAX_AUDIT_TEXT_BYTES, true)?;
        let license = external_text(string(notice, "license")?, MAX_AUDIT_TEXT_BYTES, true)?;
        let license_url = text(notice, "license_url", MAX_AUDIT_TEXT_BYTES)?;
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
            interpretation_work = checked_accumulate_external_interpretation_work(
                interpretation_work,
                array(fields, "affected_ranges")?.len(),
                array(fields, "source_patched_versions")?.len(),
                MAX_WORDPRESS_EVALUATION_WORK,
            )
            .ok_or(ComparisonError::InvalidDocument)?;
        }
        let evaluation = external_evaluation(
            fields,
            namespace,
            components,
            &notices_by_id,
            &mut referenced_notices,
            profile,
            &profiled_resolutions,
        )?;
        check(identities.insert(evaluation.identity.clone()))?;
        imported_counts.record(&evaluation)?;
    }
    check(referenced_notices == notices_by_id.keys().cloned().collect())?;
    if profile.is_some() {
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
                && number(counts, "selected_ranges", MAX_WORDFENCE_V3_SELECTED_RANGES)?
                    == imported_counts.selected_ranges
                && number(counts, "evaluated_ranges", MAX_WORDFENCE_V3_SELECTED_RANGES)?
                    == imported_counts.evaluated_ranges
                && number(
                    counts,
                    "containing_ranges",
                    MAX_WORDFENCE_V3_SELECTED_RANGES,
                )? == imported_counts.containing_ranges
                && number(
                    counts,
                    "noncontaining_ranges",
                    MAX_WORDFENCE_V3_SELECTED_RANGES,
                )? == imported_counts.noncontaining_ranges
                && number(
                    counts,
                    "unsupported_ranges",
                    MAX_WORDFENCE_V3_SELECTED_RANGES,
                )? == imported_counts.unsupported_ranges
                && number(counts, "invalid_ranges", MAX_WORDFENCE_V3_SELECTED_RANGES)?
                    == imported_counts.invalid_ranges
                && number(
                    counts,
                    "not_evaluated_ranges",
                    MAX_WORDFENCE_V3_SELECTED_RANGES,
                )? == imported_counts.not_evaluated_ranges
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
    version_relation: &'static str,
    version_relation_reason: Option<&'static str>,
    range_relations: Vec<&'static str>,
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

fn external_evaluation(
    fields: &serde_json::Map<String, Value>,
    namespace: &str,
    components: &BTreeMap<String, ImportedWordPressComponent>,
    notices: &std::collections::BTreeMap<String, String>,
    referenced_notices: &mut std::collections::BTreeSet<String>,
    profile: Option<WordPressComparisonProfile>,
    profiled_resolutions: &BTreeMap<String, ProfiledResolution>,
) -> Result<ImportedExternalEvaluation, ComparisonError> {
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
    if profile.is_some() {
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
    } else {
        keys(fields, &common_fields, &[])?;
    }
    let key = object(required(fields, "key")?)?;
    keys(key, &["source_namespace", "upstream_id", "component"], &[])?;
    check(string(key, "source_namespace")? == namespace)?;
    let upstream_id = text(key, "upstream_id", MAX_IDENTIFIER_BYTES)?;
    check(valid_uuid(upstream_id))?;
    let component = component_identity(object(required(key, "component")?)?)?;
    let imported = components
        .get(&component)
        .ok_or(ComparisonError::InvalidDocument)?;

    external_text(
        text(fields, "title", MAX_WORDFENCE_V3_TITLE_BYTES)?,
        MAX_WORDFENCE_V3_TITLE_BYTES,
        false,
    )?;
    external_text(
        text(fields, "display_name", MAX_WORDFENCE_V3_NAME_BYTES)?,
        MAX_WORDFENCE_V3_NAME_BYTES,
        false,
    )?;
    boolean(fields, "informational")?;
    external_text(string(fields, "description")?, MAX_AUDIT_TEXT_BYTES, true)?;
    let references = unique_urls(fields, "references", MAX_WORDFENCE_V3_REFERENCES)?;
    let record_reference = optional_text(fields, "record_reference", MAX_AUDIT_TEXT_BYTES)?;
    let expected_record_reference = external_record_reference(&references);
    check(record_reference == expected_record_reference)?;
    optional_cwe(required(fields, "cwe")?)?;
    optional_cvss(required(fields, "cvss")?)?;
    let cve = optional_text(fields, "cve", MAX_WORDFENCE_V3_CVE_BYTES)?;
    if let Some(cve) = cve {
        check(valid_wordfence_cve(cve))?;
    }
    let cve_link = optional_text(fields, "cve_link", MAX_AUDIT_TEXT_BYTES)?;
    if let Some(link) = cve_link {
        check(cve.is_some())?;
        inert_url(link)?;
    }
    unique_text_array(
        fields,
        "researchers",
        MAX_WORDFENCE_V3_RESEARCHERS,
        MAX_WORDFENCE_V3_RESEARCHER_BYTES,
    )?;
    let source_dates = object(required(fields, "source_dates")?)?;
    keys(source_dates, &["published", "updated"], &[])?;
    optional_source_datetime(source_dates, "published")?;
    optional_source_datetime(source_dates, "updated")?;

    let ranges = array(fields, "affected_ranges")?;
    check(ranges.len() <= MAX_WORDFENCE_V3_RANGES)?;
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
        let from = external_range_endpoint(range, "from")?;
        let to = external_range_endpoint(range, "to")?;
        check(unique_ranges.insert((label, from, to)))?;
        imported_ranges.push((from, to));
    }

    boolean(fields, "source_patched")?;
    let source_patched_versions = unique_versions(
        fields,
        "source_patched_versions",
        MAX_WORDFENCE_V3_PATCHED_VERSIONS,
    )?;
    external_text(
        string(fields, "source_remediation")?,
        MAX_AUDIT_TEXT_BYTES,
        true,
    )?;
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
    let semantic_resolution = external_version_evidence_resolution(
        object(required(fields, "version_evidence_resolution")?)?,
        imported,
        profile,
        profiled_resolutions.get(&component),
    )?;
    let (version_relation, version_relation_reason, range_relations) = if let Some(profile) =
        profile
    {
        let semantic_resolution = semantic_resolution.ok_or(ComparisonError::InvalidDocument)?;
        let rendered_ranges = array(fields, "range_evaluations")?;
        check(rendered_ranges.len() == imported_ranges.len())?;
        let mut range_relations = Vec::with_capacity(rendered_ranges.len());
        let mut range_reasons = Vec::with_capacity(rendered_ranges.len());
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
                ],
            )?;
            let expected =
                external_profiled_range_result(source.0, source.1, profile, &semantic_resolution)?;
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
        let expected = expected_external_association_result(
            &semantic_resolution,
            &range_relations,
            &range_reasons,
            external_patched_version_conflicts(
                &source_patched_versions,
                &imported_ranges,
                profile,
            )?,
        )?;
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
        identity: format!("{namespace}:{upstream_id}:{component}"),
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
            || (kind == "declared" && version != "*" && valid_external_version(version)),
    )?;
    Ok((kind, version, inclusive))
}

fn optional_cwe(value: &Value) -> Result<(), ComparisonError> {
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
    external_text(string(fields, "description")?, MAX_AUDIT_TEXT_BYTES, true)?;
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
            && url.query().is_none()
            && url.fragment().is_none()
    })
}

fn unique_text_array(
    fields: &serde_json::Map<String, Value>,
    name: &str,
    limit: usize,
    text_limit: usize,
) -> Result<(), ComparisonError> {
    let values = array(fields, name)?;
    check(values.len() <= limit)?;
    let mut unique = std::collections::BTreeSet::new();
    for value in values {
        let value = value.as_str().ok_or(ComparisonError::InvalidDocument)?;
        external_text(value, text_limit, false)?;
        check(unique.insert(value))?;
    }
    Ok(())
}

fn unique_versions<'a>(
    fields: &'a serde_json::Map<String, Value>,
    name: &str,
    limit: usize,
) -> Result<Vec<&'a str>, ComparisonError> {
    let values = array(fields, name)?;
    check(values.len() <= limit)?;
    let mut unique = std::collections::BTreeSet::new();
    let mut validated = Vec::with_capacity(values.len());
    for value in values {
        let value = value.as_str().ok_or(ComparisonError::InvalidDocument)?;
        check(valid_external_version(value) && unique.insert(value))?;
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
    bounded_text(value, MAX_AUDIT_TEXT_BYTES)?;
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
