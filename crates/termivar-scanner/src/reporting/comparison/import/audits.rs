//! Exact optional audit wire inventories; these snapshots are not evidence authority.

use super::{
    boolean, check, digest, keys, number, object, optional_boolean, optional_text, optional_token,
    string, text, token, ComparisonError, ImportedItem, Value, MAX_IDENTIFIER_BYTES,
};
use std::collections::BTreeMap;

pub(super) const REST_CAPABILITY: &str = "api.rest-readonly-surface-observed@1";
const OPENAPI_CAPABILITY: &str = "api.openapi-contract-observed@1";
const AUTHORIZATION_CAPABILITY: &str = "authorization.resource-cross-principal-equivalence@1";

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
        _ => Err(ComparisonError::InvalidDocument),
    }
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
