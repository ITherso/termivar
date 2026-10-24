//! Closed display-only V5 input; never deserialized into runtime authority.

use super::{
    array, boolean, check, digest, keys, number, object, optional_boolean, optional_http_status,
    optional_text, required, selected_object, string, token, validate_supplied_session, BTreeMap,
    ComparisonError, ImportedItem, ImportedSuppliedSessionAudit, Value, MAX_IDENTIFIER_BYTES,
    SUPPLIED_SESSION_CAPABILITY,
};

pub(super) fn validate(
    value: &Value,
    items: &BTreeMap<String, ImportedItem>,
) -> Result<ImportedSuppliedSessionAudit, ComparisonError> {
    let fields = object(value)?;
    keys(
        fields,
        &[
            "schema",
            "capability_id",
            "policy_reference",
            "application_reference",
            "principal_reference",
            "principal_alias",
            "principal_assurance",
            "credential_mechanism",
            "credential_acquisition",
            "oauth_code",
            "health_oracle",
            "outcome",
            "coverage",
            "checkpoints",
            "resources",
            "selected_resource_count",
            "dispatched_resource_count",
            "committed_resource_count",
            "dispatched_request_count",
            "response_bytes",
            "response_byte_limit",
            "response_byte_limit_exceeded",
            "refresh_performed",
            "anonymous_fallback_performed",
            "continuous_authentication_established",
            "exploit_execution",
            "impact_validation",
        ],
        &[],
    )?;
    check(string(fields, "schema")? == "security.supplied-session-audit/v5")?;
    check(string(fields, "capability_id")? == SUPPLIED_SESSION_CAPABILITY)?;
    check(string(fields, "credential_acquisition")? == "imported_oauth_code_pkce")?;
    check(string(fields, "credential_mechanism")? == "authorization_header")?;
    let selected = number(fields, "selected_resource_count", 3)?;
    check(selected >= 1)?;
    let code = object(required(fields, "oauth_code")?)?;
    keys(
        code,
        &[
            "profile",
            "transport_profile",
            "idp_reference",
            "transaction_context_assurance",
            "pkce_assurance",
            "token_interpretation",
            "authorization_initiated",
            "browser_callback_received",
            "state_nonce_verified",
            "oidc_identity_validation_performed",
            "token_signature_validation_performed",
            "request_attempt_count",
            "request_admitted_count",
            "response_completed_count",
            "credential_commit_count",
            "verifier_in_admitted_request",
            "status",
            "body_state",
            "response_bytes",
            "configured_token_response_byte_limit",
            "token_response_validated",
            "response_scope_matched",
            "declared_token_lifetime_seconds",
            "refresh_token_returned",
            "evidence_reference",
            "outcome",
        ],
        &[],
    )?;
    for (field, expected) in [
        ("profile", "external-public-code-s256-bearer/v1"),
        (
            "transaction_context_assurance",
            "operator_declared_external_transaction",
        ),
        (
            "pkce_assurance",
            "imported_s256_context_not_remote_enforcement",
        ),
        ("token_interpretation", "opaque_bearer_not_oidc_identity"),
    ] {
        check(string(code, field)? == expected)?;
    }
    token(
        code,
        "transport_profile",
        &["verified-https/v1", "owned-numeric-loopback-http/v1"],
    )?;
    check(digest(
        string(code, "idp_reference")?,
        "oauth-code-policy-sha256:",
    ))?;
    for field in [
        "authorization_initiated",
        "browser_callback_received",
        "state_nonce_verified",
        "oidc_identity_validation_performed",
        "token_signature_validation_performed",
    ] {
        check(!boolean(code, field)?)?;
    }
    let attempted = number(code, "request_attempt_count", 1)?;
    let admitted = number(code, "request_admitted_count", attempted)?;
    let completed = number(code, "response_completed_count", admitted)?;
    let commits = number(code, "credential_commit_count", 1)?;
    check(boolean(code, "verifier_in_admitted_request")? == (admitted == 1))?;
    let status = optional_http_status(code, "status")?;
    let body_state = token(
        code,
        "body_state",
        &["complete", "incomplete", "unavailable"],
    )?;
    let has_response = body_state != "unavailable";
    let complete = body_state == "complete";
    check(status.is_some() == has_response && completed == u64::from(complete))?;
    let bytes = number(code, "response_bytes", u64::MAX)?;
    check((!has_response && bytes == 0) || admitted == 1)?;
    let configured_limit = number(code, "configured_token_response_byte_limit", 32_768)?;
    check(
        configured_limit > 0 && configured_limit <= number(fields, "response_byte_limit", 262_144)?,
    )?;
    let validated = boolean(code, "token_response_validated")?;
    let scope = optional_boolean(code, "response_scope_matched")?;
    let refresh = optional_boolean(code, "refresh_token_returned")?;
    let lifetime = if required(code, "declared_token_lifetime_seconds")?.is_null() {
        None
    } else {
        let seconds = number(code, "declared_token_lifetime_seconds", 3_600)?;
        check(seconds >= 1)?;
        Some(seconds)
    };
    check(if validated {
        complete
            && status == Some(200)
            && bytes > 0
            && bytes <= configured_limit
            && scope == Some(true)
            && refresh.is_some()
            && lifetime.is_some()
    } else {
        scope.is_none() && refresh.is_none() && lifetime.is_none()
    })?;
    let evidence = optional_text(code, "evidence_reference", MAX_IDENTIFIER_BYTES)?;
    check((commits == 1) == evidence.is_some() && commits <= u64::from(validated))?;
    if let Some(reference) = evidence {
        check(digest(
            reference,
            "supplied-session-oauth-code-evidence-sha256:",
        ))?;
    }
    let code_outcome = token(
        code,
        "outcome",
        &[
            "not_dispatched",
            "cancelled",
            "runtime_limit",
            "grant_unavailable",
            "transport_failed",
            "throttled",
            "response_rejected",
            "commit_failed",
            "credential_committed",
        ],
    )?;
    check(match code_outcome {
        "not_dispatched" => attempted == 0 && !has_response && bytes == 0 && !validated,
        "cancelled" | "runtime_limit" => !validated && commits == 0,
        "grant_unavailable" => attempted == 1 && admitted == 0 && !has_response && bytes == 0,
        "transport_failed" => attempted == 1 && !has_response && !validated,
        "throttled" => admitted == 1 && status == Some(429) && !validated,
        "response_rejected" => admitted == 1 && has_response && !validated,
        "commit_failed" => admitted == 1 && validated && commits == 0,
        "credential_committed" => admitted == 1 && validated && commits == 1,
        _ => false,
    })?;
    let outcome = token(
        fields,
        "outcome",
        &[
            "complete",
            "startup_unhealthy",
            "session_lost",
            "resource_unavailable",
            "runtime_limit",
            "cancelled",
            "oauth_code_exchange_unavailable",
        ],
    )?;
    if commits == 0 {
        check(array(fields, "checkpoints")?.is_empty())?;
        check(
            number(fields, "dispatched_resource_count", 0)? == 0
                && number(fields, "committed_resource_count", 0)? == 0,
        )?;
        check(string(fields, "coverage")? == "none")?;
        check(match code_outcome {
            "cancelled" => outcome == "cancelled",
            "runtime_limit" => outcome == "runtime_limit",
            "grant_unavailable" | "transport_failed" | "throttled" | "response_rejected"
            | "commit_failed" => outcome == "oauth_code_exchange_unavailable",
            _ => false,
        })?;
    } else {
        check(outcome != "oauth_code_exchange_unavailable")?;
    }
    let total_requests = number(fields, "dispatched_request_count", 9)?;
    let total_bytes = number(fields, "response_bytes", u64::MAX)?;
    let limit = number(fields, "response_byte_limit", 262_144)?;
    check(limit > 0 && boolean(fields, "response_byte_limit_exceeded")? == (total_bytes > limit))?;
    let common_requests = total_requests
        .checked_sub(admitted)
        .ok_or(ComparisonError::InvalidDocument)?;
    let common_bytes = total_bytes
        .checked_sub(bytes)
        .ok_or(ComparisonError::InvalidDocument)?;
    check(total_requests <= 2 + 2 * selected)?;
    // A bounded in-memory validation projection reuses the historical exact
    // health/resource grammar. It never rewrites saved bytes or mints a V1 run.
    let mut common = fields.clone();
    common.insert(
        "schema".into(),
        Value::from("security.supplied-session-audit/v1"),
    );
    common.remove("credential_acquisition");
    common.remove("oauth_code");
    common.insert(
        "dispatched_request_count".into(),
        Value::from(common_requests),
    );
    common.insert("response_bytes".into(), Value::from(common_bytes));
    common.insert(
        "response_byte_limit_exceeded".into(),
        Value::from(common_bytes > limit),
    );
    if outcome == "oauth_code_exchange_unavailable" {
        common.insert("outcome".into(), Value::from("runtime_limit"));
    }
    let mut imported = validate_supplied_session(&Value::Object(common), items)?;
    let epoch = Value::from(1);
    let code_policy = selected_object(
        code,
        &[
            "profile",
            "transport_profile",
            "idp_reference",
            "transaction_context_assurance",
            "pkce_assurance",
            "token_interpretation",
            "authorization_initiated",
            "browser_callback_received",
            "state_nonce_verified",
            "oidc_identity_validation_performed",
            "token_signature_validation_performed",
            "configured_token_response_byte_limit",
        ],
        &[],
    )?;
    imported.context = selected_object(
        fields,
        &[
            "schema",
            "capability_id",
            "policy_reference",
            "application_reference",
            "principal_reference",
            "principal_alias",
            "principal_assurance",
            "credential_mechanism",
            "credential_acquisition",
            "health_oracle",
        ],
        &[
            ("session_epoch", Some(&epoch)),
            ("oauth_code_policy", Some(&code_policy)),
        ],
    )?;
    imported.health_and_coverage = selected_object(
        fields,
        &[
            "outcome",
            "coverage",
            "oauth_code",
            "checkpoints",
            "resources",
        ],
        &[],
    )?;
    imported.accounting = selected_object(
        fields,
        &[
            "selected_resource_count",
            "dispatched_resource_count",
            "committed_resource_count",
            "dispatched_request_count",
            "response_bytes",
            "response_byte_limit",
            "response_byte_limit_exceeded",
            "refresh_performed",
            "anonymous_fallback_performed",
            "continuous_authentication_established",
            "exploit_execution",
            "impact_validation",
        ],
        &[],
    )?;
    Ok(imported)
}
