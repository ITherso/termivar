//! Closed display-only V7 input. Saved assertions never mint a callback,
//! credential, listener, dispatch permit or knowledge-authority receipt.

use super::{
    array, boolean, check, digest, keys, number, object, optional_boolean, optional_http_status,
    optional_text, required, selected_object, string, token, validate_supplied_session, BTreeMap,
    ComparisonError, ImportedItem, ImportedSuppliedSessionAudit, Value, MAX_IDENTIFIER_BYTES,
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
            "oauth_authorization",
            "oauth_token_exchange",
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
    check(string(fields, "schema")? == "security.supplied-session-audit/v7")?;
    check(string(fields, "credential_acquisition")? == "client_initiated_oauth_pkce")?;
    check(string(fields, "credential_mechanism")? == "authorization_header")?;
    let selected = number(fields, "selected_resource_count", 3)?;
    check(selected > 0)?;
    let auth = object(required(fields, "oauth_authorization")?)?;
    keys(
        auth,
        &[
            "profile",
            "authorization_policy_reference",
            "configured_wait_ms",
            "reservation_count",
            "listener_bound",
            "handoff_written",
            "accepted_connection_count",
            "completed_form_count",
            "state_validated",
            "issuer_validated",
            "callback_commit_count",
            "ingress_bytes",
            "reply_bytes_written",
            "elapsed_ms",
            "listener_closed",
            "unknown_parameter_count",
            "provider_error_class",
            "evidence_reference",
            "oidc_nonce_validation_performed",
            "oidc_identity_validation_performed",
            "token_signature_validation_performed",
            "outcome",
        ],
        &[],
    )?;
    check(string(auth, "profile")? == "loopback-form-post-state/v1")?;
    check(digest(
        string(auth, "authorization_policy_reference")?,
        "oauth-authorization-policy-sha256:",
    ))?;
    check(number(auth, "configured_wait_ms", 30000)? > 0)?;
    number(auth, "elapsed_ms", u64::MAX)?;
    let reserved = number(auth, "reservation_count", 1)?;
    let accepted = number(auth, "accepted_connection_count", reserved)?;
    let completed_form = number(auth, "completed_form_count", accepted)?;
    let state = boolean(auth, "state_validated")?;
    check(state == boolean(auth, "issuer_validated")? && (!state || completed_form == 1))?;
    let callback_commits = number(auth, "callback_commit_count", u64::from(state))?;
    let bound = boolean(auth, "listener_bound")?;
    let handoff = boolean(auth, "handoff_written")?;
    check((!handoff || bound) && (!bound || reserved == 1) && (accepted == 0 || handoff))?;
    check(boolean(auth, "listener_closed")?)?;
    let ingress = number(auth, "ingress_bytes", 12289)?;
    let reply = number(auth, "reply_bytes_written", 216)?;
    check(
        (ingress == 0 || accepted == 1)
            && (completed_form == 0 || ingress > 0)
            && (reply == 0 || completed_form == 1),
    )?;
    check(number(auth, "unknown_parameter_count", 16)? == 0 || state)?;
    for field in [
        "oidc_nonce_validation_performed",
        "oidc_identity_validation_performed",
        "token_signature_validation_performed",
    ] {
        check(!boolean(auth, field)?)?;
    }
    let callback_evidence = optional_text(auth, "evidence_reference", MAX_IDENTIFIER_BYTES)?;
    check(callback_evidence.is_some() == (callback_commits == 1))?;
    if let Some(e) = callback_evidence {
        check(digest(
            e,
            "supplied-session-oauth-authorization-evidence-sha256:",
        ))?;
    }
    let provider_error = optional_text(auth, "provider_error_class", 64)?;
    if let Some(e) = provider_error {
        check(matches!(
            e,
            "invalid_request"
                | "unauthorized_client"
                | "access_denied"
                | "unsupported_response_type"
                | "invalid_scope"
                | "server_error"
                | "temporarily_unavailable"
                | "other"
        ))?;
    }
    let auth_outcome = token(
        auth,
        "outcome",
        &[
            "not_started",
            "runtime_limit",
            "cancelled",
            "listener_unavailable",
            "handoff_failed",
            "reception_failed",
            "response_rejected",
            "provider_error",
            "commit_failed",
            "callback_committed",
        ],
    )?;
    check(
        (provider_error.is_some() == (auth_outcome == "provider_error"))
            && (provider_error.is_none() || state)
            && ((callback_commits == 1) == (auth_outcome == "callback_committed")),
    )?;
    check(match auth_outcome {
        "not_started" => {
            reserved == 0
                && !bound
                && !handoff
                && accepted == 0
                && completed_form == 0
                && !state
                && ingress == 0
                && reply == 0
        },
        "listener_unavailable" => reserved == 1 && !bound && !handoff && accepted == 0,
        "handoff_failed" => reserved == 1 && bound && !handoff && accepted == 0,
        "reception_failed" => reserved == 1 && handoff && !state,
        "response_rejected" => reserved == 1 && handoff && accepted == 1 && !state,
        "provider_error" => completed_form == 1 && state && callback_commits == 0,
        "callback_committed" => completed_form == 1 && state && callback_commits == 1,
        "commit_failed" => callback_commits == 0,
        "runtime_limit" | "cancelled" => callback_commits == 0 && !state,
        _ => false,
    })?;

    let exchange = object(required(fields, "oauth_token_exchange")?)?;
    keys(
        exchange,
        &[
            "profile",
            "pkce_assurance",
            "transport_profile",
            "idp_reference",
            "token_interpretation",
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
    check(string(exchange, "profile")? == "client-initiated-public-code-s256-bearer/v1")?;
    check(string(exchange, "pkce_assurance")? == "client_generated_s256_not_remote_enforcement")?;
    check(string(exchange, "token_interpretation")? == "opaque_bearer_not_oidc_identity")?;
    token(
        exchange,
        "transport_profile",
        &["verified-https/v1", "owned-numeric-loopback-http/v1"],
    )?;
    check(digest(
        string(exchange, "idp_reference")?,
        "oauth-code-policy-sha256:",
    ))?;
    let attempted = number(exchange, "request_attempt_count", 1)?;
    let admitted = number(exchange, "request_admitted_count", attempted)?;
    let completed = number(exchange, "response_completed_count", admitted)?;
    let commits = number(exchange, "credential_commit_count", 1)?;
    check(attempted == 0 || callback_commits == 1)?;
    check(boolean(exchange, "verifier_in_admitted_request")? == (admitted == 1))?;
    let status = optional_http_status(exchange, "status")?;
    let body = token(
        exchange,
        "body_state",
        &["unavailable", "incomplete", "complete"],
    )?;
    let bytes = number(exchange, "response_bytes", u64::MAX)?;
    check(
        status.is_some() == (body != "unavailable")
            && completed == u64::from(body == "complete")
            && ((status.is_none() && bytes == 0) || admitted == 1),
    )?;
    let limit = number(fields, "response_byte_limit", 262144)?;
    let configured = number(exchange, "configured_token_response_byte_limit", 32768)?;
    check(limit > 0 && configured > 0 && configured <= limit)?;
    let validated = boolean(exchange, "token_response_validated")?;
    let scope = optional_boolean(exchange, "response_scope_matched")?;
    let refresh = optional_boolean(exchange, "refresh_token_returned")?;
    let lifetime = if required(exchange, "declared_token_lifetime_seconds")?.is_null() {
        None
    } else {
        let n = number(exchange, "declared_token_lifetime_seconds", 3600)?;
        check(n > 0)?;
        Some(n)
    };
    check(if validated {
        admitted == 1
            && body == "complete"
            && status == Some(200)
            && bytes > 0
            && bytes <= configured
            && scope == Some(true)
            && refresh.is_some()
            && lifetime.is_some()
    } else {
        scope.is_none() && refresh.is_none() && lifetime.is_none()
    })?;
    let evidence = optional_text(exchange, "evidence_reference", MAX_IDENTIFIER_BYTES)?;
    check(commits <= u64::from(validated) && ((commits == 1) == evidence.is_some()))?;
    if let Some(e) = evidence {
        check(digest(e, "supplied-session-oauth-code-evidence-sha256:"))?;
    }
    let exchange_outcome = token(
        exchange,
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
    check(match exchange_outcome {
        "not_dispatched" => {
            attempted == 0 && admitted == 0 && status.is_none() && bytes == 0 && !validated
        },
        "cancelled" | "runtime_limit" => !validated && commits == 0,
        "grant_unavailable" => attempted == 1 && admitted == 0 && status.is_none() && bytes == 0,
        "transport_failed" => attempted == 1 && status.is_none() && !validated,
        "throttled" => admitted == 1 && status == Some(429) && !validated,
        "response_rejected" => admitted == 1 && status.is_some() && !validated,
        "commit_failed" => admitted == 1 && validated && commits == 0,
        "credential_committed" => admitted == 1 && validated && commits == 1,
        _ => false,
    })?;
    let outcome = string(fields, "outcome")?;
    if commits == 0 {
        check(
            array(fields, "checkpoints")?.is_empty()
                && number(fields, "dispatched_resource_count", 0)? == 0
                && number(fields, "committed_resource_count", 0)? == 0
                && string(fields, "coverage")? == "none",
        )?;
        check(callback_commits != 0 || exchange_outcome == "not_dispatched")?;
        check(if callback_commits == 0 {
            match auth_outcome {
                "cancelled" => outcome == "cancelled",
                "runtime_limit" => outcome == "runtime_limit",
                _ => outcome == "oauth_code_exchange_unavailable",
            }
        } else {
            match exchange_outcome {
                "cancelled" => outcome == "cancelled",
                "runtime_limit" => outcome == "runtime_limit",
                _ => outcome == "oauth_code_exchange_unavailable",
            }
        })?;
    } else {
        check(outcome != "oauth_code_exchange_unavailable")?;
    }
    let requests = number(fields, "dispatched_request_count", 8)?;
    check(requests <= 2 + 2 * selected && requests + reserved <= 9)?;
    let total_bytes = number(fields, "response_bytes", u64::MAX)?;
    check(boolean(fields, "response_byte_limit_exceeded")? == (total_bytes > limit))?;
    let common_requests = requests
        .checked_sub(admitted)
        .ok_or(ComparisonError::InvalidDocument)?;
    let common_bytes = total_bytes
        .checked_sub(bytes)
        .ok_or(ComparisonError::InvalidDocument)?;
    let mut common = fields.clone();
    common.insert(
        "schema".into(),
        Value::from("security.supplied-session-audit/v1"),
    );
    common.remove("credential_acquisition");
    common.remove("oauth_authorization");
    common.remove("oauth_token_exchange");
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
    // Reuse only the old display grammar after checking the V7 states above.
    // No stored bytes are rewritten and no runtime authority is constructed.
    let mut imported = validate_supplied_session(&Value::Object(common), items)?;
    let auth_policy = selected_object(
        auth,
        &[
            "profile",
            "authorization_policy_reference",
            "configured_wait_ms",
        ],
        &[],
    )?;
    let code_policy = selected_object(
        exchange,
        &[
            "profile",
            "pkce_assurance",
            "transport_profile",
            "idp_reference",
            "token_interpretation",
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
            ("session_epoch", Some(&Value::from(1))),
            ("oauth_authorization_policy", Some(&auth_policy)),
            ("oauth_code_policy", Some(&code_policy)),
        ],
    )?;
    imported.health_and_coverage = selected_object(
        fields,
        &[
            "outcome",
            "coverage",
            "oauth_authorization",
            "oauth_token_exchange",
            "checkpoints",
            "resources",
        ],
        &[],
    )?;
    // Timing and per-run proof references do not change semantic coverage.
    if let Some(authorization) = imported
        .health_and_coverage
        .get_mut("oauth_authorization")
        .and_then(Value::as_object_mut)
    {
        authorization.remove("elapsed_ms");
        authorization.remove("evidence_reference");
    }
    if let Some(exchange) = imported
        .health_and_coverage
        .get_mut("oauth_token_exchange")
        .and_then(Value::as_object_mut)
    {
        exchange.remove("evidence_reference");
    }
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
        &[
            ("callback_reservations", Some(&Value::from(reserved))),
            ("callback_ingress_bytes", Some(&Value::from(ingress))),
        ],
    )?;
    Ok(imported)
}
