//! Closed display-only V6 renewal input; never constructs credential authority.

use super::{
    array, boolean, check, digest, keys, number, object, optional_boolean, optional_http_status,
    optional_text, required, selected_object, string, token, validate_supplied_session_oauth_code,
    BTreeMap, BTreeSet, ComparisonError, ImportedItem, ImportedSuppliedSessionAudit, Value,
    MAX_IDENTIFIER_BYTES,
};

const SCHEMA: &str = "security.supplied-session-audit/v6";

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
            "oauth_refresh",
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
    check(string(fields, "schema")? == SCHEMA)?;
    check(number(fields, "selected_resource_count", 2)? == 2)?;
    let code = object(required(fields, "oauth_code")?)?;
    let refresh = object(required(fields, "oauth_refresh")?)?;
    keys(
        refresh,
        &[
            "profile",
            "idp_reference",
            "refresh_policy_reference",
            "after_resource_count",
            "max_attempts",
            "token_interpretation",
            "rotation_assurance",
            "server_replay_detection_established",
            "initial_epoch",
            "final_epoch",
            "request_attempt_count",
            "request_admitted_count",
            "response_completed_count",
            "credential_commit_count",
            "status",
            "body_state",
            "response_bytes",
            "configured_token_response_byte_limit",
            "token_response_validated",
            "response_scope_matched",
            "declared_token_lifetime_seconds",
            "replacement_refresh_token_received",
            "replacement_value_differs",
            "prior_credential_evidence_reference",
            "boundary_resource_evidence_reference",
            "boundary_health_evidence_reference",
            "evidence_reference",
            "health",
            "outcome",
        ],
        &[],
    )?;
    check(string(refresh, "profile")? == "scheduled-public-bearer-refresh/v1")?;
    check(string(refresh, "token_interpretation")? == "opaque_bearer_not_oidc_identity")?;
    check(
        string(refresh, "rotation_assurance")?
            == "replacement_value_observed_not_server_revocation",
    )?;
    check(!boolean(refresh, "server_replay_detection_established")?)?;
    check(digest(
        string(refresh, "idp_reference")?,
        "oauth-code-policy-sha256:",
    ))?;
    check(string(refresh, "idp_reference")? == string(code, "idp_reference")?)?;
    check(digest(
        string(refresh, "refresh_policy_reference")?,
        "oauth-refresh-policy-sha256:",
    ))?;
    check(number(refresh, "after_resource_count", 1)? == 1)?;
    check(number(refresh, "max_attempts", 1)? == 1)?;
    check(number(refresh, "initial_epoch", 1)? == 1)?;
    let attempted = number(refresh, "request_attempt_count", 1)?;
    let admitted = number(refresh, "request_admitted_count", attempted)?;
    let completed = number(refresh, "response_completed_count", admitted)?;
    let commits = number(refresh, "credential_commit_count", 1)?;
    let final_epoch = number(refresh, "final_epoch", 2)?;
    check(final_epoch == 1 + commits)?;
    check(boolean(fields, "refresh_performed")? == (commits == 1))?;
    let status = optional_http_status(refresh, "status")?;
    let body = token(
        refresh,
        "body_state",
        &["complete", "incomplete", "unavailable"],
    )?;
    let bytes = number(refresh, "response_bytes", u64::MAX)?;
    check(status.is_some() == (body != "unavailable"))?;
    check(completed == u64::from(body == "complete"))?;
    check((status.is_none() && bytes == 0) || admitted == 1)?;
    let configured = number(refresh, "configured_token_response_byte_limit", 32_768)?;
    let limit = number(fields, "response_byte_limit", 262_144)?;
    check(configured > 0 && configured <= limit && limit > 0)?;
    check(configured == number(code, "configured_token_response_byte_limit", 32_768)?)?;
    let validated = boolean(refresh, "token_response_validated")?;
    let scope = optional_boolean(refresh, "response_scope_matched")?;
    let replacement = optional_boolean(refresh, "replacement_refresh_token_received")?;
    let differs = optional_boolean(refresh, "replacement_value_differs")?;
    let lifetime = if required(refresh, "declared_token_lifetime_seconds")?.is_null() {
        None
    } else {
        let value = number(refresh, "declared_token_lifetime_seconds", 3_600)?;
        check(value > 0)?;
        Some(value)
    };
    check(if validated {
        admitted == 1
            && body == "complete"
            && status == Some(200)
            && bytes > 0
            && bytes <= configured
            && scope == Some(true)
            && replacement == Some(true)
            && differs == Some(true)
            && lifetime.is_some()
    } else {
        scope.is_none() && replacement.is_none() && differs.is_none() && lifetime.is_none()
    })?;
    let evidence = optional_text(refresh, "evidence_reference", MAX_IDENTIFIER_BYTES)?;
    check((commits == 1) == evidence.is_some() && commits <= u64::from(validated))?;
    if let Some(reference) = evidence {
        check(digest(
            reference,
            "supplied-session-oauth-refresh-evidence-sha256:",
        ))?;
    }
    let refresh_outcome = token(
        refresh,
        "outcome",
        &[
            "not_reached",
            "cancelled",
            "runtime_limit",
            "context_unavailable",
            "transport_failed",
            "throttled",
            "response_rejected",
            "commit_failed",
            "credential_committed",
        ],
    )?;
    check(match refresh_outcome {
        "not_reached" => {
            attempted == 0 && admitted == 0 && bytes == 0 && status.is_none() && !validated
        },
        "cancelled" | "runtime_limit" => commits == 0 && !validated,
        "context_unavailable" => status.is_none() && !validated,
        "transport_failed" => attempted == 1 && status.is_none() && !validated,
        "throttled" => admitted == 1 && status == Some(429) && !validated,
        "response_rejected" => admitted == 1 && status.is_some() && !validated,
        "commit_failed" => admitted == 1 && validated && commits == 0,
        "credential_committed" => admitted == 1 && validated && commits == 1,
        _ => false,
    })?;
    check(refresh_outcome == "credential_committed" || commits == 0)?;

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
            "oauth_refresh_unavailable",
        ],
    )?;
    let checkpoints = array(fields, "checkpoints")?;
    let resources = array(fields, "resources")?;
    check(checkpoints.len() <= 3 && resources.len() == 2)?;
    let mut normalized_checkpoints = Vec::with_capacity(checkpoints.len());
    for (index, checkpoint) in checkpoints.iter().enumerate() {
        let original = object(checkpoint)?;
        keys(
            original,
            &[
                "sequence",
                "phase",
                "after_subject_count",
                "evidence_reference",
                "outcome",
                "status",
                "body_state",
                "predicate",
                "response_bytes",
                "epoch",
            ],
            &[],
        )?;
        check(number(original, "epoch", 2)? == if commits == 1 && index > 1 { 2 } else { 1 })?;
        let mut normalized = original.clone();
        normalized.remove("epoch");
        normalized_checkpoints.push(Value::Object(normalized));
    }
    let mut normalized_resources = Vec::with_capacity(2);
    let mut resource_epochs = Vec::with_capacity(2);
    for (index, resource) in resources.iter().enumerate() {
        let original = object(resource)?;
        let epoch = number(original, "epoch", 2)?;
        check(epoch == if commits == 1 && index == 1 { 2 } else { 1 })?;
        let mut normalized = original.clone();
        normalized.insert("epoch".into(), Value::from(1));
        normalized_resources.push(Value::Object(normalized));
        resource_epochs.push(epoch);
    }
    let first = object(&resources[0])?;
    let second = object(&resources[1])?;
    let code_commits = number(code, "credential_commit_count", 1)?;
    if code_commits == 1 {
        check(optional_boolean(code, "refresh_token_returned")? == Some(true))?;
    } else {
        check(refresh_outcome == "not_reached")?;
    }
    let prior = optional_text(
        refresh,
        "prior_credential_evidence_reference",
        MAX_IDENTIFIER_BYTES,
    )?;
    let boundary_resource = optional_text(
        refresh,
        "boundary_resource_evidence_reference",
        MAX_IDENTIFIER_BYTES,
    )?;
    let boundary_health = optional_text(
        refresh,
        "boundary_health_evidence_reference",
        MAX_IDENTIFIER_BYTES,
    )?;
    if refresh_outcome != "not_reached" {
        check(
            code_commits == 1 && string(first, "outcome")? == "committed" && checkpoints.len() >= 2,
        )?;
        check(string(object(&checkpoints[1])?, "outcome")? == "healthy")?;
    }
    if attempted == 1 {
        check(
            prior.is_some()
                && prior == optional_text(code, "evidence_reference", MAX_IDENTIFIER_BYTES)?,
        )?;
        check(
            boundary_resource.is_some()
                && boundary_resource
                    == optional_text(first, "evidence_reference", MAX_IDENTIFIER_BYTES)?,
        )?;
        let boundary = checkpoints.get(1).ok_or(ComparisonError::InvalidDocument)?;
        check(
            boundary_health.is_some()
                && boundary_health
                    == optional_text(
                        object(boundary)?,
                        "evidence_reference",
                        MAX_IDENTIFIER_BYTES,
                    )?,
        )?;
    } else {
        check(prior.is_none() && boundary_resource.is_none() && boundary_health.is_none())?;
    }
    if commits == 0 {
        check(string(second, "outcome")? == "not_dispatched" && checkpoints.len() <= 2)?;
    }

    let mut references = BTreeSet::new();
    for reference in [
        optional_text(code, "evidence_reference", MAX_IDENTIFIER_BYTES)?,
        evidence,
    ]
    .into_iter()
    .flatten()
    {
        check(references.insert(reference.to_owned()))?;
    }
    for row in checkpoints.iter().chain(resources) {
        if let Some(reference) =
            optional_text(object(row)?, "evidence_reference", MAX_IDENTIFIER_BYTES)?
        {
            check(references.insert(reference.to_owned()))?;
        }
    }
    let (health_outcome, health_bytes) = if required(refresh, "health")?.is_null() {
        (None, 0)
    } else {
        check(commits == 1)?;
        let original = object(required(refresh, "health")?)?;
        check(number(original, "epoch", 2)? == 2 && string(original, "phase")? == "renewal")?;
        check(
            number(original, "sequence", 2)? == 2
                && number(original, "after_subject_count", 1)? == 1,
        )?;
        let mut normalized = original.clone();
        normalized.remove("epoch");
        normalized.insert("sequence".into(), Value::from(1));
        normalized.insert("phase".into(), Value::from("subject_boundary"));
        let normalized = Value::Object(normalized);
        let validated = super::validate_supplied_session_checkpoint(&normalized, 1, 2)?;
        if let Some(reference) = validated.evidence_reference {
            check(references.insert(reference.to_owned()))?;
        }
        (Some(validated.outcome.to_owned()), validated.response_bytes)
    };
    check(checkpoints.len() + usize::from(health_outcome.is_some()) <= 4)?;
    if commits == 0 {
        check(health_outcome.is_none())?;
    }
    if string(second, "outcome")? != "not_dispatched" {
        check(commits == 1 && health_outcome.as_deref() == Some("healthy"))?;
    }
    let renewal_health_stopped = commits == 1 && health_outcome.as_deref() != Some("healthy");
    if renewal_health_stopped {
        check(checkpoints.len() == 2 && string(second, "outcome")? == "not_dispatched")?;
        check(match health_outcome.as_deref() {
            Some("unhealthy") => outcome == "session_lost",
            Some("indeterminate") => matches!(
                outcome,
                "resource_unavailable" | "runtime_limit" | "cancelled"
            ),
            None => matches!(
                outcome,
                "resource_unavailable" | "runtime_limit" | "cancelled"
            ),
            _ => false,
        })?;
        if matches!(outcome, "runtime_limit" | "cancelled") && health_outcome.is_some() {
            check(required(object(required(refresh, "health")?)?, "status")?.is_null())?;
        }
    }
    check(match refresh_outcome {
        "cancelled" => outcome == "cancelled",
        "runtime_limit" => outcome == "runtime_limit",
        "context_unavailable"
        | "transport_failed"
        | "throttled"
        | "response_rejected"
        | "commit_failed" => outcome == "oauth_refresh_unavailable",
        "credential_committed" => {
            outcome != "oauth_refresh_unavailable" && outcome != "oauth_code_exchange_unavailable"
        },
        "not_reached" => outcome != "oauth_refresh_unavailable" && outcome != "complete",
        _ => false,
    })?;
    if outcome == "complete" {
        check(commits == 1 && health_outcome.as_deref() == Some("healthy"))?;
    }
    let total_requests = number(fields, "dispatched_request_count", 8)?;
    let total_bytes = number(fields, "response_bytes", u64::MAX)?;
    check(boolean(fields, "response_byte_limit_exceeded")? == (total_bytes > limit))?;
    if outcome == "complete" {
        check(total_requests == 8)?;
    }
    let normalized_requests = total_requests
        .checked_sub(admitted)
        .and_then(|count| count.checked_sub(u64::from(health_outcome.is_some())))
        .ok_or(ComparisonError::InvalidDocument)?;
    let normalized_bytes = total_bytes
        .checked_sub(bytes)
        .and_then(|count| count.checked_sub(health_bytes))
        .ok_or(ComparisonError::InvalidDocument)?;
    // Validate the unchanged initial-code grammar and common health/resource
    // grammar through a bounded projection. Stored input is never rewritten,
    // and original epochs/bindings are restored below, never imported as V5 authority.
    let mut common = fields.clone();
    common.insert(
        "schema".into(),
        Value::from("security.supplied-session-audit/v5"),
    );
    common.remove("oauth_refresh");
    common.insert("refresh_performed".into(), Value::from(false));
    common.insert("checkpoints".into(), Value::Array(normalized_checkpoints));
    common.insert("resources".into(), Value::Array(normalized_resources));
    common.insert(
        "dispatched_request_count".into(),
        Value::from(normalized_requests),
    );
    common.insert("response_bytes".into(), Value::from(normalized_bytes));
    common.insert(
        "response_byte_limit_exceeded".into(),
        Value::from(normalized_bytes > limit),
    );
    if outcome == "oauth_refresh_unavailable" || renewal_health_stopped {
        common.insert("outcome".into(), Value::from("runtime_limit"));
    }
    let mut imported = validate_supplied_session_oauth_code(&Value::Object(common), items)?;
    let code_policy = object(&imported.context)?
        .get("oauth_code_policy")
        .ok_or(ComparisonError::InvalidDocument)?
        .clone();
    let refresh_policy = selected_object(
        refresh,
        &[
            "profile",
            "idp_reference",
            "refresh_policy_reference",
            "after_resource_count",
            "max_attempts",
            "token_interpretation",
            "rotation_assurance",
            "server_replay_detection_established",
            "configured_token_response_byte_limit",
        ],
        &[],
    )?;
    let epoch = Value::from(final_epoch);
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
            ("oauth_refresh_policy", Some(&refresh_policy)),
        ],
    )?;
    imported.health_and_coverage = selected_object(
        fields,
        &[
            "outcome",
            "coverage",
            "oauth_code",
            "oauth_refresh",
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
    for (index, resource) in resources.iter().enumerate() {
        let reference = string(object(resource)?, "resource_reference")?;
        let binding = imported
            .resources
            .get_mut(reference)
            .ok_or(ComparisonError::InvalidDocument)?;
        binding.epoch = resource_epochs[index];
    }
    Ok(imported)
}
