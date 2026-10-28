//! Literal synthetic saved documents, independent of the writer/runtime.
//! Shape validation is not source authentication or executable authority.

use super::*;

fn audit() -> Value {
    let mut v = supplied_session_audit();
    v["schema"] = json!("security.supplied-session-audit/v7");
    v["credential_acquisition"] = json!("client_initiated_oauth_pkce");
    v["dispatched_request_count"] = json!(4);
    v["response_bytes"] = json!(149);
    v["oauth_authorization"] = json!({
        "profile":"loopback-form-post-state/v1",
        "authorization_policy_reference":format!("oauth-authorization-policy-sha256:{}","c".repeat(64)),
        "configured_wait_ms":2000,"reservation_count":1,"listener_bound":true,"handoff_written":true,
        "accepted_connection_count":1,"completed_form_count":1,"state_validated":true,"issuer_validated":true,
        "callback_commit_count":1,"ingress_bytes":512,"reply_bytes_written":216,"elapsed_ms":17,"listener_closed":true,
        "unknown_parameter_count":0,"provider_error_class":null,
        "evidence_reference":format!("supplied-session-oauth-authorization-evidence-sha256:{}","d".repeat(64)),
        "oidc_nonce_validation_performed":false,"oidc_identity_validation_performed":false,"token_signature_validation_performed":false,
        "outcome":"callback_committed"
    });
    v["oauth_token_exchange"] = json!({
        "profile":"client-initiated-public-code-s256-bearer/v1",
        "pkce_assurance":"client_generated_s256_not_remote_enforcement",
        "transport_profile":"verified-https/v1",
        "idp_reference":format!("oauth-code-policy-sha256:{}","a".repeat(64)),
        "token_interpretation":"opaque_bearer_not_oidc_identity",
        "request_attempt_count":1,"request_admitted_count":1,"response_completed_count":1,"credential_commit_count":1,
        "verifier_in_admitted_request":true,"status":200,"body_state":"complete","response_bytes":90,
        "configured_token_response_byte_limit":8192,"token_response_validated":true,"response_scope_matched":true,
        "declared_token_lifetime_seconds":60,"refresh_token_returned":false,
        "evidence_reference":format!("supplied-session-oauth-code-evidence-sha256:{}","b".repeat(64)),
        "outcome":"credential_committed"
    });
    v
}

fn rejected() -> Value {
    let mut v = audit();
    v["outcome"] = json!("oauth_code_exchange_unavailable");
    v["coverage"] = json!("none");
    v["checkpoints"] = json!([]);
    v["dispatched_request_count"] = json!(0);
    v["response_bytes"] = json!(0);
    v["dispatched_resource_count"] = json!(0);
    v["committed_resource_count"] = json!(0);
    v["resources"][0]["evidence_reference"] = Value::Null;
    v["resources"][0]["status"] = Value::Null;
    v["resources"][0]["outcome"] = json!("not_dispatched");
    v["resources"][0]["response_bytes"] = json!(0);
    for key in ["state_validated", "issuer_validated"] {
        v["oauth_authorization"][key] = json!(false);
    }
    v["oauth_authorization"]["callback_commit_count"] = json!(0);
    v["oauth_authorization"]["evidence_reference"] = Value::Null;
    v["oauth_authorization"]["outcome"] = json!("response_rejected");
    for key in [
        "request_attempt_count",
        "request_admitted_count",
        "response_completed_count",
        "credential_commit_count",
        "response_bytes",
    ] {
        v["oauth_token_exchange"][key] = json!(0);
    }
    for key in ["verifier_in_admitted_request", "token_response_validated"] {
        v["oauth_token_exchange"][key] = json!(false);
    }
    for key in [
        "status",
        "response_scope_matched",
        "declared_token_lifetime_seconds",
        "refresh_token_returned",
        "evidence_reference",
    ] {
        v["oauth_token_exchange"][key] = Value::Null;
    }
    v["oauth_token_exchange"]["body_state"] = json!("unavailable");
    v["oauth_token_exchange"]["outcome"] = json!("not_dispatched");
    v
}

fn document(audit: Value) -> Value {
    let mut v = report(Vec::new());
    v["supplied_session"] = audit;
    v
}

#[test]
fn oauth_authorization_saved_reader_accepts_positive_and_selected_empty_audits() {
    for a in [audit(), rejected()] {
        let v = document(a);
        let comparison = compare(&v, &v);
        assert_eq!(
            comparison["supplied_session_comparison"]["status"],
            json!("compared_within_same_declared_context")
        );
        assert_eq!(comparison["only_in_after"], json!([]));
        assert_eq!(comparison["only_in_before"], json!([]));
        assert_eq!(comparison["changed"], json!([]));
        let limits = comparison["supplied_session_comparison"]["interpretation_limits"].to_string();
        assert!(limits.contains("callback facts were recorded"));
        assert!(!limits.contains("Only the recorded explicitly scheduled renewal was assessed"));
    }
}

#[test]
fn oauth_authorization_saved_reader_rejects_missing_wrong_typed_and_forged_boundaries() {
    let original = audit();
    for section in ["oauth_authorization", "oauth_token_exchange"] {
        let fields: Vec<_> = original[section]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        for field in fields {
            let mut missing = document(original.clone());
            missing["supplied_session"][section]
                .as_object_mut()
                .unwrap()
                .remove(&field);
            reject(&missing);
            let mut wrong = document(original.clone());
            wrong["supplied_session"][section][&field] = json!([]);
            reject(&wrong);
        }
    }
    for (section, field, value) in [
        ("oauth_authorization", "reservation_count", json!(true)),
        ("oauth_authorization", "reservation_count", json!(0)),
        ("oauth_authorization", "listener_bound", json!(false)),
        ("oauth_authorization", "handoff_written", json!(false)),
        ("oauth_authorization", "listener_closed", json!(false)),
        ("oauth_authorization", "state_validated", json!(false)),
        ("oauth_authorization", "issuer_validated", json!(false)),
        ("oauth_authorization", "ingress_bytes", json!(0)),
        ("oauth_authorization", "ingress_bytes", json!(12290)),
        ("oauth_authorization", "reply_bytes_written", json!(217)),
        ("oauth_authorization", "configured_wait_ms", json!(30001)),
        (
            "oauth_authorization",
            "oidc_nonce_validation_performed",
            json!(true),
        ),
        (
            "oauth_authorization",
            "oidc_identity_validation_performed",
            json!(true),
        ),
        (
            "oauth_authorization",
            "token_signature_validation_performed",
            json!(true),
        ),
        (
            "oauth_authorization",
            "provider_error_class",
            json!("access_denied"),
        ),
        ("oauth_authorization", "evidence_reference", Value::Null),
        ("oauth_authorization", "outcome", json!("not_started")),
        (
            "oauth_token_exchange",
            "profile",
            json!("external-public-code-s256-bearer/v1"),
        ),
        (
            "oauth_token_exchange",
            "pkce_assurance",
            json!("server_enforcement_verified"),
        ),
        ("oauth_token_exchange", "request_attempt_count", json!(true)),
        ("oauth_token_exchange", "request_admitted_count", json!(0)),
        (
            "oauth_token_exchange",
            "verifier_in_admitted_request",
            json!(false),
        ),
        ("oauth_token_exchange", "body_state", json!("incomplete")),
        (
            "oauth_token_exchange",
            "response_scope_matched",
            json!(false),
        ),
        (
            "oauth_token_exchange",
            "token_interpretation",
            json!("verified_oidc_identity"),
        ),
    ] {
        let mut v = document(original.clone());
        v["supplied_session"][section][field] = value;
        reject(&v);
    }
    let mut extra = document(original.clone());
    extra["supplied_session"]["oauth_code"] = json!({});
    reject(&extra);
    let mut uncommitted = document(rejected());
    uncommitted["supplied_session"]["oauth_token_exchange"] =
        original["oauth_token_exchange"].clone();
    reject(&uncommitted);
}

#[test]
fn oauth_authorization_comparison_separates_policy_coverage_and_per_run_receipts() {
    let before = document(audit());
    let mut after = before.clone();
    after["supplied_session"]["oauth_authorization"]["elapsed_ms"] = json!(28);
    after["supplied_session"]["oauth_authorization"]["evidence_reference"] = json!(format!(
        "supplied-session-oauth-authorization-evidence-sha256:{}",
        "e".repeat(64)
    ));
    let same = compare(&before, &after);
    assert_eq!(
        same["supplied_session_comparison"]["status"],
        json!("compared_within_same_declared_context")
    );
    let changed = compare(&before, &document(rejected()));
    assert_eq!(
        changed["supplied_session_comparison"]["status"],
        json!("compared_within_same_declared_context")
    );
    after["supplied_session"]["oauth_authorization"]["configured_wait_ms"] = json!(1000);
    assert_eq!(
        compare(&before, &after)["supplied_session_comparison"]["status"],
        json!("not_compared")
    );
}

#[test]
fn oauth_authorization_saved_reader_preserves_cancel_or_deadline_after_committed_callback() {
    for outcome in ["cancelled", "runtime_limit"] {
        let mut a = rejected();
        a["oauth_authorization"] = audit()["oauth_authorization"].clone();
        a["oauth_token_exchange"]["outcome"] = json!(outcome);
        a["outcome"] = json!(outcome);
        let v = document(a);
        assert_eq!(
            compare(&v, &v)["supplied_session_comparison"]["status"],
            json!("compared_within_same_declared_context")
        );
    }
}

#[test]
fn oauth_authorization_saved_reader_rejects_exchange_or_extension_facts_before_qualification() {
    // A rejected callback never reaches token acquisition. These are literal
    // impossible-state mutations, not observations captured from a process.
    for outcome in ["cancelled", "runtime_limit"] {
        let mut a = rejected();
        a["oauth_token_exchange"]["outcome"] = json!(outcome);
        reject(&document(a));
    }
    let mut unqualified_extensions = rejected();
    unqualified_extensions["oauth_authorization"]["unknown_parameter_count"] = json!(1);
    reject(&document(unqualified_extensions));

    // The same extension count is legitimate after state and issuer validation.
    let mut qualified_extensions = audit();
    qualified_extensions["oauth_authorization"]["unknown_parameter_count"] = json!(1);
    let v = document(qualified_extensions);
    assert_eq!(
        compare(&v, &v)["supplied_session_comparison"]["status"],
        json!("compared_within_same_declared_context")
    );
}
