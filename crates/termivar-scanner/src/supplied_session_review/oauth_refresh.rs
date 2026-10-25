//! Pure codecs for one explicitly scheduled OAuth Bearer renewal.
//!
//! A changed refresh value is a local observation, not proof that the provider
//! invalidated its predecessor. Dispatch, single-use authority, response commit,
//! credential epochs and health qualification remain owned by the runtime.

use std::fmt;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{
    oauth_code::{
        authorization_from_token, parse_token_response_fields, OAuthCodeInputError,
        RefreshTokenHandling,
    },
    SuppliedSessionAuthorization, SuppliedSessionPolicy, SuppliedSessionPolicyError,
    SuppliedSessionPolicyVersion,
};

const PROFILE: &str = "scheduled-public-bearer-refresh/v1";
const MAX_REFRESH_BYTES: usize = 8 * 1_024;
const MAX_FORM_BYTES: usize = 16 * 1_024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireOAuthRefreshPolicy {
    pub(super) profile: String,
    pub(super) after_resource_count: u8,
    pub(super) max_attempts: u8,
}

/// Validated non-secret scheduling data, never a request permit.
#[derive(Clone)]
pub(crate) struct OAuthRefreshPolicy {
    binding_reference: String,
}

impl OAuthRefreshPolicy {
    pub(super) fn from_wire(
        wire: WireOAuthRefreshPolicy,
    ) -> Result<Self, SuppliedSessionPolicyError> {
        if wire.profile != PROFILE || wire.after_resource_count != 1 || wire.max_attempts != 1 {
            return Err(SuppliedSessionPolicyError::InvalidOAuthRefresh);
        }
        let mut digest = Sha256::new();
        digest.update(b"security.supplied-session.oauth-refresh-policy.v1\0");
        super::hash_field(&mut digest, PROFILE.as_bytes());
        super::hash_field(&mut digest, &[1]);
        super::hash_field(&mut digest, &[1]);
        Ok(Self {
            binding_reference: format!(
                "oauth-refresh-policy-sha256:{}",
                super::hex(digest.finalize())
            ),
        })
    }

    pub(crate) const fn profile(&self) -> &'static str {
        PROFILE
    }

    pub(crate) const fn after_resource_count(&self) -> u8 {
        1
    }

    pub(crate) const fn max_attempts(&self) -> u8 {
        1
    }

    pub(crate) fn binding_reference(&self) -> &str {
        &self.binding_reference
    }
}

impl fmt::Debug for OAuthRefreshPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthRefreshPolicy")
            .field("profile", &PROFILE)
            .field("after_resource_count", &1)
            .field("max_attempts", &1)
            .field("binding_reference", &self.binding_reference)
            .finish()
    }
}

/// A move-only guarded secret. Possession grants no network or epoch authority.
pub(crate) struct OAuthRefreshToken {
    value: Zeroizing<String>,
    policy_reference: String,
    idp_reference: String,
    refresh_reference: String,
    principal_alias: String,
}

impl OAuthRefreshToken {
    pub(crate) fn matches_policy(&self, policy: &SuppliedSessionPolicy) -> bool {
        selected_policy(policy).is_ok_and(|(idp, refresh)| {
            self.policy_reference == policy.policy_reference()
                && self.idp_reference == idp.binding_reference()
                && self.refresh_reference == refresh.binding_reference()
                && self.principal_alias == policy.principal_alias()
        })
    }

    /// Exactly the reviewed public-client refresh form. Query credentials,
    /// redirect URI, code, verifier and arbitrary fields are not supported.
    pub(crate) fn compose_form_body(
        &self,
        policy: &SuppliedSessionPolicy,
    ) -> Result<OAuthRefreshFormBody, OAuthCodeInputError> {
        if !self.matches_policy(policy) {
            return Err(OAuthCodeInputError::PolicyMismatch);
        }
        let (idp, _) = selected_policy(policy)?;
        let scope = idp.scopes().join(" ");
        let fields = [
            ("grant_type", "refresh_token"),
            ("client_id", idp.client_id()),
            ("refresh_token", self.value.as_str()),
            ("scope", scope.as_str()),
        ];
        // Calculate exact form expansion before allocating any secret form
        // buffer. A bounded raw token can still exceed the encoded form cap.
        let length = encoded_form_length(&fields).ok_or(OAuthCodeInputError::SecretTooLarge)?;
        if length > MAX_FORM_BYTES {
            return Err(OAuthCodeInputError::SecretTooLarge);
        }
        let mut value = Zeroizing::new(String::with_capacity(length));
        {
            let mut form = url::form_urlencoded::Serializer::new(&mut *value);
            for (key, item) in fields {
                form.append_pair(key, item);
            }
            form.finish();
        }
        if value.len() != length || value.len() > MAX_FORM_BYTES {
            return Err(OAuthCodeInputError::SecretTooLarge);
        }
        Ok(OAuthRefreshFormBody { value })
    }
}

impl fmt::Debug for OAuthRefreshToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OAuthRefreshToken(<redacted>)")
    }
}

/// Guarded bytes available only to the crate-owned request composer.
pub(crate) struct OAuthRefreshFormBody {
    value: Zeroizing<String>,
}

impl OAuthRefreshFormBody {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.value.as_bytes()
    }
}

impl fmt::Debug for OAuthRefreshFormBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OAuthRefreshFormBody(<redacted>)")
    }
}

/// Bounded token facts plus guarded credentials, not evidence or authority.
pub(crate) struct OAuthRenewableTokenResponse {
    access_token: Zeroizing<String>,
    refresh_token: OAuthRefreshToken,
    expires_in_seconds: u64,
    replacement_value_differs: Option<bool>,
}

impl OAuthRenewableTokenResponse {
    pub(crate) const fn expires_in_seconds(&self) -> u64 {
        self.expires_in_seconds
    }

    /// This is only local value inequality, not provider replay protection.
    pub(crate) const fn replacement_value_differs(&self) -> Option<bool> {
        self.replacement_value_differs
    }

    pub(crate) fn into_parts(
        self,
    ) -> Result<(SuppliedSessionAuthorization, OAuthRefreshToken), OAuthCodeInputError> {
        Ok((
            authorization_from_token(self.access_token)?,
            self.refresh_token,
        ))
    }
}

impl fmt::Debug for OAuthRenewableTokenResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OAuthRenewableTokenResponse(<redacted>)")
    }
}

/// Pure reduction of the complete representation already admitted by the
/// runtime. This never proves HTTP completeness, commit or remote revocation.
pub(crate) fn parse_renewable_token_response(
    policy: &SuppliedSessionPolicy,
    body: Zeroizing<Vec<u8>>,
    previous: Option<&OAuthRefreshToken>,
) -> Result<OAuthRenewableTokenResponse, OAuthCodeInputError> {
    let (idp, refresh) = selected_policy(policy)?;
    if previous.is_some_and(|previous| !previous.matches_policy(policy)) {
        return Err(OAuthCodeInputError::PolicyMismatch);
    }
    let parsed = parse_token_response_fields(idp, body, RefreshTokenHandling::RetainAscii)?;
    let value = parsed
        .retained_refresh_token
        .ok_or(OAuthCodeInputError::InvalidTokenResponse)?;
    if value.is_empty()
        || value.len() > MAX_REFRESH_BYTES
        || !value.bytes().all(|byte| matches!(byte, 0x20..=0x7e))
    {
        return Err(OAuthCodeInputError::InvalidTokenResponse);
    }
    let replacement_value_differs = if let Some(previous) = previous {
        // The existing primitive compares equal-length contents in constant
        // time; length inequality itself is not claimed to be constant time.
        if bool::from(value.as_bytes().ct_eq(previous.value.as_bytes())) {
            return Err(OAuthCodeInputError::InvalidTokenResponse);
        }
        Some(true)
    } else {
        None
    };
    Ok(OAuthRenewableTokenResponse {
        access_token: parsed.access_token,
        refresh_token: OAuthRefreshToken {
            value,
            policy_reference: policy.policy_reference().to_owned(),
            idp_reference: idp.binding_reference().to_owned(),
            refresh_reference: refresh.binding_reference().to_owned(),
            principal_alias: policy.principal_alias().to_owned(),
        },
        expires_in_seconds: parsed.expires_in_seconds,
        replacement_value_differs,
    })
}

fn selected_policy(
    policy: &SuppliedSessionPolicy,
) -> Result<(&super::oauth_code::OAuthCodePolicy, &OAuthRefreshPolicy), OAuthCodeInputError> {
    if policy.version() != SuppliedSessionPolicyVersion::V6 {
        return Err(OAuthCodeInputError::PolicyMismatch);
    }
    let idp = policy
        .oauth_code_policy()
        .ok_or(OAuthCodeInputError::PolicyMismatch)?;
    let refresh = policy
        .oauth_refresh_policy()
        .filter(|refresh| {
            refresh.profile() == PROFILE
                && refresh.after_resource_count() == 1
                && refresh.max_attempts() == 1
        })
        .ok_or(OAuthCodeInputError::PolicyMismatch)?;
    Ok((idp, refresh))
}

fn encoded_form_length(fields: &[(&str, &str)]) -> Option<usize> {
    let mut length = fields.len().checked_sub(1)?;
    for (key, value) in fields {
        length = length.checked_add(1)?;
        for byte in key.bytes().chain(value.bytes()) {
            let width = if byte.is_ascii_alphanumeric()
                || matches!(byte, b'*' | b'-' | b'.' | b'_' | b' ')
            {
                1
            } else {
                3
            };
            length = length.checked_add(width)?;
        }
    }
    Some(length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supplied_session_review::{oauth_code, SuppliedSessionOAuthGrant};
    use url::Url;

    // Original synthetic values, not a captured provider response. Expected
    // fields and request bytes below are literal independent profile oracles.
    const RESPONSE: &str = r#"{"access_token":"SYNTHETIC.ACCESS+/==","token_type":"Bearer","expires_in":60,"scope":"canary-read","refresh_token":"SYNTHETIC_REFRESH_FIRST"}"#;
    const POLICY: &str = r#"schema = "security.supplied-session-policy/v6"
principal_alias = "canary-a"
credential_mechanism = "authorization_header"
credential_acquisition = "imported_oauth_code_pkce"
health_path = "/app/health"
health_json_field = "authenticated"
resources = ["/app/private/one", "/app/private/two"]
max_session_requests = 8
max_total_response_bytes = 65536
max_response_body_bytes = 32768
max_wall_time_ms = 10000
[oauth_code]
profile = "external-public-code-s256-bearer/v1"
transport_profile = "verified-https/v1"
issuer = "https://issuer.test/realm"
token_endpoint = "https://issuer.test/realm/token"
client_id = "owned-client"
redirect_uri = "https://client.test/callback"
scopes = ["canary-read"]
max_token_response_bytes = 32768
[oauth_refresh]
profile = "scheduled-public-bearer-refresh/v1"
after_resource_count = 1
max_attempts = 1
"#;

    fn policy_from(source: &str) -> SuppliedSessionPolicy {
        SuppliedSessionPolicy::parse_toml(
            &Url::parse("https://application.test/app/").unwrap(),
            source.as_bytes(),
        )
        .unwrap()
    }

    fn policy() -> SuppliedSessionPolicy {
        policy_from(POLICY)
    }

    fn body(source: &str) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(source.as_bytes().to_vec())
    }

    fn initial(policy: &SuppliedSessionPolicy) -> OAuthRenewableTokenResponse {
        parse_renewable_token_response(policy, body(RESPONSE), None).unwrap()
    }

    fn response_with_refresh(value: &str) -> String {
        // serde_json is fixture composition only; expected grammar and outcomes
        // do not use the production reducer or classifier.
        format!(
            r#"{{"access_token":"SYNTHETIC.ACCESS+/==","token_type":"Bearer","expires_in":60,"scope":"canary-read","refresh_token":{}}}"#,
            serde_json::to_string(value).unwrap()
        )
    }

    #[test]
    fn refresh_policy_has_literal_binding_and_exact_schedule() {
        let parsed = policy();
        let refresh = parsed.oauth_refresh_policy().unwrap();
        assert_eq!(refresh.profile(), "scheduled-public-bearer-refresh/v1");
        assert_eq!(refresh.after_resource_count(), 1);
        assert_eq!(refresh.max_attempts(), 1);
        // Python hashlib/struct over the independent literal three fields,
        // framed with u64 big-endian lengths, frozen before production tests.
        assert_eq!(
            refresh.binding_reference(),
            "oauth-refresh-policy-sha256:aecc9da33d787ae12a261b6be130398b223719a4f6215c1e1607f4660c247c0b"
        );
        assert_eq!(
            format!("{refresh:?}"),
            "OAuthRefreshPolicy { profile: \"scheduled-public-bearer-refresh/v1\", after_resource_count: 1, max_attempts: 1, binding_reference: \"oauth-refresh-policy-sha256:aecc9da33d787ae12a261b6be130398b223719a4f6215c1e1607f4660c247c0b\" }"
        );
    }

    #[test]
    fn refresh_policy_rejects_unknown_fields_and_nonexact_profile_or_schedule() {
        for source in [
            r#"{"profile":"scheduled-public-bearer-refresh/v1","after_resource_count":1,"max_attempts":1,"extra":true}"#,
            r#"{"profile":"scheduled-public-bearer-refresh/v1","after_resource_count":true,"max_attempts":1}"#,
            r#"{"profile":"scheduled-public-bearer-refresh/v1","after_resource_count":1,"max_attempts":256}"#,
            r#"{"profile":"scheduled-public-bearer-refresh/v1","after_resource_count":1,"max_attempts":1,"max_attempts":1}"#,
        ] {
            assert!(serde_json::from_str::<WireOAuthRefreshPolicy>(source).is_err());
        }
        for (profile, boundary, attempts) in [
            ("scheduled-public-bearer-refresh/v2", 1, 1),
            ("scheduled-public-bearer-refresh/v1", 0, 1),
            ("scheduled-public-bearer-refresh/v1", 2, 1),
            ("scheduled-public-bearer-refresh/v1", 1, 0),
            ("scheduled-public-bearer-refresh/v1", 1, 2),
        ] {
            assert!(OAuthRefreshPolicy::from_wire(WireOAuthRefreshPolicy {
                profile: profile.to_owned(),
                after_resource_count: boundary,
                max_attempts: attempts,
            })
            .is_err());
        }
    }

    #[test]
    fn renewable_response_requires_v6_while_v5_still_discards_refresh_values() {
        let source = POLICY
            .split("[oauth_refresh]")
            .next()
            .unwrap()
            .replace("policy/v6", "policy/v5")
            .replace("max_session_requests = 8", "max_session_requests = 6");
        let legacy = policy_from(&source);
        assert!(matches!(
            parse_renewable_token_response(&legacy, body(RESPONSE), None),
            Err(OAuthCodeInputError::PolicyMismatch)
        ));
        let observed = oauth_code::parse_token_response(
            legacy.oauth_code_policy().unwrap(),
            body(&response_with_refresh("\u{00e9} LEGACY_VALUE")),
        )
        .unwrap();
        assert!(observed.refresh_token_returned());
        assert_eq!(observed.expires_in_seconds(), 60);
        assert_eq!(
            format!("{observed:?}"),
            "OAuthCodeTokenResponse(<redacted>)"
        );
        // V5 continues treating bounded unknown extensions as inert. V6's
        // explicit top-level unsupported-constraint vocabulary is not global.
        let legacy_cnf = RESPONSE.replace("{", "{\"cnf\":null,");
        assert!(oauth_code::parse_token_response(
            legacy.oauth_code_policy().unwrap(),
            body(&legacy_cnf)
        )
        .is_ok());
    }

    #[test]
    fn initial_and_replacement_responses_keep_finite_local_meaning() {
        let policy = policy();
        let first = initial(&policy);
        assert_eq!(first.expires_in_seconds(), 60);
        assert_eq!(first.replacement_value_differs(), None);
        let (_, previous) = first.into_parts().unwrap();
        assert!(previous.matches_policy(&policy));
        let replacement = parse_renewable_token_response(
            &policy,
            body(&response_with_refresh("SYNTHETIC_REFRESH_SECOND")),
            Some(&previous),
        )
        .unwrap();
        assert_eq!(replacement.replacement_value_differs(), Some(true));
        assert_eq!(replacement.expires_in_seconds(), 60);
        let (authorization, next) = replacement.into_parts().unwrap();
        assert!(next.matches_policy(&policy));
        assert!(!format!("{authorization:?}").contains("SYNTHETIC"));
        assert_eq!(format!("{next:?}"), "OAuthRefreshToken(<redacted>)");
    }

    #[test]
    fn unchanged_previous_refresh_value_is_rejected_without_consuming_it() {
        let policy = policy();
        let (_, previous) = initial(&policy).into_parts().unwrap();
        assert!(matches!(
            parse_renewable_token_response(&policy, body(RESPONSE), Some(&previous)),
            Err(OAuthCodeInputError::InvalidTokenResponse)
        ));
        assert!(previous.matches_policy(&policy));
        assert!(parse_renewable_token_response(
            &policy,
            body(&response_with_refresh("SYNTHETIC_REFRESH_DIFFERENT_LENGTH")),
            Some(&previous)
        )
        .is_ok());
        // The pure codec deliberately has no replay cache or dispatch right;
        // once-only use is separately enforced by the assessment-owned broker.
    }

    #[test]
    fn refresh_token_is_bound_to_alias_policy_scope_client_and_idp() {
        let original = policy();
        let (_, previous) = initial(&original).into_parts().unwrap();
        for source in [
            POLICY.replace("canary-a", "canary-b"),
            POLICY.replace("canary-read", "other-read"),
            POLICY.replace("owned-client", "other-client"),
            POLICY.replace("issuer.test", "other-issuer.test"),
            POLICY.replace("max_wall_time_ms = 10000", "max_wall_time_ms = 9000"),
        ] {
            let other = policy_from(&source);
            assert!(!previous.matches_policy(&other));
            assert!(matches!(
                previous.compose_form_body(&other),
                Err(OAuthCodeInputError::PolicyMismatch)
            ));
            assert!(matches!(
                parse_renewable_token_response(&other, body(RESPONSE), Some(&previous)),
                Err(OAuthCodeInputError::PolicyMismatch)
            ));
        }
        let other_application = SuppliedSessionPolicy::parse_toml(
            &Url::parse("https://different-application.test/app/").unwrap(),
            POLICY.as_bytes(),
        )
        .unwrap();
        assert!(!previous.matches_policy(&other_application));
    }

    #[test]
    fn refresh_form_has_exact_four_fields_and_real_encoding_without_trimming() {
        let policy = policy();
        let response = parse_renewable_token_response(
            &policy,
            body(&response_with_refresh(" SYNTHETIC+/=~ ")),
            None,
        )
        .unwrap();
        let (_, token) = response.into_parts().unwrap();
        let form = token.compose_form_body(&policy).unwrap();
        assert_eq!(
            form.as_bytes(),
            b"grant_type=refresh_token&client_id=owned-client&refresh_token=+SYNTHETIC%2B%2F%3D%7E+&scope=canary-read"
        );
        assert_eq!(format!("{form:?}"), "OAuthRefreshFormBody(<redacted>)");
    }

    #[test]
    fn form_expansion_has_independent_exact_limit_and_limit_plus_one() {
        let policy = policy();
        let overhead =
            b"grant_type=refresh_token&client_id=owned-client&refresh_token=&scope=canary-read"
                .len();
        let available = 16_384 - overhead;
        let mut value = "+".repeat(available / 3);
        value.push_str(&"a".repeat(available % 3));
        let exact =
            parse_renewable_token_response(&policy, body(&response_with_refresh(&value)), None)
                .unwrap();
        let (_, token) = exact.into_parts().unwrap();
        assert_eq!(
            token.compose_form_body(&policy).unwrap().as_bytes().len(),
            16_384
        );
        value.push('a');
        let over =
            parse_renewable_token_response(&policy, body(&response_with_refresh(&value)), None)
                .unwrap();
        let (_, token) = over.into_parts().unwrap();
        assert!(matches!(
            token.compose_form_body(&policy),
            Err(OAuthCodeInputError::SecretTooLarge)
        ));
    }

    #[test]
    fn refresh_string_bound_is_independent_of_larger_json_body_cap() {
        let policy = policy();
        for length in [1, 8_192] {
            assert!(parse_renewable_token_response(
                &policy,
                body(&response_with_refresh(&"a".repeat(length))),
                None
            )
            .is_ok());
        }
        for value in [
            String::new(),
            "a".repeat(8_193),
            "\u{00e9}".to_owned(),
            "\n".to_owned(),
            "\u{007f}".to_owned(),
        ] {
            assert!(parse_renewable_token_response(
                &policy,
                body(&response_with_refresh(&value)),
                None
            )
            .is_err());
        }
    }

    #[test]
    fn refresh_response_rejects_missing_malformed_and_unsupported_fields() {
        let policy = policy();
        for source in [
            RESPONSE.replace(",\"refresh_token\":\"SYNTHETIC_REFRESH_FIRST\"", ""),
            RESPONSE.replace(
                "\"refresh_token\":\"SYNTHETIC_REFRESH_FIRST\"",
                "\"refresh_token\":null",
            ),
            RESPONSE.replace(
                "\"refresh_token\":\"SYNTHETIC_REFRESH_FIRST\"",
                "\"refresh_token\":true",
            ),
            RESPONSE.replace("\"expires_in\":60", "\"expires_in\":true"),
            RESPONSE.replace("\"expires_in\":60", "\"expires_in\":0"),
            RESPONSE.replace("\"expires_in\":60", "\"expires_in\":3601"),
            RESPONSE.replace("\"token_type\":\"Bearer\"", "\"token_type\":\"DPoP\""),
            RESPONSE.replace("\"scope\":\"canary-read\"", "\"scope\":\"other-read\""),
            RESPONSE.replace("{", "{\"id_token\":null,"),
            RESPONSE.replace("{", "{\"cnf\":null,"),
            RESPONSE.replace("{", "{\"error\":\"invalid_grant\","),
        ] {
            assert!(parse_renewable_token_response(&policy, body(&source), None).is_err());
        }
        for field in ["id_token", "cnf"] {
            let source = RESPONSE.replacen('{', &format!("{{\"{field}\":false,"), 1);
            assert!(matches!(
                parse_renewable_token_response(&policy, body(&source), None),
                Err(OAuthCodeInputError::UnsupportedTokenProfile)
            ));
        }
    }

    #[test]
    fn renewable_parser_reuses_duplicate_utf8_depth_and_completeness_guards() {
        let policy = policy();
        for source in [
            RESPONSE.replacen('{', "{\"refresh_token\":\"SYNTHETIC_DUPLICATE\",", 1),
            RESPONSE.replacen('{', "{\"vendor\":{\"x\":1,\"x\":2},", 1),
            RESPONSE.replacen('{', "{\"vendor\":[[[[[[[[[true]]]]]]]]],", 1),
            format!("{RESPONSE} trailing"),
            "[]".to_owned(),
        ] {
            assert!(parse_renewable_token_response(&policy, body(&source), None).is_err());
        }
        assert!(parse_renewable_token_response(&policy, Zeroizing::new(vec![0xff]), None).is_err());
        assert!(
            parse_renewable_token_response(&policy, Zeroizing::new(vec![b'a'; 32_769]), None)
                .is_err()
        );
        let inert = RESPONSE.replacen('{', "{\"vendor\":{\"finite\":[true,1,null]},", 1);
        assert!(parse_renewable_token_response(&policy, body(&inert), None).is_ok());
    }

    #[test]
    fn renewable_token_and_error_debug_never_export_secret_values_or_hashes() {
        let policy = policy();
        let response = initial(&policy);
        assert_eq!(
            format!("{response:?}"),
            "OAuthRenewableTokenResponse(<redacted>)"
        );
        let (_, token) = response.into_parts().unwrap();
        let form = token.compose_form_body(&policy).unwrap();
        for diagnostic in [
            format!("{token:?}"),
            format!("{form:?}"),
            OAuthCodeInputError::InvalidTokenResponse.to_string(),
            format!("{:?}", OAuthCodeInputError::PolicyMismatch),
        ] {
            assert!(!diagnostic.contains("SYNTHETIC"));
            assert!(!diagnostic.contains("sha256"));
        }
    }

    #[test]
    fn v6_imported_grant_keeps_existing_rfc7636_and_policy_binding() {
        // RFC7636 appendix B known-answer verifier/challenge, not generated by
        // the production hash helper and not captured account credentials.
        let source = b"authorization_code\tSYNTHETIC_CODE\ncode_verifier\tdBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk\ncode_challenge\tE9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\nissuer\thttps://issuer.test/realm\nclient_id\towned-client\nredirect_uri\thttps://client.test/callback\nscope\tcanary-read\nreceived_unix_seconds\t1000\n";
        let policy = policy();
        let grant = SuppliedSessionOAuthGrant::parse_tsv(&policy, source.to_vec(), 1000).unwrap();
        assert!(grant.matches_policy(&policy));
        assert_eq!(
            grant.compose_form_body(&policy).unwrap().as_bytes(),
            b"grant_type=authorization_code&client_id=owned-client&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&code=SYNTHETIC_CODE&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        );
        let other = policy_from(&POLICY.replace("canary-a", "canary-b"));
        assert!(!grant.matches_policy(&other));
        assert!(SuppliedSessionOAuthGrant::parse_tsv(&policy, source.to_vec(), 1061).is_err());
        let bad = String::from_utf8(source.to_vec())
            .unwrap()
            .replace("E9Melhoa", "X9Melhoa");
        assert!(SuppliedSessionOAuthGrant::parse_tsv(&policy, bad.into_bytes(), 1000).is_err());
    }
}
