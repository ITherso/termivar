//! Pure, bounded client-initiated public-code/S256 authorization codecs.
//!
//! A validated form is not a transport receipt, an authenticated user identity,
//! or a network permit. The runtime must commit its exact callback observation
//! before using the move-only result. This module owns no listener or client.
//! The explicit owned-HTTP issuer exception is a fixture profile, not a claim
//! of RFC 9207 HTTPS conformance. No OIDC nonce or ID-token validation occurs.

use std::{
    fmt,
    net::{Ipv4Addr, SocketAddrV4},
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use url::{Host, Url};
use zeroize::Zeroizing;

use super::{oauth_code::OAuthCodePolicy, SuppliedSessionPolicyError};

const PROFILE: &str = "loopback-form-post-state/v1";
const CALLBACK_PATH: &str = "/termivar/oauth/callback";
const MAX_WAIT_MS: u64 = 30_000;
const MAX_AUTHORIZATION_URL_BYTES: usize = 4_096;
const MAX_RESPONSE_BYTES: usize = 8_192;
const MAX_PARAMETERS: usize = 16;
const MAX_KEY_BYTES: usize = 128;
const MAX_FIELD_BYTES: usize = 2_048;
const RANDOM_BYTES: usize = 32;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireOAuthAuthorizationPolicy {
    pub(super) profile: String,
    pub(super) authorization_endpoint: String,
    pub(super) max_wait_ms: u64,
}

/// Validated non-secret configuration. It grants no listener or network right.
#[derive(Clone)]
pub(crate) struct OAuthAuthorizationPolicy {
    authorization_endpoint: Url,
    callback_socket: SocketAddrV4,
    callback_host: String,
    max_wait_ms: u64,
    code_binding_reference: String,
    binding_reference: String,
}

impl OAuthAuthorizationPolicy {
    pub(super) fn from_wire(
        wire: WireOAuthAuthorizationPolicy,
        code: &OAuthCodePolicy,
    ) -> Result<Self, SuppliedSessionPolicyError> {
        let invalid = || SuppliedSessionPolicyError::InvalidOAuthAuthorization;
        if wire.profile != PROFILE
            || !code.is_client_initiated()
            || wire.max_wait_ms == 0
            || wire.max_wait_ms > MAX_WAIT_MS
        {
            return Err(invalid());
        }
        let endpoint =
            super::oauth_code::safe_url(&wire.authorization_endpoint, code.transport_profile())
                .ok_or_else(invalid)?;
        if endpoint.origin() != code.issuer().origin()
            || !super::oauth_code::path_beneath(code.issuer().path(), endpoint.path())
        {
            return Err(invalid());
        }
        let callback = code.redirect_uri();
        let port = callback
            .port()
            .filter(|port| *port >= 1_024)
            .ok_or_else(invalid)?;
        if callback.scheme() != "http"
            || callback.host() != Some(Host::Ipv4(Ipv4Addr::LOCALHOST))
            || callback.path() != CALLBACK_PATH
            || callback.query().is_some()
            || callback.fragment().is_some()
            || !callback.username().is_empty()
            || callback.password().is_some()
            || callback.as_str() != format!("http://127.0.0.1:{port}{CALLBACK_PATH}")
        {
            return Err(invalid());
        }
        let mut digest = Sha256::new();
        digest.update(b"security.supplied-session.oauth-authorization-policy.v1\0");
        for field in [PROFILE, code.binding_reference(), endpoint.as_str()] {
            super::hash_field(&mut digest, field.as_bytes());
        }
        super::hash_field(&mut digest, &wire.max_wait_ms.to_be_bytes());
        Ok(Self {
            authorization_endpoint: endpoint,
            callback_socket: SocketAddrV4::new(Ipv4Addr::LOCALHOST, port),
            callback_host: format!("127.0.0.1:{port}"),
            max_wait_ms: wire.max_wait_ms,
            code_binding_reference: code.binding_reference().to_owned(),
            binding_reference: format!(
                "oauth-authorization-policy-sha256:{}",
                super::hex(digest.finalize())
            ),
        })
    }

    pub(crate) fn authorization_endpoint(&self) -> &Url {
        &self.authorization_endpoint
    }

    pub(crate) const fn callback_socket(&self) -> SocketAddrV4 {
        self.callback_socket
    }

    pub(crate) fn callback_host(&self) -> &str {
        &self.callback_host
    }

    pub(crate) const fn max_wait_ms(&self) -> u64 {
        self.max_wait_ms
    }

    pub(crate) fn binding_reference(&self) -> &str {
        &self.binding_reference
    }
}

impl fmt::Debug for OAuthAuthorizationPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthAuthorizationPolicy")
            .field("profile", &PROFILE)
            .field("max_wait_ms", &self.max_wait_ms)
            .field("binding_reference", &self.binding_reference)
            .finish()
    }
}

/// Closed, redaction-safe failures; no provider-controlled text is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum OAuthAuthorizationError {
    #[error("OAuth authorization configuration binding is invalid")]
    InvalidBinding,
    #[error("OAuth authorization entropy is unavailable")]
    EntropyUnavailable,
    #[error("OAuth authorization transaction expired")]
    Expired,
    #[error("OAuth authorization URL exceeds its compiled limit")]
    AuthorizationUrlTooLarge,
    #[error("OAuth authorization response exceeds its compiled limit")]
    ResponseTooLarge,
    #[error("OAuth authorization form is malformed")]
    MalformedForm,
    #[error("OAuth authorization form contains too many parameters")]
    TooManyParameters,
    #[error("OAuth authorization parameter key exceeds its compiled limit")]
    KeyTooLarge,
    #[error("OAuth authorization parameter value exceeds its compiled limit")]
    FieldTooLarge,
    #[error("OAuth authorization form is not valid UTF-8")]
    InvalidUtf8,
    #[error("OAuth authorization form repeats a known parameter")]
    DuplicateParameter,
    #[error("OAuth authorization response is missing state")]
    MissingState,
    #[error("OAuth authorization response state does not match")]
    StateMismatch,
    #[error("OAuth authorization response is missing issuer")]
    MissingIssuer,
    #[error("OAuth authorization response issuer does not match")]
    IssuerMismatch,
    #[error("OAuth authorization response has no outcome")]
    MissingOutcome,
    #[error("OAuth authorization response contains conflicting outcomes")]
    ConflictingOutcome,
    #[error("OAuth authorization response code is invalid")]
    InvalidCode,
    #[error("OAuth authorization provider error is invalid")]
    InvalidProviderError,
}

/// One initiated transaction. Consuming acceptance prevents a second local use.
/// It is intentionally neither Clone nor Serialize, and Debug is redacted.
pub(crate) struct PendingOAuthAuthorization {
    code_policy: OAuthCodePolicy,
    authorization_policy: OAuthAuthorizationPolicy,
    policy_reference: String,
    principal_alias: String,
    verifier: Zeroizing<String>,
    state: Zeroizing<String>,
    transaction_reference: String,
    deadline: Instant,
}

impl PendingOAuthAuthorization {
    pub(crate) fn generate(
        code: &OAuthCodePolicy,
        authorization: &OAuthAuthorizationPolicy,
        policy_reference: &str,
        principal_alias: &str,
        deadline: Instant,
    ) -> Result<Self, OAuthAuthorizationError> {
        Self::generate_with_entropy(
            code,
            authorization,
            policy_reference,
            principal_alias,
            Instant::now(),
            deadline,
            |bytes| getrandom::getrandom(bytes).map_err(|_| ()),
        )
    }

    fn generate_with_entropy(
        code: &OAuthCodePolicy,
        authorization: &OAuthAuthorizationPolicy,
        policy_reference: &str,
        principal_alias: &str,
        now: Instant,
        deadline: Instant,
        mut fill: impl FnMut(&mut [u8]) -> Result<(), ()>,
    ) -> Result<Self, OAuthAuthorizationError> {
        if authorization.code_binding_reference != code.binding_reference()
            || !valid_policy_reference(policy_reference)
            || super::validate_token(principal_alias, super::MAX_PRINCIPAL_ALIAS_BYTES).is_err()
        {
            return Err(OAuthAuthorizationError::InvalidBinding);
        }
        let wait_deadline = now
            .checked_add(Duration::from_millis(authorization.max_wait_ms))
            .ok_or(OAuthAuthorizationError::InvalidBinding)?;
        let deadline = deadline.min(wait_deadline);
        if now >= deadline {
            return Err(OAuthAuthorizationError::Expired);
        }
        // Separate OS draws; public correlation is never a digest of a secret.
        let mut verifier = Zeroizing::new([0_u8; RANDOM_BYTES]);
        let mut state = Zeroizing::new([0_u8; RANDOM_BYTES]);
        let mut transaction = Zeroizing::new([0_u8; RANDOM_BYTES]);
        fill(verifier.as_mut()).map_err(|()| OAuthAuthorizationError::EntropyUnavailable)?;
        fill(state.as_mut()).map_err(|()| OAuthAuthorizationError::EntropyUnavailable)?;
        fill(transaction.as_mut()).map_err(|()| OAuthAuthorizationError::EntropyUnavailable)?;
        Ok(Self {
            code_policy: code.clone(),
            authorization_policy: authorization.clone(),
            policy_reference: policy_reference.to_owned(),
            principal_alias: principal_alias.to_owned(),
            verifier: Zeroizing::new(URL_SAFE_NO_PAD.encode(verifier.as_ref())),
            state: Zeroizing::new(URL_SAFE_NO_PAD.encode(state.as_ref())),
            transaction_reference: format!(
                "oauth-authorization-transaction:{}",
                URL_SAFE_NO_PAD.encode(transaction.as_ref())
            ),
            deadline,
        })
    }

    pub(crate) fn transaction_reference(&self) -> &str {
        &self.transaction_reference
    }

    /// Sensitive one-use user-agent handoff; never progress, argv or report data.
    pub(crate) fn authorization_url(&self) -> Result<Zeroizing<String>, OAuthAuthorizationError> {
        let challenge = s256_challenge(&self.verifier);
        let scopes = self.code_policy.scopes().join(" ");
        let fields = [
            ("response_type", "code"),
            ("response_mode", "form_post"),
            ("client_id", self.code_policy.client_id()),
            ("redirect_uri", self.code_policy.redirect_uri().as_str()),
            ("scope", scopes.as_str()),
            ("state", self.state.as_str()),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ];
        let endpoint = self.authorization_policy.authorization_endpoint.as_str();
        let mut length = endpoint.len();
        for (key, value) in fields {
            length = length
                .checked_add(2)
                .and_then(|length| length.checked_add(key.len()))
                .and_then(|length| encoded_length(value).and_then(|size| length.checked_add(size)))
                .ok_or(OAuthAuthorizationError::AuthorizationUrlTooLarge)?;
        }
        if length > MAX_AUTHORIZATION_URL_BYTES {
            return Err(OAuthAuthorizationError::AuthorizationUrlTooLarge);
        }
        let mut result = Zeroizing::new(String::with_capacity(length));
        result.push_str(endpoint);
        for (index, (key, value)) in fields.into_iter().enumerate() {
            result.push(if index == 0 { '?' } else { '&' });
            result.push_str(key);
            result.push('=');
            append_encoded(&mut result, value);
        }
        Ok(result)
    }

    /// Consumes the pending state, including on failure. The caller must already
    /// have validated HTTP method, peer, exact callback target, type and framing.
    pub(crate) fn accept_form_post(
        self,
        source: Vec<u8>,
        now: Instant,
    ) -> Result<OAuthAuthorizationResponse, OAuthAuthorizationError> {
        // Ownership is guarded before the first fallible operation.
        let source = Zeroizing::new(source);
        if source.len() > MAX_RESPONSE_BYTES {
            return Err(OAuthAuthorizationError::ResponseTooLarge);
        }
        if now >= self.deadline {
            return Err(OAuthAuthorizationError::Expired);
        }
        let fields = ResponseFields::parse(&source)?;
        let state = fields
            .state
            .as_ref()
            .ok_or(OAuthAuthorizationError::MissingState)?;
        if !bool::from(state.as_bytes().ct_eq(self.state.as_bytes())) {
            return Err(OAuthAuthorizationError::StateMismatch);
        }
        let issuer = fields
            .issuer
            .as_ref()
            .ok_or(OAuthAuthorizationError::MissingIssuer)?;
        if issuer.as_str() != self.code_policy.issuer().as_str() {
            return Err(OAuthAuthorizationError::IssuerMismatch);
        }
        match (fields.code, fields.error) {
            (Some(_), Some(_)) => Err(OAuthAuthorizationError::ConflictingOutcome),
            (None, None) => Err(OAuthAuthorizationError::MissingOutcome),
            (Some(code), None) => {
                if code.is_empty() || !code.bytes().all(|byte| matches!(byte, 0x20..=0x7e)) {
                    return Err(OAuthAuthorizationError::InvalidCode);
                }
                Ok(OAuthAuthorizationResponse::Code(
                    ValidatedOAuthAuthorizationCode {
                        code,
                        verifier: self.verifier,
                        policy_reference: self.policy_reference,
                        idp_reference: self.code_policy.binding_reference().to_owned(),
                        authorization_reference: self.authorization_policy.binding_reference,
                        principal_alias: self.principal_alias,
                        transaction_reference: self.transaction_reference,
                        unknown_parameter_count: fields.unknown_parameter_count,
                    },
                ))
            },
            (None, Some(error)) => {
                if error.is_empty()
                    || error.len() > MAX_KEY_BYTES
                    || !error.bytes().all(|byte| matches!(byte, 0x21..=0x7e))
                {
                    return Err(OAuthAuthorizationError::InvalidProviderError);
                }
                Ok(OAuthAuthorizationResponse::Error(
                    ValidatedOAuthProviderError {
                        class: OAuthProviderErrorClass::from_value(&error),
                        policy_reference: self.policy_reference,
                        idp_reference: self.code_policy.binding_reference().to_owned(),
                        authorization_reference: self.authorization_policy.binding_reference,
                        principal_alias: self.principal_alias,
                        transaction_reference: self.transaction_reference,
                        unknown_parameter_count: fields.unknown_parameter_count,
                    },
                ))
            },
        }
    }
}

impl fmt::Debug for PendingOAuthAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingOAuthAuthorization(<redacted>)")
    }
}

#[derive(Debug)]
pub(crate) enum OAuthAuthorizationResponse {
    Code(ValidatedOAuthAuthorizationCode),
    Error(ValidatedOAuthProviderError),
}

pub(crate) struct ValidatedOAuthAuthorizationCode {
    code: Zeroizing<String>,
    verifier: Zeroizing<String>,
    policy_reference: String,
    idp_reference: String,
    authorization_reference: String,
    principal_alias: String,
    transaction_reference: String,
    unknown_parameter_count: usize,
}

impl ValidatedOAuthAuthorizationCode {
    pub(crate) fn policy_reference(&self) -> &str {
        &self.policy_reference
    }

    pub(crate) fn idp_reference(&self) -> &str {
        &self.idp_reference
    }

    pub(crate) fn authorization_reference(&self) -> &str {
        &self.authorization_reference
    }

    pub(crate) fn principal_alias(&self) -> &str {
        &self.principal_alias
    }

    pub(crate) fn transaction_reference(&self) -> &str {
        &self.transaction_reference
    }

    pub(crate) const fn unknown_parameter_count(&self) -> usize {
        self.unknown_parameter_count
    }

    /// Only the assessment-owned adapter may turn these guarded values into a
    /// token body, after committing and binding the callback. No TSV re-import.
    pub(crate) fn into_parts(self) -> OAuthAuthorizationCodeParts {
        OAuthAuthorizationCodeParts {
            code: self.code,
            verifier: self.verifier,
            policy_reference: self.policy_reference,
            idp_reference: self.idp_reference,
            authorization_reference: self.authorization_reference,
            principal_alias: self.principal_alias,
            transaction_reference: self.transaction_reference,
            unknown_parameter_count: self.unknown_parameter_count,
        }
    }
}

impl fmt::Debug for ValidatedOAuthAuthorizationCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ValidatedOAuthAuthorizationCode(<redacted>)")
    }
}

/// Move-only, guarded handoff to the private runtime/broker adapter.
pub(crate) struct OAuthAuthorizationCodeParts {
    pub(crate) code: Zeroizing<String>,
    pub(crate) verifier: Zeroizing<String>,
    pub(crate) policy_reference: String,
    pub(crate) idp_reference: String,
    pub(crate) authorization_reference: String,
    pub(crate) principal_alias: String,
    pub(crate) transaction_reference: String,
    pub(crate) unknown_parameter_count: usize,
}

impl fmt::Debug for OAuthAuthorizationCodeParts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OAuthAuthorizationCodeParts(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OAuthProviderErrorClass {
    InvalidRequest,
    UnauthorizedClient,
    AccessDenied,
    UnsupportedResponseType,
    InvalidScope,
    ServerError,
    TemporarilyUnavailable,
    Other,
}

impl OAuthProviderErrorClass {
    fn from_value(value: &str) -> Self {
        match value {
            "invalid_request" => Self::InvalidRequest,
            "unauthorized_client" => Self::UnauthorizedClient,
            "access_denied" => Self::AccessDenied,
            "unsupported_response_type" => Self::UnsupportedResponseType,
            "invalid_scope" => Self::InvalidScope,
            "server_error" => Self::ServerError,
            "temporarily_unavailable" => Self::TemporarilyUnavailable,
            _ => Self::Other,
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::AccessDenied => "access_denied",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope => "invalid_scope",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::Other => "other",
        }
    }
}

pub(crate) struct ValidatedOAuthProviderError {
    class: OAuthProviderErrorClass,
    policy_reference: String,
    idp_reference: String,
    authorization_reference: String,
    principal_alias: String,
    transaction_reference: String,
    unknown_parameter_count: usize,
}

impl ValidatedOAuthProviderError {
    pub(crate) const fn class(&self) -> OAuthProviderErrorClass {
        self.class
    }

    pub(crate) fn policy_reference(&self) -> &str {
        &self.policy_reference
    }

    pub(crate) fn idp_reference(&self) -> &str {
        &self.idp_reference
    }

    pub(crate) fn authorization_reference(&self) -> &str {
        &self.authorization_reference
    }

    pub(crate) fn principal_alias(&self) -> &str {
        &self.principal_alias
    }

    pub(crate) fn transaction_reference(&self) -> &str {
        &self.transaction_reference
    }

    pub(crate) const fn unknown_parameter_count(&self) -> usize {
        self.unknown_parameter_count
    }
}

impl fmt::Debug for ValidatedOAuthProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ValidatedOAuthProviderError(<redacted>)")
    }
}

#[derive(Default)]
struct ResponseFields {
    state: Option<Zeroizing<String>>,
    issuer: Option<Zeroizing<String>>,
    code: Option<Zeroizing<String>>,
    error: Option<Zeroizing<String>>,
    error_description_seen: bool,
    error_uri_seen: bool,
    unknown_parameter_count: usize,
}

impl ResponseFields {
    fn parse(source: &[u8]) -> Result<Self, OAuthAuthorizationError> {
        let mut result = Self::default();
        if source.is_empty() {
            return Ok(result);
        }
        for (index, parameter) in source.split(|byte| *byte == b'&').enumerate() {
            if index >= MAX_PARAMETERS {
                return Err(OAuthAuthorizationError::TooManyParameters);
            }
            let separator = parameter.iter().position(|byte| *byte == b'=');
            let (key, value) = match separator {
                Some(position) => (&parameter[..position], &parameter[position + 1..]),
                None => (parameter, &[][..]),
            };
            let key = decode_form_field(key, MAX_KEY_BYTES, OAuthAuthorizationError::KeyTooLarge)?;
            if key.is_empty() {
                return Err(OAuthAuthorizationError::MalformedForm);
            }
            let value = decode_form_field(
                value,
                MAX_FIELD_BYTES,
                OAuthAuthorizationError::FieldTooLarge,
            )?;
            let slot = match key.as_str() {
                "state" => Some(&mut result.state),
                "iss" => Some(&mut result.issuer),
                "code" => Some(&mut result.code),
                "error" => Some(&mut result.error),
                "error_description" => {
                    if result.error_description_seen {
                        return Err(OAuthAuthorizationError::DuplicateParameter);
                    }
                    result.error_description_seen = true;
                    None
                },
                "error_uri" => {
                    if result.error_uri_seen {
                        return Err(OAuthAuthorizationError::DuplicateParameter);
                    }
                    result.error_uri_seen = true;
                    None
                },
                _ => {
                    // RFC 6749: unknown response parameters are inert. They
                    // remain bounded and cannot select keys, URLs or authority.
                    result.unknown_parameter_count += 1;
                    None
                },
            };
            if let Some(slot) = slot {
                if slot.is_some() {
                    return Err(OAuthAuthorizationError::DuplicateParameter);
                }
                *slot = Some(value);
            }
        }
        Ok(result)
    }
}

fn decode_form_field(
    source: &[u8],
    maximum: usize,
    too_large: OAuthAuthorizationError,
) -> Result<Zeroizing<String>, OAuthAuthorizationError> {
    let mut decoded = Zeroizing::new(Vec::with_capacity(source.len().min(maximum)));
    let mut position = 0;
    while position < source.len() {
        if decoded.len() == maximum {
            return Err(too_large);
        }
        let byte = match source[position] {
            b'+' => b' ',
            b'%' => {
                let high = source.get(position + 1).copied().and_then(hex_digit);
                let low = source.get(position + 2).copied().and_then(hex_digit);
                let (Some(high), Some(low)) = (high, low) else {
                    return Err(OAuthAuthorizationError::MalformedForm);
                };
                position += 2;
                (high << 4) | low
            },
            byte => byte,
        };
        decoded.push(byte);
        position += 1;
    }
    // Validation borrows guarded bytes: FromUtf8Error must not own an
    // unguarded secret buffer on malformed input.
    let text = std::str::from_utf8(&decoded).map_err(|_| OAuthAuthorizationError::InvalidUtf8)?;
    Ok(Zeroizing::new(text.to_owned()))
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn valid_policy_reference(value: &str) -> bool {
    value
        .strip_prefix("supplied-session-policy-sha256:")
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
}

fn s256_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn encoded_length(value: &str) -> Option<usize> {
    value.bytes().try_fold(0_usize, |length, byte| {
        length.checked_add(if unreserved(byte) { 1 } else { 3 })
    })
}

fn append_encoded(output: &mut String, value: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        if unreserved(byte) {
            output.push(char::from(byte));
        } else {
            output.push('%');
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
}

fn unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supplied_session_review::oauth_code::WireOAuthCodePolicy;

    const POLICY_REFERENCE: &str =
        "supplied-session-policy-sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const PRINCIPAL: &str = "synthetic-canary-a";
    const ISSUER: &str = "https://issuer.test/realms/owned";
    const AUTHORIZATION: &str = "https://issuer.test/realms/owned/authorize";
    const CALLBACK: &str = "http://127.0.0.1:18443/termivar/oauth/callback";

    fn code_wire(issuer: &str, redirect: &str) -> WireOAuthCodePolicy {
        WireOAuthCodePolicy {
            profile: "client-initiated-public-code-s256-bearer/v1".to_owned(),
            transport_profile: "verified-https/v1".to_owned(),
            issuer: issuer.to_owned(),
            token_endpoint: format!("{issuer}/token"),
            client_id: "synthetic-public-client".to_owned(),
            redirect_uri: redirect.to_owned(),
            scopes: vec!["canary-read".to_owned()],
            max_token_response_bytes: 8_192,
        }
    }

    fn code_policy() -> OAuthCodePolicy {
        OAuthCodePolicy::from_authorization_wire(code_wire(ISSUER, CALLBACK)).unwrap()
    }

    fn wire(endpoint: &str, max_wait_ms: u64) -> WireOAuthAuthorizationPolicy {
        WireOAuthAuthorizationPolicy {
            profile: PROFILE.to_owned(),
            authorization_endpoint: endpoint.to_owned(),
            max_wait_ms,
        }
    }

    fn policy() -> (OAuthCodePolicy, OAuthAuthorizationPolicy) {
        let code = code_policy();
        let authorization =
            OAuthAuthorizationPolicy::from_wire(wire(AUTHORIZATION, 20_000), &code).unwrap();
        (code, authorization)
    }

    fn pending(now: Instant) -> PendingOAuthAuthorization {
        let (code, authorization) = policy();
        let mut counter = 0_u8;
        PendingOAuthAuthorization::generate_with_entropy(
            &code,
            &authorization,
            POLICY_REFERENCE,
            PRINCIPAL,
            now,
            now + Duration::from_secs(60),
            |bytes| {
                counter += 1;
                bytes.fill(counter);
                Ok(())
            },
        )
        .unwrap()
    }

    // Literal oracle: URL-safe-no-pad encoding of 32 bytes of 0x02. This
    // expectation is not produced by authorization_url or its form encoder.
    const STATE: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI";
    const VERIFIER: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
    const TRANSACTION: &str = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM";

    fn response(extra: &str) -> Vec<u8> {
        format!("state={STATE}&iss=https%3A%2F%2Fissuer.test%2Frealms%2Fowned&{extra}").into_bytes()
    }

    fn error(source: Vec<u8>) -> OAuthAuthorizationError {
        let now = Instant::now();
        pending(now).accept_form_post(source, now).unwrap_err()
    }

    #[test]
    fn authorization_policy_is_query_free_scoped_and_fixed_numeric_callback() {
        let (code, authorization) = policy();
        assert_eq!(
            authorization.authorization_endpoint().as_str(),
            AUTHORIZATION
        );
        assert_eq!(authorization.callback_host(), "127.0.0.1:18443");
        assert_eq!(
            authorization.callback_socket(),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18_443)
        );
        assert_eq!(authorization.max_wait_ms(), 20_000);
        assert!(authorization
            .binding_reference()
            .starts_with("oauth-authorization-policy-sha256:"));
        for endpoint in [
            "https://foreign.test/realms/owned/authorize",
            "https://issuer.test:8443/realms/owned/authorize",
            "https://issuer.test/realms/owned-sibling/authorize",
            "https://issuer.test/realms/other/authorize",
            "https://issuer.test/realms/owned/authorize?prompt=none",
            "https://issuer.test/realms/owned/authorize#fragment",
            "https://user@issuer.test/realms/owned/authorize",
            "https://issuer.test/realms/owned/%2e%2e/authorize",
            "https://issuer.test/realms/owned/../authorize",
            "https://issuer.test/realms/owned//authorize",
            "https://issuer.test/realms/owned\\authorize",
            "http://issuer.test/realms/owned/authorize",
        ] {
            assert!(OAuthAuthorizationPolicy::from_wire(wire(endpoint, 1), &code).is_err());
        }
        for wait in [0, 30_001, u64::MAX] {
            assert!(OAuthAuthorizationPolicy::from_wire(wire(AUTHORIZATION, wait), &code).is_err());
        }
        for wait in [1, 30_000] {
            assert!(OAuthAuthorizationPolicy::from_wire(wire(AUTHORIZATION, wait), &code).is_ok());
        }
        let mut wrong_profile = wire(AUTHORIZATION, 1);
        wrong_profile.profile = "automatic-browser-login/v1".to_owned();
        assert!(OAuthAuthorizationPolicy::from_wire(wrong_profile, &code).is_err());
    }

    #[test]
    fn callback_aliases_paths_ports_and_encoded_material_cannot_expand_policy() {
        for callback in [
            "https://127.0.0.1:18443/termivar/oauth/callback",
            "http://localhost:18443/termivar/oauth/callback",
            "http://127.0.0.2:18443/termivar/oauth/callback",
            "http://[::1]:18443/termivar/oauth/callback",
            "http://127.0.0.1:1023/termivar/oauth/callback",
            "http://127.0.0.1/termivar/oauth/callback",
            "http://127.0.0.1:18443/termivar/oauth/callback/",
            "http://127.0.0.1:18443/termivar/oauth/callback-evil",
            "http://127.0.0.1:18443/other/termivar/oauth/callback",
            "http://127.0.0.1:18443/termivar/oauth/callback?code=secret",
            "http://127.0.0.1:18443/termivar/oauth/callback#fragment",
            "http://user@127.0.0.1:18443/termivar/oauth/callback",
            "http://127.0.0.1:18443/termivar/oauth/%63allback",
            "http://127.0.0.1:18443/termivar/oauth/../callback",
        ] {
            if let Ok(code) = OAuthCodePolicy::from_authorization_wire(code_wire(ISSUER, callback))
            {
                assert!(
                    OAuthAuthorizationPolicy::from_wire(wire(AUTHORIZATION, 1), &code).is_err()
                );
            }
        }
        for port in [1_024, 65_535] {
            let code = OAuthCodePolicy::from_authorization_wire(code_wire(
                ISSUER,
                &format!("http://127.0.0.1:{port}{CALLBACK_PATH}"),
            ))
            .unwrap();
            assert!(OAuthAuthorizationPolicy::from_wire(wire(AUTHORIZATION, 1), &code).is_ok());
        }
    }

    #[test]
    fn owned_http_issuer_is_explicit_fixture_only_not_https_conformance() {
        let mut raw = code_wire("http://127.0.0.1:18444/realms/owned", CALLBACK);
        raw.transport_profile = "owned-numeric-loopback-http/v1".to_owned();
        let code = OAuthCodePolicy::from_authorization_wire(raw).unwrap();
        assert!(OAuthAuthorizationPolicy::from_wire(
            wire("http://127.0.0.1:18444/realms/owned/authorize", 1),
            &code,
        )
        .is_ok());
        for endpoint in [
            "http://localhost:18444/realms/owned/authorize",
            "http://127.0.0.1:18445/realms/owned/authorize",
        ] {
            assert!(OAuthAuthorizationPolicy::from_wire(wire(endpoint, 1), &code).is_err());
        }
    }

    #[test]
    fn wire_policy_rejects_missing_duplicate_unknown_and_wrong_types() {
        let source = format!(
            "profile = \"{PROFILE}\"\nauthorization_endpoint = \"{AUTHORIZATION}\"\nmax_wait_ms = 20000\n"
        );
        assert!(toml::from_str::<WireOAuthAuthorizationPolicy>(&source).is_ok());
        for invalid in [
            source.replace("max_wait_ms = 20000", "max_wait_ms = true"),
            source.replace("max_wait_ms = 20000", "max_wait_ms = -1"),
            source.replace("max_wait_ms = 20000\n", ""),
            format!("{source}unknown = false\n"),
            format!("{source}max_wait_ms = 1\n"),
        ] {
            assert!(toml::from_str::<WireOAuthAuthorizationPolicy>(&invalid).is_err());
        }
    }

    #[test]
    fn nonsecret_policy_bindings_distinguish_config_without_secret_input() {
        let (code, first) = policy();
        let same = OAuthAuthorizationPolicy::from_wire(wire(AUTHORIZATION, 20_000), &code).unwrap();
        let changed =
            OAuthAuthorizationPolicy::from_wire(wire(AUTHORIZATION, 19_999), &code).unwrap();
        let endpoint = OAuthAuthorizationPolicy::from_wire(
            wire("https://issuer.test/realms/owned/other-authorize", 20_000),
            &code,
        )
        .unwrap();
        assert_eq!(first.binding_reference(), same.binding_reference());
        assert_ne!(first.binding_reference(), changed.binding_reference());
        assert_ne!(first.binding_reference(), endpoint.binding_reference());
        let mut peer_wire = code_wire(ISSUER, CALLBACK);
        peer_wire.client_id = "another-public-client".to_owned();
        let peer = OAuthCodePolicy::from_authorization_wire(peer_wire).unwrap();
        let now = Instant::now();
        let mut calls = 0;
        assert_eq!(
            PendingOAuthAuthorization::generate_with_entropy(
                &peer,
                &first,
                POLICY_REFERENCE,
                PRINCIPAL,
                now,
                now + Duration::from_secs(1),
                |_| {
                    calls += 1;
                    Ok(())
                },
            )
            .unwrap_err(),
            OAuthAuthorizationError::InvalidBinding
        );
        assert_eq!(calls, 0);
    }

    #[test]
    fn rfc7636_s256_known_answer_is_exact_and_not_a_version_or_identity_claim() {
        // RFC 7636 Appendix B, literal verifier and independently specified result.
        assert_eq!(
            s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn independent_entropy_draws_build_closed_authorization_handoff_without_verifier() {
        let now = Instant::now();
        let transaction = pending(now);
        assert_eq!(transaction.verifier.as_str(), VERIFIER);
        assert_eq!(transaction.state.as_str(), STATE);
        assert_eq!(
            transaction.transaction_reference(),
            format!("oauth-authorization-transaction:{TRANSACTION}")
        );
        let handoff = transaction.authorization_url().unwrap();
        let parsed = Url::parse(&handoff).unwrap();
        let pairs = parsed.query_pairs().collect::<Vec<_>>();
        assert_eq!(pairs.len(), 8);
        let names = pairs
            .iter()
            .map(|(key, _)| key.as_ref())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "response_type",
                "response_mode",
                "client_id",
                "redirect_uri",
                "scope",
                "state",
                "code_challenge",
                "code_challenge_method"
            ]
        );
        assert_eq!(pairs[0].1, "code");
        assert_eq!(pairs[1].1, "form_post");
        assert_eq!(pairs[2].1, "synthetic-public-client");
        assert_eq!(pairs[3].1, CALLBACK);
        assert_eq!(pairs[4].1, "canary-read");
        assert_eq!(pairs[5].1, STATE);
        assert_eq!(pairs[7].1, "S256");
        assert_eq!(pairs[6].1.len(), 43);
        assert!(!handoff.contains(VERIFIER));
        assert!(!handoff.contains(TRANSACTION));
        assert!(!handoff.contains("code_verifier"));
        assert!(handoff.len() <= MAX_AUTHORIZATION_URL_BYTES);
    }

    #[test]
    fn entropy_failure_at_each_draw_discards_transaction_with_static_error() {
        let (code, authorization) = policy();
        let now = Instant::now();
        for fail_at in 1..=3 {
            let mut calls = 0;
            let result = PendingOAuthAuthorization::generate_with_entropy(
                &code,
                &authorization,
                POLICY_REFERENCE,
                PRINCIPAL,
                now,
                now + Duration::from_secs(1),
                |bytes| {
                    calls += 1;
                    assert_eq!(bytes.len(), 32);
                    bytes.fill(0x7b);
                    if calls == fail_at {
                        Err(())
                    } else {
                        Ok(())
                    }
                },
            );
            assert_eq!(
                result.unwrap_err(),
                OAuthAuthorizationError::EntropyUnavailable
            );
            assert_eq!(calls, fail_at);
        }
    }

    #[test]
    fn monotonic_transaction_never_extends_parent_or_selected_wait() {
        let (code, authorization) = policy();
        let now = Instant::now();
        for (parent_ms, expected_ms) in [(1, 1), (30_000, 20_000)] {
            let transaction = PendingOAuthAuthorization::generate_with_entropy(
                &code,
                &authorization,
                POLICY_REFERENCE,
                PRINCIPAL,
                now,
                now + Duration::from_millis(parent_ms),
                |bytes| {
                    bytes.fill(1);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(
                transaction.deadline,
                now + Duration::from_millis(expected_ms)
            );
        }
        assert_eq!(
            pending(now)
                .accept_form_post(response("code=CANARY-CODE"), now + Duration::from_secs(20))
                .unwrap_err(),
            OAuthAuthorizationError::Expired
        );
        let mut called = false;
        assert_eq!(
            PendingOAuthAuthorization::generate_with_entropy(
                &code,
                &authorization,
                POLICY_REFERENCE,
                PRINCIPAL,
                now,
                now,
                |_| {
                    called = true;
                    Ok(())
                },
            )
            .unwrap_err(),
            OAuthAuthorizationError::Expired
        );
        assert!(!called);
    }

    #[test]
    fn generated_context_requires_bounded_alias_and_real_nonsecret_policy_reference() {
        let (code, authorization) = policy();
        let now = Instant::now();
        for (reference, alias) in [
            ("", PRINCIPAL),
            ("supplied-session-policy-sha256:short", PRINCIPAL),
            (POLICY_REFERENCE, ""),
            (POLICY_REFERENCE, "untrusted\nprincipal"),
        ] {
            assert_eq!(
                PendingOAuthAuthorization::generate_with_entropy(
                    &code,
                    &authorization,
                    reference,
                    alias,
                    now,
                    now + Duration::from_secs(1),
                    |_| panic!("invalid binding consumed entropy"),
                )
                .unwrap_err(),
                OAuthAuthorizationError::InvalidBinding
            );
        }
    }

    #[test]
    fn valid_form_is_state_and_issuer_qualified_then_moved_into_guarded_parts() {
        let now = Instant::now();
        let transaction = pending(now);
        let (_, authorization) = policy();
        let OAuthAuthorizationResponse::Code(code) = transaction
            .accept_form_post(response("code=CANARY%2BCODE%2F%3D%26%25%252B"), now)
            .unwrap()
        else {
            panic!("expected code result")
        };
        assert_eq!(code.policy_reference(), POLICY_REFERENCE);
        assert_eq!(code.idp_reference(), code_policy().binding_reference());
        assert_eq!(
            code.authorization_reference(),
            authorization.binding_reference()
        );
        assert_eq!(code.principal_alias(), PRINCIPAL);
        assert_eq!(
            code.transaction_reference(),
            format!("oauth-authorization-transaction:{TRANSACTION}")
        );
        assert_eq!(code.unknown_parameter_count(), 0);
        assert_eq!(
            format!("{code:?}"),
            "ValidatedOAuthAuthorizationCode(<redacted>)"
        );
        let parts = code.into_parts();
        assert_eq!(parts.code.as_str(), "CANARY+CODE/=&%%2B");
        assert_eq!(parts.verifier.as_str(), VERIFIER);
        assert_eq!(parts.policy_reference, POLICY_REFERENCE);
        assert_eq!(parts.idp_reference, code_policy().binding_reference());
        assert_eq!(
            parts.authorization_reference,
            authorization.binding_reference()
        );
        assert_eq!(parts.principal_alias, PRINCIPAL);
        assert_eq!(
            parts.transaction_reference,
            format!("oauth-authorization-transaction:{TRANSACTION}")
        );
        assert_eq!(parts.unknown_parameter_count, 0);
        assert_eq!(
            format!("{parts:?}"),
            "OAuthAuthorizationCodeParts(<redacted>)"
        );
        // Both calls above consume self. No public Clone, Deserialize or raw
        // value getter can recreate or replay a validated code transaction.
    }

    #[test]
    fn missing_wrong_empty_duplicate_state_and_issuer_fail_closed() {
        let valid = String::from_utf8(response("code=CANARY-CODE")).unwrap();
        for (source, expected) in [
            (
                valid.replace(&format!("state={STATE}&"), ""),
                OAuthAuthorizationError::MissingState,
            ),
            (
                valid.replace(STATE, "wrong"),
                OAuthAuthorizationError::StateMismatch,
            ),
            (
                valid.replace(STATE, ""),
                OAuthAuthorizationError::StateMismatch,
            ),
            (
                valid.replace(STATE, &format!("{STATE}+")),
                OAuthAuthorizationError::StateMismatch,
            ),
            (
                format!("{valid}&state={STATE}"),
                OAuthAuthorizationError::DuplicateParameter,
            ),
            (
                format!("{valid}&%73tate={STATE}"),
                OAuthAuthorizationError::DuplicateParameter,
            ),
            (
                valid.replace("iss=https%3A%2F%2Fissuer.test%2Frealms%2Fowned&", ""),
                OAuthAuthorizationError::MissingIssuer,
            ),
            (
                valid.replace("issuer.test", "other.test"),
                OAuthAuthorizationError::IssuerMismatch,
            ),
            (
                valid.replace("realms%2Fowned", "realms%2Fowned%2F"),
                OAuthAuthorizationError::IssuerMismatch,
            ),
            (
                format!("{valid}&iss={ISSUER}"),
                OAuthAuthorizationError::DuplicateParameter,
            ),
        ] {
            assert_eq!(error(source.into_bytes()), expected);
        }
    }

    #[test]
    fn provider_error_requires_state_issuer_and_retains_only_closed_class() {
        let now = Instant::now();
        for (value, expected) in [
            ("invalid_request", OAuthProviderErrorClass::InvalidRequest),
            (
                "unauthorized_client",
                OAuthProviderErrorClass::UnauthorizedClient,
            ),
            ("access_denied", OAuthProviderErrorClass::AccessDenied),
            (
                "unsupported_response_type",
                OAuthProviderErrorClass::UnsupportedResponseType,
            ),
            ("invalid_scope", OAuthProviderErrorClass::InvalidScope),
            ("server_error", OAuthProviderErrorClass::ServerError),
            (
                "temporarily_unavailable",
                OAuthProviderErrorClass::TemporarilyUnavailable,
            ),
            ("SYNTHETIC_PROVIDER_SECRET", OAuthProviderErrorClass::Other),
        ] {
            let source = response(&format!("error={value}&error_description=DO-NOT-RETAIN&error_uri=https%3A%2F%2Funtrusted.invalid%2Fno-fetch"));
            let OAuthAuthorizationResponse::Error(error) =
                pending(now).accept_form_post(source, now).unwrap()
            else {
                panic!("expected classified provider error")
            };
            assert_eq!(error.class(), expected);
            assert!(!error.class().as_str().contains("SYNTHETIC"));
            assert_eq!(error.policy_reference(), POLICY_REFERENCE);
            assert_eq!(error.idp_reference(), code_policy().binding_reference());
            assert_eq!(error.principal_alias(), PRINCIPAL);
            assert_eq!(error.unknown_parameter_count(), 0);
            assert!(error
                .authorization_reference()
                .starts_with("oauth-authorization-policy-sha256:"));
            assert!(error
                .transaction_reference()
                .starts_with("oauth-authorization-transaction:"));
            assert_eq!(
                format!("{error:?}"),
                "ValidatedOAuthProviderError(<redacted>)"
            );
        }
        let source = String::from_utf8(response("error=access_denied")).unwrap();
        assert_eq!(
            error(source.replace(STATE, "wrong").into_bytes()),
            OAuthAuthorizationError::StateMismatch
        );
        assert_eq!(
            error(source.replace("issuer.test", "wrong.test").into_bytes()),
            OAuthAuthorizationError::IssuerMismatch
        );
        for extra in ["error=", "error=bad+value", "error=%00"] {
            assert_eq!(
                error(response(extra)),
                OAuthAuthorizationError::InvalidProviderError
            );
        }
    }

    #[test]
    fn outcome_exclusivity_duplicates_and_printable_code_are_required() {
        for (extra, expected) in [
            ("", OAuthAuthorizationError::MalformedForm),
            ("extension=only", OAuthAuthorizationError::MissingOutcome),
            (
                "code=CANARY&error=access_denied",
                OAuthAuthorizationError::ConflictingOutcome,
            ),
            (
                "code=CANARY&code=SECOND",
                OAuthAuthorizationError::DuplicateParameter,
            ),
            (
                "error=access_denied&error=server_error",
                OAuthAuthorizationError::DuplicateParameter,
            ),
            (
                "code=CANARY&error_description=a&error_description=b",
                OAuthAuthorizationError::DuplicateParameter,
            ),
            (
                "code=CANARY&error_uri=a&error_uri=b",
                OAuthAuthorizationError::DuplicateParameter,
            ),
            ("code=", OAuthAuthorizationError::InvalidCode),
            ("code=%00", OAuthAuthorizationError::InvalidCode),
            ("code=%1F", OAuthAuthorizationError::InvalidCode),
            ("code=%7F", OAuthAuthorizationError::InvalidCode),
            ("code=%C3%A9", OAuthAuthorizationError::InvalidCode),
        ] {
            assert_eq!(error(response(extra)), expected);
        }
    }

    #[test]
    fn unknown_parameters_are_bounded_ignored_and_counted_without_authority() {
        let now = Instant::now();
        let result = pending(now).accept_form_post(
            response("code=CANARY&session_state=inert&extension=x&extension=y&jku=https%3A%2F%2Funtrusted.invalid"), now,
        ).unwrap();
        let OAuthAuthorizationResponse::Code(code) = result else {
            panic!("expected code")
        };
        assert_eq!(code.unknown_parameter_count(), 4);
        let mut at_limit = response("code=CANARY");
        for _ in 0..13 {
            at_limit.extend_from_slice(b"&extension=inert");
        }
        let result = pending(now)
            .accept_form_post(at_limit.clone(), now)
            .unwrap();
        let OAuthAuthorizationResponse::Code(code) = result else {
            panic!("expected code")
        };
        assert_eq!(code.unknown_parameter_count(), 13);
        at_limit.extend_from_slice(b"&extension=inert");
        assert_eq!(error(at_limit), OAuthAuthorizationError::TooManyParameters);
    }

    #[test]
    fn percent_decoding_is_once_strict_utf8_and_bounds_all_fields() {
        for suffix in ["%", "%0", "%GG", "%2x"] {
            assert_eq!(
                error(response(&format!("code={suffix}"))),
                OAuthAuthorizationError::MalformedForm
            );
        }
        for suffix in ["%FF", "%C0%AF", "%ED%A0%80"] {
            assert_eq!(
                error(response(&format!("code={suffix}"))),
                OAuthAuthorizationError::InvalidUtf8
            );
        }
        assert_eq!(
            error(response("%FF=x&code=CANARY")),
            OAuthAuthorizationError::InvalidUtf8
        );
        assert_eq!(
            error(response(&format!("{}=x&code=CANARY", "k".repeat(129)))),
            OAuthAuthorizationError::KeyTooLarge
        );
        assert_eq!(
            error(response(&format!(
                "extension={}&code=CANARY",
                "x".repeat(2_049)
            ))),
            OAuthAuthorizationError::FieldTooLarge
        );
        assert_eq!(
            error(response(&format!("code={}", "x".repeat(2_049)))),
            OAuthAuthorizationError::FieldTooLarge
        );
        assert_eq!(
            error(vec![b'x'; 8_193]),
            OAuthAuthorizationError::ResponseTooLarge
        );
        let now = Instant::now();
        assert!(pending(now)
            .accept_form_post(
                response(&format!(
                    "{}={}&code=CANARY",
                    "k".repeat(128),
                    "x".repeat(2_048)
                )),
                now
            )
            .is_ok());
        assert!(pending(now)
            .accept_form_post(response(&format!("code={}", "x".repeat(2_048))), now)
            .is_ok());
        // A percent sequence remaining after one decode is literal code data.
        let OAuthAuthorizationResponse::Code(code) = pending(now)
            .accept_form_post(response("code=%252F+CANARY"), now)
            .unwrap()
        else {
            panic!("expected code")
        };
        assert_eq!(code.into_parts().code.as_str(), "%2F CANARY");
    }

    #[test]
    fn authorization_url_refuses_encoded_growth_before_secret_allocation() {
        let (code, mut authorization) = policy();
        let now = Instant::now();
        // Test-only corruption exercises the final bound independently of the
        // policy's smaller URL cap; no public constructor admits this endpoint.
        authorization.authorization_endpoint = Url::parse(&format!(
            "https://issuer.test/realms/owned/{}",
            "a".repeat(4_096)
        ))
        .unwrap();
        let transaction = PendingOAuthAuthorization::generate_with_entropy(
            &code,
            &authorization,
            POLICY_REFERENCE,
            PRINCIPAL,
            now,
            now + Duration::from_secs(1),
            |bytes| {
                bytes.fill(1);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            transaction.authorization_url().unwrap_err(),
            OAuthAuthorizationError::AuthorizationUrlTooLarge
        );
    }

    #[test]
    fn debug_and_all_static_errors_exclude_private_transaction_material() {
        let now = Instant::now();
        assert_eq!(
            format!("{:?}", pending(now)),
            "PendingOAuthAuthorization(<redacted>)"
        );
        for source in [
            response("code=SYNTHETIC-CODE&state=PRIVATE-SECOND-STATE"),
            response("code=SYNTHETIC-CODE&iss=https%3A%2F%2FPRIVATE.invalid"),
            response("error=SYNTHETIC_PROVIDER_SECRET&error_description=PRIVATE-DESCRIPTION&code=PRIVATE-CODE"),
        ] {
            let failure = error(source);
            let text = format!("{failure:?}: {failure}");
            for secret in [STATE, VERIFIER, TRANSACTION, "SYNTHETIC", "PRIVATE", ISSUER] {
                assert!(!text.contains(secret));
            }
        }
    }
}
