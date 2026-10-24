//! Pure codecs for an explicitly imported public-client code/S256 grant.
//!
//! Importing a verifier/challenge pair does not prove client initiation, CSRF
//! protection, issuer authenticity or authorization-server PKCE enforcement.
//! Transport, single-use dispatch, response completeness and runtime authority
//! belong to the parent runtime, never to these parsers.

use std::{fmt, ops::Range};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
    Deserialize,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::{Host, Url};
use zeroize::Zeroizing;

use super::{
    SuppliedSessionAuthorization, SuppliedSessionPolicy, SuppliedSessionPolicyError,
    HARD_MAX_SUPPLIED_SESSION_OAUTH_CODE_SECRET_BYTES,
    MAX_SUPPLIED_SESSION_OAUTH_TOKEN_RESPONSE_BYTES,
};

const PROFILE: &str = "external-public-code-s256-bearer/v1";
const HTTPS: &str = "verified-https/v1";
const OWNED_HTTP: &str = "owned-numeric-loopback-http/v1";
const MAX_URL_BYTES: usize = 2_048;
const MAX_CLIENT_BYTES: usize = 128;
const MAX_SCOPE_COUNT: usize = 8;
const MAX_SCOPE_BYTES: usize = 64;
const MAX_CODE_BYTES: usize = 2_048;
const MAX_TOKEN_BYTES: usize = 8 * 1_024;
const MAX_FORM_BYTES: usize = 16 * 1_024;
const MAX_JSON_NODES: usize = 256;
const MAX_JSON_KEYS: usize = 128;
const MAX_JSON_KEY_BYTES: usize = 128;
const MAX_JSON_DEPTH: usize = 8;
const MAX_UNIX_SECONDS: i64 = 253_402_300_799;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireOAuthCodePolicy {
    pub(super) profile: String,
    pub(super) transport_profile: String,
    pub(super) issuer: String,
    pub(super) token_endpoint: String,
    pub(super) client_id: String,
    pub(super) redirect_uri: String,
    pub(super) scopes: Vec<String>,
    pub(super) max_token_response_bytes: usize,
}

/// Validated non-secret configuration, not a network permit.
#[derive(Clone)]
pub(crate) struct OAuthCodePolicy {
    issuer: Url,
    token_endpoint: Url,
    client_id: String,
    redirect_uri: Url,
    scopes: Vec<String>,
    max_token_response_bytes: usize,
    transport_profile: String,
    binding_reference: String,
}

impl OAuthCodePolicy {
    pub(super) fn from_wire(
        mut wire: WireOAuthCodePolicy,
    ) -> Result<Self, SuppliedSessionPolicyError> {
        let invalid = || SuppliedSessionPolicyError::InvalidOAuthCode;
        if wire.profile != PROFILE
            || !matches!(wire.transport_profile.as_str(), HTTPS | OWNED_HTTP)
            || wire.client_id.is_empty()
            || wire.client_id.len() > MAX_CLIENT_BYTES
            || !wire.client_id.bytes().all(visible_ascii)
            || wire.scopes.is_empty()
            || wire.scopes.len() > MAX_SCOPE_COUNT
            || wire.scopes.iter().any(|scope| !valid_scope(scope))
            || wire.max_token_response_bytes == 0
            || wire.max_token_response_bytes > MAX_SUPPLIED_SESSION_OAUTH_TOKEN_RESPONSE_BYTES
        {
            return Err(invalid());
        }
        wire.scopes.sort();
        if wire.scopes.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(invalid());
        }
        let issuer = safe_url(&wire.issuer, &wire.transport_profile).ok_or_else(invalid)?;
        let token_endpoint =
            safe_url(&wire.token_endpoint, &wire.transport_profile).ok_or_else(invalid)?;
        let redirect_uri =
            safe_url(&wire.redirect_uri, &wire.transport_profile).ok_or_else(invalid)?;
        if issuer.origin() != token_endpoint.origin()
            || !path_beneath(issuer.path(), token_endpoint.path())
        {
            return Err(invalid());
        }
        let mut hasher = Sha256::new();
        hasher.update(b"security.supplied-session.oauth-code-policy.v1\0");
        for field in [
            PROFILE,
            wire.transport_profile.as_str(),
            issuer.as_str(),
            token_endpoint.as_str(),
            wire.client_id.as_str(),
            redirect_uri.as_str(),
        ] {
            super::hash_field(&mut hasher, field.as_bytes());
        }
        let scope_count = u64::try_from(wire.scopes.len()).map_err(|_| invalid())?;
        super::hash_field(&mut hasher, &scope_count.to_be_bytes());
        for scope in &wire.scopes {
            super::hash_field(&mut hasher, scope.as_bytes());
        }
        let response_cap = u64::try_from(wire.max_token_response_bytes).map_err(|_| invalid())?;
        super::hash_field(&mut hasher, &response_cap.to_be_bytes());
        let binding_reference =
            format!("oauth-code-policy-sha256:{}", super::hex(hasher.finalize()));
        Ok(Self {
            issuer,
            token_endpoint,
            client_id: wire.client_id,
            redirect_uri,
            scopes: wire.scopes,
            max_token_response_bytes: wire.max_token_response_bytes,
            transport_profile: wire.transport_profile,
            binding_reference,
        })
    }

    pub(crate) fn issuer(&self) -> &Url {
        &self.issuer
    }

    pub(crate) fn token_endpoint(&self) -> &Url {
        &self.token_endpoint
    }

    pub(crate) fn client_id(&self) -> &str {
        &self.client_id
    }

    pub(crate) fn redirect_uri(&self) -> &Url {
        &self.redirect_uri
    }

    pub(crate) fn scopes(&self) -> &[String] {
        &self.scopes
    }

    pub(crate) const fn max_token_response_bytes(&self) -> usize {
        self.max_token_response_bytes
    }

    pub(crate) fn transport_profile(&self) -> &str {
        &self.transport_profile
    }

    pub(crate) fn binding_reference(&self) -> &str {
        &self.binding_reference
    }

    pub(crate) fn is_valid_for_application(&self, application: &Url) -> bool {
        // The parent owns validation of the original application input. This
        // method narrows an already parsed application; it cannot recover raw
        // material that a caller normalized before constructing its Url.
        application.path().ends_with('/')
            && safe_url(application.as_str(), &self.transport_profile).as_ref() == Some(application)
    }
}

impl fmt::Debug for OAuthCodePolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthCodePolicy")
            .field("profile", &PROFILE)
            .field("transport_profile", &self.transport_profile)
            .field("scope_count", &self.scopes.len())
            .field("max_token_response_bytes", &self.max_token_response_bytes)
            .field("binding_reference", &self.binding_reference)
            .finish()
    }
}

fn safe_url(raw: &str, transport: &str) -> Option<Url> {
    if raw.is_empty()
        || raw.len() > MAX_URL_BYTES
        || !raw.bytes().all(visible_ascii)
        || raw
            .bytes()
            .any(|byte| matches!(byte, b'?' | b'#' | b'%' | b'\\'))
    {
        return None;
    }
    let (scheme, remainder) = raw.split_once("://")?;
    if !matches!(scheme, "https" | "http") || remainder.starts_with('/') {
        return None;
    }
    let authority_end = remainder.find('/').unwrap_or(remainder.len());
    if remainder[..authority_end].contains('@') {
        return None;
    }
    let raw_path = &remainder[authority_end..];
    if raw_path.contains("//") || raw_path.split('/').any(|part| matches!(part, "." | "..")) {
        return None;
    }
    let parsed = Url::parse(raw).ok()?;
    if parsed.as_str() != raw
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.port() == Some(0)
    {
        return None;
    }
    match parsed.host()? {
        Host::Domain(host) if host.ends_with('.') => return None,
        _ => {},
    }
    if parsed.scheme() == "http"
        && !(transport == OWNED_HTTP
            && match parsed.host()? {
                Host::Ipv4(address) => address.is_loopback(),
                Host::Ipv6(address) => address.is_loopback(),
                Host::Domain(_) => false,
            })
    {
        return None;
    }
    Some(parsed)
}

fn path_beneath(parent: &str, child: &str) -> bool {
    let directory = parent.trim_end_matches('/');
    directory.is_empty()
        || child == directory
        || child
            .strip_prefix(directory)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn visible_ascii(byte: u8) -> bool {
    matches!(byte, 0x21..=0x7e)
}

fn valid_scope(scope: &str) -> bool {
    !scope.is_empty()
        && scope.len() <= MAX_SCOPE_BYTES
        && !matches!(scope, "openid" | "offline_access")
        && scope
            .bytes()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
}

fn scope_matches(raw: &str, policy: &OAuthCodePolicy) -> bool {
    let mut scopes = Vec::new();
    for scope in raw.split(' ') {
        if scopes.len() == MAX_SCOPE_COUNT || !valid_scope(scope) {
            return false;
        }
        scopes.push(scope);
    }
    scopes.sort_unstable();
    !scopes.windows(2).any(|pair| pair[0] == pair[1])
        && scopes.len() == policy.scopes().len()
        && scopes
            .iter()
            .zip(policy.scopes())
            .all(|(actual, expected)| *actual == expected.as_str())
}

/// Static failures which never include grant, token or provider text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum OAuthCodeInputError {
    /// A secret source exceeded its fixed input ceiling.
    #[error("imported OAuth code input exceeds its byte limit")]
    SecretTooLarge,
    /// Rows, text, exact keys or the local verifier relationship were invalid.
    #[error("imported OAuth code input is malformed")]
    MalformedGrant,
    /// Repeated context did not agree with the independently selected policy.
    #[error("imported OAuth code input does not match the selected policy")]
    PolicyMismatch,
    /// The asserted receipt time was outside the permitted freshness window.
    #[error("imported OAuth code receipt time is outside its permitted window")]
    StaleGrant,
    /// The token response was structurally invalid or exceeded local limits.
    #[error("OAuth token response is invalid for the selected bounded profile")]
    InvalidTokenResponse,
    /// The response required unsupported token or identity semantics.
    #[error("OAuth token response requires an unsupported token profile")]
    UnsupportedTokenProfile,
}

/// Move-only imported grant bound to one selected policy and principal alias.
pub struct SuppliedSessionOAuthGrant {
    backing: Zeroizing<Vec<u8>>,
    code: Range<usize>,
    verifier: Range<usize>,
    policy_reference: String,
    oauth_binding: String,
    principal_alias: String,
    received_unix_seconds: i64,
}

impl SuppliedSessionOAuthGrant {
    /// Parses eight exact TSV keys without trimming or exporting secret values.
    /// Receipt time and the local S256 relationship are assertions, not proof of
    /// an authorization interaction or authorization-server enforcement.
    pub fn parse_tsv(
        policy: &SuppliedSessionPolicy,
        source: Vec<u8>,
        now_unix_seconds: i64,
    ) -> Result<Self, OAuthCodeInputError> {
        let backing = Zeroizing::new(source);
        if backing.len() > HARD_MAX_SUPPLIED_SESSION_OAUTH_CODE_SECRET_BYTES {
            return Err(OAuthCodeInputError::SecretTooLarge);
        }
        let oauth = policy
            .oauth_code_policy()
            .ok_or(OAuthCodeInputError::PolicyMismatch)?;
        if backing.is_empty()
            || backing.starts_with(&[0xef, 0xbb, 0xbf])
            || std::str::from_utf8(&backing).is_err()
        {
            return Err(OAuthCodeInputError::MalformedGrant);
        }
        let mut fields: [Option<Range<usize>>; 8] = std::array::from_fn(|_| None);
        let mut cursor = 0;
        let mut rows = 0;
        while cursor < backing.len() {
            rows += 1;
            if rows > fields.len() {
                return Err(OAuthCodeInputError::MalformedGrant);
            }
            let physical_end = backing[cursor..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(backing.len(), |offset| cursor + offset);
            let mut end = physical_end;
            if physical_end < backing.len() && end > cursor && backing[end - 1] == b'\r' {
                end -= 1;
            }
            let line = &backing[cursor..end];
            let tab = line
                .iter()
                .position(|byte| *byte == b'\t')
                .ok_or(OAuthCodeInputError::MalformedGrant)?;
            let index = match &line[..tab] {
                b"authorization_code" => 0,
                b"code_verifier" => 1,
                b"code_challenge" => 2,
                b"issuer" => 3,
                b"client_id" => 4,
                b"redirect_uri" => 5,
                b"scope" => 6,
                b"received_unix_seconds" => 7,
                _ => return Err(OAuthCodeInputError::MalformedGrant),
            };
            let start = cursor + tab + 1;
            if fields[index].is_some()
                || start == end
                || !backing[start..end]
                    .iter()
                    .all(|byte| matches!(*byte, 0x20..=0x7e))
            {
                return Err(OAuthCodeInputError::MalformedGrant);
            }
            fields[index] = Some(start..end);
            cursor = if physical_end == backing.len() {
                backing.len()
            } else {
                physical_end + 1
            };
        }
        if rows != fields.len() || fields.iter().any(Option::is_none) {
            return Err(OAuthCodeInputError::MalformedGrant);
        }
        let value = |index: usize| {
            std::str::from_utf8(&backing[fields[index].clone().expect("all fields checked")])
                .expect("the complete guarded input is UTF-8")
        };
        if value(0).len() > MAX_CODE_BYTES
            || !value(0).bytes().all(visible_ascii)
            || !(43..=128).contains(&value(1).len())
            || !value(1).bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
            })
            || value(2).len() != 43
            || !value(2)
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(OAuthCodeInputError::MalformedGrant);
        }
        let digest = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(value(1).as_bytes())));
        let expected = Zeroizing::new(URL_SAFE_NO_PAD.encode(digest.as_slice()));
        if expected.as_bytes() != value(2).as_bytes() {
            return Err(OAuthCodeInputError::MalformedGrant);
        }
        if value(3) != oauth.issuer().as_str()
            || value(4) != oauth.client_id()
            || value(5) != oauth.redirect_uri().as_str()
            || !scope_matches(value(6), oauth)
        {
            return Err(OAuthCodeInputError::PolicyMismatch);
        }
        let timestamp = value(7);
        if timestamp.len() > 12
            || !timestamp.bytes().all(|byte| byte.is_ascii_digit())
            || (timestamp.len() > 1 && timestamp.starts_with('0'))
        {
            return Err(OAuthCodeInputError::MalformedGrant);
        }
        let received_unix_seconds = timestamp
            .parse::<i64>()
            .map_err(|_| OAuthCodeInputError::MalformedGrant)?;
        if !fresh(received_unix_seconds, now_unix_seconds) {
            return Err(OAuthCodeInputError::StaleGrant);
        }
        let code = fields[0].clone().expect("all fields checked");
        let verifier = fields[1].clone().expect("all fields checked");
        Ok(Self {
            backing,
            code,
            verifier,
            policy_reference: policy.policy_reference().to_owned(),
            oauth_binding: oauth.binding_reference.clone(),
            principal_alias: policy.principal_alias().to_owned(),
            received_unix_seconds,
        })
    }

    pub(crate) fn matches_policy(&self, policy: &SuppliedSessionPolicy) -> bool {
        self.policy_reference == policy.policy_reference()
            && self.principal_alias == policy.principal_alias()
            && policy
                .oauth_code_policy()
                .is_some_and(|oauth| self.oauth_binding == oauth.binding_reference)
    }

    /// Rechecks only the imported, operator-asserted receipt timestamp.
    pub(crate) fn is_fresh_at(&self, now_unix_seconds: i64) -> bool {
        fresh(self.received_unix_seconds, now_unix_seconds)
    }

    pub(crate) fn compose_form_body(
        &self,
        policy: &SuppliedSessionPolicy,
    ) -> Result<OAuthCodeFormBody, OAuthCodeInputError> {
        if !self.matches_policy(policy) {
            return Err(OAuthCodeInputError::PolicyMismatch);
        }
        let oauth = policy
            .oauth_code_policy()
            .ok_or(OAuthCodeInputError::PolicyMismatch)?;
        let text = |range: Range<usize>| {
            std::str::from_utf8(&self.backing[range]).expect("grant UTF-8 was validated")
        };
        let mut body = Zeroizing::new(String::new());
        {
            let mut form = url::form_urlencoded::Serializer::new(&mut *body);
            form.append_pair("grant_type", "authorization_code");
            form.append_pair("client_id", oauth.client_id());
            form.append_pair("redirect_uri", oauth.redirect_uri().as_str());
            form.append_pair("code", text(self.code.clone()));
            form.append_pair("code_verifier", text(self.verifier.clone()));
            form.finish();
        }
        if body.len() > MAX_FORM_BYTES {
            return Err(OAuthCodeInputError::SecretTooLarge);
        }
        Ok(OAuthCodeFormBody { value: body })
    }
}

fn fresh(received: i64, now: i64) -> bool {
    (0..=MAX_UNIX_SECONDS).contains(&received)
        && (0..=MAX_UNIX_SECONDS).contains(&now)
        && if received <= now {
            now - received <= 60
        } else {
            received - now <= 5
        }
}

impl fmt::Debug for SuppliedSessionOAuthGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SuppliedSessionOAuthGrant(<redacted>)")
    }
}

/// Guarded form bytes available only at the crate-owned composition boundary.
pub(crate) struct OAuthCodeFormBody {
    value: Zeroizing<String>,
}

impl OAuthCodeFormBody {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.value.as_bytes()
    }
}

impl fmt::Debug for OAuthCodeFormBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OAuthCodeFormBody(<redacted>)")
    }
}

/// A guarded response reduction, not proof of token acceptance or identity.
pub(crate) struct OAuthCodeTokenResponse {
    access_token: Zeroizing<String>,
    expires_in_seconds: u64,
    refresh_token_returned: bool,
}

impl OAuthCodeTokenResponse {
    pub(crate) fn into_authorization(
        self,
    ) -> Result<SuppliedSessionAuthorization, OAuthCodeInputError> {
        let mut header = Zeroizing::new(Vec::with_capacity(7 + self.access_token.len()));
        header.extend_from_slice(b"Bearer ");
        header.extend_from_slice(self.access_token.as_bytes());
        SuppliedSessionAuthorization::new(std::mem::take(&mut *header))
            .map_err(|_| OAuthCodeInputError::InvalidTokenResponse)
    }

    pub(crate) const fn expires_in_seconds(&self) -> u64 {
        self.expires_in_seconds
    }

    pub(crate) const fn refresh_token_returned(&self) -> bool {
        self.refresh_token_returned
    }
}

impl fmt::Debug for OAuthCodeTokenResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OAuthCodeTokenResponse(<redacted>)")
    }
}

/// Parses inert bounded JSON. The caller separately proves HTTP status, MIME,
/// identity coding, end-of-body, byte accounting and response commit.
pub(crate) fn parse_token_response(
    policy: &OAuthCodePolicy,
    body: Zeroizing<Vec<u8>>,
) -> Result<OAuthCodeTokenResponse, OAuthCodeInputError> {
    if body.is_empty()
        || body.len() > policy.max_token_response_bytes
        || body.len() > MAX_SUPPLIED_SESSION_OAUTH_TOKEN_RESPONSE_BYTES
    {
        return Err(OAuthCodeInputError::InvalidTokenResponse);
    }
    let mut budget = JsonBudget::default();
    let mut decoder = serde_json::Deserializer::from_slice(&body);
    let value = JsonSeed {
        budget: &mut budget,
        depth: 0,
    }
    .deserialize(&mut decoder)
    .map_err(|_| OAuthCodeInputError::InvalidTokenResponse)?;
    decoder
        .end()
        .map_err(|_| OAuthCodeInputError::InvalidTokenResponse)?;
    let JsonValue::Object(entries) = value else {
        return Err(OAuthCodeInputError::InvalidTokenResponse);
    };
    let mut access_token = None;
    let mut token_type = None;
    let mut expires = None;
    let mut scope = None;
    let mut refresh_token_returned = false;
    for (key, value) in entries {
        match key.as_str() {
            "id_token" => return Err(OAuthCodeInputError::UnsupportedTokenProfile),
            "error" | "error_description" | "error_uri" => {
                return Err(OAuthCodeInputError::InvalidTokenResponse);
            },
            "access_token" => access_token = Some(require_string(value)?),
            "token_type" => token_type = Some(require_string(value)?),
            "expires_in" => {
                let JsonValue::Unsigned(seconds @ 1..=3_600) = value else {
                    return Err(OAuthCodeInputError::InvalidTokenResponse);
                };
                expires = Some(seconds);
            },
            "scope" => scope = Some(require_string(value)?),
            "refresh_token" => {
                let token = require_string(value)?;
                if token.as_str().is_empty() {
                    return Err(OAuthCodeInputError::InvalidTokenResponse);
                }
                // The guarded string drops here. It is never retained for use.
                refresh_token_returned = true;
            },
            _ => {}, // RFC 6749 section 5.1 extension values remain inert.
        }
    }
    let access_token = access_token.ok_or(OAuthCodeInputError::InvalidTokenResponse)?;
    let token_type = token_type.ok_or(OAuthCodeInputError::InvalidTokenResponse)?;
    let scope = scope.ok_or(OAuthCodeInputError::InvalidTokenResponse)?;
    if !token_type.as_str().eq_ignore_ascii_case("Bearer") {
        return Err(OAuthCodeInputError::UnsupportedTokenProfile);
    }
    if !valid_bearer(access_token.as_str()) || !scope_matches(scope.as_str(), policy) {
        return Err(OAuthCodeInputError::InvalidTokenResponse);
    }
    Ok(OAuthCodeTokenResponse {
        access_token: access_token.value,
        expires_in_seconds: expires.ok_or(OAuthCodeInputError::InvalidTokenResponse)?,
        refresh_token_returned,
    })
}

fn valid_bearer(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_TOKEN_BYTES
        || value.len() + 7 > super::MAX_AUTHORIZATION_HEADER_BYTES
    {
        return false;
    }
    let (base, padding) = value
        .find('=')
        .map_or((value, ""), |index| value.split_at(index));
    !base.is_empty()
        && base.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
        && padding.bytes().all(|byte| byte == b'=')
}

fn require_string(value: JsonValue) -> Result<GuardedText, OAuthCodeInputError> {
    match value {
        JsonValue::Text(text) => Ok(text),
        _ => Err(OAuthCodeInputError::InvalidTokenResponse),
    }
}

struct GuardedText {
    value: Zeroizing<String>,
}

impl GuardedText {
    fn as_str(&self) -> &str {
        self.value.as_str()
    }
}

impl<'de> Deserialize<'de> for GuardedText {
    fn deserialize<D: de::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct TextVisitor;
        impl Visitor<'_> for TextVisitor {
            type Value = GuardedText;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded OAuth response string")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                self.visit_string(value.to_owned())
            }

            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                let value = Zeroizing::new(value);
                if value.len() > MAX_TOKEN_BYTES {
                    return Err(E::custom("OAuth response string exceeds its bound"));
                }
                Ok(GuardedText { value })
            }
        }
        decoder.deserialize_string(TextVisitor)
    }
}

enum JsonValue {
    Text(GuardedText),
    Unsigned(u64),
    Object(Vec<(GuardedText, Self)>),
    Other,
}

#[derive(Default)]
struct JsonBudget {
    nodes: usize,
    keys: usize,
    string_bytes: usize,
}

impl JsonBudget {
    fn string<E: de::Error>(&mut self, length: usize) -> Result<(), E> {
        self.string_bytes = self
            .string_bytes
            .checked_add(length)
            .ok_or_else(|| E::custom("OAuth response string accounting exceeded"))?;
        if self.string_bytes > MAX_SUPPLIED_SESSION_OAUTH_TOKEN_RESPONSE_BYTES {
            return Err(E::custom("OAuth response string accounting exceeded"));
        }
        Ok(())
    }
}

struct JsonSeed<'a> {
    budget: &'a mut JsonBudget,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for JsonSeed<'_> {
    type Value = JsonValue;

    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        self.budget.nodes = self.budget.nodes.checked_add(1).ok_or_else(|| {
            <D::Error as de::Error>::custom("OAuth response node accounting exceeded")
        })?;
        if self.budget.nodes > MAX_JSON_NODES || self.depth > MAX_JSON_DEPTH {
            return Err(de::Error::custom(
                "OAuth response nesting or work limit exceeded",
            ));
        }
        decoder.deserialize_any(JsonVisitor {
            budget: self.budget,
            depth: self.depth,
        })
    }
}

struct JsonVisitor<'a> {
    budget: &'a mut JsonBudget,
    depth: usize,
}

impl<'de> Visitor<'de> for JsonVisitor<'_> {
    type Value = JsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded OAuth response JSON")
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
        Ok(JsonValue::Other)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(JsonValue::Other)
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(u64::try_from(value).map_or(JsonValue::Other, JsonValue::Unsigned))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(JsonValue::Unsigned(value))
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Ok(JsonValue::Other)
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        let value = Zeroizing::new(value);
        if value.len() > MAX_TOKEN_BYTES {
            return Err(E::custom("OAuth response string exceeds its bound"));
        }
        self.budget.string(value.len())?;
        Ok(JsonValue::Text(GuardedText { value }))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        while sequence
            .next_element_seed(JsonSeed {
                budget: &mut *self.budget,
                depth: self.depth + 1,
            })?
            .is_some()
        {}
        Ok(JsonValue::Other)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut entries: Vec<(GuardedText, JsonValue)> = Vec::new();
        while let Some(key) = map.next_key::<GuardedText>()? {
            self.budget.keys = self.budget.keys.checked_add(1).ok_or_else(|| {
                <A::Error as de::Error>::custom("OAuth response key accounting exceeded")
            })?;
            if self.budget.keys > MAX_JSON_KEYS
                || key.as_str().len() > MAX_JSON_KEY_BYTES
                || entries
                    .iter()
                    .any(|(previous, _)| previous.as_str() == key.as_str())
            {
                return Err(de::Error::custom("OAuth response key contract exceeded"));
            }
            self.budget.string(key.as_str().len())?;
            let value = map.next_value_seed(JsonSeed {
                budget: &mut *self.budget,
                depth: self.depth + 1,
            })?;
            entries.push((key, value));
        }
        Ok(JsonValue::Object(entries))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Public RFC 7636 appendix-B known-answer values, not captured credentials:
    // https://www.rfc-editor.org/rfc/rfc7636.html#appendix-B
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const RESPONSE: &str = r#"{"access_token":"SYNTHETIC.ACCESS_TOKEN+/==","token_type":"Bearer","expires_in":60,"scope":"canary-read"}"#;

    fn wire() -> WireOAuthCodePolicy {
        WireOAuthCodePolicy {
            profile: PROFILE.to_owned(),
            transport_profile: HTTPS.to_owned(),
            issuer: "https://issuer.test/realm".to_owned(),
            token_endpoint: "https://issuer.test/realm/token".to_owned(),
            client_id: "owned-client".to_owned(),
            redirect_uri: "https://client.test/callback".to_owned(),
            scopes: vec!["canary-read".to_owned()],
            max_token_response_bytes: 32_768,
        }
    }

    fn oauth() -> OAuthCodePolicy {
        OAuthCodePolicy::from_wire(wire()).unwrap()
    }

    fn policy(alias: &str) -> SuppliedSessionPolicy {
        let source = format!(
            r#"schema = "security.supplied-session-policy/v5"
principal_alias = "{alias}"
credential_mechanism = "authorization_header"
credential_acquisition = "imported_oauth_code_pkce"
health_path = "/app/health"
health_json_field = "authenticated"
resources = ["/app/private"]
max_session_requests = 4
max_total_response_bytes = 65536
max_response_body_bytes = 8192
max_wall_time_ms = 10000
[oauth_code]
profile = "external-public-code-s256-bearer/v1"
transport_profile = "verified-https/v1"
issuer = "https://issuer.test/realm"
token_endpoint = "https://issuer.test/realm/token"
client_id = "owned-client"
redirect_uri = "https://client.test/callback"
scopes = ["canary-read"]
max_token_response_bytes = 8192
"#
        );
        SuppliedSessionPolicy::parse_toml(
            &Url::parse("https://application.test/app/").unwrap(),
            source.as_bytes(),
        )
        .unwrap()
    }

    fn grant_source(code: &str, received: i64) -> Vec<u8> {
        format!(
            "authorization_code\t{code}\ncode_verifier\t{VERIFIER}\ncode_challenge\t{CHALLENGE}\nissuer\thttps://issuer.test/realm\nclient_id\towned-client\nredirect_uri\thttps://client.test/callback\nscope\tcanary-read\nreceived_unix_seconds\t{received}\n"
        )
        .into_bytes()
    }

    fn token(body: &str) -> Result<OAuthCodeTokenResponse, OAuthCodeInputError> {
        parse_token_response(&oauth(), Zeroizing::new(body.as_bytes().to_vec()))
    }

    #[test]
    fn oauth_code_policy_has_stable_nonsecret_canonical_binding_and_bounds() {
        let original = oauth();
        assert_eq!(original.issuer().as_str(), "https://issuer.test/realm");
        assert_eq!(
            original.token_endpoint().as_str(),
            "https://issuer.test/realm/token"
        );
        assert_eq!(original.client_id(), "owned-client");
        assert_eq!(
            original.redirect_uri().as_str(),
            "https://client.test/callback"
        );
        assert_eq!(original.scopes(), &["canary-read"]);
        assert_eq!(original.max_token_response_bytes(), 32_768);
        assert_eq!(original.transport_profile(), HTTPS);
        // Independently frozen with Python hashlib/struct over nine literal
        // framed non-secret fields, not generated by this production helper.
        assert_eq!(
            original.binding_reference(),
            "oauth-code-policy-sha256:72e15098e7d39ca96ee6619165d087b919b49b2862cbe50393c5bc79f2a558f9"
        );
        assert!(original
            .binding_reference()
            .starts_with("oauth-code-policy-sha256:"));
        assert_eq!(
            original
                .binding_reference()
                .strip_prefix("oauth-code-policy-sha256:")
                .unwrap()
                .len(),
            64
        );
        let mut first = wire();
        first.scopes = vec!["write".to_owned(), "read".to_owned()];
        let mut second = wire();
        second.scopes = vec!["read".to_owned(), "write".to_owned()];
        let first = OAuthCodePolicy::from_wire(first).unwrap();
        let second = OAuthCodePolicy::from_wire(second).unwrap();
        assert_eq!(first.binding_reference(), second.binding_reference());
        let mut smaller = wire();
        smaller.max_token_response_bytes -= 1;
        assert_ne!(
            original.binding_reference(),
            OAuthCodePolicy::from_wire(smaller)
                .unwrap()
                .binding_reference()
        );
        assert!(original
            .is_valid_for_application(&Url::parse("https://application.test/app/").unwrap()));
        assert!(
            !original.is_valid_for_application(&Url::parse("http://127.0.0.1:8080/app/").unwrap())
        );
    }

    #[test]
    fn oauth_code_policy_rejects_unsafe_urls_before_normalization() {
        for value in [
            "https://issuer.test/realm/../other",
            "https://issuer.test/realm/./token",
            "https://issuer.test/realm/%2e%2e/token",
            "https://issuer.test/realm%2ftoken",
            "https://issuer.test/realm\\token",
            "https://issuer.test/realm?code=value",
            "https://issuer.test/realm#part",
            "https://reader@issuer.test/realm",
            "https://reader:password@issuer.test/realm",
            "https://ISSUER.test/realm",
            "https://issuer.test:443/realm",
            "https:issuer.test/realm",
            " https://issuer.test/realm",
            "https://issuer.test/realm\n",
            "https://issuer.test//realm",
            "https://issuer.test./realm",
            "https://issuer.test:0/realm",
        ] {
            let mut input = wire();
            input.issuer = value.to_owned();
            assert!(
                OAuthCodePolicy::from_wire(input).is_err(),
                "unsafe issuer admitted"
            );
            let mut input = wire();
            input.redirect_uri = value.to_owned();
            assert!(
                OAuthCodePolicy::from_wire(input).is_err(),
                "unsafe redirect admitted"
            );
        }
        for endpoint in [
            "https://issuer.test/realm-evil/token",
            "https://issuer.test/real/token",
            "https://issuer.test:8443/realm/token",
            "https://other.test/realm/token",
            "http://issuer.test/realm/token",
        ] {
            let mut input = wire();
            input.token_endpoint = endpoint.to_owned();
            assert!(
                OAuthCodePolicy::from_wire(input).is_err(),
                "endpoint scope widened"
            );
        }
    }

    #[test]
    fn oauth_code_http_requires_the_explicit_numeric_loopback_profile() {
        for address in ["127.0.0.1", "[::1]"] {
            let mut input = wire();
            input.transport_profile = OWNED_HTTP.to_owned();
            input.issuer = format!("http://{address}:8080/realm");
            input.token_endpoint = format!("http://{address}:8080/realm/token");
            input.redirect_uri = format!("http://{address}:8081/callback");
            let parsed = OAuthCodePolicy::from_wire(input).unwrap();
            assert!(parsed.is_valid_for_application(
                &Url::parse(&format!("http://{address}:8082/app/")).unwrap()
            ));
        }
        for address in ["localhost", "127.1", "0.0.0.0", "192.0.2.1", "[::]"] {
            let mut input = wire();
            input.transport_profile = OWNED_HTTP.to_owned();
            input.issuer = format!("http://{address}:8080/realm");
            input.token_endpoint = format!("http://{address}:8080/realm/token");
            assert!(
                OAuthCodePolicy::from_wire(input).is_err(),
                "HTTP authority widened"
            );
        }
        let mut input = wire();
        input.issuer = "http://127.0.0.1:8080/realm".to_owned();
        input.token_endpoint = "http://127.0.0.1:8080/realm/token".to_owned();
        assert!(OAuthCodePolicy::from_wire(input).is_err());
    }

    #[test]
    fn oauth_code_policy_rejects_unsupported_profiles_and_nonfinite_scope_contracts() {
        for scopes in [
            vec![],
            vec!["read", "read"],
            vec!["openid"],
            vec!["offline_access"],
            vec!["read write"],
            vec!["read\twrite"],
            vec!["a\\b"],
            vec!["a\"b"],
            vec!["é"],
            vec!["read"; 9],
        ] {
            let mut input = wire();
            input.scopes = scopes.into_iter().map(str::to_owned).collect();
            assert!(OAuthCodePolicy::from_wire(input).is_err());
        }
        for maximum in [0, 32_769, usize::MAX] {
            let mut input = wire();
            input.max_token_response_bytes = maximum;
            assert!(OAuthCodePolicy::from_wire(input).is_err());
        }
        for client in [
            "".to_owned(),
            "x".repeat(129),
            "client secret".to_owned(),
            "client\r\n".to_owned(),
        ] {
            let mut input = wire();
            input.client_id = client;
            assert!(OAuthCodePolicy::from_wire(input).is_err());
        }
        let mut input = wire();
        input.scopes = vec!["s".repeat(65)];
        assert!(OAuthCodePolicy::from_wire(input).is_err());
        let mut input = wire();
        input.profile = "implicit-or-plain".to_owned();
        assert!(OAuthCodePolicy::from_wire(input).is_err());
    }

    #[test]
    fn oauth_code_wire_policy_rejects_unknown_duplicate_missing_and_wrong_types() {
        let source = r#"profile = "external-public-code-s256-bearer/v1"
transport_profile = "verified-https/v1"
issuer = "https://issuer.test/realm"
token_endpoint = "https://issuer.test/realm/token"
client_id = "owned-client"
redirect_uri = "https://client.test/callback"
scopes = ["canary-read"]
max_token_response_bytes = 8192
"#;
        assert!(toml::from_str::<WireOAuthCodePolicy>(source).is_ok());
        for malformed in [
            format!("{source}unknown = true\n"),
            format!("{source}client_id = \"other\"\n"),
            source.replace(
                "max_token_response_bytes = 8192",
                "max_token_response_bytes = true",
            ),
            source.replace("transport_profile = \"verified-https/v1\"\n", ""),
        ] {
            assert!(toml::from_str::<WireOAuthCodePolicy>(&malformed).is_err());
        }
    }

    #[test]
    fn oauth_code_grant_uses_the_literal_s256_answer_and_exact_five_field_encoding() {
        let selected = policy("canary-a");
        let grant = SuppliedSessionOAuthGrant::parse_tsv(
            &selected,
            grant_source("CODE+/=&?%", 1_000),
            1_000,
        )
        .unwrap();
        assert!(grant.matches_policy(&selected));
        assert!(grant.is_fresh_at(1_060));
        assert!(!grant.is_fresh_at(1_061));
        let body = grant.compose_form_body(&selected).unwrap();
        let expected = concat!(
            "grant_type=authorization_code&client_id=owned-client&redirect_uri=",
            "https%3A%2F%2Fclient.test%2Fcallback&code=CODE%2B%2F%3D%26%3F%25",
            "&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        );
        assert!(
            body.as_bytes() == expected.as_bytes(),
            "exact form oracle differed"
        );
        assert_eq!(url::form_urlencoded::parse(body.as_bytes()).count(), 5);
    }

    #[test]
    fn oauth_code_grant_supports_crlf_unordered_rows_but_never_trims_values() {
        let selected = policy("canary-a");
        let source = String::from_utf8(grant_source("SYNTHETIC-CODE", 1_000)).unwrap();
        let reversed = source.lines().rev().collect::<Vec<_>>().join("\r\n") + "\r\n";
        assert!(
            SuppliedSessionOAuthGrant::parse_tsv(&selected, reversed.into_bytes(), 1_000).is_ok()
        );
        for replacement in [" CODE", "CODE ", "CODE\tEXTRA", "CODE\rX", "CODE\0"] {
            assert!(
                SuppliedSessionOAuthGrant::parse_tsv(
                    &selected,
                    grant_source(replacement, 1_000),
                    1_000,
                )
                .is_err(),
                "secret value was normalized"
            );
        }
    }

    #[test]
    fn oauth_code_grant_rejects_missing_duplicate_unknown_and_malformed_rows() {
        let selected = policy("canary-a");
        let valid = String::from_utf8(grant_source("SYNTHETIC-CODE", 1_000)).unwrap();
        for index in 0..8 {
            let mut rows = valid.lines().collect::<Vec<_>>();
            rows.remove(index);
            assert!(SuppliedSessionOAuthGrant::parse_tsv(
                &selected,
                rows.join("\n").into_bytes(),
                1_000
            )
            .is_err());
            let mut rows = valid.lines().collect::<Vec<_>>();
            rows.push(rows[index]);
            assert!(SuppliedSessionOAuthGrant::parse_tsv(
                &selected,
                rows.join("\n").into_bytes(),
                1_000
            )
            .is_err());
        }
        for source in [
            Vec::new(),
            b"\xff".to_vec(),
            [b"\xef\xbb\xbf".as_slice(), valid.as_bytes()].concat(),
            (valid.clone() + "\n").into_bytes(),
            valid
                .replace("authorization_code\t", "unknown\t")
                .into_bytes(),
            format!("{}\r", valid.trim_end_matches('\n')).into_bytes(),
        ] {
            assert!(SuppliedSessionOAuthGrant::parse_tsv(&selected, source, 1_000).is_err());
        }
        assert_eq!(
            SuppliedSessionOAuthGrant::parse_tsv(&selected, vec![b'x'; 16_385], 1_000).unwrap_err(),
            OAuthCodeInputError::SecretTooLarge,
        );
    }

    #[test]
    fn oauth_code_grant_checks_each_context_and_principal_binding() {
        let selected = policy("canary-a");
        let valid = String::from_utf8(grant_source("SYNTHETIC-CODE", 1_000)).unwrap();
        for (from, to) in [
            ("https://issuer.test/realm", "https://other.test/realm"),
            ("client_id\towned-client", "client_id\tother-client"),
            ("https://client.test/callback", "https://client.test/other"),
            ("scope\tcanary-read", "scope\tother-scope"),
            ("scope\tcanary-read", "scope\tcanary-read canary-read"),
        ] {
            assert_eq!(
                SuppliedSessionOAuthGrant::parse_tsv(
                    &selected,
                    valid.replace(from, to).into_bytes(),
                    1_000,
                )
                .unwrap_err(),
                OAuthCodeInputError::PolicyMismatch
            );
        }
        let grant =
            SuppliedSessionOAuthGrant::parse_tsv(&selected, valid.into_bytes(), 1_000).unwrap();
        let peer = policy("canary-b");
        assert!(!grant.matches_policy(&peer));
        assert_eq!(
            grant.compose_form_body(&peer).unwrap_err(),
            OAuthCodeInputError::PolicyMismatch
        );
    }

    #[test]
    fn oauth_code_grant_rejects_plain_wrong_noncanonical_and_out_of_bounds_verifiers() {
        let selected = policy("canary-a");
        let source = String::from_utf8(grant_source("SYNTHETIC-CODE", 1_000)).unwrap();
        for (from, to) in [
            (VERIFIER, "short"),
            (VERIFIER, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX!"),
            (CHALLENGE, VERIFIER),
            (CHALLENGE, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cN"),
            (CHALLENGE, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM="),
        ] {
            assert_eq!(
                SuppliedSessionOAuthGrant::parse_tsv(
                    &selected,
                    source.replace(from, to).into_bytes(),
                    1_000,
                )
                .unwrap_err(),
                OAuthCodeInputError::MalformedGrant
            );
        }
        let oversized = source.replace(VERIFIER, &"x".repeat(129));
        assert!(
            SuppliedSessionOAuthGrant::parse_tsv(&selected, oversized.into_bytes(), 1_000).is_err()
        );
        assert!(SuppliedSessionOAuthGrant::parse_tsv(
            &selected,
            grant_source(&"x".repeat(2_049), 1_000),
            1_000
        )
        .is_err());
    }

    #[test]
    fn oauth_code_grant_freshness_is_bounded_asserted_time_not_remote_proof() {
        let selected = policy("canary-a");
        for (received, now, accepted) in [
            (1_000, 1_000, true),
            (940, 1_000, true),
            (939, 1_000, false),
            (1_005, 1_000, true),
            (1_006, 1_000, false),
            (0, 0, true),
            (1_000, -1, false),
            (1_000, i64::MAX, false),
            (i64::MAX, 1_000, false),
        ] {
            assert_eq!(
                SuppliedSessionOAuthGrant::parse_tsv(
                    &selected,
                    grant_source("SYNTHETIC-CODE", received),
                    now,
                )
                .is_ok(),
                accepted
            );
        }
    }

    #[test]
    fn oauth_code_token_is_an_opaque_guarded_bearer_and_refresh_is_only_a_fact() {
        let response = token(&RESPONSE.replace("Bearer", "bEaReR")).unwrap();
        assert_eq!(response.expires_in_seconds(), 60);
        assert!(!response.refresh_token_returned());
        let authorization = response.into_authorization().unwrap();
        assert!(
            authorization.as_str() == "Bearer SYNTHETIC.ACCESS_TOKEN+/==",
            "safe header composition differed"
        );
        let with_refresh = RESPONSE.replace(
            "\"scope\"",
            "\"refresh_token\":\"SYNTHETIC_REFRESH\",\"scope\"",
        );
        let response = token(&with_refresh).unwrap();
        assert!(response.refresh_token_returned());
    }

    #[test]
    fn oauth_code_token_requires_typed_explicit_scope_expiry_and_supported_type() {
        for body in [
            "[]",
            "null",
            "true",
            "{}",
            r#"{"access_token":"x","token_type":"Bearer","expires_in":true,"scope":"canary-read"}"#,
            r#"{"access_token":"x","token_type":"Bearer","expires_in":60.0,"scope":"canary-read"}"#,
            r#"{"access_token":"x","token_type":"Bearer","expires_in":"60","scope":"canary-read"}"#,
            r#"{"access_token":"x","token_type":"Bearer","expires_in":0,"scope":"canary-read"}"#,
            r#"{"access_token":"x","token_type":"Bearer","expires_in":3601,"scope":"canary-read"}"#,
            r#"{"access_token":"x","token_type":"Bearer","expires_in":60}"#,
            r#"{"access_token":"x","token_type":"Bearer","scope":"canary-read"}"#,
            r#"{"token_type":"Bearer","expires_in":60,"scope":"canary-read"}"#,
            r#"{"access_token":"x","expires_in":60,"scope":"canary-read"}"#,
            r#"{"access_token":true,"token_type":"Bearer","expires_in":60,"scope":"canary-read"}"#,
        ] {
            assert!(token(body).is_err(), "invalid token contract admitted");
        }
        for scope in [
            "other",
            "canary-read canary-read",
            " canary-read",
            "canary-read ",
        ] {
            assert!(token(&RESPONSE.replace("canary-read", scope)).is_err());
        }
        assert_eq!(
            token(&RESPONSE.replace("Bearer", "DPoP")).unwrap_err(),
            OAuthCodeInputError::UnsupportedTokenProfile
        );
        for value in ["null", "false", "{}", "\"\""] {
            let body = RESPONSE.replacen('{', &format!("{{\"id_token\":{value},"), 1);
            assert_eq!(
                token(&body).unwrap_err(),
                OAuthCodeInputError::UnsupportedTokenProfile
            );
        }
    }

    #[test]
    fn oauth_code_token_unknown_extensions_are_inert_but_duplicate_keys_always_fail() {
        let original = token(RESPONSE).unwrap();
        let extended = RESPONSE.replacen('{', "{\"provider_extension\":{\"values\":[1,true,null,{\"inert\":\"https://never-fetch.invalid/\"}]},", 1);
        let extended = token(&extended).unwrap();
        assert_eq!(extended.expires_in_seconds(), original.expires_in_seconds());
        assert!(!extended.refresh_token_returned());
        for extension in [
            "\"x\":1,\"x\":2,",
            "\"x\":{\"a\":1,\"a\":2},",
            "\"x\":[{\"a\":1,\"a\":2}],",
            "\"x\":1,\"\\u0078\":2,",
            "\"access_token\":\"other\",",
            "\"access_\\u0074oken\":\"other\",",
        ] {
            let body = RESPONSE.replacen('{', &format!("{{{extension}"), 1);
            assert!(token(&body).is_err(), "duplicate JSON key admitted");
        }
        assert!(token(&(RESPONSE.to_owned() + "{}")).is_err());
    }

    #[test]
    fn oauth_code_token_known_errors_and_invalid_refresh_are_not_extensions() {
        for field in ["error", "error_description", "error_uri"] {
            for value in ["null", "false", "\"SYNTHETIC_PROVIDER_ERROR\""] {
                let extended = RESPONSE.replacen('{', &format!("{{\"{field}\":{value},"), 1);
                assert_eq!(
                    token(&extended).unwrap_err(),
                    OAuthCodeInputError::InvalidTokenResponse
                );
            }
        }
        for value in ["null", "false", "{}", "\"\""] {
            let extended = RESPONSE.replacen('{', &format!("{{\"refresh_token\":{value},"), 1);
            assert_eq!(
                token(&extended).unwrap_err(),
                OAuthCodeInputError::InvalidTokenResponse
            );
        }
    }

    #[test]
    fn oauth_code_token_node_key_depth_and_string_limits_have_boundary_cases() {
        for (count, accepted) in [(250, true), (251, false)] {
            let extension = format!("\"x\":[{}],", vec!["0"; count].join(","));
            let body = RESPONSE.replacen('{', &format!("{{{extension}"), 1);
            assert_eq!(token(&body).is_ok(), accepted, "node boundary differed");
        }
        for (count, accepted) in [(124, true), (125, false)] {
            let extension = (0..count)
                .map(|n| format!("\"x{n}\":null,"))
                .collect::<String>();
            let body = RESPONSE.replacen('{', &format!("{{{extension}"), 1);
            assert_eq!(token(&body).is_ok(), accepted, "key boundary differed");
        }
        for (depth, accepted) in [(7, true), (8, false)] {
            let extension = format!("\"x\":{}0{},", "[".repeat(depth), "]".repeat(depth));
            let body = RESPONSE.replacen('{', &format!("{{{extension}"), 1);
            assert_eq!(token(&body).is_ok(), accepted, "depth boundary differed");
        }
        for (length, accepted) in [(8_192, true), (8_193, false)] {
            let extension = format!("\"x\":\"{}\",", "x".repeat(length));
            let body = RESPONSE.replacen('{', &format!("{{{extension}"), 1);
            assert_eq!(token(&body).is_ok(), accepted, "string boundary differed");
        }
        for (length, accepted) in [(128, true), (129, false)] {
            let extension = format!("\"{}\":null,", "x".repeat(length));
            let body = RESPONSE.replacen('{', &format!("{{{extension}"), 1);
            assert_eq!(
                token(&body).is_ok(),
                accepted,
                "key string boundary differed"
            );
        }
    }

    #[test]
    fn oauth_code_token_bearer_grammar_and_existing_header_ceiling_are_joint_limits() {
        for access in ["", "=", "x=x", "has space", "x\r\nHost:x", "x\t", "é"] {
            let encoded = serde_json::to_string(access).unwrap();
            let body =
                RESPONSE.replace("SYNTHETIC.ACCESS_TOKEN+/==", &encoded[1..encoded.len() - 1]);
            assert!(token(&body).is_err(), "unsafe bearer value admitted");
        }
        for (length, accepted) in [(8_185, true), (8_186, false)] {
            let body = RESPONSE.replace("SYNTHETIC.ACCESS_TOKEN+/==", &"x".repeat(length));
            assert_eq!(token(&body).is_ok(), accepted);
        }
        let mut input = wire();
        input.max_token_response_bytes = 16;
        let limited = OAuthCodePolicy::from_wire(input).unwrap();
        assert!(
            parse_token_response(&limited, Zeroizing::new(RESPONSE.as_bytes().to_vec())).is_err()
        );
        assert!(parse_token_response(&oauth(), Zeroizing::new(vec![b'x'; 32_769])).is_err());
    }

    #[test]
    fn oauth_code_secret_debug_and_error_paths_remain_redacted() {
        let selected = policy("canary-a");
        let grant = SuppliedSessionOAuthGrant::parse_tsv(
            &selected,
            grant_source("PRIVATE_CODE_SENTINEL", 1_000),
            1_000,
        )
        .unwrap();
        let form = grant.compose_form_body(&selected).unwrap();
        let response = token(RESPONSE).unwrap();
        let error = token("{\"PRIVATE_TOKEN_SENTINEL\":").unwrap_err();
        for rendered in [
            format!("{grant:?}"),
            format!("{form:?}"),
            format!("{response:?}"),
            format!("{error:?} {error}"),
        ] {
            for sentinel in [
                "PRIVATE_CODE_SENTINEL",
                VERIFIER,
                CHALLENGE,
                "SYNTHETIC.ACCESS_TOKEN+/==",
                "PRIVATE_TOKEN_SENTINEL",
            ] {
                assert!(!rendered.contains(sentinel), "redaction guard failed");
            }
        }
    }
}
