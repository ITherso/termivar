//! Transport-neutral contracts for one explicitly supplied authorization session.
//!
//! The policy is non-secret and grants only a small ordered set of bodyless,
//! operator-selected GET requests beneath one already selected application.
//! Application-defined GET handling can still have server-side effects. The
//! authorization value is move-only, zeroized on drop, never serialized, and
//! exposed only to the crate-owned request-composition boundary.

use std::{fmt, ops::Range};

use reqwest::header::HeaderValue;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::{Host, Url};
use zeroize::Zeroizing;

/// Strict V1 supplied-session policy schema.
pub const SUPPLIED_SESSION_POLICY_SCHEMA: &str = "security.supplied-session-policy/v1";
/// Strict V2 supplied-cookie policy schema.
pub const SUPPLIED_SESSION_COOKIE_POLICY_SCHEMA: &str = "security.supplied-session-policy/v2";
/// Maximum accepted policy bytes.
pub const HARD_MAX_SUPPLIED_SESSION_POLICY_BYTES: usize = 64 * 1024;
/// Maximum accepted supplied-cookie secret bytes.
pub const HARD_MAX_SUPPLIED_SESSION_COOKIE_SECRET_BYTES: usize = 16 * 1024;
/// Maximum supplied cookies declared by V2.
pub const MAX_SUPPLIED_SESSION_COOKIES: usize = 8;
/// Maximum composed `Cookie` request-header bytes.
pub const MAX_SUPPLIED_SESSION_COOKIE_HEADER_BYTES: usize = 8 * 1024;
/// Maximum explicitly selected protected resources.
pub const MAX_SUPPLIED_SESSION_RESOURCES: usize = 4;
/// Maximum health checkpoints: startup plus one after every selected resource.
pub const MAX_SUPPLIED_SESSION_CHECKPOINTS: usize = MAX_SUPPLIED_SESSION_RESOURCES + 1;
/// Maximum session-owned requests: startup health plus resource/checkpoint pairs.
pub const MAX_SUPPLIED_SESSION_REQUESTS: u8 = 9;
/// Maximum session-owned response bytes declared by one policy.
pub const MAX_SUPPLIED_SESSION_TOTAL_RESPONSE_BYTES: u64 = 256 * 1024;
/// Maximum retained body bytes for one session-owned response.
pub const MAX_SUPPLIED_SESSION_RESPONSE_BODY_BYTES: usize = 64 * 1024;
/// Maximum local wall-clock allowance declared by one policy.
pub const MAX_SUPPLIED_SESSION_WALL_TIME_MS: u64 = 10_000;

pub(crate) const SUPPLIED_SESSION_HEALTH_ACTION_ID: &str = "web.review.supplied-session.health";
pub(crate) const SUPPLIED_SESSION_RESOURCE_ACTION_ID: &str = "web.review.supplied-session.resource";

const MAX_PRINCIPAL_ALIAS_BYTES: usize = 128;
const MAX_HEALTH_FIELD_BYTES: usize = 128;
const MAX_POLICY_PATH_BYTES: usize = 2 * 1024;
const MAX_AUTHORIZATION_HEADER_BYTES: usize = 8 * 1024;
const MAX_COOKIE_ID_BYTES: usize = 128;
const MAX_COOKIE_NAME_BYTES: usize = 128;
const MAX_COOKIE_VALUE_BYTES: usize = 4 * 1024;
const POLICY_REFERENCE_DOMAIN: &[u8] = b"security.supplied-session-policy.reference.v1\0";
const COOKIE_POLICY_REFERENCE_DOMAIN: &[u8] = b"security.supplied-session-policy.reference.v2\0";
const APPLICATION_REFERENCE_DOMAIN: &[u8] = b"security.supplied-session-application.reference.v1\0";
const HEALTH_FIELD_REFERENCE_DOMAIN: &[u8] =
    b"security.supplied-session-health-field.reference.v1\0";
const RESOURCE_REFERENCE_DOMAIN: &[u8] = b"security.supplied-session-resource.reference.v1\0";
const REQUEST_DESCRIPTOR_REFERENCE_DOMAIN: &[u8] =
    b"security.supplied-session-request-descriptor.reference.v1\0";
const SUPPLIED_SESSION_PRINCIPAL_REFERENCE: &str = "supplied-session-principal-0001";

/// Supplied-session policy generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SuppliedSessionPolicyVersion {
    /// Authorization-header policy V1.
    V1,
    /// Supplied-cookie policy V2.
    V2,
}

impl SuppliedSessionPolicyVersion {
    /// Exact schema identifier for this generation.
    pub const fn schema(self) -> &'static str {
        match self {
            Self::V1 => SUPPLIED_SESSION_POLICY_SCHEMA,
            Self::V2 => SUPPLIED_SESSION_COOKIE_POLICY_SCHEMA,
        }
    }
}

/// Credential mechanism selected by a supplied-session policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SuppliedSessionCredentialMechanism {
    /// One complete caller-supplied `Authorization` header value.
    AuthorizationHeader,
    /// A bounded caller-supplied cookie jar with non-secret policy metadata.
    CookieJar,
}

impl SuppliedSessionCredentialMechanism {
    /// Exact stable wire token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizationHeader => "authorization_header",
            Self::CookieJar => "cookie_jar",
        }
    }
}

/// V2 behavior when a selected cookie is reissued by a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SuppliedSessionCookieUpdatePolicy {
    /// Never apply a response update; stop before further session work.
    StopOnSelectedCookie,
}

impl SuppliedSessionCookieUpdatePolicy {
    /// Exact stable wire token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StopOnSelectedCookie => "stop_on_selected_cookie",
        }
    }
}

/// Preserved SameSite declaration for one supplied cookie.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SuppliedSessionCookieSameSite {
    /// No SameSite attribute was declared.
    Missing,
    /// `SameSite=Strict` was declared.
    Strict,
    /// `SameSite=Lax` was declared.
    Lax,
    /// `SameSite=None` was declared.
    None,
}

impl SuppliedSessionCookieSameSite {
    /// Exact stable wire token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Strict => "strict",
            Self::Lax => "lax",
            Self::None => "none",
        }
    }
}

/// Static, redaction-safe policy validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SuppliedSessionPolicyError {
    /// Policy input exceeded its compiled source ceiling.
    #[error("supplied-session policy exceeds its compiled byte limit")]
    PolicyTooLarge,
    /// TOML, UTF-8, required fields, duplicate fields, or bounded values were invalid.
    #[error("supplied-session policy is malformed")]
    MalformedPolicy,
    /// The schema identifier is not supported.
    #[error("supplied-session policy schema is unsupported")]
    UnsupportedSchema,
    /// The credential mechanism is not supported by V1.
    #[error("supplied-session credential mechanism is unsupported")]
    UnsupportedCredentialMechanism,
    /// The response-cookie update policy is not supported by V2.
    #[error("supplied-session cookie update policy is unsupported")]
    UnsupportedCookieUpdatePolicy,
    /// The selected application is not a safe trailing-slash HTTP(S) application URL.
    #[error("supplied-session application is invalid")]
    InvalidApplication,
    /// A principal alias violated the bounded opaque-token contract.
    #[error("supplied-session principal alias is invalid")]
    InvalidPrincipalAlias,
    /// A health field violated the bounded top-level-field contract.
    #[error("supplied-session health JSON field is invalid")]
    InvalidHealthField,
    /// A path was unsafe, action-oriented, duplicated, or outside the application.
    #[error("supplied-session path is invalid or outside the selected application")]
    InvalidPath,
    /// The selected resource count violated V1's closed bound.
    #[error("supplied-session resource count is invalid")]
    InvalidResourceCount,
    /// The selected cookie count violated V2's closed bound.
    #[error("supplied-session cookie count is invalid")]
    InvalidCookieCount,
    /// Cookie metadata was unsafe, out of scope, duplicated, or internally inconsistent.
    #[error("supplied-session cookie metadata is invalid")]
    InvalidCookieMetadata,
    /// A policy limit was zero, inconsistent, or above a compiled maximum.
    #[error("supplied-session limits are invalid")]
    InvalidLimits,
}

/// Static, redaction-safe authorization value validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SuppliedSessionAuthorizationError {
    /// The value was empty, malformed, non-visible ASCII, or too large.
    #[error("supplied-session authorization is not a bounded safe HTTP header value")]
    InvalidValue,
}

/// Static, redaction-safe supplied-cookie validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SuppliedSessionCookieError {
    /// Secret input exceeded its compiled byte limit.
    #[error("supplied-session cookie secret exceeds its compiled byte limit")]
    SecretTooLarge,
    /// Secret rows, identifiers, values, or their exact declared set were invalid.
    #[error("supplied-session cookie secret is malformed")]
    MalformedSecret,
    /// The selected policy does not admit a supplied-cookie credential.
    #[error("supplied-session cookie credential does not match the selected policy")]
    PolicyMismatch,
    /// At least one selected request had no initially applicable cookie.
    #[error("supplied-session cookie credential does not cover every selected request")]
    IncompleteInitialCoverage,
    /// The exact requested target was not admitted by the bound policy.
    #[error("supplied-session cookie target is not admitted by the selected policy")]
    TargetNotAdmitted,
    /// No unexpired cookie applies to this admitted request.
    #[error("supplied-session cookie credential is unavailable for this request")]
    NoApplicableCookie,
    /// Applicable cookie pairs exceeded the request-header ceiling.
    #[error("supplied-session cookie header exceeds its compiled byte limit")]
    HeaderTooLarge,
}

/// One move-only complete `Authorization` header value.
pub struct SuppliedSessionAuthorization {
    value: Zeroizing<String>,
}

impl SuppliedSessionAuthorization {
    /// Validates bounded visible-ASCII header bytes without retaining a second copy.
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, SuppliedSessionAuthorizationError> {
        let mut value = Zeroizing::new(value.into());
        if value.is_empty()
            || value.len() > MAX_AUTHORIZATION_HEADER_BYTES
            || value.iter().any(|byte| !matches!(*byte, 0x20..=0x7e))
        {
            return Err(SuppliedSessionAuthorizationError::InvalidValue);
        }
        let parsed = HeaderValue::from_bytes(value.as_slice())
            .map_err(|_| SuppliedSessionAuthorizationError::InvalidValue)?;
        let text = parsed
            .to_str()
            .map_err(|_| SuppliedSessionAuthorizationError::InvalidValue)?;
        let Some((scheme, credentials)) = text.split_once(' ') else {
            return Err(SuppliedSessionAuthorizationError::InvalidValue);
        };
        if scheme.is_empty()
            || credentials.is_empty()
            || credentials.starts_with(' ')
            || credentials.ends_with(' ')
            || !scheme.bytes().all(http_token_byte)
        {
            return Err(SuppliedSessionAuthorizationError::InvalidValue);
        }
        let owned = String::from_utf8(std::mem::take(&mut *value))
            .map_err(|_| SuppliedSessionAuthorizationError::InvalidValue)?;
        Ok(Self {
            value: Zeroizing::new(owned),
        })
    }

    pub(crate) fn as_str(&self) -> &str {
        self.value.as_str()
    }
}

impl fmt::Debug for SuppliedSessionAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SuppliedSessionAuthorization(<redacted>)")
    }
}

/// Non-secret aggregate of the supplied cookie metadata selected by a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SuppliedSessionCookieSummary {
    cookie_count: usize,
    host_only_count: usize,
    domain_count: usize,
    secure_count: usize,
    http_only_count: usize,
    session_count: usize,
    persistent_count: usize,
    same_site_missing_count: usize,
    same_site_strict_count: usize,
    same_site_lax_count: usize,
    same_site_none_count: usize,
}

impl SuppliedSessionCookieSummary {
    /// Number of declared cookie records.
    pub const fn cookie_count(self) -> usize {
        self.cookie_count
    }

    /// Number of host-only cookie records.
    pub const fn host_only_count(self) -> usize {
        self.host_only_count
    }

    /// Number of Domain-attribute cookie records.
    pub const fn domain_count(self) -> usize {
        self.domain_count
    }

    /// Number of Secure cookie records.
    pub const fn secure_count(self) -> usize {
        self.secure_count
    }

    /// Number of HttpOnly cookie records.
    pub const fn http_only_count(self) -> usize {
        self.http_only_count
    }

    /// Number of session cookies without a declared expiry.
    pub const fn session_count(self) -> usize {
        self.session_count
    }

    /// Number of cookies with a declared expiry.
    pub const fn persistent_count(self) -> usize {
        self.persistent_count
    }

    /// Number of records without a SameSite declaration.
    pub const fn same_site_missing_count(self) -> usize {
        self.same_site_missing_count
    }

    /// Number of `SameSite=Strict` records.
    pub const fn same_site_strict_count(self) -> usize {
        self.same_site_strict_count
    }

    /// Number of `SameSite=Lax` records.
    pub const fn same_site_lax_count(self) -> usize {
        self.same_site_lax_count
    }

    /// Number of `SameSite=None` records.
    pub const fn same_site_none_count(self) -> usize {
        self.same_site_none_count
    }
}

struct SuppliedSessionCookieMetadata {
    id: String,
    name: String,
    domain: String,
    host_only: bool,
    path: String,
    secure: bool,
    http_only: bool,
    same_site: SuppliedSessionCookieSameSite,
    expires_unix_seconds: Option<i64>,
}

struct SuppliedSessionCookieValue {
    metadata_index: usize,
    range: Range<usize>,
}

/// Move-only supplied cookie values bound to one validated V2 policy.
///
/// Secret bytes remain in one zeroizing backing allocation. Request headers
/// are composed transiently only for exact policy-admitted targets.
pub struct SuppliedSessionCookies {
    backing: Zeroizing<Vec<u8>>,
    values: Vec<SuppliedSessionCookieValue>,
    policy_reference: String,
    principal_alias: String,
}

impl SuppliedSessionCookies {
    /// Parses strict `cookie-id<TAB>value` rows and validates initial coverage.
    ///
    /// Every policy cookie must occur exactly once. Values use the RFC cookie
    /// octet subset and are never trimmed or decoded. `now_unix_seconds` is an
    /// explicit caller-supplied clock reading used only for expiry checks.
    pub fn parse_tsv(
        policy: &SuppliedSessionPolicy,
        source: impl Into<Vec<u8>>,
        now_unix_seconds: i64,
    ) -> Result<Self, SuppliedSessionCookieError> {
        if policy.credential_mechanism != SuppliedSessionCredentialMechanism::CookieJar
            || policy.version != SuppliedSessionPolicyVersion::V2
            || policy.cookies.is_empty()
        {
            return Err(SuppliedSessionCookieError::PolicyMismatch);
        }
        let backing = Zeroizing::new(source.into());
        if backing.is_empty() {
            return Err(SuppliedSessionCookieError::MalformedSecret);
        }
        if backing.len() > HARD_MAX_SUPPLIED_SESSION_COOKIE_SECRET_BYTES {
            return Err(SuppliedSessionCookieError::SecretTooLarge);
        }

        let mut ranges: Vec<Option<Range<usize>>> =
            (0..policy.cookies.len()).map(|_| None).collect();
        let mut cursor = 0_usize;
        while cursor < backing.len() {
            let physical_end = backing[cursor..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(backing.len(), |offset| cursor + offset);
            let mut line_end = physical_end;
            if line_end > cursor && backing[line_end - 1] == b'\r' {
                line_end -= 1;
            }
            if line_end == cursor {
                return Err(SuppliedSessionCookieError::MalformedSecret);
            }
            let line = &backing[cursor..line_end];
            let Some(tab_offset) = line.iter().position(|byte| *byte == b'\t') else {
                return Err(SuppliedSessionCookieError::MalformedSecret);
            };
            if line[tab_offset + 1..].contains(&b'\t') {
                return Err(SuppliedSessionCookieError::MalformedSecret);
            }
            let id = std::str::from_utf8(&line[..tab_offset])
                .map_err(|_| SuppliedSessionCookieError::MalformedSecret)?;
            let Some(metadata_index) = policy.cookies.iter().position(|cookie| cookie.id == id)
            else {
                return Err(SuppliedSessionCookieError::MalformedSecret);
            };
            if ranges[metadata_index].is_some() {
                return Err(SuppliedSessionCookieError::MalformedSecret);
            }
            let value_start = cursor
                .checked_add(tab_offset)
                .and_then(|value| value.checked_add(1))
                .ok_or(SuppliedSessionCookieError::MalformedSecret)?;
            let value = &backing[value_start..line_end];
            if value.is_empty()
                || value.len() > MAX_COOKIE_VALUE_BYTES
                || !value.iter().copied().all(cookie_octet)
            {
                return Err(SuppliedSessionCookieError::MalformedSecret);
            }
            ranges[metadata_index] = Some(value_start..line_end);
            cursor = if physical_end == backing.len() {
                backing.len()
            } else {
                physical_end + 1
            };
        }
        if ranges.iter().any(Option::is_none) {
            return Err(SuppliedSessionCookieError::MalformedSecret);
        }
        if policy.cookies.iter().any(|cookie| {
            cookie
                .expires_unix_seconds
                .is_some_and(|expires| expires <= now_unix_seconds)
        }) {
            return Err(SuppliedSessionCookieError::IncompleteInitialCoverage);
        }
        let values = ranges
            .into_iter()
            .enumerate()
            .map(|(metadata_index, range)| SuppliedSessionCookieValue {
                metadata_index,
                range: range.expect("the exact cookie id set was checked above"),
            })
            .collect::<Vec<_>>();
        let cookies = Self {
            backing,
            values,
            policy_reference: policy.policy_reference.clone(),
            principal_alias: policy.principal_alias.clone(),
        };
        if !policy
            .execution_targets()
            .all(|target| cookies.has_applicable_cookie(policy, target, now_unix_seconds))
        {
            return Err(SuppliedSessionCookieError::IncompleteInitialCoverage);
        }
        Ok(cookies)
    }

    /// Number of secret cookie values retained by this jar.
    pub fn cookie_count(&self) -> usize {
        self.values.len()
    }

    pub(crate) fn sensitive_header_for_target(
        &self,
        policy: &SuppliedSessionPolicy,
        target: &Url,
        now_unix_seconds: i64,
    ) -> Result<HeaderValue, SuppliedSessionCookieError> {
        if !self.matches_policy(policy) {
            return Err(SuppliedSessionCookieError::PolicyMismatch);
        }
        if !policy.admits_execution_target(target) {
            return Err(SuppliedSessionCookieError::TargetNotAdmitted);
        }
        // The supplied jar is one fixed session epoch. Silently omitting an
        // expired selected cookie while sending the remaining set would change
        // that credential context without a validated renewal transition.
        if policy.cookies.iter().any(|cookie| {
            cookie
                .expires_unix_seconds
                .is_some_and(|expires| expires <= now_unix_seconds)
        }) {
            return Err(SuppliedSessionCookieError::NoApplicableCookie);
        }
        let mut selected = self
            .values
            .iter()
            .filter(|value| {
                cookie_applies(
                    &policy.cookies[value.metadata_index],
                    target,
                    now_unix_seconds,
                )
            })
            .collect::<Vec<_>>();
        selected.sort_by(|left, right| {
            policy.cookies[right.metadata_index]
                .path
                .len()
                .cmp(&policy.cookies[left.metadata_index].path.len())
                .then_with(|| left.metadata_index.cmp(&right.metadata_index))
        });
        if selected.is_empty() {
            return Err(SuppliedSessionCookieError::NoApplicableCookie);
        }

        let mut composed = Zeroizing::new(Vec::new());
        for (position, value) in selected.into_iter().enumerate() {
            let metadata = &policy.cookies[value.metadata_index];
            let separator_bytes = usize::from(position > 0) * 2;
            let next_len = composed
                .len()
                .checked_add(separator_bytes)
                .and_then(|length| length.checked_add(metadata.name.len()))
                .and_then(|length| length.checked_add(1))
                .and_then(|length| length.checked_add(value.range.len()))
                .ok_or(SuppliedSessionCookieError::HeaderTooLarge)?;
            if next_len > MAX_SUPPLIED_SESSION_COOKIE_HEADER_BYTES {
                return Err(SuppliedSessionCookieError::HeaderTooLarge);
            }
            if position > 0 {
                composed.extend_from_slice(b"; ");
            }
            composed.extend_from_slice(metadata.name.as_bytes());
            composed.push(b'=');
            composed.extend_from_slice(&self.backing[value.range.clone()]);
        }
        let mut header = HeaderValue::from_bytes(composed.as_slice())
            .map_err(|_| SuppliedSessionCookieError::MalformedSecret)?;
        header.set_sensitive(true);
        Ok(header)
    }

    fn matches_policy(&self, policy: &SuppliedSessionPolicy) -> bool {
        policy.version == SuppliedSessionPolicyVersion::V2
            && policy.credential_mechanism == SuppliedSessionCredentialMechanism::CookieJar
            && self.policy_reference == policy.policy_reference
            && self.principal_alias == policy.principal_alias
            && self.values.len() == policy.cookies.len()
    }

    fn has_applicable_cookie(
        &self,
        policy: &SuppliedSessionPolicy,
        target: &Url,
        now_unix_seconds: i64,
    ) -> bool {
        self.values.iter().any(|value| {
            cookie_applies(
                &policy.cookies[value.metadata_index],
                target,
                now_unix_seconds,
            )
        })
    }
}

impl fmt::Debug for SuppliedSessionCookies {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SuppliedSessionCookies")
            .field("values", &"<redacted>")
            .field("cookie_count", &self.values.len())
            .finish()
    }
}

/// Move-only supplied credential selected for one session runtime.
pub enum SuppliedSessionCredential {
    /// One caller-supplied Authorization header.
    Authorization(SuppliedSessionAuthorization),
    /// One bounded caller-supplied cookie jar.
    SuppliedCookies(SuppliedSessionCookies),
}

impl SuppliedSessionCredential {
    /// Credential mechanism carried by this value.
    pub const fn mechanism(&self) -> SuppliedSessionCredentialMechanism {
        match self {
            Self::Authorization(_) => SuppliedSessionCredentialMechanism::AuthorizationHeader,
            Self::SuppliedCookies(_) => SuppliedSessionCredentialMechanism::CookieJar,
        }
    }

    pub(crate) const fn authorization(&self) -> Option<&SuppliedSessionAuthorization> {
        match self {
            Self::Authorization(value) => Some(value),
            Self::SuppliedCookies(_) => None,
        }
    }

    pub(crate) const fn cookies(&self) -> Option<&SuppliedSessionCookies> {
        match self {
            Self::Authorization(_) => None,
            Self::SuppliedCookies(value) => Some(value),
        }
    }
}

impl From<SuppliedSessionAuthorization> for SuppliedSessionCredential {
    fn from(value: SuppliedSessionAuthorization) -> Self {
        Self::Authorization(value)
    }
}

impl From<SuppliedSessionCookies> for SuppliedSessionCredential {
    fn from(value: SuppliedSessionCookies) -> Self {
        Self::SuppliedCookies(value)
    }
}

impl fmt::Debug for SuppliedSessionCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorization(_) => {
                formatter.write_str("SuppliedSessionCredential::Authorization(<redacted>)")
            },
            Self::SuppliedCookies(_) => {
                formatter.write_str("SuppliedSessionCredential::SuppliedCookies(<redacted>)")
            },
        }
    }
}

/// Strict non-secret policy for one supplied session.
pub struct SuppliedSessionPolicy {
    version: SuppliedSessionPolicyVersion,
    application_url: Url,
    principal_alias: String,
    health_url: Url,
    health_json_field: String,
    resources: Vec<SuppliedSessionResource>,
    credential_mechanism: SuppliedSessionCredentialMechanism,
    cookie_update_policy: Option<SuppliedSessionCookieUpdatePolicy>,
    cookies: Vec<SuppliedSessionCookieMetadata>,
    policy_reference: String,
    application_reference: String,
    principal_reference: String,
    health_field_reference: String,
    max_session_requests: u8,
    max_total_response_bytes: u64,
    max_response_body_bytes: usize,
    max_wall_time_ms: u64,
}

struct SuppliedSessionResource {
    url: Url,
    reference: String,
}

impl SuppliedSessionPolicy {
    /// Parses and resolves a strict policy beneath `application_url`.
    pub fn parse_toml(
        application_url: &Url,
        source: &[u8],
    ) -> Result<Self, SuppliedSessionPolicyError> {
        if source.len() > HARD_MAX_SUPPLIED_SESSION_POLICY_BYTES {
            return Err(SuppliedSessionPolicyError::PolicyTooLarge);
        }
        validate_application_url(application_url)?;
        let source =
            std::str::from_utf8(source).map_err(|_| SuppliedSessionPolicyError::MalformedPolicy)?;
        match toml::from_str::<WirePolicy>(source) {
            Ok(wire) => Self::from_v1_wire(application_url, wire),
            Err(_) => {
                let wire: WireCookiePolicy = toml::from_str(source)
                    .map_err(|_| SuppliedSessionPolicyError::MalformedPolicy)?;
                if wire.schema == SUPPLIED_SESSION_POLICY_SCHEMA {
                    return Err(SuppliedSessionPolicyError::MalformedPolicy);
                }
                Self::from_v2_wire(application_url, wire)
            },
        }
    }

    fn from_v1_wire(
        application_url: &Url,
        wire: WirePolicy,
    ) -> Result<Self, SuppliedSessionPolicyError> {
        if wire.schema != SUPPLIED_SESSION_POLICY_SCHEMA {
            return Err(SuppliedSessionPolicyError::UnsupportedSchema);
        }
        let credential_mechanism = match wire.credential_mechanism.as_str() {
            "authorization_header" => SuppliedSessionCredentialMechanism::AuthorizationHeader,
            _ => return Err(SuppliedSessionPolicyError::UnsupportedCredentialMechanism),
        };
        validate_token(&wire.principal_alias, MAX_PRINCIPAL_ALIAS_BYTES)
            .map_err(|_| SuppliedSessionPolicyError::InvalidPrincipalAlias)?;
        validate_token(&wire.health_json_field, MAX_HEALTH_FIELD_BYTES)
            .map_err(|_| SuppliedSessionPolicyError::InvalidHealthField)?;
        if wire.resources.is_empty() || wire.resources.len() > MAX_SUPPLIED_SESSION_RESOURCES {
            return Err(SuppliedSessionPolicyError::InvalidResourceCount);
        }
        let minimum_requests = 1_usize
            .checked_add(
                wire.resources
                    .len()
                    .checked_mul(2)
                    .ok_or(SuppliedSessionPolicyError::InvalidLimits)?,
            )
            .ok_or(SuppliedSessionPolicyError::InvalidLimits)?;
        if wire.max_session_requests == 0
            || usize::from(wire.max_session_requests) < minimum_requests
            || wire.max_session_requests > MAX_SUPPLIED_SESSION_REQUESTS
            || wire.max_total_response_bytes == 0
            || wire.max_total_response_bytes > MAX_SUPPLIED_SESSION_TOTAL_RESPONSE_BYTES
            || wire.max_response_body_bytes == 0
            || wire.max_response_body_bytes > MAX_SUPPLIED_SESSION_RESPONSE_BODY_BYTES
            || u64::try_from(wire.max_response_body_bytes).unwrap_or(u64::MAX)
                > wire.max_total_response_bytes
            || wire.max_wall_time_ms == 0
            || wire.max_wall_time_ms > MAX_SUPPLIED_SESSION_WALL_TIME_MS
        {
            return Err(SuppliedSessionPolicyError::InvalidLimits);
        }

        let health_url = resolve_safe_path(application_url, &wire.health_path)?;
        let mut seen = std::collections::BTreeSet::new();
        let mut resources = Vec::with_capacity(wire.resources.len());
        for raw in &wire.resources {
            let url = resolve_safe_path(application_url, raw)?;
            if url == health_url || !seen.insert(url.as_str().to_owned()) {
                return Err(SuppliedSessionPolicyError::InvalidPath);
            }
            resources.push(SuppliedSessionResource {
                reference: reference(
                    RESOURCE_REFERENCE_DOMAIN,
                    url.as_str(),
                    "supplied-session-resource-sha256",
                ),
                url,
            });
        }
        let policy_reference = policy_reference(application_url, &wire, credential_mechanism);
        Ok(Self {
            version: SuppliedSessionPolicyVersion::V1,
            application_url: application_url.clone(),
            principal_alias: wire.principal_alias,
            health_url,
            health_json_field: wire.health_json_field.clone(),
            resources,
            credential_mechanism,
            cookie_update_policy: None,
            cookies: Vec::new(),
            policy_reference,
            application_reference: reference(
                APPLICATION_REFERENCE_DOMAIN,
                application_url.as_str(),
                "supplied-session-application-sha256",
            ),
            // V1 has exactly one run-local principal slot. This deliberately
            // does not publish an unkeyed digest of the operator's potentially
            // low-entropy alias (and never derives identity from credentials).
            principal_reference: SUPPLIED_SESSION_PRINCIPAL_REFERENCE.to_owned(),
            health_field_reference: reference(
                HEALTH_FIELD_REFERENCE_DOMAIN,
                &wire.health_json_field,
                "supplied-session-health-field-sha256",
            ),
            max_session_requests: wire.max_session_requests,
            max_total_response_bytes: wire.max_total_response_bytes,
            max_response_body_bytes: wire.max_response_body_bytes,
            max_wall_time_ms: wire.max_wall_time_ms,
        })
    }

    fn from_v2_wire(
        application_url: &Url,
        wire: WireCookiePolicy,
    ) -> Result<Self, SuppliedSessionPolicyError> {
        if wire.schema != SUPPLIED_SESSION_COOKIE_POLICY_SCHEMA {
            return Err(SuppliedSessionPolicyError::UnsupportedSchema);
        }
        let credential_mechanism = match wire.credential_mechanism.as_str() {
            "cookie_jar" => SuppliedSessionCredentialMechanism::CookieJar,
            _ => return Err(SuppliedSessionPolicyError::UnsupportedCredentialMechanism),
        };
        let cookie_update_policy = match wire.cookie_update_policy.as_str() {
            "stop_on_selected_cookie" => SuppliedSessionCookieUpdatePolicy::StopOnSelectedCookie,
            _ => return Err(SuppliedSessionPolicyError::UnsupportedCookieUpdatePolicy),
        };
        validate_token(&wire.principal_alias, MAX_PRINCIPAL_ALIAS_BYTES)
            .map_err(|_| SuppliedSessionPolicyError::InvalidPrincipalAlias)?;
        validate_token(&wire.health_json_field, MAX_HEALTH_FIELD_BYTES)
            .map_err(|_| SuppliedSessionPolicyError::InvalidHealthField)?;
        if wire.resources.is_empty() || wire.resources.len() > MAX_SUPPLIED_SESSION_RESOURCES {
            return Err(SuppliedSessionPolicyError::InvalidResourceCount);
        }
        validate_policy_limits(
            wire.resources.len(),
            wire.max_session_requests,
            wire.max_total_response_bytes,
            wire.max_response_body_bytes,
            wire.max_wall_time_ms,
        )?;

        let health_url = resolve_safe_path(application_url, &wire.health_path)?;
        let mut seen_resources = std::collections::BTreeSet::new();
        let mut resources = Vec::with_capacity(wire.resources.len());
        for raw in &wire.resources {
            let url = resolve_safe_path(application_url, raw)?;
            if url == health_url || !seen_resources.insert(url.as_str().to_owned()) {
                return Err(SuppliedSessionPolicyError::InvalidPath);
            }
            resources.push(SuppliedSessionResource {
                reference: reference(
                    RESOURCE_REFERENCE_DOMAIN,
                    url.as_str(),
                    "supplied-session-resource-sha256",
                ),
                url,
            });
        }
        if wire.cookies.is_empty() || wire.cookies.len() > MAX_SUPPLIED_SESSION_COOKIES {
            return Err(SuppliedSessionPolicyError::InvalidCookieCount);
        }
        let canonical_host = application_url
            .host_str()
            .ok_or(SuppliedSessionPolicyError::InvalidApplication)?;
        let application_host_is_domain = matches!(application_url.host(), Some(Host::Domain(_)));
        let mut seen_ids = std::collections::BTreeSet::new();
        let mut seen_tuples = std::collections::BTreeSet::new();
        let mut cookies = Vec::with_capacity(wire.cookies.len());
        for cookie in &wire.cookies {
            validate_token(&cookie.id, MAX_COOKIE_ID_BYTES)
                .map_err(|_| SuppliedSessionPolicyError::InvalidCookieMetadata)?;
            if cookie.name.is_empty()
                || cookie.name.len() > MAX_COOKIE_NAME_BYTES
                || !cookie.name.bytes().all(http_token_byte)
                || cookie.name.starts_with('$')
                || cookie.domain != canonical_host
                || (!cookie.host_only && !application_host_is_domain)
                || (cookie.secure && application_url.scheme() != "https")
            {
                return Err(SuppliedSessionPolicyError::InvalidCookieMetadata);
            }
            validate_cookie_path(&cookie.path)?;
            let same_site = parse_cookie_same_site(&cookie.same_site)?;
            if same_site == SuppliedSessionCookieSameSite::None && !cookie.secure {
                return Err(SuppliedSessionPolicyError::InvalidCookieMetadata);
            }
            if !cookie_path_matches(&cookie.path, health_url.path())
                && !resources
                    .iter()
                    .any(|resource| cookie_path_matches(&cookie.path, resource.url.path()))
            {
                return Err(SuppliedSessionPolicyError::InvalidCookieMetadata);
            }
            if !seen_ids.insert(cookie.id.clone())
                || !seen_tuples.insert((
                    cookie.name.clone(),
                    cookie.domain.clone(),
                    cookie.path.clone(),
                ))
            {
                return Err(SuppliedSessionPolicyError::InvalidCookieMetadata);
            }
            cookies.push(SuppliedSessionCookieMetadata {
                id: cookie.id.clone(),
                name: cookie.name.clone(),
                domain: cookie.domain.clone(),
                host_only: cookie.host_only,
                path: cookie.path.clone(),
                secure: cookie.secure,
                http_only: cookie.http_only,
                same_site,
                expires_unix_seconds: cookie.expires_unix_seconds,
            });
        }

        let policy_reference = cookie_policy_reference(
            application_url,
            &wire,
            credential_mechanism,
            cookie_update_policy,
        );
        Ok(Self {
            version: SuppliedSessionPolicyVersion::V2,
            application_url: application_url.clone(),
            principal_alias: wire.principal_alias,
            health_url,
            health_json_field: wire.health_json_field.clone(),
            resources,
            credential_mechanism,
            cookie_update_policy: Some(cookie_update_policy),
            cookies,
            policy_reference,
            application_reference: reference(
                APPLICATION_REFERENCE_DOMAIN,
                application_url.as_str(),
                "supplied-session-application-sha256",
            ),
            principal_reference: SUPPLIED_SESSION_PRINCIPAL_REFERENCE.to_owned(),
            health_field_reference: reference(
                HEALTH_FIELD_REFERENCE_DOMAIN,
                &wire.health_json_field,
                "supplied-session-health-field-sha256",
            ),
            max_session_requests: wire.max_session_requests,
            max_total_response_bytes: wire.max_total_response_bytes,
            max_response_body_bytes: wire.max_response_body_bytes,
            max_wall_time_ms: wire.max_wall_time_ms,
        })
    }

    /// Policy schema generation.
    pub const fn version(&self) -> SuppliedSessionPolicyVersion {
        self.version
    }

    /// Exact policy schema identifier.
    pub const fn schema(&self) -> &'static str {
        self.version.schema()
    }

    /// Stable semantic policy reference; it contains no credential or raw URL.
    pub fn policy_reference(&self) -> &str {
        &self.policy_reference
    }

    /// Stable exact-application reference; it contains no raw URL.
    pub fn application_reference(&self) -> &str {
        &self.application_reference
    }

    /// Opaque run-local principal slot; it is not an authenticated or cross-run identity.
    pub fn principal_reference(&self) -> &str {
        &self.principal_reference
    }

    /// Explicitly non-secret operator assertion saved for cross-run context distinction.
    ///
    /// This label is not authenticated identity truth and is never derived from
    /// the authorization value. Operators should use a non-sensitive stable alias.
    pub fn principal_alias(&self) -> &str {
        &self.principal_alias
    }

    /// Stable configured-health-field reference.
    pub fn health_field_reference(&self) -> &str {
        &self.health_field_reference
    }

    /// Selected credential mechanism.
    pub const fn credential_mechanism(&self) -> SuppliedSessionCredentialMechanism {
        self.credential_mechanism
    }

    /// V2 response-cookie update behavior, absent for V1.
    pub const fn cookie_update_policy(&self) -> Option<SuppliedSessionCookieUpdatePolicy> {
        self.cookie_update_policy
    }

    /// Non-secret aggregate cookie metadata, absent for V1.
    pub fn cookie_summary(&self) -> Option<SuppliedSessionCookieSummary> {
        (!self.cookies.is_empty()).then(|| summarize_cookies(&self.cookies))
    }

    /// Number of selected protected resources.
    pub fn resource_count(&self) -> usize {
        self.resources.len()
    }

    pub const fn max_session_requests(&self) -> u8 {
        self.max_session_requests
    }

    pub const fn max_total_response_bytes(&self) -> u64 {
        self.max_total_response_bytes
    }

    pub const fn max_response_body_bytes(&self) -> usize {
        self.max_response_body_bytes
    }

    pub const fn max_wall_time_ms(&self) -> u64 {
        self.max_wall_time_ms
    }

    pub(crate) const fn application_url(&self) -> &Url {
        &self.application_url
    }

    pub(crate) fn health_json_field(&self) -> &str {
        &self.health_json_field
    }

    pub(crate) fn execution_resources(&self) -> impl ExactSizeIterator<Item = (&Url, &str)> {
        self.resources
            .iter()
            .map(|resource| (&resource.url, resource.reference.as_str()))
    }

    fn execution_targets(&self) -> impl Iterator<Item = &Url> {
        std::iter::once(&self.health_url).chain(self.resources.iter().map(|resource| &resource.url))
    }

    fn admits_execution_target(&self, target: &Url) -> bool {
        self.health_url == *target
            || self
                .resources
                .iter()
                .any(|resource| resource.url == *target)
    }

    pub(crate) fn is_selected_cookie_name(&self, name: &str) -> bool {
        self.cookies.iter().any(|cookie| cookie.name == name)
    }
}

impl fmt::Debug for SuppliedSessionPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SuppliedSessionPolicy")
            .field("application", &"<redacted>")
            .field("health", &"<redacted>")
            .field("health_json_field", &"<redacted>")
            .field("principal_alias", &"<operator-declared>")
            .field("version", &self.version)
            .field("resource_count", &self.resources.len())
            .field("credential_mechanism", &self.credential_mechanism)
            .field("cookie_update_policy", &self.cookie_update_policy)
            .field("cookie_count", &self.cookies.len())
            .field("policy_reference", &self.policy_reference)
            .field("application_reference", &self.application_reference)
            .field("principal_reference", &self.principal_reference)
            .field("max_session_requests", &self.max_session_requests)
            .field("max_total_response_bytes", &self.max_total_response_bytes)
            .field("max_response_body_bytes", &self.max_response_body_bytes)
            .field("max_wall_time_ms", &self.max_wall_time_ms)
            .finish()
    }
}

/// Closed request purpose checked at both construction and broker dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SuppliedSessionRequestPurpose {
    Health,
    Resource,
}

/// Private proof that one exact URL was admitted by a validated session policy.
///
/// Fields are private so an arbitrary same-origin URL cannot be substituted by
/// another runtime. The broker calls `validate` again immediately before
/// request construction and accounting.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SuppliedSessionRequestDescriptor {
    application_url: Url,
    target: Url,
    target_reference: String,
    purpose: SuppliedSessionRequestPurpose,
    credential_mechanism: SuppliedSessionCredentialMechanism,
    policy_reference: String,
    purpose_binding: String,
}

impl SuppliedSessionRequestDescriptor {
    pub(crate) fn health(policy: &SuppliedSessionPolicy) -> Self {
        let purpose = SuppliedSessionRequestPurpose::Health;
        let descriptor = Self {
            application_url: policy.application_url.clone(),
            target: policy.health_url.clone(),
            target_reference: reference(
                RESOURCE_REFERENCE_DOMAIN,
                policy.health_url.as_str(),
                "supplied-session-resource-sha256",
            ),
            purpose,
            credential_mechanism: policy.credential_mechanism,
            policy_reference: policy.policy_reference.clone(),
            purpose_binding: request_descriptor_reference(
                &policy.application_url,
                &policy.health_url,
                purpose,
                policy.credential_mechanism,
                &policy.policy_reference,
            ),
        };
        debug_assert!(descriptor.validate_against(policy));
        descriptor
    }

    pub(crate) fn resource(
        policy: &SuppliedSessionPolicy,
        target: &Url,
        target_reference: &str,
    ) -> Option<Self> {
        if !policy
            .resources
            .iter()
            .any(|resource| resource.url == *target && resource.reference == target_reference)
        {
            return None;
        }
        let purpose = SuppliedSessionRequestPurpose::Resource;
        let descriptor = Self {
            application_url: policy.application_url.clone(),
            target: target.clone(),
            target_reference: target_reference.to_owned(),
            purpose,
            credential_mechanism: policy.credential_mechanism,
            policy_reference: policy.policy_reference.clone(),
            purpose_binding: request_descriptor_reference(
                &policy.application_url,
                target,
                purpose,
                policy.credential_mechanism,
                &policy.policy_reference,
            ),
        };
        descriptor.validate_against(policy).then_some(descriptor)
    }

    pub(crate) fn validate(&self) -> bool {
        validate_application_url(&self.application_url).is_ok()
            && self.target.origin() == self.application_url.origin()
            && self.target.query().is_none()
            && self.target.fragment().is_none()
            && self.target.username().is_empty()
            && self.target.password().is_none()
            && path_within_application(&self.application_url, &self.target)
            && !self
                .target
                .path()
                .bytes()
                .any(|byte| matches!(byte, b'%' | b'\\'))
            && !self.target.path().split('/').any(action_or_admin_segment)
            && self.target_reference
                == reference(
                    RESOURCE_REFERENCE_DOMAIN,
                    self.target.as_str(),
                    "supplied-session-resource-sha256",
                )
            && self.purpose_binding
                == request_descriptor_reference(
                    &self.application_url,
                    &self.target,
                    self.purpose,
                    self.credential_mechanism,
                    &self.policy_reference,
                )
    }

    pub(crate) fn validate_against(&self, policy: &SuppliedSessionPolicy) -> bool {
        self.validate()
            && self.policy_reference == policy.policy_reference
            && self.application_url == policy.application_url
            && self.credential_mechanism == policy.credential_mechanism
            && match self.purpose {
                SuppliedSessionRequestPurpose::Health => {
                    self.target == policy.health_url
                        && self.target_reference
                            == reference(
                                RESOURCE_REFERENCE_DOMAIN,
                                policy.health_url.as_str(),
                                "supplied-session-resource-sha256",
                            )
                },
                SuppliedSessionRequestPurpose::Resource => {
                    policy.resources.iter().any(|resource| {
                        resource.url == self.target && resource.reference == self.target_reference
                    })
                },
            }
    }

    pub(crate) const fn target(&self) -> &Url {
        &self.target
    }

    pub(crate) fn target_reference(&self) -> &str {
        &self.target_reference
    }

    pub(crate) const fn purpose(&self) -> SuppliedSessionRequestPurpose {
        self.purpose
    }

    pub(crate) const fn credential_mechanism(&self) -> SuppliedSessionCredentialMechanism {
        self.credential_mechanism
    }
}

impl fmt::Debug for SuppliedSessionRequestDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SuppliedSessionRequestDescriptor")
            .field("application", &"<redacted>")
            .field("target", &"<redacted>")
            .field("purpose", &self.purpose)
            .field("credential_mechanism", &self.credential_mechanism)
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePolicy {
    schema: String,
    principal_alias: String,
    credential_mechanism: String,
    health_path: String,
    health_json_field: String,
    resources: Vec<String>,
    max_session_requests: u8,
    max_total_response_bytes: u64,
    max_response_body_bytes: usize,
    max_wall_time_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCookiePolicy {
    schema: String,
    principal_alias: String,
    credential_mechanism: String,
    cookie_update_policy: String,
    health_path: String,
    health_json_field: String,
    resources: Vec<String>,
    cookies: Vec<WireCookieMetadata>,
    max_session_requests: u8,
    max_total_response_bytes: u64,
    max_response_body_bytes: usize,
    max_wall_time_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCookieMetadata {
    id: String,
    name: String,
    domain: String,
    host_only: bool,
    path: String,
    secure: bool,
    http_only: bool,
    same_site: String,
    expires_unix_seconds: Option<i64>,
}

fn validate_policy_limits(
    resource_count: usize,
    max_session_requests: u8,
    max_total_response_bytes: u64,
    max_response_body_bytes: usize,
    max_wall_time_ms: u64,
) -> Result<(), SuppliedSessionPolicyError> {
    let minimum_requests = 1_usize
        .checked_add(
            resource_count
                .checked_mul(2)
                .ok_or(SuppliedSessionPolicyError::InvalidLimits)?,
        )
        .ok_or(SuppliedSessionPolicyError::InvalidLimits)?;
    if max_session_requests == 0
        || usize::from(max_session_requests) < minimum_requests
        || max_session_requests > MAX_SUPPLIED_SESSION_REQUESTS
        || max_total_response_bytes == 0
        || max_total_response_bytes > MAX_SUPPLIED_SESSION_TOTAL_RESPONSE_BYTES
        || max_response_body_bytes == 0
        || max_response_body_bytes > MAX_SUPPLIED_SESSION_RESPONSE_BODY_BYTES
        || u64::try_from(max_response_body_bytes).unwrap_or(u64::MAX) > max_total_response_bytes
        || max_wall_time_ms == 0
        || max_wall_time_ms > MAX_SUPPLIED_SESSION_WALL_TIME_MS
    {
        Err(SuppliedSessionPolicyError::InvalidLimits)
    } else {
        Ok(())
    }
}

fn validate_cookie_path(path: &str) -> Result<(), SuppliedSessionPolicyError> {
    if path.is_empty()
        || path.len() > MAX_POLICY_PATH_BYTES
        || !path.starts_with('/')
        || path.contains("//")
        || path
            .bytes()
            .any(|byte| matches!(byte, b'?' | b'#' | b'%' | b'\\'))
        || path.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.' | b'~'))
        })
        || path
            .split('/')
            .skip(1)
            .filter(|segment| !segment.is_empty())
            .any(|segment| matches!(segment, "." | ".."))
    {
        Err(SuppliedSessionPolicyError::InvalidCookieMetadata)
    } else {
        Ok(())
    }
}

fn parse_cookie_same_site(
    value: &str,
) -> Result<SuppliedSessionCookieSameSite, SuppliedSessionPolicyError> {
    match value {
        "missing" => Ok(SuppliedSessionCookieSameSite::Missing),
        "strict" => Ok(SuppliedSessionCookieSameSite::Strict),
        "lax" => Ok(SuppliedSessionCookieSameSite::Lax),
        "none" => Ok(SuppliedSessionCookieSameSite::None),
        _ => Err(SuppliedSessionPolicyError::InvalidCookieMetadata),
    }
}

fn cookie_path_matches(cookie_path: &str, request_path: &str) -> bool {
    request_path == cookie_path
        || request_path
            .strip_prefix(cookie_path)
            .is_some_and(|suffix| {
                cookie_path.ends_with('/') || suffix.as_bytes().first() == Some(&b'/')
            })
}

fn cookie_applies(
    cookie: &SuppliedSessionCookieMetadata,
    target: &Url,
    now_unix_seconds: i64,
) -> bool {
    let Some(target_host) = target.host_str() else {
        return false;
    };
    let host_matches = if cookie.host_only {
        target_host == cookie.domain
    } else {
        target_host == cookie.domain
            || (target_host.ends_with(&cookie.domain)
                && target_host
                    .as_bytes()
                    .get(target_host.len().saturating_sub(cookie.domain.len() + 1))
                    == Some(&b'.'))
    };
    host_matches
        && (!cookie.secure || target.scheme() == "https")
        && cookie_path_matches(&cookie.path, target.path())
        && cookie
            .expires_unix_seconds
            .is_none_or(|expires| expires > now_unix_seconds)
}

fn cookie_octet(byte: u8) -> bool {
    matches!(byte, 0x21 | 0x23..=0x2b | 0x2d..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e)
}

fn summarize_cookies(cookies: &[SuppliedSessionCookieMetadata]) -> SuppliedSessionCookieSummary {
    let mut summary = SuppliedSessionCookieSummary {
        cookie_count: cookies.len(),
        host_only_count: 0,
        domain_count: 0,
        secure_count: 0,
        http_only_count: 0,
        session_count: 0,
        persistent_count: 0,
        same_site_missing_count: 0,
        same_site_strict_count: 0,
        same_site_lax_count: 0,
        same_site_none_count: 0,
    };
    for cookie in cookies {
        if cookie.host_only {
            summary.host_only_count += 1;
        } else {
            summary.domain_count += 1;
        }
        summary.secure_count += usize::from(cookie.secure);
        summary.http_only_count += usize::from(cookie.http_only);
        if cookie.expires_unix_seconds.is_some() {
            summary.persistent_count += 1;
        } else {
            summary.session_count += 1;
        }
        match cookie.same_site {
            SuppliedSessionCookieSameSite::Missing => summary.same_site_missing_count += 1,
            SuppliedSessionCookieSameSite::Strict => summary.same_site_strict_count += 1,
            SuppliedSessionCookieSameSite::Lax => summary.same_site_lax_count += 1,
            SuppliedSessionCookieSameSite::None => summary.same_site_none_count += 1,
        }
    }
    summary
}

fn validate_application_url(application: &Url) -> Result<(), SuppliedSessionPolicyError> {
    if !matches!(application.scheme(), "http" | "https")
        || application.host().is_none()
        || !application.username().is_empty()
        || application.password().is_some()
        || application.query().is_some()
        || application.fragment().is_some()
        || !application.path().starts_with('/')
        || !application.path().ends_with('/')
        || application.path().contains('%')
        || application.path().contains('\\')
    {
        return Err(SuppliedSessionPolicyError::InvalidApplication);
    }
    Ok(())
}

fn resolve_safe_path(application: &Url, raw: &str) -> Result<Url, SuppliedSessionPolicyError> {
    if raw.is_empty()
        || raw.len() > MAX_POLICY_PATH_BYTES
        || !raw.starts_with('/')
        || raw.starts_with("//")
        || raw == "/"
        || raw.contains("//")
        || raw
            .bytes()
            .any(|byte| matches!(byte, b'?' | b'#' | b'%' | b'\\'))
        || raw.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.' | b'~'))
        })
        || raw
            .split('/')
            .skip(1)
            .filter(|segment| !segment.is_empty())
            .any(|segment| matches!(segment, "." | ".."))
    {
        return Err(SuppliedSessionPolicyError::InvalidPath);
    }
    if raw
        .split('/')
        .skip(1)
        .filter(|segment| !segment.is_empty())
        .any(action_or_admin_segment)
    {
        return Err(SuppliedSessionPolicyError::InvalidPath);
    }
    let mut target = application.clone();
    target.set_path(raw);
    target.set_query(None);
    target.set_fragment(None);
    if target.origin() != application.origin() || !path_within_application(application, &target) {
        return Err(SuppliedSessionPolicyError::InvalidPath);
    }
    Ok(target)
}

fn path_within_application(application: &Url, target: &Url) -> bool {
    target.path().starts_with(application.path())
}

fn action_or_admin_segment(segment: &str) -> bool {
    segment
        .split(['-', '_', '.'])
        .filter(|token| !token.is_empty())
        .any(|token| {
            matches!(
                token.to_ascii_lowercase().as_str(),
                "admin"
                    | "login"
                    | "logout"
                    | "action"
                    | "actions"
                    | "delete"
                    | "remove"
                    | "update"
                    | "create"
                    | "edit"
                    | "upload"
                    | "download"
            )
        })
}

fn request_descriptor_reference(
    application: &Url,
    target: &Url,
    purpose: SuppliedSessionRequestPurpose,
    credential_mechanism: SuppliedSessionCredentialMechanism,
    policy_reference: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_DESCRIPTOR_REFERENCE_DOMAIN);
    hash_field(&mut hasher, application.as_str().as_bytes());
    hash_field(&mut hasher, target.as_str().as_bytes());
    hash_field(
        &mut hasher,
        match purpose {
            SuppliedSessionRequestPurpose::Health => b"health",
            SuppliedSessionRequestPurpose::Resource => b"resource",
        },
    );
    hash_field(&mut hasher, credential_mechanism.as_str().as_bytes());
    hash_field(&mut hasher, policy_reference.as_bytes());
    hex(hasher.finalize().as_slice())
}

fn validate_token(value: &str, maximum: usize) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > maximum
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'@' | b'-')
        })
    {
        Err(())
    } else {
        Ok(())
    }
}

fn policy_reference(
    application: &Url,
    wire: &WirePolicy,
    mechanism: SuppliedSessionCredentialMechanism,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(POLICY_REFERENCE_DOMAIN);
    hash_field(&mut hasher, SUPPLIED_SESSION_POLICY_SCHEMA.as_bytes());
    hash_field(&mut hasher, application.as_str().as_bytes());
    // The operator's potentially low-entropy display alias is validated but
    // deliberately excluded from every public reference. V1 has one opaque
    // run-local principal slot, so the alias grants no transport distinction.
    hash_field(
        &mut hasher,
        match mechanism {
            SuppliedSessionCredentialMechanism::AuthorizationHeader => b"authorization_header",
            SuppliedSessionCredentialMechanism::CookieJar => b"cookie_jar",
        },
    );
    hash_field(&mut hasher, wire.health_path.as_bytes());
    hash_field(&mut hasher, wire.health_json_field.as_bytes());
    for resource in &wire.resources {
        hash_field(&mut hasher, resource.as_bytes());
    }
    hash_field(&mut hasher, &[wire.max_session_requests]);
    hash_field(&mut hasher, &wire.max_total_response_bytes.to_be_bytes());
    hash_field(
        &mut hasher,
        &u64::try_from(wire.max_response_body_bytes)
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hash_field(&mut hasher, &wire.max_wall_time_ms.to_be_bytes());
    format!("supplied-session-policy-sha256:{}", hex(hasher.finalize()))
}

fn cookie_policy_reference(
    application: &Url,
    wire: &WireCookiePolicy,
    mechanism: SuppliedSessionCredentialMechanism,
    update_policy: SuppliedSessionCookieUpdatePolicy,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(COOKIE_POLICY_REFERENCE_DOMAIN);
    hash_field(
        &mut hasher,
        SUPPLIED_SESSION_COOKIE_POLICY_SCHEMA.as_bytes(),
    );
    hash_field(&mut hasher, application.as_str().as_bytes());
    hash_field(&mut hasher, mechanism.as_str().as_bytes());
    hash_field(&mut hasher, update_policy.as_str().as_bytes());
    hash_field(&mut hasher, wire.health_path.as_bytes());
    hash_field(&mut hasher, wire.health_json_field.as_bytes());
    for resource in &wire.resources {
        hash_field(&mut hasher, resource.as_bytes());
    }
    for cookie in &wire.cookies {
        hash_field(&mut hasher, cookie.id.as_bytes());
        hash_field(&mut hasher, cookie.name.as_bytes());
        hash_field(&mut hasher, cookie.domain.as_bytes());
        hash_field(&mut hasher, &[u8::from(cookie.host_only)]);
        hash_field(&mut hasher, cookie.path.as_bytes());
        hash_field(&mut hasher, &[u8::from(cookie.secure)]);
        hash_field(&mut hasher, &[u8::from(cookie.http_only)]);
        hash_field(&mut hasher, cookie.same_site.as_bytes());
        match cookie.expires_unix_seconds {
            Some(expires) => {
                hash_field(&mut hasher, b"persistent");
                hash_field(&mut hasher, &expires.to_be_bytes());
            },
            None => hash_field(&mut hasher, b"session"),
        }
    }
    hash_field(&mut hasher, &[wire.max_session_requests]);
    hash_field(&mut hasher, &wire.max_total_response_bytes.to_be_bytes());
    hash_field(
        &mut hasher,
        &u64::try_from(wire.max_response_body_bytes)
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hash_field(&mut hasher, &wire.max_wall_time_ms.to_be_bytes());
    format!("supplied-session-policy-sha256:{}", hex(hasher.finalize()))
}

fn reference(domain: &[u8], value: &str, prefix: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hash_field(&mut hasher, value.as_bytes());
    format!("{prefix}:{}", hex(hasher.finalize()))
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    use std::fmt::Write as _;
    let bytes = bytes.as_ref();
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing into String cannot fail");
    }
    output
}

fn http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> &'static [u8] {
        br#"schema = "security.supplied-session-policy/v1"
principal_alias = "fixture-user"
credential_mechanism = "authorization_header"
health_path = "/app/session-health"
health_json_field = "authenticated"
resources = ["/app/private-one", "/app/private-two"]
max_session_requests = 5
max_total_response_bytes = 262144
max_response_body_bytes = 65536
max_wall_time_ms = 10000
"#
    }

    fn cookie_policy() -> &'static [u8] {
        br#"schema = "security.supplied-session-policy/v2"
principal_alias = "fixture-user"
credential_mechanism = "cookie_jar"
cookie_update_policy = "stop_on_selected_cookie"
health_path = "/app/session-health"
health_json_field = "authenticated"
resources = ["/app/private-one", "/app/private-two"]
max_session_requests = 5
max_total_response_bytes = 262144
max_response_body_bytes = 65536
max_wall_time_ms = 10000

[[cookies]]
id = "broad-session"
name = "session"
domain = "example.test"
host_only = true
path = "/app/"
secure = true
http_only = true
same_site = "lax"

[[cookies]]
id = "narrow-session"
name = "session"
domain = "example.test"
host_only = false
path = "/app/private-one"
secure = true
http_only = true
same_site = "strict"
expires_unix_seconds = 4102444800
"#
    }

    #[test]
    fn policy_is_strict_bounded_and_path_scoped() {
        let application = Url::parse("https://example.test/app/").unwrap();
        let parsed = SuppliedSessionPolicy::parse_toml(&application, policy()).unwrap();
        assert_eq!(parsed.resource_count(), 2);
        assert_eq!(parsed.max_session_requests(), 5);
        assert!(parsed
            .policy_reference()
            .starts_with("supplied-session-policy-sha256:"));
        assert_eq!(
            parsed.policy_reference(),
            "supplied-session-policy-sha256:502b4044585b1cb18b9d4692f3c864d4611bb51e4aef0663188951de15a018c0"
        );
        assert_eq!(parsed.version(), SuppliedSessionPolicyVersion::V1);
        assert_eq!(parsed.schema(), SUPPLIED_SESSION_POLICY_SCHEMA);
        assert_eq!(parsed.cookie_update_policy(), None);
        assert_eq!(parsed.cookie_summary(), None);
        assert!(parsed
            .application_reference()
            .starts_with("supplied-session-application-sha256:"));
        assert_eq!(
            parsed.principal_reference(),
            "supplied-session-principal-0001"
        );
        assert_eq!(parsed.principal_alias(), "fixture-user");
        assert!(!format!("{parsed:?}").contains("/app/private"));
        assert!(!format!("{parsed:?}").contains("fixture-user"));
        let renamed = std::str::from_utf8(policy())
            .unwrap()
            .replace("fixture-user", "another-low-entropy-label");
        let renamed = SuppliedSessionPolicy::parse_toml(&application, renamed.as_bytes()).unwrap();
        assert_eq!(parsed.policy_reference(), renamed.policy_reference());
        assert_eq!(parsed.principal_reference(), renamed.principal_reference());
        assert_ne!(parsed.principal_alias(), renamed.principal_alias());

        for invalid in [
            "/app/../admin",
            "/app/%2e%2e/admin",
            "/app",
            "/application/private",
            "/app/logout",
            "/app/account/logout.php",
            "/app/delete.php",
            "/app/admin-panel/",
            "https://example.test/app/private",
            "/app/private?x=1",
            "/app/privaté",
            "/app/private[0]",
        ] {
            let text = std::str::from_utf8(policy()).unwrap().replace(
                "resources = [\"/app/private-one\", \"/app/private-two\"]",
                &format!("resources = [\"{invalid}\"]"),
            );
            assert!(SuppliedSessionPolicy::parse_toml(&application, text.as_bytes()).is_err());
        }

        let ordinary = std::str::from_utf8(policy()).unwrap().replace(
            "resources = [\"/app/private-one\", \"/app/private-two\"]",
            "resources = [\"/app/administrator-guide\"]",
        );
        let ordinary = ordinary.replace("max_session_requests = 5", "max_session_requests = 3");
        assert!(SuppliedSessionPolicy::parse_toml(&application, ordinary.as_bytes()).is_ok());
    }

    #[test]
    fn policy_rejects_duplicates_unknowns_and_inconsistent_limits() {
        let application = Url::parse("https://example.test/app/").unwrap();
        let duplicate = std::str::from_utf8(policy()).unwrap().replace(
            "resources = [\"/app/private-one\", \"/app/private-two\"]",
            "resources = [\"/app/private-one\", \"/app/private-one\"]",
        );
        assert_eq!(
            SuppliedSessionPolicy::parse_toml(&application, duplicate.as_bytes()).unwrap_err(),
            SuppliedSessionPolicyError::InvalidPath
        );
        let unknown = [policy(), b"unknown = true\n"].concat();
        assert_eq!(
            SuppliedSessionPolicy::parse_toml(&application, &unknown).unwrap_err(),
            SuppliedSessionPolicyError::MalformedPolicy
        );
        let too_few = std::str::from_utf8(policy())
            .unwrap()
            .replace("max_session_requests = 5", "max_session_requests = 4");
        assert_eq!(
            SuppliedSessionPolicy::parse_toml(&application, too_few.as_bytes()).unwrap_err(),
            SuppliedSessionPolicyError::InvalidLimits
        );
    }

    #[test]
    fn authorization_is_move_only_bounded_and_redacted() {
        let authorization = SuppliedSessionAuthorization::new("Bearer SECRET-CANARY").unwrap();
        assert_eq!(
            format!("{authorization:?}"),
            "SuppliedSessionAuthorization(<redacted>)"
        );
        assert!(!format!("{authorization:?}").contains("SECRET-CANARY"));
        for invalid in [
            "",
            "Bearer",
            "Bearer  spaced",
            "Bearer trailing ",
            "Bad\r\n injected",
        ] {
            assert!(SuppliedSessionAuthorization::new(invalid).is_err());
        }
    }

    #[test]
    fn cookie_policy_and_secret_preserve_metadata_and_rfc_path_order() {
        let application = Url::parse("https://example.test/app/").unwrap();
        let parsed = SuppliedSessionPolicy::parse_toml(&application, cookie_policy()).unwrap();
        assert_eq!(parsed.version(), SuppliedSessionPolicyVersion::V2);
        assert_eq!(parsed.schema(), SUPPLIED_SESSION_COOKIE_POLICY_SCHEMA);
        assert_eq!(
            parsed.credential_mechanism(),
            SuppliedSessionCredentialMechanism::CookieJar
        );
        assert_eq!(
            parsed.cookie_update_policy(),
            Some(SuppliedSessionCookieUpdatePolicy::StopOnSelectedCookie)
        );
        let summary = parsed.cookie_summary().unwrap();
        assert_eq!(summary.cookie_count(), 2);
        assert_eq!(summary.host_only_count(), 1);
        assert_eq!(summary.domain_count(), 1);
        assert_eq!(summary.secure_count(), 2);
        assert_eq!(summary.http_only_count(), 2);
        assert_eq!(summary.session_count(), 1);
        assert_eq!(summary.persistent_count(), 1);
        assert_eq!(summary.same_site_lax_count(), 1);
        assert_eq!(summary.same_site_strict_count(), 1);
        assert_eq!(summary.same_site_missing_count(), 0);
        assert_eq!(summary.same_site_none_count(), 0);
        assert!(parsed.is_selected_cookie_name("session"));
        assert!(!parsed.is_selected_cookie_name("Session"));

        let cookies = SuppliedSessionCookies::parse_tsv(
            &parsed,
            b"narrow-session\tNARROW-CANARY\r\nbroad-session\tBROAD-CANARY\n".to_vec(),
            2_000_000_000,
        )
        .unwrap();
        assert_eq!(cookies.cookie_count(), 2);
        assert_eq!(
            format!("{cookies:?}"),
            "SuppliedSessionCookies { values: \"<redacted>\", cookie_count: 2 }"
        );
        assert!(!format!("{cookies:?}").contains("CANARY"));

        let target = Url::parse("https://example.test/app/private-one").unwrap();
        let header = cookies
            .sensitive_header_for_target(&parsed, &target, 2_000_000_000)
            .unwrap();
        assert!(header.is_sensitive());
        assert_eq!(
            header.to_str().unwrap(),
            "session=NARROW-CANARY; session=BROAD-CANARY"
        );

        let second = Url::parse("https://example.test/app/private-two").unwrap();
        assert_eq!(
            cookies
                .sensitive_header_for_target(&parsed, &second, 2_000_000_000)
                .unwrap()
                .to_str()
                .unwrap(),
            "session=BROAD-CANARY"
        );
        assert_eq!(
            cookies
                .sensitive_header_for_target(
                    &parsed,
                    &Url::parse("https://example.test/app/unselected").unwrap(),
                    2_000_000_000,
                )
                .unwrap_err(),
            SuppliedSessionCookieError::TargetNotAdmitted
        );
    }

    #[test]
    fn cookie_policy_rejects_unsafe_scope_duplicates_and_wrong_contracts() {
        let application = Url::parse("https://example.test/app/").unwrap();
        for (needle, replacement) in [
            ("domain = \"example.test\"", "domain = \"parent.test\""),
            ("path = \"/app/\"", "path = \"/application/\""),
            ("same_site = \"lax\"", "same_site = \"future\""),
            (
                "cookie_update_policy = \"stop_on_selected_cookie\"",
                "cookie_update_policy = \"apply_automatically\"",
            ),
            (
                "credential_mechanism = \"cookie_jar\"",
                "credential_mechanism = \"authorization_header\"",
            ),
        ] {
            let changed =
                std::str::from_utf8(cookie_policy())
                    .unwrap()
                    .replacen(needle, replacement, 1);
            assert!(SuppliedSessionPolicy::parse_toml(&application, changed.as_bytes()).is_err());
        }

        let duplicate_id = std::str::from_utf8(cookie_policy())
            .unwrap()
            .replace("id = \"narrow-session\"", "id = \"broad-session\"");
        assert_eq!(
            SuppliedSessionPolicy::parse_toml(&application, duplicate_id.as_bytes()).unwrap_err(),
            SuppliedSessionPolicyError::InvalidCookieMetadata
        );
        let duplicate_tuple = std::str::from_utf8(cookie_policy())
            .unwrap()
            .replace("path = \"/app/private-one\"", "path = \"/app/\"");
        assert_eq!(
            SuppliedSessionPolicy::parse_toml(&application, duplicate_tuple.as_bytes())
                .unwrap_err(),
            SuppliedSessionPolicyError::InvalidCookieMetadata
        );
        let insecure_none = std::str::from_utf8(cookie_policy())
            .unwrap()
            .replacen("secure = true", "secure = false", 1)
            .replacen("same_site = \"lax\"", "same_site = \"none\"", 1);
        assert_eq!(
            SuppliedSessionPolicy::parse_toml(&application, insecure_none.as_bytes()).unwrap_err(),
            SuppliedSessionPolicyError::InvalidCookieMetadata
        );

        let ip_application = Url::parse("https://127.0.0.1/app/").unwrap();
        let ip_domain = std::str::from_utf8(cookie_policy())
            .unwrap()
            .replace("example.test", "127.0.0.1")
            .replace("host_only = true", "host_only = false");
        assert_eq!(
            SuppliedSessionPolicy::parse_toml(&ip_application, ip_domain.as_bytes()).unwrap_err(),
            SuppliedSessionPolicyError::InvalidCookieMetadata
        );
    }

    #[test]
    fn cookie_secret_is_exact_bounded_redacted_and_expiry_aware() {
        let application = Url::parse("https://example.test/app/").unwrap();
        let parsed = SuppliedSessionPolicy::parse_toml(&application, cookie_policy()).unwrap();
        for invalid in [
            b"broad-session\tVALUE\n".as_slice(),
            b"broad-session\tVALUE\nnarrow-session\tVALUE\nextra\tVALUE\n".as_slice(),
            b"broad-session\tVALUE\nbroad-session\tOTHER\nnarrow-session\tVALUE\n".as_slice(),
            b"broad-session\tBAD VALUE\nnarrow-session\tVALUE\n".as_slice(),
            b"broad-session\tBAD;VALUE\nnarrow-session\tVALUE\n".as_slice(),
            b"\n".as_slice(),
        ] {
            assert_eq!(
                SuppliedSessionCookies::parse_tsv(&parsed, invalid.to_vec(), 2_000_000_000)
                    .unwrap_err(),
                SuppliedSessionCookieError::MalformedSecret
            );
        }
        assert_eq!(
            SuppliedSessionCookies::parse_tsv(
                &parsed,
                vec![b'a'; HARD_MAX_SUPPLIED_SESSION_COOKIE_SECRET_BYTES + 1],
                2_000_000_000,
            )
            .unwrap_err(),
            SuppliedSessionCookieError::SecretTooLarge
        );

        let expired = std::str::from_utf8(cookie_policy()).unwrap().replace(
            "expires_unix_seconds = 4102444800",
            "expires_unix_seconds = 1",
        );
        let expired = SuppliedSessionPolicy::parse_toml(&application, expired.as_bytes()).unwrap();
        let values = b"broad-session\tBROAD\nnarrow-session\tNARROW\n".to_vec();
        assert_eq!(
            SuppliedSessionCookies::parse_tsv(&expired, values, 2_000_000_000).unwrap_err(),
            SuppliedSessionCookieError::IncompleteInitialCoverage
        );

        let authorization_policy =
            SuppliedSessionPolicy::parse_toml(&application, policy()).unwrap();
        assert_eq!(
            SuppliedSessionCookies::parse_tsv(
                &authorization_policy,
                b"broad-session\tSECRET\n".to_vec(),
                2_000_000_000,
            )
            .unwrap_err(),
            SuppliedSessionCookieError::PolicyMismatch
        );
    }

    #[test]
    fn cookie_header_limit_and_mid_run_expiry_fail_closed() {
        let application = Url::parse("https://example.test/app/").unwrap();
        let parsed = SuppliedSessionPolicy::parse_toml(&application, cookie_policy()).unwrap();
        let secret = format!(
            "broad-session\t{}\nnarrow-session\t{}\n",
            "a".repeat(MAX_COOKIE_VALUE_BYTES),
            "b".repeat(MAX_COOKIE_VALUE_BYTES)
        );
        let cookies =
            SuppliedSessionCookies::parse_tsv(&parsed, secret.into_bytes(), 2_000_000_000).unwrap();
        let target = Url::parse("https://example.test/app/private-one").unwrap();
        assert_eq!(
            cookies
                .sensitive_header_for_target(&parsed, &target, 2_000_000_000)
                .unwrap_err(),
            SuppliedSessionCookieError::HeaderTooLarge
        );

        let one_cookie = std::str::from_utf8(cookie_policy()).unwrap();
        let one_cookie = one_cookie
            .split("\n[[cookies]]\nid = \"narrow-session\"")
            .next()
            .unwrap();
        let one_cookie = format!("{one_cookie}\nexpires_unix_seconds = 2000000001\n");
        let one_cookie =
            SuppliedSessionPolicy::parse_toml(&application, one_cookie.as_bytes()).unwrap();
        let cookies = SuppliedSessionCookies::parse_tsv(
            &one_cookie,
            b"broad-session\tSECRET\n".to_vec(),
            2_000_000_000,
        )
        .unwrap();
        let health = SuppliedSessionRequestDescriptor::health(&one_cookie);
        assert_eq!(
            cookies
                .sensitive_header_for_target(&one_cookie, health.target(), 2_000_000_001)
                .unwrap_err(),
            SuppliedSessionCookieError::NoApplicableCookie
        );

        let partially_expiring = std::str::from_utf8(cookie_policy()).unwrap().replace(
            "expires_unix_seconds = 4102444800",
            "expires_unix_seconds = 2000000001",
        );
        let partially_expiring =
            SuppliedSessionPolicy::parse_toml(&application, partially_expiring.as_bytes()).unwrap();
        let cookies = SuppliedSessionCookies::parse_tsv(
            &partially_expiring,
            b"broad-session\tBROAD\nnarrow-session\tNARROW\n".to_vec(),
            2_000_000_000,
        )
        .unwrap();
        let target = Url::parse("https://example.test/app/private-one").unwrap();
        assert_eq!(
            cookies
                .sensitive_header_for_target(&partially_expiring, &target, 2_000_000_001)
                .unwrap_err(),
            SuppliedSessionCookieError::NoApplicableCookie
        );
    }

    #[test]
    fn typed_credentials_are_redacted_and_mechanism_specific() {
        let authorization = SuppliedSessionCredential::Authorization(
            SuppliedSessionAuthorization::new("Bearer SECRET-CANARY").unwrap(),
        );
        assert_eq!(
            authorization.mechanism(),
            SuppliedSessionCredentialMechanism::AuthorizationHeader
        );
        assert!(authorization.authorization().is_some());
        assert!(authorization.cookies().is_none());
        assert!(!format!("{authorization:?}").contains("SECRET-CANARY"));

        let application = Url::parse("https://example.test/app/").unwrap();
        let policy = SuppliedSessionPolicy::parse_toml(&application, cookie_policy()).unwrap();
        let cookies = SuppliedSessionCookies::parse_tsv(
            &policy,
            b"broad-session\tBROAD\nnarrow-session\tNARROW\n".to_vec(),
            2_000_000_000,
        )
        .unwrap();
        let cookies = SuppliedSessionCredential::SuppliedCookies(cookies);
        assert_eq!(
            cookies.mechanism(),
            SuppliedSessionCredentialMechanism::CookieJar
        );
        assert!(cookies.authorization().is_none());
        assert!(cookies.cookies().is_some());
        assert!(!format!("{cookies:?}").contains("BROAD"));
    }

    #[test]
    fn request_descriptor_binds_its_closed_purpose() {
        let application = Url::parse("https://example.test/app/").unwrap();
        let parsed = SuppliedSessionPolicy::parse_toml(&application, policy()).unwrap();
        let mut health = SuppliedSessionRequestDescriptor::health(&parsed);
        assert!(health.validate());
        assert!(health.validate_against(&parsed));
        health.purpose = SuppliedSessionRequestPurpose::Resource;
        assert!(!health.validate());
        assert!(!health.validate_against(&parsed));

        let (target, reference) = parsed.execution_resources().next().unwrap();
        let mut resource = SuppliedSessionRequestDescriptor::resource(&parsed, target, reference)
            .expect("literal resource must be admitted");
        assert!(resource.validate());
        assert!(resource.validate_against(&parsed));
        resource.purpose = SuppliedSessionRequestPurpose::Health;
        assert!(!resource.validate());

        let mut mechanism = SuppliedSessionRequestDescriptor::health(&parsed);
        assert_eq!(
            mechanism.credential_mechanism(),
            SuppliedSessionCredentialMechanism::AuthorizationHeader
        );
        mechanism.credential_mechanism = SuppliedSessionCredentialMechanism::CookieJar;
        assert!(!mechanism.validate());

        let changed_policy_source = std::str::from_utf8(policy())
            .unwrap()
            .replace("max_wall_time_ms = 10000", "max_wall_time_ms = 9999");
        let changed_policy =
            SuppliedSessionPolicy::parse_toml(&application, changed_policy_source.as_bytes())
                .unwrap();
        let descriptor = SuppliedSessionRequestDescriptor::health(&parsed);
        assert!(descriptor.validate());
        assert!(!descriptor.validate_against(&changed_policy));

        let mut wrong_reference = SuppliedSessionRequestDescriptor::health(&parsed);
        wrong_reference.policy_reference = changed_policy.policy_reference().to_owned();
        assert!(!wrong_reference.validate());
        assert!(!wrong_reference.validate_against(&parsed));
    }
}
