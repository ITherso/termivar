//! Transport-neutral contracts for one explicitly supplied authorization session.
//!
//! The policy is non-secret and grants only a small ordered set of bodyless,
//! read-oriented GET requests beneath one already selected application. The
//! authorization value is move-only, zeroized on drop, never serialized, and
//! exposed only to the crate-owned request-composition boundary.

use std::fmt;

use reqwest::header::HeaderValue;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

/// Strict V1 supplied-session policy schema.
pub const SUPPLIED_SESSION_POLICY_SCHEMA: &str = "security.supplied-session-policy/v1";
/// Maximum accepted policy bytes.
pub const HARD_MAX_SUPPLIED_SESSION_POLICY_BYTES: usize = 64 * 1024;
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
const POLICY_REFERENCE_DOMAIN: &[u8] = b"security.supplied-session-policy.reference.v1\0";
const APPLICATION_REFERENCE_DOMAIN: &[u8] = b"security.supplied-session-application.reference.v1\0";
const HEALTH_FIELD_REFERENCE_DOMAIN: &[u8] =
    b"security.supplied-session-health-field.reference.v1\0";
const RESOURCE_REFERENCE_DOMAIN: &[u8] = b"security.supplied-session-resource.reference.v1\0";
const REQUEST_DESCRIPTOR_REFERENCE_DOMAIN: &[u8] =
    b"security.supplied-session-request-descriptor.reference.v1\0";
const SUPPLIED_SESSION_PRINCIPAL_REFERENCE: &str = "supplied-session-principal-0001";

/// The only credential mechanism admitted by V1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SuppliedSessionCredentialMechanism {
    /// One complete caller-supplied `Authorization` header value.
    AuthorizationHeader,
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

/// Strict non-secret policy for one supplied session.
pub struct SuppliedSessionPolicy {
    application_url: Url,
    principal_alias: String,
    health_url: Url,
    health_json_field: String,
    resources: Vec<SuppliedSessionResource>,
    credential_mechanism: SuppliedSessionCredentialMechanism,
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
        let wire: WirePolicy =
            toml::from_str(source).map_err(|_| SuppliedSessionPolicyError::MalformedPolicy)?;
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
            application_url: application_url.clone(),
            principal_alias: wire.principal_alias,
            health_url,
            health_json_field: wire.health_json_field.clone(),
            resources,
            credential_mechanism,
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

    /// Stable semantic policy reference; it contains no credential or raw URL.
    pub fn policy_reference(&self) -> &str {
        &self.policy_reference
    }

    /// Stable exact-application reference; it contains no raw URL.
    pub fn application_reference(&self) -> &str {
        &self.application_reference
    }

    /// Opaque V1 principal slot; it is not an authenticated or cross-run identity.
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

    /// V1's sole credential mechanism.
    pub const fn credential_mechanism(&self) -> SuppliedSessionCredentialMechanism {
        self.credential_mechanism
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
}

impl fmt::Debug for SuppliedSessionPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SuppliedSessionPolicy")
            .field("application", &"<redacted>")
            .field("health", &"<redacted>")
            .field("health_json_field", &"<redacted>")
            .field("principal_alias", &"<operator-declared>")
            .field("resource_count", &self.resources.len())
            .field("credential_mechanism", &self.credential_mechanism)
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
            purpose_binding: request_descriptor_reference(
                &policy.application_url,
                &policy.health_url,
                purpose,
            ),
        };
        debug_assert!(descriptor.validate());
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
            purpose_binding: request_descriptor_reference(&policy.application_url, target, purpose),
        };
        descriptor.validate().then_some(descriptor)
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
                == request_descriptor_reference(&self.application_url, &self.target, self.purpose)
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
}

impl fmt::Debug for SuppliedSessionRequestDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SuppliedSessionRequestDescriptor")
            .field("application", &"<redacted>")
            .field("target", &"<redacted>")
            .field("purpose", &self.purpose)
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

    #[test]
    fn policy_is_strict_bounded_and_path_scoped() {
        let application = Url::parse("https://example.test/app/").unwrap();
        let parsed = SuppliedSessionPolicy::parse_toml(&application, policy()).unwrap();
        assert_eq!(parsed.resource_count(), 2);
        assert_eq!(parsed.max_session_requests(), 5);
        assert!(parsed
            .policy_reference()
            .starts_with("supplied-session-policy-sha256:"));
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
    fn request_descriptor_binds_its_closed_purpose() {
        let application = Url::parse("https://example.test/app/").unwrap();
        let parsed = SuppliedSessionPolicy::parse_toml(&application, policy()).unwrap();
        let mut health = SuppliedSessionRequestDescriptor::health(&parsed);
        assert!(health.validate());
        health.purpose = SuppliedSessionRequestPurpose::Resource;
        assert!(!health.validate());

        let (target, reference) = parsed.execution_resources().next().unwrap();
        let mut resource = SuppliedSessionRequestDescriptor::resource(&parsed, target, reference)
            .expect("literal resource must be admitted");
        assert!(resource.validate());
        resource.purpose = SuppliedSessionRequestPurpose::Health;
        assert!(!resource.validate());
    }
}
