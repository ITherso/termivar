//! Strict authorization-review policy parsing and semantic identity.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::{ParseError, Url};

use crate::{
    api_evidence::{ApiComparisonProfile, JsonPathPattern},
    HttpEvidencePolicy,
};

/// Purpose-oriented repository policy schema.
pub const AUTHORIZATION_REVIEW_POLICY_SCHEMA: &str = "security.authorization-review-policy/v1";
/// Stable comparison and identity algorithm implemented by this module.
pub const AUTHORIZATION_REVIEW_ALGORITHM_VERSION: &str = "security.authorization-differential/v1";
/// Maximum accepted policy source bytes.
pub const HARD_MAX_AUTHORIZATION_REVIEW_POLICY_BYTES: usize = 64 * 1024;
/// Maximum selected subtrees in V1.
pub const HARD_MAX_AUTHORIZATION_REVIEW_SELECTED_PATHS: usize = 8;
/// Maximum ignored subtrees in V1.
pub const HARD_MAX_AUTHORIZATION_REVIEW_IGNORED_PATHS: usize = 16;
/// Maximum unordered-array paths in V1.
pub const HARD_MAX_AUTHORIZATION_REVIEW_UNORDERED_ARRAY_PATHS: usize = 8;
/// Maximum bytes in one canonical pointer.
pub const HARD_MAX_AUTHORIZATION_REVIEW_PATH_BYTES: usize = 256;
/// Maximum retained redacted diff paths in V1.
pub const HARD_MAX_AUTHORIZATION_REVIEW_DIFF_PATHS: u16 = 32;

const HARD_MAX_AUTHORIZATION_REVIEW_RESOURCE_BYTES: usize = 8 * 1024;
const HARD_MAX_AUTHORIZATION_REVIEW_HANDLE_BYTES: usize = 128;
const POLICY_ID_DOMAIN: &[u8] = b"security.authorization-review-policy.identity.v1\0";
const RESOURCE_SCOPE_DOMAIN: &[u8] = b"security.authorization-review-resource.v1\0";
const HANDLE_DOMAIN: &[u8] = b"security.authorization-review-handle.v1\0";

/// V1 host-declared relation under review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum AuthorizationReviewExpectation {
    /// The host asserts that only the primary principal should receive the resource.
    PrimaryOnly,
}

impl AuthorizationReviewExpectation {
    const fn wire(self) -> &'static str {
        match self {
            Self::PrimaryOnly => "primary-only",
        }
    }
}

/// Read-only method supported by V1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum AuthorizationReviewMethod {
    /// One bodyless GET request template is replayed across four legs.
    Get,
}

impl AuthorizationReviewMethod {
    const fn wire(self) -> &'static str {
        match self {
            Self::Get => "GET",
        }
    }
}

/// Stable semantic identity of a validated policy.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthorizationReviewPolicyId([u8; 32]);

impl AuthorizationReviewPolicyId {
    /// Returns the raw domain-separated digest.
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Returns the prefixed lowercase hexadecimal wire identity.
    pub fn to_wire(self) -> String {
        format!("authorization-policy-sha256:{}", hex(self.0))
    }
}

impl fmt::Debug for AuthorizationReviewPolicyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_wire())
    }
}

impl fmt::Display for AuthorizationReviewPolicyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_wire())
    }
}

impl Serialize for AuthorizationReviewPolicyId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_wire())
    }
}

/// Pseudonymous exact selected-resource identity.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthorizationResourceScopeId([u8; 32]);

impl AuthorizationResourceScopeId {
    /// Returns the raw domain-separated digest.
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Returns the prefixed lowercase hexadecimal wire identity.
    pub fn to_wire(self) -> String {
        format!("authorization-resource-sha256:{}", hex(self.0))
    }
}

impl fmt::Debug for AuthorizationResourceScopeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_wire())
    }
}

impl fmt::Display for AuthorizationResourceScopeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_wire())
    }
}

impl Serialize for AuthorizationResourceScopeId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_wire())
    }
}

/// Strict, bounded policy for one exact-origin JSON resource.
pub struct AuthorizationReviewPolicy {
    expectation: AuthorizationReviewExpectation,
    method: AuthorizationReviewMethod,
    comparison: ApiComparisonProfile,
    policy_id: AuthorizationReviewPolicyId,
    resource: Url,
}

impl AuthorizationReviewPolicy {
    /// Parses a strict bounded TOML policy and resolves its resource under the
    /// existing exact-origin HTTP evidence authority contract.
    pub fn parse_toml(
        authorized_origin: &Url,
        source: &[u8],
    ) -> Result<Self, AuthorizationReviewPolicyError> {
        if source.len() > HARD_MAX_AUTHORIZATION_REVIEW_POLICY_BYTES {
            return Err(AuthorizationReviewPolicyError::PolicyTooLarge);
        }
        let source = std::str::from_utf8(source)
            .map_err(|_| AuthorizationReviewPolicyError::MalformedPolicy)?;
        let wire: WirePolicy =
            toml::from_str(source).map_err(|_| AuthorizationReviewPolicyError::MalformedPolicy)?;
        if wire.schema != AUTHORIZATION_REVIEW_POLICY_SCHEMA {
            return Err(AuthorizationReviewPolicyError::UnsupportedSchema);
        }
        let expectation = match wire.expectation.as_str() {
            "primary-only" => AuthorizationReviewExpectation::PrimaryOnly,
            _ => return Err(AuthorizationReviewPolicyError::UnsupportedExpectation),
        };
        let method = match wire.method.as_str() {
            "GET" => AuthorizationReviewMethod::Get,
            _ => return Err(AuthorizationReviewPolicyError::UnsupportedMethod),
        };
        validate_handle(&wire.resource_handle)?;

        let resource = resolve_resource(authorized_origin, &wire.resource)?;
        let comparison = build_comparison_profile(wire.comparison)?;
        let resource_scope_id = resource_scope_id(&resource);
        let handle_digest: [u8; 32] = domain_digest(HANDLE_DOMAIN, wire.resource_handle.as_bytes());
        let policy_id = policy_id(
            resource_scope_id,
            handle_digest,
            expectation,
            method,
            &comparison,
        );
        Ok(Self {
            expectation,
            method,
            comparison,
            policy_id,
            resource,
        })
    }

    /// Returns the stable semantic policy identity.
    pub const fn policy_id(&self) -> AuthorizationReviewPolicyId {
        self.policy_id
    }

    /// Returns the pseudonymous exact-resource scope identity.
    pub fn resource_scope_id(&self) -> AuthorizationResourceScopeId {
        resource_scope_id(self.execution_resource())
    }

    /// Returns the sole executable V1 expectation.
    pub const fn expectation(&self) -> AuthorizationReviewExpectation {
        self.expectation
    }

    /// Returns the sole executable V1 method.
    pub const fn method(&self) -> AuthorizationReviewMethod {
        self.method
    }

    /// Returns the checked raw-value-free projection profile.
    pub const fn comparison(&self) -> &ApiComparisonProfile {
        &self.comparison
    }

    /// Returns the selected-path count without exposing path material.
    pub fn selected_path_count(&self) -> usize {
        self.comparison.selected_paths().len()
    }

    /// Returns the ignored-path count without exposing path material.
    pub fn ignored_path_count(&self) -> usize {
        self.comparison.ignored_paths().len()
    }

    /// Returns the unordered-array-path count without exposing path material.
    pub fn unordered_array_path_count(&self) -> usize {
        self.comparison.unordered_arrays().len()
    }

    /// Returns the already validated canonical request target only to the
    /// crate-owned execution boundary.
    pub(crate) const fn execution_resource(&self) -> &Url {
        &self.resource
    }
}

impl fmt::Debug for AuthorizationReviewPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationReviewPolicy")
            .field("resource", &"<redacted>")
            .field("resource_handle", &"<redacted>")
            .field("expectation", &self.expectation)
            .field("method", &self.method)
            .field("comparison", &self.comparison)
            .field("policy_id", &self.policy_id)
            .field("resource_scope_id", &self.resource_scope_id())
            .finish()
    }
}

/// Static, value-free policy validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum AuthorizationReviewPolicyError {
    /// Input exceeded the compiled policy source ceiling.
    #[error("authorization review policy exceeds its compiled byte limit")]
    PolicyTooLarge,
    /// TOML, UTF-8, required fields, or a bounded scalar was invalid.
    #[error("authorization review policy is malformed")]
    MalformedPolicy,
    /// The schema identifier is not supported.
    #[error("authorization review policy schema is unsupported")]
    UnsupportedSchema,
    /// V1 implements only primary-only policy review.
    #[error("authorization review expectation is unsupported")]
    UnsupportedExpectation,
    /// V1 implements only bodyless GET review.
    #[error("authorization review method is unsupported")]
    UnsupportedMethod,
    /// The exact selected resource was invalid or outside authority.
    #[error("authorization review resource is invalid or outside exact-origin authority")]
    InvalidResource,
    /// The opaque resource handle violated its bounded token contract.
    #[error("authorization review resource handle is invalid")]
    InvalidResourceHandle,
    /// The comparison path set violated V1's exact bounded profile contract.
    #[error("authorization review comparison profile is invalid")]
    InvalidComparisonProfile,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePolicy {
    schema: String,
    resource: String,
    resource_handle: String,
    expectation: String,
    method: String,
    comparison: WireComparison,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireComparison {
    selected_paths: Vec<String>,
    #[serde(default)]
    ignored_paths: Vec<String>,
    #[serde(default)]
    unordered_array_paths: Vec<String>,
    max_diff_paths: u16,
}

fn resolve_resource(
    authorized_origin: &Url,
    raw: &str,
) -> Result<Url, AuthorizationReviewPolicyError> {
    if raw.is_empty() || raw.len() > HARD_MAX_AUTHORIZATION_REVIEW_RESOURCE_BYTES {
        return Err(AuthorizationReviewPolicyError::InvalidResource);
    }
    let authority = HttpEvidencePolicy::for_origin(authorized_origin.clone())
        .map_err(|_| AuthorizationReviewPolicyError::InvalidResource)?;
    let mut origin_root = authorized_origin.clone();
    origin_root.set_path("/");
    origin_root.set_query(None);
    origin_root.set_fragment(None);
    let resource = match Url::parse(raw) {
        Ok(resource) => resource,
        Err(ParseError::RelativeUrlWithoutBase) => origin_root
            .join(raw)
            .map_err(|_| AuthorizationReviewPolicyError::InvalidResource)?,
        Err(_) => return Err(AuthorizationReviewPolicyError::InvalidResource),
    };
    if resource.fragment().is_some()
        || resource.path().is_empty()
        || resource.as_str().len() > HARD_MAX_AUTHORIZATION_REVIEW_RESOURCE_BYTES
    {
        return Err(AuthorizationReviewPolicyError::InvalidResource);
    }
    authority
        .require_permitted_target(&resource)
        .map_err(|_| AuthorizationReviewPolicyError::InvalidResource)?;
    Ok(resource)
}

fn validate_handle(value: &str) -> Result<(), AuthorizationReviewPolicyError> {
    if value.is_empty()
        || value.len() > HARD_MAX_AUTHORIZATION_REVIEW_HANDLE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(AuthorizationReviewPolicyError::InvalidResourceHandle);
    }
    Ok(())
}

fn build_comparison_profile(
    wire: WireComparison,
) -> Result<ApiComparisonProfile, AuthorizationReviewPolicyError> {
    if wire.selected_paths.is_empty()
        || wire.selected_paths.len() > HARD_MAX_AUTHORIZATION_REVIEW_SELECTED_PATHS
        || wire.ignored_paths.len() > HARD_MAX_AUTHORIZATION_REVIEW_IGNORED_PATHS
        || wire.unordered_array_paths.len() > HARD_MAX_AUTHORIZATION_REVIEW_UNORDERED_ARRAY_PATHS
        || wire.max_diff_paths == 0
        || wire.max_diff_paths > HARD_MAX_AUTHORIZATION_REVIEW_DIFF_PATHS
    {
        return Err(AuthorizationReviewPolicyError::InvalidComparisonProfile);
    }

    let selected = parse_exact_paths(wire.selected_paths, true)?;
    let ignored = parse_exact_paths(wire.ignored_paths, false)?;
    let unordered = parse_exact_paths(wire.unordered_array_paths, false)?;

    if has_redundant_subtrees(&selected)
        || has_redundant_subtrees(&ignored)
        || ignored.iter().any(|path| {
            !selected
                .iter()
                .any(|root| is_strict_descendant(root.as_str(), path.as_str()))
        })
        || unordered.iter().any(|path| {
            !selected
                .iter()
                .any(|root| is_within(root.as_str(), path.as_str()))
        })
        || unordered.iter().any(|path| {
            ignored
                .iter()
                .any(|ignored| is_within(ignored.as_str(), path.as_str()))
        })
    {
        return Err(AuthorizationReviewPolicyError::InvalidComparisonProfile);
    }

    ApiComparisonProfile::new(selected, ignored, unordered, wire.max_diff_paths)
        .map_err(|_| AuthorizationReviewPolicyError::InvalidComparisonProfile)
}

fn parse_exact_paths(
    values: Vec<String>,
    selected: bool,
) -> Result<Vec<JsonPathPattern>, AuthorizationReviewPolicyError> {
    let mut unique = BTreeSet::new();
    let mut parsed = Vec::with_capacity(values.len());
    for value in values {
        if value.len() > HARD_MAX_AUTHORIZATION_REVIEW_PATH_BYTES {
            return Err(AuthorizationReviewPolicyError::InvalidComparisonProfile);
        }
        let path = JsonPathPattern::new(value)
            .map_err(|_| AuthorizationReviewPolicyError::InvalidComparisonProfile)?;
        if path.as_str().len() > HARD_MAX_AUTHORIZATION_REVIEW_PATH_BYTES
            || (selected && path.as_str().is_empty())
            || path.as_str().split('/').any(|token| token == "*")
            || !unique.insert(path.as_str().to_owned())
        {
            return Err(AuthorizationReviewPolicyError::InvalidComparisonProfile);
        }
        parsed.push(path);
    }
    Ok(parsed)
}

fn is_within(root: &str, candidate: &str) -> bool {
    candidate == root
        || candidate
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn is_strict_descendant(root: &str, candidate: &str) -> bool {
    candidate != root && is_within(root, candidate)
}

fn has_redundant_subtrees(paths: &[JsonPathPattern]) -> bool {
    paths.iter().enumerate().any(|(index, left)| {
        paths.iter().skip(index + 1).any(|right| {
            is_within(left.as_str(), right.as_str()) || is_within(right.as_str(), left.as_str())
        })
    })
}

fn resource_scope_id(resource: &Url) -> AuthorizationResourceScopeId {
    AuthorizationResourceScopeId(domain_digest(
        RESOURCE_SCOPE_DOMAIN,
        resource.as_str().as_bytes(),
    ))
}

fn policy_id(
    resource: AuthorizationResourceScopeId,
    handle_digest: [u8; 32],
    expectation: AuthorizationReviewExpectation,
    method: AuthorizationReviewMethod,
    comparison: &ApiComparisonProfile,
) -> AuthorizationReviewPolicyId {
    let mut hasher = Sha256::new();
    hasher.update(POLICY_ID_DOMAIN);
    framed(&mut hasher, AUTHORIZATION_REVIEW_POLICY_SCHEMA.as_bytes());
    framed(
        &mut hasher,
        AUTHORIZATION_REVIEW_ALGORITHM_VERSION.as_bytes(),
    );
    framed(&mut hasher, &resource.as_bytes());
    framed(&mut hasher, &handle_digest);
    framed(&mut hasher, expectation.wire().as_bytes());
    framed(&mut hasher, method.wire().as_bytes());
    framed(&mut hasher, comparison.projection_policy_id().as_bytes());
    framed(
        &mut hasher,
        &u64::try_from(comparison.selected_paths().len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    framed(
        &mut hasher,
        &u64::try_from(comparison.ignored_paths().len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    framed(
        &mut hasher,
        &u64::try_from(comparison.unordered_arrays().len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    framed(&mut hasher, &comparison.max_diff_paths().to_be_bytes());
    AuthorizationReviewPolicyId(hasher.finalize().into())
}

fn domain_digest(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    framed(&mut hasher, value);
    hasher.finalize().into()
}

fn framed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

fn hex(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const QUERY_SECRET: &str = "RESOURCE-QUERY-MUST-NOT-LEAK-51A9BC";
    const HANDLE_SECRET: &str = "PRIVATE-RESOURCE-HANDLE-MUST-NOT-LEAK-346E2A";

    fn origin() -> Url {
        Url::parse("https://api.example.test/root").unwrap()
    }

    fn source(resource: &str, selected: &[&str], ignored: &[&str], unordered: &[&str]) -> String {
        format!(
            "schema = \"{AUTHORIZATION_REVIEW_POLICY_SCHEMA}\"\nresource = \"{resource}\"\nresource_handle = \"account-self-profile\"\nexpectation = \"primary-only\"\nmethod = \"GET\"\n[comparison]\nselected_paths = {selected:?}\nignored_paths = {ignored:?}\nunordered_array_paths = {unordered:?}\nmax_diff_paths = 32\n"
        )
    }

    fn source_owned(
        resource: &str,
        selected: &[String],
        ignored: &[String],
        unordered: &[String],
    ) -> String {
        format!(
            "schema = \"{AUTHORIZATION_REVIEW_POLICY_SCHEMA}\"\nresource = {resource:?}\nresource_handle = \"account-self-profile\"\nexpectation = \"primary-only\"\nmethod = \"GET\"\n[comparison]\nselected_paths = {selected:?}\nignored_paths = {ignored:?}\nunordered_array_paths = {unordered:?}\nmax_diff_paths = 32\n"
        )
    }

    fn policy(resource: &str) -> AuthorizationReviewPolicy {
        AuthorizationReviewPolicy::parse_toml(
            &origin(),
            source(
                resource,
                &["/data/account"],
                &["/data/account/updated_at"],
                &[],
            )
            .as_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn valid_policy_is_bounded_exact_origin_and_redacted() {
        let policy = policy(&format!("/api/accounts/42?opaque={QUERY_SECRET}"));
        assert_eq!(
            policy.expectation(),
            AuthorizationReviewExpectation::PrimaryOnly
        );
        assert_eq!(policy.method(), AuthorizationReviewMethod::Get);
        assert_eq!(policy.selected_path_count(), 1);
        assert_eq!(policy.ignored_path_count(), 1);
        assert_eq!(policy.unordered_array_path_count(), 0);
        assert_eq!(policy.policy_id().to_wire().len(), 92);
        let rendered = format!("{policy:?}");
        assert!(!rendered.contains(QUERY_SECRET));
        assert!(!rendered.contains("account-self-profile"));
        assert!(!rendered.contains("/data/account"));
    }

    #[test]
    fn relative_resource_is_resolved_from_the_exact_origin_root() {
        let nested = Url::parse("https://example.test/nested/base/?opaque=ignored").unwrap();
        let policy = AuthorizationReviewPolicy::parse_toml(
            &nested,
            source("api/accounts/42", &["/data/account"], &[], &[]).as_bytes(),
        )
        .unwrap();
        assert_eq!(
            policy.execution_resource().as_str(),
            "https://example.test/api/accounts/42"
        );
    }

    #[test]
    fn schema_unknown_fields_expectation_and_method_fail_closed() {
        let valid = source("/api/accounts/42", &["/data/account"], &[], &[]);
        for (needle, replacement, expected) in [
            (
                AUTHORIZATION_REVIEW_POLICY_SCHEMA,
                "security.authorization-review-policy/v2",
                AuthorizationReviewPolicyError::UnsupportedSchema,
            ),
            (
                "expectation = \"primary-only\"",
                "expectation = \"both-allowed\"",
                AuthorizationReviewPolicyError::UnsupportedExpectation,
            ),
            (
                "method = \"GET\"",
                "method = \"POST\"",
                AuthorizationReviewPolicyError::UnsupportedMethod,
            ),
        ] {
            let mutated = valid.replacen(needle, replacement, 1);
            assert_eq!(
                AuthorizationReviewPolicy::parse_toml(&origin(), mutated.as_bytes()).unwrap_err(),
                expected
            );
        }
        let unknown = format!("{valid}credential = \"secret\"\n");
        assert_eq!(
            AuthorizationReviewPolicy::parse_toml(&origin(), unknown.as_bytes()).unwrap_err(),
            AuthorizationReviewPolicyError::MalformedPolicy
        );
        for malformed in [b"not = [".as_slice(), &[0xff]] {
            assert_eq!(
                AuthorizationReviewPolicy::parse_toml(&origin(), malformed).unwrap_err(),
                AuthorizationReviewPolicyError::MalformedPolicy
            );
        }
    }

    #[test]
    fn policy_source_and_handle_limits_are_strict() {
        assert_eq!(
            AuthorizationReviewPolicy::parse_toml(
                &origin(),
                &vec![b'x'; HARD_MAX_AUTHORIZATION_REVIEW_POLICY_BYTES + 1]
            )
            .unwrap_err(),
            AuthorizationReviewPolicyError::PolicyTooLarge
        );
        let invalid_handle = source("/api/accounts/42", &["/data"], &[], &[])
            .replace("account-self-profile", "handle with spaces");
        assert_eq!(
            AuthorizationReviewPolicy::parse_toml(&origin(), invalid_handle.as_bytes())
                .unwrap_err(),
            AuthorizationReviewPolicyError::InvalidResourceHandle
        );
        for handle in [
            String::new(),
            "h".repeat(HARD_MAX_AUTHORIZATION_REVIEW_HANDLE_BYTES + 1),
        ] {
            let invalid = source("/api/accounts/42", &["/data"], &[], &[])
                .replace("account-self-profile", &handle);
            assert_eq!(
                AuthorizationReviewPolicy::parse_toml(&origin(), invalid.as_bytes()).unwrap_err(),
                AuthorizationReviewPolicyError::InvalidResourceHandle
            );
        }
        let maximum = source("/api/accounts/42", &["/data"], &[], &[]).replace(
            "account-self-profile",
            &"h".repeat(HARD_MAX_AUTHORIZATION_REVIEW_HANDLE_BYTES),
        );
        assert!(AuthorizationReviewPolicy::parse_toml(&origin(), maximum.as_bytes()).is_ok());
    }

    #[test]
    fn resource_binding_reuses_exact_origin_authority() {
        let relative = policy("/api/accounts/42");
        let absolute = policy("https://api.example.test:443/api/accounts/42");
        assert_eq!(relative.resource_scope_id(), absolute.resource_scope_id());

        for invalid in [
            "http://api.example.test/api/accounts/42",
            "https://other.example.test/api/accounts/42",
            "https://api.example.test:444/api/accounts/42",
            "https://user:secret@api.example.test/api/accounts/42",
            "/api/accounts/42#fragment",
            "ftp://api.example.test/api/accounts/42",
        ] {
            assert_eq!(
                AuthorizationReviewPolicy::parse_toml(
                    &origin(),
                    source(invalid, &["/data"], &[], &[]).as_bytes()
                )
                .unwrap_err(),
                AuthorizationReviewPolicyError::InvalidResource
            );
        }
        for invalid in [
            String::new(),
            format!(
                "/{}",
                "a".repeat(HARD_MAX_AUTHORIZATION_REVIEW_RESOURCE_BYTES)
            ),
        ] {
            assert_eq!(
                AuthorizationReviewPolicy::parse_toml(
                    &origin(),
                    source_owned(&invalid, &["/data".to_owned()], &[], &[]).as_bytes(),
                )
                .unwrap_err(),
                AuthorizationReviewPolicyError::InvalidResource
            );
        }
        assert!(AuthorizationReviewPolicy::parse_toml(
            &origin(),
            source("/", &["/data/account"], &[], &[]).as_bytes(),
        )
        .is_ok());
    }

    #[test]
    fn exact_selected_paths_and_nested_rules_are_enforced() {
        let invalid_profiles = [
            source("/api/x", &[], &[], &[]),
            source("/api/x", &[""], &[], &[]),
            source("/api/x", &["/data/*"], &[], &[]),
            source("/api/x", &["/data/~2bad"], &[], &[]),
            source("/api/x", &["/data", "/data"], &[], &[]),
            source("/api/x", &["/data", "/data/account"], &[], &[]),
            source("/api/x", &["/data"], &["/outside"], &[]),
            source("/api/x", &["/data"], &["/data"], &[]),
            source(
                "/api/x",
                &["/data"],
                &["/data/account", "/data/account/name"],
                &[],
            ),
            source("/api/x", &["/data"], &[], &["/outside"]),
            source("/api/x", &["/data"], &[], &["/data/*"]),
            source(
                "/api/x",
                &["/data"],
                &["/data/account"],
                &["/data/account/roles"],
            ),
        ];
        for invalid in invalid_profiles {
            assert_eq!(
                AuthorizationReviewPolicy::parse_toml(&origin(), invalid.as_bytes()).unwrap_err(),
                AuthorizationReviewPolicyError::InvalidComparisonProfile
            );
        }
    }

    #[test]
    fn zero_and_over_limit_diff_paths_are_rejected() {
        let valid = source("/api/x", &["/data"], &[], &[]);
        for invalid in [
            valid.replace("max_diff_paths = 32", "max_diff_paths = 0"),
            valid.replace("max_diff_paths = 32", "max_diff_paths = 33"),
        ] {
            assert_eq!(
                AuthorizationReviewPolicy::parse_toml(&origin(), invalid.as_bytes()).unwrap_err(),
                AuthorizationReviewPolicyError::InvalidComparisonProfile
            );
        }
    }

    #[test]
    fn comparison_count_and_path_byte_ceilings_are_enforced() {
        let selected = (0..=HARD_MAX_AUTHORIZATION_REVIEW_SELECTED_PATHS)
            .map(|index| format!("/selected/{index}"))
            .collect::<Vec<_>>();
        let ignored = (0..=HARD_MAX_AUTHORIZATION_REVIEW_IGNORED_PATHS)
            .map(|index| format!("/data/ignored-{index}"))
            .collect::<Vec<_>>();
        let unordered = (0..=HARD_MAX_AUTHORIZATION_REVIEW_UNORDERED_ARRAY_PATHS)
            .map(|index| format!("/data/array-{index}"))
            .collect::<Vec<_>>();
        let overlong = format!("/{}", "p".repeat(HARD_MAX_AUTHORIZATION_REVIEW_PATH_BYTES));
        let canonical_overlong = format!("/{}", "~".repeat(128));
        for invalid in [
            source_owned("/api/x", &selected, &[], &[]),
            source_owned("/api/x", &["/data".to_owned()], &ignored, &[]),
            source_owned("/api/x", &["/data".to_owned()], &[], &unordered),
            source_owned("/api/x", &[overlong], &[], &[]),
            source_owned("/api/x", &[canonical_overlong], &[], &[]),
        ] {
            assert_eq!(
                AuthorizationReviewPolicy::parse_toml(&origin(), invalid.as_bytes()).unwrap_err(),
                AuthorizationReviewPolicyError::InvalidComparisonProfile
            );
        }
    }

    #[test]
    fn canonical_execution_resource_is_retained_without_debug_disclosure() {
        let policy = policy("/api/../accounts/42?mode=review");
        assert_eq!(
            policy.execution_resource().as_str(),
            "https://api.example.test/accounts/42?mode=review"
        );
        assert!(!format!("{policy:?}").contains("mode=review"));
    }

    #[test]
    fn semantic_policy_identity_is_order_independent_and_materially_bound() {
        let first = AuthorizationReviewPolicy::parse_toml(
            &origin(),
            source(
                "/api/accounts/42",
                &["/data/account", "/meta/owner"],
                &["/data/account/updated_at", "/meta/owner/seen_at"],
                &[],
            )
            .as_bytes(),
        )
        .unwrap();
        let reordered = AuthorizationReviewPolicy::parse_toml(
            &origin(),
            source(
                "/api/accounts/42",
                &["/meta/owner", "/data/account"],
                &["/meta/owner/seen_at", "/data/account/updated_at"],
                &[],
            )
            .as_bytes(),
        )
        .unwrap();
        assert_eq!(first.policy_id(), reordered.policy_id());
        assert_ne!(first.policy_id(), policy("/api/accounts/43").policy_id());

        let changed_profile = AuthorizationReviewPolicy::parse_toml(
            &origin(),
            source("/api/accounts/42", &["/data/other"], &[], &[]).as_bytes(),
        )
        .unwrap();
        assert_ne!(first.policy_id(), changed_profile.policy_id());
    }

    #[test]
    fn query_and_handle_material_change_identity_without_cleartext_output() {
        let first = policy(&format!("/api/accounts/42?q={QUERY_SECRET}"));
        let second = policy("/api/accounts/42?q=other");
        assert_ne!(first.resource_scope_id(), second.resource_scope_id());
        assert_ne!(first.policy_id(), second.policy_id());

        let source_with_private_handle = source("/api/accounts/42", &["/data"], &[], &[])
            .replace("account-self-profile", HANDLE_SECRET);
        let handle_policy =
            AuthorizationReviewPolicy::parse_toml(&origin(), source_with_private_handle.as_bytes())
                .unwrap();
        let ordinary_handle = AuthorizationReviewPolicy::parse_toml(
            &origin(),
            source("/api/accounts/42", &["/data"], &[], &[]).as_bytes(),
        )
        .unwrap();
        assert_ne!(handle_policy.policy_id(), ordinary_handle.policy_id());
        for rendered in [
            format!("{handle_policy:?}"),
            handle_policy.policy_id().to_string(),
            handle_policy.resource_scope_id().to_string(),
        ] {
            assert!(!rendered.contains(QUERY_SECRET));
            assert!(!rendered.contains(HANDLE_SECRET));
        }
    }
}
