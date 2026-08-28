//! Bounded, value-free projection of passive HTTP response metadata.
//!
//! Raw header values remain borrowed inside this module. The projection keeps
//! only fixed-vocabulary facts plus bounded cookie names; it never retains a
//! cookie value, CSP source expression, Permissions-Policy origin, or raw
//! cookie Domain/Path value. Limit exhaustion is explicit and cannot be
//! mistaken for a missing header.

use std::{collections::BTreeSet, fmt};

use reqwest::header::{HeaderMap, HeaderValue};

pub(crate) const MAX_PASSIVE_HEADER_OCCURRENCES: usize = 8;
pub(crate) const MAX_PASSIVE_HEADER_VALUE_BYTES: usize = 8 * 1024;
pub(crate) const MAX_PASSIVE_CSP_POLICIES: usize = 16;
pub(crate) const MAX_PASSIVE_CSP_DIRECTIVES: usize = 64;
pub(crate) const MAX_PASSIVE_PERMISSIONS_POLICY_DIRECTIVES: usize = 64;
pub(crate) const MAX_PASSIVE_PERMISSIONS_POLICY_MEMBERS: usize = 64;
pub(crate) const MAX_PASSIVE_SET_COOKIE_OCCURRENCES: usize = 16;
pub(crate) const MAX_PASSIVE_SET_COOKIE_VALUE_BYTES: usize = 8 * 1024;
pub(crate) const MAX_PASSIVE_COOKIE_PAIR_BYTES: usize = 4 * 1024;
pub(crate) const MAX_PASSIVE_COOKIE_NAME_BYTES: usize = 256;
pub(crate) const MAX_PASSIVE_COOKIE_ATTRIBUTES: usize = 32;
pub(crate) const MAX_PASSIVE_COOKIE_SCOPE_VALUE_BYTES: usize = 1024;
pub(crate) const MAX_PASSIVE_DERIVED_OBSERVATIONS: usize = 160;

const HSTS: &str = "strict-transport-security";
const CSP: &str = "content-security-policy";
const XCTO: &str = "x-content-type-options";
const REFERRER_POLICY: &str = "referrer-policy";
const PERMISSIONS_POLICY: &str = "permissions-policy";
const SET_COOKIE: &str = "set-cookie";

/// Stable state of one bounded passive projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PassiveProjectionState {
    Missing,
    Parsed,
    Nonconformant,
    Malformed,
    ProjectionIncomplete,
}

/// Fixed, value-free reason why a bounded projection could not finish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PassiveProjectionIncompleteReason {
    TooManyHeaderOccurrences,
    OversizedHeaderValue,
    TooManyCspPolicies,
    TooManyCspDirectives,
    TooManyPermissionsPolicyDirectives,
    TooManyPermissionsPolicyMembers,
    TooManySetCookieOccurrences,
    OversizedSetCookieValue,
    OversizedCookiePair,
    OversizedCookieName,
    TooManyCookieAttributes,
    OversizedCookieScopeValue,
    TooManyDerivedObservations,
}

/// One typed passive projection and optional value-free metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PassiveFieldProjection<T> {
    state: PassiveProjectionState,
    metadata: Option<T>,
    incomplete_reason: Option<PassiveProjectionIncompleteReason>,
}

impl<T> PassiveFieldProjection<T> {
    pub(crate) const fn state(&self) -> PassiveProjectionState {
        self.state
    }

    pub(crate) const fn metadata(&self) -> Option<&T> {
        self.metadata.as_ref()
    }

    pub(crate) const fn incomplete_reason(&self) -> Option<PassiveProjectionIncompleteReason> {
        self.incomplete_reason
    }

    const fn missing() -> Self {
        Self {
            state: PassiveProjectionState::Missing,
            metadata: None,
            incomplete_reason: None,
        }
    }

    const fn parsed(metadata: T) -> Self {
        Self {
            state: PassiveProjectionState::Parsed,
            metadata: Some(metadata),
            incomplete_reason: None,
        }
    }

    const fn nonconformant(metadata: Option<T>) -> Self {
        Self {
            state: PassiveProjectionState::Nonconformant,
            metadata,
            incomplete_reason: None,
        }
    }

    const fn malformed() -> Self {
        Self {
            state: PassiveProjectionState::Malformed,
            metadata: None,
            incomplete_reason: None,
        }
    }

    const fn incomplete(reason: PassiveProjectionIncompleteReason) -> Self {
        Self {
            state: PassiveProjectionState::ProjectionIncomplete,
            metadata: None,
            incomplete_reason: Some(reason),
        }
    }
}

/// Parsed Strict-Transport-Security facts without retaining its raw value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StrictTransportSecurityMetadata {
    max_age_seconds: u64,
    includes_subdomains: bool,
    requests_preload: bool,
    has_unrecognized_directive: bool,
}

impl StrictTransportSecurityMetadata {
    pub(crate) const fn max_age_seconds(&self) -> u64 {
        self.max_age_seconds
    }

    pub(crate) const fn includes_subdomains(&self) -> bool {
        self.includes_subdomains
    }

    pub(crate) const fn requests_preload(&self) -> bool {
        self.requests_preload
    }

    pub(crate) const fn has_unrecognized_directive(&self) -> bool {
        self.has_unrecognized_directive
    }
}

/// Fixed CSP characteristics. Source expressions themselves are discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ContentSecurityPolicyMetadata {
    policy_count: u8,
    directive_count: u8,
    has_default_src: bool,
    has_script_src: bool,
    has_object_src: bool,
    has_object_src_none: bool,
    has_base_uri: bool,
    has_base_uri_none: bool,
    has_frame_ancestors: bool,
    declares_unsafe_inline: bool,
    declares_unsafe_eval: bool,
    declares_nonce: bool,
    declares_hash: bool,
}

impl ContentSecurityPolicyMetadata {
    pub(crate) const fn policy_count(&self) -> u8 {
        self.policy_count
    }

    pub(crate) const fn directive_count(&self) -> u8 {
        self.directive_count
    }

    pub(crate) const fn has_default_src(&self) -> bool {
        self.has_default_src
    }

    pub(crate) const fn has_script_src(&self) -> bool {
        self.has_script_src
    }

    pub(crate) const fn has_object_src(&self) -> bool {
        self.has_object_src
    }

    pub(crate) const fn has_object_src_none(&self) -> bool {
        self.has_object_src_none
    }

    pub(crate) const fn has_base_uri(&self) -> bool {
        self.has_base_uri
    }

    pub(crate) const fn has_base_uri_none(&self) -> bool {
        self.has_base_uri_none
    }

    pub(crate) const fn has_frame_ancestors(&self) -> bool {
        self.has_frame_ancestors
    }

    pub(crate) const fn declares_unsafe_inline(&self) -> bool {
        self.declares_unsafe_inline
    }

    pub(crate) const fn declares_unsafe_eval(&self) -> bool {
        self.declares_unsafe_eval
    }

    pub(crate) const fn declares_nonce(&self) -> bool {
        self.declares_nonce
    }

    pub(crate) const fn declares_hash(&self) -> bool {
        self.declares_hash
    }
}

/// Parsed X-Content-Type-Options facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct XContentTypeOptionsMetadata {
    nosniff: bool,
}

impl XContentTypeOptionsMetadata {
    pub(crate) const fn nosniff(&self) -> bool {
        self.nosniff
    }
}

/// Fixed Referrer-Policy vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReferrerPolicyValue {
    NoReferrer,
    NoReferrerWhenDowngrade,
    Origin,
    OriginWhenCrossOrigin,
    SameOrigin,
    StrictOrigin,
    StrictOriginWhenCrossOrigin,
    UnsafeUrl,
}

/// Effective fixed Referrer-Policy facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReferrerPolicyMetadata {
    effective_policy: Option<ReferrerPolicyValue>,
    declared_policy_count: u16,
}

impl ReferrerPolicyMetadata {
    pub(crate) const fn effective_policy(&self) -> Option<ReferrerPolicyValue> {
        self.effective_policy
    }

    pub(crate) const fn declared_policy_count(&self) -> u16 {
        self.declared_policy_count
    }
}

/// Permissions-Policy shape without feature names or allowlist values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PermissionsPolicyMetadata {
    directive_count: u8,
    member_count: u8,
    empty_allowlist_directives: u8,
    wildcard_members: u8,
    self_members: u8,
    src_members: u8,
    explicit_members: u8,
    duplicate_feature_directives: bool,
}

impl PermissionsPolicyMetadata {
    pub(crate) const fn directive_count(&self) -> u8 {
        self.directive_count
    }

    pub(crate) const fn member_count(&self) -> u8 {
        self.member_count
    }

    pub(crate) const fn empty_allowlist_directives(&self) -> u8 {
        self.empty_allowlist_directives
    }

    pub(crate) const fn wildcard_members(&self) -> u8 {
        self.wildcard_members
    }

    pub(crate) const fn self_members(&self) -> u8 {
        self.self_members
    }

    pub(crate) const fn src_members(&self) -> u8 {
        self.src_members
    }

    pub(crate) const fn explicit_members(&self) -> u8 {
        self.explicit_members
    }

    pub(crate) const fn duplicate_feature_directives(&self) -> bool {
        self.duplicate_feature_directives
    }
}

/// Fixed SameSite vocabulary. No cookie value is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PassiveCookieSameSite {
    Missing,
    Strict,
    Lax,
    None,
}

/// Value-free metadata for one bounded Set-Cookie occurrence.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PassiveCookieMetadata {
    name: String,
    secure: bool,
    http_only: bool,
    same_site: PassiveCookieSameSite,
    domain_attribute_present: bool,
    path_attribute_present: bool,
}

impl fmt::Debug for PassiveCookieMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PassiveCookieMetadata")
            .field("name", &"<redacted>")
            .field("secure", &self.secure)
            .field("http_only", &self.http_only)
            .field("same_site", &self.same_site)
            .field("domain_attribute_present", &self.domain_attribute_present)
            .field("path_attribute_present", &self.path_attribute_present)
            .finish()
    }
}

impl PassiveCookieMetadata {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) const fn secure(&self) -> bool {
        self.secure
    }

    pub(crate) const fn http_only(&self) -> bool {
        self.http_only
    }

    pub(crate) const fn same_site(&self) -> PassiveCookieSameSite {
        self.same_site
    }

    pub(crate) const fn domain_attribute_present(&self) -> bool {
        self.domain_attribute_present
    }

    pub(crate) const fn path_attribute_present(&self) -> bool {
        self.path_attribute_present
    }
}

/// Complete bounded passive metadata projection for one response.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PassiveResponseProjection {
    strict_transport_security: PassiveFieldProjection<StrictTransportSecurityMetadata>,
    content_security_policy: PassiveFieldProjection<ContentSecurityPolicyMetadata>,
    x_content_type_options: PassiveFieldProjection<XContentTypeOptionsMetadata>,
    referrer_policy: PassiveFieldProjection<ReferrerPolicyMetadata>,
    permissions_policy: PassiveFieldProjection<PermissionsPolicyMetadata>,
    cookies: PassiveFieldProjection<Vec<PassiveCookieMetadata>>,
    derived_observation_count: u16,
}

impl fmt::Debug for PassiveResponseProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PassiveResponseProjection")
            .field(
                "strict_transport_security_state",
                &self.strict_transport_security.state,
            )
            .field(
                "content_security_policy_state",
                &self.content_security_policy.state,
            )
            .field(
                "x_content_type_options_state",
                &self.x_content_type_options.state,
            )
            .field("referrer_policy_state", &self.referrer_policy.state)
            .field("permissions_policy_state", &self.permissions_policy.state)
            .field("cookie_state", &self.cookies.state)
            .field(
                "cookie_count",
                &self.cookies.metadata.as_ref().map_or(0, Vec::len),
            )
            .field("derived_observation_count", &self.derived_observation_count)
            .finish()
    }
}

impl PassiveResponseProjection {
    pub(crate) const fn strict_transport_security(
        &self,
    ) -> &PassiveFieldProjection<StrictTransportSecurityMetadata> {
        &self.strict_transport_security
    }

    pub(crate) const fn content_security_policy(
        &self,
    ) -> &PassiveFieldProjection<ContentSecurityPolicyMetadata> {
        &self.content_security_policy
    }

    pub(crate) const fn x_content_type_options(
        &self,
    ) -> &PassiveFieldProjection<XContentTypeOptionsMetadata> {
        &self.x_content_type_options
    }

    pub(crate) const fn referrer_policy(&self) -> &PassiveFieldProjection<ReferrerPolicyMetadata> {
        &self.referrer_policy
    }

    pub(crate) const fn permissions_policy(
        &self,
    ) -> &PassiveFieldProjection<PermissionsPolicyMetadata> {
        &self.permissions_policy
    }

    pub(crate) const fn cookies(&self) -> &PassiveFieldProjection<Vec<PassiveCookieMetadata>> {
        &self.cookies
    }

    pub(crate) const fn derived_observation_count(&self) -> u16 {
        self.derived_observation_count
    }

    fn all_incomplete(reason: PassiveProjectionIncompleteReason) -> Self {
        Self {
            strict_transport_security: PassiveFieldProjection::incomplete(reason),
            content_security_policy: PassiveFieldProjection::incomplete(reason),
            x_content_type_options: PassiveFieldProjection::incomplete(reason),
            referrer_policy: PassiveFieldProjection::incomplete(reason),
            permissions_policy: PassiveFieldProjection::incomplete(reason),
            cookies: PassiveFieldProjection::incomplete(reason),
            // The evidence schema always emits one state record for each of
            // the six passive fields, including when the aggregate projection
            // itself reached a hard ceiling.
            derived_observation_count: 6,
        }
    }
}

/// Projects a raw response header map into bounded, value-free passive facts.
pub(crate) fn project_passive_response(headers: &HeaderMap) -> PassiveResponseProjection {
    let mut projection = PassiveResponseProjection {
        strict_transport_security: project_hsts(headers),
        content_security_policy: project_csp(headers),
        x_content_type_options: project_xcto(headers),
        referrer_policy: project_referrer_policy(headers),
        permissions_policy: project_permissions_policy(headers),
        cookies: project_cookies(headers),
        derived_observation_count: 0,
    };
    let count = derived_observation_count(&projection);
    let Ok(count) = enforce_derived_observation_limit(count) else {
        return PassiveResponseProjection::all_incomplete(
            PassiveProjectionIncompleteReason::TooManyDerivedObservations,
        );
    };
    projection.derived_observation_count = count;
    projection
}

fn project_hsts(headers: &HeaderMap) -> PassiveFieldProjection<StrictTransportSecurityMetadata> {
    let values = match bounded_values(
        headers,
        HSTS,
        MAX_PASSIVE_HEADER_OCCURRENCES,
        MAX_PASSIVE_HEADER_VALUE_BYTES,
    ) {
        Ok(values) => values,
        Err(reason) => return PassiveFieldProjection::incomplete(reason),
    };
    if values.is_empty() {
        return PassiveFieldProjection::missing();
    }

    let mut nonconformant = values.len() != 1;
    let value = match values[0].to_str() {
        Ok(value) => value,
        Err(_) => return PassiveFieldProjection::malformed(),
    };
    let mut max_age = None;
    let mut includes_subdomains = false;
    let mut requests_preload = false;
    let mut has_unrecognized_directive = false;
    let mut saw_directive = false;
    let mut seen_names = BTreeSet::new();

    for directive in value
        .split(';')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        saw_directive = true;
        let (name, raw_value) = match directive.split_once('=') {
            Some((name, raw_value)) => (name.trim(), Some(raw_value.trim())),
            None => (directive, None),
        };
        if !valid_token(name) {
            return PassiveFieldProjection::malformed();
        }
        let canonical = name.to_ascii_lowercase();
        if !seen_names.insert(canonical.clone()) {
            nonconformant = true;
        }
        match canonical.as_str() {
            "max-age" => {
                let Some(raw_value) = raw_value else {
                    return PassiveFieldProjection::malformed();
                };
                let digits = unquote_ascii(raw_value);
                if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                    return PassiveFieldProjection::malformed();
                }
                let Ok(seconds) = digits.parse::<u64>() else {
                    return PassiveFieldProjection::malformed();
                };
                max_age = Some(seconds);
            },
            "includesubdomains" => {
                if raw_value.is_some() {
                    nonconformant = true;
                }
                includes_subdomains = true;
            },
            "preload" => {
                if raw_value.is_some() {
                    nonconformant = true;
                }
                requests_preload = true;
            },
            _ => {
                has_unrecognized_directive = true;
                if raw_value.is_some_and(|item| !valid_directive_value(item)) {
                    return PassiveFieldProjection::malformed();
                }
            },
        }
    }
    if !saw_directive {
        return PassiveFieldProjection::malformed();
    }
    let Some(max_age_seconds) = max_age else {
        return PassiveFieldProjection::nonconformant(None);
    };
    let metadata = StrictTransportSecurityMetadata {
        max_age_seconds,
        includes_subdomains,
        requests_preload,
        has_unrecognized_directive,
    };
    if nonconformant {
        PassiveFieldProjection::nonconformant(Some(metadata))
    } else {
        PassiveFieldProjection::parsed(metadata)
    }
}

fn project_csp(headers: &HeaderMap) -> PassiveFieldProjection<ContentSecurityPolicyMetadata> {
    let values = match bounded_values(
        headers,
        CSP,
        MAX_PASSIVE_HEADER_OCCURRENCES,
        MAX_PASSIVE_HEADER_VALUE_BYTES,
    ) {
        Ok(values) => values,
        Err(reason) => return PassiveFieldProjection::incomplete(reason),
    };
    if values.is_empty() {
        return PassiveFieldProjection::missing();
    }

    let mut metadata = ContentSecurityPolicyMetadata {
        policy_count: 0,
        directive_count: 0,
        has_default_src: false,
        has_script_src: false,
        has_object_src: false,
        has_object_src_none: false,
        has_base_uri: false,
        has_base_uri_none: false,
        has_frame_ancestors: false,
        declares_unsafe_inline: false,
        declares_unsafe_eval: false,
        declares_nonce: false,
        declares_hash: false,
    };
    let mut nonconformant = false;
    let mut saw_policy = false;

    for value in values {
        let value = match value.to_str() {
            Ok(value) => value,
            Err(_) => return PassiveFieldProjection::malformed(),
        };
        for policy in value.split(',') {
            let policy = policy.trim();
            if policy.is_empty() {
                return PassiveFieldProjection::malformed();
            }
            saw_policy = true;
            let next_policy_count = usize::from(metadata.policy_count) + 1;
            if next_policy_count > MAX_PASSIVE_CSP_POLICIES {
                return PassiveFieldProjection::incomplete(
                    PassiveProjectionIncompleteReason::TooManyCspPolicies,
                );
            }
            metadata.policy_count = u8::try_from(next_policy_count).unwrap_or(u8::MAX);
            let mut seen_directives = BTreeSet::new();
            let mut saw_directive = false;
            for directive in policy
                .split(';')
                .map(str::trim)
                .filter(|item| !item.is_empty())
            {
                saw_directive = true;
                let next_directive_count = usize::from(metadata.directive_count) + 1;
                if next_directive_count > MAX_PASSIVE_CSP_DIRECTIVES {
                    return PassiveFieldProjection::incomplete(
                        PassiveProjectionIncompleteReason::TooManyCspDirectives,
                    );
                }
                metadata.directive_count = u8::try_from(next_directive_count).unwrap_or(u8::MAX);
                let mut tokens = directive.split_ascii_whitespace();
                let Some(name) = tokens.next() else {
                    return PassiveFieldProjection::malformed();
                };
                if !valid_token(name) {
                    return PassiveFieldProjection::malformed();
                }
                let canonical = name.to_ascii_lowercase();
                if !seen_directives.insert(canonical.clone()) {
                    nonconformant = true;
                }
                let sources: Vec<_> = tokens.collect();
                let has_none = sources
                    .iter()
                    .any(|source| source.eq_ignore_ascii_case("'none'"));
                if has_none && sources.len() != 1 {
                    nonconformant = true;
                }
                match canonical.as_str() {
                    "default-src" => {
                        metadata.has_default_src = true;
                        project_script_sources(&sources, &mut metadata);
                    },
                    "script-src" | "script-src-elem" | "script-src-attr" => {
                        if canonical == "script-src" {
                            metadata.has_script_src = true;
                        }
                        project_script_sources(&sources, &mut metadata);
                    },
                    "object-src" => {
                        metadata.has_object_src = true;
                        metadata.has_object_src_none |= has_none;
                    },
                    "base-uri" => {
                        metadata.has_base_uri = true;
                        metadata.has_base_uri_none |= has_none;
                    },
                    "frame-ancestors" => metadata.has_frame_ancestors = true,
                    _ => {},
                }
            }
            if !saw_directive {
                return PassiveFieldProjection::malformed();
            }
        }
    }
    if !saw_policy {
        return PassiveFieldProjection::malformed();
    }
    if nonconformant {
        PassiveFieldProjection::nonconformant(Some(metadata))
    } else {
        PassiveFieldProjection::parsed(metadata)
    }
}

fn project_script_sources(sources: &[&str], metadata: &mut ContentSecurityPolicyMetadata) {
    for source in sources {
        metadata.declares_unsafe_inline |= source.eq_ignore_ascii_case("'unsafe-inline'");
        metadata.declares_unsafe_eval |= source.eq_ignore_ascii_case("'unsafe-eval'");
        let lower = source.to_ascii_lowercase();
        metadata.declares_nonce |= lower.starts_with("'nonce-") && lower.ends_with('\'');
        metadata.declares_hash |= ["'sha256-", "'sha384-", "'sha512-"]
            .iter()
            .any(|prefix| lower.starts_with(prefix) && lower.ends_with('\''));
    }
}

fn project_xcto(headers: &HeaderMap) -> PassiveFieldProjection<XContentTypeOptionsMetadata> {
    let values = match bounded_values(
        headers,
        XCTO,
        MAX_PASSIVE_HEADER_OCCURRENCES,
        MAX_PASSIVE_HEADER_VALUE_BYTES,
    ) {
        Ok(values) => values,
        Err(reason) => return PassiveFieldProjection::incomplete(reason),
    };
    if values.is_empty() {
        return PassiveFieldProjection::missing();
    }
    let mut all_nosniff = true;
    for value in &values {
        let Ok(value) = value.to_str() else {
            return PassiveFieldProjection::malformed();
        };
        let value = value.trim();
        if !valid_token(value) {
            return PassiveFieldProjection::malformed();
        }
        all_nosniff &= value.eq_ignore_ascii_case("nosniff");
    }
    let metadata = XContentTypeOptionsMetadata {
        nosniff: all_nosniff,
    };
    if values.len() == 1 && all_nosniff {
        PassiveFieldProjection::parsed(metadata)
    } else {
        PassiveFieldProjection::nonconformant(Some(metadata))
    }
}

fn project_referrer_policy(headers: &HeaderMap) -> PassiveFieldProjection<ReferrerPolicyMetadata> {
    let values = match bounded_values(
        headers,
        REFERRER_POLICY,
        MAX_PASSIVE_HEADER_OCCURRENCES,
        MAX_PASSIVE_HEADER_VALUE_BYTES,
    ) {
        Ok(values) => values,
        Err(reason) => return PassiveFieldProjection::incomplete(reason),
    };
    if values.is_empty() {
        return PassiveFieldProjection::missing();
    }
    let mut effective_policy = None;
    let mut declared_policy_count = 0usize;
    let mut nonconformant = false;
    for value in values {
        let value = match value.to_str() {
            Ok(value) => value,
            Err(_) => return PassiveFieldProjection::malformed(),
        };
        for token in value.split(',') {
            let token = token.trim();
            if token.is_empty() || !valid_token(token) {
                return PassiveFieldProjection::malformed();
            }
            declared_policy_count = declared_policy_count.saturating_add(1);
            if declared_policy_count > MAX_PASSIVE_DERIVED_OBSERVATIONS {
                return PassiveFieldProjection::incomplete(
                    PassiveProjectionIncompleteReason::TooManyDerivedObservations,
                );
            }
            match parse_referrer_policy(token) {
                Some(policy) => effective_policy = Some(policy),
                None => nonconformant = true,
            }
        }
    }
    let metadata = ReferrerPolicyMetadata {
        effective_policy,
        declared_policy_count: u16::try_from(declared_policy_count).unwrap_or(u16::MAX),
    };
    if nonconformant || effective_policy.is_none() {
        PassiveFieldProjection::nonconformant(Some(metadata))
    } else {
        PassiveFieldProjection::parsed(metadata)
    }
}

fn parse_referrer_policy(value: &str) -> Option<ReferrerPolicyValue> {
    if value.eq_ignore_ascii_case("no-referrer") {
        Some(ReferrerPolicyValue::NoReferrer)
    } else if value.eq_ignore_ascii_case("no-referrer-when-downgrade") {
        Some(ReferrerPolicyValue::NoReferrerWhenDowngrade)
    } else if value.eq_ignore_ascii_case("origin") {
        Some(ReferrerPolicyValue::Origin)
    } else if value.eq_ignore_ascii_case("origin-when-cross-origin") {
        Some(ReferrerPolicyValue::OriginWhenCrossOrigin)
    } else if value.eq_ignore_ascii_case("same-origin") {
        Some(ReferrerPolicyValue::SameOrigin)
    } else if value.eq_ignore_ascii_case("strict-origin") {
        Some(ReferrerPolicyValue::StrictOrigin)
    } else if value.eq_ignore_ascii_case("strict-origin-when-cross-origin") {
        Some(ReferrerPolicyValue::StrictOriginWhenCrossOrigin)
    } else if value.eq_ignore_ascii_case("unsafe-url") {
        Some(ReferrerPolicyValue::UnsafeUrl)
    } else {
        None
    }
}

fn project_permissions_policy(
    headers: &HeaderMap,
) -> PassiveFieldProjection<PermissionsPolicyMetadata> {
    let values = match bounded_values(
        headers,
        PERMISSIONS_POLICY,
        MAX_PASSIVE_HEADER_OCCURRENCES,
        MAX_PASSIVE_HEADER_VALUE_BYTES,
    ) {
        Ok(values) => values,
        Err(reason) => return PassiveFieldProjection::incomplete(reason),
    };
    if values.is_empty() {
        return PassiveFieldProjection::missing();
    }
    let mut metadata = PermissionsPolicyMetadata {
        directive_count: 0,
        member_count: 0,
        empty_allowlist_directives: 0,
        wildcard_members: 0,
        self_members: 0,
        src_members: 0,
        explicit_members: 0,
        duplicate_feature_directives: false,
    };
    let mut nonconformant = false;
    let mut seen_features = BTreeSet::new();
    for value in values {
        let value = match value.to_str() {
            Ok(value) => value,
            Err(_) => return PassiveFieldProjection::malformed(),
        };
        let directives = match split_permissions_directives(value) {
            Ok(directives) => directives,
            Err(()) => return PassiveFieldProjection::malformed(),
        };
        for directive in directives {
            let next_directive_count = usize::from(metadata.directive_count) + 1;
            if next_directive_count > MAX_PASSIVE_PERMISSIONS_POLICY_DIRECTIVES {
                return PassiveFieldProjection::incomplete(
                    PassiveProjectionIncompleteReason::TooManyPermissionsPolicyDirectives,
                );
            }
            metadata.directive_count = u8::try_from(next_directive_count).unwrap_or(u8::MAX);
            let Some((feature, allowlist)) = directive.split_once('=') else {
                return PassiveFieldProjection::malformed();
            };
            let feature = feature.trim();
            if !valid_token(feature) {
                return PassiveFieldProjection::malformed();
            }
            if !seen_features.insert(feature.to_ascii_lowercase()) {
                metadata.duplicate_feature_directives = true;
                nonconformant = true;
            }
            let allowlist = allowlist.trim();
            if allowlist == "*" {
                if increment_permissions_member_count(&mut metadata).is_err() {
                    return PassiveFieldProjection::incomplete(
                        PassiveProjectionIncompleteReason::TooManyPermissionsPolicyMembers,
                    );
                }
                metadata.wildcard_members = metadata.wildcard_members.saturating_add(1);
                continue;
            }
            let Some(inner) = allowlist
                .strip_prefix('(')
                .and_then(|value| value.strip_suffix(')'))
            else {
                return PassiveFieldProjection::malformed();
            };
            let members = match split_permissions_members(inner) {
                Ok(members) => members,
                Err(()) => return PassiveFieldProjection::malformed(),
            };
            if members.is_empty() {
                metadata.empty_allowlist_directives =
                    metadata.empty_allowlist_directives.saturating_add(1);
            }
            for member in members {
                if increment_permissions_member_count(&mut metadata).is_err() {
                    return PassiveFieldProjection::incomplete(
                        PassiveProjectionIncompleteReason::TooManyPermissionsPolicyMembers,
                    );
                }
                if member == "*" {
                    metadata.wildcard_members = metadata.wildcard_members.saturating_add(1);
                } else if member.eq_ignore_ascii_case("self") {
                    metadata.self_members = metadata.self_members.saturating_add(1);
                } else if member.eq_ignore_ascii_case("src") {
                    metadata.src_members = metadata.src_members.saturating_add(1);
                } else if member.starts_with('"') && member.ends_with('"') && member.len() >= 2 {
                    metadata.explicit_members = metadata.explicit_members.saturating_add(1);
                } else if valid_token(member) {
                    metadata.explicit_members = metadata.explicit_members.saturating_add(1);
                    nonconformant = true;
                } else {
                    return PassiveFieldProjection::malformed();
                }
            }
        }
    }
    if metadata.directive_count == 0 {
        return PassiveFieldProjection::malformed();
    }
    if nonconformant {
        PassiveFieldProjection::nonconformant(Some(metadata))
    } else {
        PassiveFieldProjection::parsed(metadata)
    }
}

fn increment_permissions_member_count(metadata: &mut PermissionsPolicyMetadata) -> Result<(), ()> {
    let next = usize::from(metadata.member_count) + 1;
    if next > MAX_PASSIVE_PERMISSIONS_POLICY_MEMBERS {
        return Err(());
    }
    metadata.member_count = u8::try_from(next).unwrap_or(u8::MAX);
    Ok(())
}

fn project_cookies(headers: &HeaderMap) -> PassiveFieldProjection<Vec<PassiveCookieMetadata>> {
    let values = match bounded_values(
        headers,
        SET_COOKIE,
        MAX_PASSIVE_SET_COOKIE_OCCURRENCES,
        MAX_PASSIVE_SET_COOKIE_VALUE_BYTES,
    ) {
        Ok(values) => values,
        Err(PassiveProjectionIncompleteReason::TooManyHeaderOccurrences) => {
            return PassiveFieldProjection::incomplete(
                PassiveProjectionIncompleteReason::TooManySetCookieOccurrences,
            );
        },
        Err(PassiveProjectionIncompleteReason::OversizedHeaderValue) => {
            return PassiveFieldProjection::incomplete(
                PassiveProjectionIncompleteReason::OversizedSetCookieValue,
            );
        },
        Err(reason) => return PassiveFieldProjection::incomplete(reason),
    };
    if values.is_empty() {
        return PassiveFieldProjection::missing();
    }
    let mut cookies = Vec::with_capacity(values.len());
    let mut any_nonconformant = false;
    for value in values {
        match parse_cookie(value) {
            Ok((cookie, nonconformant)) => {
                cookies.push(cookie);
                any_nonconformant |= nonconformant;
            },
            Err(CookieProjectionError::Malformed) => {
                return PassiveFieldProjection::malformed();
            },
            Err(CookieProjectionError::Incomplete(reason)) => {
                return PassiveFieldProjection::incomplete(reason);
            },
        }
    }
    if any_nonconformant {
        PassiveFieldProjection::nonconformant(Some(cookies))
    } else {
        PassiveFieldProjection::parsed(cookies)
    }
}

enum CookieProjectionError {
    Malformed,
    Incomplete(PassiveProjectionIncompleteReason),
}

fn parse_cookie(
    value: &HeaderValue,
) -> Result<(PassiveCookieMetadata, bool), CookieProjectionError> {
    let value = value
        .to_str()
        .map_err(|_| CookieProjectionError::Malformed)?;
    let mut segments = value.split(';');
    let pair = segments.next().ok_or(CookieProjectionError::Malformed)?;
    if pair.len() > MAX_PASSIVE_COOKIE_PAIR_BYTES {
        return Err(CookieProjectionError::Incomplete(
            PassiveProjectionIncompleteReason::OversizedCookiePair,
        ));
    }
    let Some((name, cookie_value)) = pair.split_once('=') else {
        return Err(CookieProjectionError::Malformed);
    };
    let name = name.trim();
    if name.len() > MAX_PASSIVE_COOKIE_NAME_BYTES {
        return Err(CookieProjectionError::Incomplete(
            PassiveProjectionIncompleteReason::OversizedCookieName,
        ));
    }
    if !super::valid_cookie_name(name) || !valid_cookie_value(cookie_value.trim()) {
        return Err(CookieProjectionError::Malformed);
    }

    let attributes: Vec<_> = segments.collect();
    if attributes.len() > MAX_PASSIVE_COOKIE_ATTRIBUTES {
        return Err(CookieProjectionError::Incomplete(
            PassiveProjectionIncompleteReason::TooManyCookieAttributes,
        ));
    }
    let mut secure = false;
    let mut http_only = false;
    let mut same_site = PassiveCookieSameSite::Missing;
    let mut domain_attribute_present = false;
    let mut path_attribute_present = false;
    let mut seen_attributes = BTreeSet::new();
    let mut nonconformant = false;
    for attribute in attributes {
        let attribute = attribute.trim();
        if attribute.is_empty() {
            nonconformant = true;
            continue;
        }
        let (name, raw_value) = match attribute.split_once('=') {
            Some((name, raw_value)) => (name.trim(), Some(raw_value.trim())),
            None => (attribute, None),
        };
        if !valid_token(name) {
            return Err(CookieProjectionError::Malformed);
        }
        let canonical = name.to_ascii_lowercase();
        if !seen_attributes.insert(canonical.clone()) {
            nonconformant = true;
        }
        match canonical.as_str() {
            "secure" => {
                secure = true;
                nonconformant |= raw_value.is_some();
            },
            "httponly" => {
                http_only = true;
                nonconformant |= raw_value.is_some();
            },
            "samesite" => match raw_value {
                Some(value) if value.eq_ignore_ascii_case("strict") => {
                    same_site = PassiveCookieSameSite::Strict;
                },
                Some(value) if value.eq_ignore_ascii_case("lax") => {
                    same_site = PassiveCookieSameSite::Lax;
                },
                Some(value) if value.eq_ignore_ascii_case("none") => {
                    same_site = PassiveCookieSameSite::None;
                },
                _ => nonconformant = true,
            },
            "domain" => {
                domain_attribute_present = true;
                let Some(value) = raw_value else {
                    nonconformant = true;
                    continue;
                };
                if value.len() > MAX_PASSIVE_COOKIE_SCOPE_VALUE_BYTES {
                    return Err(CookieProjectionError::Incomplete(
                        PassiveProjectionIncompleteReason::OversizedCookieScopeValue,
                    ));
                }
                if !valid_cookie_domain(value) {
                    nonconformant = true;
                }
            },
            "path" => {
                path_attribute_present = true;
                let Some(value) = raw_value else {
                    nonconformant = true;
                    continue;
                };
                if value.len() > MAX_PASSIVE_COOKIE_SCOPE_VALUE_BYTES {
                    return Err(CookieProjectionError::Incomplete(
                        PassiveProjectionIncompleteReason::OversizedCookieScopeValue,
                    ));
                }
                if !value.starts_with('/') {
                    nonconformant = true;
                }
            },
            _ => {},
        }
    }
    if same_site == PassiveCookieSameSite::None && !secure {
        nonconformant = true;
    }
    Ok((
        PassiveCookieMetadata {
            name: name.to_owned(),
            secure,
            http_only,
            same_site,
            domain_attribute_present,
            path_attribute_present,
        },
        nonconformant,
    ))
}

fn bounded_values<'a>(
    headers: &'a HeaderMap,
    name: &str,
    max_occurrences: usize,
    max_value_bytes: usize,
) -> Result<Vec<&'a HeaderValue>, PassiveProjectionIncompleteReason> {
    let values: Vec<_> = headers
        .get_all(name)
        .iter()
        .take(max_occurrences + 1)
        .collect();
    if values.len() > max_occurrences {
        return Err(PassiveProjectionIncompleteReason::TooManyHeaderOccurrences);
    }
    if values
        .iter()
        .any(|value| value.as_bytes().len() > max_value_bytes)
    {
        return Err(PassiveProjectionIncompleteReason::OversizedHeaderValue);
    }
    Ok(values)
}

fn split_permissions_directives(value: &str) -> Result<Vec<&str>, ()> {
    let mut directives = Vec::new();
    let mut start = 0usize;
    let mut parentheses = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    for (index, byte) in value.bytes().enumerate() {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            continue;
        }
        match byte {
            b'"' => quoted = true,
            b'(' => parentheses = parentheses.checked_add(1).ok_or(())?,
            b')' => {
                parentheses = parentheses.checked_sub(1).ok_or(())?;
            },
            b',' if parentheses == 0 => {
                let directive = value[start..index].trim();
                if directive.is_empty() {
                    return Err(());
                }
                directives.push(directive);
                if directives.len() > MAX_PASSIVE_PERMISSIONS_POLICY_DIRECTIVES {
                    return Ok(directives);
                }
                start = index + 1;
            },
            _ => {},
        }
    }
    if quoted || escaped || parentheses != 0 {
        return Err(());
    }
    let directive = value[start..].trim();
    if directive.is_empty() {
        return Err(());
    }
    directives.push(directive);
    Ok(directives)
}

fn split_permissions_members(value: &str) -> Result<Vec<&str>, ()> {
    let mut members = Vec::new();
    let mut start = None;
    let mut quoted = false;
    let mut escaped = false;
    for (index, byte) in value.bytes().enumerate() {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            continue;
        }
        if byte == b'"' {
            quoted = true;
            start.get_or_insert(index);
        } else if byte.is_ascii_whitespace() {
            if let Some(token_start) = start.take() {
                members.push(&value[token_start..index]);
            }
        } else {
            start.get_or_insert(index);
        }
    }
    if quoted || escaped {
        return Err(());
    }
    if let Some(token_start) = start {
        members.push(&value[token_start..]);
    }
    Ok(members)
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
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
        })
}

fn valid_directive_value(value: &str) -> bool {
    let value = unquote_ascii(value);
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b';' | b','))
}

fn unquote_ascii(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value)
}

fn valid_cookie_value(value: &str) -> bool {
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value);
    value.bytes().all(|byte| {
        byte == 0x21
            || (0x23..=0x2b).contains(&byte)
            || (0x2d..=0x3a).contains(&byte)
            || (0x3c..=0x5b).contains(&byte)
            || (0x5d..=0x7e).contains(&byte)
    })
}

fn valid_cookie_domain(value: &str) -> bool {
    let value = value.strip_prefix('.').unwrap_or(value);
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

fn derived_observation_count(projection: &PassiveResponseProjection) -> usize {
    let mut count = 6usize;
    if projection.strict_transport_security.metadata().is_some() {
        count += 4;
    }
    if projection.content_security_policy.metadata().is_some() {
        count += 13;
    }
    if projection.x_content_type_options.metadata().is_some() {
        count += 1;
    }
    if projection.referrer_policy.metadata().is_some() {
        count += 2;
    }
    if projection.permissions_policy.metadata().is_some() {
        count += 8;
    }
    if let Some(cookies) = projection.cookies.metadata() {
        count += cookies.len().saturating_mul(6);
    }
    count
}

fn enforce_derived_observation_limit(
    count: usize,
) -> Result<u16, PassiveProjectionIncompleteReason> {
    if count > MAX_PASSIVE_DERIVED_OBSERVATIONS {
        return Err(PassiveProjectionIncompleteReason::TooManyDerivedObservations);
    }
    u16::try_from(count).map_err(|_| PassiveProjectionIncompleteReason::TooManyDerivedObservations)
}

#[cfg(test)]
#[path = "passive_review_tests.rs"]
mod tests;
