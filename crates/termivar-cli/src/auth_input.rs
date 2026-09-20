//! Bounded, redacted authorization-context input for the opt-in web review.
//!
//! This module is the only CLI boundary that reads credential material. It
//! never accepts a credential as a command-line value, never serializes or
//! logs one, and converts bounded bytes directly into scanner-owned root,
//! supplied-session, role-bound two-principal, or OAST administrator-secret
//! contracts.

#[cfg(any(feature = "supplied-session-review", feature = "jwt-policy-review"))]
use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    ffi::OsString,
    fmt,
    fs::File,
    io::{self, Read},
    path::PathBuf,
};
use zeroize::{Zeroize, Zeroizing};

#[cfg(any(feature = "jwt-policy-review", feature = "supplied-session-review"))]
use std::path::Path;

#[cfg(feature = "jwt-policy-review")]
use termivar_scanner::jwt_policy_review::{
    review_compact_jwt, Es256LocalPublicKey, JwtEvaluationTime, JwtLocalPolicy,
    JwtPolicyReviewAudit, SecretCompactJwt, MAX_COMPACT_JWT_BYTES, MAX_LOCAL_PUBLIC_JWK_BYTES,
};
#[cfg(feature = "jwt-target-acceptance-review")]
use termivar_scanner::{
    jwt_policy_review::{review_and_prepare_target_acceptance, JwtTargetAcceptanceRuntimeInput},
    jwt_target_acceptance::JwtTargetAcceptancePolicy,
};

#[cfg(feature = "authorization-review")]
use termivar_scanner::authorization_review::{
    AuthorizationPrincipalPair, AuthorizationReviewPolicy, PeerAuthorizationPrincipal,
    PrimaryAuthorizationPrincipal, HARD_MAX_AUTHORIZATION_REVIEW_POLICY_BYTES,
};
#[cfg(feature = "ssrf-oast-review")]
use termivar_scanner::ssrf_oast_review::{
    SsrfOastAdminToken, SsrfOastReviewPolicy, MAX_SSRF_OAST_REVIEW_POLICY_BYTES,
};
#[cfg(all(
    feature = "supplied-session-review",
    any(feature = "wordpress-review", test)
))]
use termivar_scanner::supplied_session_review::SuppliedSessionPolicyVersion;
#[cfg(feature = "supplied-session-review")]
use termivar_scanner::supplied_session_review::{
    SuppliedSessionAuthorization, SuppliedSessionCookies, SuppliedSessionCredentialAcquisition,
    SuppliedSessionFormCredential, SuppliedSessionPolicy, SuppliedSessionRuntimeInput,
    HARD_MAX_SUPPLIED_SESSION_COOKIE_SECRET_BYTES, HARD_MAX_SUPPLIED_SESSION_FORM_SECRET_BYTES,
    HARD_MAX_SUPPLIED_SESSION_POLICY_BYTES,
};
use termivar_scanner::{
    web_runtime::WebAssessmentRootAuthorizationContext, DEFAULT_MAX_PAYLOAD_ARTIFACT_BYTES,
};

/// The CLI deliberately uses the standard payload-strategy seed ceiling.
pub(crate) const MAX_AUTHORIZATION_CONTEXT_BYTES: usize =
    DEFAULT_MAX_PAYLOAD_ARTIFACT_BYTES as usize;

/// Owns only CLI intake material, including every fallible read/validation.
/// Handoff transfers the existing allocation; downstream constructor copies
/// and their lifetimes are outside this boundary's erasure guarantee.
struct CredentialBytes {
    bytes: Zeroizing<Vec<u8>>,
}

impl CredentialBytes {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    fn as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    fn into_owned(mut self) -> Vec<u8> {
        std::mem::take(&mut *self.bytes)
    }
}

impl fmt::Debug for CredentialBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialBytes(<redacted>)")
    }
}

impl Drop for CredentialBytes {
    fn drop(&mut self) {
        self.bytes.as_mut_slice().zeroize();
        #[cfg(test)]
        INTAKE_DROPS.with(|drops| {
            drops
                .borrow_mut()
                .push((self.bytes.len(), self.bytes.iter().all(|byte| *byte == 0)));
        });
        // The inner Zeroizing<Vec<_>> additionally wipes the full capacity.
    }
}

#[cfg(test)]
thread_local! {
    // Observe only still-owned storage, before its allocation is released.
    // Never retain a credential, allocation pointer, or freed-memory view.
    static INTAKE_DROPS: std::cell::RefCell<Vec<(usize, bool)>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

/// One explicit out-of-band source for a complete Authorization header value.
///
/// Source identifiers and paths are redacted as well as the value. This type
/// intentionally implements neither `Clone` nor `Serialize`.
pub(crate) enum AuthorizationInputSource {
    Environment(OsString),
    File(PathBuf),
    Stdin,
}

impl fmt::Debug for AuthorizationInputSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let source = match self {
            Self::Environment(_) => "environment",
            Self::File(_) => "file",
            Self::Stdin => "stdin",
        };
        formatter
            .debug_struct("AuthorizationInputSource")
            .field("source", &source)
            .field("location", &"<redacted>")
            .finish()
    }
}

impl AuthorizationInputSource {
    /// Selects zero or one source without reading it.
    pub(crate) fn select(
        environment: Option<OsString>,
        file: Option<PathBuf>,
        stdin: bool,
    ) -> Result<Option<Self>, AuthorizationInputError> {
        let selected = usize::from(environment.is_some())
            .saturating_add(usize::from(file.is_some()))
            .saturating_add(usize::from(stdin));
        if selected > 1 {
            return Err(AuthorizationInputError::ConflictingSources);
        }
        Ok(match (environment, file, stdin) {
            (Some(name), None, false) => Some(Self::Environment(name)),
            (None, Some(path), false) => Some(Self::File(path)),
            (None, None, true) => Some(Self::Stdin),
            (None, None, false) => None,
            _ => return Err(AuthorizationInputError::ConflictingSources),
        })
    }

    /// Reads and validates the selected source exactly once.
    pub(crate) fn load(
        self,
    ) -> Result<WebAssessmentRootAuthorizationContext, AuthorizationInputError> {
        let bytes = self.read_bytes()?;
        WebAssessmentRootAuthorizationContext::new(bytes.into_owned())
            .map_err(|_| AuthorizationInputError::InvalidValue)
    }

    fn read_bytes(self) -> Result<CredentialBytes, AuthorizationInputError> {
        self.read_bytes_with_limit(MAX_AUTHORIZATION_CONTEXT_BYTES)
    }

    fn read_bytes_with_limit(
        self,
        max_bytes: usize,
    ) -> Result<CredentialBytes, AuthorizationInputError> {
        match self {
            Self::Environment(name) => read_environment_with_limit(name, max_bytes),
            Self::File(path) => {
                let mut file = open_regular_file(path)?;
                ensure_opened_file_length(&file, max_bytes.saturating_add(2))?;
                read_bounded_line_source_with_limit(&mut file, max_bytes)
            },
            Self::Stdin => {
                let stdin = io::stdin();
                let mut input = stdin.lock();
                read_bounded_line_source_with_limit(&mut input, max_bytes)
            },
        }
    }
}

/// Complete input selection for one transport-free local JWT review.
///
/// The policy and public key are validated before output reservation. The
/// compact token remains unread until every non-secret preflight succeeds.
#[cfg(feature = "jwt-policy-review")]
pub(crate) struct JwtPolicyReviewInput {
    policy_file: PathBuf,
    public_jwk_file: PathBuf,
    token: AuthorizationInputSource,
    #[cfg(feature = "jwt-target-acceptance-review")]
    target_acceptance_policy_file: Option<PathBuf>,
}

/// Validated non-secret policy and public key paired with the unread token.
#[cfg(feature = "jwt-policy-review")]
pub(crate) struct PreparedJwtPolicyReviewInput {
    policy: JwtLocalPolicy,
    public_key: Es256LocalPublicKey,
    token: AuthorizationInputSource,
    #[cfg(feature = "jwt-target-acceptance-review")]
    target_acceptance_policy: Option<JwtTargetAcceptancePolicy>,
}

/// Loaded local audit and the optional move-only target-acceptance handoff.
#[cfg(feature = "jwt-target-acceptance-review")]
pub(crate) struct LoadedJwtPolicyReviewInput {
    local_audit: JwtPolicyReviewAudit,
    target_acceptance: Option<LoadedJwtTargetAcceptanceInput>,
}

/// Target selection retained even when local eligibility prevents dispatch.
#[cfg(feature = "jwt-target-acceptance-review")]
pub(crate) struct LoadedJwtTargetAcceptanceInput {
    policy: JwtTargetAcceptancePolicy,
    runtime_input: JwtTargetAcceptanceRuntimeInput,
}

#[cfg(feature = "jwt-policy-review")]
impl fmt::Debug for JwtPolicyReviewInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JwtPolicyReviewInput")
            .field("policy_file", &"<redacted>")
            .field("public_jwk_file", &"<redacted>")
            .field("token", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "jwt-policy-review")]
impl fmt::Debug for PreparedJwtPolicyReviewInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedJwtPolicyReviewInput")
            .field("policy", &"<validated>")
            .field("public_key", &"<validated-public-key>")
            .field("token", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "jwt-target-acceptance-review")]
impl fmt::Debug for LoadedJwtPolicyReviewInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LoadedJwtPolicyReviewInput(<redacted>)")
    }
}

#[cfg(feature = "jwt-target-acceptance-review")]
impl LoadedJwtPolicyReviewInput {
    pub(crate) fn into_parts(
        self,
    ) -> (JwtPolicyReviewAudit, Option<LoadedJwtTargetAcceptanceInput>) {
        (self.local_audit, self.target_acceptance)
    }
}

#[cfg(feature = "jwt-target-acceptance-review")]
impl LoadedJwtTargetAcceptanceInput {
    pub(crate) fn into_parts(self) -> (JwtTargetAcceptancePolicy, JwtTargetAcceptanceRuntimeInput) {
        (self.policy, self.runtime_input)
    }
}

#[cfg(feature = "jwt-policy-review")]
const MAX_JWT_POLICY_BYTES: usize = 8 * 1024;
#[cfg(feature = "jwt-policy-review")]
const JWT_POLICY_INPUT_SCHEMA: &str = "security.jwt-local-policy/v1";

#[cfg(feature = "jwt-policy-review")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct JwtPolicyDocument {
    schema: String,
    policy_reference: String,
    policy_revision: String,
    expected_type: String,
    expected_issuer: String,
    expected_audience: String,
    required_claims: Vec<String>,
    require_expiration: bool,
    allowed_clock_skew_seconds: u32,
}

#[cfg(feature = "jwt-policy-review")]
impl Drop for JwtPolicyDocument {
    fn drop(&mut self) {
        self.expected_type.zeroize();
        self.expected_issuer.zeroize();
        self.expected_audience.zeroize();
        self.required_claims.zeroize();
    }
}

#[cfg(feature = "jwt-target-acceptance-review")]
const MAX_JWT_TARGET_ACCEPTANCE_POLICY_BYTES: usize = 8 * 1024;
#[cfg(feature = "jwt-target-acceptance-review")]
const JWT_TARGET_ACCEPTANCE_POLICY_INPUT_SCHEMA: &str = "security.jwt-target-acceptance-policy/v1";

#[cfg(feature = "jwt-target-acceptance-review")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct JwtTargetAcceptancePolicyDocument {
    schema: String,
    policy_reference: String,
    policy_revision: String,
    application: String,
    resource: String,
    resource_reference: String,
    success_json_field: String,
}

#[cfg(feature = "jwt-target-acceptance-review")]
fn parse_exact_jwt_target_policy_url(value: &str) -> Result<url::Url, JwtPolicyInputError> {
    // The URL parser follows the URL Standard and can canonicalize literal or
    // encoded dot segments, backslashes, host casing, and default ports. An
    // operator policy is an authority input, so its raw spelling must already
    // be the exact canonical URL that will be bound into the request
    // descriptor. Normalization must never turn rejected text into authority.
    if value.is_empty()
        || value.trim() != value
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_control())
        || value.contains('%')
        || value.contains('\\')
    {
        return Err(JwtPolicyInputError::InvalidTargetPolicy);
    }
    let parsed = url::Url::parse(value).map_err(|_| JwtPolicyInputError::InvalidTargetPolicy)?;
    if parsed.as_str() != value {
        return Err(JwtPolicyInputError::InvalidTargetPolicy);
    }
    Ok(parsed)
}

#[cfg(feature = "jwt-target-acceptance-review")]
impl Drop for JwtTargetAcceptancePolicyDocument {
    fn drop(&mut self) {
        self.application.zeroize();
        self.resource.zeroize();
        self.success_json_field.zeroize();
    }
}

#[cfg(feature = "jwt-policy-review")]
impl JwtPolicyReviewInput {
    /// Requires one policy, one local public JWK, and exactly one token source.
    pub(crate) fn select(
        policy_file: Option<PathBuf>,
        public_jwk_file: Option<PathBuf>,
        token: AuthorizationSourceOptions,
        #[cfg(feature = "jwt-target-acceptance-review")] target_acceptance_policy_file: Option<
            PathBuf,
        >,
    ) -> Result<Option<Self>, JwtPolicyInputError> {
        let any_selected = policy_file.is_some()
            || public_jwk_file.is_some()
            || token.environment.is_some()
            || token.file.is_some()
            || token.stdin
            || {
                #[cfg(feature = "jwt-target-acceptance-review")]
                {
                    target_acceptance_policy_file.is_some()
                }
                #[cfg(not(feature = "jwt-target-acceptance-review"))]
                {
                    false
                }
            };
        if !any_selected {
            return Ok(None);
        }
        let policy_file = policy_file.ok_or(JwtPolicyInputError::MissingPolicy)?;
        let public_jwk_file = public_jwk_file.ok_or(JwtPolicyInputError::MissingPublicKey)?;
        let token = AuthorizationInputSource::select(token.environment, token.file, token.stdin)
            .map_err(|_| JwtPolicyInputError::ConflictingTokenSources)?
            .ok_or(JwtPolicyInputError::MissingTokenSource)?;
        validate_local_file_path(&policy_file).map_err(JwtPolicyInputError::PolicySource)?;
        validate_local_file_path(&public_jwk_file).map_err(JwtPolicyInputError::PublicKeySource)?;
        if let AuthorizationInputSource::File(token_file) = &token {
            validate_local_file_path(token_file).map_err(JwtPolicyInputError::TokenSource)?;
        }
        #[cfg(feature = "jwt-target-acceptance-review")]
        if let Some(target_policy_file) = &target_acceptance_policy_file {
            validate_local_file_path(target_policy_file)
                .map_err(JwtPolicyInputError::TargetPolicySource)?;
        }
        Ok(Some(Self {
            policy_file,
            public_jwk_file,
            token,
            #[cfg(feature = "jwt-target-acceptance-review")]
            target_acceptance_policy_file,
        }))
    }

    /// Validates the non-secret policy and explicit local public key while the
    /// secret compact token remains unread.
    pub(crate) fn prepare(
        self,
        #[cfg(feature = "jwt-target-acceptance-review")] selected_application: &url::Url,
    ) -> Result<PreparedJwtPolicyReviewInput, JwtPolicyInputError> {
        let policy_source = read_bounded_regular_file(self.policy_file, MAX_JWT_POLICY_BYTES)
            .map_err(JwtPolicyInputError::PolicySource)?;
        let document: JwtPolicyDocument = toml::from_str(
            std::str::from_utf8(policy_source.as_slice())
                .map_err(|_| JwtPolicyInputError::InvalidPolicy)?,
        )
        .map_err(|_| JwtPolicyInputError::InvalidPolicy)?;
        if document.schema != JWT_POLICY_INPUT_SCHEMA {
            return Err(JwtPolicyInputError::InvalidPolicy);
        }
        let required_claims = document
            .required_claims
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let policy = JwtLocalPolicy::new(
            (&document.policy_reference, &document.policy_revision),
            &document.expected_type,
            &document.expected_issuer,
            &document.expected_audience,
            &required_claims,
            document.require_expiration,
            document.allowed_clock_skew_seconds,
        )
        .map_err(|_| JwtPolicyInputError::InvalidPolicy)?;
        let public_jwk_source =
            read_bounded_regular_file(self.public_jwk_file, MAX_LOCAL_PUBLIC_JWK_BYTES)
                .map_err(JwtPolicyInputError::PublicKeySource)?;
        let public_key = Es256LocalPublicKey::from_jwk_json(public_jwk_source.into_owned())
            .map_err(|_| JwtPolicyInputError::InvalidPublicKey)?;
        #[cfg(feature = "jwt-target-acceptance-review")]
        let target_acceptance_policy = self
            .target_acceptance_policy_file
            .map(|path| {
                let source =
                    read_bounded_regular_file(path, MAX_JWT_TARGET_ACCEPTANCE_POLICY_BYTES)
                        .map_err(JwtPolicyInputError::TargetPolicySource)?;
                let document: JwtTargetAcceptancePolicyDocument = toml::from_str(
                    std::str::from_utf8(source.as_slice())
                        .map_err(|_| JwtPolicyInputError::InvalidTargetPolicy)?,
                )
                .map_err(|_| JwtPolicyInputError::InvalidTargetPolicy)?;
                if document.schema != JWT_TARGET_ACCEPTANCE_POLICY_INPUT_SCHEMA {
                    return Err(JwtPolicyInputError::InvalidTargetPolicy);
                }
                let application = parse_exact_jwt_target_policy_url(&document.application)?;
                let resource = parse_exact_jwt_target_policy_url(&document.resource)?;
                if application != *selected_application {
                    return Err(JwtPolicyInputError::InvalidTargetPolicy);
                }
                JwtTargetAcceptancePolicy::new(
                    (&document.policy_reference, &document.policy_revision),
                    application,
                    resource,
                    &document.resource_reference,
                    &document.success_json_field,
                )
                .map_err(|_| JwtPolicyInputError::InvalidTargetPolicy)
            })
            .transpose()?;
        Ok(PreparedJwtPolicyReviewInput {
            policy,
            public_key,
            token: self.token,
            #[cfg(feature = "jwt-target-acceptance-review")]
            target_acceptance_policy,
        })
    }
}

/// Rejects Windows remote and device spellings before a guarded local input is opened.
///
/// This is deliberately a lexical Windows guard. It does not claim to detect a
/// mapped drive, a local path backed by a network filesystem, or a parent that
/// changes after selection; the existing trusted-parent assumption still
/// applies to every accepted path.
#[cfg(any(feature = "jwt-policy-review", feature = "supplied-session-review"))]
fn validate_local_file_path(path: &Path) -> Result<(), AuthorizationInputError> {
    #[cfg(windows)]
    if windows_path_is_remote_or_special(path) {
        return Err(AuthorizationInputError::SourceUnavailable);
    }

    #[cfg(not(windows))]
    let _ = path;

    Ok(())
}

#[cfg(all(
    any(feature = "jwt-policy-review", feature = "supplied-session-review"),
    windows
))]
fn windows_path_is_remote_or_special(path: &Path) -> bool {
    use std::path::{Component, Prefix};

    let first = path.components().next();
    if let Some(Component::Prefix(prefix)) = first {
        match prefix.kind() {
            Prefix::Disk(_) | Prefix::VerbatimDisk(_) => {},
            Prefix::UNC(_, _)
            | Prefix::VerbatimUNC(_, _)
            | Prefix::DeviceNS(_)
            | Prefix::Verbatim(_) => return true,
        }
    } else {
        let normalized = path.as_os_str().to_string_lossy().replace('/', "\\");
        let upper = normalized.to_ascii_uppercase();
        if upper.starts_with("\\\\")
            || upper.starts_with("\\??\\")
            || upper.starts_with("\\DEVICE\\")
            || upper.starts_with("\\GLOBAL??\\")
            || upper.starts_with("\\GLOBALROOT\\")
            || upper.starts_with("\\PIPE\\")
        {
            return true;
        }
    }

    path.components().any(|component| match component {
        Component::Normal(name) => windows_path_component_is_special(name),
        _ => false,
    })
}

#[cfg(all(
    any(feature = "jwt-policy-review", feature = "supplied-session-review"),
    windows
))]
fn windows_path_component_is_special(component: &std::ffi::OsStr) -> bool {
    let component = component.to_string_lossy();
    if component.contains(':') {
        // A colon outside the parsed drive prefix selects an alternate data
        // stream or another special Win32 spelling, not the named local file.
        return true;
    }
    let component = component.trim_end_matches([' ', '.']);
    let stem = component
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    if matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }
    for prefix in ["COM", "LPT"] {
        if let Some(suffix) = stem.strip_prefix(prefix) {
            if matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            ) {
                return true;
            }
        }
    }
    false
}

#[cfg(feature = "jwt-policy-review")]
impl PreparedJwtPolicyReviewInput {
    /// Reads and evaluates the compact token exactly once after output
    /// reservation. The token is never sent to the target or serialized.
    #[cfg(not(feature = "jwt-target-acceptance-review"))]
    pub(crate) fn load(self) -> Result<JwtPolicyReviewAudit, JwtPolicyInputError> {
        let token = self
            .token
            .read_bytes_with_limit(MAX_COMPACT_JWT_BYTES)
            .map_err(JwtPolicyInputError::TokenSource)?;
        let token = SecretCompactJwt::new(token.into_owned())
            .map_err(|_| JwtPolicyInputError::InvalidToken)?;
        let unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_secs()).ok())
            .ok_or(JwtPolicyInputError::EvaluationClockUnavailable)?;
        Ok(review_compact_jwt(
            &token,
            &self.public_key,
            &self.policy,
            JwtEvaluationTime { unix_seconds },
        ))
    }

    /// Reads the compact token exactly once after output reservation. When
    /// target acceptance is selected, only a locally parsed, policy-consistent,
    /// and signature-verified token crosses into the move-only runtime handoff.
    #[cfg(feature = "jwt-target-acceptance-review")]
    pub(crate) fn load(self) -> Result<LoadedJwtPolicyReviewInput, JwtPolicyInputError> {
        let token = self
            .token
            .read_bytes_with_limit(MAX_COMPACT_JWT_BYTES)
            .map_err(JwtPolicyInputError::TokenSource)?;
        let token = SecretCompactJwt::new(token.into_owned())
            .map_err(|_| JwtPolicyInputError::InvalidToken)?;
        let unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_secs()).ok())
            .ok_or(JwtPolicyInputError::EvaluationClockUnavailable)?;
        let evaluation_time = JwtEvaluationTime { unix_seconds };
        let Some(target_policy) = self.target_acceptance_policy else {
            return Ok(LoadedJwtPolicyReviewInput {
                local_audit: review_compact_jwt(
                    &token,
                    &self.public_key,
                    &self.policy,
                    evaluation_time,
                ),
                target_acceptance: None,
            });
        };
        let prepared = review_and_prepare_target_acceptance(
            token,
            &self.public_key,
            &self.policy,
            evaluation_time,
        )
        .map_err(|_| JwtPolicyInputError::TargetControlPreparation)?;
        let (local_audit, runtime_input) = prepared.into_parts();
        Ok(LoadedJwtPolicyReviewInput {
            local_audit,
            target_acceptance: Some(LoadedJwtTargetAcceptanceInput {
                policy: target_policy,
                runtime_input,
            }),
        })
    }
}

/// Redaction-safe failures for the local JWT input boundary.
#[cfg(feature = "jwt-policy-review")]
#[derive(Debug)]
pub(crate) enum JwtPolicyInputError {
    MissingPolicy,
    MissingPublicKey,
    MissingTokenSource,
    ConflictingTokenSources,
    PolicySource(AuthorizationInputError),
    InvalidPolicy,
    PublicKeySource(AuthorizationInputError),
    InvalidPublicKey,
    #[cfg(feature = "jwt-target-acceptance-review")]
    TargetPolicySource(AuthorizationInputError),
    #[cfg(feature = "jwt-target-acceptance-review")]
    InvalidTargetPolicy,
    TokenSource(AuthorizationInputError),
    InvalidToken,
    EvaluationClockUnavailable,
    #[cfg(feature = "jwt-target-acceptance-review")]
    TargetControlPreparation,
}

#[cfg(feature = "jwt-policy-review")]
impl fmt::Display for JwtPolicyInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingPolicy => "JWT policy review requires one policy file",
            Self::MissingPublicKey => "JWT policy review requires one local public JWK file",
            Self::MissingTokenSource | Self::ConflictingTokenSources => {
                "JWT policy review requires exactly one compact-token source"
            },
            Self::PolicySource(_) => "JWT policy must be a bounded regular UTF-8 file",
            Self::InvalidPolicy => "JWT policy is invalid",
            Self::PublicKeySource(_) => "JWT public JWK must be a bounded regular file",
            Self::InvalidPublicKey => "JWT public JWK is invalid",
            #[cfg(feature = "jwt-target-acceptance-review")]
            Self::TargetPolicySource(_) => {
                "JWT target-acceptance policy must be a bounded regular UTF-8 file"
            },
            #[cfg(feature = "jwt-target-acceptance-review")]
            Self::InvalidTargetPolicy => "JWT target-acceptance policy is invalid",
            Self::TokenSource(_) => "JWT token source could not be loaded",
            Self::InvalidToken => "JWT token value is invalid",
            Self::EvaluationClockUnavailable => "JWT local evaluation clock is unavailable",
            #[cfg(feature = "jwt-target-acceptance-review")]
            Self::TargetControlPreparation => {
                "JWT invalid-signature control could not be prepared safely"
            },
        })
    }
}

#[cfg(feature = "jwt-policy-review")]
impl std::error::Error for JwtPolicyInputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PolicySource(source)
            | Self::PublicKeySource(source)
            | Self::TokenSource(source) => Some(source),
            #[cfg(feature = "jwt-target-acceptance-review")]
            Self::TargetPolicySource(source) => Some(source),
            _ => None,
        }
    }
}

/// Complete, preflight-checked CLI input for one resource authorization review.
///
/// Paths, source names, and credential values are deliberately omitted from
/// `Debug`. Selecting inputs performs no filesystem, environment, or stdin I/O.
#[cfg(feature = "authorization-review")]
pub(crate) struct AuthorizationReviewInput {
    policy_file: PathBuf,
    primary: AuthorizationInputSource,
    peer: AuthorizationInputSource,
}

/// Complete, preflight-selected input for one supplied credential session.
///
/// Selection performs no I/O. Policy and secret locations are never exposed
/// through `Debug`, and the policy is validated before the credential source
/// is opened.
#[cfg(feature = "supplied-session-review")]
pub(crate) struct SuppliedSessionInput {
    policy_file: PathBuf,
    secret: SuppliedSessionSecretSource,
}

/// Validated non-secret supplied-session policy paired with the still-unread
/// secret source. Keeping this intermediate state makes the CLI's preflight
/// order explicit: policy validation precedes output reservation, while the
/// secret is not acquired until after that reservation succeeds.
#[cfg(feature = "supplied-session-review")]
pub(crate) struct PreparedSuppliedSessionInput {
    policy: SuppliedSessionPolicy,
    secret: SuppliedSessionSecretSource,
}

#[cfg(feature = "supplied-session-review")]
enum SuppliedSessionSecretSource {
    Authorization(AuthorizationInputSource),
    Cookies(PathBuf),
    FormLogin(PathBuf),
}

#[cfg(feature = "supplied-session-review")]
impl SuppliedSessionSecretSource {
    const fn acquisition(&self) -> SuppliedSessionCredentialAcquisition {
        match self {
            Self::Authorization(_) => SuppliedSessionCredentialAcquisition::SuppliedAuthorization,
            Self::Cookies(_) => SuppliedSessionCredentialAcquisition::SuppliedCookieJar,
            Self::FormLogin(_) => SuppliedSessionCredentialAcquisition::BoundedFormLogin,
        }
    }
}

#[cfg(feature = "supplied-session-review")]
impl fmt::Debug for SuppliedSessionSecretSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Authorization(_) => "authorization",
            Self::Cookies(_) => "cookies",
            Self::FormLogin(_) => "form_login",
        };
        formatter
            .debug_struct("SuppliedSessionSecretSource")
            .field("kind", &kind)
            .field("location", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "supplied-session-review")]
impl fmt::Debug for PreparedSuppliedSessionInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedSuppliedSessionInput")
            .field("policy", &"<validated>")
            .field("secret", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "supplied-session-review")]
impl fmt::Debug for SuppliedSessionInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SuppliedSessionInput")
            .field("policy_file", &"<redacted>")
            .field("secret", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "supplied-session-review")]
impl SuppliedSessionInput {
    /// Requires one policy and exactly one matching out-of-band credential source.
    pub(crate) fn select(
        policy_file: Option<PathBuf>,
        authorization: AuthorizationSourceOptions,
        cookie_file: Option<PathBuf>,
        login_file: Option<PathBuf>,
    ) -> Result<Option<Self>, SuppliedSessionInputError> {
        let any_selected = policy_file.is_some()
            || authorization.environment.is_some()
            || authorization.file.is_some()
            || authorization.stdin
            || cookie_file.is_some()
            || login_file.is_some();
        if !any_selected {
            return Ok(None);
        }
        let policy_file = policy_file.ok_or(SuppliedSessionInputError::MissingPolicy)?;
        validate_local_file_path(&policy_file).map_err(SuppliedSessionInputError::PolicySource)?;
        let authorization = AuthorizationInputSource::select(
            authorization.environment,
            authorization.file,
            authorization.stdin,
        )
        .map_err(|_| SuppliedSessionInputError::ConflictingCredentialSources)?;
        let secret = match (authorization, cookie_file, login_file) {
            (Some(source), None, None) => SuppliedSessionSecretSource::Authorization(source),
            (None, Some(path), None) => SuppliedSessionSecretSource::Cookies(path),
            (None, None, Some(path)) => SuppliedSessionSecretSource::FormLogin(path),
            (None, None, None) => return Err(SuppliedSessionInputError::MissingCredentialSource),
            _ => return Err(SuppliedSessionInputError::ConflictingCredentialSources),
        };
        if let SuppliedSessionSecretSource::Authorization(AuthorizationInputSource::File(path))
        | SuppliedSessionSecretSource::Cookies(path)
        | SuppliedSessionSecretSource::FormLogin(path) = &secret
        {
            validate_local_file_path(path).map_err(SuppliedSessionInputError::CredentialSource)?;
        }
        Ok(Some(Self {
            policy_file,
            secret,
        }))
    }

    /// Loads and validates only the non-secret policy, retaining the selected
    /// secret source in an unread intermediate state.
    pub(crate) fn prepare(
        self,
        target: &url::Url,
    ) -> Result<PreparedSuppliedSessionInput, SuppliedSessionInputError> {
        let policy_source =
            read_bounded_regular_file(self.policy_file, HARD_MAX_SUPPLIED_SESSION_POLICY_BYTES)
                .map_err(SuppliedSessionInputError::PolicySource)?;
        let policy = SuppliedSessionPolicy::parse_toml(target, policy_source.as_slice())
            .map_err(|_| SuppliedSessionInputError::InvalidPolicy)?;
        if policy.credential_acquisition() != self.secret.acquisition() {
            return Err(SuppliedSessionInputError::CredentialMechanismMismatch);
        }
        Ok(PreparedSuppliedSessionInput {
            policy,
            secret: self.secret,
        })
    }
}

#[cfg(feature = "supplied-session-review")]
impl PreparedSuppliedSessionInput {
    /// Policy generation is non-secret and may be used for cross-capability
    /// preflight before any credential source or output destination is opened.
    #[cfg(any(feature = "wordpress-review", test))]
    pub(crate) const fn policy_version(&self) -> SuppliedSessionPolicyVersion {
        self.policy.version()
    }

    /// Reads the selected secret exactly once after all non-secret preflight
    /// and output reservation have succeeded.
    pub(crate) fn load(
        self,
    ) -> Result<(SuppliedSessionPolicy, SuppliedSessionRuntimeInput), SuppliedSessionInputError>
    {
        let runtime_input = match self.secret {
            SuppliedSessionSecretSource::Authorization(source) => {
                let authorization = source
                    .read_bytes()
                    .map_err(SuppliedSessionInputError::CredentialSource)
                    .and_then(|bytes| {
                        SuppliedSessionAuthorization::new(bytes.into_owned())
                            .map_err(|_| SuppliedSessionInputError::InvalidCredentialValue)
                    })?;
                SuppliedSessionRuntimeInput::from(authorization)
            },
            SuppliedSessionSecretSource::Cookies(path) => {
                let bytes =
                    read_bounded_regular_file(path, HARD_MAX_SUPPLIED_SESSION_COOKIE_SECRET_BYTES)
                        .map_err(SuppliedSessionInputError::CredentialSource)?;
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .ok()
                    .and_then(|duration| i64::try_from(duration.as_secs()).ok())
                    .ok_or(SuppliedSessionInputError::CredentialClockUnavailable)?;
                let cookies =
                    SuppliedSessionCookies::parse_tsv(&self.policy, bytes.into_owned(), now)
                        .map_err(|_| SuppliedSessionInputError::InvalidCredentialValue)?;
                SuppliedSessionRuntimeInput::from(cookies)
            },
            SuppliedSessionSecretSource::FormLogin(path) => {
                let bytes =
                    read_bounded_regular_file(path, HARD_MAX_SUPPLIED_SESSION_FORM_SECRET_BYTES)
                        .map_err(SuppliedSessionInputError::CredentialSource)?;
                let credential =
                    SuppliedSessionFormCredential::parse_tsv(&self.policy, bytes.into_owned())
                        .map_err(|_| SuppliedSessionInputError::InvalidCredentialValue)?;
                SuppliedSessionRuntimeInput::from(credential)
            },
        };
        Ok((self.policy, runtime_input))
    }
}

/// Static, value-free failures for the supplied-session input boundary.
#[cfg(feature = "supplied-session-review")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SuppliedSessionInputError {
    MissingPolicy,
    MissingCredentialSource,
    ConflictingCredentialSources,
    PolicySource(AuthorizationInputError),
    InvalidPolicy,
    CredentialMechanismMismatch,
    CredentialSource(AuthorizationInputError),
    InvalidCredentialValue,
    CredentialClockUnavailable,
}

#[cfg(feature = "supplied-session-review")]
impl fmt::Display for SuppliedSessionInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingPolicy => "supplied-session review requires one policy file",
            Self::MissingCredentialSource | Self::ConflictingCredentialSources => {
                "supplied-session review requires exactly one credential source"
            },
            Self::PolicySource(_) => "supplied-session policy must be a bounded regular UTF-8 file",
            Self::InvalidPolicy => "supplied-session policy is invalid",
            Self::CredentialMechanismMismatch => {
                "supplied-session credential source does not match the selected policy acquisition"
            },
            Self::CredentialSource(_) => "supplied-session credential source could not be loaded",
            Self::InvalidCredentialValue => "supplied-session credential value is invalid",
            Self::CredentialClockUnavailable => "supplied-session credential clock is unavailable",
        })
    }
}

#[cfg(feature = "supplied-session-review")]
impl std::error::Error for SuppliedSessionInputError {}

/// One unvalidated credential source selection. The wrapper keeps the public
/// CLI flow small without exposing source identifiers through `Debug`.
#[cfg(any(
    feature = "authorization-review",
    feature = "jwt-policy-review",
    feature = "ssrf-oast-review",
    feature = "supplied-session-review"
))]
pub(crate) struct AuthorizationSourceOptions {
    environment: Option<OsString>,
    file: Option<PathBuf>,
    stdin: bool,
}

#[cfg(any(
    feature = "authorization-review",
    feature = "jwt-policy-review",
    feature = "ssrf-oast-review",
    feature = "supplied-session-review"
))]
impl AuthorizationSourceOptions {
    pub(crate) const fn new(
        environment: Option<OsString>,
        file: Option<PathBuf>,
        stdin: bool,
    ) -> Self {
        Self {
            environment,
            file,
            stdin,
        }
    }
}

#[cfg(any(
    feature = "authorization-review",
    feature = "jwt-policy-review",
    feature = "ssrf-oast-review",
    feature = "supplied-session-review"
))]
impl fmt::Debug for AuthorizationSourceOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizationSourceOptions(<redacted>)")
    }
}

/// Complete source selection for one explicit SSRF OAST query review.
///
/// The policy path, administrator source, and secret material are excluded
/// from `Debug`. Selection itself performs no I/O.
#[cfg(feature = "ssrf-oast-review")]
pub(crate) struct SsrfOastReviewInput {
    policy_file: PathBuf,
    administrator: AuthorizationInputSource,
}

/// Validated non-secret SSRF/OAST policy paired with an unread administrator
/// token source. This prevents another selected credential from being acquired
/// before every compatible local policy has completed preflight.
#[cfg(feature = "ssrf-oast-review")]
pub(crate) struct PreparedSsrfOastReviewInput {
    policy: SsrfOastReviewPolicy,
    administrator: AuthorizationInputSource,
}

#[cfg(feature = "ssrf-oast-review")]
impl fmt::Debug for SsrfOastReviewInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SsrfOastReviewInput")
            .field("policy_file", &"<redacted>")
            .field("administrator", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "ssrf-oast-review")]
impl fmt::Debug for PreparedSsrfOastReviewInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedSsrfOastReviewInput")
            .field("policy", &"<validated>")
            .field("administrator", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "ssrf-oast-review")]
impl SsrfOastReviewInput {
    /// Requires one policy and exactly one administrator-token source without
    /// reading either source.
    pub(crate) fn select(
        enabled: bool,
        policy_file: Option<PathBuf>,
        administrator: AuthorizationSourceOptions,
    ) -> Result<Option<Self>, SsrfOastReviewInputError> {
        let any_input = policy_file.is_some()
            || administrator.environment.is_some()
            || administrator.file.is_some()
            || administrator.stdin;
        if !enabled {
            return if any_input {
                Err(SsrfOastReviewInputError::ExplicitEnableRequired)
            } else {
                Ok(None)
            };
        }
        let policy_file = policy_file.ok_or(SsrfOastReviewInputError::MissingPolicy)?;
        let administrator = AuthorizationInputSource::select(
            administrator.environment,
            administrator.file,
            administrator.stdin,
        )
        .map_err(|_| SsrfOastReviewInputError::ConflictingAdministratorSources)?
        .ok_or(SsrfOastReviewInputError::MissingAdministratorSource)?;
        Ok(Some(Self {
            policy_file,
            administrator,
        }))
    }

    /// Reads and validates only the bounded UTF-8 policy. The administrator
    /// source remains unread until all compatible non-secret preflight and
    /// report-output reservation have succeeded.
    pub(crate) fn prepare(
        self,
        target: &url::Url,
    ) -> Result<PreparedSsrfOastReviewInput, SsrfOastReviewInputError> {
        let policy_source =
            read_bounded_regular_file(self.policy_file, MAX_SSRF_OAST_REVIEW_POLICY_BYTES)
                .map_err(SsrfOastReviewInputError::PolicySource)?;
        let policy_source = std::str::from_utf8(policy_source.as_slice())
            .map_err(|_| SsrfOastReviewInputError::InvalidPolicyEncoding)?;
        let policy = SsrfOastReviewPolicy::parse_toml(target, policy_source.as_bytes())
            .map_err(|_| SsrfOastReviewInputError::InvalidPolicy)?;
        Ok(PreparedSsrfOastReviewInput {
            policy,
            administrator: self.administrator,
        })
    }
}

#[cfg(feature = "ssrf-oast-review")]
impl PreparedSsrfOastReviewInput {
    /// Reads the administrator token exactly once after non-secret preflight.
    pub(crate) fn load(
        self,
    ) -> Result<(SsrfOastReviewPolicy, SsrfOastAdminToken), SsrfOastReviewInputError> {
        let administrator = self
            .administrator
            .read_bytes()
            .map_err(SsrfOastReviewInputError::AdministratorSource)
            .and_then(|bytes| {
                SsrfOastAdminToken::new(bytes.into_owned())
                    .map_err(|_| SsrfOastReviewInputError::InvalidAdministratorValue)
            })?;
        Ok((self.policy, administrator))
    }
}

/// Static, value-free failures for the SSRF OAST CLI input boundary.
#[cfg(feature = "ssrf-oast-review")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SsrfOastReviewInputError {
    ExplicitEnableRequired,
    MissingPolicy,
    MissingAdministratorSource,
    ConflictingAdministratorSources,
    PolicySource(AuthorizationInputError),
    InvalidPolicyEncoding,
    InvalidPolicy,
    AdministratorSource(AuthorizationInputError),
    InvalidAdministratorValue,
}

#[cfg(feature = "ssrf-oast-review")]
impl fmt::Display for SsrfOastReviewInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ExplicitEnableRequired => {
                "SSRF OAST query-review inputs require explicit `--ssrf-oast-review`"
            },
            Self::MissingPolicy => "SSRF OAST query review requires one policy file",
            Self::MissingAdministratorSource | Self::ConflictingAdministratorSources => {
                "SSRF OAST query review requires exactly one administrator-token source"
            },
            Self::PolicySource(_) => {
                "SSRF OAST query-review policy must be a bounded regular UTF-8 file"
            },
            Self::InvalidPolicyEncoding => "SSRF OAST query-review policy must contain valid UTF-8",
            Self::InvalidPolicy => "SSRF OAST query-review policy is invalid",
            Self::AdministratorSource(_) => {
                "SSRF OAST administrator-token source could not be loaded"
            },
            Self::InvalidAdministratorValue => "SSRF OAST administrator token is invalid",
        })
    }
}

#[cfg(feature = "ssrf-oast-review")]
impl std::error::Error for SsrfOastReviewInputError {}

#[cfg(feature = "authorization-review")]
impl fmt::Debug for AuthorizationReviewInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationReviewInput")
            .field("policy_file", &"<redacted>")
            .field("primary", &"<redacted>")
            .field("peer", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "authorization-review")]
impl AuthorizationReviewInput {
    /// Requires one policy and exactly one source for each role without reading
    /// any selected input. A shared stdin cannot represent two principals.
    pub(crate) fn select(
        policy_file: Option<PathBuf>,
        primary: AuthorizationSourceOptions,
        peer: AuthorizationSourceOptions,
    ) -> Result<Option<Self>, AuthorizationReviewInputError> {
        let any_selected = policy_file.is_some()
            || primary.environment.is_some()
            || primary.file.is_some()
            || primary.stdin
            || peer.environment.is_some()
            || peer.file.is_some()
            || peer.stdin;
        if !any_selected {
            return Ok(None);
        }

        let policy_file = policy_file.ok_or(AuthorizationReviewInputError::MissingPolicy)?;
        let both_stdin = primary.stdin && peer.stdin;
        let primary =
            AuthorizationInputSource::select(primary.environment, primary.file, primary.stdin)
                .map_err(|_| AuthorizationReviewInputError::ConflictingPrimarySources)?
                .ok_or(AuthorizationReviewInputError::MissingPrimarySource)?;
        let peer = AuthorizationInputSource::select(peer.environment, peer.file, peer.stdin)
            .map_err(|_| AuthorizationReviewInputError::ConflictingPeerSources)?
            .ok_or(AuthorizationReviewInputError::MissingPeerSource)?;
        if both_stdin {
            return Err(AuthorizationReviewInputError::AmbiguousStdin);
        }

        Ok(Some(Self {
            policy_file,
            primary,
            peer,
        }))
    }

    /// Reads the policy first, then each credential exactly once, producing the
    /// move-only scanner contracts without exposing any input bytes.
    pub(crate) fn load(
        self,
        target: &url::Url,
    ) -> Result<
        (AuthorizationReviewPolicy, AuthorizationPrincipalPair),
        AuthorizationReviewInputError,
    > {
        let policy_source =
            read_bounded_regular_file(self.policy_file, HARD_MAX_AUTHORIZATION_REVIEW_POLICY_BYTES)
                .map_err(AuthorizationReviewInputError::PolicySource)?;
        let policy = AuthorizationReviewPolicy::parse_toml(target, policy_source.as_slice())
            .map_err(|_| AuthorizationReviewInputError::InvalidPolicy)?;

        let primary = self
            .primary
            .read_bytes()
            .map_err(AuthorizationReviewInputError::PrimarySource)
            .and_then(|bytes| {
                PrimaryAuthorizationPrincipal::new(bytes.into_owned())
                    .map_err(|_| AuthorizationReviewInputError::InvalidPrimaryValue)
            })?;
        let peer = self
            .peer
            .read_bytes()
            .map_err(AuthorizationReviewInputError::PeerSource)
            .and_then(|bytes| {
                PeerAuthorizationPrincipal::new(bytes.into_owned())
                    .map_err(|_| AuthorizationReviewInputError::InvalidPeerValue)
            })?;
        let principals = AuthorizationPrincipalPair::new(primary, peer)
            .map_err(|_| AuthorizationReviewInputError::PrincipalsNotDistinct)?;
        Ok((policy, principals))
    }
}

/// Static, value-free failures for the two-principal CLI boundary.
#[cfg(feature = "authorization-review")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorizationReviewInputError {
    MissingPolicy,
    MissingPrimarySource,
    MissingPeerSource,
    ConflictingPrimarySources,
    ConflictingPeerSources,
    AmbiguousStdin,
    PolicySource(AuthorizationInputError),
    InvalidPolicy,
    PrimarySource(AuthorizationInputError),
    PeerSource(AuthorizationInputError),
    InvalidPrimaryValue,
    InvalidPeerValue,
    PrincipalsNotDistinct,
}

#[cfg(feature = "authorization-review")]
impl fmt::Display for AuthorizationReviewInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingPolicy => "authorization review requires one policy file",
            Self::MissingPrimarySource => {
                "authorization review requires exactly one primary input source"
            },
            Self::MissingPeerSource => {
                "authorization review requires exactly one peer input source"
            },
            Self::ConflictingPrimarySources => {
                "authorization review requires exactly one primary input source"
            },
            Self::ConflictingPeerSources => {
                "authorization review requires exactly one peer input source"
            },
            Self::AmbiguousStdin => {
                "authorization review cannot read both principal contexts from stdin"
            },
            Self::PolicySource(_) => "authorization review policy must be a bounded regular file",
            Self::InvalidPolicy => "authorization review policy is invalid",
            Self::PrimarySource(_) => {
                "authorization review primary input source could not be loaded"
            },
            Self::PeerSource(_) => "authorization review peer input source could not be loaded",
            Self::InvalidPrimaryValue => {
                "authorization review primary value is not a safe HTTP header value"
            },
            Self::InvalidPeerValue => {
                "authorization review peer value is not a safe HTTP header value"
            },
            Self::PrincipalsNotDistinct => {
                "authorization review requires distinct principal credentials"
            },
        })
    }
}

#[cfg(feature = "authorization-review")]
impl std::error::Error for AuthorizationReviewInputError {}

/// Static, credential-free authorization input failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorizationInputError {
    ConflictingSources,
    SourceNameInvalid,
    SourceUnavailable,
    SourceNotRegularFile,
    SourceNotUnicode,
    SourceReadFailed,
    ValueTooLarge,
    InvalidValue,
}

impl fmt::Display for AuthorizationInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ConflictingSources => "select exactly one authorization-context input source",
            Self::SourceNameInvalid => "authorization-context environment name is invalid",
            Self::SourceUnavailable => "authorization-context input source is unavailable",
            Self::SourceNotRegularFile => {
                "authorization-context file source must be a regular file"
            },
            Self::SourceNotUnicode => {
                "authorization-context environment value is not valid Unicode"
            },
            Self::SourceReadFailed => "authorization-context input source could not be read",
            Self::ValueTooLarge => "authorization-context value exceeds the compiled byte limit",
            Self::InvalidValue => "authorization-context value is not a safe HTTP header value",
        })
    }
}

impl std::error::Error for AuthorizationInputError {}

#[cfg(test)]
fn read_environment(name: OsString) -> Result<CredentialBytes, AuthorizationInputError> {
    read_environment_with_limit(name, MAX_AUTHORIZATION_CONTEXT_BYTES)
}

fn read_environment_with_limit(
    name: OsString,
    max_bytes: usize,
) -> Result<CredentialBytes, AuthorizationInputError> {
    let name = name
        .into_string()
        .map_err(|_| AuthorizationInputError::SourceNameInvalid)?;
    if name.is_empty()
        || name
            .chars()
            .any(|character| matches!(character, '=' | '\0'))
    {
        return Err(AuthorizationInputError::SourceNameInvalid);
    }
    let value = std::env::var_os(name).ok_or(AuthorizationInputError::SourceUnavailable)?;
    validate_environment_value_with_limit(value, max_bytes)
}

#[cfg(test)]
fn validate_environment_value(value: OsString) -> Result<CredentialBytes, AuthorizationInputError> {
    validate_environment_value_with_limit(value, MAX_AUTHORIZATION_CONTEXT_BYTES)
}

fn validate_environment_value_with_limit(
    value: OsString,
    max_bytes: usize,
) -> Result<CredentialBytes, AuthorizationInputError> {
    // Take ownership of the returned environment-value allocation without an
    // invalid-Unicode conversion error dropping an unguarded OsString.
    let bytes = CredentialBytes::new(value.into_encoded_bytes());
    std::str::from_utf8(bytes.as_slice()).map_err(|_| AuthorizationInputError::SourceNotUnicode)?;
    if bytes.as_slice().len() > max_bytes {
        return Err(AuthorizationInputError::ValueTooLarge);
    }
    Ok(bytes)
}

pub(super) fn open_regular_file(path: PathBuf) -> Result<File, AuthorizationInputError> {
    // Only the final component is no-follow. Parent directories must be trusted;
    // this is neither whole-path containment nor an immutable content snapshot.
    validate_opened_regular_file(open_no_follow(&path)?)
}

#[cfg(unix)]
fn open_no_follow(path: &std::path::Path) -> Result<File, AuthorizationInputError> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .read(true)
        // A FIFO must not block opening before its handle is rejected.
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(libc::ELOOP) {
                AuthorizationInputError::SourceNotRegularFile
            } else {
                AuthorizationInputError::SourceUnavailable
            }
        })
}

#[cfg(windows)]
fn open_no_follow(path: &std::path::Path) -> Result<File, AuthorizationInputError> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    std::fs::OpenOptions::new()
        .read(true)
        // Directory/reparse handles are rejected before reading their content.
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        // SECURITY_ANONYMOUS: no named-pipe impersonation before metadata rejects
        // non-files. Opening a special/network path may still contact its owner.
        .security_qos_flags(0)
        .open(path)
        .map_err(|_| AuthorizationInputError::SourceUnavailable)
}

#[cfg(not(any(unix, windows)))]
fn open_no_follow(_: &std::path::Path) -> Result<File, AuthorizationInputError> {
    Err(AuthorizationInputError::SourceUnavailable)
}

fn validate_opened_regular_file(file: File) -> Result<File, AuthorizationInputError> {
    let opened_metadata = file
        .metadata()
        .map_err(|_| AuthorizationInputError::SourceUnavailable)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if opened_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(AuthorizationInputError::SourceNotRegularFile);
        }
    }
    if !opened_metadata.is_file() {
        return Err(AuthorizationInputError::SourceNotRegularFile);
    }
    Ok(file)
}

#[cfg(any(
    feature = "authorization-review",
    feature = "jwt-policy-review",
    feature = "ssrf-oast-review",
    feature = "supplied-session-review"
))]
fn read_bounded_regular_file(
    path: PathBuf,
    max_bytes: usize,
) -> Result<CredentialBytes, AuthorizationInputError> {
    let mut file = open_regular_file(path)?;
    ensure_opened_file_length(&file, max_bytes)?;
    let retained = max_bytes.saturating_add(1);
    let bytes = read_bounded_bytes(&mut file, retained)?;
    if bytes.as_slice().len() > max_bytes {
        return Err(AuthorizationInputError::ValueTooLarge);
    }
    Ok(bytes)
}

fn ensure_opened_file_length(file: &File, max_bytes: usize) -> Result<(), AuthorizationInputError> {
    let length = file
        .metadata()
        .map_err(|_| AuthorizationInputError::SourceUnavailable)?
        .len();
    if length > u64::try_from(max_bytes).unwrap_or(u64::MAX) {
        return Err(AuthorizationInputError::ValueTooLarge);
    }
    Ok(())
}

/// Reads at most the credential ceiling plus one terminal CRLF and then probes
/// for one additional byte so a longer stream cannot masquerade as an exact
/// `MAX + CRLF` value. Only one terminal LF or CRLF is removed; no trimming or
/// lossy decoding occurs.
#[cfg(test)]
fn read_bounded_line_source(
    reader: &mut impl Read,
) -> Result<CredentialBytes, AuthorizationInputError> {
    read_bounded_line_source_with_limit(reader, MAX_AUTHORIZATION_CONTEXT_BYTES)
}

fn read_bounded_line_source_with_limit(
    reader: &mut impl Read,
    max_bytes: usize,
) -> Result<CredentialBytes, AuthorizationInputError> {
    let retained_limit = max_bytes.saturating_add(2);
    let mut bytes = read_bounded_bytes(reader, retained_limit)?;
    let mut overflow = Zeroizing::new([0_u8; 1]);
    if read_overflow_byte(reader, &mut overflow)? != 0 {
        return Err(AuthorizationInputError::ValueTooLarge);
    }

    let retained = wipe_terminal_line_ending(bytes.bytes.as_mut_slice());
    bytes.bytes.truncate(retained);
    if bytes.as_slice().len() > max_bytes {
        return Err(AuthorizationInputError::ValueTooLarge);
    }
    Ok(bytes)
}

fn read_bounded_bytes(
    reader: &mut impl Read,
    retained_limit: usize,
) -> Result<CredentialBytes, AuthorizationInputError> {
    // Fixed, initialized storage prevents credential-bearing reallocations and
    // also covers bytes written by a reader before it returns an error.
    let mut bytes = CredentialBytes::new(vec![0; retained_limit]);
    let mut filled = 0;
    while filled < retained_limit {
        match reader.read(&mut bytes.bytes[filled..]) {
            Ok(0) => break,
            Ok(count) => {
                filled = filled
                    .checked_add(count)
                    .filter(|filled| *filled <= retained_limit)
                    .ok_or(AuthorizationInputError::SourceReadFailed)?;
            },
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(AuthorizationInputError::SourceReadFailed),
        }
    }
    bytes.bytes[filled..].zeroize();
    bytes.bytes.truncate(filled);
    Ok(bytes)
}

fn read_overflow_byte(
    reader: &mut impl Read,
    overflow: &mut [u8; 1],
) -> Result<usize, AuthorizationInputError> {
    let result = reader
        .read(overflow)
        .map_err(|_| AuthorizationInputError::SourceReadFailed);
    overflow.zeroize();
    result
}

fn wipe_terminal_line_ending(bytes: &mut [u8]) -> usize {
    let removed = if bytes.ends_with(b"\r\n") {
        2
    } else if bytes.ends_with(b"\n") {
        1
    } else {
        0
    };
    let retained = bytes.len().saturating_sub(removed);
    bytes[retained..].zeroize();
    retained
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor, Read};

    use super::*;

    #[cfg(feature = "jwt-policy-review")]
    use termivar_scanner::jwt_policy_review::{
        JwtExternalOperationStatus, JwtLocalSignatureStatus, JwtParsingStatus,
        JwtTargetAcceptanceStatus,
    };

    #[cfg(feature = "jwt-policy-review")]
    const RFC7515_PUBLIC_JWK: &str = r#"{"kty":"EC","crv":"P-256","alg":"ES256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;
    #[cfg(feature = "jwt-policy-review")]
    const RFC7515_ES256_JWS: &str = concat!(
        "eyJhbGciOiJFUzI1NiJ9.",
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt",
        "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ.",
        "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA",
        "pmWQxfKTUJqPP3-Kg6NU1Q"
    );

    #[cfg(feature = "jwt-policy-review")]
    fn jwt_policy_source() -> &'static str {
        r#"schema = "security.jwt-local-policy/v1"
policy_reference = "rfc7515-local"
policy_revision = "rfc7515-local-v1"
expected_type = "JWT"
expected_issuer = "joe"
expected_audience = "termivar-fixture"
required_claims = ["http://example.com/is_root"]
require_expiration = true
allowed_clock_skew_seconds = 0
"#
    }

    #[cfg(feature = "jwt-policy-review")]
    fn select_local_jwt_input(
        policy_file: Option<PathBuf>,
        public_jwk_file: Option<PathBuf>,
        token: AuthorizationSourceOptions,
    ) -> Result<Option<JwtPolicyReviewInput>, JwtPolicyInputError> {
        JwtPolicyReviewInput::select(
            policy_file,
            public_jwk_file,
            token,
            #[cfg(feature = "jwt-target-acceptance-review")]
            None,
        )
    }

    #[cfg(feature = "jwt-policy-review")]
    fn prepare_local_jwt_input(
        input: JwtPolicyReviewInput,
    ) -> Result<PreparedJwtPolicyReviewInput, JwtPolicyInputError> {
        input.prepare(
            #[cfg(feature = "jwt-target-acceptance-review")]
            &url::Url::parse("https://owned.example.test/app/").unwrap(),
        )
    }

    #[cfg(feature = "jwt-policy-review")]
    fn load_local_jwt_input(
        input: PreparedJwtPolicyReviewInput,
    ) -> Result<JwtPolicyReviewAudit, JwtPolicyInputError> {
        #[cfg(not(feature = "jwt-target-acceptance-review"))]
        {
            input.load()
        }
        #[cfg(feature = "jwt-target-acceptance-review")]
        {
            let loaded = input.load()?;
            let (audit, target_acceptance) = loaded.into_parts();
            assert!(target_acceptance.is_none());
            Ok(audit)
        }
    }

    #[cfg(feature = "jwt-target-acceptance-review")]
    fn jwt_target_acceptance_policy_source(application: &url::Url) -> String {
        format!(
            concat!(
                "schema = \"security.jwt-target-acceptance-policy/v1\"\n",
                "policy_reference = \"owned-target-acceptance\"\n",
                "policy_revision = \"owned-target-acceptance-v1\"\n",
                "application = \"{}\"\n",
                "resource = \"{}protected/marker\"\n",
                "resource_reference = \"protected-marker\"\n",
                "success_json_field = \"accepted\"\n"
            ),
            application, application,
        )
    }

    #[cfg(feature = "jwt-policy-review")]
    #[test]
    fn jwt_input_selection_and_debug_redact_all_sources() {
        assert!(select_local_jwt_input(
            None,
            None,
            AuthorizationSourceOptions::new(None, None, false),
        )
        .unwrap()
        .is_none());
        assert!(matches!(
            select_local_jwt_input(
                Some(PathBuf::from("POLICY-MUST-NOT-LEAK")),
                None,
                AuthorizationSourceOptions::new(None, None, false),
            ),
            Err(JwtPolicyInputError::MissingPublicKey)
        ));
        assert!(matches!(
            select_local_jwt_input(
                Some(PathBuf::from("POLICY-MUST-NOT-LEAK")),
                Some(PathBuf::from("KEY-MUST-NOT-LEAK")),
                AuthorizationSourceOptions::new(
                    Some(OsString::from("TOKEN-ENV-MUST-NOT-LEAK")),
                    Some(PathBuf::from("TOKEN-FILE-MUST-NOT-LEAK")),
                    false,
                ),
            ),
            Err(JwtPolicyInputError::ConflictingTokenSources)
        ));
        let input = select_local_jwt_input(
            Some(PathBuf::from("POLICY-MUST-NOT-LEAK")),
            Some(PathBuf::from("KEY-MUST-NOT-LEAK")),
            AuthorizationSourceOptions::new(
                Some(OsString::from("TOKEN-ENV-MUST-NOT-LEAK")),
                None,
                false,
            ),
        )
        .unwrap()
        .unwrap();
        let debug = format!("{input:?}");
        assert!(!debug.contains("MUST-NOT-LEAK"));
        assert_eq!(
            JwtPolicyInputError::TokenSource(AuthorizationInputError::SourceUnavailable)
                .to_string(),
            "JWT token source could not be loaded"
        );
    }

    #[cfg(all(feature = "jwt-policy-review", windows))]
    #[test]
    fn jwt_windows_file_inputs_reject_remote_and_special_spellings_before_open() {
        for rejected in [
            r"\\server\share\policy.toml",
            r"\\?\UNC\server\share\policy.toml",
            r"\\.\pipe\termivar-jwt-policy",
            r"\\?\GLOBALROOT\Device\NamedPipe\termivar-jwt-policy",
            r"\??\C:\termivar\policy.toml",
            r"\Device\HarddiskVolume1\termivar\policy.toml",
            r"\GLOBAL??\termivar\policy.toml",
            r"\pipe\termivar-jwt-policy",
            r"C:\termivar\NUL",
            r"C:\termivar\con.txt",
            r"C:\termivar\aux .toml",
            r"C:\termivar\COM1.jwt",
            r"C:\termivar\LPT9",
            r"C:\termivar\com¹.secret",
            r"C:\termivar\policy.toml:stream",
        ] {
            assert_eq!(
                validate_local_file_path(Path::new(rejected)),
                Err(AuthorizationInputError::SourceUnavailable),
                "special JWT file spelling was accepted"
            );
        }

        for accepted in [
            r"C:\termivar\policy.toml",
            r"C:termivar\relative-policy.toml",
            r"\\?\C:\termivar\policy.toml",
            r"relative\policy.toml",
            r"relative\com10.toml",
            r"relative\pipeline.toml",
        ] {
            assert_eq!(validate_local_file_path(Path::new(accepted)), Ok(()));
        }

        let local_policy = PathBuf::from(r"C:\termivar\policy.toml");
        let local_jwk = PathBuf::from(r"C:\termivar\public.jwk");
        let local_token = PathBuf::from(r"C:\termivar\token.secret");
        let named_pipe = PathBuf::from(r"\\.\pipe\termivar-jwt-must-not-open");
        for (error, expected) in [
            (
                select_local_jwt_input(
                    Some(named_pipe.clone()),
                    Some(local_jwk.clone()),
                    AuthorizationSourceOptions::new(None, Some(local_token.clone()), false),
                )
                .unwrap_err(),
                "policy",
            ),
            (
                select_local_jwt_input(
                    Some(local_policy.clone()),
                    Some(named_pipe.clone()),
                    AuthorizationSourceOptions::new(None, Some(local_token.clone()), false),
                )
                .unwrap_err(),
                "public-key",
            ),
            (
                select_local_jwt_input(
                    Some(local_policy.clone()),
                    Some(local_jwk.clone()),
                    AuthorizationSourceOptions::new(None, Some(named_pipe.clone()), false),
                )
                .unwrap_err(),
                "token",
            ),
        ] {
            match (expected, &error) {
                (
                    "policy",
                    JwtPolicyInputError::PolicySource(AuthorizationInputError::SourceUnavailable),
                )
                | (
                    "public-key",
                    JwtPolicyInputError::PublicKeySource(
                        AuthorizationInputError::SourceUnavailable,
                    ),
                )
                | (
                    "token",
                    JwtPolicyInputError::TokenSource(AuthorizationInputError::SourceUnavailable),
                ) => {},
                _ => panic!("{expected} path produced the wrong path-safe error: {error:?}"),
            }
            assert!(!format!("{error:?}").contains("termivar-jwt-must-not-open"));
        }
    }

    #[cfg(feature = "jwt-policy-review")]
    #[test]
    fn jwt_policy_and_public_key_preflight_precede_token_read() {
        let directory = tempfile::tempdir().unwrap();
        let policy = directory.path().join("policy.toml");
        let key = directory.path().join("public.jwk");
        std::fs::write(&policy, "schema = \"wrong\"").unwrap();
        std::fs::write(&key, RFC7515_PUBLIC_JWK).unwrap();
        let missing_token = directory.path().join("TOKEN-MUST-NOT-BE-OPENED");
        let input = select_local_jwt_input(
            Some(policy),
            Some(key),
            AuthorizationSourceOptions::new(None, Some(missing_token), false),
        )
        .unwrap()
        .unwrap();
        let error = prepare_local_jwt_input(input).unwrap_err();
        assert!(matches!(error, JwtPolicyInputError::InvalidPolicy));
    }

    #[cfg(feature = "jwt-policy-review")]
    #[test]
    fn jwt_policy_requires_type_issuer_and_audience_before_token_read() {
        for missing in [
            "policy_revision",
            "expected_type",
            "expected_issuer",
            "expected_audience",
        ] {
            let directory = tempfile::tempdir().unwrap();
            let policy = directory.path().join("policy.toml");
            let key = directory.path().join("public.jwk");
            let missing_token = directory.path().join("TOKEN-MUST-NOT-BE-OPENED");
            let source = jwt_policy_source()
                .lines()
                .filter(|line| !line.starts_with(missing))
                .collect::<Vec<_>>()
                .join("\n");
            std::fs::write(&policy, source).unwrap();
            std::fs::write(&key, RFC7515_PUBLIC_JWK).unwrap();
            let input = select_local_jwt_input(
                Some(policy),
                Some(key),
                AuthorizationSourceOptions::new(None, Some(missing_token), false),
            )
            .unwrap()
            .unwrap();
            let error = prepare_local_jwt_input(input).unwrap_err();
            assert!(matches!(error, JwtPolicyInputError::InvalidPolicy));
        }
    }

    #[cfg(feature = "jwt-target-acceptance-review")]
    #[test]
    fn jwt_target_policy_preflight_follows_local_inputs_and_precedes_token_read() {
        let directory = tempfile::tempdir().unwrap();
        let policy = directory.path().join("policy.toml");
        let key = directory.path().join("public.jwk");
        let target_policy = directory.path().join("target-policy.toml");
        let missing_target_policy = directory.path().join("MISSING-TARGET-POLICY");
        let missing_token = directory.path().join("TOKEN-MUST-NOT-BE-OPENED");
        let application = url::Url::parse("https://owned.example.test/app/").unwrap();

        let select = |target_policy_file: PathBuf| {
            JwtPolicyReviewInput::select(
                Some(policy.clone()),
                Some(key.clone()),
                AuthorizationSourceOptions::new(None, Some(missing_token.clone()), false),
                Some(target_policy_file),
            )
            .unwrap()
            .unwrap()
        };

        std::fs::write(&policy, "schema = \"wrong\"").unwrap();
        std::fs::write(&key, RFC7515_PUBLIC_JWK).unwrap();
        assert!(matches!(
            select(missing_target_policy.clone())
                .prepare(&application)
                .unwrap_err(),
            JwtPolicyInputError::InvalidPolicy
        ));

        std::fs::write(&policy, jwt_policy_source()).unwrap();
        std::fs::write(&key, "{}").unwrap();
        assert!(matches!(
            select(missing_target_policy)
                .prepare(&application)
                .unwrap_err(),
            JwtPolicyInputError::InvalidPublicKey
        ));

        std::fs::write(&key, RFC7515_PUBLIC_JWK).unwrap();
        std::fs::write(&target_policy, "schema = \"wrong\"").unwrap();
        assert!(matches!(
            select(target_policy.clone())
                .prepare(&application)
                .unwrap_err(),
            JwtPolicyInputError::InvalidTargetPolicy
        ));

        let canonical_resource = format!("{application}protected/marker");
        for unsafe_resource in [
            format!("{application}safe/../protected/marker"),
            format!("{application}safe/%2e%2e/protected/marker"),
            format!(r"{application}safe\..\protected\marker"),
        ] {
            let source = jwt_target_acceptance_policy_source(&application)
                .replace(&canonical_resource, &unsafe_resource);
            std::fs::write(&target_policy, source).unwrap();
            assert!(matches!(
                select(target_policy.clone())
                    .prepare(&application)
                    .unwrap_err(),
                JwtPolicyInputError::InvalidTargetPolicy
            ));
        }

        std::fs::write(
            &target_policy,
            jwt_target_acceptance_policy_source(&application),
        )
        .unwrap();
        let error = select(target_policy)
            .prepare(&application)
            .unwrap()
            .load()
            .unwrap_err();
        assert!(matches!(
            error,
            JwtPolicyInputError::TokenSource(AuthorizationInputError::SourceUnavailable)
        ));
    }

    #[cfg(feature = "jwt-target-acceptance-review")]
    #[test]
    fn jwt_target_policy_urls_require_exact_raw_canonical_spelling() {
        let canonical = "https://owned.example.test/app/protected/marker";
        assert_eq!(
            parse_exact_jwt_target_policy_url(canonical)
                .unwrap()
                .as_str(),
            canonical
        );
        for normalized_away in [
            "https://owned.example.test/app/safe/%2e%2e/protected/marker",
            r"https://owned.example.test/app/safe\..\protected\marker",
        ] {
            assert_eq!(
                url::Url::parse(normalized_away).unwrap().as_str(),
                canonical,
                "the underlying parser no longer reproduces the guarded normalization"
            );
            assert!(parse_exact_jwt_target_policy_url(normalized_away).is_err());
        }
        for rejected in [
            "https://owned.example.test/app/./protected/marker",
            "https://owned.example.test/app/safe/../protected/marker",
            "https://owned.example.test/app/safe/%2e%2e/protected/marker",
            r"https://owned.example.test/app\protected\marker",
            r"https:\\owned.example.test\app\protected\marker",
            "HTTPS://OWNED.EXAMPLE.TEST/app/protected/marker",
            "https://owned.example.test:443/app/protected/marker",
            "https://owned.example.test",
            " https://owned.example.test/app/protected/marker",
            "https://owned.example.test/app/protected/marker\n",
        ] {
            assert!(
                parse_exact_jwt_target_policy_url(rejected).is_err(),
                "non-canonical authority spelling was accepted: {rejected:?}"
            );
        }
    }

    #[cfg(feature = "jwt-policy-review")]
    #[test]
    fn jwt_input_loads_once_and_preserves_four_separate_states() {
        let directory = tempfile::tempdir().unwrap();
        let policy = directory.path().join("policy.toml");
        let key = directory.path().join("public.jwk");
        let token = directory.path().join("token.secret");
        std::fs::write(&policy, jwt_policy_source()).unwrap();
        std::fs::write(&key, RFC7515_PUBLIC_JWK).unwrap();
        std::fs::write(&token, format!("{RFC7515_ES256_JWS}\r\n")).unwrap();
        let input = select_local_jwt_input(
            Some(policy),
            Some(key),
            AuthorizationSourceOptions::new(None, Some(token), false),
        )
        .unwrap()
        .unwrap();
        let prepared = prepare_local_jwt_input(input).unwrap();
        let audit = load_local_jwt_input(prepared).unwrap();
        assert_eq!(audit.parsing_status(), JwtParsingStatus::Parsed);
        assert_eq!(
            audit.local_signature_status(),
            JwtLocalSignatureStatus::Verified
        );
        assert_eq!(
            audit.target_acceptance_status(),
            JwtTargetAcceptanceStatus::NotPerformed
        );
        assert_eq!(audit.external_activity().target_request_count(), 0);
        assert_eq!(
            audit.external_activity().remote_key_retrieval(),
            JwtExternalOperationStatus::NotPerformed
        );
        assert_eq!(
            audit.external_activity().token_forwarding(),
            JwtExternalOperationStatus::NotPerformed
        );
    }

    #[test]
    fn opened_secret_handle_survives_final_path_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credential");
        let retained_path = directory.path().join("retained");
        std::fs::write(&path, b"Bearer original").unwrap();
        let opened = open_no_follow(&path).unwrap();
        std::fs::rename(&path, &retained_path).unwrap();
        std::fs::write(&path, b"Bearer replacement").unwrap();
        let mut validated = validate_opened_regular_file(opened).unwrap();
        let mut bytes = Vec::new();
        validated.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"Bearer original");
    }

    #[test]
    fn directory_handle_is_rejected_before_reading() {
        let directory = tempfile::tempdir().unwrap();
        let opened = open_no_follow(directory.path()).unwrap();
        assert_eq!(
            validate_opened_regular_file(opened).unwrap_err(),
            AuthorizationInputError::SourceNotRegularFile
        );
    }

    #[cfg(unix)]
    #[test]
    fn replaced_final_symlink_is_not_followed() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credential");
        let original = directory.path().join("original");
        let destination = directory.path().join("destination");
        std::fs::write(&path, b"Bearer original").unwrap();
        std::fs::write(&destination, b"Bearer replacement").unwrap();
        std::fs::rename(&path, &original).unwrap();
        symlink(&destination, &path).unwrap();
        assert_eq!(
            open_regular_file(path).unwrap_err(),
            AuthorizationInputError::SourceNotRegularFile
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_opened_reparse_handle_is_rejected() {
        use std::os::windows::fs::MetadataExt;
        use std::process::{Command, Stdio};

        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("destination");
        let link = directory.path().join("link");
        std::fs::create_dir(&destination).unwrap();
        // Directory junctions exercise the same final-component reparse-point
        // rejection without requiring Developer Mode or SeCreateSymbolicLink.
        let result = Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&link)
            .arg(&destination)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(result.success(), "Windows junction fixture creation failed");
        let opened = open_no_follow(&link).unwrap();
        assert_ne!(
            opened.metadata().unwrap().file_attributes() & 0x0000_0400,
            0
        );
        assert_eq!(
            validate_opened_regular_file(opened).unwrap_err(),
            AuthorizationInputError::SourceNotRegularFile
        );
    }

    #[test]
    fn opened_secret_size_is_checked_even_after_path_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credential");
        let original = directory.path().join("original");
        std::fs::write(&path, vec![b'x'; MAX_AUTHORIZATION_CONTEXT_BYTES + 3]).unwrap();
        let opened = open_regular_file(path.clone()).unwrap();
        std::fs::rename(&path, &original).unwrap();
        std::fs::write(&path, b"Bearer replacement").unwrap();
        assert_eq!(
            ensure_opened_file_length(&opened, MAX_AUTHORIZATION_CONTEXT_BYTES + 2).unwrap_err(),
            AuthorizationInputError::ValueTooLarge
        );
    }

    fn take_intake_drops() -> Vec<(usize, bool)> {
        INTAKE_DROPS.with(|drops| std::mem::take(&mut *drops.borrow_mut()))
    }

    #[test]
    fn guarded_intake_erases_live_storage_and_redacts_debug() {
        take_intake_drops();
        let input = CredentialBytes::new(b"INTAKE-PRIVATE-SENTINEL".to_vec());
        assert_eq!(format!("{input:?}"), "CredentialBytes(<redacted>)");
        let length = input.as_slice().len();
        drop(input);
        assert_eq!(take_intake_drops(), [(length, true)]);
    }

    #[test]
    fn handoff_moves_the_allocation_and_ends_only_the_cli_guard() {
        take_intake_drops();
        let input = read_bounded_line_source(&mut Cursor::new(b"Bearer handoff\r\n")).unwrap();
        let allocation = input.as_slice().as_ptr();
        let owned = input.into_owned();
        // Both pointers refer to the same still-live, now receiver-owned Vec.
        // No pointer is dereferenced after that allocation is released.
        assert_eq!(owned.as_ptr(), allocation);
        assert_eq!(owned, b"Bearer handoff");
        assert_eq!(take_intake_drops(), [(0, true)]);
        // This synthetic receiver explicitly guards its own lifetime. Real
        // root/principal constructors may copy; that is outside CLI coverage.
        let receiver = Zeroizing::new(owned);
        assert_eq!(receiver.as_slice(), b"Bearer handoff");
    }

    #[test]
    fn environment_size_and_encoding_validation_happen_inside_the_guard() {
        take_intake_drops();
        let oversized = OsString::from("x".repeat(MAX_AUTHORIZATION_CONTEXT_BYTES + 1));
        assert_eq!(
            validate_environment_value(oversized).unwrap_err(),
            AuthorizationInputError::ValueTooLarge
        );
        assert_eq!(
            take_intake_drops(),
            [(MAX_AUTHORIZATION_CONTEXT_BYTES + 1, true)]
        );
        let input = validate_environment_value(OsString::from("Bearer unchanged\n")).unwrap();
        assert_eq!(input.as_slice(), b"Bearer unchanged\n");
        drop(input);
        assert_eq!(take_intake_drops(), [(17, true)]);
        let unicode = validate_environment_value(OsString::from("\u{00e9}")).unwrap();
        assert_eq!(unicode.as_slice(), "\u{00e9}".as_bytes());
        drop(unicode);
        assert_eq!(take_intake_drops(), [(2, true)]);
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn invalid_unicode_environment_storage_is_erased_before_release() {
        #[cfg(unix)]
        let invalid = {
            use std::os::unix::ffi::OsStringExt;
            OsString::from_vec(vec![0xff])
        };
        #[cfg(windows)]
        let invalid = {
            use std::os::windows::ffi::OsStringExt;
            OsString::from_wide(&[0xd800])
        };
        take_intake_drops();
        assert_eq!(
            validate_environment_value(invalid).unwrap_err(),
            AuthorizationInputError::SourceNotUnicode
        );
        let drops = take_intake_drops();
        assert_eq!(drops.len(), 1);
        assert!(drops[0].0 > 0);
        assert!(drops[0].1);
    }

    struct PartialErrorReader {
        calls: usize,
    }

    impl Read for PartialErrorReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.calls += 1;
            buffer[..7].copy_from_slice(b"private");
            if self.calls == 1 {
                Ok(7)
            } else {
                // These bytes were written but not reported as initialized by
                // a successful read. The fixed initialized guard covers them.
                Err(io::Error::other("PRIVATE-PARTIAL-READ"))
            }
        }
    }

    #[test]
    fn partial_read_failure_erases_reported_and_unreported_bytes() {
        take_intake_drops();
        let mut reader = PartialErrorReader { calls: 0 };
        assert_eq!(
            read_bounded_line_source(&mut reader).unwrap_err(),
            AuthorizationInputError::SourceReadFailed
        );
        assert_eq!(reader.calls, 2);
        assert_eq!(
            take_intake_drops(),
            [(MAX_AUTHORIZATION_CONTEXT_BYTES + 2, true)]
        );
    }

    struct InterruptedReader {
        interrupted: bool,
        input: Cursor<&'static [u8]>,
    }

    impl Read for InterruptedReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                Err(io::Error::from(io::ErrorKind::Interrupted))
            } else {
                self.input.read(buffer)
            }
        }
    }

    #[test]
    fn bounded_read_retries_interrupted_reads_without_reallocation() {
        let mut reader = InterruptedReader {
            interrupted: false,
            input: Cursor::new(b"value"),
        };
        let value = read_bounded_bytes(&mut reader, 8).unwrap();
        assert!(reader.interrupted);
        assert_eq!(value.as_slice(), b"value");
        assert_eq!(value.bytes.capacity(), 8);
        assert!(read_bounded_bytes(&mut FailingReader, 0)
            .unwrap()
            .as_slice()
            .is_empty());
    }

    struct OverReportingReader {
        first: bool,
    }

    impl Read for OverReportingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            if self.first {
                self.first = false;
                Ok(1)
            } else {
                Ok(usize::MAX)
            }
        }
    }

    #[test]
    fn impossible_read_counts_fail_closed_while_storage_is_guarded() {
        for first in [false, true] {
            take_intake_drops();
            assert_eq!(
                read_bounded_bytes(&mut OverReportingReader { first }, 2).unwrap_err(),
                AuthorizationInputError::SourceReadFailed
            );
            assert_eq!(take_intake_drops(), [(2, true)]);
        }
    }

    #[test]
    fn oversize_failure_drops_the_retained_guard_without_handoff() {
        take_intake_drops();
        let input = vec![b'x'; MAX_AUTHORIZATION_CONTEXT_BYTES + 3];
        assert_eq!(
            read_bounded_line_source(&mut Cursor::new(input)).unwrap_err(),
            AuthorizationInputError::ValueTooLarge
        );
        assert_eq!(
            take_intake_drops(),
            [(MAX_AUTHORIZATION_CONTEXT_BYTES + 2, true)]
        );
    }

    struct OverflowErrorReader;

    impl Read for OverflowErrorReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            buffer[0] = b'x';
            Err(io::Error::other("PRIVATE-OVERFLOW-READ"))
        }
    }

    #[test]
    fn overflow_probe_erases_its_live_byte_on_success_eof_and_error() {
        let mut overflow = *b"x";
        assert_eq!(
            read_overflow_byte(&mut Cursor::new(b"x"), &mut overflow),
            Ok(1)
        );
        assert_eq!(overflow, [0]);
        assert_eq!(
            read_overflow_byte(&mut Cursor::new(b""), &mut overflow),
            Ok(0)
        );
        assert_eq!(overflow, [0]);
        assert_eq!(
            read_overflow_byte(&mut OverflowErrorReader, &mut overflow),
            Err(AuthorizationInputError::SourceReadFailed)
        );
        assert_eq!(overflow, [0]);
    }

    struct ErrorAfterBody {
        remaining: usize,
    }

    impl Read for ErrorAfterBody {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                buffer[0] = b'x';
                return Err(io::Error::other("PRIVATE-PROBE-FAILURE"));
            }
            let read = buffer.len().min(self.remaining);
            buffer[..read].fill(b'a');
            self.remaining -= read;
            Ok(read)
        }
    }

    #[test]
    fn overflow_read_failure_also_drops_the_full_retained_guard() {
        take_intake_drops();
        assert_eq!(
            read_bounded_line_source(&mut ErrorAfterBody {
                remaining: MAX_AUTHORIZATION_CONTEXT_BYTES + 2,
            })
            .unwrap_err(),
            AuthorizationInputError::SourceReadFailed
        );
        assert_eq!(
            take_intake_drops(),
            [(MAX_AUTHORIZATION_CONTEXT_BYTES + 2, true)]
        );
    }

    #[test]
    fn removed_line_ending_bytes_are_wiped_before_truncation() {
        for (input, retained) in [
            (b"value\n".as_slice(), 5),
            (b"value\r\n".as_slice(), 5),
            (b"value\r".as_slice(), 6),
            (b"value\n\n".as_slice(), 6),
            (b"".as_slice(), 0),
        ] {
            let mut owned = Zeroizing::new(input.to_vec());
            assert_eq!(wipe_terminal_line_ending(&mut owned), retained);
            assert_eq!(&owned[..retained], &input[..retained]);
            assert!(owned[retained..].iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn source_selection_is_exact_and_debug_is_redacted() {
        assert!(AuthorizationInputSource::select(None, None, false)
            .unwrap()
            .is_none());
        let source = AuthorizationInputSource::select(
            Some(OsString::from("AUTH_SOURCE_NAME_SENTINEL")),
            None,
            false,
        )
        .unwrap()
        .unwrap();
        let debug = format!("{source:?}");
        assert!(debug.contains("environment"));
        assert!(!debug.contains("AUTH_SOURCE_NAME_SENTINEL"));

        let error = AuthorizationInputSource::select(
            Some(OsString::from("first")),
            Some(PathBuf::from("second-secret-path")),
            false,
        )
        .unwrap_err();
        assert_eq!(error, AuthorizationInputError::ConflictingSources);
        assert!(!error.to_string().contains("first"));
        assert!(!error.to_string().contains("second-secret-path"));
    }

    #[test]
    fn bounded_reader_accepts_exact_limit_and_one_line_ending() {
        let exact = vec![b'a'; MAX_AUTHORIZATION_CONTEXT_BYTES];
        assert_eq!(
            read_bounded_line_source(&mut Cursor::new(exact.clone()))
                .unwrap()
                .as_slice(),
            exact.as_slice()
        );

        let mut lf = exact.clone();
        lf.push(b'\n');
        assert_eq!(
            read_bounded_line_source(&mut Cursor::new(lf))
                .unwrap()
                .as_slice(),
            exact.as_slice()
        );

        let mut crlf = exact.clone();
        crlf.extend_from_slice(b"\r\n");
        assert_eq!(
            read_bounded_line_source(&mut Cursor::new(crlf))
                .unwrap()
                .as_slice(),
            exact.as_slice()
        );
    }

    #[test]
    fn invalid_environment_names_fail_without_calling_the_process_environment() {
        for name in ["", "INVALID=NAME", "INVALID\0NAME"] {
            assert_eq!(
                read_environment(OsString::from(name)).unwrap_err(),
                AuthorizationInputError::SourceNameInvalid
            );
        }
    }

    #[test]
    fn bounded_reader_rejects_oversize_and_data_after_allowed_crlf() {
        let oversized = vec![b'a'; MAX_AUTHORIZATION_CONTEXT_BYTES + 1];
        assert_eq!(
            read_bounded_line_source(&mut Cursor::new(oversized)).unwrap_err(),
            AuthorizationInputError::ValueTooLarge
        );

        let mut disguised = vec![b'a'; MAX_AUTHORIZATION_CONTEXT_BYTES];
        disguised.extend_from_slice(b"\r\nextra");
        assert_eq!(
            read_bounded_line_source(&mut Cursor::new(disguised)).unwrap_err(),
            AuthorizationInputError::ValueTooLarge
        );
    }

    #[test]
    fn bounded_reader_removes_only_one_terminal_line_ending() {
        let value = read_bounded_line_source(&mut Cursor::new(b" Bearer token \n\n")).unwrap();
        assert_eq!(value.as_slice(), b" Bearer token \n");
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("PRIVATE_SOURCE_DIAGNOSTIC"))
        }
    }

    #[test]
    fn read_failures_discard_private_diagnostics() {
        let error = read_bounded_line_source(&mut FailingReader).unwrap_err();
        assert_eq!(error, AuthorizationInputError::SourceReadFailed);
        assert!(!error.to_string().contains("PRIVATE_SOURCE_DIAGNOSTIC"));
    }

    #[cfg(feature = "supplied-session-review")]
    fn valid_supplied_session_policy() -> &'static str {
        r#"schema = "security.supplied-session-policy/v1"
principal_alias = "fixture-reader"
credential_mechanism = "authorization_header"
health_path = "/app/health"
health_json_field = "authenticated"
resources = ["/app/private", "/app/private-2"]
max_session_requests = 5
max_total_response_bytes = 131072
max_response_body_bytes = 32768
max_wall_time_ms = 5000
"#
    }

    #[cfg(feature = "supplied-session-review")]
    fn valid_supplied_cookie_policy() -> &'static str {
        r#"schema = "security.supplied-session-policy/v2"
principal_alias = "fixture-cookie-reader"
credential_mechanism = "cookie_jar"
cookie_update_policy = "stop_on_selected_cookie"
health_path = "/app/health"
health_json_field = "authenticated"
resources = ["/app/private", "/app/private-2"]
max_session_requests = 5
max_total_response_bytes = 131072
max_response_body_bytes = 32768
max_wall_time_ms = 5000

[[cookies]]
id = "fixture-session"
name = "session"
domain = "127.0.0.1"
host_only = true
path = "/app/"
secure = false
http_only = true
same_site = "lax"
expires_unix_seconds = 4102444800
"#
    }

    #[cfg(feature = "supplied-session-review")]
    fn valid_supplied_form_login_policy() -> &'static str {
        r#"schema = "security.supplied-session-policy/v3"
principal_alias = "fixture-login-reader"
credential_mechanism = "cookie_jar"
credential_acquisition = "bounded_form_login"
cookie_update_policy = "stop_on_selected_cookie"
login_path = "/app/login"
login_method = "post"
login_encoding = "application/x-www-form-urlencoded"
username_field = "username"
password_field = "password"
csrf_field = "csrf_token"
max_login_attempts = 1
health_path = "/app/health"
health_json_field = "authenticated"
resources = ["/app/private"]
max_session_requests = 5
max_total_response_bytes = 131072
max_response_body_bytes = 32768
max_wall_time_ms = 5000

[[cookies]]
id = "fixture-session"
name = "session"
domain = "127.0.0.1"
host_only = true
path = "/app/"
secure = false
http_only = true
same_site = "lax"
"#
    }

    #[cfg(feature = "supplied-session-review")]
    #[test]
    fn supplied_session_selection_is_complete_and_redacted() {
        assert!(SuppliedSessionInput::select(
            None,
            AuthorizationSourceOptions::new(None, None, false),
            None,
            None,
        )
        .unwrap()
        .is_none());
        assert_eq!(
            SuppliedSessionInput::select(
                Some(PathBuf::from("PRIVATE-POLICY-PATH")),
                AuthorizationSourceOptions::new(None, None, false),
                None,
                None,
            )
            .unwrap_err(),
            SuppliedSessionInputError::MissingCredentialSource
        );
        assert_eq!(
            SuppliedSessionInput::select(
                None,
                AuthorizationSourceOptions::new(
                    Some(OsString::from("PRIVATE-SESSION-ENV")),
                    None,
                    false,
                ),
                None,
                None,
            )
            .unwrap_err(),
            SuppliedSessionInputError::MissingPolicy
        );
        assert_eq!(
            SuppliedSessionInput::select(
                Some(PathBuf::from("PRIVATE-POLICY-PATH")),
                AuthorizationSourceOptions::new(
                    Some(OsString::from("PRIVATE-SESSION-ENV")),
                    Some(PathBuf::from("PRIVATE-SESSION-FILE")),
                    false,
                ),
                None,
                None,
            )
            .unwrap_err(),
            SuppliedSessionInputError::ConflictingCredentialSources
        );

        let input = SuppliedSessionInput::select(
            Some(PathBuf::from("PRIVATE-POLICY-PATH")),
            AuthorizationSourceOptions::new(
                Some(OsString::from("PRIVATE-SESSION-ENV")),
                None,
                false,
            ),
            None,
            None,
        )
        .unwrap()
        .unwrap();
        let debug = format!("{input:?}");
        for private in ["PRIVATE-POLICY-PATH", "PRIVATE-SESSION-ENV"] {
            assert!(!debug.contains(private));
        }
        for error in [
            SuppliedSessionInputError::MissingPolicy,
            SuppliedSessionInputError::MissingCredentialSource,
            SuppliedSessionInputError::ConflictingCredentialSources,
            SuppliedSessionInputError::PolicySource(AuthorizationInputError::SourceUnavailable),
            SuppliedSessionInputError::InvalidPolicy,
            SuppliedSessionInputError::CredentialMechanismMismatch,
            SuppliedSessionInputError::CredentialSource(AuthorizationInputError::SourceUnavailable),
            SuppliedSessionInputError::InvalidCredentialValue,
            SuppliedSessionInputError::CredentialClockUnavailable,
        ] {
            let rendered = error.to_string();
            assert!(!rendered.contains("PRIVATE"));
            assert!(!rendered.contains("Bearer"));
        }
    }

    #[cfg(feature = "supplied-session-review")]
    #[test]
    fn supplied_session_loads_policy_before_one_move_only_secret() {
        const SECRET: &str = "Bearer SESSION-CANARY-MUST-NOT-LEAK-0123456789";
        let directory = tempfile::tempdir().unwrap();
        let policy_path = directory.path().join("session-policy.toml");
        let secret_path = directory.path().join("authorization.secret");
        std::fs::write(&policy_path, valid_supplied_session_policy()).unwrap();
        std::fs::write(&secret_path, format!("{SECRET}\r\n")).unwrap();

        let input = SuppliedSessionInput::select(
            Some(policy_path),
            AuthorizationSourceOptions::new(None, Some(secret_path), false),
            None,
            None,
        )
        .unwrap()
        .unwrap();
        let (policy, authorization) = input
            .prepare(&url::Url::parse("http://127.0.0.1:8123/app/").unwrap())
            .unwrap()
            .load()
            .unwrap();
        let rendered = format!("{policy:?} {authorization:?}");
        assert!(!rendered.contains(SECRET));
        assert!(!rendered.contains("SESSION-CANARY"));

        let invalid_policy = directory.path().join("invalid-policy.toml");
        std::fs::write(&invalid_policy, "schema = [not-valid").unwrap();
        let input = SuppliedSessionInput::select(
            Some(invalid_policy),
            AuthorizationSourceOptions::new(
                None,
                Some(directory.path().join("SECRET-MUST-NOT-BE-OPENED")),
                false,
            ),
            None,
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            input
                .prepare(&url::Url::parse("http://127.0.0.1:8123/app/").unwrap())
                .unwrap_err(),
            SuppliedSessionInputError::InvalidPolicy
        );
    }

    #[cfg(feature = "supplied-session-review")]
    #[test]
    fn supplied_session_cookie_selection_loads_one_redacted_jar_and_checks_mechanism_first() {
        const COOKIE: &str = "COOKIE-INPUT-CANARY-MUST-NOT-LEAK";
        let directory = tempfile::tempdir().unwrap();
        let policy_path = directory.path().join("cookie-policy.toml");
        let cookie_path = directory.path().join("cookies.secret.tsv");
        std::fs::write(&policy_path, valid_supplied_cookie_policy()).unwrap();
        std::fs::write(&cookie_path, format!("fixture-session\t{COOKIE}\r\n")).unwrap();

        let input = SuppliedSessionInput::select(
            Some(policy_path.clone()),
            AuthorizationSourceOptions::new(None, None, false),
            Some(cookie_path),
            None,
        )
        .unwrap()
        .unwrap();
        let debug = format!("{input:?}");
        assert!(!debug.contains("cookie-policy.toml"));
        assert!(!debug.contains("cookies.secret.tsv"));
        let prepared = input
            .prepare(&url::Url::parse("http://127.0.0.1:8123/app/").unwrap())
            .unwrap();
        assert_eq!(
            format!("{prepared:?}"),
            "PreparedSuppliedSessionInput { policy: \"<validated>\", secret: \"<redacted>\" }"
        );
        let (policy, credential) = prepared.load().unwrap();
        assert_eq!(
            policy.credential_acquisition(),
            SuppliedSessionCredentialAcquisition::SuppliedCookieJar
        );
        assert!(credential.matches_policy(&policy));
        let rendered = format!("{policy:?} {credential:?}");
        assert!(!rendered.contains(COOKIE));
        assert!(!rendered.contains("COOKIE-INPUT-CANARY"));

        let missing_authorization = directory.path().join("PRIVATE-AUTH-MUST-NOT-BE-OPENED");
        let mismatch = SuppliedSessionInput::select(
            Some(policy_path),
            AuthorizationSourceOptions::new(None, Some(missing_authorization), false),
            None,
            None,
        )
        .unwrap()
        .unwrap()
        .prepare(&url::Url::parse("http://127.0.0.1:8123/app/").unwrap())
        .unwrap_err();
        assert_eq!(
            mismatch,
            SuppliedSessionInputError::CredentialMechanismMismatch
        );

        assert_eq!(
            SuppliedSessionInput::select(
                Some(PathBuf::from("PRIVATE-POLICY")),
                AuthorizationSourceOptions::new(
                    None,
                    Some(PathBuf::from("PRIVATE-AUTHORIZATION")),
                    false,
                ),
                Some(PathBuf::from("PRIVATE-COOKIE")),
                None,
            )
            .unwrap_err(),
            SuppliedSessionInputError::ConflictingCredentialSources
        );
    }

    #[cfg(feature = "supplied-session-review")]
    #[test]
    fn supplied_session_form_login_is_loaded_only_for_the_exact_v3_acquisition() {
        const USERNAME: &str = "LOGIN-USER-CANARY-MUST-NOT-LEAK";
        const PASSWORD: &str = "LOGIN-PASSWORD-CANARY-MUST-NOT-LEAK";
        let directory = tempfile::tempdir().unwrap();
        let policy_path = directory.path().join("form-login-policy.toml");
        let login_path = directory.path().join("form-login.secret.tsv");
        std::fs::write(&policy_path, valid_supplied_form_login_policy()).unwrap();
        std::fs::write(
            &login_path,
            format!("username\t{USERNAME}\r\npassword\t{PASSWORD}\r\n"),
        )
        .unwrap();

        let unopened_login = directory.path().join("PRIVATE-LOGIN-PREFLIGHT-ONLY");
        let prepared_without_secret_read = SuppliedSessionInput::select(
            Some(policy_path.clone()),
            AuthorizationSourceOptions::new(None, None, false),
            None,
            Some(unopened_login.clone()),
        )
        .unwrap()
        .unwrap()
        .prepare(&url::Url::parse("http://127.0.0.1:8123/app/").unwrap())
        .unwrap();
        assert_eq!(
            prepared_without_secret_read.policy_version(),
            SuppliedSessionPolicyVersion::V3
        );
        assert!(!unopened_login.exists());

        let input = SuppliedSessionInput::select(
            Some(policy_path.clone()),
            AuthorizationSourceOptions::new(None, None, false),
            None,
            Some(login_path),
        )
        .unwrap()
        .unwrap();
        let debug = format!("{input:?}");
        assert!(!debug.contains("form-login-policy.toml"));
        assert!(!debug.contains("form-login.secret.tsv"));
        let prepared = input
            .prepare(&url::Url::parse("http://127.0.0.1:8123/app/").unwrap())
            .unwrap();
        assert_eq!(prepared.policy_version(), SuppliedSessionPolicyVersion::V3);
        let (policy, runtime_input) = prepared.load().unwrap();
        assert_eq!(
            policy.credential_acquisition(),
            SuppliedSessionCredentialAcquisition::BoundedFormLogin
        );
        assert!(runtime_input.matches_policy(&policy));
        let rendered = format!("{policy:?} {runtime_input:?}");
        for canary in [USERNAME, PASSWORD, "LOGIN-USER", "LOGIN-PASSWORD"] {
            assert!(!rendered.contains(canary));
        }

        let malformed_path = directory.path().join("malformed-login.secret.tsv");
        std::fs::write(
            &malformed_path,
            "username\tPRIVATE-MALFORMED-CANARY\npassword\t\n",
        )
        .unwrap();
        let malformed = SuppliedSessionInput::select(
            Some(policy_path.clone()),
            AuthorizationSourceOptions::new(None, None, false),
            None,
            Some(malformed_path),
        )
        .unwrap()
        .unwrap()
        .prepare(&url::Url::parse("http://127.0.0.1:8123/app/").unwrap())
        .unwrap()
        .load()
        .unwrap_err();
        assert_eq!(malformed, SuppliedSessionInputError::InvalidCredentialValue);
        assert!(!malformed.to_string().contains("PRIVATE-MALFORMED-CANARY"));

        let missing_login = directory.path().join("PRIVATE-LOGIN-MUST-NOT-BE-OPENED");
        let v2_with_login = SuppliedSessionInput::select(
            Some(directory.path().join("cookie-policy.toml")),
            AuthorizationSourceOptions::new(None, None, false),
            None,
            Some(missing_login.clone()),
        )
        .unwrap()
        .unwrap();
        std::fs::write(
            directory.path().join("cookie-policy.toml"),
            valid_supplied_cookie_policy(),
        )
        .unwrap();
        assert_eq!(
            v2_with_login
                .prepare(&url::Url::parse("http://127.0.0.1:8123/app/").unwrap())
                .unwrap_err(),
            SuppliedSessionInputError::CredentialMechanismMismatch
        );
        assert!(!missing_login.exists());

        let v1_policy_path = directory.path().join("authorization-policy.toml");
        std::fs::write(&v1_policy_path, valid_supplied_session_policy()).unwrap();
        for mismatched in [
            SuppliedSessionInput::select(
                Some(v1_policy_path.clone()),
                AuthorizationSourceOptions::new(None, None, false),
                None,
                Some(directory.path().join("PRIVATE-V1-LOGIN-MUST-NOT-BE-OPENED")),
            )
            .unwrap()
            .unwrap(),
            SuppliedSessionInput::select(
                Some(v1_policy_path),
                AuthorizationSourceOptions::new(None, None, false),
                Some(
                    directory
                        .path()
                        .join("PRIVATE-V1-COOKIE-MUST-NOT-BE-OPENED"),
                ),
                None,
            )
            .unwrap()
            .unwrap(),
        ] {
            assert_eq!(
                mismatched
                    .prepare(&url::Url::parse("http://127.0.0.1:8123/app/").unwrap())
                    .unwrap_err(),
                SuppliedSessionInputError::CredentialMechanismMismatch
            );
        }

        let v3_with_cookie = SuppliedSessionInput::select(
            Some(policy_path.clone()),
            AuthorizationSourceOptions::new(None, None, false),
            Some(directory.path().join("PRIVATE-COOKIE-MUST-NOT-BE-OPENED")),
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            v3_with_cookie
                .prepare(&url::Url::parse("http://127.0.0.1:8123/app/").unwrap())
                .unwrap_err(),
            SuppliedSessionInputError::CredentialMechanismMismatch
        );
        let v3_with_authorization = SuppliedSessionInput::select(
            Some(policy_path),
            AuthorizationSourceOptions::new(
                None,
                Some(directory.path().join("PRIVATE-AUTH-MUST-NOT-BE-OPENED")),
                false,
            ),
            None,
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            v3_with_authorization
                .prepare(&url::Url::parse("http://127.0.0.1:8123/app/").unwrap())
                .unwrap_err(),
            SuppliedSessionInputError::CredentialMechanismMismatch
        );

        assert_eq!(
            SuppliedSessionInput::select(
                Some(PathBuf::from("PRIVATE-POLICY")),
                AuthorizationSourceOptions::new(
                    None,
                    Some(PathBuf::from("PRIVATE-AUTHORIZATION")),
                    false,
                ),
                None,
                Some(PathBuf::from("PRIVATE-LOGIN")),
            )
            .unwrap_err(),
            SuppliedSessionInputError::ConflictingCredentialSources
        );
        assert_eq!(
            SuppliedSessionInput::select(
                Some(PathBuf::from("PRIVATE-POLICY")),
                AuthorizationSourceOptions::new(None, None, false),
                Some(PathBuf::from("PRIVATE-COOKIE")),
                Some(PathBuf::from("PRIVATE-LOGIN")),
            )
            .unwrap_err(),
            SuppliedSessionInputError::ConflictingCredentialSources
        );
    }

    #[cfg(all(feature = "supplied-session-review", windows))]
    #[test]
    fn supplied_session_form_login_rejects_remote_and_special_paths_before_open() {
        let remote_policy_error = SuppliedSessionInput::select(
            Some(PathBuf::from(r"\\server\share\session-policy.toml")),
            AuthorizationSourceOptions::new(None, None, false),
            None,
            Some(PathBuf::from(r"C:\termivar\form-login.secret.tsv")),
        )
        .unwrap_err();
        assert_eq!(
            remote_policy_error,
            SuppliedSessionInputError::PolicySource(AuthorizationInputError::SourceUnavailable)
        );

        for rejected in [
            r"\\server\share\form-login.secret.tsv",
            r"\\?\UNC\server\share\form-login.secret.tsv",
            r"\\.\pipe\termivar-login-must-not-open",
            r"\\?\GLOBALROOT\Device\NamedPipe\termivar-login-must-not-open",
            r"C:\termivar\NUL",
            r"C:\termivar\login.secret.tsv:stream",
        ] {
            let error = SuppliedSessionInput::select(
                Some(PathBuf::from("PRIVATE-POLICY-MUST-NOT-OPEN")),
                AuthorizationSourceOptions::new(None, None, false),
                None,
                Some(PathBuf::from(rejected)),
            )
            .unwrap_err();
            assert_eq!(
                error,
                SuppliedSessionInputError::CredentialSource(
                    AuthorizationInputError::SourceUnavailable
                ),
                "remote or special form-login path was accepted"
            );
            assert!(!format!("{error:?}").contains("termivar-login-must-not-open"));
        }

        for accepted in [
            r"C:\termivar\form-login.secret.tsv",
            r"C:termivar\relative-form-login.secret.tsv",
            r"\\?\C:\termivar\form-login.secret.tsv",
            r"relative\form-login.secret.tsv",
        ] {
            assert!(SuppliedSessionInput::select(
                Some(PathBuf::from("PRIVATE-POLICY-MUST-NOT-OPEN")),
                AuthorizationSourceOptions::new(None, None, false),
                None,
                Some(PathBuf::from(accepted)),
            )
            .is_ok());
        }
    }

    #[cfg(feature = "ssrf-oast-review")]
    fn valid_ssrf_oast_policy() -> &'static str {
        r#"schema = "security.ssrf-oast-review-policy/v1"
target_origin = "https://authorized.example.test"
provider_origin = "https://oast.authorized.example.test"
acknowledge_external_interaction = true
polls_per_leg = 1
poll_interval_ms = 250
lifetime_ms = 5000
"#
    }

    #[cfg(feature = "ssrf-oast-review")]
    #[test]
    fn ssrf_oast_selection_requires_one_policy_and_one_admin_source() {
        assert!(SsrfOastReviewInput::select(
            false,
            None,
            AuthorizationSourceOptions::new(None, None, false),
        )
        .unwrap()
        .is_none());
        assert_eq!(
            SsrfOastReviewInput::select(
                false,
                Some(PathBuf::from("PRIVATE-POLICY-PATH")),
                AuthorizationSourceOptions::new(
                    Some(OsString::from("PRIVATE-OAST-ENV-NAME")),
                    None,
                    false,
                ),
            )
            .unwrap_err(),
            SsrfOastReviewInputError::ExplicitEnableRequired
        );
        assert_eq!(
            SsrfOastReviewInput::select(
                true,
                Some(PathBuf::from("PRIVATE-POLICY-PATH")),
                AuthorizationSourceOptions::new(None, None, false),
            )
            .unwrap_err(),
            SsrfOastReviewInputError::MissingAdministratorSource
        );
        assert_eq!(
            SsrfOastReviewInput::select(
                true,
                None,
                AuthorizationSourceOptions::new(
                    Some(OsString::from("PRIVATE-OAST-ENV-NAME")),
                    None,
                    false,
                ),
            )
            .unwrap_err(),
            SsrfOastReviewInputError::MissingPolicy
        );
        assert_eq!(
            SsrfOastReviewInput::select(
                true,
                Some(PathBuf::from("PRIVATE-POLICY-PATH")),
                AuthorizationSourceOptions::new(
                    Some(OsString::from("PRIVATE-OAST-ENV-NAME")),
                    Some(PathBuf::from("PRIVATE-OAST-TOKEN-PATH")),
                    false,
                ),
            )
            .unwrap_err(),
            SsrfOastReviewInputError::ConflictingAdministratorSources
        );

        let input = SsrfOastReviewInput::select(
            true,
            Some(PathBuf::from("PRIVATE-POLICY-PATH")),
            AuthorizationSourceOptions::new(
                Some(OsString::from("PRIVATE-OAST-ENV-NAME")),
                None,
                false,
            ),
        )
        .unwrap()
        .unwrap();
        let debug = format!("{input:?}");
        for private in [
            "PRIVATE-POLICY-PATH",
            "PRIVATE-OAST-ENV-NAME",
            "PRIVATE-OAST-TOKEN-PATH",
        ] {
            assert!(!debug.contains(private));
        }
        let messages = [
            SsrfOastReviewInputError::ExplicitEnableRequired,
            SsrfOastReviewInputError::MissingPolicy,
            SsrfOastReviewInputError::MissingAdministratorSource,
            SsrfOastReviewInputError::ConflictingAdministratorSources,
            SsrfOastReviewInputError::PolicySource(AuthorizationInputError::SourceUnavailable),
            SsrfOastReviewInputError::InvalidPolicyEncoding,
            SsrfOastReviewInputError::InvalidPolicy,
            SsrfOastReviewInputError::AdministratorSource(
                AuthorizationInputError::SourceUnavailable,
            ),
            SsrfOastReviewInputError::InvalidAdministratorValue,
        ]
        .map(|error| error.to_string());
        assert!(messages
            .iter()
            .all(|message| !message.contains("PRIVATE") && !message.contains("secret bytes")));
    }

    #[cfg(feature = "ssrf-oast-review")]
    #[test]
    fn ssrf_oast_input_loads_policy_and_move_only_admin_token_from_files() {
        const ADMIN_SECRET: &str = "OAST-ADMIN-TOKEN-MUST-NOT-LEAK-0123456789ABCDEF";

        let directory = tempfile::tempdir().unwrap();
        let policy_path = directory.path().join("PRIVATE-policy.toml");
        let administrator_path = directory.path().join("PRIVATE-administrator.txt");
        std::fs::write(&policy_path, valid_ssrf_oast_policy()).unwrap();
        std::fs::write(&administrator_path, format!("{ADMIN_SECRET}\r\n")).unwrap();
        let input = SsrfOastReviewInput::select(
            true,
            Some(policy_path),
            AuthorizationSourceOptions::new(None, Some(administrator_path), false),
        )
        .unwrap()
        .unwrap();
        let prepared = input
            .prepare(&url::Url::parse("https://authorized.example.test/").unwrap())
            .unwrap();
        let prepared_debug = format!("{prepared:?}");
        let (policy, administrator) = prepared.load().unwrap();
        let rendered = format!("{prepared_debug} {policy:?} {administrator:?}");
        assert!(!rendered.contains(ADMIN_SECRET));
        assert!(!rendered.contains("PRIVATE-policy.toml"));
        assert!(!rendered.contains("PRIVATE-administrator.txt"));
    }

    #[cfg(feature = "ssrf-oast-review")]
    #[test]
    fn ssrf_oast_policy_source_is_strict_utf8_bounded_and_secret_free() {
        const ADMIN_SECRET: &[u8] = b"OAST-ADMIN-TOKEN-MUST-NOT-LEAK-0123456789ABCDEF";

        let directory = tempfile::tempdir().unwrap();
        let administrator_path = directory.path().join("administrator.txt");
        std::fs::write(&administrator_path, ADMIN_SECRET).unwrap();
        let prepare_error = |policy_path: PathBuf| {
            SsrfOastReviewInput::select(
                true,
                Some(policy_path),
                AuthorizationSourceOptions::new(None, Some(administrator_path.clone()), false),
            )
            .unwrap()
            .unwrap()
            .prepare(&url::Url::parse("https://authorized.example.test/").unwrap())
            .unwrap_err()
        };

        assert_eq!(
            prepare_error(directory.path().to_path_buf()),
            SsrfOastReviewInputError::PolicySource(AuthorizationInputError::SourceNotRegularFile)
        );
        let invalid_utf8 = directory.path().join("invalid-utf8.toml");
        std::fs::write(&invalid_utf8, [0xff, 0xfe]).unwrap();
        assert_eq!(
            prepare_error(invalid_utf8),
            SsrfOastReviewInputError::InvalidPolicyEncoding
        );
        let oversized = directory.path().join("oversized.toml");
        std::fs::write(
            &oversized,
            vec![b'x'; MAX_SSRF_OAST_REVIEW_POLICY_BYTES + 1],
        )
        .unwrap();
        assert_eq!(
            prepare_error(oversized),
            SsrfOastReviewInputError::PolicySource(AuthorizationInputError::ValueTooLarge)
        );
        let secret_field = directory.path().join("secret-field.toml");
        std::fs::write(
            &secret_field,
            format!(
                "{}admin_token = \"OAST-ADMIN-TOKEN-MUST-NOT-LEAK-0123456789ABCDEF\"\n",
                valid_ssrf_oast_policy()
            ),
        )
        .unwrap();
        assert_eq!(
            prepare_error(secret_field),
            SsrfOastReviewInputError::InvalidPolicy
        );
    }

    #[cfg(feature = "ssrf-oast-review")]
    #[test]
    fn ssrf_oast_prepare_validates_policy_before_opening_administrator_source() {
        let directory = tempfile::tempdir().unwrap();
        let valid_policy = directory.path().join("valid-policy.toml");
        let invalid_policy = directory.path().join("invalid-policy.toml");
        let missing_administrator = directory.path().join("PRIVATE-MISSING-OAST-ADMINISTRATOR");
        std::fs::write(&valid_policy, valid_ssrf_oast_policy()).unwrap();
        std::fs::write(&invalid_policy, [0xff, 0xfe]).unwrap();
        let target = url::Url::parse("https://authorized.example.test/").unwrap();

        let select = |policy| {
            SsrfOastReviewInput::select(
                true,
                Some(policy),
                AuthorizationSourceOptions::new(None, Some(missing_administrator.clone()), false),
            )
            .unwrap()
            .unwrap()
        };

        assert_eq!(
            select(invalid_policy).prepare(&target).unwrap_err(),
            SsrfOastReviewInputError::InvalidPolicyEncoding
        );
        let prepared = select(valid_policy).prepare(&target).unwrap();
        let debug = format!("{prepared:?}");
        assert!(!debug.contains("PRIVATE-MISSING-OAST-ADMINISTRATOR"));
        assert_eq!(
            prepared.load().unwrap_err(),
            SsrfOastReviewInputError::AdministratorSource(
                AuthorizationInputError::SourceUnavailable
            )
        );
    }

    #[cfg(all(feature = "ssrf-oast-review", unix))]
    #[test]
    fn ssrf_oast_policy_and_admin_sources_reject_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let policy_target = directory.path().join("policy-target.toml");
        let policy_link = directory.path().join("policy-link.toml");
        let administrator_target = directory.path().join("administrator-target.txt");
        let administrator_link = directory.path().join("administrator-link.txt");
        std::fs::write(&policy_target, valid_ssrf_oast_policy()).unwrap();
        std::fs::write(
            &administrator_target,
            b"OAST-ADMIN-TOKEN-MUST-NOT-LEAK-0123456789ABCDEF",
        )
        .unwrap();
        symlink(&policy_target, &policy_link).unwrap();
        symlink(&administrator_target, &administrator_link).unwrap();

        let load = |policy: PathBuf, administrator: PathBuf| {
            SsrfOastReviewInput::select(
                true,
                Some(policy),
                AuthorizationSourceOptions::new(None, Some(administrator), false),
            )
            .unwrap()
            .unwrap()
            .prepare(&url::Url::parse("https://authorized.example.test/").unwrap())
        };
        assert_eq!(
            load(policy_link, administrator_target).unwrap_err(),
            SsrfOastReviewInputError::PolicySource(AuthorizationInputError::SourceNotRegularFile)
        );
        assert_eq!(
            load(policy_target, administrator_link)
                .unwrap()
                .load()
                .unwrap_err(),
            SsrfOastReviewInputError::AdministratorSource(
                AuthorizationInputError::SourceNotRegularFile
            )
        );
    }

    #[test]
    #[cfg(unix)]
    fn file_source_rejects_a_non_regular_object_before_reading() {
        let error = AuthorizationInputSource::File(PathBuf::from("/dev/null"))
            .load()
            .unwrap_err();
        assert_eq!(error, AuthorizationInputError::SourceNotRegularFile);
    }

    #[cfg(feature = "authorization-review")]
    fn valid_policy(resource: &str, handle: &str) -> String {
        format!(
            r#"schema = "security.authorization-review-policy/v1"
resource = "{resource}"
resource_handle = "{handle}"
expectation = "primary-only"
method = "GET"

[comparison]
selected_paths = ["/data/account"]
ignored_paths = ["/data/account/updated_at"]
unordered_array_paths = []
max_diff_paths = 8
"#
        )
    }

    #[cfg(feature = "authorization-review")]
    #[test]
    fn review_selection_requires_a_policy_and_exactly_one_source_per_role() {
        assert!(AuthorizationReviewInput::select(
            None,
            AuthorizationSourceOptions::new(None, None, false),
            AuthorizationSourceOptions::new(None, None, false),
        )
        .unwrap()
        .is_none());
        assert_eq!(
            AuthorizationReviewInput::select(
                Some(PathBuf::from("private-policy")),
                AuthorizationSourceOptions::new(None, None, false),
                AuthorizationSourceOptions::new(None, None, false),
            )
            .unwrap_err(),
            AuthorizationReviewInputError::MissingPrimarySource
        );
        assert_eq!(
            AuthorizationReviewInput::select(
                Some(PathBuf::from("private-policy")),
                AuthorizationSourceOptions::new(
                    Some(OsString::from("PRIMARY_PRIVATE_NAME")),
                    None,
                    false,
                ),
                AuthorizationSourceOptions::new(None, None, false),
            )
            .unwrap_err(),
            AuthorizationReviewInputError::MissingPeerSource
        );
        assert_eq!(
            AuthorizationReviewInput::select(
                None,
                AuthorizationSourceOptions::new(
                    Some(OsString::from("PRIMARY_PRIVATE_NAME")),
                    None,
                    false,
                ),
                AuthorizationSourceOptions::new(
                    Some(OsString::from("PEER_PRIVATE_NAME")),
                    None,
                    false,
                ),
            )
            .unwrap_err(),
            AuthorizationReviewInputError::MissingPolicy
        );
        assert_eq!(
            AuthorizationReviewInput::select(
                Some(PathBuf::from("private-policy")),
                AuthorizationSourceOptions::new(
                    Some(OsString::from("PRIMARY_PRIVATE_NAME")),
                    Some(PathBuf::from("primary-private-path")),
                    false,
                ),
                AuthorizationSourceOptions::new(
                    Some(OsString::from("PEER_PRIVATE_NAME")),
                    None,
                    false,
                ),
            )
            .unwrap_err(),
            AuthorizationReviewInputError::ConflictingPrimarySources
        );
        assert_eq!(
            AuthorizationReviewInput::select(
                Some(PathBuf::from("private-policy")),
                AuthorizationSourceOptions::new(
                    Some(OsString::from("PRIMARY_PRIVATE_NAME")),
                    None,
                    false,
                ),
                AuthorizationSourceOptions::new(
                    Some(OsString::from("PEER_PRIVATE_NAME")),
                    Some(PathBuf::from("peer-private-path")),
                    false,
                ),
            )
            .unwrap_err(),
            AuthorizationReviewInputError::ConflictingPeerSources
        );
        assert_eq!(
            AuthorizationReviewInput::select(
                Some(PathBuf::from("private-policy")),
                AuthorizationSourceOptions::new(None, None, true),
                AuthorizationSourceOptions::new(None, None, true),
            )
            .unwrap_err(),
            AuthorizationReviewInputError::AmbiguousStdin
        );
    }

    #[cfg(feature = "authorization-review")]
    #[test]
    fn review_input_debug_and_errors_redact_every_source_identifier() {
        let options = AuthorizationSourceOptions::new(
            Some(OsString::from("PRIMARY-AUTHORIZATION-MUST-NOT-LEAK-7C3A19")),
            None,
            false,
        );
        assert_eq!(
            format!("{options:?}"),
            "AuthorizationSourceOptions(<redacted>)"
        );
        let input = AuthorizationReviewInput::select(
            Some(PathBuf::from(
                "PRIVATE-RESOURCE-HANDLE-MUST-NOT-LEAK-346E2A",
            )),
            AuthorizationSourceOptions::new(
                Some(OsString::from("PRIMARY-AUTHORIZATION-MUST-NOT-LEAK-7C3A19")),
                None,
                false,
            ),
            AuthorizationSourceOptions::new(
                None,
                Some(PathBuf::from("PEER-AUTHORIZATION-MUST-NOT-LEAK-82FD44")),
                false,
            ),
        )
        .unwrap()
        .unwrap();
        let debug = format!("{input:?}");
        for secret in [
            "PRIVATE-RESOURCE-HANDLE-MUST-NOT-LEAK-346E2A",
            "PRIMARY-AUTHORIZATION-MUST-NOT-LEAK-7C3A19",
            "PEER-AUTHORIZATION-MUST-NOT-LEAK-82FD44",
        ] {
            assert!(!debug.contains(secret));
        }
        assert_eq!(
            AuthorizationReviewInputError::PolicySource(AuthorizationInputError::SourceUnavailable)
                .to_string(),
            "authorization review policy must be a bounded regular file"
        );
        let messages = [
            AuthorizationReviewInputError::MissingPolicy,
            AuthorizationReviewInputError::MissingPrimarySource,
            AuthorizationReviewInputError::MissingPeerSource,
            AuthorizationReviewInputError::ConflictingPrimarySources,
            AuthorizationReviewInputError::ConflictingPeerSources,
            AuthorizationReviewInputError::AmbiguousStdin,
            AuthorizationReviewInputError::InvalidPolicy,
            AuthorizationReviewInputError::PrimarySource(
                AuthorizationInputError::SourceUnavailable,
            ),
            AuthorizationReviewInputError::PeerSource(AuthorizationInputError::SourceUnavailable),
            AuthorizationReviewInputError::InvalidPrimaryValue,
            AuthorizationReviewInputError::InvalidPeerValue,
            AuthorizationReviewInputError::PrincipalsNotDistinct,
        ]
        .map(|error| error.to_string());
        assert!(messages.iter().all(|message| {
            !message.contains("PRIVATE")
                && !message.contains("credential bytes")
                && !message.contains("source path")
        }));
    }

    #[cfg(feature = "authorization-review")]
    #[test]
    fn review_input_loads_a_strict_policy_and_distinct_file_principals() {
        let directory = tempfile::tempdir().unwrap();
        let policy_path = directory.path().join("review.toml");
        let primary_path = directory.path().join("primary.txt");
        let peer_path = directory.path().join("peer.txt");
        std::fs::write(
            &policy_path,
            valid_policy(
                "/api/account?opaque=RESOURCE-QUERY-MUST-NOT-LEAK-51A9BC",
                "PRIVATE-RESOURCE-HANDLE-MUST-NOT-LEAK-346E2A",
            ),
        )
        .unwrap();
        std::fs::write(
            &primary_path,
            b"Bearer PRIMARY-AUTHORIZATION-MUST-NOT-LEAK-7C3A19\r\n",
        )
        .unwrap();
        std::fs::write(
            &peer_path,
            b"Bearer PEER-AUTHORIZATION-MUST-NOT-LEAK-82FD44\n",
        )
        .unwrap();

        let input = AuthorizationReviewInput::select(
            Some(policy_path),
            AuthorizationSourceOptions::new(None, Some(primary_path), false),
            AuthorizationSourceOptions::new(None, Some(peer_path), false),
        )
        .unwrap()
        .unwrap();
        let (policy, principals) = input
            .load(&url::Url::parse("https://example.test/").unwrap())
            .unwrap();
        let rendered = format!("{policy:?} {principals:?}");
        for secret in [
            "RESOURCE-QUERY-MUST-NOT-LEAK-51A9BC",
            "PRIVATE-RESOURCE-HANDLE-MUST-NOT-LEAK-346E2A",
            "PRIMARY-AUTHORIZATION-MUST-NOT-LEAK-7C3A19",
            "PEER-AUTHORIZATION-MUST-NOT-LEAK-82FD44",
        ] {
            assert!(!rendered.contains(secret));
        }
    }

    #[cfg(feature = "authorization-review")]
    #[test]
    fn relative_policy_resource_is_bound_to_the_assessment_origin_root() {
        let directory = tempfile::tempdir().unwrap();
        let policy_path = directory.path().join("review.toml");
        let primary_path = directory.path().join("primary.txt");
        let peer_path = directory.path().join("peer.txt");
        let source = valid_policy("api/account", "account-self");
        std::fs::write(&policy_path, &source).unwrap();
        std::fs::write(&primary_path, b"Bearer primary").unwrap();
        std::fs::write(&peer_path, b"Bearer peer").unwrap();

        let input = AuthorizationReviewInput::select(
            Some(policy_path),
            AuthorizationSourceOptions::new(None, Some(primary_path), false),
            AuthorizationSourceOptions::new(None, Some(peer_path), false),
        )
        .unwrap()
        .unwrap();
        let (policy, _) = input
            .load(&url::Url::parse("https://example.test/nested/base/").unwrap())
            .unwrap();
        let root_policy = AuthorizationReviewPolicy::parse_toml(
            &url::Url::parse("https://example.test/").unwrap(),
            source.as_bytes(),
        )
        .unwrap();
        assert_eq!(policy.resource_scope_id(), root_policy.resource_scope_id());
        assert_eq!(policy.policy_id(), root_policy.policy_id());
    }

    #[cfg(feature = "authorization-review")]
    #[test]
    fn review_input_rejects_equal_values_after_loading_distinct_sources() {
        let directory = tempfile::tempdir().unwrap();
        let policy_path = directory.path().join("review.toml");
        let primary_path = directory.path().join("primary.txt");
        let peer_path = directory.path().join("peer.txt");
        std::fs::write(&policy_path, valid_policy("/api/account", "account-self")).unwrap();
        std::fs::write(&primary_path, b"Bearer same-context\n").unwrap();
        std::fs::write(&peer_path, b"Bearer same-context\r\n").unwrap();
        let input = AuthorizationReviewInput::select(
            Some(policy_path),
            AuthorizationSourceOptions::new(None, Some(primary_path), false),
            AuthorizationSourceOptions::new(None, Some(peer_path), false),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            input
                .load(&url::Url::parse("https://example.test/").unwrap())
                .unwrap_err(),
            AuthorizationReviewInputError::PrincipalsNotDistinct
        );
    }

    #[cfg(feature = "authorization-review")]
    #[test]
    fn review_policy_source_must_be_a_bounded_regular_file() {
        let directory = tempfile::tempdir().unwrap();
        let primary_path = directory.path().join("primary.txt");
        let peer_path = directory.path().join("peer.txt");
        std::fs::write(&primary_path, b"Bearer primary").unwrap();
        std::fs::write(&peer_path, b"Bearer peer").unwrap();

        let input = AuthorizationReviewInput::select(
            Some(directory.path().to_path_buf()),
            AuthorizationSourceOptions::new(None, Some(primary_path.clone()), false),
            AuthorizationSourceOptions::new(None, Some(peer_path.clone()), false),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            input
                .load(&url::Url::parse("https://example.test/").unwrap())
                .unwrap_err(),
            AuthorizationReviewInputError::PolicySource(
                AuthorizationInputError::SourceNotRegularFile
            )
        );

        let oversized = directory.path().join("oversized.toml");
        std::fs::write(
            &oversized,
            vec![b'x'; HARD_MAX_AUTHORIZATION_REVIEW_POLICY_BYTES + 1],
        )
        .unwrap();
        let input = AuthorizationReviewInput::select(
            Some(oversized),
            AuthorizationSourceOptions::new(None, Some(primary_path), false),
            AuthorizationSourceOptions::new(None, Some(peer_path), false),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            input
                .load(&url::Url::parse("https://example.test/").unwrap())
                .unwrap_err(),
            AuthorizationReviewInputError::PolicySource(AuthorizationInputError::ValueTooLarge)
        );
    }

    #[cfg(feature = "authorization-review")]
    #[test]
    fn review_loading_classifies_policy_source_and_role_failures_without_values() {
        let directory = tempfile::tempdir().unwrap();
        let policy_path = directory.path().join("review.toml");
        let invalid_policy_path = directory.path().join("invalid.toml");
        let primary_path = directory.path().join("primary.txt");
        let peer_path = directory.path().join("peer.txt");
        let missing_path = directory.path().join("missing-private-source");
        std::fs::write(&policy_path, valid_policy("/api/account", "account-self")).unwrap();
        std::fs::write(&invalid_policy_path, "unknown = 'policy'").unwrap();
        std::fs::write(&primary_path, b"Bearer primary").unwrap();
        std::fs::write(&peer_path, b"Bearer peer").unwrap();

        let load_error =
            |policy: PathBuf, primary: PathBuf, peer: PathBuf| -> AuthorizationReviewInputError {
                AuthorizationReviewInput::select(
                    Some(policy),
                    AuthorizationSourceOptions::new(None, Some(primary), false),
                    AuthorizationSourceOptions::new(None, Some(peer), false),
                )
                .unwrap()
                .unwrap()
                .load(&url::Url::parse("https://example.test/").unwrap())
                .unwrap_err()
            };

        assert_eq!(
            load_error(
                missing_path.clone(),
                primary_path.clone(),
                peer_path.clone()
            ),
            AuthorizationReviewInputError::PolicySource(AuthorizationInputError::SourceUnavailable)
        );
        assert_eq!(
            load_error(invalid_policy_path, primary_path.clone(), peer_path.clone()),
            AuthorizationReviewInputError::InvalidPolicy
        );
        assert_eq!(
            load_error(policy_path.clone(), missing_path.clone(), peer_path.clone()),
            AuthorizationReviewInputError::PrimarySource(
                AuthorizationInputError::SourceUnavailable
            )
        );
        assert_eq!(
            load_error(policy_path.clone(), primary_path.clone(), missing_path),
            AuthorizationReviewInputError::PeerSource(AuthorizationInputError::SourceUnavailable)
        );

        let invalid_primary = directory.path().join("invalid-primary.txt");
        let invalid_peer = directory.path().join("invalid-peer.txt");
        std::fs::write(&invalid_primary, b"Bearer primary\nembedded").unwrap();
        std::fs::write(&invalid_peer, b"Bearer peer\0embedded").unwrap();
        assert_eq!(
            load_error(policy_path.clone(), invalid_primary, peer_path),
            AuthorizationReviewInputError::InvalidPrimaryValue
        );
        assert_eq!(
            load_error(policy_path, primary_path, invalid_peer),
            AuthorizationReviewInputError::InvalidPeerValue
        );
    }

    #[cfg(all(feature = "authorization-review", unix))]
    #[test]
    fn review_policy_and_principal_sources_reject_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let policy_target = directory.path().join("policy-target.toml");
        let policy_link = directory.path().join("policy-link.toml");
        let primary_target = directory.path().join("primary-target.txt");
        let primary_link = directory.path().join("primary-link.txt");
        let peer = directory.path().join("peer.txt");
        std::fs::write(&policy_target, valid_policy("/api/account", "account-self")).unwrap();
        std::fs::write(&primary_target, b"Bearer primary").unwrap();
        std::fs::write(&peer, b"Bearer peer").unwrap();
        symlink(&policy_target, &policy_link).unwrap();
        symlink(&primary_target, &primary_link).unwrap();

        let error = AuthorizationReviewInput::select(
            Some(policy_link),
            AuthorizationSourceOptions::new(None, Some(primary_target), false),
            AuthorizationSourceOptions::new(None, Some(peer.clone()), false),
        )
        .unwrap()
        .unwrap()
        .load(&url::Url::parse("https://example.test/").unwrap())
        .unwrap_err();
        assert_eq!(
            error,
            AuthorizationReviewInputError::PolicySource(
                AuthorizationInputError::SourceNotRegularFile
            )
        );

        let error = AuthorizationReviewInput::select(
            Some(policy_target),
            AuthorizationSourceOptions::new(None, Some(primary_link), false),
            AuthorizationSourceOptions::new(None, Some(peer), false),
        )
        .unwrap()
        .unwrap()
        .load(&url::Url::parse("https://example.test/").unwrap())
        .unwrap_err();
        assert_eq!(
            error,
            AuthorizationReviewInputError::PrimarySource(
                AuthorizationInputError::SourceNotRegularFile
            )
        );
    }
}
