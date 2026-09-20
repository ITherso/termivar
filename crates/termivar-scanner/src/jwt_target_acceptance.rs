//! Pure domain contracts for bounded JWT target-acceptance review.
//!
//! This module performs no I/O and retains no token bytes. It binds one
//! operator-selected JSON marker to one exact-origin, application-contained
//! GET resource, validates six ordered value-free leg facts, and derives one
//! conservative audit conclusion. The two invalid-signature control legs are
//! the only active legs and are admitted only after their same-stage valid and
//! anonymous controls establish the prerequisite marker relationship.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

/// Stable schema identifier for the value-free target-acceptance audit.
pub const JWT_TARGET_ACCEPTANCE_AUDIT_SCHEMA: &str = "security.jwt-target-acceptance-audit/v1";
/// Stable schema identifier for operator-supplied target policy documents.
pub const JWT_TARGET_ACCEPTANCE_POLICY_SCHEMA: &str = "security.jwt-target-acceptance-policy/v1";
/// Stable identifier for the exact-origin JSON-marker interpretation policy.
pub const JWT_TARGET_ACCEPTANCE_POLICY_ID: &str =
    "termivar.jwt-target-acceptance/exact-origin-json-marker-v1";

/// Stable action identifier for valid-token baseline legs.
pub const JWT_TARGET_ACCEPTANCE_VALID_BASELINE_ACTION_ID: &str =
    "web.review.jwt-target-acceptance.valid-baseline@1";
/// Stable action identifier for anonymous control legs.
pub const JWT_TARGET_ACCEPTANCE_ANONYMOUS_CONTROL_ACTION_ID: &str =
    "web.review.jwt-target-acceptance.anonymous-control@1";
/// Stable action identifier for invalid-signature control legs.
pub const JWT_TARGET_ACCEPTANCE_INVALID_CONTROL_ACTION_ID: &str =
    "web.review.jwt-target-acceptance.invalid-control@1";
/// Runtime-facing alias for the valid-token baseline action identifier.
pub const JWT_TARGET_ACCEPTANCE_VALID_ACTION_ID: &str =
    JWT_TARGET_ACCEPTANCE_VALID_BASELINE_ACTION_ID;
/// Runtime-facing alias for the anonymous control action identifier.
pub const JWT_TARGET_ACCEPTANCE_ANONYMOUS_ACTION_ID: &str =
    JWT_TARGET_ACCEPTANCE_ANONYMOUS_CONTROL_ACTION_ID;
/// Runtime-facing alias for the invalid-signature control action identifier.
pub const JWT_TARGET_ACCEPTANCE_INVALID_ACTION_ID: &str =
    JWT_TARGET_ACCEPTANCE_INVALID_CONTROL_ACTION_ID;

/// Exact maximum number of role slots in one target-acceptance review.
pub const MAX_JWT_TARGET_ACCEPTANCE_REQUESTS: u8 = 6;
/// Maximum dispatched active invalid-signature control requests.
pub const MAX_JWT_TARGET_ACCEPTANCE_ACTIVE_REQUESTS: u8 = 2;
/// Maximum response bytes retained and interpreted for any one role.
pub const MAX_JWT_TARGET_ACCEPTANCE_RESPONSE_BYTES: u64 = 64 * 1024;
/// Maximum response bytes retained and interpreted across the complete review.
pub const MAX_JWT_TARGET_ACCEPTANCE_TOTAL_RESPONSE_BYTES: u64 = 256 * 1024;
/// Maximum bounded opaque evidence-reference bytes.
pub const MAX_JWT_TARGET_ACCEPTANCE_EVIDENCE_REFERENCE_BYTES: usize = 128;

const MAX_POLICY_REFERENCE_BYTES: usize = 64;
const MAX_RESOURCE_REFERENCE_BYTES: usize = 64;
const MAX_JSON_FIELD_BYTES: usize = 128;
const JWT_TARGET_PREPARATION_BINDING_BYTES: usize = 32;
const JWT_TARGET_PREPARATION_REFERENCE_PREFIX: &str = "jwt-target-preparation:";

/// Opaque per-preparation identity that binds one local JWT review to the
/// target-side audit produced from the same move-only handoff.
///
/// The bytes are random and are not derived from token material. The type is
/// intentionally non-serializable and has no public constructor or byte
/// accessor. A one-run opaque reference derived from the bytes may be projected
/// into the v2 report solely to link its local and target audits; the raw bytes
/// remain private and external callers may only move the value returned by the
/// reviewed preparation boundary.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct JwtTargetAcceptanceBinding([u8; JWT_TARGET_PREPARATION_BINDING_BYTES]);

impl JwtTargetAcceptanceBinding {
    pub(crate) const fn from_random_bytes(
        bytes: [u8; JWT_TARGET_PREPARATION_BINDING_BYTES],
    ) -> Self {
        Self(bytes)
    }

    pub(crate) fn reference(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut reference = String::with_capacity(
            JWT_TARGET_PREPARATION_REFERENCE_PREFIX.len()
                + JWT_TARGET_PREPARATION_BINDING_BYTES * 2,
        );
        reference.push_str(JWT_TARGET_PREPARATION_REFERENCE_PREFIX);
        for byte in self.0 {
            reference.push(char::from(HEX[usize::from(byte >> 4)]));
            reference.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        reference
    }

    #[cfg(test)]
    pub(crate) const fn synthetic_for_test(tag: u8) -> Self {
        Self([tag; JWT_TARGET_PREPARATION_BINDING_BYTES])
    }
}

impl fmt::Debug for JwtTargetAcceptanceBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JwtTargetAcceptanceBinding(<opaque-per-preparation>)")
    }
}

/// Fixed request method admitted by the target-acceptance policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum JwtTargetAcceptanceMethod {
    /// A bodyless HTTP GET request.
    Get,
}

/// One strict, non-serializable target-selection policy.
///
/// Raw URLs and the selected JSON field stay private to this policy and are
/// omitted from audit output. `Debug` redacts them. The policy grants no
/// authority beyond its one exact resource.
pub struct JwtTargetAcceptancePolicy {
    operator_policy_reference: String,
    operator_policy_revision: String,
    application: Url,
    resource: Url,
    resource_reference: String,
    success_json_field: String,
}

impl JwtTargetAcceptancePolicy {
    /// Constructs one exact-origin, application-contained GET policy.
    ///
    /// Both URLs must use HTTP or HTTPS and must omit user information, query,
    /// and fragment components. HTTP admission here does not grant network
    /// authority; the owning runtime applies its existing transport policy.
    /// Library callers must reject unsafe raw URL spellings before parsing,
    /// because a typed [`Url`] can no longer expose spelling normalized by its
    /// parser. The declared policy revision must change whenever the application,
    /// resource, resource reference, or private success-marker semantics change;
    /// reports omit the raw URL and marker and compare that revision instead.
    pub fn new(
        operator_policy_identity: (&str, &str),
        application: Url,
        resource: Url,
        resource_reference: &str,
        success_json_field: &str,
    ) -> Result<Self, JwtTargetAcceptancePolicyError> {
        let (operator_policy_reference, operator_policy_revision) = operator_policy_identity;
        if !valid_slug(operator_policy_reference, MAX_POLICY_REFERENCE_BYTES) {
            return Err(JwtTargetAcceptancePolicyError::InvalidOperatorPolicyReference);
        }
        if !valid_slug(operator_policy_revision, MAX_POLICY_REFERENCE_BYTES) {
            return Err(JwtTargetAcceptancePolicyError::InvalidOperatorPolicyRevision);
        }
        validate_http_url(&application)
            .map_err(|_| JwtTargetAcceptancePolicyError::InvalidApplication)?;
        validate_http_url(&resource)
            .map_err(|_| JwtTargetAcceptancePolicyError::InvalidResource)?;
        if !same_exact_origin(&application, &resource) {
            return Err(JwtTargetAcceptancePolicyError::ForeignResourceOrigin);
        }
        if !path_within_application(&application, &resource) {
            return Err(JwtTargetAcceptancePolicyError::ResourceOutsideApplication);
        }
        if !valid_slug(resource_reference, MAX_RESOURCE_REFERENCE_BYTES) {
            return Err(JwtTargetAcceptancePolicyError::InvalidResourceReference);
        }
        if !valid_json_field(success_json_field) {
            return Err(JwtTargetAcceptancePolicyError::InvalidSuccessJsonField);
        }

        Ok(Self {
            operator_policy_reference: operator_policy_reference.to_owned(),
            operator_policy_revision: operator_policy_revision.to_owned(),
            application,
            resource,
            resource_reference: resource_reference.to_owned(),
            success_json_field: success_json_field.to_owned(),
        })
    }

    /// Stable schema identifier for the selected operator policy.
    pub const fn schema(&self) -> &'static str {
        JWT_TARGET_ACCEPTANCE_POLICY_SCHEMA
    }

    /// Stable interpretation-policy identifier.
    pub const fn policy_id(&self) -> &'static str {
        JWT_TARGET_ACCEPTANCE_POLICY_ID
    }

    /// Fixed bodyless request method.
    pub const fn method(&self) -> JwtTargetAcceptanceMethod {
        JwtTargetAcceptanceMethod::Get
    }

    /// Safe non-secret operator policy reference.
    pub fn operator_policy_reference(&self) -> &str {
        &self.operator_policy_reference
    }

    /// Safe non-secret operator policy revision.
    pub fn operator_policy_revision(&self) -> &str {
        &self.operator_policy_revision
    }

    /// Exact selected application URL.
    ///
    /// The value is runtime input and is never copied into the value-free
    /// audit.
    pub const fn application(&self) -> &Url {
        &self.application
    }

    /// Exact selected GET resource URL.
    ///
    /// The value is runtime input and is never copied into the value-free
    /// audit.
    pub const fn resource(&self) -> &Url {
        &self.resource
    }

    /// Safe non-secret resource reference used by audit output.
    pub fn resource_reference(&self) -> &str {
        &self.resource_reference
    }

    /// Private top-level JSON marker selected by the operator.
    ///
    /// The field name is exposed only for response classification and is
    /// never copied into the audit.
    pub fn success_json_field(&self) -> &str {
        &self.success_json_field
    }

    /// Fixed request ceiling.
    pub const fn max_requests(&self) -> u8 {
        MAX_JWT_TARGET_ACCEPTANCE_REQUESTS
    }

    /// Fixed active-request ceiling.
    pub const fn max_active_requests(&self) -> u8 {
        MAX_JWT_TARGET_ACCEPTANCE_ACTIVE_REQUESTS
    }

    /// Fixed per-response retained/interpreted byte ceiling.
    pub const fn max_response_bytes(&self) -> u64 {
        MAX_JWT_TARGET_ACCEPTANCE_RESPONSE_BYTES
    }

    /// Fixed aggregate retained/interpreted byte ceiling.
    pub const fn max_total_response_bytes(&self) -> u64 {
        MAX_JWT_TARGET_ACCEPTANCE_TOTAL_RESPONSE_BYTES
    }
}

impl fmt::Debug for JwtTargetAcceptancePolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JwtTargetAcceptancePolicy")
            .field("operator_policy_reference", &self.operator_policy_reference)
            .field("operator_policy_revision", &self.operator_policy_revision)
            .field("application", &"<redacted>")
            .field("resource", &"<redacted>")
            .field("resource_reference", &self.resource_reference)
            .field("success_json_field", &"<redacted>")
            .field("method", &JwtTargetAcceptanceMethod::Get)
            .finish()
    }
}

/// Static, redaction-safe target policy failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum JwtTargetAcceptancePolicyError {
    /// The operator policy reference was not a bounded lowercase ASCII slug.
    #[error("JWT target-acceptance operator policy reference is invalid")]
    InvalidOperatorPolicyReference,
    /// The operator policy revision was not a bounded lowercase ASCII slug.
    #[error("JWT target-acceptance operator policy revision is invalid")]
    InvalidOperatorPolicyRevision,
    /// The application URL violated the strict HTTP(S) URL shape.
    #[error("JWT target-acceptance application URL is invalid")]
    InvalidApplication,
    /// The resource URL violated the strict HTTP(S) URL shape.
    #[error("JWT target-acceptance resource URL is invalid")]
    InvalidResource,
    /// The resource scheme, host, or effective port differed from the application.
    #[error("JWT target-acceptance resource has a foreign origin")]
    ForeignResourceOrigin,
    /// The resource path was not segment-contained by the application path.
    #[error("JWT target-acceptance resource is outside the application path")]
    ResourceOutsideApplication,
    /// The resource reference was not a bounded lowercase ASCII slug.
    #[error("JWT target-acceptance resource reference is invalid")]
    InvalidResourceReference,
    /// The selected top-level JSON field was not a bounded safe ASCII name.
    #[error("JWT target-acceptance JSON marker field is invalid")]
    InvalidSuccessJsonField,
}

fn valid_slug(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'-' | b'_' | b'.'))
        })
}

fn valid_json_field(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_JSON_FIELD_BYTES
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'-')
                || (index > 0 && matches!(byte, b'.' | b':'))
        })
}

fn validate_http_url(url: &Url) -> Result<(), ()> {
    if !matches!(url.scheme(), "http" | "https")
        || url.host().is_none()
        || url.port_or_known_default().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.path().starts_with('/')
        || url.path().contains('%')
        || url.path().contains('\\')
        || url.path().contains("//")
    {
        return Err(());
    }
    Ok(())
}

fn same_exact_origin(application: &Url, resource: &Url) -> bool {
    application.scheme() == resource.scheme()
        && application.host() == resource.host()
        && application.port_or_known_default() == resource.port_or_known_default()
}

fn path_within_application(application: &Url, resource: &Url) -> bool {
    let application_path = application.path();
    let resource_path = resource.path();
    if application_path == "/" {
        return true;
    }
    let boundary = application_path.trim_end_matches('/');
    resource_path == boundary
        || resource_path
            .strip_prefix(boundary)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

/// Candidate/replay stage for one ordered role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum JwtTargetAcceptanceLegStage {
    /// First observation in a pair.
    Candidate,
    /// Stability replay in a pair.
    Replay,
}

/// Passive/active classification derived from a role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum JwtTargetAcceptanceActivity {
    /// A valid-token baseline or anonymous control.
    Passive,
    /// An invalid-signature control request.
    Active,
}

/// Exact closed order of target-acceptance request roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum JwtTargetAcceptanceLegRole {
    /// Valid token, first observation.
    ValidCandidate,
    /// No Authorization value, first observation.
    AnonymousCandidate,
    /// Invalid-signature token, first observation.
    InvalidCandidate,
    /// Valid token replay.
    ValidReplay,
    /// No Authorization value, replay.
    AnonymousReplay,
    /// Invalid-signature token replay.
    InvalidReplay,
}

impl JwtTargetAcceptanceLegRole {
    /// Required order for all aggregate audits.
    pub const ORDERED: [Self; MAX_JWT_TARGET_ACCEPTANCE_REQUESTS as usize] = [
        Self::ValidCandidate,
        Self::AnonymousCandidate,
        Self::InvalidCandidate,
        Self::ValidReplay,
        Self::AnonymousReplay,
        Self::InvalidReplay,
    ];

    /// Stable action identifier used for this role.
    pub const fn action_id(self) -> &'static str {
        match self {
            Self::ValidCandidate | Self::ValidReplay => {
                JWT_TARGET_ACCEPTANCE_VALID_BASELINE_ACTION_ID
            },
            Self::AnonymousCandidate | Self::AnonymousReplay => {
                JWT_TARGET_ACCEPTANCE_ANONYMOUS_CONTROL_ACTION_ID
            },
            Self::InvalidCandidate | Self::InvalidReplay => {
                JWT_TARGET_ACCEPTANCE_INVALID_CONTROL_ACTION_ID
            },
        }
    }

    /// Candidate/replay stage associated with this role.
    pub const fn stage(self) -> JwtTargetAcceptanceLegStage {
        match self {
            Self::ValidCandidate | Self::AnonymousCandidate | Self::InvalidCandidate => {
                JwtTargetAcceptanceLegStage::Candidate
            },
            Self::ValidReplay | Self::AnonymousReplay | Self::InvalidReplay => {
                JwtTargetAcceptanceLegStage::Replay
            },
        }
    }

    /// Passive/active classification associated with this role.
    pub const fn activity(self) -> JwtTargetAcceptanceActivity {
        if self.is_active() {
            JwtTargetAcceptanceActivity::Active
        } else {
            JwtTargetAcceptanceActivity::Passive
        }
    }

    /// Whether the role uses an invalid-signature control token.
    pub const fn is_active(self) -> bool {
        matches!(self, Self::InvalidCandidate | Self::InvalidReplay)
    }

    /// Whether an Authorization value is required for the role.
    pub const fn requires_authorization(self) -> bool {
        !self.is_anonymous()
    }

    /// Whether the role uses the supplied valid token.
    pub const fn uses_valid_token(self) -> bool {
        matches!(self, Self::ValidCandidate | Self::ValidReplay)
    }

    /// Whether the role uses the invalid-signature control token.
    pub const fn uses_invalid_token(self) -> bool {
        self.is_active()
    }

    /// Whether the role omits Authorization.
    pub const fn is_anonymous(self) -> bool {
        matches!(self, Self::AnonymousCandidate | Self::AnonymousReplay)
    }
}

/// Whether a leg was dispatched by the owning runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum JwtTargetAcceptanceDispatchStatus {
    /// No target request was sent for the role.
    NotDispatched,
    /// One target request was sent for the role.
    Dispatched,
}

/// Whether response evidence was committed for a dispatched leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum JwtTargetAcceptanceCommitStatus {
    /// No response evidence was committed.
    NotCommitted,
    /// Response evidence was committed exactly once.
    Committed,
}

/// Completeness and JSON-marker classification state for one response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum JwtTargetAcceptanceResponseStatus {
    /// No complete response classification is available.
    NotClassified,
    /// The response was complete and the selected top-level marker was classified.
    CompleteAndClassified,
    /// The response was incomplete and the marker was not evaluated.
    Incomplete,
}

/// Value-free observation of the one privately selected JSON marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum JwtTargetAcceptanceMarkerStatus {
    /// The selected top-level marker was observed.
    Observed,
    /// The selected top-level marker was not observed.
    NotObserved,
    /// No complete marker classification was available.
    NotEvaluated,
}

/// Value-free facts for exactly one ordered request role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtTargetAcceptanceLegFact {
    role: JwtTargetAcceptanceLegRole,
    dispatched: JwtTargetAcceptanceDispatchStatus,
    committed: JwtTargetAcceptanceCommitStatus,
    response_status: JwtTargetAcceptanceResponseStatus,
    marker_status: JwtTargetAcceptanceMarkerStatus,
    retained_response_bytes: u64,
    accounted_response_bytes: u64,
    evidence_reference: Option<String>,
}

impl JwtTargetAcceptanceLegFact {
    /// Constructs and validates one value-free leg fact.
    pub fn new(
        role: JwtTargetAcceptanceLegRole,
        dispatched: JwtTargetAcceptanceDispatchStatus,
        committed: JwtTargetAcceptanceCommitStatus,
        response_status: JwtTargetAcceptanceResponseStatus,
        marker_status: JwtTargetAcceptanceMarkerStatus,
        accounted_response_bytes: u64,
        evidence_reference: Option<String>,
    ) -> Result<Self, JwtTargetAcceptanceLegFactError> {
        Self::new_with_transport_accounting(
            role,
            dispatched,
            committed,
            response_status,
            marker_status,
            accounted_response_bytes,
            accounted_response_bytes,
            evidence_reference,
        )
    }

    /// Constructs one fact while retaining both the bounded body bytes and
    /// the broker's exact transport accounting. A delivered transport chunk
    /// may cross the retention ceiling; those extra bytes remain charged but
    /// are never retained or interpreted.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_transport_accounting(
        role: JwtTargetAcceptanceLegRole,
        dispatched: JwtTargetAcceptanceDispatchStatus,
        committed: JwtTargetAcceptanceCommitStatus,
        response_status: JwtTargetAcceptanceResponseStatus,
        marker_status: JwtTargetAcceptanceMarkerStatus,
        retained_response_bytes: u64,
        accounted_response_bytes: u64,
        evidence_reference: Option<String>,
    ) -> Result<Self, JwtTargetAcceptanceLegFactError> {
        let fact = Self {
            role,
            dispatched,
            committed,
            response_status,
            marker_status,
            retained_response_bytes,
            accounted_response_bytes,
            evidence_reference,
        };
        fact.validate()?;
        Ok(fact)
    }

    /// Creates the only valid undispatched placeholder for a role.
    pub fn not_dispatched(role: JwtTargetAcceptanceLegRole) -> Self {
        Self {
            role,
            dispatched: JwtTargetAcceptanceDispatchStatus::NotDispatched,
            committed: JwtTargetAcceptanceCommitStatus::NotCommitted,
            response_status: JwtTargetAcceptanceResponseStatus::NotClassified,
            marker_status: JwtTargetAcceptanceMarkerStatus::NotEvaluated,
            retained_response_bytes: 0,
            accounted_response_bytes: 0,
            evidence_reference: None,
        }
    }

    /// Ordered role represented by this fact.
    pub const fn role(&self) -> JwtTargetAcceptanceLegRole {
        self.role
    }

    /// Dispatch state.
    pub const fn dispatch_status(&self) -> JwtTargetAcceptanceDispatchStatus {
        self.dispatched
    }

    /// Whether one request was dispatched.
    pub const fn was_dispatched(&self) -> bool {
        matches!(
            self.dispatched,
            JwtTargetAcceptanceDispatchStatus::Dispatched
        )
    }

    /// Evidence-commit state.
    pub const fn commit_status(&self) -> JwtTargetAcceptanceCommitStatus {
        self.committed
    }

    /// Whether response evidence was committed.
    pub const fn was_committed(&self) -> bool {
        matches!(self.committed, JwtTargetAcceptanceCommitStatus::Committed)
    }

    /// Response completeness/classification state.
    pub const fn response_status(&self) -> JwtTargetAcceptanceResponseStatus {
        self.response_status
    }

    /// Selected-marker observation state.
    pub const fn marker_status(&self) -> JwtTargetAcceptanceMarkerStatus {
        self.marker_status
    }

    /// Response bytes retained for bounded classification.
    pub const fn retained_response_bytes(&self) -> u64 {
        self.retained_response_bytes
    }

    /// Exact response bytes charged by the shared transport authority.
    pub const fn accounted_response_bytes(&self) -> u64 {
        self.accounted_response_bytes
    }

    /// Optional bounded opaque evidence reference.
    pub fn evidence_reference(&self) -> Option<&str> {
        self.evidence_reference.as_deref()
    }

    fn is_complete_classification(&self) -> bool {
        self.was_dispatched()
            && self.was_committed()
            && self.response_status == JwtTargetAcceptanceResponseStatus::CompleteAndClassified
            && matches!(
                self.marker_status,
                JwtTargetAcceptanceMarkerStatus::Observed
                    | JwtTargetAcceptanceMarkerStatus::NotObserved
            )
    }

    fn validate(&self) -> Result<(), JwtTargetAcceptanceLegFactError> {
        if self.retained_response_bytes > MAX_JWT_TARGET_ACCEPTANCE_RESPONSE_BYTES {
            return Err(JwtTargetAcceptanceLegFactError::ResponseBytesExceeded);
        }
        if self.accounted_response_bytes < self.retained_response_bytes {
            return Err(JwtTargetAcceptanceLegFactError::TransportBytesBelowRetained);
        }
        if let Some(reference) = self.evidence_reference.as_deref() {
            if !valid_evidence_reference(reference) {
                return Err(JwtTargetAcceptanceLegFactError::InvalidEvidenceReference);
            }
        }

        let valid = match (self.dispatched, self.committed) {
            (
                JwtTargetAcceptanceDispatchStatus::NotDispatched,
                JwtTargetAcceptanceCommitStatus::NotCommitted,
            ) => {
                self.response_status == JwtTargetAcceptanceResponseStatus::NotClassified
                    && self.marker_status == JwtTargetAcceptanceMarkerStatus::NotEvaluated
                    && self.retained_response_bytes == 0
                    && self.accounted_response_bytes == 0
                    && self.evidence_reference.is_none()
            },
            (
                JwtTargetAcceptanceDispatchStatus::Dispatched,
                JwtTargetAcceptanceCommitStatus::NotCommitted,
            ) => {
                self.response_status != JwtTargetAcceptanceResponseStatus::CompleteAndClassified
                    && self.marker_status == JwtTargetAcceptanceMarkerStatus::NotEvaluated
                    && self.evidence_reference.is_none()
            },
            (
                JwtTargetAcceptanceDispatchStatus::Dispatched,
                JwtTargetAcceptanceCommitStatus::Committed,
            ) => {
                self.evidence_reference.is_some()
                    && match self.response_status {
                        JwtTargetAcceptanceResponseStatus::CompleteAndClassified => matches!(
                            self.marker_status,
                            JwtTargetAcceptanceMarkerStatus::Observed
                                | JwtTargetAcceptanceMarkerStatus::NotObserved
                        ),
                        JwtTargetAcceptanceResponseStatus::NotClassified
                        | JwtTargetAcceptanceResponseStatus::Incomplete => {
                            self.marker_status == JwtTargetAcceptanceMarkerStatus::NotEvaluated
                        },
                    }
            },
            (
                JwtTargetAcceptanceDispatchStatus::NotDispatched,
                JwtTargetAcceptanceCommitStatus::Committed,
            ) => false,
        };

        if valid {
            Ok(())
        } else {
            Err(JwtTargetAcceptanceLegFactError::InconsistentState)
        }
    }
}

fn valid_evidence_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_JWT_TARGET_ACCEPTANCE_EVIDENCE_REFERENCE_BYTES
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

/// Static, redaction-safe leg construction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum JwtTargetAcceptanceLegFactError {
    /// Dispatch, commit, classification, marker, byte, and evidence states disagreed.
    #[error("JWT target-acceptance leg state is inconsistent")]
    InconsistentState,
    /// The leg exceeded the fixed per-response retention ceiling.
    #[error("JWT target-acceptance leg exceeds its response-byte limit")]
    ResponseBytesExceeded,
    /// Exact transport accounting was smaller than the retained body.
    #[error("JWT target-acceptance transport bytes cannot be below retained bytes")]
    TransportBytesBelowRetained,
    /// The optional evidence reference was empty, unsafe, or oversized.
    #[error("JWT target-acceptance evidence reference is invalid")]
    InvalidEvidenceReference,
}

/// Stable candidate/replay relationship for one marker dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum JwtTargetAcceptanceDimension {
    /// Candidate and replay both observed the selected marker.
    ObservedStable,
    /// Candidate and replay both did not observe the selected marker.
    NotObservedStable,
    /// Candidate and replay produced different complete marker observations.
    Unstable,
    /// Both role slots were deliberately not dispatched.
    NotEvaluated,
    /// At least one role slot lacked a complete classified response.
    Incomplete,
}

/// Value-free reason the target portion was not eligible to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum JwtTargetAcceptanceNotEligibleReason {
    /// A supported local compact-token parse was not established.
    LocalParsingNotEstablished,
    /// Local expected-claim policy consistency was not established.
    LocalPolicyNotEstablished,
    /// Local signature validity against the selected key was not established.
    LocalSignatureNotEstablished,
    /// The required target runtime authority was unavailable.
    RuntimeAuthorityUnavailable,
    /// The bounded target request budget was unavailable.
    RequestBudgetUnavailable,
}

/// Typed reason a complete target conclusion was unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum JwtTargetAcceptanceIncompleteReason {
    /// Local or runtime eligibility was not established before target work.
    NotEligible(JwtTargetAcceptanceNotEligibleReason),
    /// One required role was never dispatched.
    LegNotDispatched { role: JwtTargetAcceptanceLegRole },
    /// A dispatched role did not commit response evidence.
    LegNotCommitted { role: JwtTargetAcceptanceLegRole },
    /// A committed response was incomplete.
    ResponseIncomplete { role: JwtTargetAcceptanceLegRole },
    /// A committed response was not classified for the selected marker.
    ResponseNotClassified { role: JwtTargetAcceptanceLegRole },
}

/// Conservative aggregate interpretation of the three paired dimensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum JwtTargetAcceptanceConclusion {
    /// Valid observations were stable, anonymous controls were stably absent,
    /// and invalid-signature controls stably observed the selected marker.
    InvalidSignatureControlMarkerObservedWithAnonymousControl,
    /// Anonymous controls stably observed the selected marker, suppressing any
    /// invalid-signature-specific interpretation.
    PublicOrTokenAgnosticMarkerObserved,
    /// Valid observations were stable, anonymous controls were stably absent,
    /// and invalid-signature controls stably lacked the selected marker.
    InvalidControlMarkerNotObserved,
    /// At least one complete candidate/replay pair disagreed.
    UnstableInconclusive,
    /// All required facts were complete and stable but did not match a more
    /// specific relationship.
    Inconclusive,
    /// Required facts or eligibility were incomplete for a stable conclusion.
    Incomplete(JwtTargetAcceptanceIncompleteReason),
}

/// Derived integer accounting for one aggregate audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct JwtTargetAcceptanceAccounting {
    dispatched_request_count: u8,
    dispatched_passive_request_count: u8,
    dispatched_active_request_count: u8,
    committed_response_count: u8,
    retained_response_bytes: u64,
    accounted_response_bytes: u64,
}

impl JwtTargetAcceptanceAccounting {
    /// Total dispatched target requests.
    pub const fn dispatched_request_count(self) -> u8 {
        self.dispatched_request_count
    }

    /// Dispatched valid and anonymous legs.
    pub const fn dispatched_passive_request_count(self) -> u8 {
        self.dispatched_passive_request_count
    }

    /// Dispatched invalid-signature control legs.
    pub const fn dispatched_active_request_count(self) -> u8 {
        self.dispatched_active_request_count
    }

    /// Responses whose evidence was committed.
    pub const fn committed_response_count(self) -> u8 {
        self.committed_response_count
    }

    /// Total body bytes retained and interpreted across all roles.
    pub const fn retained_response_bytes(self) -> u64 {
        self.retained_response_bytes
    }

    /// Total response bytes charged across all roles.
    pub const fn accounted_response_bytes(self) -> u64 {
        self.accounted_response_bytes
    }
}

/// Strict value-free aggregate audit for the target portion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JwtTargetAcceptanceAudit {
    schema: &'static str,
    policy: &'static str,
    operator_policy_reference: String,
    operator_policy_revision: String,
    resource_reference: String,
    method: JwtTargetAcceptanceMethod,
    legs: Vec<JwtTargetAcceptanceLegFact>,
    accounting: JwtTargetAcceptanceAccounting,
    valid_marker: JwtTargetAcceptanceDimension,
    anonymous_marker: JwtTargetAcceptanceDimension,
    invalid_marker: JwtTargetAcceptanceDimension,
    conclusion: JwtTargetAcceptanceConclusion,
    #[serde(skip)]
    preparation_binding: Option<JwtTargetAcceptanceBinding>,
}

impl JwtTargetAcceptanceAudit {
    /// Validates six exact ordered roles and derives a strict aggregate audit.
    pub fn from_legs(
        policy: &JwtTargetAcceptancePolicy,
        legs: Vec<JwtTargetAcceptanceLegFact>,
    ) -> Result<Self, JwtTargetAcceptanceAuditError> {
        if legs.len() != usize::from(MAX_JWT_TARGET_ACCEPTANCE_REQUESTS) {
            return Err(JwtTargetAcceptanceAuditError::UnexpectedLegCount);
        }
        for (index, (fact, expected_role)) in legs
            .iter()
            .zip(JwtTargetAcceptanceLegRole::ORDERED)
            .enumerate()
        {
            if fact.role != expected_role {
                return Err(JwtTargetAcceptanceAuditError::UnexpectedRoleOrder {
                    ordinal: u8::try_from(index).expect("six roles fit u8"),
                });
            }
            fact.validate()
                .map_err(|reason| JwtTargetAcceptanceAuditError::InvalidLeg {
                    role: fact.role,
                    reason,
                })?;
        }

        validate_active_prerequisite(&legs, 0, 1, 2)?;
        validate_active_prerequisite(&legs, 3, 4, 5)?;
        validate_sequential_lifecycle(&legs)?;

        let mut evidence_references = BTreeSet::new();
        let mut dispatched_request_count = 0_u8;
        let mut dispatched_passive_request_count = 0_u8;
        let mut dispatched_active_request_count = 0_u8;
        let mut committed_response_count = 0_u8;
        let mut retained_response_bytes = 0_u64;
        let mut accounted_response_bytes = 0_u64;
        for fact in &legs {
            if fact.was_dispatched() {
                dispatched_request_count = dispatched_request_count
                    .checked_add(1)
                    .ok_or(JwtTargetAcceptanceAuditError::RequestCountExceeded)?;
                if fact.role.is_active() {
                    dispatched_active_request_count = dispatched_active_request_count
                        .checked_add(1)
                        .ok_or(JwtTargetAcceptanceAuditError::ActiveRequestCountExceeded)?;
                } else {
                    dispatched_passive_request_count = dispatched_passive_request_count
                        .checked_add(1)
                        .ok_or(JwtTargetAcceptanceAuditError::RequestCountExceeded)?;
                }
            }
            if fact.was_committed() {
                committed_response_count = committed_response_count
                    .checked_add(1)
                    .ok_or(JwtTargetAcceptanceAuditError::RequestCountExceeded)?;
            }
            retained_response_bytes = retained_response_bytes
                .checked_add(fact.retained_response_bytes)
                .ok_or(JwtTargetAcceptanceAuditError::TotalResponseBytesExceeded)?;
            accounted_response_bytes = accounted_response_bytes
                .checked_add(fact.accounted_response_bytes)
                .ok_or(JwtTargetAcceptanceAuditError::TransportResponseBytesOverflow)?;
            if let Some(reference) = fact.evidence_reference.as_deref() {
                if !evidence_references.insert(reference) {
                    return Err(JwtTargetAcceptanceAuditError::DuplicateEvidenceReference);
                }
            }
        }
        if dispatched_request_count > MAX_JWT_TARGET_ACCEPTANCE_REQUESTS {
            return Err(JwtTargetAcceptanceAuditError::RequestCountExceeded);
        }
        if dispatched_active_request_count > MAX_JWT_TARGET_ACCEPTANCE_ACTIVE_REQUESTS {
            return Err(JwtTargetAcceptanceAuditError::ActiveRequestCountExceeded);
        }
        if retained_response_bytes > MAX_JWT_TARGET_ACCEPTANCE_TOTAL_RESPONSE_BYTES {
            return Err(JwtTargetAcceptanceAuditError::TotalResponseBytesExceeded);
        }

        let accounting = JwtTargetAcceptanceAccounting {
            dispatched_request_count,
            dispatched_passive_request_count,
            dispatched_active_request_count,
            committed_response_count,
            retained_response_bytes,
            accounted_response_bytes,
        };
        let valid_marker = pair_dimension(&legs[0], &legs[3]);
        let anonymous_marker = pair_dimension(&legs[1], &legs[4]);
        let invalid_marker = pair_dimension(&legs[2], &legs[5]);
        let conclusion = derive_conclusion(&legs, valid_marker, anonymous_marker, invalid_marker);

        Ok(Self::new_value_free(
            policy,
            legs,
            accounting,
            valid_marker,
            anonymous_marker,
            invalid_marker,
            conclusion,
        ))
    }

    /// Creates a zero-request audit when prerequisites are not established.
    pub fn not_eligible(
        policy: &JwtTargetAcceptancePolicy,
        reason: JwtTargetAcceptanceNotEligibleReason,
    ) -> Self {
        Self::new_value_free(
            policy,
            Vec::new(),
            JwtTargetAcceptanceAccounting {
                dispatched_request_count: 0,
                dispatched_passive_request_count: 0,
                dispatched_active_request_count: 0,
                committed_response_count: 0,
                retained_response_bytes: 0,
                accounted_response_bytes: 0,
            },
            JwtTargetAcceptanceDimension::NotEvaluated,
            JwtTargetAcceptanceDimension::NotEvaluated,
            JwtTargetAcceptanceDimension::NotEvaluated,
            JwtTargetAcceptanceConclusion::Incomplete(
                JwtTargetAcceptanceIncompleteReason::NotEligible(reason),
            ),
        )
    }

    fn new_value_free(
        policy: &JwtTargetAcceptancePolicy,
        legs: Vec<JwtTargetAcceptanceLegFact>,
        accounting: JwtTargetAcceptanceAccounting,
        valid_marker: JwtTargetAcceptanceDimension,
        anonymous_marker: JwtTargetAcceptanceDimension,
        invalid_marker: JwtTargetAcceptanceDimension,
        conclusion: JwtTargetAcceptanceConclusion,
    ) -> Self {
        Self {
            schema: JWT_TARGET_ACCEPTANCE_AUDIT_SCHEMA,
            policy: JWT_TARGET_ACCEPTANCE_POLICY_ID,
            operator_policy_reference: policy.operator_policy_reference.clone(),
            operator_policy_revision: policy.operator_policy_revision.clone(),
            resource_reference: policy.resource_reference.clone(),
            method: JwtTargetAcceptanceMethod::Get,
            legs,
            accounting,
            valid_marker,
            anonymous_marker,
            invalid_marker,
            conclusion,
            preparation_binding: None,
        }
    }

    pub(crate) fn bind_to_preparation(mut self, binding: JwtTargetAcceptanceBinding) -> Self {
        self.preparation_binding = Some(binding);
        self
    }

    pub(crate) const fn preparation_binding(&self) -> Option<&JwtTargetAcceptanceBinding> {
        self.preparation_binding.as_ref()
    }

    /// Stable audit schema identifier.
    pub const fn schema(&self) -> &'static str {
        JWT_TARGET_ACCEPTANCE_AUDIT_SCHEMA
    }

    /// Stable interpretation-policy identifier.
    pub const fn policy(&self) -> &'static str {
        JWT_TARGET_ACCEPTANCE_POLICY_ID
    }

    /// Safe non-secret operator policy reference.
    pub fn operator_policy_reference(&self) -> &str {
        &self.operator_policy_reference
    }

    /// Safe non-secret operator policy revision.
    pub fn operator_policy_revision(&self) -> &str {
        &self.operator_policy_revision
    }

    /// Safe non-secret selected-resource reference.
    pub fn resource_reference(&self) -> &str {
        &self.resource_reference
    }

    /// Fixed request method.
    pub const fn method(&self) -> JwtTargetAcceptanceMethod {
        self.method
    }

    /// Ordered value-free leg facts. This is empty only for `not_eligible`.
    pub fn legs(&self) -> &[JwtTargetAcceptanceLegFact] {
        &self.legs
    }

    /// Derived integer accounting.
    pub const fn accounting(&self) -> JwtTargetAcceptanceAccounting {
        self.accounting
    }

    /// Stable valid-token marker dimension.
    pub const fn valid_marker(&self) -> JwtTargetAcceptanceDimension {
        self.valid_marker
    }

    /// Stable anonymous marker dimension.
    pub const fn anonymous_marker(&self) -> JwtTargetAcceptanceDimension {
        self.anonymous_marker
    }

    /// Stable invalid-signature control marker dimension.
    pub const fn invalid_marker(&self) -> JwtTargetAcceptanceDimension {
        self.invalid_marker
    }

    /// Conservative aggregate conclusion.
    pub const fn conclusion(&self) -> JwtTargetAcceptanceConclusion {
        self.conclusion
    }
}

fn validate_active_prerequisite(
    legs: &[JwtTargetAcceptanceLegFact],
    valid_index: usize,
    anonymous_index: usize,
    invalid_index: usize,
) -> Result<(), JwtTargetAcceptanceAuditError> {
    let invalid = &legs[invalid_index];
    if invalid.was_dispatched()
        && !active_prerequisite_is_established(legs, valid_index, anonymous_index)
    {
        return Err(
            JwtTargetAcceptanceAuditError::ActiveLegPrerequisiteNotEstablished {
                role: invalid.role,
            },
        );
    }
    Ok(())
}

fn active_prerequisite_is_established(
    legs: &[JwtTargetAcceptanceLegFact],
    valid_index: usize,
    anonymous_index: usize,
) -> bool {
    legs[valid_index].is_complete_classification()
        && legs[valid_index].marker_status == JwtTargetAcceptanceMarkerStatus::Observed
        && legs[anonymous_index].is_complete_classification()
        && legs[anonymous_index].marker_status == JwtTargetAcceptanceMarkerStatus::NotObserved
}

fn validate_sequential_lifecycle(
    legs: &[JwtTargetAcceptanceLegFact],
) -> Result<(), JwtTargetAcceptanceAuditError> {
    let mut stopped = false;
    let mut retained_response_bytes = 0_u64;
    for (index, leg) in legs.iter().enumerate() {
        if stopped {
            if leg.was_dispatched() {
                return Err(JwtTargetAcceptanceAuditError::DispatchAfterStop { role: leg.role });
            }
            continue;
        }

        if !leg.was_dispatched() {
            let prerequisite_skip = match index {
                2 => !active_prerequisite_is_established(legs, 0, 1),
                5 => !active_prerequisite_is_established(legs, 3, 4),
                _ => false,
            };
            if !prerequisite_skip {
                stopped = true;
            }
            continue;
        }

        retained_response_bytes = retained_response_bytes
            .checked_add(leg.retained_response_bytes)
            .ok_or(JwtTargetAcceptanceAuditError::TotalResponseBytesExceeded)?;
        if !leg.was_committed()
            || retained_response_bytes >= MAX_JWT_TARGET_ACCEPTANCE_TOTAL_RESPONSE_BYTES
        {
            stopped = true;
        }
    }
    Ok(())
}

fn pair_dimension(
    candidate: &JwtTargetAcceptanceLegFact,
    replay: &JwtTargetAcceptanceLegFact,
) -> JwtTargetAcceptanceDimension {
    if candidate.dispatch_status() == JwtTargetAcceptanceDispatchStatus::NotDispatched
        && replay.dispatch_status() == JwtTargetAcceptanceDispatchStatus::NotDispatched
    {
        return JwtTargetAcceptanceDimension::NotEvaluated;
    }
    if !candidate.is_complete_classification() || !replay.is_complete_classification() {
        return JwtTargetAcceptanceDimension::Incomplete;
    }
    match (candidate.marker_status, replay.marker_status) {
        (JwtTargetAcceptanceMarkerStatus::Observed, JwtTargetAcceptanceMarkerStatus::Observed) => {
            JwtTargetAcceptanceDimension::ObservedStable
        },
        (
            JwtTargetAcceptanceMarkerStatus::NotObserved,
            JwtTargetAcceptanceMarkerStatus::NotObserved,
        ) => JwtTargetAcceptanceDimension::NotObservedStable,
        _ => JwtTargetAcceptanceDimension::Unstable,
    }
}

fn derive_conclusion(
    legs: &[JwtTargetAcceptanceLegFact],
    valid: JwtTargetAcceptanceDimension,
    anonymous: JwtTargetAcceptanceDimension,
    invalid: JwtTargetAcceptanceDimension,
) -> JwtTargetAcceptanceConclusion {
    if [valid, anonymous, invalid].contains(&JwtTargetAcceptanceDimension::Unstable) {
        return JwtTargetAcceptanceConclusion::UnstableInconclusive;
    }
    if anonymous == JwtTargetAcceptanceDimension::ObservedStable {
        return JwtTargetAcceptanceConclusion::PublicOrTokenAgnosticMarkerObserved;
    }
    if valid == JwtTargetAcceptanceDimension::ObservedStable
        && anonymous == JwtTargetAcceptanceDimension::NotObservedStable
        && invalid == JwtTargetAcceptanceDimension::ObservedStable
    {
        return JwtTargetAcceptanceConclusion::InvalidSignatureControlMarkerObservedWithAnonymousControl;
    }
    if valid == JwtTargetAcceptanceDimension::ObservedStable
        && anonymous == JwtTargetAcceptanceDimension::NotObservedStable
        && invalid == JwtTargetAcceptanceDimension::NotObservedStable
    {
        return JwtTargetAcceptanceConclusion::InvalidControlMarkerNotObserved;
    }
    if [valid, anonymous, invalid].iter().any(|dimension| {
        matches!(
            dimension,
            JwtTargetAcceptanceDimension::Incomplete | JwtTargetAcceptanceDimension::NotEvaluated
        )
    }) {
        return JwtTargetAcceptanceConclusion::Incomplete(first_incomplete_reason(legs));
    }
    JwtTargetAcceptanceConclusion::Inconclusive
}

fn first_incomplete_reason(
    legs: &[JwtTargetAcceptanceLegFact],
) -> JwtTargetAcceptanceIncompleteReason {
    for fact in legs {
        if !fact.was_dispatched() {
            return JwtTargetAcceptanceIncompleteReason::LegNotDispatched { role: fact.role };
        }
        if !fact.was_committed() {
            return JwtTargetAcceptanceIncompleteReason::LegNotCommitted { role: fact.role };
        }
        match fact.response_status {
            JwtTargetAcceptanceResponseStatus::Incomplete => {
                return JwtTargetAcceptanceIncompleteReason::ResponseIncomplete { role: fact.role };
            },
            JwtTargetAcceptanceResponseStatus::NotClassified => {
                return JwtTargetAcceptanceIncompleteReason::ResponseNotClassified {
                    role: fact.role,
                };
            },
            JwtTargetAcceptanceResponseStatus::CompleteAndClassified => {},
        }
    }
    // A not-evaluated dimension can only arise from undispatched role slots,
    // which the loop above handles. This fallback keeps the function total if
    // a future enum variant is added without updating the derivation.
    JwtTargetAcceptanceIncompleteReason::LegNotDispatched {
        role: JwtTargetAcceptanceLegRole::ValidCandidate,
    }
}

/// Static, redaction-safe aggregate validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum JwtTargetAcceptanceAuditError {
    /// The aggregate did not contain exactly six role slots.
    #[error("JWT target-acceptance audit requires exactly six ordered legs")]
    UnexpectedLegCount,
    /// One role did not appear at its exact zero-based ordinal.
    #[error("JWT target-acceptance leg role order is invalid")]
    UnexpectedRoleOrder { ordinal: u8 },
    /// A leg bypassed its own constructor invariants.
    #[error("JWT target-acceptance aggregate contains an invalid leg")]
    InvalidLeg {
        /// Role of the invalid fact.
        role: JwtTargetAcceptanceLegRole,
        /// Static invariant failure.
        reason: JwtTargetAcceptanceLegFactError,
    },
    /// An invalid-signature control was dispatched without its passive controls.
    #[error("JWT target-acceptance active leg prerequisite is not established")]
    ActiveLegPrerequisiteNotEstablished {
        /// Active role rejected by the prerequisite check.
        role: JwtTargetAcceptanceLegRole,
    },
    /// A later request was represented after cancellation, a failed commit,
    /// a passive undispatched slot, or exhaustion of the retained-byte cap had
    /// already frozen the ordered tail.
    #[error("JWT target-acceptance dispatched work appears after the ordered runtime stopped")]
    DispatchAfterStop {
        /// First dispatched role that appears after the stop boundary.
        role: JwtTargetAcceptanceLegRole,
    },
    /// More than six request dispatches were represented.
    #[error("JWT target-acceptance request count exceeds its limit")]
    RequestCountExceeded,
    /// More than two active request dispatches were represented.
    #[error("JWT target-acceptance active request count exceeds its limit")]
    ActiveRequestCountExceeded,
    /// Aggregate retained response bytes exceeded 256 KiB.
    #[error("JWT target-acceptance total response bytes exceed their limit")]
    TotalResponseBytesExceeded,
    /// Exact transport response-byte accounting overflowed `u64`.
    #[error("JWT target-acceptance transport response-byte accounting overflowed")]
    TransportResponseBytesOverflow,
    /// Two committed legs referenced the same evidence object.
    #[error("JWT target-acceptance evidence references must be unique")]
    DuplicateEvidenceReference,
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIVATE_FIELD: &str = "private_acceptance_marker";

    fn policy() -> JwtTargetAcceptancePolicy {
        JwtTargetAcceptancePolicy::new(
            ("operator-policy", "revision-1"),
            Url::parse("https://example.test/app/").unwrap(),
            Url::parse("https://example.test/app/profile").unwrap(),
            "profile-resource",
            PRIVATE_FIELD,
        )
        .unwrap()
    }

    fn complete(
        role: JwtTargetAcceptanceLegRole,
        marker: JwtTargetAcceptanceMarkerStatus,
        bytes: u64,
        evidence_ordinal: u8,
    ) -> JwtTargetAcceptanceLegFact {
        JwtTargetAcceptanceLegFact::new(
            role,
            JwtTargetAcceptanceDispatchStatus::Dispatched,
            JwtTargetAcceptanceCommitStatus::Committed,
            JwtTargetAcceptanceResponseStatus::CompleteAndClassified,
            marker,
            bytes,
            Some(format!("evidence-{evidence_ordinal:02}")),
        )
        .unwrap()
    }

    fn complete_legs(
        valid_candidate: JwtTargetAcceptanceMarkerStatus,
        anonymous_candidate: JwtTargetAcceptanceMarkerStatus,
        invalid_candidate: JwtTargetAcceptanceMarkerStatus,
        valid_replay: JwtTargetAcceptanceMarkerStatus,
        anonymous_replay: JwtTargetAcceptanceMarkerStatus,
        invalid_replay: JwtTargetAcceptanceMarkerStatus,
    ) -> Vec<JwtTargetAcceptanceLegFact> {
        [
            valid_candidate,
            anonymous_candidate,
            invalid_candidate,
            valid_replay,
            anonymous_replay,
            invalid_replay,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, marker)| {
            complete(
                JwtTargetAcceptanceLegRole::ORDERED[index],
                marker,
                1024,
                u8::try_from(index).unwrap(),
            )
        })
        .collect()
    }

    #[test]
    fn positive_control_relationship_is_strict_and_value_free() {
        let audit = JwtTargetAcceptanceAudit::from_legs(
            &policy(),
            complete_legs(
                JwtTargetAcceptanceMarkerStatus::Observed,
                JwtTargetAcceptanceMarkerStatus::NotObserved,
                JwtTargetAcceptanceMarkerStatus::Observed,
                JwtTargetAcceptanceMarkerStatus::Observed,
                JwtTargetAcceptanceMarkerStatus::NotObserved,
                JwtTargetAcceptanceMarkerStatus::Observed,
            ),
        )
        .unwrap();

        assert_eq!(audit.schema(), JWT_TARGET_ACCEPTANCE_AUDIT_SCHEMA);
        assert_eq!(audit.policy(), JWT_TARGET_ACCEPTANCE_POLICY_ID);
        assert_eq!(
            audit.valid_marker(),
            JwtTargetAcceptanceDimension::ObservedStable
        );
        assert_eq!(
            audit.anonymous_marker(),
            JwtTargetAcceptanceDimension::NotObservedStable
        );
        assert_eq!(
            audit.invalid_marker(),
            JwtTargetAcceptanceDimension::ObservedStable
        );
        assert_eq!(
            audit.conclusion(),
            JwtTargetAcceptanceConclusion::InvalidSignatureControlMarkerObservedWithAnonymousControl
        );
        assert_eq!(audit.accounting().dispatched_request_count(), 6);
        assert_eq!(audit.accounting().dispatched_passive_request_count(), 4);
        assert_eq!(audit.accounting().dispatched_active_request_count(), 2);
        assert_eq!(audit.accounting().committed_response_count(), 6);

        let serialized = serde_json::to_string(&audit).unwrap();
        assert!(!serialized.contains("example.test"));
        assert!(!serialized.contains(PRIVATE_FIELD));
    }

    #[test]
    fn stable_anonymous_marker_suppresses_invalid_control_work() {
        let roles = JwtTargetAcceptanceLegRole::ORDERED;
        let legs = vec![
            complete(roles[0], JwtTargetAcceptanceMarkerStatus::Observed, 10, 0),
            complete(roles[1], JwtTargetAcceptanceMarkerStatus::Observed, 10, 1),
            JwtTargetAcceptanceLegFact::not_dispatched(roles[2]),
            complete(roles[3], JwtTargetAcceptanceMarkerStatus::Observed, 10, 3),
            complete(roles[4], JwtTargetAcceptanceMarkerStatus::Observed, 10, 4),
            JwtTargetAcceptanceLegFact::not_dispatched(roles[5]),
        ];
        let audit = JwtTargetAcceptanceAudit::from_legs(&policy(), legs).unwrap();

        assert_eq!(
            audit.anonymous_marker(),
            JwtTargetAcceptanceDimension::ObservedStable
        );
        assert_eq!(
            audit.invalid_marker(),
            JwtTargetAcceptanceDimension::NotEvaluated
        );
        assert_eq!(
            audit.conclusion(),
            JwtTargetAcceptanceConclusion::PublicOrTokenAgnosticMarkerObserved
        );
        assert_eq!(audit.accounting().dispatched_request_count(), 4);
        assert_eq!(audit.accounting().dispatched_active_request_count(), 0);
    }

    #[test]
    fn stable_invalid_control_rejection_is_reported_narrowly() {
        let audit = JwtTargetAcceptanceAudit::from_legs(
            &policy(),
            complete_legs(
                JwtTargetAcceptanceMarkerStatus::Observed,
                JwtTargetAcceptanceMarkerStatus::NotObserved,
                JwtTargetAcceptanceMarkerStatus::NotObserved,
                JwtTargetAcceptanceMarkerStatus::Observed,
                JwtTargetAcceptanceMarkerStatus::NotObserved,
                JwtTargetAcceptanceMarkerStatus::NotObserved,
            ),
        )
        .unwrap();
        assert_eq!(
            audit.conclusion(),
            JwtTargetAcceptanceConclusion::InvalidControlMarkerNotObserved
        );
    }

    #[test]
    fn replay_disagreement_is_unstable() {
        let roles = JwtTargetAcceptanceLegRole::ORDERED;
        let legs = vec![
            complete(roles[0], JwtTargetAcceptanceMarkerStatus::Observed, 10, 0),
            complete(
                roles[1],
                JwtTargetAcceptanceMarkerStatus::NotObserved,
                10,
                1,
            ),
            complete(roles[2], JwtTargetAcceptanceMarkerStatus::Observed, 10, 2),
            complete(
                roles[3],
                JwtTargetAcceptanceMarkerStatus::NotObserved,
                10,
                3,
            ),
            complete(
                roles[4],
                JwtTargetAcceptanceMarkerStatus::NotObserved,
                10,
                4,
            ),
            JwtTargetAcceptanceLegFact::not_dispatched(roles[5]),
        ];
        let audit = JwtTargetAcceptanceAudit::from_legs(&policy(), legs).unwrap();
        assert_eq!(audit.valid_marker(), JwtTargetAcceptanceDimension::Unstable);
        assert_eq!(
            audit.conclusion(),
            JwtTargetAcceptanceConclusion::UnstableInconclusive
        );
    }

    #[test]
    fn incomplete_and_not_eligible_states_are_typed() {
        let roles = JwtTargetAcceptanceLegRole::ORDERED;
        let mut legs: Vec<_> = roles
            .into_iter()
            .map(JwtTargetAcceptanceLegFact::not_dispatched)
            .collect();
        legs[0] = JwtTargetAcceptanceLegFact::new(
            roles[0],
            JwtTargetAcceptanceDispatchStatus::Dispatched,
            JwtTargetAcceptanceCommitStatus::NotCommitted,
            JwtTargetAcceptanceResponseStatus::Incomplete,
            JwtTargetAcceptanceMarkerStatus::NotEvaluated,
            19,
            None,
        )
        .unwrap();
        let audit = JwtTargetAcceptanceAudit::from_legs(&policy(), legs).unwrap();
        assert_eq!(
            audit.conclusion(),
            JwtTargetAcceptanceConclusion::Incomplete(
                JwtTargetAcceptanceIncompleteReason::LegNotCommitted {
                    role: JwtTargetAcceptanceLegRole::ValidCandidate,
                }
            )
        );

        let skipped = JwtTargetAcceptanceAudit::not_eligible(
            &policy(),
            JwtTargetAcceptanceNotEligibleReason::LocalSignatureNotEstablished,
        );
        assert!(skipped.legs().is_empty());
        assert_eq!(skipped.accounting().dispatched_request_count(), 0);
        assert_eq!(
            skipped.conclusion(),
            JwtTargetAcceptanceConclusion::Incomplete(
                JwtTargetAcceptanceIncompleteReason::NotEligible(
                    JwtTargetAcceptanceNotEligibleReason::LocalSignatureNotEstablished
                )
            )
        );
    }

    #[test]
    fn policy_enforces_segment_boundaries_and_exact_origin() {
        let application = Url::parse("https://example.test:443/app/").unwrap();
        let accepted = [
            "https://example.test/app",
            "https://example.test/app/",
            "https://example.test/app/profile",
        ];
        for resource in accepted {
            JwtTargetAcceptancePolicy::new(
                ("operator-policy", "revision-1"),
                application.clone(),
                Url::parse(resource).unwrap(),
                "resource-1",
                "accepted",
            )
            .unwrap();
        }

        for resource in [
            "https://example.test/application/profile",
            "https://example.test/app2/profile",
        ] {
            assert_eq!(
                JwtTargetAcceptancePolicy::new(
                    ("operator-policy", "revision-1"),
                    application.clone(),
                    Url::parse(resource).unwrap(),
                    "resource-1",
                    "accepted",
                )
                .unwrap_err(),
                JwtTargetAcceptancePolicyError::ResourceOutsideApplication
            );
        }

        for resource in [
            "http://example.test/app/profile",
            "https://other.test/app/profile",
            "https://example.test:444/app/profile",
        ] {
            assert_eq!(
                JwtTargetAcceptancePolicy::new(
                    ("operator-policy", "revision-1"),
                    application.clone(),
                    Url::parse(resource).unwrap(),
                    "resource-1",
                    "accepted",
                )
                .unwrap_err(),
                JwtTargetAcceptancePolicyError::ForeignResourceOrigin
            );
        }
    }

    #[test]
    fn policy_rejects_query_fragment_userinfo_and_unsafe_slugs() {
        let application = Url::parse("https://example.test/app/").unwrap();
        for resource in [
            "https://example.test/app/profile?view=1",
            "https://example.test/app/profile#marker",
            "https://user@example.test/app/profile",
        ] {
            assert_eq!(
                JwtTargetAcceptancePolicy::new(
                    ("operator-policy", "revision-1"),
                    application.clone(),
                    Url::parse(resource).unwrap(),
                    "resource-1",
                    "accepted",
                )
                .unwrap_err(),
                JwtTargetAcceptancePolicyError::InvalidResource
            );
        }

        for identity in [("Uppercase", "revision-1"), ("operator", "bad revision")] {
            assert!(JwtTargetAcceptancePolicy::new(
                identity,
                application.clone(),
                Url::parse("https://example.test/app/profile").unwrap(),
                "resource-1",
                "accepted",
            )
            .is_err());
        }
        assert_eq!(
            JwtTargetAcceptancePolicy::new(
                ("operator", "revision-1"),
                application.clone(),
                Url::parse("https://example.test/app/profile").unwrap(),
                "bad resource",
                "accepted",
            )
            .unwrap_err(),
            JwtTargetAcceptancePolicyError::InvalidResourceReference
        );
        assert_eq!(
            JwtTargetAcceptancePolicy::new(
                ("operator", "revision-1"),
                application,
                Url::parse("https://example.test/app/profile").unwrap(),
                "resource-1",
                "bad field!",
            )
            .unwrap_err(),
            JwtTargetAcceptancePolicyError::InvalidSuccessJsonField
        );
    }

    #[test]
    fn policy_accepts_http_without_minting_transport_authority() {
        let policy = JwtTargetAcceptancePolicy::new(
            ("operator", "revision-1"),
            Url::parse("http://127.0.0.1:8080/app/").unwrap(),
            Url::parse("http://127.0.0.1:8080/app/profile").unwrap(),
            "resource-1",
            "accepted",
        )
        .unwrap();
        assert_eq!(policy.method(), JwtTargetAcceptanceMethod::Get);
        assert_eq!(policy.application().scheme(), "http");

        let rendered = format!("{policy:?}");
        assert!(!rendered.contains("127.0.0.1"));
        assert!(!rendered.contains("accepted"));
    }

    #[test]
    fn role_contract_is_closed_and_ordered() {
        for (index, role) in JwtTargetAcceptanceLegRole::ORDERED.into_iter().enumerate() {
            assert_eq!(
                role.stage(),
                if index < 3 {
                    JwtTargetAcceptanceLegStage::Candidate
                } else {
                    JwtTargetAcceptanceLegStage::Replay
                }
            );
            assert_eq!(role.requires_authorization(), !role.is_anonymous());
            assert_eq!(role.is_active(), role.uses_invalid_token());
            assert_eq!(
                (
                    role.uses_valid_token(),
                    role.uses_invalid_token(),
                    role.is_anonymous(),
                ),
                match index % 3 {
                    0 => (true, false, false),
                    1 => (false, false, true),
                    _ => (false, true, false),
                }
            );
        }
        assert_eq!(
            JwtTargetAcceptanceLegRole::InvalidCandidate.action_id(),
            JWT_TARGET_ACCEPTANCE_INVALID_CONTROL_ACTION_ID
        );
    }

    #[test]
    fn fact_constructor_rejects_inconsistent_states_and_oversized_bytes() {
        assert_eq!(
            JwtTargetAcceptanceLegFact::new(
                JwtTargetAcceptanceLegRole::ValidCandidate,
                JwtTargetAcceptanceDispatchStatus::NotDispatched,
                JwtTargetAcceptanceCommitStatus::Committed,
                JwtTargetAcceptanceResponseStatus::CompleteAndClassified,
                JwtTargetAcceptanceMarkerStatus::Observed,
                1,
                Some("evidence-1".to_owned()),
            )
            .unwrap_err(),
            JwtTargetAcceptanceLegFactError::InconsistentState
        );
        assert_eq!(
            JwtTargetAcceptanceLegFact::new(
                JwtTargetAcceptanceLegRole::ValidCandidate,
                JwtTargetAcceptanceDispatchStatus::Dispatched,
                JwtTargetAcceptanceCommitStatus::Committed,
                JwtTargetAcceptanceResponseStatus::CompleteAndClassified,
                JwtTargetAcceptanceMarkerStatus::NotEvaluated,
                1,
                Some("evidence-1".to_owned()),
            )
            .unwrap_err(),
            JwtTargetAcceptanceLegFactError::InconsistentState
        );
        assert_eq!(
            JwtTargetAcceptanceLegFact::new(
                JwtTargetAcceptanceLegRole::ValidCandidate,
                JwtTargetAcceptanceDispatchStatus::Dispatched,
                JwtTargetAcceptanceCommitStatus::NotCommitted,
                JwtTargetAcceptanceResponseStatus::Incomplete,
                JwtTargetAcceptanceMarkerStatus::NotEvaluated,
                MAX_JWT_TARGET_ACCEPTANCE_RESPONSE_BYTES + 1,
                None,
            )
            .unwrap_err(),
            JwtTargetAcceptanceLegFactError::ResponseBytesExceeded
        );
        assert_eq!(
            JwtTargetAcceptanceLegFact::new_with_transport_accounting(
                JwtTargetAcceptanceLegRole::ValidCandidate,
                JwtTargetAcceptanceDispatchStatus::Dispatched,
                JwtTargetAcceptanceCommitStatus::NotCommitted,
                JwtTargetAcceptanceResponseStatus::Incomplete,
                JwtTargetAcceptanceMarkerStatus::NotEvaluated,
                2,
                1,
                None,
            )
            .unwrap_err(),
            JwtTargetAcceptanceLegFactError::TransportBytesBelowRetained
        );
    }

    #[test]
    fn aggregate_rejects_count_role_byte_and_evidence_mutations() {
        let markers = || {
            complete_legs(
                JwtTargetAcceptanceMarkerStatus::Observed,
                JwtTargetAcceptanceMarkerStatus::NotObserved,
                JwtTargetAcceptanceMarkerStatus::Observed,
                JwtTargetAcceptanceMarkerStatus::Observed,
                JwtTargetAcceptanceMarkerStatus::NotObserved,
                JwtTargetAcceptanceMarkerStatus::Observed,
            )
        };

        let mut missing = markers();
        missing.pop();
        assert_eq!(
            JwtTargetAcceptanceAudit::from_legs(&policy(), missing).unwrap_err(),
            JwtTargetAcceptanceAuditError::UnexpectedLegCount
        );

        let mut extra = markers();
        extra.push(JwtTargetAcceptanceLegFact::not_dispatched(
            JwtTargetAcceptanceLegRole::InvalidReplay,
        ));
        assert_eq!(
            JwtTargetAcceptanceAudit::from_legs(&policy(), extra).unwrap_err(),
            JwtTargetAcceptanceAuditError::UnexpectedLegCount
        );

        let mut wrong_role = markers();
        wrong_role[1].role = JwtTargetAcceptanceLegRole::ValidCandidate;
        assert_eq!(
            JwtTargetAcceptanceAudit::from_legs(&policy(), wrong_role).unwrap_err(),
            JwtTargetAcceptanceAuditError::UnexpectedRoleOrder { ordinal: 1 }
        );

        let mut too_many_bytes = markers();
        for fact in &mut too_many_bytes {
            fact.retained_response_bytes = 45 * 1024;
            fact.accounted_response_bytes = 45 * 1024;
        }
        assert_eq!(
            JwtTargetAcceptanceAudit::from_legs(&policy(), too_many_bytes).unwrap_err(),
            JwtTargetAcceptanceAuditError::TotalResponseBytesExceeded
        );

        let mut transport_overrun = markers();
        transport_overrun[0].accounted_response_bytes =
            transport_overrun[0].retained_response_bytes + 8 * 1024;
        let transport_overrun =
            JwtTargetAcceptanceAudit::from_legs(&policy(), transport_overrun).unwrap();
        // `complete_legs` gives each of the six exact roles 1 KiB of
        // retained response data. The transport-only overrun below must not
        // change that independently specified retained total.
        assert_eq!(
            transport_overrun.accounting().retained_response_bytes(),
            6 * 1024
        );
        assert_eq!(
            transport_overrun.accounting().accounted_response_bytes(),
            (6 * 1024) + (8 * 1024)
        );

        let mut duplicate_evidence = markers();
        duplicate_evidence[5].evidence_reference = duplicate_evidence[2].evidence_reference.clone();
        assert_eq!(
            JwtTargetAcceptanceAudit::from_legs(&policy(), duplicate_evidence).unwrap_err(),
            JwtTargetAcceptanceAuditError::DuplicateEvidenceReference
        );
    }

    #[test]
    fn aggregate_revalidates_mutated_facts_and_active_prerequisites() {
        let roles = JwtTargetAcceptanceLegRole::ORDERED;
        let mut invalid_fact = JwtTargetAcceptanceLegFact::not_dispatched(roles[0]);
        invalid_fact.accounted_response_bytes = 1;
        let mut legs: Vec<_> = roles
            .into_iter()
            .map(JwtTargetAcceptanceLegFact::not_dispatched)
            .collect();
        legs[0] = invalid_fact;
        assert_eq!(
            JwtTargetAcceptanceAudit::from_legs(&policy(), legs).unwrap_err(),
            JwtTargetAcceptanceAuditError::InvalidLeg {
                role: JwtTargetAcceptanceLegRole::ValidCandidate,
                reason: JwtTargetAcceptanceLegFactError::InconsistentState,
            }
        );

        let mut public = vec![
            complete(roles[0], JwtTargetAcceptanceMarkerStatus::Observed, 10, 0),
            complete(roles[1], JwtTargetAcceptanceMarkerStatus::Observed, 10, 1),
            complete(roles[2], JwtTargetAcceptanceMarkerStatus::Observed, 10, 2),
            complete(roles[3], JwtTargetAcceptanceMarkerStatus::Observed, 10, 3),
            complete(roles[4], JwtTargetAcceptanceMarkerStatus::Observed, 10, 4),
            JwtTargetAcceptanceLegFact::not_dispatched(roles[5]),
        ];
        assert_eq!(
            JwtTargetAcceptanceAudit::from_legs(&policy(), public.clone()).unwrap_err(),
            JwtTargetAcceptanceAuditError::ActiveLegPrerequisiteNotEstablished {
                role: JwtTargetAcceptanceLegRole::InvalidCandidate,
            }
        );
        public[2] = JwtTargetAcceptanceLegFact::not_dispatched(roles[2]);
        JwtTargetAcceptanceAudit::from_legs(&policy(), public).unwrap();
    }

    #[test]
    fn aggregate_rejects_dispatch_after_ordered_stop_boundaries() {
        let roles = JwtTargetAcceptanceLegRole::ORDERED;
        let uncommitted = JwtTargetAcceptanceLegFact::new(
            roles[0],
            JwtTargetAcceptanceDispatchStatus::Dispatched,
            JwtTargetAcceptanceCommitStatus::NotCommitted,
            JwtTargetAcceptanceResponseStatus::Incomplete,
            JwtTargetAcceptanceMarkerStatus::NotEvaluated,
            1,
            None,
        )
        .unwrap();
        let mut after_uncommitted = roles
            .into_iter()
            .map(JwtTargetAcceptanceLegFact::not_dispatched)
            .collect::<Vec<_>>();
        after_uncommitted[0] = uncommitted;
        after_uncommitted[1] =
            complete(roles[1], JwtTargetAcceptanceMarkerStatus::NotObserved, 1, 1);
        assert_eq!(
            JwtTargetAcceptanceAudit::from_legs(&policy(), after_uncommitted).unwrap_err(),
            JwtTargetAcceptanceAuditError::DispatchAfterStop { role: roles[1] }
        );

        let mut after_passive_skip = roles
            .into_iter()
            .map(JwtTargetAcceptanceLegFact::not_dispatched)
            .collect::<Vec<_>>();
        after_passive_skip[1] =
            complete(roles[1], JwtTargetAcceptanceMarkerStatus::NotObserved, 1, 1);
        assert_eq!(
            JwtTargetAcceptanceAudit::from_legs(&policy(), after_passive_skip).unwrap_err(),
            JwtTargetAcceptanceAuditError::DispatchAfterStop { role: roles[1] }
        );

        let mut after_byte_limit = vec![
            complete(
                roles[0],
                JwtTargetAcceptanceMarkerStatus::Observed,
                MAX_JWT_TARGET_ACCEPTANCE_RESPONSE_BYTES,
                0,
            ),
            complete(
                roles[1],
                JwtTargetAcceptanceMarkerStatus::NotObserved,
                MAX_JWT_TARGET_ACCEPTANCE_RESPONSE_BYTES,
                1,
            ),
            complete(
                roles[2],
                JwtTargetAcceptanceMarkerStatus::Observed,
                MAX_JWT_TARGET_ACCEPTANCE_RESPONSE_BYTES,
                2,
            ),
            complete(
                roles[3],
                JwtTargetAcceptanceMarkerStatus::Observed,
                MAX_JWT_TARGET_ACCEPTANCE_RESPONSE_BYTES,
                3,
            ),
            complete(roles[4], JwtTargetAcceptanceMarkerStatus::NotObserved, 0, 4),
            JwtTargetAcceptanceLegFact::not_dispatched(roles[5]),
        ];
        assert_eq!(
            JwtTargetAcceptanceAudit::from_legs(&policy(), after_byte_limit.clone()).unwrap_err(),
            JwtTargetAcceptanceAuditError::DispatchAfterStop { role: roles[4] }
        );

        after_byte_limit[4] = JwtTargetAcceptanceLegFact::not_dispatched(roles[4]);
        JwtTargetAcceptanceAudit::from_legs(&policy(), after_byte_limit)
            .expect("a frozen all-not-dispatched tail remains valid");
    }

    #[test]
    fn evidence_reference_is_bounded_opaque_ascii_and_unique() {
        assert_eq!(
            JwtTargetAcceptanceLegFact::new(
                JwtTargetAcceptanceLegRole::ValidCandidate,
                JwtTargetAcceptanceDispatchStatus::Dispatched,
                JwtTargetAcceptanceCommitStatus::Committed,
                JwtTargetAcceptanceResponseStatus::CompleteAndClassified,
                JwtTargetAcceptanceMarkerStatus::Observed,
                1,
                Some("contains space".to_owned()),
            )
            .unwrap_err(),
            JwtTargetAcceptanceLegFactError::InvalidEvidenceReference
        );
        assert_eq!(
            JwtTargetAcceptanceLegFact::new(
                JwtTargetAcceptanceLegRole::ValidCandidate,
                JwtTargetAcceptanceDispatchStatus::Dispatched,
                JwtTargetAcceptanceCommitStatus::Committed,
                JwtTargetAcceptanceResponseStatus::CompleteAndClassified,
                JwtTargetAcceptanceMarkerStatus::Observed,
                1,
                Some("x".repeat(MAX_JWT_TARGET_ACCEPTANCE_EVIDENCE_REFERENCE_BYTES + 1)),
            )
            .unwrap_err(),
            JwtTargetAcceptanceLegFactError::InvalidEvidenceReference
        );
    }
}
