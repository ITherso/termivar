//! Pure contracts for one bounded XML external-entity resolution review.
//!
//! This module performs no I/O and parses no XML. An operator policy binds one
//! disposable, application-contained endpoint to an exact anonymous POST
//! carrying application/xml; charset=utf-8. The only generated documents use
//! one external general entity and three fixed roles: Control declares but does
//! not reference the entity, while Candidate and Replay reference independently
//! allocated callback targets. Transport and provider authority remain with
//! WebAssessmentRuntime.

use std::{fmt, mem, str::FromStr};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use termivar_oast::{CallbackTarget, NativeOastRoute, PublicOrigin};
use thiserror::Error;
use url::{Host, Url};
use zeroize::{Zeroize, Zeroizing};

/// Exact purpose-oriented policy schema implemented by V1.
pub const XML_EXTERNAL_ENTITY_REVIEW_POLICY_SCHEMA: &str =
    "security.xml-external-entity-review-policy/v1";
/// Exact raw-free audit schema implemented by V1.
pub const XML_EXTERNAL_ENTITY_REVIEW_AUDIT_SCHEMA: &str =
    "security.xml-external-entity-review-audit/v1";
/// Semantic revision for policy, document, and audit invariants.
pub const XML_EXTERNAL_ENTITY_REVIEW_ALGORITHM: &str =
    "security.xml-external-entity-resolution-review/v1";
/// Stable native action identity reserved for this review.
pub const XML_EXTERNAL_ENTITY_REVIEW_ACTION_ID: &str =
    "web.review.xml.external-entity-resolution@1";
/// Stable knowledge-only capability identity reserved for this review.
pub const XML_EXTERNAL_ENTITY_REVIEW_CAPABILITY_ID: &str =
    "xml.external-entity.repeated-outbound-interaction@1";
/// Exact target method authorized by V1.
pub const XML_EXTERNAL_ENTITY_REVIEW_METHOD: &str = "POST";
/// Exact target media type authorized by V1.
pub const XML_EXTERNAL_ENTITY_REVIEW_MEDIA_TYPE: &str = "application/xml; charset=utf-8";
/// Exact control semantics used by V1.
pub const XML_EXTERNAL_ENTITY_REVIEW_CONTROL_MODEL: &str =
    "external_general_entity_declared_not_referenced";

/// Hard policy-source ceiling.
pub const MAX_XML_EXTERNAL_ENTITY_REVIEW_POLICY_BYTES: usize = 64 * 1024;
/// Hard ceiling for the exact endpoint or callback URL.
pub const MAX_XML_EXTERNAL_ENTITY_URL_BYTES: usize = 2 * 1024;
/// Hard ceiling for one generated XML request body.
pub const MAX_XML_EXTERNAL_ENTITY_DOCUMENT_BYTES: usize = 4 * 1024;
/// Hard retained-response ceiling for each controlled target request.
pub(crate) const MAX_XML_EXTERNAL_ENTITY_TARGET_RESPONSE_BYTES: u64 = 16 * 1024;
/// Control, Candidate, and Replay are the exact target request plan.
pub const XML_EXTERNAL_ENTITY_TARGET_REQUESTS: usize = 3;
/// V1 owns one logical active verification.
pub const XML_EXTERNAL_ENTITY_ACTIVE_VERIFICATIONS: usize = 1;
/// V1 allocates one independent callback for each target leg.
pub const XML_EXTERNAL_ENTITY_CALLBACKS: usize = 3;
/// Register, three allocations, preflight, two polls per leg, and cleanup.
pub const MAX_XML_EXTERNAL_ENTITY_PROVIDER_REQUESTS: usize = 12;
/// Minimum polls allowed for each target leg.
pub const MIN_XML_EXTERNAL_ENTITY_POLLS_PER_LEG: u16 = 1;
/// Maximum polls allowed for each target leg.
pub const MAX_XML_EXTERNAL_ENTITY_POLLS_PER_LEG: u16 = 2;
/// Minimum interval between bounded polls.
pub const MIN_XML_EXTERNAL_ENTITY_POLL_INTERVAL_MS: u64 = 250;
/// Maximum interval between bounded polls.
pub const MAX_XML_EXTERNAL_ENTITY_POLL_INTERVAL_MS: u64 = 2_000;
/// Minimum provider session lifetime.
pub const MIN_XML_EXTERNAL_ENTITY_LIFETIME_MS: u64 = 5_000;
/// Maximum provider session lifetime.
pub const MAX_XML_EXTERNAL_ENTITY_LIFETIME_MS: u64 = 30_000;
/// Minimum administrator bearer-token bytes.
pub const MIN_XML_EXTERNAL_ENTITY_ADMIN_TOKEN_BYTES: usize = 32;
/// Maximum administrator bearer-token bytes.
pub const MAX_XML_EXTERNAL_ENTITY_ADMIN_TOKEN_BYTES: usize = 4_096;

const POLICY_ID_DOMAIN: &[u8] = b"security.xml-external-entity-review-policy.identity.v1\0";
const XML_ENTITY_NAME: &str = "termivar_external";

/// Stable non-secret digest of one validated policy.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct XmlExternalEntityPolicyId([u8; 32]);

impl XmlExternalEntityPolicyId {
    /// Returns a stable pseudonymous wire identity.
    pub fn to_wire(self) -> String {
        format!("xml-external-entity-policy-sha256:{}", hex(self.0))
    }

    /// Returns the domain-separated digest bytes.
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for XmlExternalEntityPolicyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_wire())
    }
}

impl fmt::Display for XmlExternalEntityPolicyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_wire())
    }
}

/// Closed execution environment selected during policy validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum XmlExternalEntityExecutionMode {
    /// Public execution requires exact HTTPS origins with DNS hosts.
    Production,
    /// Cleartext numeric loopback is reserved for repository-owned fixtures.
    OwnedNumericLoopbackTest,
}

impl XmlExternalEntityExecutionMode {
    /// Stable raw-free audit token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::OwnedNumericLoopbackTest => "owned_numeric_loopback_test",
        }
    }
}

/// Closed target method authorized by the V1 policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum XmlExternalEntityHttpMethod {
    /// One exact anonymous POST.
    #[serde(rename = "POST")]
    Post,
}

impl XmlExternalEntityHttpMethod {
    /// Exact HTTP method token.
    pub const fn as_str(self) -> &'static str {
        XML_EXTERNAL_ENTITY_REVIEW_METHOD
    }
}

/// Closed target media type authorized by the V1 policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum XmlExternalEntityMediaType {
    /// UTF-8 XML without media-type parameters beyond the exact charset.
    #[serde(rename = "application/xml; charset=utf-8")]
    ApplicationXmlUtf8,
}

impl XmlExternalEntityMediaType {
    /// Exact HTTP media-type value.
    pub const fn as_str(self) -> &'static str {
        XML_EXTERNAL_ENTITY_REVIEW_MEDIA_TYPE
    }
}

/// Strict operator authorization for one disposable XML endpoint and provider.
///
/// The endpoint and provider are private and this type is not serializable.
/// Its Debug implementation exposes only bounded scheduling facts and a digest.
pub struct XmlExternalEntityReviewPolicy {
    application: Url,
    endpoint: Url,
    provider_origin: PublicOrigin,
    execution_mode: XmlExternalEntityExecutionMode,
    polls_per_leg: u16,
    poll_interval_ms: u64,
    lifetime_ms: u64,
    policy_id: XmlExternalEntityPolicyId,
}

impl XmlExternalEntityReviewPolicy {
    /// Parses strict TOML and binds one production policy to the assessment
    /// application's exact origin and path boundary.
    pub fn parse_toml(
        assessment_target: &Url,
        source: &[u8],
    ) -> Result<Self, XmlExternalEntityReviewPolicyError> {
        if source.len() > MAX_XML_EXTERNAL_ENTITY_REVIEW_POLICY_BYTES {
            return Err(XmlExternalEntityReviewPolicyError::PolicyTooLarge);
        }
        let source = std::str::from_utf8(source)
            .map_err(|_| XmlExternalEntityReviewPolicyError::MalformedPolicy)?;
        let wire: WirePolicy = toml::from_str(source)
            .map_err(|_| XmlExternalEntityReviewPolicyError::MalformedPolicy)?;

        if wire.schema != XML_EXTERNAL_ENTITY_REVIEW_POLICY_SCHEMA {
            return Err(XmlExternalEntityReviewPolicyError::UnsupportedSchema);
        }
        if wire.method != XML_EXTERNAL_ENTITY_REVIEW_METHOD {
            return Err(XmlExternalEntityReviewPolicyError::InvalidMethod);
        }
        if wire.media_type != XML_EXTERNAL_ENTITY_REVIEW_MEDIA_TYPE {
            return Err(XmlExternalEntityReviewPolicyError::InvalidMediaType);
        }
        if !wire.acknowledge_xml_post
            || !wire.acknowledge_external_interaction
            || !wire.acknowledge_disposable_test_endpoint
        {
            return Err(XmlExternalEntityReviewPolicyError::AcknowledgementRequired);
        }
        validate_limits(wire.polls_per_leg, wire.poll_interval_ms, wire.lifetime_ms)?;

        validate_production_url(assessment_target)
            .map_err(|_| XmlExternalEntityReviewPolicyError::InvalidAssessmentTarget)?;
        let endpoint = parse_exact_policy_endpoint(&wire.endpoint)
            .map_err(|_| XmlExternalEntityReviewPolicyError::InvalidEndpoint)?;
        validate_production_url(&endpoint)
            .map_err(|_| XmlExternalEntityReviewPolicyError::InvalidEndpoint)?;
        if !same_origin(assessment_target, &endpoint) {
            return Err(XmlExternalEntityReviewPolicyError::TargetOriginMismatch);
        }
        if !application_contains(assessment_target, &endpoint) {
            return Err(XmlExternalEntityReviewPolicyError::EndpointOutsideApplication);
        }

        let provider_origin = PublicOrigin::from_str(&wire.provider_origin)
            .map_err(|_| XmlExternalEntityReviewPolicyError::InvalidProviderOrigin)?;
        let provider_url = Url::parse(provider_origin.as_str())
            .map_err(|_| XmlExternalEntityReviewPolicyError::InvalidProviderOrigin)?;
        if same_origin(&endpoint, &provider_url) {
            return Err(XmlExternalEntityReviewPolicyError::ProviderOriginMatchesTarget);
        }

        let execution_mode = XmlExternalEntityExecutionMode::Production;
        let policy_id = policy_identity(
            assessment_target,
            &endpoint,
            &provider_url,
            execution_mode,
            wire.polls_per_leg,
            wire.poll_interval_ms,
            wire.lifetime_ms,
        );
        Ok(Self {
            application: assessment_target.clone(),
            endpoint,
            provider_origin,
            execution_mode,
            polls_per_leg: wire.polls_per_leg,
            poll_interval_ms: wire.poll_interval_ms,
            lifetime_ms: wire.lifetime_ms,
            policy_id,
        })
    }

    /// Constructs the same policy around repository-owned numeric-loopback
    /// fixtures. Production callers cannot access this seam.
    #[cfg(test)]
    pub(crate) fn for_owned_loopback(
        assessment_target: Url,
        endpoint: Url,
        provider_origin: PublicOrigin,
        polls_per_leg: u16,
        poll_interval_ms: u64,
        lifetime_ms: u64,
    ) -> Result<Self, XmlExternalEntityReviewPolicyError> {
        validate_limits(polls_per_leg, poll_interval_ms, lifetime_ms)?;
        if !is_owned_http_loopback(&assessment_target) {
            return Err(XmlExternalEntityReviewPolicyError::InvalidAssessmentTarget);
        }
        if !is_owned_http_loopback(&endpoint) {
            return Err(XmlExternalEntityReviewPolicyError::InvalidEndpoint);
        }
        if !same_origin(&assessment_target, &endpoint) {
            return Err(XmlExternalEntityReviewPolicyError::TargetOriginMismatch);
        }
        if !application_contains(&assessment_target, &endpoint) {
            return Err(XmlExternalEntityReviewPolicyError::EndpointOutsideApplication);
        }
        let provider_url = Url::parse(provider_origin.as_str())
            .map_err(|_| XmlExternalEntityReviewPolicyError::InvalidProviderOrigin)?;
        if !is_owned_http_loopback(&provider_url) {
            return Err(XmlExternalEntityReviewPolicyError::InvalidProviderOrigin);
        }
        if same_origin(&endpoint, &provider_url) {
            return Err(XmlExternalEntityReviewPolicyError::ProviderOriginMatchesTarget);
        }

        let execution_mode = XmlExternalEntityExecutionMode::OwnedNumericLoopbackTest;
        let policy_id = policy_identity(
            &assessment_target,
            &endpoint,
            &provider_url,
            execution_mode,
            polls_per_leg,
            poll_interval_ms,
            lifetime_ms,
        );
        Ok(Self {
            application: assessment_target,
            endpoint,
            provider_origin,
            execution_mode,
            polls_per_leg,
            poll_interval_ms,
            lifetime_ms,
            policy_id,
        })
    }

    /// Stable redaction-safe policy identity.
    pub const fn policy_id(&self) -> XmlExternalEntityPolicyId {
        self.policy_id
    }

    /// Stable semantic revision used by this policy.
    pub const fn policy_revision(&self) -> &'static str {
        XML_EXTERNAL_ENTITY_REVIEW_ALGORITHM
    }

    /// Validated execution environment.
    pub const fn execution_mode(&self) -> XmlExternalEntityExecutionMode {
        self.execution_mode
    }

    /// Exact authorized HTTP method.
    pub const fn method(&self) -> XmlExternalEntityHttpMethod {
        XmlExternalEntityHttpMethod::Post
    }

    /// Exact authorized request media type.
    pub const fn media_type(&self) -> XmlExternalEntityMediaType {
        XmlExternalEntityMediaType::ApplicationXmlUtf8
    }

    /// Exact bounded polls allowed for each target leg.
    pub const fn polls_per_leg(&self) -> u16 {
        self.polls_per_leg
    }

    /// Configured interval between bounded polls.
    pub const fn poll_interval_ms(&self) -> u64 {
        self.poll_interval_ms
    }

    /// Configured provider session lifetime.
    pub const fn lifetime_ms(&self) -> u64 {
        self.lifetime_ms
    }

    /// Exact authorized endpoint, available only to the in-crate runtime.
    pub(crate) const fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    /// Rechecks that a consuming runtime owns the exact application used to
    /// validate this policy. Same-origin sibling paths are not interchangeable.
    pub(crate) fn is_bound_to_application(&self, application: &Url) -> bool {
        self.application == *application
    }

    /// Exact selected application retained for the sealed child broker.
    pub(crate) const fn application(&self) -> &Url {
        &self.application
    }

    /// Exact provider origin, available only to the in-crate runtime.
    pub(crate) const fn provider_origin(&self) -> &PublicOrigin {
        &self.provider_origin
    }
}

impl fmt::Debug for XmlExternalEntityReviewPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XmlExternalEntityReviewPolicy")
            .field("application", &"<redacted>")
            .field("endpoint", &"<redacted>")
            .field("provider_origin", &"<redacted>")
            .field("execution_mode", &self.execution_mode)
            .field("polls_per_leg", &self.polls_per_leg)
            .field("poll_interval_ms", &self.poll_interval_ms)
            .field("lifetime_ms", &self.lifetime_ms)
            .field("policy_id", &self.policy_id)
            .finish()
    }
}

/// Static, value-free policy validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum XmlExternalEntityReviewPolicyError {
    /// Input exceeded the compiled source ceiling.
    #[error("XML external-entity review policy exceeds its compiled byte limit")]
    PolicyTooLarge,
    /// TOML, UTF-8, required fields, or scalar types were invalid.
    #[error("XML external-entity review policy is malformed")]
    MalformedPolicy,
    /// The policy schema is not implemented.
    #[error("XML external-entity review policy schema is unsupported")]
    UnsupportedSchema,
    /// The method was not exact uppercase POST.
    #[error("XML external-entity review method is invalid")]
    InvalidMethod,
    /// The media type was not the exact V1 XML media type.
    #[error("XML external-entity review media type is invalid")]
    InvalidMediaType,
    /// At least one explicit operator acknowledgement was absent.
    #[error("XML external-entity review requires all explicit acknowledgements")]
    AcknowledgementRequired,
    /// One of the fixed V1 scheduling limits was outside its range.
    #[error("XML external-entity review scheduling limits are invalid")]
    InvalidLimits,
    /// The assessment target was not one production HTTPS/DNS application.
    #[error("XML external-entity review assessment target is invalid")]
    InvalidAssessmentTarget,
    /// The declared endpoint was not one bounded exact URL.
    #[error("XML external-entity review endpoint is invalid")]
    InvalidEndpoint,
    /// The declared endpoint did not share the assessment's exact origin.
    #[error("XML external-entity review endpoint does not match exact-origin authority")]
    TargetOriginMismatch,
    /// The declared endpoint escaped the assessment application's path boundary.
    #[error("XML external-entity review endpoint is outside the selected application")]
    EndpointOutsideApplication,
    /// The provider was not one exact supported origin.
    #[error("XML external-entity review provider origin is invalid")]
    InvalidProviderOrigin,
    /// Provider and target origins must be distinct.
    #[error("XML external-entity review provider origin must differ from target origin")]
    ProviderOriginMatchesTarget,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePolicy {
    schema: String,
    endpoint: String,
    provider_origin: String,
    method: String,
    media_type: String,
    acknowledge_xml_post: bool,
    acknowledge_external_interaction: bool,
    acknowledge_disposable_test_endpoint: bool,
    polls_per_leg: u16,
    poll_interval_ms: u64,
    lifetime_ms: u64,
}

/// Move-only administrator credential accepted only through a secret boundary.
pub struct XmlExternalEntityAdminToken {
    bytes: Vec<u8>,
}

impl XmlExternalEntityAdminToken {
    /// Takes ownership of one bounded visible-ASCII Bearer credential.
    pub fn new(mut bytes: Vec<u8>) -> Result<Self, XmlExternalEntityAdminTokenError> {
        let valid = (MIN_XML_EXTERNAL_ENTITY_ADMIN_TOKEN_BYTES
            ..=MAX_XML_EXTERNAL_ENTITY_ADMIN_TOKEN_BYTES)
            .contains(&bytes.len())
            && bytes.iter().all(|byte| (0x21..=0x7e).contains(byte));
        if !valid {
            bytes.zeroize();
            return Err(XmlExternalEntityAdminTokenError::Invalid);
        }
        Ok(Self { bytes })
    }

    /// Consumes the wrapper at the fixed native-provider request boundary.
    pub(crate) fn into_bytes(mut self) -> Vec<u8> {
        mem::take(&mut self.bytes)
    }
}

impl fmt::Debug for XmlExternalEntityAdminToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XmlExternalEntityAdminToken(<redacted>)")
    }
}

impl Drop for XmlExternalEntityAdminToken {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Static administrator-token validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum XmlExternalEntityAdminTokenError {
    /// The supplied bytes were not one bounded visible-ASCII credential.
    #[error("XML external-entity review administrator token is invalid")]
    Invalid,
}

/// Exact role of one generated document in the fixed three-request plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum XmlExternalEntityDocumentRole {
    /// Declares the external entity but never references it.
    Control,
    /// References the first independently allocated callback target.
    Candidate,
    /// References the second independently allocated callback target.
    Replay,
}

impl XmlExternalEntityDocumentRole {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Candidate => "candidate",
            Self::Replay => "replay",
        }
    }

    const fn references_entity(self) -> bool {
        !matches!(self, Self::Control)
    }
}

/// Three validated, callback-bearing XML documents.
///
/// This type deliberately has no Debug, Clone, or serialization
/// implementation because each body contains one raw callback target.
pub(crate) struct XmlExternalEntityDocumentPlan {
    control: XmlExternalEntityDocument,
    candidate: XmlExternalEntityDocument,
    replay: XmlExternalEntityDocument,
}

impl XmlExternalEntityDocumentPlan {
    /// Validates three native callback targets and materializes the fixed plan.
    pub(crate) fn new(
        policy: &XmlExternalEntityReviewPolicy,
        control_target: &CallbackTarget,
        candidate_target: &CallbackTarget,
        replay_target: &CallbackTarget,
    ) -> Result<Self, XmlExternalEntityDocumentError> {
        Self::from_callback_strings(
            policy,
            control_target.as_str(),
            candidate_target.as_str(),
            replay_target.as_str(),
        )
    }

    fn from_callback_strings(
        policy: &XmlExternalEntityReviewPolicy,
        control_target: &str,
        candidate_target: &str,
        replay_target: &str,
    ) -> Result<Self, XmlExternalEntityDocumentError> {
        let control_target = validate_callback_target(policy, control_target)?;
        let candidate_target = validate_callback_target(policy, candidate_target)?;
        let replay_target = validate_callback_target(policy, replay_target)?;
        if control_target == candidate_target
            || control_target == replay_target
            || candidate_target == replay_target
        {
            return Err(XmlExternalEntityDocumentError::CallbackIdentityConflict);
        }

        Ok(Self {
            control: build_document(
                policy,
                XmlExternalEntityDocumentRole::Control,
                control_target.as_str(),
            )?,
            candidate: build_document(
                policy,
                XmlExternalEntityDocumentRole::Candidate,
                candidate_target.as_str(),
            )?,
            replay: build_document(
                policy,
                XmlExternalEntityDocumentRole::Replay,
                replay_target.as_str(),
            )?,
        })
    }

    /// Test-only seam for proving that the sealed broker rejects policy,
    /// application, role, and document substitutions before accounting.
    #[cfg(test)]
    pub(crate) fn from_callback_strings_for_test(
        policy: &XmlExternalEntityReviewPolicy,
        control_target: &str,
        candidate_target: &str,
        replay_target: &str,
    ) -> Result<Self, XmlExternalEntityDocumentError> {
        Self::from_callback_strings(policy, control_target, candidate_target, replay_target)
    }

    /// Borrows one exact document for the target broker.
    pub(crate) const fn document(
        &self,
        role: XmlExternalEntityDocumentRole,
    ) -> &XmlExternalEntityDocument {
        match role {
            XmlExternalEntityDocumentRole::Control => &self.control,
            XmlExternalEntityDocumentRole::Candidate => &self.candidate,
            XmlExternalEntityDocumentRole::Replay => &self.replay,
        }
    }
}

/// One bounded generated XML body.
///
/// Raw bytes are zeroized when dropped and this type deliberately has no
/// Debug, Clone, or serialization implementation.
pub(crate) struct XmlExternalEntityDocument {
    policy_id: XmlExternalEntityPolicyId,
    role: XmlExternalEntityDocumentRole,
    bytes: Zeroizing<Vec<u8>>,
}

impl XmlExternalEntityDocument {
    /// Exact immutable policy that minted this document.
    pub(crate) const fn policy_id(&self) -> XmlExternalEntityPolicyId {
        self.policy_id
    }

    /// Exact immutable role encoded in this document.
    pub(crate) const fn role(&self) -> XmlExternalEntityDocumentRole {
        self.role
    }

    /// Borrows exact body bytes for one metered target request.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

/// Static document-plan validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum XmlExternalEntityDocumentError {
    /// A callback was not one exact route under the policy provider.
    #[error("XML external-entity callback target is invalid")]
    InvalidCallbackTarget,
    /// Two plan legs were assigned the same callback target.
    #[error("XML external-entity callback targets must be distinct")]
    CallbackIdentityConflict,
    /// A generated body exceeded its compiled byte ceiling.
    #[error("XML external-entity document exceeds its compiled byte limit")]
    DocumentTooLarge,
}

/// Closed, raw-free conclusion retained by the typed audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum XmlExternalEntityReviewOutcome {
    /// The fixed plan was not eligible for dispatch.
    NotEligible,
    /// The control lifecycle did not complete.
    ControlIncomplete,
    /// Provider preflight observed stale or background callback activity.
    PreflightContaminated,
    /// The unreferenced control declaration produced a callback.
    ControlCallbackObserved,
    /// No candidate or replay callback was observed.
    NoCallback,
    /// Only the candidate callback was observed.
    CandidateOnly,
    /// Only the replay callback was observed.
    ReplayOnly,
    /// A callback or event identity violated exact correlation.
    CorrelationMismatch,
    /// Provider cleanup could not be verified.
    CleanupIncomplete,
    /// Host cancellation stopped the bounded review.
    Cancelled,
    /// Parent request, byte, verification, or time authority was exhausted.
    BudgetExhausted,
    /// The lifecycle ended without a complete classifiable result.
    Incomplete,
    /// Candidate and replay produced distinct exactly correlated callbacks.
    RepeatedExternalEntityResolutionObserved,
}

impl XmlExternalEntityReviewOutcome {
    /// Stable raw-free wire token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotEligible => "not_eligible",
            Self::ControlIncomplete => "control_incomplete",
            Self::PreflightContaminated => "preflight_contaminated",
            Self::ControlCallbackObserved => "control_callback_observed",
            Self::NoCallback => "no_callback",
            Self::CandidateOnly => "candidate_only",
            Self::ReplayOnly => "replay_only",
            Self::CorrelationMismatch => "correlation_mismatch",
            Self::CleanupIncomplete => "cleanup_incomplete",
            Self::Cancelled => "cancelled",
            Self::BudgetExhausted => "budget_exhausted",
            Self::Incomplete => "incomplete",
            Self::RepeatedExternalEntityResolutionObserved => {
                "repeated_external_entity_resolution_observed"
            },
        }
    }
}

/// Maximum product disposition authorized by this evidence family.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum XmlExternalEntityMaximumDisposition {
    /// Correlated callbacks require human review and never confirm impact.
    NeedsReview,
}

impl XmlExternalEntityMaximumDisposition {
    /// Stable product-disposition token.
    pub const fn as_str(self) -> &'static str {
        "needs_review"
    }
}

/// Closed state for excluded semantic or impact operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum XmlExternalEntityOperationStatus {
    /// The operation was deliberately not performed.
    NotPerformed,
}

impl XmlExternalEntityOperationStatus {
    /// Stable excluded-operation token.
    pub const fn as_str(self) -> &'static str {
        "not_performed"
    }
}

/// Explicit ceiling on claims derivable from a completed callback review.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct XmlExternalEntityClaimLimits {
    maximum_disposition: XmlExternalEntityMaximumDisposition,
    semantic_effect: XmlExternalEntityOperationStatus,
    impact_validation: XmlExternalEntityOperationStatus,
}

impl XmlExternalEntityClaimLimits {
    const fn v1() -> Self {
        Self {
            maximum_disposition: XmlExternalEntityMaximumDisposition::NeedsReview,
            semantic_effect: XmlExternalEntityOperationStatus::NotPerformed,
            impact_validation: XmlExternalEntityOperationStatus::NotPerformed,
        }
    }

    /// Strongest product disposition allowed by this contract.
    pub const fn maximum_disposition(self) -> XmlExternalEntityMaximumDisposition {
        self.maximum_disposition
    }

    /// Server-side semantic effect was not tested.
    pub const fn semantic_effect(self) -> XmlExternalEntityOperationStatus {
        self.semantic_effect
    }

    /// Exploitability and business impact were not tested.
    pub const fn impact_validation(self) -> XmlExternalEntityOperationStatus {
        self.impact_validation
    }
}

/// Raw-free runtime facts accepted by the audit invariant.
pub(crate) struct XmlExternalEntityAuditFacts {
    pub(crate) outcome: XmlExternalEntityReviewOutcome,
    pub(crate) target_request_count: u8,
    pub(crate) provider_request_count: u8,
    pub(crate) active_verification_count: u8,
    pub(crate) target_request_body_bytes: u64,
    pub(crate) target_response_bytes: u64,
    pub(crate) target_complete: bool,
    pub(crate) preflight_clean: bool,
    pub(crate) control_callback_observed: bool,
    pub(crate) candidate_callback_observed: bool,
    pub(crate) replay_callback_observed: bool,
    pub(crate) callback_targets_distinct: bool,
    pub(crate) event_identities_distinct: bool,
    pub(crate) cleanup_verified: bool,
    pub(crate) target_accounting_complete: bool,
    pub(crate) provider_accounting_complete: bool,
    pub(crate) item_projected: bool,
}

/// Redaction-safe audit retained by one composed assessment report.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct XmlExternalEntityReviewAudit {
    schema: &'static str,
    algorithm: &'static str,
    action_id: &'static str,
    capability_id: &'static str,
    outcome: XmlExternalEntityReviewOutcome,
    policy_id: String,
    execution_mode: XmlExternalEntityExecutionMode,
    target_request_count: u8,
    provider_request_count: u8,
    active_verification_count: u8,
    target_request_body_bytes: u64,
    target_response_bytes: u64,
    target_complete: bool,
    preflight_clean: bool,
    control_callback_observed: bool,
    candidate_callback_observed: bool,
    replay_callback_observed: bool,
    callback_targets_distinct: bool,
    event_identities_distinct: bool,
    cleanup_verified: bool,
    target_accounting_complete: bool,
    provider_accounting_complete: bool,
    item_projected: bool,
    claim_limits: XmlExternalEntityClaimLimits,
}

impl XmlExternalEntityReviewAudit {
    /// Constructs an audit only when counts, correlation, projection, and claim
    /// ceilings form one internally consistent V1 result.
    pub(crate) fn from_runtime(
        policy: &XmlExternalEntityReviewPolicy,
        facts: XmlExternalEntityAuditFacts,
    ) -> Result<Self, XmlExternalEntityAuditError> {
        validate_audit_facts(&facts)?;
        Ok(Self {
            schema: XML_EXTERNAL_ENTITY_REVIEW_AUDIT_SCHEMA,
            algorithm: XML_EXTERNAL_ENTITY_REVIEW_ALGORITHM,
            action_id: XML_EXTERNAL_ENTITY_REVIEW_ACTION_ID,
            capability_id: XML_EXTERNAL_ENTITY_REVIEW_CAPABILITY_ID,
            outcome: facts.outcome,
            policy_id: policy.policy_id().to_wire(),
            execution_mode: policy.execution_mode(),
            target_request_count: facts.target_request_count,
            provider_request_count: facts.provider_request_count,
            active_verification_count: facts.active_verification_count,
            target_request_body_bytes: facts.target_request_body_bytes,
            target_response_bytes: facts.target_response_bytes,
            target_complete: facts.target_complete,
            preflight_clean: facts.preflight_clean,
            control_callback_observed: facts.control_callback_observed,
            candidate_callback_observed: facts.candidate_callback_observed,
            replay_callback_observed: facts.replay_callback_observed,
            callback_targets_distinct: facts.callback_targets_distinct,
            event_identities_distinct: facts.event_identities_distinct,
            cleanup_verified: facts.cleanup_verified,
            target_accounting_complete: facts.target_accounting_complete,
            provider_accounting_complete: facts.provider_accounting_complete,
            item_projected: facts.item_projected,
            claim_limits: XmlExternalEntityClaimLimits::v1(),
        })
    }

    /// Stable audit schema.
    pub const fn schema(&self) -> &'static str {
        self.schema
    }

    /// Stable review algorithm revision.
    pub const fn algorithm(&self) -> &'static str {
        self.algorithm
    }

    /// Stable semantic revision used by this audit.
    pub const fn policy_revision(&self) -> &'static str {
        self.algorithm
    }

    /// Stable action identity.
    pub const fn action_id(&self) -> &'static str {
        self.action_id
    }

    /// Stable capability identity.
    pub const fn capability_id(&self) -> &'static str {
        self.capability_id
    }

    /// Exact target method used by every request leg.
    pub const fn method(&self) -> &'static str {
        XML_EXTERNAL_ENTITY_REVIEW_METHOD
    }

    /// Exact target media type used by every request leg.
    pub const fn media_type(&self) -> &'static str {
        XML_EXTERNAL_ENTITY_REVIEW_MEDIA_TYPE
    }

    /// Stable description of the inert control construction.
    pub const fn control_model(&self) -> &'static str {
        XML_EXTERNAL_ENTITY_REVIEW_CONTROL_MODEL
    }

    /// Raw-free terminal outcome.
    pub const fn outcome(&self) -> XmlExternalEntityReviewOutcome {
        self.outcome
    }

    /// Stable pseudonymous policy identity.
    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    /// Validated execution environment.
    pub const fn execution_mode(&self) -> XmlExternalEntityExecutionMode {
        self.execution_mode
    }

    /// Target requests admitted by the parent broker.
    pub const fn target_request_count(&self) -> u8 {
        self.target_request_count
    }

    /// Provider operations admitted by the parent provider permit.
    pub const fn provider_request_count(&self) -> u8 {
        self.provider_request_count
    }

    /// Logical active verifications consumed by this review.
    pub const fn active_verification_count(&self) -> u8 {
        self.active_verification_count
    }

    /// Total XML request-body bytes reconciled with target receipts.
    pub const fn target_request_body_bytes(&self) -> u64 {
        self.target_request_body_bytes
    }

    /// Total retained target response bytes reconciled with target receipts.
    pub const fn target_response_bytes(&self) -> u64 {
        self.target_response_bytes
    }

    /// Whether all three target receipts were complete.
    pub const fn target_complete(&self) -> bool {
        self.target_complete
    }

    /// Whether the provider preflight was empty.
    pub const fn preflight_clean(&self) -> bool {
        self.preflight_clean
    }

    /// Whether the unreferenced control entity caused an interaction.
    pub const fn control_callback_observed(&self) -> bool {
        self.control_callback_observed
    }

    /// Whether the candidate interaction was exactly correlated.
    pub const fn candidate_callback_observed(&self) -> bool {
        self.candidate_callback_observed
    }

    /// Whether the replay interaction was exactly correlated.
    pub const fn replay_callback_observed(&self) -> bool {
        self.replay_callback_observed
    }

    /// Whether all allocated callback targets were distinct.
    pub const fn callback_targets_distinct(&self) -> bool {
        self.callback_targets_distinct
    }

    /// Whether candidate and replay event identities were distinct.
    pub const fn event_identities_distinct(&self) -> bool {
        self.event_identities_distinct
    }

    /// Count of distinct correlated candidate/replay event identities.
    pub const fn distinct_event_count(&self) -> u8 {
        if self.event_identities_distinct {
            2
        } else if self.candidate_callback_observed || self.replay_callback_observed {
            1
        } else {
            0
        }
    }

    /// Whether explicit provider cleanup was verified.
    pub const fn cleanup_verified(&self) -> bool {
        self.cleanup_verified
    }

    /// Whether target accounting reconciled with parent receipts.
    pub const fn target_accounting_complete(&self) -> bool {
        self.target_accounting_complete
    }

    /// Whether provider accounting reconciled with parent receipts.
    pub const fn provider_accounting_complete(&self) -> bool {
        self.provider_accounting_complete
    }

    /// Whether provider cleanup and parent accounting both completed.
    pub const fn provider_complete(&self) -> bool {
        self.cleanup_verified && self.provider_accounting_complete
    }

    /// Whether a knowledge-only NeedsReview item was projected.
    pub const fn item_projected(&self) -> bool {
        self.item_projected
    }

    /// Explicit ceiling on semantic and impact claims.
    pub const fn claim_limits(&self) -> XmlExternalEntityClaimLimits {
        self.claim_limits
    }

    /// Server-side semantic effect was deliberately not tested.
    pub const fn semantic_effect(&self) -> XmlExternalEntityOperationStatus {
        self.claim_limits.semantic_effect()
    }

    /// Exploitability and business impact were deliberately not tested.
    pub const fn impact_validation(&self) -> XmlExternalEntityOperationStatus {
        self.claim_limits.impact_validation()
    }
}

impl fmt::Debug for XmlExternalEntityReviewAudit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XmlExternalEntityReviewAudit")
            .field("schema", &self.schema)
            .field("algorithm", &self.algorithm)
            .field("action_id", &self.action_id)
            .field("capability_id", &self.capability_id)
            .field("outcome", &self.outcome)
            .field("policy_id", &self.policy_id)
            .field("execution_mode", &self.execution_mode)
            .field("target_request_count", &self.target_request_count)
            .field("provider_request_count", &self.provider_request_count)
            .field("active_verification_count", &self.active_verification_count)
            .field("target_request_body_bytes", &self.target_request_body_bytes)
            .field("target_response_bytes", &self.target_response_bytes)
            .field("target_complete", &self.target_complete)
            .field("preflight_clean", &self.preflight_clean)
            .field("control_callback_observed", &self.control_callback_observed)
            .field(
                "candidate_callback_observed",
                &self.candidate_callback_observed,
            )
            .field("replay_callback_observed", &self.replay_callback_observed)
            .field("callback_targets_distinct", &self.callback_targets_distinct)
            .field("event_identities_distinct", &self.event_identities_distinct)
            .field("cleanup_verified", &self.cleanup_verified)
            .field(
                "target_accounting_complete",
                &self.target_accounting_complete,
            )
            .field(
                "provider_accounting_complete",
                &self.provider_accounting_complete,
            )
            .field("item_projected", &self.item_projected)
            .field("claim_limits", &self.claim_limits)
            .finish()
    }
}

/// Static audit-invariant failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum XmlExternalEntityAuditError {
    /// Target, provider, or active-verification counts exceeded hard bounds.
    #[error("XML external-entity review audit counts are invalid")]
    InvalidCounts,
    /// Callback or event facts contradicted each other.
    #[error("XML external-entity review audit correlation facts are invalid")]
    InvalidCorrelation,
    /// The terminal outcome contradicted the retained lifecycle facts.
    #[error("XML external-entity review audit outcome is invalid")]
    InvalidOutcome,
    /// Item projection exceeded the knowledge-only positive outcome.
    #[error("XML external-entity review audit projection is invalid")]
    InvalidProjection,
}

fn validate_limits(
    polls_per_leg: u16,
    poll_interval_ms: u64,
    lifetime_ms: u64,
) -> Result<(), XmlExternalEntityReviewPolicyError> {
    let minimum_poll_window_ms = u64::from(polls_per_leg)
        .checked_mul(3)
        .and_then(|polls| polls.checked_mul(poll_interval_ms));
    if !(MIN_XML_EXTERNAL_ENTITY_POLLS_PER_LEG..=MAX_XML_EXTERNAL_ENTITY_POLLS_PER_LEG)
        .contains(&polls_per_leg)
        || !(MIN_XML_EXTERNAL_ENTITY_POLL_INTERVAL_MS..=MAX_XML_EXTERNAL_ENTITY_POLL_INTERVAL_MS)
            .contains(&poll_interval_ms)
        || !(MIN_XML_EXTERNAL_ENTITY_LIFETIME_MS..=MAX_XML_EXTERNAL_ENTITY_LIFETIME_MS)
            .contains(&lifetime_ms)
        || minimum_poll_window_ms.is_none_or(|minimum| lifetime_ms <= minimum)
    {
        return Err(XmlExternalEntityReviewPolicyError::InvalidLimits);
    }
    Ok(())
}

fn validate_production_url(url: &Url) -> Result<(), ()> {
    if !valid_url_shape(url)
        || url.scheme() != "https"
        || !matches!(url.host(), Some(Host::Domain(host)) if valid_dns_host(host))
    {
        return Err(());
    }
    Ok(())
}

fn parse_exact_policy_endpoint(value: &str) -> Result<Url, ()> {
    // URL parsing follows the URL Standard and can erase literal or encoded
    // dot segments, translate backslashes, and canonicalize the authority. An
    // operator policy is request authority, so its raw spelling must already
    // be the exact bounded URL that will reach the broker. Normalization must
    // never turn rejected text into an admitted endpoint.
    if value.is_empty()
        || value.len() > MAX_XML_EXTERNAL_ENTITY_URL_BYTES
        || value.trim() != value
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_control())
        || value.contains('%')
        || value.contains('\\')
    {
        return Err(());
    }
    let parsed = Url::parse(value).map_err(|_| ())?;
    if parsed.as_str() != value {
        return Err(());
    }
    Ok(parsed)
}

fn valid_url_shape(url: &Url) -> bool {
    url.as_str().len() <= MAX_XML_EXTERNAL_ENTITY_URL_BYTES
        && !url.cannot_be_a_base()
        && url.has_host()
        && url.port_or_known_default().is_some_and(|port| port != 0)
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && safe_unambiguous_path(url.path())
}

fn safe_unambiguous_path(path: &str) -> bool {
    !path.is_empty()
        && path.starts_with('/')
        && path
            .bytes()
            .all(|byte| (0x21..=0x7e).contains(&byte) && !matches!(byte, b'%' | b'\\'))
}

fn valid_dns_host(host: &str) -> bool {
    !host.eq_ignore_ascii_case("localhost")
        && !host.ends_with(".localhost")
        && !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn application_contains(application: &Url, endpoint: &Url) -> bool {
    if !same_origin(application, endpoint) {
        return false;
    }
    let application_segments = nonempty_path_segments(application);
    let endpoint_segments = nonempty_path_segments(endpoint);
    application_segments.len() <= endpoint_segments.len()
        && application_segments
            .iter()
            .zip(endpoint_segments.iter())
            .all(|(application, endpoint)| application == endpoint)
}

fn nonempty_path_segments(url: &Url) -> Vec<&str> {
    url.path_segments()
        .map(|segments| segments.filter(|segment| !segment.is_empty()).collect())
        .unwrap_or_default()
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host() == right.host()
        && left.port_or_known_default() == right.port_or_known_default()
}

#[cfg(test)]
fn is_owned_http_loopback(url: &Url) -> bool {
    valid_url_shape(url)
        && url.scheme() == "http"
        && url.port().is_some_and(|port| port != 0)
        && match url.host() {
            Some(Host::Ipv4(address)) => address.is_loopback(),
            Some(Host::Ipv6(address)) => address.is_loopback(),
            _ => false,
        }
}

fn policy_identity(
    application: &Url,
    endpoint: &Url,
    provider: &Url,
    execution_mode: XmlExternalEntityExecutionMode,
    polls_per_leg: u16,
    poll_interval_ms: u64,
    lifetime_ms: u64,
) -> XmlExternalEntityPolicyId {
    let polls = polls_per_leg.to_be_bytes();
    let interval = poll_interval_ms.to_be_bytes();
    let lifetime = lifetime_ms.to_be_bytes();
    XmlExternalEntityPolicyId(digest_parts(
        POLICY_ID_DOMAIN,
        &[
            XML_EXTERNAL_ENTITY_REVIEW_POLICY_SCHEMA.as_bytes(),
            XML_EXTERNAL_ENTITY_REVIEW_ALGORITHM.as_bytes(),
            XML_EXTERNAL_ENTITY_REVIEW_METHOD.as_bytes(),
            XML_EXTERNAL_ENTITY_REVIEW_MEDIA_TYPE.as_bytes(),
            application.as_str().as_bytes(),
            endpoint.as_str().as_bytes(),
            provider.as_str().as_bytes(),
            execution_mode.as_str().as_bytes(),
            &polls,
            &interval,
            &lifetime,
        ],
    ))
}

fn validate_callback_target(
    policy: &XmlExternalEntityReviewPolicy,
    source: &str,
) -> Result<Url, XmlExternalEntityDocumentError> {
    if source.is_empty() || source.len() > MAX_XML_EXTERNAL_ENTITY_URL_BYTES {
        return Err(XmlExternalEntityDocumentError::InvalidCallbackTarget);
    }
    let parsed =
        Url::parse(source).map_err(|_| XmlExternalEntityDocumentError::InvalidCallbackTarget)?;
    let provider = Url::parse(policy.provider_origin().as_str())
        .map_err(|_| XmlExternalEntityDocumentError::InvalidCallbackTarget)?;
    let environment_valid = match policy.execution_mode() {
        XmlExternalEntityExecutionMode::Production => {
            parsed.scheme() == "https" && validate_production_url(&parsed).is_ok()
        },
        XmlExternalEntityExecutionMode::OwnedNumericLoopbackTest => {
            #[cfg(test)]
            {
                is_owned_http_loopback(&parsed)
            }
            #[cfg(not(test))]
            {
                false
            }
        },
    };
    if !environment_valid
        || !same_origin(&parsed, &provider)
        || !matches!(
            NativeOastRoute::from_str(parsed.path()),
            Ok(NativeOastRoute::Callback { .. })
        )
    {
        return Err(XmlExternalEntityDocumentError::InvalidCallbackTarget);
    }
    Ok(parsed)
}

fn build_document(
    policy: &XmlExternalEntityReviewPolicy,
    role: XmlExternalEntityDocumentRole,
    callback_target: &str,
) -> Result<XmlExternalEntityDocument, XmlExternalEntityDocumentError> {
    let callback_target = escape_xml_attribute(callback_target);
    let content = if role.references_entity() {
        format!("&{XML_ENTITY_NAME};")
    } else {
        "control".to_owned()
    };
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE termivar-review [<!ENTITY {XML_ENTITY_NAME} SYSTEM \"{callback_target}\">]>\n\
<termivar-review role=\"{}\">{content}</termivar-review>\n",
        role.as_str()
    )
    .into_bytes();
    if body.len() > MAX_XML_EXTERNAL_ENTITY_DOCUMENT_BYTES {
        return Err(XmlExternalEntityDocumentError::DocumentTooLarge);
    }
    Ok(XmlExternalEntityDocument {
        policy_id: policy.policy_id(),
        role,
        bytes: Zeroizing::new(body),
    })
}

fn escape_xml_attribute(source: &str) -> String {
    let mut escaped = String::with_capacity(source.len());
    for character in source.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            character => escaped.push(character),
        }
    }
    escaped
}

fn validate_audit_facts(
    facts: &XmlExternalEntityAuditFacts,
) -> Result<(), XmlExternalEntityAuditError> {
    let maximum_target_body_bytes = u64::try_from(XML_EXTERNAL_ENTITY_TARGET_REQUESTS)
        .ok()
        .and_then(|requests| {
            u64::try_from(MAX_XML_EXTERNAL_ENTITY_DOCUMENT_BYTES)
                .ok()
                .and_then(|bytes| requests.checked_mul(bytes))
        });
    let maximum_complete_target_response_bytes = u64::try_from(XML_EXTERNAL_ENTITY_TARGET_REQUESTS)
        .ok()
        .and_then(|requests| requests.checked_mul(MAX_XML_EXTERNAL_ENTITY_TARGET_RESPONSE_BYTES));
    if usize::from(facts.target_request_count) > XML_EXTERNAL_ENTITY_TARGET_REQUESTS
        || usize::from(facts.provider_request_count) > MAX_XML_EXTERNAL_ENTITY_PROVIDER_REQUESTS
        || usize::from(facts.active_verification_count) > XML_EXTERNAL_ENTITY_ACTIVE_VERIFICATIONS
        || maximum_target_body_bytes.is_none_or(|maximum| facts.target_request_body_bytes > maximum)
        || (facts.target_complete
            && maximum_complete_target_response_bytes
                .is_none_or(|maximum| facts.target_response_bytes > maximum))
    {
        return Err(XmlExternalEntityAuditError::InvalidCounts);
    }
    let expected_active_verification_count = u8::from(facts.target_request_count >= 2);
    let target_bytes_consistent =
        (facts.target_request_count == 0) == (facts.target_request_body_bytes == 0);
    let target_completion_consistent = !facts.target_complete
        || usize::from(facts.target_request_count) == XML_EXTERNAL_ENTITY_TARGET_REQUESTS;
    let target_accounting_consistent = !facts.target_accounting_complete || facts.target_complete;
    let callback_facts_consistent = (!facts.control_callback_observed
        && !facts.candidate_callback_observed
        && !facts.replay_callback_observed)
        || facts.callback_targets_distinct;
    let event_facts_consistent = !facts.event_identities_distinct
        || (facts.callback_targets_distinct
            && facts.candidate_callback_observed
            && facts.replay_callback_observed);
    let provider_empty_consistent = facts.provider_request_count != 0
        || (facts.active_verification_count == 0
            && !facts.preflight_clean
            && !facts.control_callback_observed
            && !facts.candidate_callback_observed
            && !facts.replay_callback_observed
            && !facts.callback_targets_distinct
            && !facts.event_identities_distinct
            && !facts.cleanup_verified
            && !facts.provider_accounting_complete);
    let provider_completion_consistent = !facts.provider_accounting_complete
        || (usize::from(facts.provider_request_count) >= 9
            && facts.preflight_clean
            && facts.callback_targets_distinct);
    let target_started_consistent = facts.target_request_count == 0
        || (facts.provider_request_count > 0
            && facts.preflight_clean
            && facts.callback_targets_distinct);
    if facts.active_verification_count != expected_active_verification_count
        || !target_bytes_consistent
        || !target_completion_consistent
        || !target_accounting_consistent
        || !callback_facts_consistent
        || !event_facts_consistent
        || !provider_empty_consistent
        || !provider_completion_consistent
        || !target_started_consistent
    {
        return Err(XmlExternalEntityAuditError::InvalidCorrelation);
    }

    let complete_lifecycle = usize::from(facts.target_request_count)
        == XML_EXTERNAL_ENTITY_TARGET_REQUESTS
        && facts.provider_request_count > 0
        && usize::from(facts.active_verification_count) == XML_EXTERNAL_ENTITY_ACTIVE_VERIFICATIONS
        && facts.target_request_body_bytes > 0
        && facts.target_complete
        && facts.preflight_clean
        && !facts.control_callback_observed
        && facts.callback_targets_distinct
        && facts.cleanup_verified
        && facts.target_accounting_complete
        && facts.provider_accounting_complete;
    let complete_positive = complete_lifecycle
        && facts.candidate_callback_observed
        && facts.replay_callback_observed
        && facts.event_identities_distinct;
    let positive_outcome =
        facts.outcome == XmlExternalEntityReviewOutcome::RepeatedExternalEntityResolutionObserved;
    if positive_outcome != complete_positive {
        return Err(XmlExternalEntityAuditError::InvalidOutcome);
    }

    let no_callbacks = !facts.control_callback_observed
        && !facts.candidate_callback_observed
        && !facts.replay_callback_observed;
    let empty_lifecycle = facts.target_request_count == 0
        && facts.provider_request_count == 0
        && no_callbacks
        && !facts.target_complete
        && !facts.preflight_clean
        && !facts.callback_targets_distinct
        && !facts.event_identities_distinct
        && !facts.cleanup_verified
        && !facts.target_accounting_complete
        && !facts.provider_accounting_complete;
    let stopped_lifecycle = !complete_lifecycle
        && !facts.control_callback_observed
        && (!facts.target_accounting_complete || !facts.provider_accounting_complete);
    let outcome_facts_match = match facts.outcome {
        XmlExternalEntityReviewOutcome::NotEligible => empty_lifecycle,
        XmlExternalEntityReviewOutcome::ControlIncomplete => {
            facts.target_request_count == 0
                && !facts.target_complete
                && !facts.preflight_clean
                && no_callbacks
                && !facts.target_accounting_complete
                && !facts.provider_accounting_complete
        },
        XmlExternalEntityReviewOutcome::PreflightContaminated => {
            facts.target_request_count == 0
                && facts.provider_request_count > 0
                && !facts.preflight_clean
                && !no_callbacks
                && facts.callback_targets_distinct
                && !facts.target_complete
                && !facts.target_accounting_complete
                && !facts.provider_accounting_complete
        },
        XmlExternalEntityReviewOutcome::ControlCallbackObserved => {
            facts.preflight_clean
                && facts.control_callback_observed
                && facts.target_request_count > 0
                && !facts.target_complete
                && !facts.target_accounting_complete
                && !facts.provider_accounting_complete
        },
        XmlExternalEntityReviewOutcome::NoCallback => complete_lifecycle && no_callbacks,
        XmlExternalEntityReviewOutcome::CandidateOnly => {
            complete_lifecycle
                && facts.candidate_callback_observed
                && !facts.replay_callback_observed
                && !facts.event_identities_distinct
        },
        XmlExternalEntityReviewOutcome::ReplayOnly => {
            complete_lifecycle
                && !facts.candidate_callback_observed
                && facts.replay_callback_observed
                && !facts.event_identities_distinct
        },
        XmlExternalEntityReviewOutcome::CorrelationMismatch => {
            facts.preflight_clean
                && !facts.control_callback_observed
                && (facts.candidate_callback_observed || facts.replay_callback_observed)
                && !facts.event_identities_distinct
        },
        XmlExternalEntityReviewOutcome::CleanupIncomplete => {
            facts.preflight_clean && !facts.control_callback_observed && !facts.cleanup_verified
        },
        XmlExternalEntityReviewOutcome::Cancelled
        | XmlExternalEntityReviewOutcome::BudgetExhausted
        | XmlExternalEntityReviewOutcome::Incomplete => stopped_lifecycle,
        XmlExternalEntityReviewOutcome::RepeatedExternalEntityResolutionObserved => {
            complete_positive
        },
    };
    if !outcome_facts_match {
        return Err(XmlExternalEntityAuditError::InvalidOutcome);
    }
    if facts.item_projected != positive_outcome {
        return Err(XmlExternalEntityAuditError::InvalidProjection);
    }
    Ok(())
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn hex(bytes: [u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;

    const SESSION: &str = "AQEBAQEBAQEBAQEBAQEBAQ";
    const CONTROL_CALLBACK: &str = "AgICAgICAgICAgICAgICAg";
    const CANDIDATE_CALLBACK: &str = "AwMDAwMDAwMDAwMDAwMDAw";
    const REPLAY_CALLBACK: &str = "BAQEBAQEBAQEBAQEBAQEBA";

    fn policy_source(endpoint: &str, provider: &str) -> Vec<u8> {
        format!(
            "schema = \"{XML_EXTERNAL_ENTITY_REVIEW_POLICY_SCHEMA}\"\n\
endpoint = \"{endpoint}\"\n\
provider_origin = \"{provider}\"\n\
method = \"{XML_EXTERNAL_ENTITY_REVIEW_METHOD}\"\n\
media_type = \"{XML_EXTERNAL_ENTITY_REVIEW_MEDIA_TYPE}\"\n\
acknowledge_xml_post = true\n\
acknowledge_external_interaction = true\n\
acknowledge_disposable_test_endpoint = true\n\
polls_per_leg = 2\n\
poll_interval_ms = 500\n\
lifetime_ms = 10000\n"
        )
        .into_bytes()
    }

    fn production_policy() -> XmlExternalEntityReviewPolicy {
        XmlExternalEntityReviewPolicy::parse_toml(
            &Url::parse("https://app.example.test/application/").unwrap(),
            &policy_source(
                "https://app.example.test/application/fixtures/xml",
                "https://oast.example.test/",
            ),
        )
        .unwrap()
    }

    fn loopback_policy() -> XmlExternalEntityReviewPolicy {
        let provider_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 39091);
        XmlExternalEntityReviewPolicy::for_owned_loopback(
            Url::parse("http://127.0.0.1:39090/application/").unwrap(),
            Url::parse("http://127.0.0.1:39090/application/fixtures/xml").unwrap(),
            PublicOrigin::from_test_loopback(provider_address).unwrap(),
            2,
            500,
            10_000,
        )
        .unwrap()
    }

    fn callback(callback: &str) -> String {
        format!("http://127.0.0.1:39091/c/{SESSION}/{callback}")
    }

    fn positive_facts() -> XmlExternalEntityAuditFacts {
        XmlExternalEntityAuditFacts {
            outcome: XmlExternalEntityReviewOutcome::RepeatedExternalEntityResolutionObserved,
            target_request_count: XML_EXTERNAL_ENTITY_TARGET_REQUESTS as u8,
            provider_request_count: MAX_XML_EXTERNAL_ENTITY_PROVIDER_REQUESTS as u8,
            active_verification_count: XML_EXTERNAL_ENTITY_ACTIVE_VERIFICATIONS as u8,
            target_request_body_bytes: 768,
            target_response_bytes: 96,
            target_complete: true,
            preflight_clean: true,
            control_callback_observed: false,
            candidate_callback_observed: true,
            replay_callback_observed: true,
            callback_targets_distinct: true,
            event_identities_distinct: true,
            cleanup_verified: true,
            target_accounting_complete: true,
            provider_accounting_complete: true,
            item_projected: true,
        }
    }

    #[test]
    fn strict_policy_binds_exact_post_media_origin_and_application() {
        let policy = production_policy();
        let selected_application = Url::parse("https://app.example.test/application/").unwrap();
        let broader_application = Url::parse("https://app.example.test/").unwrap();
        assert!(policy.is_bound_to_application(&selected_application));
        assert!(!policy.is_bound_to_application(&broader_application));
        let broader_policy = XmlExternalEntityReviewPolicy::parse_toml(
            &broader_application,
            &policy_source(
                "https://app.example.test/application/fixtures/xml",
                "https://oast.example.test/",
            ),
        )
        .unwrap();
        assert_ne!(policy.policy_id(), broader_policy.policy_id());
        assert_eq!(policy.method(), XmlExternalEntityHttpMethod::Post);
        assert_eq!(
            policy.media_type(),
            XmlExternalEntityMediaType::ApplicationXmlUtf8
        );
        assert_eq!(
            policy.execution_mode(),
            XmlExternalEntityExecutionMode::Production
        );
        assert_eq!(policy.polls_per_leg(), 2);
        assert_eq!(policy.poll_interval_ms(), 500);
        assert_eq!(policy.lifetime_ms(), 10_000);
        assert!(policy
            .policy_id()
            .to_wire()
            .starts_with("xml-external-entity-policy-sha256:"));
        let rendered = format!("{policy:?}");
        assert!(!rendered.contains("app.example.test"));
        assert!(!rendered.contains("oast.example.test"));
        assert!(!rendered.contains("/fixtures/xml"));
    }

    #[test]
    fn policy_rejects_authority_broadening_mutations() {
        let assessment = Url::parse("https://app.example.test/application/").unwrap();
        let base = String::from_utf8(policy_source(
            "https://app.example.test/application/fixtures/xml",
            "https://oast.example.test/",
        ))
        .unwrap();
        let mutations = [
            base.replace(
                XML_EXTERNAL_ENTITY_REVIEW_POLICY_SCHEMA,
                "security.xml-external-entity-review-policy/v2",
            ),
            base.replace("method = \"POST\"", "method = \"PUT\""),
            base.replace(
                "media_type = \"application/xml; charset=utf-8\"",
                "media_type = \"text/xml\"",
            ),
            base.replace(
                "acknowledge_xml_post = true",
                "acknowledge_xml_post = false",
            ),
            base.replace(
                "acknowledge_external_interaction = true",
                "acknowledge_external_interaction = false",
            ),
            base.replace(
                "acknowledge_disposable_test_endpoint = true",
                "acknowledge_disposable_test_endpoint = false",
            ),
            base.replace(
                "https://app.example.test/application/fixtures/xml",
                "https://other.example.test/application/fixtures/xml",
            ),
            base.replace(
                "https://app.example.test/application/fixtures/xml",
                "https://app.example.test/sibling/fixtures/xml",
            ),
            base.replace(
                "https://app.example.test/application/fixtures/xml",
                "https://app.example.test/application/fixtures/xml?mode=test",
            ),
            base.replace(
                "https://app.example.test/application/fixtures/xml",
                "https://user@app.example.test/application/fixtures/xml",
            ),
            base.replace(
                "https://app.example.test/application/fixtures/xml",
                "http://app.example.test/application/fixtures/xml",
            ),
            base.replace(
                "https://app.example.test/application/fixtures/xml",
                "https://127.0.0.1/application/fixtures/xml",
            ),
            format!("{base}unknown = true\n"),
        ];
        for mutation in mutations {
            assert!(
                XmlExternalEntityReviewPolicy::parse_toml(&assessment, mutation.as_bytes())
                    .is_err(),
                "authority-broadening mutation unexpectedly passed"
            );
        }

        let same_provider = base.replace("https://oast.example.test/", "https://app.example.test/");
        assert_eq!(
            XmlExternalEntityReviewPolicy::parse_toml(&assessment, same_provider.as_bytes())
                .unwrap_err(),
            XmlExternalEntityReviewPolicyError::ProviderOriginMatchesTarget
        );
    }

    #[test]
    fn policy_endpoint_rejects_raw_normalization_and_unsafe_separators() {
        let assessment = Url::parse("https://app.example.test/application/").unwrap();
        let canonical = "https://app.example.test/application/fixtures/xml";
        assert!(XmlExternalEntityReviewPolicy::parse_toml(
            &assessment,
            &policy_source(canonical, "https://oast.example.test/")
        )
        .is_ok());

        for ambiguous in [
            "https://app.example.test/application/fixtures/./xml",
            "https://app.example.test/application/fixtures/safe/../xml",
            "https://app.example.test/application/fixtures/safe/%2e%2e/xml",
            "https://app.example.test/application/fixtures/%2f/xml",
            "HTTPS://APP.EXAMPLE.TEST:443/application/fixtures/xml",
        ] {
            assert_eq!(
                XmlExternalEntityReviewPolicy::parse_toml(
                    &assessment,
                    &policy_source(ambiguous, "https://oast.example.test/")
                )
                .unwrap_err(),
                XmlExternalEntityReviewPolicyError::InvalidEndpoint,
                "normalized endpoint spelling was admitted: {ambiguous}"
            );
        }

        let backslash = String::from_utf8(policy_source(canonical, "https://oast.example.test/"))
            .unwrap()
            .replace(
                &format!("endpoint = \"{canonical}\""),
                r"endpoint = 'https://app.example.test/application/fixtures\xml'",
            );
        assert_eq!(
            XmlExternalEntityReviewPolicy::parse_toml(&assessment, backslash.as_bytes())
                .unwrap_err(),
            XmlExternalEntityReviewPolicyError::InvalidEndpoint
        );
    }

    #[test]
    fn policy_limits_and_source_ceiling_fail_closed() {
        let assessment = Url::parse("https://app.example.test/application/").unwrap();
        let base = String::from_utf8(policy_source(
            "https://app.example.test/application/fixtures/xml",
            "https://oast.example.test/",
        ))
        .unwrap();
        for mutation in [
            base.replace("polls_per_leg = 2", "polls_per_leg = 0"),
            base.replace("polls_per_leg = 2", "polls_per_leg = 3"),
            base.replace("poll_interval_ms = 500", "poll_interval_ms = 249"),
            base.replace("poll_interval_ms = 500", "poll_interval_ms = 2001"),
            base.replace("lifetime_ms = 10000", "lifetime_ms = 4999"),
            base.replace("lifetime_ms = 10000", "lifetime_ms = 30001"),
            base.replace("poll_interval_ms = 500", "poll_interval_ms = 2000"),
        ] {
            assert_eq!(
                XmlExternalEntityReviewPolicy::parse_toml(&assessment, mutation.as_bytes())
                    .unwrap_err(),
                XmlExternalEntityReviewPolicyError::InvalidLimits
            );
        }
        assert_eq!(
            XmlExternalEntityReviewPolicy::parse_toml(
                &assessment,
                &vec![b'a'; MAX_XML_EXTERNAL_ENTITY_REVIEW_POLICY_BYTES + 1]
            )
            .unwrap_err(),
            XmlExternalEntityReviewPolicyError::PolicyTooLarge
        );
    }

    #[test]
    fn numeric_loopback_requires_the_owned_test_constructor() {
        let policy = loopback_policy();
        assert_eq!(
            policy.execution_mode(),
            XmlExternalEntityExecutionMode::OwnedNumericLoopbackTest
        );
        assert_eq!(
            XmlExternalEntityReviewPolicy::parse_toml(
                &Url::parse("http://127.0.0.1:39090/application/").unwrap(),
                &policy_source(
                    "http://127.0.0.1:39090/application/fixtures/xml",
                    "http://127.0.0.1:39091/"
                )
            )
            .unwrap_err(),
            XmlExternalEntityReviewPolicyError::InvalidAssessmentTarget
        );
    }

    #[test]
    fn administrator_token_is_bounded_move_only_and_redacted() {
        let token =
            XmlExternalEntityAdminToken::new(vec![b'a'; MIN_XML_EXTERNAL_ENTITY_ADMIN_TOKEN_BYTES])
                .unwrap();
        assert_eq!(
            format!("{token:?}"),
            "XmlExternalEntityAdminToken(<redacted>)"
        );
        assert_eq!(
            token.into_bytes(),
            vec![b'a'; MIN_XML_EXTERNAL_ENTITY_ADMIN_TOKEN_BYTES]
        );
        for invalid in [
            vec![],
            vec![b'a'; MIN_XML_EXTERNAL_ENTITY_ADMIN_TOKEN_BYTES - 1],
            vec![b'a'; MAX_XML_EXTERNAL_ENTITY_ADMIN_TOKEN_BYTES + 1],
            vec![b' '; MIN_XML_EXTERNAL_ENTITY_ADMIN_TOKEN_BYTES],
        ] {
            assert_eq!(
                XmlExternalEntityAdminToken::new(invalid).unwrap_err(),
                XmlExternalEntityAdminTokenError::Invalid
            );
        }
    }

    #[test]
    fn canonical_plan_has_one_external_general_entity_and_distinct_roles() {
        let policy = loopback_policy();
        let plan = XmlExternalEntityDocumentPlan::from_callback_strings(
            &policy,
            &callback(CONTROL_CALLBACK),
            &callback(CANDIDATE_CALLBACK),
            &callback(REPLAY_CALLBACK),
        )
        .unwrap();
        let control = std::str::from_utf8(
            plan.document(XmlExternalEntityDocumentRole::Control)
                .as_bytes(),
        )
        .unwrap();
        let candidate = std::str::from_utf8(
            plan.document(XmlExternalEntityDocumentRole::Candidate)
                .as_bytes(),
        )
        .unwrap();
        let replay = std::str::from_utf8(
            plan.document(XmlExternalEntityDocumentRole::Replay)
                .as_bytes(),
        )
        .unwrap();

        for body in [control, candidate, replay] {
            assert_eq!(body.matches("<!ENTITY ").count(), 1);
            assert!(body.contains("<!ENTITY termivar_external SYSTEM \""));
            assert!(!body.contains("<!ENTITY %"));
            assert!(!body.contains(" PUBLIC "));
            assert!(!body.contains("XInclude"));
            assert!(body.len() <= MAX_XML_EXTERNAL_ENTITY_DOCUMENT_BYTES);
        }
        assert!(control.contains("role=\"control\""));
        assert!(!control.contains("&termivar_external;"));
        assert!(candidate.contains("role=\"candidate\""));
        assert_eq!(candidate.matches("&termivar_external;").count(), 1);
        assert!(replay.contains("role=\"replay\""));
        assert_eq!(replay.matches("&termivar_external;").count(), 1);
        assert_ne!(control, candidate);
        assert_ne!(candidate, replay);
    }

    #[test]
    fn callback_targets_are_exact_native_routes_and_pairwise_distinct() {
        let policy = loopback_policy();
        assert_eq!(
            XmlExternalEntityDocumentPlan::from_callback_strings(
                &policy,
                &callback(CONTROL_CALLBACK),
                &callback(CONTROL_CALLBACK),
                &callback(REPLAY_CALLBACK),
            )
            .err()
            .unwrap(),
            XmlExternalEntityDocumentError::CallbackIdentityConflict
        );
        for invalid in [
            "http://127.0.0.1:39092/c/AQEBAQEBAQEBAQEBAQEBAQ/AgICAgICAgICAgICAgICAg",
            "http://127.0.0.1:39091/not-a-callback",
            "http://127.0.0.1:39091/c/AQEBAQEBAQEBAQEBAQEBAQ/AgICAgICAgICAgICAgICAg?x=1",
            "https://127.0.0.1:39091/c/AQEBAQEBAQEBAQEBAQEBAQ/AgICAgICAgICAgICAgICAg",
        ] {
            assert_eq!(
                XmlExternalEntityDocumentPlan::from_callback_strings(
                    &policy,
                    invalid,
                    &callback(CANDIDATE_CALLBACK),
                    &callback(REPLAY_CALLBACK),
                )
                .err()
                .unwrap(),
                XmlExternalEntityDocumentError::InvalidCallbackTarget
            );
        }
    }

    #[test]
    fn xml_attribute_escaping_is_canonical_and_body_bound_is_enforced() {
        assert_eq!(
            escape_xml_attribute("a&<>\"'z"),
            "a&amp;&lt;&gt;&quot;&apos;z"
        );
        assert_eq!(
            build_document(
                &loopback_policy(),
                XmlExternalEntityDocumentRole::Candidate,
                &"a".repeat(MAX_XML_EXTERNAL_ENTITY_DOCUMENT_BYTES)
            )
            .err()
            .unwrap(),
            XmlExternalEntityDocumentError::DocumentTooLarge
        );
    }

    #[test]
    fn audit_positive_outcome_enforces_claim_and_lifecycle_invariants() {
        let policy = production_policy();
        let audit = XmlExternalEntityReviewAudit::from_runtime(&policy, positive_facts()).unwrap();
        assert_eq!(audit.schema(), XML_EXTERNAL_ENTITY_REVIEW_AUDIT_SCHEMA);
        assert_eq!(audit.algorithm(), XML_EXTERNAL_ENTITY_REVIEW_ALGORITHM);
        assert_eq!(audit.action_id(), XML_EXTERNAL_ENTITY_REVIEW_ACTION_ID);
        assert_eq!(
            audit.capability_id(),
            XML_EXTERNAL_ENTITY_REVIEW_CAPABILITY_ID
        );
        assert_eq!(audit.method(), XML_EXTERNAL_ENTITY_REVIEW_METHOD);
        assert_eq!(audit.media_type(), XML_EXTERNAL_ENTITY_REVIEW_MEDIA_TYPE);
        assert_eq!(
            audit.control_model(),
            XML_EXTERNAL_ENTITY_REVIEW_CONTROL_MODEL
        );
        assert_eq!(
            audit.outcome(),
            XmlExternalEntityReviewOutcome::RepeatedExternalEntityResolutionObserved
        );
        assert_eq!(audit.target_request_body_bytes(), 768);
        assert_eq!(audit.target_response_bytes(), 96);
        assert!(audit.target_complete());
        assert!(audit.item_projected());
        assert_eq!(
            audit.claim_limits().maximum_disposition(),
            XmlExternalEntityMaximumDisposition::NeedsReview
        );
        assert_eq!(
            audit.semantic_effect(),
            XmlExternalEntityOperationStatus::NotPerformed
        );
        assert_eq!(
            audit.impact_validation(),
            XmlExternalEntityOperationStatus::NotPerformed
        );
        let wire = serde_json::to_string(&audit).unwrap();
        assert!(wire.contains(XML_EXTERNAL_ENTITY_REVIEW_AUDIT_SCHEMA));
        assert!(wire.contains("\"semantic_effect\":\"not_performed\""));
        assert!(wire.contains("\"impact_validation\":\"not_performed\""));
        assert!(!wire.contains("app.example.test"));
        assert!(!wire.contains("oast.example.test"));
        assert!(!format!("{audit:?}").contains("fixtures/xml"));

        let mut contaminated = positive_facts();
        contaminated.control_callback_observed = true;
        assert_eq!(
            XmlExternalEntityReviewAudit::from_runtime(&policy, contaminated).unwrap_err(),
            XmlExternalEntityAuditError::InvalidOutcome
        );

        let mut incomplete = positive_facts();
        incomplete.target_complete = false;
        assert_eq!(
            XmlExternalEntityReviewAudit::from_runtime(&policy, incomplete).unwrap_err(),
            XmlExternalEntityAuditError::InvalidOutcome
        );

        let mut over_budget = positive_facts();
        over_budget.provider_request_count = MAX_XML_EXTERNAL_ENTITY_PROVIDER_REQUESTS as u8 + 1;
        assert_eq!(
            XmlExternalEntityReviewAudit::from_runtime(&policy, over_budget).unwrap_err(),
            XmlExternalEntityAuditError::InvalidCounts
        );

        let mut oversized_complete_response = positive_facts();
        oversized_complete_response.target_response_bytes =
            u64::try_from(XML_EXTERNAL_ENTITY_TARGET_REQUESTS).unwrap()
                * MAX_XML_EXTERNAL_ENTITY_TARGET_RESPONSE_BYTES
                + 1;
        assert_eq!(
            XmlExternalEntityReviewAudit::from_runtime(&policy, oversized_complete_response)
                .unwrap_err(),
            XmlExternalEntityAuditError::InvalidCounts
        );
    }

    #[test]
    fn non_positive_audit_cannot_project_an_item() {
        let policy = production_policy();
        let mut preflight = positive_facts();
        preflight.outcome = XmlExternalEntityReviewOutcome::PreflightContaminated;
        preflight.target_request_count = 0;
        preflight.target_request_body_bytes = 0;
        preflight.target_response_bytes = 0;
        preflight.target_complete = false;
        preflight.target_accounting_complete = false;
        preflight.provider_request_count = 6;
        preflight.active_verification_count = 0;
        preflight.provider_accounting_complete = false;
        preflight.preflight_clean = false;
        preflight.candidate_callback_observed = true;
        preflight.replay_callback_observed = false;
        preflight.event_identities_distinct = false;
        preflight.item_projected = false;
        let audit = XmlExternalEntityReviewAudit::from_runtime(&policy, preflight).unwrap();
        assert_eq!(
            audit.outcome(),
            XmlExternalEntityReviewOutcome::PreflightContaminated
        );

        let mut facts = positive_facts();
        facts.outcome = XmlExternalEntityReviewOutcome::CandidateOnly;
        facts.replay_callback_observed = false;
        facts.event_identities_distinct = false;
        facts.item_projected = false;
        let audit = XmlExternalEntityReviewAudit::from_runtime(&policy, facts).unwrap();
        assert_eq!(
            audit.outcome(),
            XmlExternalEntityReviewOutcome::CandidateOnly
        );
        assert!(!audit.item_projected());

        let mut invalid = positive_facts();
        invalid.outcome = XmlExternalEntityReviewOutcome::CandidateOnly;
        invalid.replay_callback_observed = false;
        invalid.event_identities_distinct = false;
        assert_eq!(
            XmlExternalEntityReviewAudit::from_runtime(&policy, invalid).unwrap_err(),
            XmlExternalEntityAuditError::InvalidProjection
        );
    }

    #[test]
    fn audit_rejects_cross_field_lifecycle_mutations_for_negative_outcomes() {
        let policy = production_policy();

        let mut wrong_active_count = positive_facts();
        wrong_active_count.outcome = XmlExternalEntityReviewOutcome::CandidateOnly;
        wrong_active_count.replay_callback_observed = false;
        wrong_active_count.event_identities_distinct = false;
        wrong_active_count.item_projected = false;
        wrong_active_count.active_verification_count = 0;
        assert_eq!(
            XmlExternalEntityReviewAudit::from_runtime(&policy, wrong_active_count).unwrap_err(),
            XmlExternalEntityAuditError::InvalidCorrelation
        );

        let mut impossible_target_accounting = positive_facts();
        impossible_target_accounting.outcome = XmlExternalEntityReviewOutcome::Incomplete;
        impossible_target_accounting.target_complete = false;
        impossible_target_accounting.item_projected = false;
        assert_eq!(
            XmlExternalEntityReviewAudit::from_runtime(&policy, impossible_target_accounting)
                .unwrap_err(),
            XmlExternalEntityAuditError::InvalidCorrelation
        );

        let mut unbound_callback = positive_facts();
        unbound_callback.outcome = XmlExternalEntityReviewOutcome::CorrelationMismatch;
        unbound_callback.callback_targets_distinct = false;
        unbound_callback.event_identities_distinct = false;
        unbound_callback.item_projected = false;
        assert_eq!(
            XmlExternalEntityReviewAudit::from_runtime(&policy, unbound_callback).unwrap_err(),
            XmlExternalEntityAuditError::InvalidCorrelation
        );

        let mut fabricated_complete_provider = positive_facts();
        fabricated_complete_provider.outcome = XmlExternalEntityReviewOutcome::CandidateOnly;
        fabricated_complete_provider.provider_request_count = 8;
        fabricated_complete_provider.replay_callback_observed = false;
        fabricated_complete_provider.event_identities_distinct = false;
        fabricated_complete_provider.item_projected = false;
        assert_eq!(
            XmlExternalEntityReviewAudit::from_runtime(&policy, fabricated_complete_provider)
                .unwrap_err(),
            XmlExternalEntityAuditError::InvalidCorrelation
        );

        let mut stopped_with_complete_accounting = positive_facts();
        stopped_with_complete_accounting.outcome = XmlExternalEntityReviewOutcome::Incomplete;
        stopped_with_complete_accounting.cleanup_verified = false;
        stopped_with_complete_accounting.item_projected = false;
        assert_eq!(
            XmlExternalEntityReviewAudit::from_runtime(&policy, stopped_with_complete_accounting)
                .unwrap_err(),
            XmlExternalEntityAuditError::InvalidOutcome
        );
    }
}
