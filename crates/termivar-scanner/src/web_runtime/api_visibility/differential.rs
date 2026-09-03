//! Broker-backed, host-authorized JSON API visibility comparison.
//!
//! This is deliberately a runtime-owned side path rather than a
//! `DecisionActionExecutor`: canonical comparison evidence belongs to an
//! isolated `api-comparison:*` subject, not the endpoint action subject.

use std::{collections::BTreeSet, fmt};

use serde::Serialize;
use sha2::{Digest, Sha256};
use termivar_core::{
    ApiVisibilityDimension, ApiVocabularyError, ComparisonId, EntityId, OpaqueContextId,
    ResourceScopeId,
};
use thiserror::Error;

use crate::web_runtime::authority::authenticated_transport_is_allowed;
use crate::{
    ApiComparisonProfile, ApiObservationCommitReceipt, ApiObservationError, ApiObservationReceipt,
    ApiVisibilityReview, CanonicalizationVersion, ComparisonAlgorithmVersion, HttpEvidenceError,
    HttpProbe, HttpProbeMethod, ProfiledApiVisibilityComparison, ProfiledApiVisibilityError,
    ProjectionPolicyId, RuntimeLimitExceeded, RuntimeUsage, TransportDispatchAudit,
    CURRENT_API_VISIBILITY_CANONICALIZATION_VERSION,
};

const TEMPLATE_DIGEST_DOMAIN: &[u8] = b"venom.api-visibility.request-template.v1\0";
const OPERATION_DIGEST_DOMAIN: &[u8] = b"venom.api-visibility.runtime-operation.v1\0";
const MAX_CONTEXT_HEADER_NAMES: usize = 32;
const MAX_DIFFERENTIAL_HEADER_COUNT: usize = 64;
const MAX_DIFFERENTIAL_HEADER_VALUE_BYTES: usize = 16 * 1024;
const MAX_DIFFERENTIAL_TOTAL_HEADER_BYTES: usize = 64 * 1024;
const MAX_DIFFERENTIAL_URL_BYTES: usize = 8 * 1024;
const PRIMARY_AUTH_CONTEXT_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "x-access-token",
    "x-api-key",
    "x-auth-token",
    "x-session-token",
];
const SUPPORTING_AUTH_CONTEXT_HEADERS: &[&str] = &["x-csrf-token", "x-xsrf-token"];

mod execution;

/// One host-declared authorization context and its bodyless HTTP probe.
///
/// The context identifier must be opaque and non-secret. Header values may
/// contain credentials, so this type intentionally implements neither
/// `Clone` nor `Serialize`, and its `Debug` output is fully redacted.
pub struct ApiVisibilityContextProbe {
    context_id: OpaqueContextId,
    probe: HttpProbe,
}

impl ApiVisibilityContextProbe {
    /// Creates one context-bound probe without performing I/O.
    pub fn new(
        context_id: impl Into<String>,
        probe: HttpProbe,
    ) -> Result<Self, ApiVisibilityDifferentialRequestError> {
        Ok(Self {
            context_id: OpaqueContextId::new(context_id)?,
            probe,
        })
    }

    /// Returns the caller-owned opaque context handle.
    pub fn context_id(&self) -> &str {
        self.context_id.as_str()
    }

    /// Returns the validated probe. Its own `Debug` output redacts values.
    pub fn probe(&self) -> &HttpProbe {
        &self.probe
    }
}

impl fmt::Debug for ApiVisibilityContextProbe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiVisibilityContextProbe")
            .field("context_id", &"<redacted>")
            .field("probe", &"<redacted>")
            .finish()
    }
}

/// A fully validated, explicit JSON authorization-context pair.
///
/// The first native slice intentionally accepts only two `GET` requests for
/// the exact same URL. Header differences are permitted only for the explicit
/// context-owned header-name set. This prevents an unrelated method, path,
/// query, or representation change from being misclassified as authorization
/// visibility.
pub struct ApiVisibilityDifferentialRequest {
    comparison_id: ComparisonId,
    resource_scope: EntityId,
    resource_scope_id: ResourceScopeId,
    control: ApiVisibilityContextProbe,
    candidate: ApiVisibilityContextProbe,
    context_header_names: BTreeSet<String>,
    profile: ApiComparisonProfile,
    dimension: ApiVisibilityDimension,
    observed_at_ms: u64,
    request_template_sha256: String,
    operation_sha256: String,
}

impl ApiVisibilityDifferentialRequest {
    /// Validates one explicit authorization-context comparison before I/O.
    #[allow(clippy::too_many_arguments)]
    pub fn new<I, S>(
        comparison_id: impl Into<String>,
        resource_scope: EntityId,
        control: ApiVisibilityContextProbe,
        candidate: ApiVisibilityContextProbe,
        context_header_names: I,
        profile: ApiComparisonProfile,
        dimension: ApiVisibilityDimension,
        observed_at_ms: u64,
    ) -> Result<Self, ApiVisibilityDifferentialRequestError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let comparison_id = ComparisonId::new(comparison_id)?;
        let resource_scope_id = ResourceScopeId::new(resource_scope.as_str())?;
        if control.context_id == candidate.context_id {
            return Err(ApiVisibilityDifferentialRequestError::IdenticalContextHandles);
        }
        for probe in [&control.probe, &candidate.probe] {
            if probe.method() != HttpProbeMethod::Get {
                return Err(ApiVisibilityDifferentialRequestError::UnsupportedMethod);
            }
            if probe.url().fragment().is_some() {
                return Err(ApiVisibilityDifferentialRequestError::UrlFragment);
            }
        }
        if control.probe.url() != candidate.probe.url() {
            return Err(ApiVisibilityDifferentialRequestError::RequestTargetMismatch);
        }
        if control.probe.url().as_str().len() > MAX_DIFFERENTIAL_URL_BYTES {
            return Err(ApiVisibilityDifferentialRequestError::RequestTargetTooLong);
        }
        if !authenticated_transport_is_allowed(control.probe.url()) {
            return Err(ApiVisibilityDifferentialRequestError::InsecureAuthenticatedTransport);
        }
        if !matches!(
            dimension,
            ApiVisibilityDimension::Fields
                | ApiVisibilityDimension::Resources
                | ApiVisibilityDimension::Status
        ) {
            return Err(ApiVisibilityDifferentialRequestError::UnsupportedDimension);
        }

        let context_header_names = context_header_names
            .into_iter()
            .map(Into::into)
            .map(|name: String| name.trim().to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        if context_header_names.is_empty() {
            return Err(ApiVisibilityDifferentialRequestError::EmptyContextHeaders);
        }
        if context_header_names.len() > MAX_CONTEXT_HEADER_NAMES
            || context_header_names.iter().any(String::is_empty)
        {
            return Err(ApiVisibilityDifferentialRequestError::InvalidContextHeaders);
        }
        if context_header_names
            .iter()
            .any(|name| !is_auth_context_header(name))
            || !context_header_names
                .iter()
                .any(|name| PRIMARY_AUTH_CONTEXT_HEADERS.contains(&name.as_str()))
        {
            return Err(ApiVisibilityDifferentialRequestError::UnsupportedContextHeader);
        }

        let all_header_names = control
            .probe
            .headers()
            .keys()
            .chain(candidate.probe.headers().keys())
            .collect::<BTreeSet<_>>();
        if all_header_names.len() > MAX_DIFFERENTIAL_HEADER_COUNT {
            return Err(ApiVisibilityDifferentialRequestError::TooManyHeaders);
        }
        for probe in [&control.probe, &candidate.probe] {
            let mut total_header_bytes = 0_usize;
            for (name, value) in probe.headers() {
                if value.len() > MAX_DIFFERENTIAL_HEADER_VALUE_BYTES {
                    return Err(ApiVisibilityDifferentialRequestError::HeaderValueTooLong);
                }
                total_header_bytes = total_header_bytes
                    .saturating_add(name.len())
                    .saturating_add(value.len());
            }
            if total_header_bytes > MAX_DIFFERENTIAL_TOTAL_HEADER_BYTES {
                return Err(ApiVisibilityDifferentialRequestError::TotalHeaderBytesTooLarge);
            }
        }
        if context_header_names.iter().any(|name| {
            !all_header_names
                .iter()
                .any(|present| present.as_str() == name)
        }) {
            return Err(ApiVisibilityDifferentialRequestError::UnusedContextHeader);
        }
        if all_header_names.iter().any(|name| {
            !context_header_names.contains(name.as_str())
                && control.probe.headers().get(name.as_str())
                    != candidate.probe.headers().get(name.as_str())
        }) {
            return Err(ApiVisibilityDifferentialRequestError::RequestTemplateMismatch);
        }

        if !primary_context_headers_differ(&control.probe, &candidate.probe, &context_header_names)
        {
            return Err(ApiVisibilityDifferentialRequestError::IdenticalAuthorizationContext);
        }

        let request_template_sha256 =
            request_template_digest(&control.probe, &context_header_names, &all_header_names);
        let operation_sha256 = operation_digest(
            &comparison_id,
            &resource_scope,
            &control.context_id,
            &candidate.context_id,
            dimension,
            observed_at_ms,
            profile.projection_policy_id().as_bytes(),
            &request_template_sha256,
        );
        Ok(Self {
            comparison_id,
            resource_scope,
            resource_scope_id,
            control,
            candidate,
            context_header_names,
            profile,
            dimension,
            observed_at_ms,
            request_template_sha256,
            operation_sha256,
        })
    }

    /// Returns the logical resource asserted by the authorized host.
    pub fn resource_scope(&self) -> &EntityId {
        &self.resource_scope
    }

    /// Returns the selected comparison dimension.
    pub const fn dimension(&self) -> ApiVisibilityDimension {
        self.dimension
    }

    /// Returns the raw-value-free projection policy.
    pub const fn profile(&self) -> &ApiComparisonProfile {
        &self.profile
    }

    /// Returns the explicit deterministic observation time.
    pub const fn observed_at_ms(&self) -> u64 {
        self.observed_at_ms
    }
}

impl fmt::Debug for ApiVisibilityDifferentialRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiVisibilityDifferentialRequest")
            .field("comparison_id", &"<redacted>")
            .field("resource_scope", &"<redacted>")
            .field("control", &"<redacted>")
            .field("candidate", &"<redacted>")
            .field("context_header_names", &self.context_header_names)
            .field("profile", &self.profile)
            .field("dimension", &self.dimension)
            .field("observed_at_ms", &self.observed_at_ms)
            .field("request_template_sha256", &"<redacted>")
            .field("operation_sha256", &"<redacted>")
            .finish()
    }
}

/// Validation failure for an authorization-context pair.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ApiVisibilityDifferentialRequestError {
    /// A typed comparison, context, or scope identifier was invalid.
    #[error(transparent)]
    Vocabulary(#[from] ApiVocabularyError),
    /// Control and candidate handles must describe distinct contexts.
    #[error("API visibility contexts must use distinct opaque handles")]
    IdenticalContextHandles,
    /// The first native capability accepts discovery-only GET requests.
    #[error("API visibility differential requests must use GET")]
    UnsupportedMethod,
    /// URL fragments are not transmitted and cannot participate in identity.
    #[error("API visibility differential requests must not contain URL fragments")]
    UrlFragment,
    /// Authorization contexts must request the exact same URL.
    #[error("API visibility authorization contexts must use the same exact request target")]
    RequestTargetMismatch,
    /// The bounded native slice rejects excessively large target identities.
    #[error("API visibility request target exceeds the compiled length limit")]
    RequestTargetTooLong,
    /// Credentials require TLS except on an exact loopback fixture target.
    #[error("API visibility authorization contexts require HTTPS outside loopback fixtures")]
    InsecureAuthenticatedTransport,
    /// The comparator does not implement the requested dimension.
    #[error("API visibility differential request uses an unsupported dimension")]
    UnsupportedDimension,
    /// At least one header must be declared context-owned.
    #[error("API visibility differential request requires context-owned header names")]
    EmptyContextHeaders,
    /// The context-header set was malformed or exceeded its compiled bound.
    #[error("API visibility context-header set is invalid")]
    InvalidContextHeaders,
    /// Only explicit credential and supporting anti-CSRF headers are accepted.
    #[error("API visibility context-header set contains a non-credential header")]
    UnsupportedContextHeader,
    /// The complete request header set exceeded its compiled count ceiling.
    #[error("API visibility request contains too many headers")]
    TooManyHeaders,
    /// One request header value exceeded its compiled byte ceiling.
    #[error("API visibility request header value exceeds the compiled byte limit")]
    HeaderValueTooLong,
    /// One request's complete header material exceeded its compiled byte ceiling.
    #[error("API visibility request headers exceed the compiled total byte limit")]
    TotalHeaderBytesTooLarge,
    /// A declared context header did not occur in either request.
    #[error("API visibility context-header set contains an unused name")]
    UnusedContextHeader,
    /// A non-context request header differed across the pair.
    #[error("API visibility request templates differ outside authorization context headers")]
    RequestTemplateMismatch,
    /// Distinct labels cannot disguise identical authorization material.
    #[error("API visibility probes contain identical authorization context headers")]
    IdenticalAuthorizationContext,
}

/// Which half of a differential pair produced a receipt or stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ApiVisibilityLeg {
    /// The baseline/control authorization context.
    Control,
    /// The candidate authorization context.
    Candidate,
}

/// Raw-value-free transport receipt for one completed leg.
///
/// Digests are pseudonymous and may be dictionary-testable. They are intended
/// for authorized audit/replay correlation, not as secret-protection tokens.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ApiVisibilityLegReceipt {
    leg: ApiVisibilityLeg,
    status: u16,
    retained_body_bytes: u64,
    body_truncated: bool,
    json_compatible_media_type: bool,
    request_template_sha256: String,
    response_body_sha256: String,
}

impl ApiVisibilityLegReceipt {
    /// Returns whether this receipt describes control or candidate.
    pub const fn leg(&self) -> ApiVisibilityLeg {
        self.leg
    }

    /// Returns the exact response status.
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Returns bytes retained under broker and per-request limits.
    pub const fn retained_body_bytes(&self) -> u64 {
        self.retained_body_bytes
    }

    /// Returns whether the response body was incomplete.
    pub const fn body_truncated(&self) -> bool {
        self.body_truncated
    }

    /// Returns whether the single normalized media type was JSON-compatible.
    pub const fn json_compatible_media_type(&self) -> bool {
        self.json_compatible_media_type
    }

    /// Returns the context-value-free request-template digest.
    pub fn request_template_sha256(&self) -> &str {
        &self.request_template_sha256
    }

    /// Returns the domain-separated retained-body digest.
    pub fn response_body_sha256(&self) -> &str {
        &self.response_body_sha256
    }
}

impl fmt::Debug for ApiVisibilityLegReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiVisibilityLegReceipt")
            .field("leg", &self.leg)
            .field("status", &self.status)
            .field("retained_body_bytes", &self.retained_body_bytes)
            .field("body_truncated", &self.body_truncated)
            .field(
                "json_compatible_media_type",
                &self.json_compatible_media_type,
            )
            .field("request_template_sha256", &"<redacted>")
            .field("response_body_sha256", &"<redacted>")
            .finish()
    }
}

/// Monotonic transport audit retained on every post-start exit.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ApiVisibilityDifferentialAudit {
    comparison_id: ComparisonId,
    resource_scope_id: ResourceScopeId,
    control_context_id: OpaqueContextId,
    candidate_context_id: OpaqueContextId,
    dimension: ApiVisibilityDimension,
    observed_at_ms: u64,
    comparator_version: ComparisonAlgorithmVersion,
    canonicalization_version: CanonicalizationVersion,
    projection_policy_id: ProjectionPolicyId,
    request_template_sha256: String,
    operation_sha256: String,
    control: Option<ApiVisibilityLegReceipt>,
    candidate: Option<ApiVisibilityLegReceipt>,
    usage: RuntimeUsage,
    transport: TransportDispatchAudit,
}

impl ApiVisibilityDifferentialAudit {
    fn for_request(request: &ApiVisibilityDifferentialRequest) -> Self {
        Self {
            comparison_id: request.comparison_id.clone(),
            resource_scope_id: request.resource_scope_id.clone(),
            control_context_id: request.control.context_id.clone(),
            candidate_context_id: request.candidate.context_id.clone(),
            dimension: request.dimension,
            observed_at_ms: request.observed_at_ms,
            comparator_version: request.profile.algorithm_version(),
            canonicalization_version: CURRENT_API_VISIBILITY_CANONICALIZATION_VERSION,
            projection_policy_id: request.profile.projection_policy_id(),
            request_template_sha256: request.request_template_sha256.clone(),
            operation_sha256: request.operation_sha256.clone(),
            control: None,
            candidate: None,
            usage: RuntimeUsage::default(),
            transport: TransportDispatchAudit::default(),
        }
    }

    /// Returns the opaque, non-secret comparison handle.
    pub const fn comparison_id(&self) -> &ComparisonId {
        &self.comparison_id
    }

    /// Returns the opaque, non-secret logical-resource handle.
    pub const fn resource_scope_id(&self) -> &ResourceScopeId {
        &self.resource_scope_id
    }

    /// Returns the opaque, non-secret control-context handle.
    pub const fn control_context_id(&self) -> &OpaqueContextId {
        &self.control_context_id
    }

    /// Returns the opaque, non-secret candidate-context handle.
    pub const fn candidate_context_id(&self) -> &OpaqueContextId {
        &self.candidate_context_id
    }

    /// Returns the selected comparison dimension.
    pub const fn dimension(&self) -> ApiVisibilityDimension {
        self.dimension
    }

    /// Returns the caller-supplied deterministic observation time.
    pub const fn observed_at_ms(&self) -> u64 {
        self.observed_at_ms
    }

    /// Returns the comparator version captured before I/O.
    pub const fn comparator_version(&self) -> ComparisonAlgorithmVersion {
        self.comparator_version
    }

    /// Returns the canonical tree-hash version captured before I/O.
    pub const fn canonicalization_version(&self) -> CanonicalizationVersion {
        self.canonicalization_version
    }

    /// Returns the projection-policy identity captured before I/O.
    pub const fn projection_policy_id(&self) -> ProjectionPolicyId {
        self.projection_policy_id
    }

    /// Returns the authorization-value-free request-template digest.
    pub fn request_template_sha256(&self) -> &str {
        &self.request_template_sha256
    }

    /// Returns the domain-separated identity of the complete comparison intent.
    pub fn operation_sha256(&self) -> &str {
        &self.operation_sha256
    }

    /// Returns a completed control receipt, when one exists.
    pub const fn control(&self) -> Option<&ApiVisibilityLegReceipt> {
        self.control.as_ref()
    }

    /// Returns a completed candidate receipt, when one exists.
    pub const fn candidate(&self) -> Option<&ApiVisibilityLegReceipt> {
        self.candidate.as_ref()
    }

    /// Returns broker-owned resource accounting at the exit boundary.
    pub const fn usage(&self) -> &RuntimeUsage {
        &self.usage
    }

    /// Returns bounded, dispatch-ordered transport receipts for both legs.
    pub const fn transport(&self) -> &TransportDispatchAudit {
        &self.transport
    }
}

impl fmt::Debug for ApiVisibilityDifferentialAudit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiVisibilityDifferentialAudit")
            .field("comparison_id", &self.comparison_id)
            .field("resource_scope_id", &self.resource_scope_id)
            .field("control_context_id", &self.control_context_id)
            .field("candidate_context_id", &self.candidate_context_id)
            .field("dimension", &self.dimension)
            .field("observed_at_ms", &self.observed_at_ms)
            .field("comparator_version", &self.comparator_version)
            .field("canonicalization_version", &self.canonicalization_version)
            .field("projection_policy_id", &self.projection_policy_id)
            .field("request_template_sha256", &"<redacted>")
            .field("operation_sha256", &"<redacted>")
            .field("control", &self.control)
            .field("candidate", &self.candidate)
            .field("usage", &self.usage)
            .field("transport", &self.transport)
            .finish()
    }
}

/// Why a complete comparison could not be produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ApiVisibilityInconclusiveReason {
    /// The request was outside an applicable executor contract.
    NotApplicable,
    /// Host or transport policy denied the request.
    BlockedByPolicy,
    /// The network attempt failed after accounting.
    TransportFailure,
    /// The per-request timeout elapsed.
    RequestTimeout,
    /// The transport/executor failed without a narrower category.
    ExecutorFailure,
    /// A rate-limited response cannot establish visibility.
    RateLimited,
    /// A server-side error cannot establish visibility.
    ServerError,
    /// The complete response exceeded a retention boundary.
    TruncatedResponse,
    /// The response did not declare one JSON-compatible media type.
    NonJsonResponse,
    /// The bounded body was not valid JSON.
    MalformedJson,
    /// JSON validation or canonicalization rejected the bounded document.
    CanonicalizationRejected,
}

/// Terminal handling state for one single-use differential runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ApiVisibilityDifferentialDisposition {
    /// The selected comparison dimension was equivalent.
    NoDifferenceObserved,
    /// A difference committed but did not materialize a canonical hypothesis.
    UnresolvedDifference,
    /// A weak, supported boundary hypothesis requires authorized human review.
    AwaitHumanReview,
    /// A leg was incomplete or semantically unsuitable for comparison.
    Inconclusive,
    /// The host cancelled this single-use runtime.
    CancelledByHost,
    /// The host-owned runtime envelope stopped execution.
    RuntimeBudgetLimit,
}

/// Complete audit report for a successful or safely stopped pair.
#[derive(Clone, Serialize)]
pub struct RuntimeApiVisibilityRunReport {
    disposition: ApiVisibilityDifferentialDisposition,
    stopped_leg: Option<ApiVisibilityLeg>,
    inconclusive_reason: Option<ApiVisibilityInconclusiveReason>,
    audit: ApiVisibilityDifferentialAudit,
    comparison: Option<ProfiledApiVisibilityComparison>,
    observation: Option<ApiObservationReceipt>,
    review: Option<ApiVisibilityReview>,
    limit_exceeded: Option<RuntimeLimitExceeded>,
}

impl RuntimeApiVisibilityRunReport {
    /// Returns the non-vulnerability terminal disposition.
    pub const fn disposition(&self) -> ApiVisibilityDifferentialDisposition {
        self.disposition
    }

    /// Returns the leg at which an incomplete run stopped.
    pub const fn stopped_leg(&self) -> Option<ApiVisibilityLeg> {
        self.stopped_leg
    }

    /// Returns the structured reason for an inconclusive result.
    pub const fn inconclusive_reason(&self) -> Option<ApiVisibilityInconclusiveReason> {
        self.inconclusive_reason
    }

    /// Returns raw-value-free transport receipts and final usage.
    pub const fn audit(&self) -> &ApiVisibilityDifferentialAudit {
        &self.audit
    }

    /// Returns the complete V3 replay envelope only for a complete pair.
    pub const fn comparison(&self) -> Option<&ProfiledApiVisibilityComparison> {
        self.comparison.as_ref()
    }

    /// Returns the atomic observation/reasoning receipt only after ingestion.
    pub const fn observation(&self) -> Option<&ApiObservationReceipt> {
        self.observation.as_ref()
    }

    /// Returns the exact committed review projection only after ingestion.
    pub const fn review(&self) -> Option<&ApiVisibilityReview> {
        self.review.as_ref()
    }

    /// Returns the structured budget limit for a resource stop.
    pub const fn limit_exceeded(&self) -> Option<&RuntimeLimitExceeded> {
        self.limit_exceeded.as_ref()
    }
}

impl fmt::Debug for RuntimeApiVisibilityRunReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeApiVisibilityRunReport")
            .field("disposition", &self.disposition)
            .field("stopped_leg", &self.stopped_leg)
            .field("inconclusive_reason", &self.inconclusive_reason)
            .field("audit", &self.audit)
            .field("comparison", &self.comparison)
            .field("observation", &self.observation)
            .field("review", &self.review)
            .field("limit_exceeded", &self.limit_exceeded)
            .finish()
    }
}

/// Failure after configuration validation that cannot be represented as a
/// safe target outcome. Each post-start variant preserves transport audit.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RuntimeApiVisibilityExecutionError {
    /// API reasoning must be installed before native comparison.
    #[error("API visibility reasoning is disabled for this runtime")]
    ApiReasoningDisabled,
    /// A single-use runtime cannot execute another workflow.
    #[error("standard web decision runtime has already started")]
    AlreadyStarted,
    /// Both probes must match the runtime's exact authorized target.
    #[error("API visibility pair target does not match the runtime target")]
    RuntimeTargetMismatch,
    /// A context-isolated transport pool could not be constructed pre-I/O.
    #[error("failed to construct isolated API visibility transport: {source}")]
    TransportSetup {
        /// Redirect-disabled HTTP client construction failure.
        #[source]
        source: HttpEvidenceError,
    },
    /// A supposedly compatible profiled comparison failed closed.
    #[error("API visibility comparison failed after transport completed: {source}")]
    Comparison {
        /// Raw-value-free transport audit.
        audit: Box<ApiVisibilityDifferentialAudit>,
        /// Comparator failure without response content.
        #[source]
        source: ProfiledApiVisibilityError,
    },
    /// A complete V3 comparison could not be converted into an observation.
    #[error("API visibility observation construction failed after comparison: {source}")]
    ObservationBuild {
        /// Raw-value-free transport audit.
        audit: Box<ApiVisibilityDifferentialAudit>,
        /// Replayable V3 comparison envelope produced before the failure.
        comparison: Box<ProfiledApiVisibilityComparison>,
        /// Observation construction failure without response content.
        #[source]
        source: ProfiledApiVisibilityError,
    },
    /// Observation storage or reasoning failed after a complete comparison.
    #[error("API visibility observation failed after transport completed: {source}")]
    Observation {
        /// Raw-value-free transport audit.
        audit: Box<ApiVisibilityDifferentialAudit>,
        /// Replayable V3 comparison envelope.
        comparison: Box<ProfiledApiVisibilityComparison>,
        /// Atomic-ingestion or post-commit reasoning failure.
        #[source]
        source: ApiObservationError,
    },
    /// A committed canonical observation could not be projected exactly.
    #[error("committed API visibility observation has no canonical review projection")]
    ReviewProjection {
        /// Raw-value-free transport audit.
        audit: Box<ApiVisibilityDifferentialAudit>,
        /// Replayable V3 comparison envelope.
        comparison: Box<ProfiledApiVisibilityComparison>,
        /// Observation and reasoning receipt already committed.
        observation: Box<ApiObservationReceipt>,
    },
}

impl RuntimeApiVisibilityExecutionError {
    /// Returns transport audit captured after the runtime started.
    pub fn audit(&self) -> Option<&ApiVisibilityDifferentialAudit> {
        match self {
            Self::Comparison { audit, .. }
            | Self::ObservationBuild { audit, .. }
            | Self::Observation { audit, .. }
            | Self::ReviewProjection { audit, .. } => Some(audit),
            Self::ApiReasoningDisabled
            | Self::AlreadyStarted
            | Self::RuntimeTargetMismatch
            | Self::TransportSetup { .. } => None,
        }
    }

    /// Returns a complete comparison retained across a later failure.
    pub fn comparison(&self) -> Option<&ProfiledApiVisibilityComparison> {
        match self {
            Self::ObservationBuild { comparison, .. }
            | Self::Observation { comparison, .. }
            | Self::ReviewProjection { comparison, .. } => Some(comparison),
            Self::ApiReasoningDisabled
            | Self::AlreadyStarted
            | Self::RuntimeTargetMismatch
            | Self::TransportSetup { .. }
            | Self::Comparison { .. } => None,
        }
    }

    /// Returns an observation committed before a later reasoning failure.
    pub fn committed_observation(&self) -> Option<&ApiObservationCommitReceipt> {
        match self {
            Self::Observation { source, .. } => source.committed_observation(),
            Self::ReviewProjection { observation, .. } => Some(observation.commit()),
            Self::ApiReasoningDisabled
            | Self::AlreadyStarted
            | Self::RuntimeTargetMismatch
            | Self::TransportSetup { .. }
            | Self::ObservationBuild { .. }
            | Self::Comparison { .. } => None,
        }
    }
}

fn primary_context_headers_differ(
    control: &HttpProbe,
    candidate: &HttpProbe,
    context_header_names: &BTreeSet<String>,
) -> bool {
    context_header_names
        .iter()
        .filter(|name| PRIMARY_AUTH_CONTEXT_HEADERS.contains(&name.as_str()))
        .any(|name| control.headers().get(name) != candidate.headers().get(name))
}

fn is_auth_context_header(name: &str) -> bool {
    PRIMARY_AUTH_CONTEXT_HEADERS.contains(&name) || SUPPORTING_AUTH_CONTEXT_HEADERS.contains(&name)
}

fn request_template_digest(
    probe: &HttpProbe,
    context_header_names: &BTreeSet<String>,
    all_header_names: &BTreeSet<&String>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(TEMPLATE_DIGEST_DOMAIN);
    update_framed(&mut hasher, probe.method().as_str().as_bytes());
    update_framed(&mut hasher, probe.url().as_str().as_bytes());
    for name in all_header_names {
        update_framed(&mut hasher, name.as_bytes());
        if context_header_names.contains(name.as_str()) {
            update_framed(&mut hasher, b"<context-owned>");
        } else if let Some(value) = probe.headers().get(name.as_str()) {
            update_framed(&mut hasher, value.as_bytes());
        }
    }
    encode_digest(hasher.finalize().as_slice())
}

#[allow(clippy::too_many_arguments)]
fn operation_digest(
    comparison_id: &ComparisonId,
    resource_scope: &EntityId,
    control_context_id: &OpaqueContextId,
    candidate_context_id: &OpaqueContextId,
    dimension: ApiVisibilityDimension,
    observed_at_ms: u64,
    projection_policy_id: &[u8; 32],
    request_template_sha256: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(OPERATION_DIGEST_DOMAIN);
    for bytes in [
        comparison_id.as_str().as_bytes(),
        resource_scope.as_str().as_bytes(),
        control_context_id.as_str().as_bytes(),
        candidate_context_id.as_str().as_bytes(),
        dimension.as_str().as_bytes(),
        request_template_sha256.as_bytes(),
    ] {
        update_framed(&mut hasher, bytes);
    }
    update_framed(&mut hasher, &observed_at_ms.to_be_bytes());
    update_framed(&mut hasher, projection_policy_id);
    encode_digest(hasher.finalize().as_slice())
}

fn update_framed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}

fn encode_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
#[path = "differential_tests.rs"]
mod tests;
