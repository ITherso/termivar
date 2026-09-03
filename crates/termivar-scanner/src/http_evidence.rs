//! Scope-bound HTTP collection for the decision runner.
//!
//! ## Runtime scope
//!
//! - **Build:** default via `scanning`.
//! - **Execution:** Surface B (metered executor for the decision runtime).
//! - **Default `termivar scan`:** yes, through `StandardWebDecisionRuntime`.
//! - **Support:** implemented and tested.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! This executor performs one bounded discovery request and emits immutable,
//! typed observations. It does not classify vulnerabilities, follow redirects,
//! choose follow-up actions, or mutate the knowledge base directly.

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use async_trait::async_trait;
#[cfg(test)]
use reqwest::header::HeaderValue;
use reqwest::{header::HeaderMap, header::HeaderName, StatusCode, Url};
use sha2::{Digest, Sha256};
use termivar_core::{
    ConfidenceScore, DerivationAlgorithm, Evidence, EvidenceDerivation, EvidenceKind,
    EvidenceSource, EvidenceValue, HttpEvidencePredicate, KnowledgePredicate,
};
use thiserror::Error;

use crate::web_runtime::{
    project_assessment_defense_signal, AssessmentDefenseBodyCoverage,
    AssessmentDefenseProjectionContext, AssessmentDefenseSignal,
};
use crate::{
    defense::{DefenseState, MAX_FINGERPRINT_BODY_SCAN_BYTES},
    payload_strategy::{
        PayloadSeed, PayloadStrategyLimits, PayloadStrategyRef, PayloadStrategyRegistry,
        PayloadVariantRole,
    },
    DecisionActionExecutor, DecisionExecutionFailureKind, DecisionExecutionRequest,
    DecisionExecutionStage, DecisionExecutorError,
};

#[cfg(test)]
use crate::runtime_budget::RequestAccountingBroker;

mod form_controls;
pub(crate) mod passive_review;
mod policy;
mod probe;
mod request_broker;
mod response;
mod review_response;

use form_controls::{extract_form_control_names, FormControlExtraction};
use passive_review::{project_passive_response, PassiveResponseProjection};
use policy::forbidden_request_header;
pub use policy::{
    HttpBodyCapture, HttpEvidencePolicy, DEFAULT_HTTP_BODY_LIMIT, MAX_HTTP_BODY_LIMIT,
};
pub use probe::{HttpProbe, HttpProbeMethod, HttpProbeProvider, SubjectHttpProbeProvider};
pub(crate) use request_broker::{HttpRequestBroker, HttpRequestBrokerError};
#[cfg(feature = "authorization-review")]
pub(crate) use response::AuthorizationResponseDefense;
pub(crate) use response::CollectedHttpResponse;
#[cfg(test)]
pub(crate) use review_response::{
    project_review_response, ReviewResponseProjection, EMPTY_REVIEW_RESPONSE_PROJECTION,
};
pub(crate) use review_response::{
    CorsAllowCredentialsRelation, CorsAllowOriginRelation, LocationRelation, VaryOriginRelation,
};

/// Stable executor identity used by the standard HTTP evidence collector.
pub const HTTP_EVIDENCE_EXECUTOR_ID: &str = "http.evidence";

const MAX_HTTP_PATH_SEGMENTS: usize = 128;
const MAX_HTTP_PATH_SEGMENT_BYTES: usize = 256;
const MAX_HTTP_QUERY_PAYLOAD_PARAMETER_BYTES: usize = 64;
const MAX_ASSESSMENT_DEFENSE_HEADER_OCCURRENCES: usize = 8;
const MAX_ASSESSMENT_DEFENSE_HEADER_VALUE_BYTES: usize = 1024;
const MAX_ASSESSMENT_DEFENSE_COOKIE_NAME_BYTES: usize = 256;

/// Configuration and execution failures for HTTP evidence collection.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HttpEvidenceError {
    /// At least one explicit authorized origin is required.
    #[error("HTTP evidence policy must contain at least one allowed origin")]
    EmptyAllowedOrigins,

    /// The request timeout must be positive.
    #[error("HTTP evidence request timeout must be greater than zero")]
    ZeroTimeout,

    /// The response-body limit must be positive.
    #[error("HTTP evidence body limit must be greater than zero")]
    ZeroBodyLimit,

    /// Evidence consumed by deterministic rules needs non-zero reliability.
    #[error("HTTP evidence reliability must be greater than zero")]
    ZeroReliability,

    /// The response-body limit exceeded the hard per-request bound.
    #[error("HTTP evidence body limit {actual} exceeds maximum {maximum}")]
    BodyLimitTooLarge { actual: usize, maximum: usize },

    /// Text sampling requires at least one character.
    #[error("HTTP evidence text sample limit must be greater than zero")]
    ZeroTextSampleLimit,

    /// A text sample cannot exceed the byte buffer guarding the response.
    #[error("HTTP text sample limit {max_chars} exceeds body byte limit {max_body_bytes}")]
    TextSampleLimitTooLarge {
        /// Requested character limit.
        max_chars: usize,
        /// Configured response byte limit.
        max_body_bytes: usize,
    },

    /// Only absolute HTTP and HTTPS destinations are supported.
    #[error("unsupported HTTP evidence URL scheme {scheme}")]
    UnsupportedScheme { scheme: String },

    /// Embedded URL credentials could leak through request or evidence logs.
    #[error("HTTP evidence URL must not contain embedded credentials")]
    EmbeddedCredentials,

    /// A decision subject did not use the endpoint URL identity convention.
    #[error("decision subject {subject} is not an endpoint URL identity")]
    InvalidEndpointSubject { subject: String },

    /// The executor registry requires a stable non-empty identity.
    #[error("HTTP evidence executor id must not be empty")]
    EmptyExecutorId,

    /// An absolute URL could not be parsed.
    #[error("invalid HTTP evidence URL {value}: {source}")]
    InvalidUrl {
        /// Rejected URL string.
        value: String,
        /// URL parser diagnostic.
        #[source]
        source: url::ParseError,
    },

    /// A request or captured response header name was invalid.
    #[error("invalid HTTP header name {name}")]
    InvalidHeaderName { name: String },

    /// A request header value was invalid.
    #[error("invalid value for HTTP request header {name}")]
    InvalidHeaderValue { name: String },

    /// A streaming or otherwise opaque body could bypass byte accounting.
    #[error("HTTP request body length is unavailable to the accounting broker")]
    UnmeteredRequestBody,

    /// The opt-in GraphQL review attempted to exceed its fixed JSON request bound.
    #[cfg(feature = "graphql-review")]
    #[error("GraphQL review request body exceeds its compiled byte limit")]
    GraphqlReviewRequestBodyLimit,

    /// A request header could alter destination or message framing.
    #[error("HTTP request header {name} is forbidden by evidence policy")]
    ForbiddenRequestHeader { name: String },

    /// A provider attempted to leave the authorized origin set.
    #[error("HTTP evidence target origin is outside policy: {url}")]
    TargetOutsidePolicy { url: String },

    /// A bound payload strategy is not present in its registry.
    #[error("payload strategy {strategy} is not registered for this executor")]
    PayloadStrategyUnavailable {
        /// Stable strategy identity and revision.
        strategy: String,
    },

    /// A bound payload strategy could not derive its artifact for this turn.
    #[error("payload strategy {strategy} failed to derive a {role} artifact")]
    PayloadDerivationFailed {
        /// Stable strategy identity and revision.
        strategy: String,
        /// Control or candidate role requested for the turn.
        role: &'static str,
    },

    /// A native query-payload binding used an invalid fixed parameter name.
    #[error("HTTP query payload parameter is invalid")]
    InvalidQueryPayloadParameter,

    /// Query-payload pairs require a query-free base request so the control is
    /// unambiguous and no existing value can be overwritten or retained.
    #[error("HTTP query payload binding requires a query-free base probe")]
    QueryPayloadRequiresQueryFreeProbe,

    /// The redirect-disabled HTTP client could not be constructed.
    #[error("failed to construct HTTP evidence client: {0}")]
    Client(#[source] reqwest::Error),

    /// The total request and bounded body read timed out.
    #[error("HTTP evidence request timed out after {timeout_ms} ms")]
    Timeout { timeout_ms: u64 },

    /// Request construction or transport failed.
    #[error("HTTP evidence request failed: {0}")]
    Request(#[source] reqwest::Error),

    /// Core reasoning values could not be constructed.
    #[error("failed to construct HTTP evidence: {0}")]
    Reasoning(#[from] termivar_core::ReasoningModelError),

    /// The assessment-only defense projection could not bind its exact base
    /// evidence set. No response values are included in this diagnostic.
    #[error("assessment defense projection violated its fixed evidence boundary")]
    AssessmentDefenseProjectionInvariant,

    /// The sealed assessment observer did not receive its required non-secret
    /// base evidence identities.
    #[error("HTTP assessment observer invariant failed: {invariant}")]
    AssessmentObserverInvariant { invariant: &'static str },
}

pub(crate) fn execution_failure_kind(error: &HttpEvidenceError) -> DecisionExecutionFailureKind {
    match error {
        HttpEvidenceError::InvalidEndpointSubject { .. }
        | HttpEvidenceError::UnsupportedScheme { .. } => {
            DecisionExecutionFailureKind::NotApplicable
        },
        #[cfg(feature = "graphql-review")]
        HttpEvidenceError::GraphqlReviewRequestBodyLimit => {
            DecisionExecutionFailureKind::BlockedByPolicy
        },
        HttpEvidenceError::EmbeddedCredentials
        | HttpEvidenceError::ForbiddenRequestHeader { .. }
        | HttpEvidenceError::UnmeteredRequestBody
        | HttpEvidenceError::TargetOutsidePolicy { .. } => {
            DecisionExecutionFailureKind::BlockedByPolicy
        },
        HttpEvidenceError::Timeout { .. } => DecisionExecutionFailureKind::RequestTimeout,
        HttpEvidenceError::Request(_) => DecisionExecutionFailureKind::TransportFailure,
        HttpEvidenceError::EmptyAllowedOrigins
        | HttpEvidenceError::ZeroTimeout
        | HttpEvidenceError::ZeroBodyLimit
        | HttpEvidenceError::ZeroReliability
        | HttpEvidenceError::BodyLimitTooLarge { .. }
        | HttpEvidenceError::ZeroTextSampleLimit
        | HttpEvidenceError::TextSampleLimitTooLarge { .. }
        | HttpEvidenceError::EmptyExecutorId
        | HttpEvidenceError::InvalidUrl { .. }
        | HttpEvidenceError::InvalidHeaderName { .. }
        | HttpEvidenceError::InvalidHeaderValue { .. }
        | HttpEvidenceError::PayloadStrategyUnavailable { .. }
        | HttpEvidenceError::PayloadDerivationFailed { .. }
        | HttpEvidenceError::InvalidQueryPayloadParameter
        | HttpEvidenceError::QueryPayloadRequiresQueryFreeProbe
        | HttpEvidenceError::Client(_)
        | HttpEvidenceError::Reasoning(_)
        | HttpEvidenceError::AssessmentDefenseProjectionInvariant
        | HttpEvidenceError::AssessmentObserverInvariant { .. } => {
            DecisionExecutionFailureKind::ExecutorFailure
        },
    }
}

pub(crate) fn into_decision_executor_error(error: HttpEvidenceError) -> DecisionExecutorError {
    DecisionExecutorError::with_kind(execution_failure_kind(&error), error.to_string())
}

/// Role label used in payload-derivation diagnostics.
fn payload_role_name(role: PayloadVariantRole) -> &'static str {
    match role {
        PayloadVariantRole::Control => "control",
        PayloadVariantRole::Candidate => "candidate",
    }
}

/// Binds a header-valued payload strategy to the HTTP evidence executor.
///
/// When a decision case selects this binding's strategy reference, the executor
/// derives exactly one artifact per turn from the registry and applies it as the
/// value of `header` before dispatch. Passive turns derive the `Control`
/// artifact; explicit active verification turns derive the `Candidate` artifact,
/// aligning differential work with the existing evidence transaction boundary.
///
/// The derived bytes never bypass [`HttpProbe`] header validation, so the same
/// forbidden-header and value rules that guard hand-built probes also guard
/// strategy-materialized ones.
#[derive(Clone)]
pub struct HttpHeaderPayloadBinding {
    registry: PayloadStrategyRegistry,
    reference: PayloadStrategyRef,
    seed: PayloadSeed,
    limits: PayloadStrategyLimits,
    header: String,
}

impl HttpHeaderPayloadBinding {
    /// Binds `reference` to a request header, validating both up front.
    ///
    /// Fails when the header name is empty, malformed, or forbidden by evidence
    /// policy, or when `reference` is not registered in `registry`. Binding the
    /// registry at construction keeps derivation a pure, in-process step.
    pub fn new(
        registry: PayloadStrategyRegistry,
        reference: PayloadStrategyRef,
        seed: PayloadSeed,
        limits: PayloadStrategyLimits,
        header: impl Into<String>,
    ) -> Result<Self, HttpEvidenceError> {
        let header = header.into();
        let parsed = HeaderName::from_bytes(header.as_bytes()).map_err(|_| {
            HttpEvidenceError::InvalidHeaderName {
                name: header.clone(),
            }
        })?;
        if forbidden_request_header(&parsed) {
            return Err(HttpEvidenceError::ForbiddenRequestHeader {
                name: parsed.as_str().to_owned(),
            });
        }
        if !registry.contains(&reference) {
            return Err(HttpEvidenceError::PayloadStrategyUnavailable {
                strategy: reference.to_string(),
            });
        }
        Ok(Self {
            registry,
            reference,
            seed,
            limits,
            header: parsed.as_str().to_owned(),
        })
    }

    /// Returns the strategy reference this binding materializes.
    pub fn reference(&self) -> &PayloadStrategyRef {
        &self.reference
    }

    /// Returns the request header the derived artifact is applied to.
    pub fn header(&self) -> &str {
        &self.header
    }

    /// Derives the stage-appropriate artifact and applies it to `probe`.
    ///
    /// Passive turns map to a `Control` artifact and active turns to a
    /// `Candidate` artifact. Derivation, provenance revalidation, and byte
    /// bounds are all enforced by the registry; header validation is enforced by
    /// [`HttpProbe::with_header`]. An empty derived artifact omits the header
    /// entirely, letting a control leg represent an anonymous context.
    fn apply_to_probe(
        &self,
        stage: DecisionExecutionStage,
        probe: HttpProbe,
    ) -> Result<HttpProbe, HttpEvidenceError> {
        let role = match stage {
            DecisionExecutionStage::Passive => PayloadVariantRole::Control,
            DecisionExecutionStage::Active => PayloadVariantRole::Candidate,
        };
        let artifact = self
            .registry
            .derive_one(&self.reference, role, &self.seed, self.limits)
            .map_err(|_| HttpEvidenceError::PayloadDerivationFailed {
                strategy: self.reference.to_string(),
                role: payload_role_name(role),
            })?;
        let value = std::str::from_utf8(artifact.as_bytes()).map_err(|_| {
            HttpEvidenceError::PayloadDerivationFailed {
                strategy: self.reference.to_string(),
                role: payload_role_name(role),
            }
        })?;
        // An empty derived artifact intentionally omits the header, so a control
        // leg can represent an anonymous context rather than an empty value.
        if value.is_empty() {
            return Ok(probe);
        }
        probe.with_header(self.header.clone(), value)
    }
}

/// Binds a payload strategy to one fixed query-parameter name.
///
/// The base probe must be query-free. Passive turns derive an empty control
/// artifact and therefore preserve that exact query-free request; active turns
/// append exactly one encoded name/value pair. The destination origin, path,
/// method, and request headers are never changed by this binding.
#[derive(Clone)]
pub(crate) struct HttpQueryPayloadBinding {
    registry: PayloadStrategyRegistry,
    reference: PayloadStrategyRef,
    seed: PayloadSeed,
    limits: PayloadStrategyLimits,
    parameter: String,
}

impl HttpQueryPayloadBinding {
    pub(crate) fn new(
        registry: PayloadStrategyRegistry,
        reference: PayloadStrategyRef,
        seed: PayloadSeed,
        limits: PayloadStrategyLimits,
        parameter: impl Into<String>,
    ) -> Result<Self, HttpEvidenceError> {
        let parameter = parameter.into();
        if parameter.is_empty()
            || parameter.len() > MAX_HTTP_QUERY_PAYLOAD_PARAMETER_BYTES
            || !parameter.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
            })
        {
            return Err(HttpEvidenceError::InvalidQueryPayloadParameter);
        }
        if !registry.contains(&reference) {
            return Err(HttpEvidenceError::PayloadStrategyUnavailable {
                strategy: reference.to_string(),
            });
        }
        Ok(Self {
            registry,
            reference,
            seed,
            limits,
            parameter,
        })
    }

    pub(crate) fn reference(&self) -> &PayloadStrategyRef {
        &self.reference
    }

    #[cfg(test)]
    pub(crate) fn parameter(&self) -> &str {
        &self.parameter
    }

    fn apply_to_probe(
        &self,
        stage: DecisionExecutionStage,
        mut probe: HttpProbe,
    ) -> Result<HttpProbe, HttpEvidenceError> {
        if probe.url().query().is_some() {
            return Err(HttpEvidenceError::QueryPayloadRequiresQueryFreeProbe);
        }
        let role = match stage {
            DecisionExecutionStage::Passive => PayloadVariantRole::Control,
            DecisionExecutionStage::Active => PayloadVariantRole::Candidate,
        };
        let artifact = self
            .registry
            .derive_one(&self.reference, role, &self.seed, self.limits)
            .map_err(|_| HttpEvidenceError::PayloadDerivationFailed {
                strategy: self.reference.to_string(),
                role: payload_role_name(role),
            })?;
        let value = std::str::from_utf8(artifact.as_bytes()).map_err(|_| {
            HttpEvidenceError::PayloadDerivationFailed {
                strategy: self.reference.to_string(),
                role: payload_role_name(role),
            }
        })?;
        if value.is_empty() {
            return Ok(probe);
        }
        probe
            .url_mut()
            .query_pairs_mut()
            .append_pair(&self.parameter, value);
        Ok(probe)
    }
}

#[derive(Clone)]
enum HttpPayloadBinding {
    Header(HttpHeaderPayloadBinding),
    Query(HttpQueryPayloadBinding),
}

impl HttpPayloadBinding {
    fn reference(&self) -> &PayloadStrategyRef {
        match self {
            Self::Header(binding) => binding.reference(),
            Self::Query(binding) => binding.reference(),
        }
    }

    fn apply_to_probe(
        &self,
        stage: DecisionExecutionStage,
        probe: HttpProbe,
    ) -> Result<HttpProbe, HttpEvidenceError> {
        match self {
            Self::Header(binding) => binding.apply_to_probe(stage, probe),
            Self::Query(binding) => binding.apply_to_probe(stage, probe),
        }
    }
}

/// Real HTTP executor that produces typed evidence for the decision runner.
///
/// # Examples
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use url::Url;
/// use termivar_scanner::{
///     DecisionActionExecutor, HttpEvidenceExecutor, HttpEvidencePolicy, HttpProbeProvider,
///     SubjectHttpProbeProvider,
/// };
///
/// let target = Url::parse("https://example.test/")?;
/// let policy = HttpEvidencePolicy::for_origin(target)?;
/// let probes: Arc<dyn HttpProbeProvider> =
///     Arc::new(SubjectHttpProbeProvider::default());
/// let executor = HttpEvidenceExecutor::new(policy, probes)?;
///
/// assert_eq!(executor.id(), "http.evidence");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct HttpEvidenceExecutor {
    id: String,
    requests: HttpRequestBroker,
    probes: Arc<dyn HttpProbeProvider>,
    payload: Option<HttpPayloadBinding>,
    capture_form_control_names: bool,
    complete_response_observer: Option<Arc<dyn CompleteHttpResponseObserver>>,
    assessment_defense_projection: bool,
}

impl HttpEvidenceExecutor {
    /// Creates a redirect-disabled executor with the standard identity.
    pub fn new(
        policy: HttpEvidencePolicy,
        probes: Arc<dyn HttpProbeProvider>,
    ) -> Result<Self, HttpEvidenceError> {
        Self::with_id(HTTP_EVIDENCE_EXECUTOR_ID, policy, probes)
    }

    /// Creates a redirect-disabled executor with a host-selected identity.
    pub fn with_id(
        id: impl Into<String>,
        policy: HttpEvidencePolicy,
        probes: Arc<dyn HttpProbeProvider>,
    ) -> Result<Self, HttpEvidenceError> {
        let id = validate_executor_id(id)?;
        let requests = HttpRequestBroker::new_unmetered(policy)?;
        Ok(Self {
            id,
            requests,
            probes,
            payload: None,
            capture_form_control_names: false,
            complete_response_observer: None,
            assessment_defense_projection: false,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_with_accounting(
        policy: HttpEvidencePolicy,
        probes: Arc<dyn HttpProbeProvider>,
        accounting: RequestAccountingBroker,
    ) -> Result<Self, HttpEvidenceError> {
        Self::with_id_and_accounting(HTTP_EVIDENCE_EXECUTOR_ID, policy, probes, accounting)
    }

    #[cfg(test)]
    pub(crate) fn with_id_and_accounting(
        id: impl Into<String>,
        policy: HttpEvidencePolicy,
        probes: Arc<dyn HttpProbeProvider>,
        accounting: RequestAccountingBroker,
    ) -> Result<Self, HttpEvidenceError> {
        let id = validate_executor_id(id)?;
        let requests = HttpRequestBroker::new_metered(policy, accounting)?;
        Ok(Self {
            id,
            requests,
            probes,
            payload: None,
            capture_form_control_names: false,
            complete_response_observer: None,
            assessment_defense_projection: false,
        })
    }

    pub(crate) fn new_with_request_broker(
        requests: HttpRequestBroker,
        probes: Arc<dyn HttpProbeProvider>,
    ) -> Result<Self, HttpEvidenceError> {
        Self::with_id_and_request_broker(HTTP_EVIDENCE_EXECUTOR_ID, requests, probes)
    }

    pub(crate) fn with_id_and_request_broker(
        id: impl Into<String>,
        requests: HttpRequestBroker,
        probes: Arc<dyn HttpProbeProvider>,
    ) -> Result<Self, HttpEvidenceError> {
        let id = validate_executor_id(id)?;
        Ok(Self {
            id,
            requests,
            probes,
            payload: None,
            capture_form_control_names: false,
            complete_response_observer: None,
            assessment_defense_projection: false,
        })
    }

    /// Enables conservative HTML form-control-name discovery for this executor.
    ///
    /// When enabled, and only when the body-capture policy authorizes a bounded
    /// [`HttpBodyCapture::TextSample`] and the response is `text/html`, the
    /// executor reads named form controls from the *same* bounded sample and
    /// emits [`HttpEvidencePredicate::RESPONSE_FORM_CONTROL_NAMES`]. It never
    /// opens a second content-capture path, and never records control values.
    /// This is a deliberately narrow opt-in, not a generic extractor hook.
    pub(crate) fn with_form_control_capture(mut self) -> Self {
        self.capture_form_control_names = true;
        self
    }

    /// Installs the crate-owned response projection seam used by the origin
    /// assessment runtime.
    ///
    /// The trait and observation type are crate-private. An observer can see a
    /// body only after the broker has observed stream EOF; partial bytes are
    /// never exposed through this seam. Its evidence is returned in the same
    /// executor batch as the HTTP observations, so the decision runner either
    /// commits all of it or none of it.
    pub(crate) fn with_complete_response_observer(
        mut self,
        observer: Arc<dyn CompleteHttpResponseObserver>,
    ) -> Self {
        self.complete_response_observer = Some(observer);
        self
    }

    /// Enables the closed, namespaced defense projection used only by the
    /// origin assessment runtime. No raw response material leaves this
    /// executor; only bounded typed signals enter the atomic evidence batch.
    pub(crate) fn with_assessment_defense_projection(mut self) -> Self {
        self.assessment_defense_projection = true;
        self
    }

    /// Binds a header-valued payload strategy this executor will materialize.
    ///
    /// The executor then advertises exact support for the binding's strategy
    /// reference and, when a decision case selects it, derives one control or
    /// candidate artifact per turn and applies it before dispatch. Actions that
    /// do not select the reference are unaffected, so an executor may serve both
    /// plain discovery and strategy-driven differential turns.
    pub fn with_payload_binding(mut self, binding: HttpHeaderPayloadBinding) -> Self {
        self.payload = Some(HttpPayloadBinding::Header(binding));
        self
    }

    /// Installs the crate-owned query-pair binding used by native bounded web
    /// review actions. It is intentionally not a public arbitrary transport
    /// setting.
    pub(crate) fn with_query_payload_binding(mut self, binding: HttpQueryPayloadBinding) -> Self {
        self.payload = Some(HttpPayloadBinding::Query(binding));
        self
    }

    /// Returns the bound payload strategy reference, if any.
    pub fn payload_strategy_reference(&self) -> Option<&PayloadStrategyRef> {
        self.payload.as_ref().map(HttpPayloadBinding::reference)
    }

    /// Returns the immutable execution policy.
    pub fn policy(&self) -> &HttpEvidencePolicy {
        self.requests.policy()
    }

    /// Resolves the base probe and applies the bound payload artifact when the
    /// decision case selects this executor's strategy reference.
    fn resolve_probe(
        &self,
        decision: &DecisionExecutionRequest,
    ) -> Result<HttpProbe, HttpEvidenceError> {
        let probe = self.probes.probe_for(decision)?;
        match (self.payload.as_ref(), decision.payload_strategy()) {
            (Some(binding), Some(strategy)) if binding.reference() == strategy => {
                binding.apply_to_probe(decision.stage(), probe)
            },
            _ => Ok(probe),
        }
    }

    async fn collect(
        &self,
        decision: &DecisionExecutionRequest,
    ) -> Result<Vec<Evidence>, HttpRequestBrokerError> {
        let probe = self.resolve_probe(decision)?;
        let collected = self.requests.collect(decision, &probe).await?;
        self.to_evidence(decision, &probe, collected)
            .map_err(Into::into)
    }

    fn to_evidence(
        &self,
        decision: &DecisionExecutionRequest,
        probe: &HttpProbe,
        response: CollectedHttpResponse,
    ) -> Result<Vec<Evidence>, HttpEvidenceError> {
        let mut evidence = vec![
            self.observation(
                decision,
                EvidenceKind::Http,
                HttpEvidencePredicate::REQUEST_METHOD.into(),
                EvidenceValue::Text(probe.method().as_str().to_owned()),
                "request-method",
            )?,
            self.observation(
                decision,
                EvidenceKind::Http,
                HttpEvidencePredicate::REQUEST_URL.into(),
                EvidenceValue::Text(probe.url().to_string()),
                "request-url",
            )?,
            self.observation(
                decision,
                EvidenceKind::Http,
                HttpEvidencePredicate::RESPONSE_STATUS.into(),
                EvidenceValue::Unsigned(u64::from(response.status.as_u16())),
                "response-status",
            )?,
            self.observation(
                decision,
                EvidenceKind::Http,
                HttpEvidencePredicate::RESPONSE_FINAL_URL.into(),
                EvidenceValue::Text(response.final_url.to_string()),
                "response-final-url",
            )?,
            self.observation(
                decision,
                EvidenceKind::Http,
                HttpEvidencePredicate::RESPONSE_VERSION.into(),
                EvidenceValue::Text(response.version.clone()),
                "response-version",
            )?,
            self.observation(
                decision,
                EvidenceKind::Timing,
                HttpEvidencePredicate::TIMING_TTFB_MS.into(),
                EvidenceValue::Unsigned(response.ttfb_ms),
                "time-to-first-byte",
            )?,
            self.observation(
                decision,
                EvidenceKind::Timing,
                HttpEvidencePredicate::TIMING_TOTAL_MS.into(),
                EvidenceValue::Unsigned(response.total_ms),
                "total-response-time",
            )?,
        ];

        let path_segments: BTreeSet<_> = probe
            .url()
            .path_segments()
            .into_iter()
            .flatten()
            .filter(|segment| !segment.is_empty() && segment.len() <= MAX_HTTP_PATH_SEGMENT_BYTES)
            .take(MAX_HTTP_PATH_SEGMENTS)
            .map(str::to_owned)
            .collect();
        for segment in path_segments {
            evidence.push(self.observation(
                decision,
                EvidenceKind::Http,
                HttpEvidencePredicate::REQUEST_PATH_SEGMENT.into(),
                EvidenceValue::Text(segment),
                "request-path-segment",
            )?);
        }

        for name in self.policy().captured_headers() {
            if let Some(value) = joined_header(&response.headers, name) {
                evidence.push(self.observation(
                    decision,
                    EvidenceKind::Http,
                    HttpEvidencePredicate::response_header(name.clone())?,
                    EvidenceValue::Text(value),
                    &format!("response-header:{name}"),
                )?);
            }
        }

        if let Some(media_type) = normalized_media_type(&response.headers) {
            let json_compatible = json_compatible_media_type(&media_type);
            evidence.push(self.observation(
                decision,
                EvidenceKind::Http,
                HttpEvidencePredicate::RESPONSE_MEDIA_TYPE.into(),
                EvidenceValue::Text(media_type),
                "response-media-type",
            )?);
            evidence.push(self.observation(
                decision,
                EvidenceKind::Http,
                HttpEvidencePredicate::RESPONSE_MEDIA_TYPE_JSON_COMPATIBLE.into(),
                EvidenceValue::Boolean(json_compatible),
                "response-media-type-json-compatibility",
            )?);
        }

        // The sealed assessment observer owns a stricter bounded Set-Cookie
        // projection. Do not duplicate its names through the historical generic
        // extractor, whose contract predates the assessment-wide occurrence
        // ceiling. Baseline/default executors retain the existing behavior.
        if self.complete_response_observer.is_none() {
            for cookie_name in response_cookie_names(&response.headers) {
                evidence.push(self.observation(
                    decision,
                    EvidenceKind::Authentication,
                    HttpEvidencePredicate::COOKIE_NAME.into(),
                    EvidenceValue::Text(cookie_name),
                    "response-set-cookie-name",
                )?);
            }
        }

        evidence.push(self.observation(
            decision,
            EvidenceKind::Content,
            HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED.into(),
            EvidenceValue::Unsigned(u64::try_from(response.body.len()).unwrap_or(u64::MAX)),
            "response-body-size",
        )?);
        evidence.push(self.observation(
            decision,
            EvidenceKind::Content,
            HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED.into(),
            EvidenceValue::Boolean(response.body_truncated),
            "response-body-truncation",
        )?);
        evidence.push(self.observation(
            decision,
            EvidenceKind::Content,
            HttpEvidencePredicate::RESPONSE_BODY_SHA256.into(),
            EvidenceValue::Text(format!("{:x}", Sha256::digest(&response.body))),
            "response-body-sha256",
        )?);

        if let HttpBodyCapture::TextSample { max_chars } = self.policy().body_capture() {
            if textual_response(&response.headers) {
                let decoded = String::from_utf8_lossy(&response.body);
                let sample: String = decoded.chars().take(max_chars).collect();

                // Form-control discovery reads the SAME bounded sample and only
                // for text/html. It cannot run under MetadataOnly (no sample is
                // computed here at all), so the body-capture policy is never
                // bypassed. Only control names are recorded, never values, and
                // only when at least one name is conservatively observed. Names
                // are extracted from the borrowed sample first, before the
                // sample is moved into its own observation.
                let form_control_names = if self.capture_form_control_names
                    && normalized_media_type(&response.headers).as_deref() == Some("text/html")
                {
                    match extract_form_control_names(&sample) {
                        FormControlExtraction::Observed(names) if !names.is_empty() => Some(names),
                        _ => None,
                    }
                } else {
                    None
                };

                // Build the body-sample observation so a derived form-control
                // record can cite its exact EvidenceId as lineage. The body
                // sample is the sole transformation input; the media type and
                // truncation observations are gating/context, not lineage.
                let body_sample = self.observation(
                    decision,
                    EvidenceKind::Content,
                    HttpEvidencePredicate::RESPONSE_BODY_SAMPLE.into(),
                    EvidenceValue::Text(sample),
                    "response-body-sample",
                )?;

                if let Some(names) = form_control_names {
                    let derivation = EvidenceDerivation::new(
                        [body_sample.id().clone()],
                        form_control_derivation_algorithm(),
                    )?;
                    evidence.push(
                        self.observation(
                            decision,
                            EvidenceKind::Content,
                            HttpEvidencePredicate::RESPONSE_FORM_CONTROL_NAMES.into(),
                            EvidenceValue::TextList(names),
                            "response-form-control-names",
                        )?
                        .derived_from(derivation),
                    );
                }

                // Preserve the historical batch order: form-control names (when
                // present) precede the body sample.
                evidence.push(body_sample);
            }
        }

        append_rate_limit_evidence(self, decision, &response, &mut evidence)?;
        if let Some(observer) = &self.complete_response_observer {
            let media_type = normalized_media_type(&response.headers);
            // Raw headers remain local to the executor. Only this bounded,
            // value-free projection crosses the sealed observer boundary.
            let passive_response_projection = project_passive_response(&response.headers);
            let review_response_projection =
                review_response::project_review_response(probe, &response.headers);
            let evidence_id = |predicate: termivar_core::PredicateDescriptor| {
                let predicate = predicate.into_knowledge();
                evidence
                    .iter()
                    .find(|item| item.predicate() == &predicate)
                    .map(|item| item.id())
            };
            let observation = CompleteHttpResponseObservation {
                case_id: decision.case().id(),
                action_id: decision.case().action_id(),
                executor_id: &self.id,
                hypothesis_id: decision.case().hypothesis_id(),
                has_payload_strategy: decision.case().payload_strategy().is_some(),
                payload_strategy: decision.case().payload_strategy(),
                applies_hypothesis_transition: decision.case().applies_hypothesis_transition(),
                stage: decision.stage(),
                subject: decision.case().subject(),
                method: probe.method(),
                requested_url: probe.url(),
                status: response.status.as_u16(),
                media_type: media_type.as_deref(),
                reliability: self.policy().reliability(),
                complete_body: response.body_complete.then_some(response.body.as_slice()),
                request_method_evidence_id: evidence_id(HttpEvidencePredicate::REQUEST_METHOD),
                request_url_evidence_id: evidence_id(HttpEvidencePredicate::REQUEST_URL),
                response_status_evidence_id: evidence_id(HttpEvidencePredicate::RESPONSE_STATUS),
                response_final_url_evidence_id: evidence_id(
                    HttpEvidencePredicate::RESPONSE_FINAL_URL,
                ),
                response_media_type_evidence_id: evidence_id(
                    HttpEvidencePredicate::RESPONSE_MEDIA_TYPE,
                ),
                response_body_truncated_evidence_id: evidence_id(
                    HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED,
                ),
                response_body_digest_evidence_id: evidence_id(
                    HttpEvidencePredicate::RESPONSE_BODY_SHA256,
                ),
                passive_response_projection: &passive_response_projection,
                review_response_projection: &review_response_projection,
            };
            evidence.extend(observer.observe(observation)?);
        }
        if self.assessment_defense_projection {
            let signal = bounded_assessment_defense_signal(
                response.status.as_u16(),
                probe.method(),
                &response.headers,
                response.body_complete,
                &response.body,
            );
            let parent_predicates = [
                HttpEvidencePredicate::REQUEST_METHOD,
                HttpEvidencePredicate::REQUEST_URL,
                HttpEvidencePredicate::RESPONSE_STATUS,
                HttpEvidencePredicate::RESPONSE_FINAL_URL,
                HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED,
                HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED,
                HttpEvidencePredicate::RESPONSE_BODY_SHA256,
                HttpEvidencePredicate::RATE_LIMIT_DETECTED,
                HttpEvidencePredicate::RATE_LIMIT_ADVERTISED,
            ];
            let mut parents = Vec::with_capacity(parent_predicates.len());
            for descriptor in parent_predicates {
                let predicate = descriptor.into_knowledge();
                let mut matching = evidence
                    .iter()
                    .filter(|item| item.predicate() == &predicate);
                let Some(parent) = matching.next() else {
                    return Err(HttpEvidenceError::AssessmentDefenseProjectionInvariant);
                };
                if matching.next().is_some() {
                    return Err(HttpEvidenceError::AssessmentDefenseProjectionInvariant);
                }
                parents.push(parent.id().clone());
            }
            evidence.extend(project_assessment_defense_signal(
                &signal,
                AssessmentDefenseProjectionContext {
                    subject: decision.case().subject(),
                    case_id: decision.case().id(),
                    executor_id: &self.id,
                    reliability: self.policy().reliability(),
                    parents,
                },
            )?);
        }
        Ok(evidence)
    }

    fn observation(
        &self,
        decision: &DecisionExecutionRequest,
        kind: EvidenceKind,
        predicate: KnowledgePredicate,
        value: EvidenceValue,
        method: &str,
    ) -> Result<Evidence, HttpEvidenceError> {
        let source = EvidenceSource::new(self.id.clone(), method)?
            .with_correlation_id(decision.case().id())?;
        Ok(Evidence::new(
            decision.case().subject().clone(),
            kind,
            predicate,
            value,
            source,
            self.policy().reliability(),
        ))
    }
}

#[async_trait]
impl DecisionActionExecutor for HttpEvidenceExecutor {
    fn id(&self) -> &str {
        &self.id
    }

    fn supports_payload_strategy(&self, strategy: &PayloadStrategyRef) -> bool {
        self.payload
            .as_ref()
            .is_some_and(|binding| binding.reference() == strategy)
    }

    async fn execute(
        &self,
        request: &DecisionExecutionRequest,
    ) -> Result<Vec<Evidence>, DecisionExecutorError> {
        self.collect(request)
            .await
            .map_err(HttpRequestBrokerError::into_decision_executor_error)
    }
}

/// Sealed response projection boundary for crate-owned bounded runtimes.
///
/// This trait is intentionally not public. In particular, it is not a generic
/// host callback that could retain response bodies or mutate transport policy.
mod complete_response_observer_seal {
    pub(super) trait Sealed {}

    impl Sealed for crate::web_runtime::AssessmentDiscoveryObserver {}

    impl Sealed for crate::web_runtime::AssessmentReviewObserverSet {}

    #[cfg(test)]
    impl Sealed for super::tests::RejectingCompleteResponseObserver {}
}

#[allow(private_bounds)]
pub(crate) trait CompleteHttpResponseObserver:
    complete_response_observer_seal::Sealed + Send + Sync
{
    /// Derives safe evidence from one response. `complete_body()` returns bytes
    /// only when the broker observed stream EOF.
    fn observe(
        &self,
        observation: CompleteHttpResponseObservation<'_>,
    ) -> Result<Vec<Evidence>, HttpEvidenceError>;
}

/// Borrowed response view that never exposes a partial body.
pub(crate) struct CompleteHttpResponseObservation<'a> {
    case_id: &'a str,
    action_id: &'a str,
    executor_id: &'a str,
    hypothesis_id: &'a str,
    has_payload_strategy: bool,
    payload_strategy: Option<&'a PayloadStrategyRef>,
    applies_hypothesis_transition: bool,
    stage: DecisionExecutionStage,
    subject: &'a termivar_core::EntityId,
    method: HttpProbeMethod,
    requested_url: &'a Url,
    status: u16,
    media_type: Option<&'a str>,
    reliability: ConfidenceScore,
    complete_body: Option<&'a [u8]>,
    request_method_evidence_id: Option<&'a termivar_core::EvidenceId>,
    request_url_evidence_id: Option<&'a termivar_core::EvidenceId>,
    response_status_evidence_id: Option<&'a termivar_core::EvidenceId>,
    response_final_url_evidence_id: Option<&'a termivar_core::EvidenceId>,
    response_media_type_evidence_id: Option<&'a termivar_core::EvidenceId>,
    response_body_truncated_evidence_id: Option<&'a termivar_core::EvidenceId>,
    response_body_digest_evidence_id: Option<&'a termivar_core::EvidenceId>,
    passive_response_projection: &'a PassiveResponseProjection,
    review_response_projection: &'a review_response::ReviewResponseProjection,
}

impl CompleteHttpResponseObservation<'_> {
    pub(crate) const fn case_id(&self) -> &str {
        self.case_id
    }

    pub(crate) const fn action_id(&self) -> &str {
        self.action_id
    }

    pub(crate) const fn executor_id(&self) -> &str {
        self.executor_id
    }

    pub(crate) const fn hypothesis_id(&self) -> &str {
        self.hypothesis_id
    }

    pub(crate) const fn has_payload_strategy(&self) -> bool {
        self.has_payload_strategy
    }

    pub(crate) const fn payload_strategy(&self) -> Option<&PayloadStrategyRef> {
        self.payload_strategy
    }

    pub(crate) const fn applies_hypothesis_transition(&self) -> bool {
        self.applies_hypothesis_transition
    }

    pub(crate) const fn stage(&self) -> DecisionExecutionStage {
        self.stage
    }

    pub(crate) const fn subject(&self) -> &termivar_core::EntityId {
        self.subject
    }

    pub(crate) const fn method(&self) -> HttpProbeMethod {
        self.method
    }

    pub(crate) const fn requested_url(&self) -> &Url {
        self.requested_url
    }

    pub(crate) const fn status(&self) -> u16 {
        self.status
    }

    pub(crate) fn media_type(&self) -> Option<&str> {
        self.media_type
    }

    pub(crate) const fn reliability(&self) -> ConfidenceScore {
        self.reliability
    }

    pub(crate) const fn complete_body(&self) -> Option<&[u8]> {
        self.complete_body
    }

    pub(crate) const fn request_method_evidence_id(&self) -> Option<&termivar_core::EvidenceId> {
        self.request_method_evidence_id
    }

    pub(crate) const fn request_url_evidence_id(&self) -> Option<&termivar_core::EvidenceId> {
        self.request_url_evidence_id
    }

    pub(crate) const fn response_status_evidence_id(&self) -> Option<&termivar_core::EvidenceId> {
        self.response_status_evidence_id
    }

    pub(crate) const fn response_final_url_evidence_id(
        &self,
    ) -> Option<&termivar_core::EvidenceId> {
        self.response_final_url_evidence_id
    }

    pub(crate) const fn response_media_type_evidence_id(
        &self,
    ) -> Option<&termivar_core::EvidenceId> {
        self.response_media_type_evidence_id
    }

    pub(crate) const fn response_body_truncated_evidence_id(
        &self,
    ) -> Option<&termivar_core::EvidenceId> {
        self.response_body_truncated_evidence_id
    }

    pub(crate) const fn response_body_digest_evidence_id(
        &self,
    ) -> Option<&termivar_core::EvidenceId> {
        self.response_body_digest_evidence_id
    }

    pub(crate) const fn passive_response_projection(&self) -> &PassiveResponseProjection {
        self.passive_response_projection
    }

    pub(crate) const fn review_response_projection(
        &self,
    ) -> &review_response::ReviewResponseProjection {
        self.review_response_projection
    }
}

#[cfg(test)]
pub(crate) struct CompleteHttpResponseObservationTestInput<'a> {
    pub(crate) case_id: &'a str,
    pub(crate) action_id: &'a str,
    pub(crate) executor_id: &'a str,
    pub(crate) hypothesis_id: &'a str,
    pub(crate) has_payload_strategy: bool,
    pub(crate) payload_strategy: Option<&'a PayloadStrategyRef>,
    pub(crate) applies_hypothesis_transition: bool,
    pub(crate) stage: DecisionExecutionStage,
    pub(crate) subject: &'a termivar_core::EntityId,
    pub(crate) method: HttpProbeMethod,
    pub(crate) requested_url: &'a Url,
    pub(crate) status: u16,
    pub(crate) media_type: Option<&'a str>,
    pub(crate) reliability: ConfidenceScore,
    pub(crate) complete_body: Option<&'a [u8]>,
    pub(crate) request_method_evidence_id: Option<&'a termivar_core::EvidenceId>,
    pub(crate) request_url_evidence_id: Option<&'a termivar_core::EvidenceId>,
    pub(crate) response_status_evidence_id: Option<&'a termivar_core::EvidenceId>,
    pub(crate) response_final_url_evidence_id: Option<&'a termivar_core::EvidenceId>,
    pub(crate) response_media_type_evidence_id: Option<&'a termivar_core::EvidenceId>,
    pub(crate) response_body_truncated_evidence_id: Option<&'a termivar_core::EvidenceId>,
    pub(crate) response_body_digest_evidence_id: Option<&'a termivar_core::EvidenceId>,
    pub(crate) passive_response_projection: &'a PassiveResponseProjection,
    pub(crate) review_response_projection: Option<&'a ReviewResponseProjection>,
}

#[cfg(test)]
pub(crate) fn complete_http_response_observation_for_test<'a>(
    input: CompleteHttpResponseObservationTestInput<'a>,
) -> CompleteHttpResponseObservation<'a> {
    CompleteHttpResponseObservation {
        case_id: input.case_id,
        action_id: input.action_id,
        executor_id: input.executor_id,
        hypothesis_id: input.hypothesis_id,
        has_payload_strategy: input.has_payload_strategy,
        payload_strategy: input.payload_strategy,
        applies_hypothesis_transition: input.applies_hypothesis_transition,
        stage: input.stage,
        subject: input.subject,
        method: input.method,
        requested_url: input.requested_url,
        status: input.status,
        media_type: input.media_type,
        reliability: input.reliability,
        complete_body: input.complete_body,
        request_method_evidence_id: input.request_method_evidence_id,
        request_url_evidence_id: input.request_url_evidence_id,
        response_status_evidence_id: input.response_status_evidence_id,
        response_final_url_evidence_id: input.response_final_url_evidence_id,
        response_media_type_evidence_id: input.response_media_type_evidence_id,
        response_body_truncated_evidence_id: input.response_body_truncated_evidence_id,
        response_body_digest_evidence_id: input.response_body_digest_evidence_id,
        passive_response_projection: input.passive_response_projection,
        review_response_projection: input
            .review_response_projection
            .unwrap_or(&EMPTY_REVIEW_RESPONSE_PROJECTION),
    }
}

#[cfg(test)]
pub(crate) fn passive_response_projection_for_test(
    headers: &[(&'static str, &str)],
) -> PassiveResponseProjection {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        map.append(
            *name,
            HeaderValue::from_str(value).expect("valid fixture header value"),
        );
    }
    project_passive_response(&map)
}

fn validate_executor_id(id: impl Into<String>) -> Result<String, HttpEvidenceError> {
    let id = id.into();
    if id.trim().is_empty() {
        return Err(HttpEvidenceError::EmptyExecutorId);
    }
    Ok(id)
}

fn joined_header(headers: &HeaderMap, name: &str) -> Option<String> {
    let values: Vec<_> = headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    (!values.is_empty()).then(|| values.join(", "))
}

fn response_cookie_names(headers: &HeaderMap) -> BTreeSet<String> {
    headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split(';').next())
        .filter_map(|pair| pair.split_once('=').map(|(name, _)| name.trim()))
        .filter(|name| valid_cookie_name(name))
        .map(str::to_owned)
        .collect()
}

fn valid_cookie_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii()
                && !byte.is_ascii_control()
                && !matches!(
                    byte,
                    b' ' | b'\t'
                        | b'('
                        | b')'
                        | b'<'
                        | b'>'
                        | b'@'
                        | b','
                        | b';'
                        | b':'
                        | b'\\'
                        | b'"'
                        | b'/'
                        | b'['
                        | b']'
                        | b'?'
                        | b'='
                        | b'{'
                        | b'}'
                )
        })
}

/// Stable identity of the bounded HTML form-control-name extraction, cited as
/// the derivation algorithm of the derived form-control evidence.
fn form_control_derivation_algorithm() -> DerivationAlgorithm {
    DerivationAlgorithm::new("http.form-control-names", 1)
        .expect("static form-control derivation algorithm identity is valid")
}

fn textual_response(headers: &HeaderMap) -> bool {
    joined_header(headers, "content-type")
        .map(|content_type| {
            let content_type = content_type.to_ascii_lowercase();
            content_type.starts_with("text/")
                || content_type.contains("json")
                || content_type.contains("xml")
                || content_type.contains("javascript")
                || content_type.contains("x-www-form-urlencoded")
        })
        .unwrap_or(false)
}

pub(crate) fn normalized_media_type(headers: &HeaderMap) -> Option<String> {
    let mut values = headers.get_all("content-type").iter();
    let raw = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let essence = raw.split(';').next()?.trim();
    let (top_level, subtype) = essence.split_once('/')?;
    if top_level.is_empty()
        || subtype.is_empty()
        || subtype.contains('/')
        || !top_level.bytes().all(http_token_byte)
        || !subtype.bytes().all(http_token_byte)
    {
        return None;
    }
    Some(format!(
        "{}/{}",
        top_level.to_ascii_lowercase(),
        subtype.to_ascii_lowercase()
    ))
}

pub(crate) fn json_compatible_media_type(media_type: &str) -> bool {
    media_type
        .split_once('/')
        .is_some_and(|(_, subtype)| subtype == "json" || subtype.ends_with("+json"))
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

fn append_rate_limit_evidence(
    executor: &HttpEvidenceExecutor,
    decision: &DecisionExecutionRequest,
    response: &CollectedHttpResponse,
    evidence: &mut Vec<Evidence>,
) -> Result<(), HttpEvidenceError> {
    let rate_headers = [
        (
            "retry-after",
            None,
            HttpEvidencePredicate::RATE_LIMIT_RETRY_AFTER,
        ),
        (
            "ratelimit-limit",
            Some("x-ratelimit-limit"),
            HttpEvidencePredicate::RATE_LIMIT_LIMIT,
        ),
        (
            "ratelimit-remaining",
            Some("x-ratelimit-remaining"),
            HttpEvidencePredicate::RATE_LIMIT_REMAINING,
        ),
        (
            "ratelimit-reset",
            Some("x-ratelimit-reset"),
            HttpEvidencePredicate::RATE_LIMIT_RESET,
        ),
    ];
    let advertised = rate_headers.iter().any(|(standard, fallback, _)| {
        response.headers.contains_key(*standard)
            || fallback.is_some_and(|header| response.headers.contains_key(header))
    });

    evidence.push(executor.observation(
        decision,
        EvidenceKind::RateLimit,
        HttpEvidencePredicate::RATE_LIMIT_DETECTED.into(),
        EvidenceValue::Boolean(response.status == StatusCode::TOO_MANY_REQUESTS),
        "rate-limit-status",
    )?);
    evidence.push(executor.observation(
        decision,
        EvidenceKind::RateLimit,
        HttpEvidencePredicate::RATE_LIMIT_ADVERTISED.into(),
        EvidenceValue::Boolean(advertised),
        "rate-limit-headers",
    )?);

    for (standard, fallback, predicate) in rate_headers {
        let selected = joined_header(&response.headers, standard).map(|value| (standard, value));
        let selected = selected.or_else(|| {
            fallback.and_then(|header| {
                joined_header(&response.headers, header).map(|value| (header, value))
            })
        });
        let Some((header, raw)) = selected else {
            continue;
        };
        let value = match raw.parse::<u64>() {
            Ok(value) => EvidenceValue::Unsigned(value),
            Err(_) if executor.policy().captured_headers().contains(header) => {
                EvidenceValue::Text(raw)
            },
            Err(_) => continue,
        };
        evidence.push(executor.observation(
            decision,
            EvidenceKind::RateLimit,
            predicate.into(),
            value,
            &format!("rate-limit-header:{header}"),
        )?);
    }
    Ok(())
}

/// Projects one already-collected fixed GraphQL POST into the same bounded HTTP
/// and defense evidence vocabulary used by the standard executor.
///
/// The caller supplies only its closed GraphQL classification observations;
/// raw response bytes and headers remain inside this module. The decision
/// runner still validates and atomically commits the complete returned batch.
#[cfg(feature = "graphql-review")]
pub(crate) fn project_graphql_transport_response(
    executor_id: &str,
    decision: &DecisionExecutionRequest,
    requested_url: &Url,
    response: CollectedHttpResponse,
    reliability: ConfidenceScore,
    mut graphql_observations: Vec<Evidence>,
    graphql_classification: Evidence,
) -> Result<Vec<Evidence>, HttpEvidenceError> {
    if response.final_url != *requested_url {
        return Err(HttpEvidenceError::AssessmentObserverInvariant {
            invariant: "GraphQL transport changed the exact requested target",
        });
    }
    let source = |method: &str| {
        EvidenceSource::new(executor_id, method)
            .and_then(|source| source.with_correlation_id(decision.case().id()))
    };
    let observation = |kind, predicate, value, method: &str| {
        Ok::<_, HttpEvidenceError>(Evidence::new(
            decision.case().subject().clone(),
            kind,
            predicate,
            value,
            source(method)?,
            reliability,
        ))
    };
    let media_type = normalized_media_type(&response.headers);
    let rate_limit_advertised = [
        "retry-after",
        "ratelimit-limit",
        "ratelimit-remaining",
        "ratelimit-reset",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
    ]
    .into_iter()
    .any(|name| response.headers.contains_key(name));
    let mut evidence = vec![
        observation(
            EvidenceKind::Http,
            HttpEvidencePredicate::REQUEST_METHOD.into(),
            EvidenceValue::Text("POST".to_owned()),
            "request-method",
        )?,
        observation(
            EvidenceKind::Http,
            HttpEvidencePredicate::REQUEST_URL.into(),
            EvidenceValue::Text(requested_url.to_string()),
            "request-url",
        )?,
        observation(
            EvidenceKind::Http,
            HttpEvidencePredicate::RESPONSE_STATUS.into(),
            EvidenceValue::Unsigned(u64::from(response.status.as_u16())),
            "response-status",
        )?,
        observation(
            EvidenceKind::Http,
            HttpEvidencePredicate::RESPONSE_FINAL_URL.into(),
            EvidenceValue::Text(response.final_url.to_string()),
            "response-final-url",
        )?,
        observation(
            EvidenceKind::Http,
            HttpEvidencePredicate::RESPONSE_VERSION.into(),
            EvidenceValue::Text(response.version.clone()),
            "response-version",
        )?,
        observation(
            EvidenceKind::Timing,
            HttpEvidencePredicate::TIMING_TTFB_MS.into(),
            EvidenceValue::Unsigned(response.ttfb_ms),
            "time-to-first-byte",
        )?,
        observation(
            EvidenceKind::Timing,
            HttpEvidencePredicate::TIMING_TOTAL_MS.into(),
            EvidenceValue::Unsigned(response.total_ms),
            "total-response-time",
        )?,
        observation(
            EvidenceKind::Content,
            HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED.into(),
            EvidenceValue::Unsigned(u64::try_from(response.body.len()).unwrap_or(u64::MAX)),
            "response-body-size",
        )?,
        observation(
            EvidenceKind::Content,
            HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED.into(),
            EvidenceValue::Boolean(response.body_truncated),
            "response-body-truncation",
        )?,
        observation(
            EvidenceKind::Content,
            HttpEvidencePredicate::RESPONSE_BODY_SHA256.into(),
            EvidenceValue::Text(format!("{:x}", Sha256::digest(&response.body))),
            "response-body-sha256",
        )?,
        observation(
            EvidenceKind::RateLimit,
            HttpEvidencePredicate::RATE_LIMIT_DETECTED.into(),
            EvidenceValue::Boolean(response.status == StatusCode::TOO_MANY_REQUESTS),
            "rate-limit-status",
        )?,
        observation(
            EvidenceKind::RateLimit,
            HttpEvidencePredicate::RATE_LIMIT_ADVERTISED.into(),
            EvidenceValue::Boolean(rate_limit_advertised),
            "rate-limit-headers",
        )?,
    ];
    if let Some(media_type) = media_type {
        evidence.push(observation(
            EvidenceKind::Http,
            HttpEvidencePredicate::RESPONSE_MEDIA_TYPE.into(),
            EvidenceValue::Text(media_type.clone()),
            "response-media-type",
        )?);
        evidence.push(observation(
            EvidenceKind::Http,
            HttpEvidencePredicate::RESPONSE_MEDIA_TYPE_JSON_COMPATIBLE.into(),
            EvidenceValue::Boolean(json_compatible_media_type(&media_type)),
            "response-media-type-json-compatibility",
        )?);
    }
    let classification_predicate =
        KnowledgePredicate::new("web.graphql.transport", "classification")?;
    if graphql_observations
        .iter()
        .chain(std::iter::once(&graphql_classification))
        .any(|item| {
            item.subject() != decision.case().subject()
                || item.source().component() != executor_id
                || item.source().correlation_id() != Some(decision.case().id())
                || item.reliability() != reliability
                || !item.origin().is_direct()
        })
        || graphql_classification.predicate() != &classification_predicate
        || graphql_observations
            .iter()
            .any(|item| item.predicate() == &classification_predicate)
    {
        return Err(HttpEvidenceError::AssessmentObserverInvariant {
            invariant: "GraphQL observations must preserve executor provenance",
        });
    }
    let graphql_parent_ids = graphql_observations
        .iter()
        .map(|item| item.id().clone())
        .collect::<Vec<_>>();
    evidence.append(&mut graphql_observations);

    let classification_http_parents = [
        HttpEvidencePredicate::REQUEST_URL,
        HttpEvidencePredicate::RESPONSE_STATUS,
        HttpEvidencePredicate::RESPONSE_FINAL_URL,
        HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED,
        HttpEvidencePredicate::RESPONSE_BODY_SHA256,
    ];
    let mut classification_parents = graphql_parent_ids;
    for descriptor in classification_http_parents {
        let predicate = descriptor.into_knowledge();
        let mut matching = evidence
            .iter()
            .filter(|item| item.predicate() == &predicate);
        let Some(parent) = matching.next() else {
            return Err(HttpEvidenceError::AssessmentObserverInvariant {
                invariant: "GraphQL classification is missing transport provenance",
            });
        };
        if matching.next().is_some() {
            return Err(HttpEvidenceError::AssessmentObserverInvariant {
                invariant: "GraphQL classification transport provenance is ambiguous",
            });
        }
        classification_parents.push(parent.id().clone());
    }
    let classification_derivation = EvidenceDerivation::new(
        classification_parents,
        DerivationAlgorithm::new("web.graphql.transport-classification", 1)?,
    )?;
    evidence.push(graphql_classification.derived_from(classification_derivation));

    // POST expects a response body, so its bounded defense body semantics are
    // identical to the GET branch; no request-method behavior is inferred.
    let signal = bounded_assessment_defense_signal(
        response.status.as_u16(),
        HttpProbeMethod::Get,
        &response.headers,
        response.body_complete,
        &response.body,
    );
    let parent_predicates = [
        HttpEvidencePredicate::REQUEST_METHOD,
        HttpEvidencePredicate::REQUEST_URL,
        HttpEvidencePredicate::RESPONSE_STATUS,
        HttpEvidencePredicate::RESPONSE_FINAL_URL,
        HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED,
        HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED,
        HttpEvidencePredicate::RESPONSE_BODY_SHA256,
        HttpEvidencePredicate::RATE_LIMIT_DETECTED,
        HttpEvidencePredicate::RATE_LIMIT_ADVERTISED,
    ];
    let mut parents = Vec::with_capacity(parent_predicates.len());
    for descriptor in parent_predicates {
        let predicate = descriptor.into_knowledge();
        let mut matching = evidence
            .iter()
            .filter(|item| item.predicate() == &predicate);
        let Some(parent) = matching.next() else {
            return Err(HttpEvidenceError::AssessmentDefenseProjectionInvariant);
        };
        if matching.next().is_some() {
            return Err(HttpEvidenceError::AssessmentDefenseProjectionInvariant);
        }
        parents.push(parent.id().clone());
    }
    evidence.extend(project_assessment_defense_signal(
        &signal,
        AssessmentDefenseProjectionContext {
            subject: decision.case().subject(),
            case_id: decision.case().id(),
            executor_id,
            reliability,
            parents,
        },
    )?);
    Ok(evidence)
}

/// Reduces raw transport material to a closed, bounded signal vocabulary.
/// Returned header values are fixed literals; no response value or cookie
/// value is retained, hashed, or exposed to the assessment ledger.
pub(crate) fn bounded_assessment_defense_signal(
    status: u16,
    method: HttpProbeMethod,
    headers: &HeaderMap,
    body_complete: bool,
    body: &[u8],
) -> AssessmentDefenseSignal {
    let mut safe_headers = Vec::<(String, String)>::new();
    let mut input_limit_reached = body.len() > MAX_FINGERPRINT_BODY_SCAN_BYTES;

    for name in [
        "cf-ray",
        "x-amzn-waf-action",
        "x-amzn-requestid",
        "x-iinfo",
        "x-sucuri-id",
        "retry-after",
        "ratelimit-limit",
        "ratelimit-remaining",
        "ratelimit-reset",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
    ] {
        let count = headers
            .get_all(name)
            .iter()
            .take(MAX_ASSESSMENT_DEFENSE_HEADER_OCCURRENCES + 1)
            .count();
        if count > MAX_ASSESSMENT_DEFENSE_HEADER_OCCURRENCES {
            input_limit_reached = true;
        }
        if count > 0 {
            safe_headers.push((name.to_owned(), "present".to_owned()));
        }
    }

    let server_values: Vec<_> = headers
        .get_all("server")
        .iter()
        .take(MAX_ASSESSMENT_DEFENSE_HEADER_OCCURRENCES + 1)
        .collect();
    if server_values.len() > MAX_ASSESSMENT_DEFENSE_HEADER_OCCURRENCES {
        input_limit_reached = true;
    }
    for value in server_values
        .into_iter()
        .take(MAX_ASSESSMENT_DEFENSE_HEADER_OCCURRENCES)
    {
        let bytes = value.as_bytes();
        if bytes.len() > MAX_ASSESSMENT_DEFENSE_HEADER_VALUE_BYTES {
            input_limit_reached = true;
        }
        let prefix = &bytes[..bytes.len().min(MAX_ASSESSMENT_DEFENSE_HEADER_VALUE_BYTES)];
        for needle in ["cloudflare", "mod_security", "akamaighost"] {
            if ascii_contains_ignore_case(prefix, needle.as_bytes()) {
                safe_headers.push(("server".to_owned(), needle.to_owned()));
            }
        }
    }

    let cookie_values: Vec<_> = headers
        .get_all("set-cookie")
        .iter()
        .take(MAX_ASSESSMENT_DEFENSE_HEADER_OCCURRENCES + 1)
        .collect();
    if cookie_values.len() > MAX_ASSESSMENT_DEFENSE_HEADER_OCCURRENCES {
        input_limit_reached = true;
    }
    for value in cookie_values
        .into_iter()
        .take(MAX_ASSESSMENT_DEFENSE_HEADER_OCCURRENCES)
    {
        let bytes = value.as_bytes();
        let Some(separator) = bytes
            .iter()
            .take(MAX_ASSESSMENT_DEFENSE_COOKIE_NAME_BYTES + 1)
            .position(|byte| *byte == b'=')
        else {
            input_limit_reached = true;
            continue;
        };
        if separator == 0 || separator > MAX_ASSESSMENT_DEFENSE_COOKIE_NAME_BYTES {
            input_limit_reached = true;
            continue;
        }
        let name = &bytes[..separator];
        for recognized in [
            "incap_ses",
            "bigipserver",
            "barra_counter_session",
            "fortiwafsid",
        ] {
            if ascii_starts_with_ignore_case(name, recognized.as_bytes()) {
                safe_headers.push(("set-cookie".to_owned(), recognized.to_owned()));
            }
        }
    }

    safe_headers.sort();
    safe_headers.dedup();
    let safe_header_refs: Vec<_> = safe_headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();

    let (body_text, body_coverage) = if method == HttpProbeMethod::Head || !body_complete {
        ("", AssessmentDefenseBodyCoverage::MetadataOnly)
    } else if body.len() <= MAX_FINGERPRINT_BODY_SCAN_BYTES {
        match std::str::from_utf8(body) {
            Ok(text) => (text, AssessmentDefenseBodyCoverage::CompleteUtf8Prefix),
            Err(_) => {
                input_limit_reached = true;
                ("", AssessmentDefenseBodyCoverage::MetadataOnly)
            },
        }
    } else {
        input_limit_reached = true;
        let prefix = &body[..MAX_FINGERPRINT_BODY_SCAN_BYTES];
        match std::str::from_utf8(prefix) {
            Ok(text) => (text, AssessmentDefenseBodyCoverage::CompleteUtf8Prefix),
            Err(error) if error.error_len().is_none() => {
                let valid = &prefix[..error.valid_up_to()];
                (
                    std::str::from_utf8(valid).unwrap_or(""),
                    AssessmentDefenseBodyCoverage::CompleteUtf8Prefix,
                )
            },
            Err(_) => ("", AssessmentDefenseBodyCoverage::MetadataOnly),
        }
    };

    AssessmentDefenseSignal::new(
        DefenseState::observe(status, &safe_header_refs, body_text),
        body_coverage,
        input_limit_reached,
    )
}

fn ascii_contains_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
    })
}

fn ascii_starts_with_ignore_case(value: &[u8], prefix: &[u8]) -> bool {
    value.len() >= prefix.len()
        && value[..prefix.len()]
            .iter()
            .zip(prefix)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn elapsed_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use termivar_core::{EntityId, EvidenceValue, HypothesisStrength};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    use super::*;
    use crate::{
        DecisionActionOrigin, DecisionExecutionStage, DecisionExecutorRegistry,
        DecisionLoopCommand, DecisionRunnerAdapter, KnowledgeBase, RuleEngine, RuntimeBudget,
        RuntimeBudgetDimension, StandardWebReasoning, TransportDispatchOutcome, VerificationCase,
    };

    pub(super) struct RejectingCompleteResponseObserver;

    impl CompleteHttpResponseObserver for RejectingCompleteResponseObserver {
        fn observe(
            &self,
            _observation: CompleteHttpResponseObservation<'_>,
        ) -> Result<Vec<Evidence>, HttpEvidenceError> {
            Err(HttpEvidenceError::AssessmentObserverInvariant {
                invariant: "test-observer-rejected",
            })
        }
    }

    #[test]
    fn assessment_defense_metadata_only_never_projects_open() {
        let signal = bounded_assessment_defense_signal(
            200,
            HttpProbeMethod::Head,
            &HeaderMap::new(),
            true,
            b"attention required",
        );
        assert_eq!(
            signal.body_coverage(),
            AssessmentDefenseBodyCoverage::MetadataOnly
        );
        assert_eq!(
            signal.state().posture(),
            crate::defense::DefensePosture::Open
        );
        assert!(!signal.has_positive_metadata_signal());
    }

    #[test]
    fn assessment_defense_reset_only_is_a_positive_rate_signal() {
        let mut headers = HeaderMap::new();
        headers.insert("ratelimit-reset", HeaderValue::from_static("60"));
        let signal =
            bounded_assessment_defense_signal(200, HttpProbeMethod::Get, &headers, true, b"ok");
        assert!(signal.state().has_rate_limit_headers());
        assert!(signal.state().is_rate_limited());
        assert!(signal.has_positive_metadata_signal());
    }

    #[test]
    fn incomplete_large_body_records_the_detector_input_limit() {
        let body = vec![b'a'; MAX_FINGERPRINT_BODY_SCAN_BYTES + 1];
        let signal = bounded_assessment_defense_signal(
            200,
            HttpProbeMethod::Get,
            &HeaderMap::new(),
            false,
            &body,
        );
        assert_eq!(
            signal.body_coverage(),
            AssessmentDefenseBodyCoverage::MetadataOnly
        );
        assert!(signal.input_limit_reached());
        assert!(!signal.has_positive_metadata_signal());
    }

    #[test]
    fn standard_http_executor_keeps_assessment_projection_disabled() {
        let target = Url::parse("https://example.test/").unwrap();
        let policy = HttpEvidencePolicy::for_origin(target).unwrap();
        let requests = HttpRequestBroker::new_unmetered(policy).unwrap();
        let executor = HttpEvidenceExecutor::new_with_request_broker(
            requests,
            Arc::new(SubjectHttpProbeProvider::new(HttpProbeMethod::Get)),
        )
        .unwrap();
        assert!(!executor.assessment_defense_projection);
    }

    fn observed_form_control_names(sample: &str) -> Vec<String> {
        match extract_form_control_names(sample) {
            FormControlExtraction::Observed(names) => names,
            FormControlExtraction::SampleTooLarge => {
                panic!("test sample unexpectedly exceeded the form-control parse boundary")
            },
        }
    }

    #[test]
    fn form_control_extraction_reads_named_controls_sorted_and_deduplicated() {
        let names = observed_form_control_names(
            "<form>\
             <input name=\"username\">\
             <select name=\"country\"><option>x</option></select>\
             <textarea name=\"comment\"></textarea>\
             <input name=\"username\">\
             <input name='remember'>\
             </form>",
        );
        // Sorted, deduplicated, single- and double-quoted both read.
        assert_eq!(names, ["comment", "country", "remember", "username"]);
    }

    #[test]
    fn form_control_extraction_ignores_unnamed_or_valueless_names() {
        let names = observed_form_control_names(
            "<input type=\"submit\"><input name=\"\"><button name=\"go\">",
        );
        // Nameless/empty-name controls are skipped; button is not a target element.
        assert!(names.is_empty());
    }

    #[test]
    fn form_control_extraction_never_treats_commented_or_scripted_markup_as_controls() {
        let names = observed_form_control_names(
            "<!-- <input name=\"fake_comment\"> -->\
             <script>const x = '<input name=\"fake_script\">';</script>\
             <style>input[name=\"fake_style\"] { color: red; }</style>\
             <input name=\"real\">",
        );
        assert_eq!(names, ["real"]);
    }

    #[test]
    fn form_control_extraction_keeps_textarea_name_but_drops_its_body() {
        let names = observed_form_control_names(
            "<textarea name=\"real\">\n  <input name=\"fake_in_textarea\">\n</textarea>",
        );
        // The textarea's own name is a control; markup inside its body is text.
        assert_eq!(names, ["real"]);
    }

    #[test]
    fn form_control_extraction_records_names_never_values() {
        let names = observed_form_control_names(
            "<input type=\"hidden\" name=\"_token\" value=\"SUPER_SECRET_CSRF\">\
             <input type=\"password\" name=\"password\" value=\"hunter2\">",
        );
        assert_eq!(names, ["_token", "password"]);
        // The captured set must never leak any control value.
        assert!(!names.iter().any(|name| name.contains("SUPER_SECRET_CSRF")));
        assert!(!names.iter().any(|name| name.contains("hunter2")));
    }

    #[test]
    fn form_control_extraction_does_not_confuse_suffix_attributes_with_name() {
        // `data-name` / `formname` are not the `name` attribute and must not leak.
        let names = observed_form_control_names(
            "<input data-name=\"nickname\" formname=\"x\" name=\"real\">",
        );
        assert_eq!(names, ["real"]);
    }

    #[test]
    fn form_control_extraction_respects_attribute_quote_state() {
        // A `name=` sequence inside another attribute's quoted value is text, not
        // a real attribute — the tokenizer tracks quote state so it is never read.
        assert!(observed_form_control_names("<input title=\" name='fake'\">").is_empty());
        assert!(observed_form_control_names("<input title=' name=\"fake\"'>").is_empty());
        assert_eq!(
            observed_form_control_names("<input title=\"ordinary\" name=\"real\">"),
            ["real"]
        );
    }

    #[test]
    fn form_control_extraction_preserves_name_attribute_whitespace() {
        let names = observed_form_control_names(
            "<input name=\" _token \"><input name=\" \"><input name=\"\">",
        );

        // HTML form-control names are attribute values, not space-separated
        // tokens. Preserve non-empty values exactly so a padded convention name
        // cannot be promoted into an exact `_token` observation.
        assert_eq!(names, [" ", " _token "]);
        assert!(!names.iter().any(|name| name == "_token"));
    }

    #[test]
    fn form_control_extraction_rejects_foreign_namespace_lookalikes() {
        let names = observed_form_control_names(
            "<svg><input name=\"svg-input\"></input>\
                   <select name=\"svg-select\"></select>\
                   <textarea name=\"svg-textarea\"></textarea></svg>\
             <math><input name=\"math-input\"></input>\
                    <select name=\"math-select\"></select>\
                    <textarea name=\"math-textarea\"></textarea></math>",
        );

        // SVG/MathML elements can share an HTML control's local name, but they
        // are not HTML form controls and must not manufacture PHP/convention
        // evidence.
        assert_eq!(names, Vec::<String>::new());
    }

    #[test]
    fn form_control_extraction_observes_html_integration_points_only() {
        // HTML integration points return descendants to the HTML namespace.
        // Re-entering SVG makes the nested lookalike foreign again.
        assert_eq!(
            observed_form_control_names(
                "<svg><foreignObject><input name=\"foreign-object\">\
                      <svg><input name=\"nested-svg\"></svg>\
                    </foreignObject></svg>\
                 <math><mtext><select name=\"math-text\"></select></mtext>\
                   <annotation-xml encoding=\"text/html\">\
                     <textarea name=\"annotation\"></textarea>\
                   </annotation-xml></math>"
            ),
            ["annotation", "foreign-object", "math-text"]
        );
    }

    #[test]
    fn form_control_extraction_is_stack_safe_near_sixty_four_kibibytes() {
        const DEPTH: usize = 5_900;
        let mut html = String::with_capacity(DEPTH * 11 + 32);
        for _ in 0..DEPTH {
            html.push_str("<div>");
        }
        html.push_str("<input name=\"deep\">");
        for _ in 0..DEPTH {
            html.push_str("</div>");
        }

        assert!((63 * 1024..=64 * 1024).contains(&html.len()));
        assert_eq!(observed_form_control_names(&html), ["deep"]);
    }

    #[test]
    fn form_control_extraction_is_stack_safe_at_compact_nesting_limit() {
        use super::form_controls::MAX_FORM_CONTROL_PARSE_BYTES;

        let control = "<input name=\"compact-deep\">";
        let depth = (MAX_FORM_CONTROL_PARSE_BYTES - control.len()) / 3;
        let mut html = "<q>".repeat(depth);
        html.push_str(control);
        html.push_str(&"x".repeat(MAX_FORM_CONTROL_PARSE_BYTES - html.len()));

        assert_eq!(html.len(), MAX_FORM_CONTROL_PARSE_BYTES);
        assert_eq!(observed_form_control_names(&html), ["compact-deep"]);
    }

    #[test]
    fn form_control_extraction_accepts_exact_limit_and_rejects_limit_plus_one() {
        use super::form_controls::MAX_FORM_CONTROL_PARSE_BYTES;

        assert_eq!(MAX_FORM_CONTROL_PARSE_BYTES, 64 * 1024);
        let mut exact = "<input name=\"boundary\">".to_owned();
        exact.push_str(&"x".repeat(MAX_FORM_CONTROL_PARSE_BYTES - exact.len()));
        assert_eq!(exact.len(), MAX_FORM_CONTROL_PARSE_BYTES);
        assert_eq!(
            extract_form_control_names(&exact),
            FormControlExtraction::Observed(vec!["boundary".to_owned()])
        );

        exact.push('x');
        assert_eq!(exact.len(), MAX_FORM_CONTROL_PARSE_BYTES + 1);
        assert_eq!(
            extract_form_control_names(&exact),
            FormControlExtraction::SampleTooLarge,
            "an over-limit sample must not be partially parsed"
        );
    }

    struct CountedServer {
        target: Url,
        requests: Arc<AtomicUsize>,
        task: tokio::task::JoinHandle<()>,
    }

    impl CountedServer {
        fn target(&self) -> Url {
            self.target.clone()
        }

        fn requests(&self) -> usize {
            self.requests.load(Ordering::SeqCst)
        }
    }

    impl Drop for CountedServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    struct MultiRequestExecutor {
        requests: HttpRequestBroker,
        target: Url,
    }

    struct BufferedRequestExecutor {
        requests: HttpRequestBroker,
        target: Url,
        body: Vec<u8>,
    }

    #[async_trait]
    impl DecisionActionExecutor for MultiRequestExecutor {
        fn id(&self) -> &str {
            HTTP_EVIDENCE_EXECUTOR_ID
        }

        async fn execute(
            &self,
            request: &DecisionExecutionRequest,
        ) -> Result<Vec<Evidence>, DecisionExecutorError> {
            let probe = HttpProbe::new(self.target.clone(), HttpProbeMethod::Get)
                .map_err(into_decision_executor_error)?;
            self.requests
                .collect(request, &probe)
                .await
                .map_err(HttpRequestBrokerError::into_decision_executor_error)?;
            self.requests
                .collect(request, &probe)
                .await
                .map_err(HttpRequestBrokerError::into_decision_executor_error)?;
            Ok(Vec::new())
        }
    }

    #[async_trait]
    impl DecisionActionExecutor for BufferedRequestExecutor {
        fn id(&self) -> &str {
            HTTP_EVIDENCE_EXECUTOR_ID
        }

        async fn execute(
            &self,
            request: &DecisionExecutionRequest,
        ) -> Result<Vec<Evidence>, DecisionExecutorError> {
            let mut buffered = reqwest::Request::new(reqwest::Method::POST, self.target.clone());
            *buffered.body_mut() = Some(reqwest::Body::from(self.body.clone()));
            self.requests
                .collect_buffered_request_for_test(request, buffered)
                .await
                .map_err(HttpRequestBrokerError::into_decision_executor_error)?;
            Ok(Vec::new())
        }
    }

    async fn serve_counted(response: &'static [u8]) -> CountedServer {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let counted = requests.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0_u8; 2048];
                let _ = stream.read(&mut request).await.unwrap();
                counted.fetch_add(1, Ordering::SeqCst);
                stream.write_all(response).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        CountedServer {
            target: Url::parse(&format!("http://{address}/probe")).unwrap(),
            requests,
            task,
        }
    }

    async fn serve_empty_response_then_watch_for_retry() -> CountedServer {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let counted = requests.clone();
        let task = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 2048];
            let _ = first.read(&mut request).await.unwrap();
            counted.fetch_add(1, Ordering::SeqCst);
            drop(first);

            if let Ok(Ok((mut retry, _))) =
                tokio::time::timeout(Duration::from_millis(250), listener.accept()).await
            {
                let _ = retry.read(&mut request).await.unwrap();
                counted.fetch_add(1, Ordering::SeqCst);
            }
        });
        CountedServer {
            target: Url::parse(&format!("http://{address}/probe")).unwrap(),
            requests,
            task,
        }
    }

    async fn serve_once(response: &'static [u8]) -> Url {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request).await.unwrap();
            stream.write_all(response).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        Url::parse(&format!("http://{address}/probe")).unwrap()
    }

    async fn serve_partial_then_stall(response_prefix: &'static [u8]) -> Url {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request).await.unwrap();
            stream.write_all(response_prefix).await.unwrap();
            stream.flush().await.unwrap();
            std::future::pending::<()>().await;
        });
        Url::parse(&format!("http://{address}/probe")).unwrap()
    }

    async fn serve_split_body_after_release() -> (Url, oneshot::Receiver<()>, oneshot::Sender<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (first_sent, first_received) = oneshot::channel();
        let (release, released) = oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 8\r\nConnection: close\r\n\r\n0123",
                )
                .await
                .unwrap();
            stream.flush().await.unwrap();
            let _ = first_sent.send(());
            let _ = released.await;
            let _ = stream.write_all(b"4567").await;
            let _ = stream.shutdown().await;
        });
        (
            Url::parse(&format!("http://{address}/probe")).unwrap(),
            first_received,
            release,
        )
    }

    fn command(url: &Url) -> DecisionLoopCommand {
        DecisionLoopCommand::ExecuteAction {
            case: VerificationCase::new(
                "case:http:1",
                EntityId::new(format!("endpoint:{url}")).unwrap(),
                "http.probe",
                "hypothesis:http",
            )
            .unwrap(),
            executor: Some(HTTP_EVIDENCE_EXECUTOR_ID.to_owned()),
            origin: DecisionActionOrigin::Planned,
            delay_ms: None,
        }
    }

    /// Serves a canned response for `connections` requests and captures each
    /// raw request head so a test can assert the exact bytes that were sent.
    async fn serve_capturing(
        response: &'static [u8],
        connections: usize,
    ) -> (Url, Arc<std::sync::Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = captured.clone();
        tokio::spawn(async move {
            for _ in 0..connections {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buffer = [0_u8; 2048];
                let read = stream.read(&mut buffer).await.unwrap();
                sink.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buffer[..read]).into_owned());
                stream.write_all(response).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        (
            Url::parse(&format!("http://{address}/probe")).unwrap(),
            captured,
        )
    }

    #[test]
    fn query_payload_binding_materializes_only_one_active_parameter() {
        let reference = PayloadStrategyRef::new(
            crate::payload_strategies::EXTERNAL_URL_QUERY_PAIR_ID,
            crate::payload_strategies::EXTERNAL_URL_QUERY_PAIR_REVISION,
        )
        .unwrap();
        let strategies = crate::standard_payload_strategies().unwrap();
        let limits = PayloadStrategyLimits::default();
        let candidate = "https://case-07.review.invalid/landing?source=venom";
        let seed = PayloadSeed::new(candidate.as_bytes().to_vec(), limits).unwrap();
        let binding =
            HttpQueryPayloadBinding::new(strategies, reference.clone(), seed, limits, "next")
                .unwrap();
        assert_eq!(binding.reference(), &reference);
        assert_eq!(binding.parameter(), "next");

        let target = Url::parse("https://authorized.example.test/review").unwrap();
        let control = binding
            .apply_to_probe(
                DecisionExecutionStage::Passive,
                HttpProbe::new(target.clone(), HttpProbeMethod::Get).unwrap(),
            )
            .unwrap();
        assert_eq!(control.url(), &target);
        assert!(control.url().query().is_none());

        let active = binding
            .apply_to_probe(
                DecisionExecutionStage::Active,
                HttpProbe::new(target.clone(), HttpProbeMethod::Get).unwrap(),
            )
            .unwrap();
        assert_eq!(active.url().origin(), target.origin());
        assert_eq!(active.url().path(), target.path());
        assert_eq!(active.method(), HttpProbeMethod::Get);
        assert!(active.headers().is_empty());
        assert_eq!(
            active.url().query_pairs().collect::<Vec<_>>(),
            [("next".into(), candidate.into())]
        );
    }

    #[test]
    fn query_payload_binding_rejects_ambiguous_or_invalid_base_state() {
        let reference = PayloadStrategyRef::new(
            crate::payload_strategies::EXTERNAL_URL_QUERY_PAIR_ID,
            crate::payload_strategies::EXTERNAL_URL_QUERY_PAIR_REVISION,
        )
        .unwrap();
        let limits = PayloadStrategyLimits::default();
        let seed = PayloadSeed::new(b"https://case.review.invalid/".to_vec(), limits).unwrap();
        for invalid in ["", "has space", "unsafe&name", "x=y"] {
            assert!(matches!(
                HttpQueryPayloadBinding::new(
                    crate::standard_payload_strategies().unwrap(),
                    reference.clone(),
                    seed.clone(),
                    limits,
                    invalid,
                ),
                Err(HttpEvidenceError::InvalidQueryPayloadParameter)
            ));
        }
        let oversized = "x".repeat(MAX_HTTP_QUERY_PAYLOAD_PARAMETER_BYTES + 1);
        assert!(matches!(
            HttpQueryPayloadBinding::new(
                crate::standard_payload_strategies().unwrap(),
                reference.clone(),
                seed.clone(),
                limits,
                oversized,
            ),
            Err(HttpEvidenceError::InvalidQueryPayloadParameter)
        ));

        let binding = HttpQueryPayloadBinding::new(
            crate::standard_payload_strategies().unwrap(),
            reference,
            seed,
            limits,
            "next",
        )
        .unwrap();
        let existing = HttpProbe::new(
            Url::parse("https://authorized.example.test/review?kept=value").unwrap(),
            HttpProbeMethod::Get,
        )
        .unwrap();
        assert!(matches!(
            binding.apply_to_probe(DecisionExecutionStage::Passive, existing),
            Err(HttpEvidenceError::QueryPayloadRequiresQueryFreeProbe)
        ));
    }

    #[tokio::test]
    async fn strategy_binding_derives_and_dispatches_control_then_candidate_headers() {
        let (url, captured) = serve_capturing(
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            2,
        )
        .await;

        let reference = PayloadStrategyRef::new(
            crate::HTTP_HEADER_CONTROL_PAIR_ID,
            crate::HTTP_HEADER_CONTROL_PAIR_REVISION,
        )
        .unwrap();
        let strategies = crate::standard_payload_strategies().unwrap();
        let limits = PayloadStrategyLimits::default();
        let seed = PayloadSeed::new(b"application/json".to_vec(), limits).unwrap();
        let binding = HttpHeaderPayloadBinding::new(
            strategies,
            reference.clone(),
            seed,
            limits,
            crate::HTTP_HEADER_CONTROL_PAIR_HEADER_NAME,
        )
        .unwrap();

        let probe_url = url.clone();
        let provider: Arc<dyn HttpProbeProvider> =
            Arc::new(move |_request: &DecisionExecutionRequest| {
                HttpProbe::new(probe_url.clone(), HttpProbeMethod::Get)
            });
        let policy = HttpEvidencePolicy::new([url.clone()], Duration::from_secs(2), 1024).unwrap();
        let executor = HttpEvidenceExecutor::new(policy, provider)
            .unwrap()
            .with_payload_binding(binding);
        assert!(executor.supports_payload_strategy(&reference));
        assert!(!executor
            .supports_payload_strategy(&PayloadStrategyRef::new("other.strategy", 1).unwrap()));
        assert_eq!(executor.payload_strategy_reference(), Some(&reference));

        let mut registry = DecisionExecutorRegistry::new();
        registry.register(Arc::new(executor)).unwrap();
        registry
            .route_action(
                DecisionExecutionStage::Active,
                "http.probe",
                HTTP_EVIDENCE_EXECUTOR_ID,
            )
            .unwrap();
        let adapter = DecisionRunnerAdapter::new(registry);
        let knowledge = KnowledgeBase::new();

        let case = VerificationCase::new(
            "case:strategy:1",
            EntityId::new(format!("endpoint:{url}")).unwrap(),
            "http.probe",
            "hypothesis:http",
        )
        .unwrap()
        .with_payload_strategy(Some(reference.clone()));

        // Passive turn derives the seed-independent Control artifact.
        let passive = DecisionLoopCommand::ExecuteAction {
            case: case.clone(),
            executor: Some(HTTP_EVIDENCE_EXECUTOR_ID.to_owned()),
            origin: DecisionActionOrigin::Planned,
            delay_ms: None,
        };
        adapter.execute_command(&passive, &knowledge).await.unwrap();

        // Active verification turn derives the Candidate artifact for the pair.
        let active = DecisionLoopCommand::CollectActiveEvidence { case };
        adapter.execute_command(&active, &knowledge).await.unwrap();

        let requests = captured.lock().unwrap().clone();
        assert_eq!(
            requests.len(),
            2,
            "expected one control and one candidate dispatch"
        );
        let control = requests[0].to_ascii_lowercase();
        let candidate = requests[1].to_ascii_lowercase();
        assert!(
            control.contains("accept: */*\r\n"),
            "control leg must send the baseline header, got: {}",
            requests[0]
        );
        assert!(
            candidate.contains("accept: */*, application/json\r\n"),
            "candidate leg must send the seed-derived variation, got: {}",
            requests[1]
        );
    }

    #[tokio::test]
    async fn metered_strategy_dispatch_charges_control_and_candidate_requests() {
        let (url, captured) = serve_capturing(
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            2,
        )
        .await;

        let reference = PayloadStrategyRef::new(
            crate::HTTP_HEADER_CONTROL_PAIR_ID,
            crate::HTTP_HEADER_CONTROL_PAIR_REVISION,
        )
        .unwrap();
        let limits = PayloadStrategyLimits::default();
        let binding = HttpHeaderPayloadBinding::new(
            crate::standard_payload_strategies().unwrap(),
            reference.clone(),
            PayloadSeed::new(b"application/json".to_vec(), limits).unwrap(),
            limits,
            crate::HTTP_HEADER_CONTROL_PAIR_HEADER_NAME,
        )
        .unwrap();

        let probe_url = url.clone();
        let provider: Arc<dyn HttpProbeProvider> =
            Arc::new(move |_request: &DecisionExecutionRequest| {
                HttpProbe::new(probe_url.clone(), HttpProbeMethod::Get)
            });
        let policy = HttpEvidencePolicy::new([url.clone()], Duration::from_secs(2), 1024).unwrap();
        let accounting = RequestAccountingBroker::new(RuntimeBudget::default());
        let executor =
            HttpEvidenceExecutor::new_with_accounting(policy, provider, accounting.clone())
                .unwrap()
                .with_payload_binding(binding);

        let mut registry = DecisionExecutorRegistry::new();
        registry.register(Arc::new(executor)).unwrap();
        registry
            .route_action(
                DecisionExecutionStage::Active,
                "http.probe",
                HTTP_EVIDENCE_EXECUTOR_ID,
            )
            .unwrap();
        let adapter = DecisionRunnerAdapter::new(registry);
        let knowledge = KnowledgeBase::new();

        let case = VerificationCase::new(
            "case:metered:1",
            EntityId::new(format!("endpoint:{url}")).unwrap(),
            "http.probe",
            "hypothesis:http",
        )
        .unwrap()
        .with_payload_strategy(Some(reference));

        adapter
            .execute_command(
                &DecisionLoopCommand::ExecuteAction {
                    case: case.clone(),
                    executor: Some(HTTP_EVIDENCE_EXECUTOR_ID.to_owned()),
                    origin: DecisionActionOrigin::Planned,
                    delay_ms: None,
                },
                &knowledge,
            )
            .await
            .unwrap();
        adapter
            .execute_command(
                &DecisionLoopCommand::CollectActiveEvidence { case },
                &knowledge,
            )
            .await
            .unwrap();

        // Both the derived control and candidate dispatches are charged through
        // the host-owned accounting broker.
        assert_eq!(accounting.snapshot().total_requests(), 2);
        assert_eq!(captured.lock().unwrap().len(), 2);
        assert!(!accounting.dispatch_audit().is_empty());
    }

    #[tokio::test]
    async fn authorization_context_pair_omits_control_header_and_sends_candidate_credential() {
        let (url, captured) = serve_capturing(
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            2,
        )
        .await;

        let reference = PayloadStrategyRef::new(
            crate::API_AUTHORIZATION_CONTEXT_PAIR_ID,
            crate::API_AUTHORIZATION_CONTEXT_PAIR_REVISION,
        )
        .unwrap();
        let limits = PayloadStrategyLimits::default();
        let binding = HttpHeaderPayloadBinding::new(
            crate::standard_payload_strategies().unwrap(),
            reference.clone(),
            PayloadSeed::new(b"Bearer test-token".to_vec(), limits).unwrap(),
            limits,
            crate::API_AUTHORIZATION_CONTEXT_PAIR_HEADER_NAME,
        )
        .unwrap();

        let probe_url = url.clone();
        let provider: Arc<dyn HttpProbeProvider> =
            Arc::new(move |_request: &DecisionExecutionRequest| {
                HttpProbe::new(probe_url.clone(), HttpProbeMethod::Get)
            });
        let policy = HttpEvidencePolicy::new([url.clone()], Duration::from_secs(2), 1024).unwrap();
        let executor = HttpEvidenceExecutor::new(policy, provider)
            .unwrap()
            .with_payload_binding(binding);

        let mut registry = DecisionExecutorRegistry::new();
        registry.register(Arc::new(executor)).unwrap();
        registry
            .route_action(
                DecisionExecutionStage::Active,
                "http.probe",
                HTTP_EVIDENCE_EXECUTOR_ID,
            )
            .unwrap();
        let adapter = DecisionRunnerAdapter::new(registry);
        let knowledge = KnowledgeBase::new();

        let case = VerificationCase::new(
            "case:authz:1",
            EntityId::new(format!("endpoint:{url}")).unwrap(),
            "http.probe",
            "hypothesis:http",
        )
        .unwrap()
        .with_payload_strategy(Some(reference));

        // Passive turn derives the empty Control artifact: anonymous context.
        adapter
            .execute_command(
                &DecisionLoopCommand::ExecuteAction {
                    case: case.clone(),
                    executor: Some(HTTP_EVIDENCE_EXECUTOR_ID.to_owned()),
                    origin: DecisionActionOrigin::Planned,
                    delay_ms: None,
                },
                &knowledge,
            )
            .await
            .unwrap();

        // Active turn derives the Candidate credential: authorized context.
        adapter
            .execute_command(
                &DecisionLoopCommand::CollectActiveEvidence { case },
                &knowledge,
            )
            .await
            .unwrap();

        let requests = captured.lock().unwrap().clone();
        assert_eq!(requests.len(), 2);
        let control = requests[0].to_ascii_lowercase();
        let candidate = requests[1].to_ascii_lowercase();
        assert!(
            !control.contains("authorization:"),
            "control leg must be anonymous (no authorization header), got: {}",
            requests[0]
        );
        assert!(
            candidate.contains("authorization: bearer test-token\r\n"),
            "candidate leg must send the authorized credential, got: {}",
            requests[1]
        );
    }

    fn adapter(
        url: &Url,
        capture: HttpBodyCapture,
        max_body_bytes: usize,
    ) -> DecisionRunnerAdapter {
        let probe_url = url.clone();
        let provider: Arc<dyn HttpProbeProvider> =
            Arc::new(move |_request: &DecisionExecutionRequest| {
                HttpProbe::new(probe_url.clone(), HttpProbeMethod::Get)
            });
        let policy = HttpEvidencePolicy::new([url.clone()], Duration::from_secs(2), max_body_bytes)
            .unwrap()
            .with_body_capture(capture)
            .unwrap();
        let executor = HttpEvidenceExecutor::new(policy, provider).unwrap();
        let mut registry = DecisionExecutorRegistry::new();
        registry.register(Arc::new(executor)).unwrap();
        DecisionRunnerAdapter::new(registry)
    }

    fn metered_adapter(
        url: &Url,
        policy: HttpEvidencePolicy,
        budget: RuntimeBudget,
    ) -> (DecisionRunnerAdapter, RequestAccountingBroker) {
        let probe_url = url.clone();
        let provider: Arc<dyn HttpProbeProvider> =
            Arc::new(move |_request: &DecisionExecutionRequest| {
                HttpProbe::new(probe_url.clone(), HttpProbeMethod::Get)
            });
        let accounting = RequestAccountingBroker::new(budget);
        let executor =
            HttpEvidenceExecutor::new_with_accounting(policy, provider, accounting.clone())
                .unwrap();
        let mut registry = DecisionExecutorRegistry::new();
        registry.register(Arc::new(executor)).unwrap();
        (DecisionRunnerAdapter::new(registry), accounting)
    }

    fn buffered_adapter(
        url: &Url,
        budget: RuntimeBudget,
        body: impl Into<Vec<u8>>,
    ) -> (DecisionRunnerAdapter, RequestAccountingBroker) {
        let policy = HttpEvidencePolicy::for_origin(url.clone()).unwrap();
        let accounting = RequestAccountingBroker::new(budget);
        let requests = HttpRequestBroker::new_metered(policy, accounting.clone()).unwrap();
        let mut registry = DecisionExecutorRegistry::new();
        registry
            .register(Arc::new(BufferedRequestExecutor {
                requests,
                target: url.clone(),
                body: body.into(),
            }))
            .unwrap();
        (DecisionRunnerAdapter::new(registry), accounting)
    }

    fn value<P>(evidence: &[Evidence], predicate: P) -> Option<&EvidenceValue>
    where
        P: Into<KnowledgePredicate>,
    {
        let predicate = predicate.into();
        evidence
            .iter()
            .find(|item| item.predicate() == &predicate)
            .map(Evidence::value)
    }

    fn record<P>(evidence: &[Evidence], predicate: P) -> Option<&Evidence>
    where
        P: Into<KnowledgePredicate>,
    {
        let predicate = predicate.into();
        evidence.iter().find(|item| item.predicate() == &predicate)
    }

    /// Serves one `text/html` response with an auto-computed `Content-Length`, so
    /// tests can vary the HTML body without hand-counting bytes.
    async fn serve_html_once(body: impl Into<String>) -> Url {
        serve_body_once("text/html", body).await
    }

    async fn serve_body_once(content_type: &str, body: impl Into<String>) -> Url {
        let body = body.into();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request).await.unwrap();
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        Url::parse(&format!("http://{address}/probe")).unwrap()
    }

    /// A GET executor with form-control capture enabled, under the given body
    /// policy — the exact wiring the php input-discovery route uses.
    fn form_capturing_adapter(url: &Url, capture: HttpBodyCapture) -> DecisionRunnerAdapter {
        form_capturing_adapter_with_limit(url, capture, 65_536)
    }

    fn form_capturing_adapter_with_limit(
        url: &Url,
        capture: HttpBodyCapture,
        max_body_bytes: usize,
    ) -> DecisionRunnerAdapter {
        let probe_url = url.clone();
        let provider: Arc<dyn HttpProbeProvider> =
            Arc::new(move |_request: &DecisionExecutionRequest| {
                HttpProbe::new(probe_url.clone(), HttpProbeMethod::Get)
            });
        let policy = HttpEvidencePolicy::new([url.clone()], Duration::from_secs(2), max_body_bytes)
            .unwrap()
            .with_body_capture(capture)
            .unwrap();
        let executor = HttpEvidenceExecutor::new(policy, provider)
            .unwrap()
            .with_form_control_capture();
        let mut registry = DecisionExecutorRegistry::new();
        registry.register(Arc::new(executor)).unwrap();
        DecisionRunnerAdapter::new(registry)
    }

    #[tokio::test]
    async fn form_control_capture_is_suppressed_under_metadata_only_policy() {
        let url = serve_html_once("<form><input name=\"username\"></form>").await;
        let adapter = form_capturing_adapter(&url, HttpBodyCapture::MetadataOnly);
        let knowledge = KnowledgeBase::new();

        let receipt = adapter
            .execute_command(&command(&url), &knowledge)
            .await
            .unwrap();
        let evidence = receipt.after_execution().evidence();

        // MetadataOnly authorizes no bounded sample, so no body content — and
        // therefore no derived form-control names — may enter the knowledge base.
        assert!(value(evidence, HttpEvidencePredicate::RESPONSE_BODY_SAMPLE).is_none());
        assert!(value(evidence, HttpEvidencePredicate::RESPONSE_FORM_CONTROL_NAMES).is_none());
    }

    #[tokio::test]
    async fn form_control_capture_requires_explicit_executor_opt_in() {
        let body = "<input name=\"not-authorized\">";
        let url = serve_html_once(body).await;
        let adapter = adapter(&url, HttpBodyCapture::TextSample { max_chars: 1024 }, 1024);
        let knowledge = KnowledgeBase::new();

        let receipt = adapter
            .execute_command(&command(&url), &knowledge)
            .await
            .unwrap();
        let evidence = receipt.after_execution().evidence();

        assert_eq!(
            value(evidence, HttpEvidencePredicate::RESPONSE_BODY_SAMPLE),
            Some(&EvidenceValue::Text(body.to_owned()))
        );
        assert!(value(evidence, HttpEvidencePredicate::RESPONSE_FORM_CONTROL_NAMES).is_none());
    }

    #[tokio::test]
    async fn form_control_capture_requires_exact_html_media_type() {
        let body = "<input name=\"not-html\">";
        let url = serve_body_once("text/plain", body).await;
        let adapter = form_capturing_adapter(&url, HttpBodyCapture::TextSample { max_chars: 8192 });
        let knowledge = KnowledgeBase::new();

        let receipt = adapter
            .execute_command(&command(&url), &knowledge)
            .await
            .unwrap();
        let evidence = receipt.after_execution().evidence();

        assert_eq!(
            value(evidence, HttpEvidencePredicate::RESPONSE_BODY_SAMPLE),
            Some(&EvidenceValue::Text(body.to_owned()))
        );
        assert!(value(evidence, HttpEvidencePredicate::RESPONSE_FORM_CONTROL_NAMES).is_none());
    }

    #[tokio::test]
    async fn form_control_names_predicate_carries_names_only_not_values() {
        let url = serve_html_once(
            "<input type=\"hidden\" name=\"_token\" value=\"SUPER_SECRET_CSRF\">\
             <input type=\"password\" name=\"password\" value=\"hunter2\">",
        )
        .await;
        let adapter = form_capturing_adapter(&url, HttpBodyCapture::TextSample { max_chars: 8192 });
        let knowledge = KnowledgeBase::new();

        let receipt = adapter
            .execute_command(&command(&url), &knowledge)
            .await
            .unwrap();
        let evidence = receipt.after_execution().evidence();

        // The derived form-control-names predicate carries only control names,
        // deduplicated and sorted; control values are never copied into it.
        let names = value(evidence, HttpEvidencePredicate::RESPONSE_FORM_CONTROL_NAMES);
        assert_eq!(
            names,
            Some(&EvidenceValue::TextList(vec![
                "_token".to_owned(),
                "password".to_owned()
            ]))
        );
        if let Some(EvidenceValue::TextList(list)) = names {
            assert!(list.iter().all(|name| name != "SUPER_SECRET_CSRF"));
            assert!(list.iter().all(|name| name != "hunter2"));
        }
        // Note: this asserts the boundary of the DERIVED predicate only. The
        // separate host-authorized RESPONSE_BODY_SAMPLE intentionally contains the
        // original bounded HTML and may include these value= contents; that is not
        // this feature's concern and is deliberately not asserted here.
    }

    #[tokio::test]
    async fn form_control_names_predicate_preserves_exact_attribute_value() {
        let url = serve_html_once("<form><input name=\" _token \"></form>").await;
        let adapter = form_capturing_adapter(&url, HttpBodyCapture::TextSample { max_chars: 8192 });
        let knowledge = KnowledgeBase::new();

        let receipt = adapter
            .execute_command(&command(&url), &knowledge)
            .await
            .unwrap();

        assert_eq!(
            value(
                receipt.after_execution().evidence(),
                HttpEvidencePredicate::RESPONSE_FORM_CONTROL_NAMES
            ),
            Some(&EvidenceValue::TextList(vec![" _token ".to_owned()]))
        );
    }

    #[tokio::test]
    async fn form_control_names_are_derived_from_the_exact_body_sample() {
        let url = serve_html_once("<form><input name=\"_token\"></form>").await;
        let adapter = form_capturing_adapter(&url, HttpBodyCapture::TextSample { max_chars: 8192 });
        let knowledge = KnowledgeBase::new();

        let receipt = adapter
            .execute_command(&command(&url), &knowledge)
            .await
            .unwrap();
        let evidence = receipt.after_execution().evidence();

        let body_sample = record(evidence, HttpEvidencePredicate::RESPONSE_BODY_SAMPLE).unwrap();
        let form_controls =
            record(evidence, HttpEvidencePredicate::RESPONSE_FORM_CONTROL_NAMES).unwrap();

        // The body sample is a direct observation; the form-control record is
        // derived from exactly that record — not merely case-correlated with it.
        assert!(body_sample.origin().is_direct());
        let derivation = form_controls
            .origin()
            .derivation()
            .expect("form-control evidence must carry derivation lineage");
        assert_eq!(derivation.parents(), std::slice::from_ref(body_sample.id()));
        assert_eq!(derivation.algorithm().name(), "http.form-control-names");
        assert_eq!(derivation.algorithm().version(), 1);
        // Same subject and same case as the parent.
        assert_eq!(form_controls.subject(), body_sample.subject());
        assert_eq!(
            form_controls.source().correlation_id(),
            body_sample.source().correlation_id()
        );

        // The committed knowledge base exposes the reverse edge.
        assert!(knowledge
            .derivation_children(body_sample.id())
            .contains(form_controls.id()));
    }

    #[tokio::test]
    async fn form_control_capture_rejects_foreign_namespace_lookalikes() {
        let body = "<svg><input name=\"_token\"></input></svg>\
                    <math><select name=\"_method\"></select></math>";
        let url = serve_html_once(body).await;
        let adapter = form_capturing_adapter(&url, HttpBodyCapture::TextSample { max_chars: 8192 });
        let knowledge = KnowledgeBase::new();

        let receipt = adapter
            .execute_command(&command(&url), &knowledge)
            .await
            .unwrap();
        let evidence = receipt.after_execution().evidence();

        assert_eq!(
            value(evidence, HttpEvidencePredicate::RESPONSE_BODY_SAMPLE),
            Some(&EvidenceValue::Text(body.to_owned())),
            "the sample capture path must actually run"
        );
        assert!(
            value(evidence, HttpEvidencePredicate::RESPONSE_FORM_CONTROL_NAMES).is_none(),
            "foreign elements must not produce typed HTML form-control evidence"
        );
    }

    #[tokio::test]
    async fn oversized_form_control_sample_remains_body_evidence_but_is_not_parsed() {
        use super::form_controls::MAX_FORM_CONTROL_PARSE_BYTES;

        let mut body = "<input name=\"must-not-be-partially-observed\">".to_owned();
        body.push_str(&"x".repeat(MAX_FORM_CONTROL_PARSE_BYTES + 1 - body.len()));
        let url = serve_html_once(body.clone()).await;
        let adapter = form_capturing_adapter_with_limit(
            &url,
            HttpBodyCapture::TextSample {
                max_chars: body.len(),
            },
            body.len(),
        );
        let knowledge = KnowledgeBase::new();

        let receipt = adapter
            .execute_command(&command(&url), &knowledge)
            .await
            .unwrap();
        let evidence = receipt.after_execution().evidence();

        assert_eq!(
            value(evidence, HttpEvidencePredicate::RESPONSE_BODY_SAMPLE),
            Some(&EvidenceValue::Text(body))
        );
        assert!(
            value(evidence, HttpEvidencePredicate::RESPONSE_FORM_CONTROL_NAMES).is_none(),
            "an over-limit sample must not be partially parsed"
        );
    }

    #[tokio::test]
    async fn form_control_past_the_sample_boundary_is_not_observed() {
        // The early control is within the 64-char sample; the late one is past it
        // and must not be discovered — the bounded sample never implies a complete
        // set.
        let padding = "x".repeat(80);
        let url = serve_html_once(format!(
            "<input name=\"early\">{padding}<input name=\"late\">"
        ))
        .await;
        let adapter = form_capturing_adapter(&url, HttpBodyCapture::TextSample { max_chars: 64 });
        let knowledge = KnowledgeBase::new();

        let receipt = adapter
            .execute_command(&command(&url), &knowledge)
            .await
            .unwrap();
        let evidence = receipt.after_execution().evidence();

        assert_eq!(
            value(evidence, HttpEvidencePredicate::RESPONSE_FORM_CONTROL_NAMES),
            Some(&EvidenceValue::TextList(vec!["early".to_owned()]))
        );
    }

    #[tokio::test]
    async fn executor_emits_typed_status_headers_body_and_timing() {
        let url = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nServer: test-server\r\nSet-Cookie: secret=value\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}",
        )
        .await;
        let adapter = adapter(&url, HttpBodyCapture::TextSample { max_chars: 64 }, 1024);
        let knowledge = KnowledgeBase::new();

        let receipt = adapter
            .execute_command(&command(&url), &knowledge)
            .await
            .unwrap();
        let evidence = receipt.after_execution().evidence();

        assert_eq!(
            value(evidence, HttpEvidencePredicate::RESPONSE_STATUS),
            Some(&EvidenceValue::Unsigned(200))
        );
        assert_eq!(
            value(evidence, HttpEvidencePredicate::HEADER_CONTENT_TYPE),
            Some(&EvidenceValue::Text("application/json".to_owned()))
        );
        assert_eq!(
            value(evidence, HttpEvidencePredicate::REQUEST_PATH_SEGMENT),
            Some(&EvidenceValue::Text("probe".to_owned()))
        );
        assert_eq!(
            value(evidence, HttpEvidencePredicate::RESPONSE_MEDIA_TYPE),
            Some(&EvidenceValue::Text("application/json".to_owned()))
        );
        assert_eq!(
            value(
                evidence,
                HttpEvidencePredicate::RESPONSE_MEDIA_TYPE_JSON_COMPATIBLE,
            ),
            Some(&EvidenceValue::Boolean(true))
        );
        assert_eq!(
            value(evidence, HttpEvidencePredicate::RESPONSE_BODY_SAMPLE),
            Some(&EvidenceValue::Text("{\"ok\":true}".to_owned()))
        );
        assert_eq!(
            value(
                evidence,
                HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED,
            ),
            Some(&EvidenceValue::Unsigned(11))
        );
        assert!(value(evidence, HttpEvidencePredicate::TIMING_TTFB_MS).is_some());
        assert!(value(evidence, HttpEvidencePredicate::TIMING_TOTAL_MS).is_some());
        assert!(value(
            evidence,
            HttpEvidencePredicate::response_header("set-cookie").unwrap()
        )
        .is_none());
        assert_eq!(
            value(evidence, HttpEvidencePredicate::COOKIE_NAME),
            Some(&EvidenceValue::Text("secret".to_owned()))
        );
        assert!(evidence.iter().all(|item| {
            item.source().component() == HTTP_EVIDENCE_EXECUTOR_ID
                && item.source().correlation_id() == Some("case:http:1")
        }));
    }

    #[tokio::test]
    async fn complete_response_observer_error_commits_none_of_the_atomic_batch() {
        let url = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: DEBUG_COOKIE_NAME_SENTINEL=value\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        )
        .await;
        let probe_url = url.clone();
        let provider: Arc<dyn HttpProbeProvider> =
            Arc::new(move |_request: &DecisionExecutionRequest| {
                HttpProbe::new(probe_url.clone(), HttpProbeMethod::Get)
            });
        let policy = HttpEvidencePolicy::new([url.clone()], Duration::from_secs(2), 1024)
            .unwrap()
            .with_body_capture(HttpBodyCapture::MetadataOnly)
            .unwrap();
        let executor = HttpEvidenceExecutor::new(policy, provider)
            .unwrap()
            .with_complete_response_observer(Arc::new(RejectingCompleteResponseObserver));
        let mut registry = DecisionExecutorRegistry::new();
        registry.register(Arc::new(executor)).unwrap();
        let adapter = DecisionRunnerAdapter::new(registry);
        let knowledge = KnowledgeBase::new();

        let error = adapter
            .execute_command(&command(&url), &knowledge)
            .await
            .unwrap_err();

        assert!(error
            .execution_failure()
            .unwrap()
            .diagnostic()
            .contains("test-observer-rejected"));
        assert_eq!(knowledge.stats().evidence, 0);
        assert!(knowledge
            .evidence_for_predicate(&HttpEvidencePredicate::COOKIE_NAME.into_knowledge())
            .is_empty());
        assert!(!format!("{error:?}").contains("DEBUG_COOKIE_NAME_SENTINEL"));
    }

    #[tokio::test]
    async fn producer_output_feeds_a_method_agnostic_endpoint_entity() {
        // End-to-end production contract: the real HttpEvidenceExecutor output is
        // fed into the EntityExtractor. With the standard SubjectHttpProbeProvider
        // the case subject and probe URL are the same absolute request URL, so the
        // emitted url+method evidence merge into exactly one method-agnostic
        // Endpoint entity. No external network: a loopback response seam is used.
        let url =
            serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
        let adapter = adapter(&url, HttpBodyCapture::MetadataOnly, 1024);
        let knowledge = KnowledgeBase::new();

        let receipt = adapter
            .execute_command(&command(&url), &knowledge)
            .await
            .unwrap();
        let evidence = receipt.after_execution().evidence();

        // The real producer emits an uppercase GET and the probe URL, correlated
        // by the case id.
        assert_eq!(
            value(evidence, HttpEvidencePredicate::REQUEST_METHOD),
            Some(&EvidenceValue::Text("GET".to_owned()))
        );
        assert_eq!(
            value(evidence, HttpEvidencePredicate::REQUEST_URL),
            Some(&EvidenceValue::Text(url.to_string()))
        );
        let method_evidence = evidence
            .iter()
            .find(|item| item.predicate() == &HttpEvidencePredicate::REQUEST_METHOD.into())
            .expect("producer must emit a request method");
        assert_eq!(method_evidence.kind(), &EvidenceKind::Http);
        assert_eq!(
            method_evidence.source().component(),
            HTTP_EVIDENCE_EXECUTOR_ID
        );
        assert_eq!(
            method_evidence.source().correlation_id(),
            Some("case:http:1")
        );
        // Standard subject convention: subject == the absolute request URL.
        assert_eq!(
            method_evidence.subject().as_str(),
            format!("endpoint:{url}")
        );

        let extraction = crate::EntityExtractor::new().extract_from_evidence(evidence);
        let endpoint = extraction
            .entities
            .iter()
            .find(|entity| entity.entity_type() == crate::SemanticEntityType::Endpoint)
            .expect("producer evidence must yield an endpoint entity");

        // Identity is method-agnostic: the observed method is an attribute only.
        assert_eq!(endpoint.id().as_str(), format!("v1:endpoint:{url}"));
        assert!(!endpoint.id().as_str().contains('#'));
        assert_eq!(
            endpoint.attributes().get("method"),
            Some(&std::collections::BTreeSet::from(["GET".to_owned()]))
        );
        assert_eq!(
            endpoint.attributes().get("url"),
            Some(&std::collections::BTreeSet::from([url.to_string()]))
        );
    }

    #[tokio::test]
    async fn typed_http_evidence_drives_standard_web_reasoning_without_cookie_secrets() {
        let url = serve_once(
            b"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.3\r\nSet-Cookie: laravel_session=secret-one; Path=/; HttpOnly\r\nSet-Cookie: XSRF-TOKEN=secret-two; Path=/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        let adapter = adapter(&url, HttpBodyCapture::MetadataOnly, 1024);
        let knowledge = KnowledgeBase::new();

        adapter
            .execute_command(&command(&url), &knowledge)
            .await
            .unwrap();
        let mut rules = RuleEngine::new();
        StandardWebReasoning::new()
            .unwrap()
            .install(&knowledge, &mut rules)
            .unwrap();
        rules
            .apply(
                &knowledge,
                &EntityId::new(format!("endpoint:{url}")).unwrap(),
            )
            .unwrap();

        let hypotheses =
            knowledge.hypotheses_for_subject(&EntityId::new(format!("endpoint:{url}")).unwrap());
        let laravel = hypotheses
            .iter()
            .find(|item| item.value() == &EvidenceValue::Text("laravel".to_owned()))
            .unwrap();
        assert_eq!(laravel.strength(), HypothesisStrength::Strong);
        assert!(hypotheses
            .iter()
            .any(|item| item.value() == &EvidenceValue::Text("sanctum".to_owned())));
        assert!(knowledge
            .evidence_for_subject(laravel.subject())
            .iter()
            .all(|item| match item.value() {
                EvidenceValue::Text(value) => !value.contains("secret-"),
                _ => true,
            }));
    }

    #[test]
    fn cookie_name_extraction_deduplicates_names_without_retaining_values() {
        let mut headers = HeaderMap::new();
        headers.append(
            "set-cookie",
            HeaderValue::from_static("laravel_session=secret-one; Path=/; HttpOnly"),
        );
        headers.append(
            "set-cookie",
            HeaderValue::from_static("XSRF-TOKEN=secret-two; Path=/"),
        );
        headers.append(
            "set-cookie",
            HeaderValue::from_static("laravel_session=rotated; Path=/"),
        );
        headers.append("set-cookie", HeaderValue::from_static("bad name=value"));

        assert_eq!(
            response_cookie_names(&headers),
            BTreeSet::from(["XSRF-TOKEN".to_owned(), "laravel_session".to_owned()])
        );
    }

    #[test]
    fn media_type_normalization_is_exact_and_fail_closed() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            HeaderValue::from_static("Application/Problem+JSON; charset=UTF-8"),
        );
        let normalized = normalized_media_type(&headers).unwrap();
        assert_eq!(normalized, "application/problem+json");
        assert!(json_compatible_media_type(&normalized));

        headers.insert(
            "content-type",
            HeaderValue::from_static("application/jsonp"),
        );
        let normalized = normalized_media_type(&headers).unwrap();
        assert!(!json_compatible_media_type(&normalized));

        headers.insert(
            "content-type",
            HeaderValue::from_static("application/graphql-response+json"),
        );
        let normalized = normalized_media_type(&headers).unwrap();
        assert!(json_compatible_media_type(&normalized));

        headers.insert(
            "content-type",
            HeaderValue::from_static("application/json/extra"),
        );
        assert!(normalized_media_type(&headers).is_none());

        let mut ambiguous = HeaderMap::new();
        ambiguous.append("content-type", HeaderValue::from_static("application/json"));
        ambiguous.append("content-type", HeaderValue::from_static("text/plain"));
        assert!(normalized_media_type(&ambiguous).is_none());
    }

    #[tokio::test]
    async fn query_text_does_not_become_a_path_segment_signal() {
        let mut url =
            serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
        url.set_query(Some("next=/graphql"));
        let adapter = adapter(&url, HttpBodyCapture::MetadataOnly, 1024);
        let knowledge = KnowledgeBase::new();

        let receipt = adapter
            .execute_command(&command(&url), &knowledge)
            .await
            .unwrap();
        let path_predicate = HttpEvidencePredicate::REQUEST_PATH_SEGMENT.into_knowledge();
        let segments = receipt
            .after_execution()
            .evidence()
            .iter()
            .filter(|item| item.predicate() == &path_predicate)
            .map(Evidence::value)
            .collect::<Vec<_>>();

        assert_eq!(segments, vec![&EvidenceValue::Text("probe".to_owned())]);
    }

    #[tokio::test]
    async fn response_body_is_bounded_and_hashed_as_observed() {
        let url = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 10\r\nConnection: close\r\n\r\n0123456789",
        )
        .await;
        let adapter = adapter(&url, HttpBodyCapture::MetadataOnly, 4);
        let knowledge = KnowledgeBase::new();

        let receipt = adapter
            .execute_command(&command(&url), &knowledge)
            .await
            .unwrap();
        let evidence = receipt.after_execution().evidence();

        assert_eq!(
            value(
                evidence,
                HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED,
            ),
            Some(&EvidenceValue::Unsigned(4))
        );
        assert_eq!(
            value(evidence, HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED),
            Some(&EvidenceValue::Boolean(true))
        );
        assert_eq!(
            value(evidence, HttpEvidencePredicate::RESPONSE_BODY_SHA256),
            Some(&EvidenceValue::Text(format!(
                "{:x}",
                Sha256::digest(b"0123")
            )))
        );
        assert!(value(evidence, HttpEvidencePredicate::RESPONSE_BODY_SAMPLE).is_none());
    }

    #[tokio::test]
    async fn rate_limit_response_emits_status_and_typed_policy_evidence() {
        let url = serve_once(
            b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 7\r\nX-RateLimit-Limit: 100\r\nRateLimit-Remaining: 3\r\nX-RateLimit-Remaining: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        let adapter = adapter(&url, HttpBodyCapture::MetadataOnly, 1024);
        let knowledge = KnowledgeBase::new();

        let receipt = adapter
            .execute_command(&command(&url), &knowledge)
            .await
            .unwrap();
        let evidence = receipt.after_execution().evidence();

        assert_eq!(
            value(evidence, HttpEvidencePredicate::RESPONSE_STATUS),
            Some(&EvidenceValue::Unsigned(429))
        );
        assert_eq!(
            value(evidence, HttpEvidencePredicate::RATE_LIMIT_DETECTED),
            Some(&EvidenceValue::Boolean(true))
        );
        assert_eq!(
            value(evidence, HttpEvidencePredicate::RATE_LIMIT_ADVERTISED),
            Some(&EvidenceValue::Boolean(true))
        );
        assert_eq!(
            value(evidence, HttpEvidencePredicate::RATE_LIMIT_RETRY_AFTER),
            Some(&EvidenceValue::Unsigned(7))
        );
        assert_eq!(
            value(evidence, HttpEvidencePredicate::RATE_LIMIT_REMAINING),
            Some(&EvidenceValue::Unsigned(3))
        );
        assert_eq!(
            value(evidence, HttpEvidencePredicate::RATE_LIMIT_LIMIT),
            Some(&EvidenceValue::Unsigned(100))
        );
    }

    #[tokio::test]
    async fn redirect_is_observed_without_following_the_location() {
        let url = serve_once(
            b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/outside\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        let policy = HttpEvidencePolicy::new([url.clone()], Duration::from_secs(2), 1024)
            .unwrap()
            .with_body_capture(HttpBodyCapture::MetadataOnly)
            .unwrap();
        let (adapter, accounting) = metered_adapter(
            &url,
            policy,
            RuntimeBudget::default().with_max_total_requests(1),
        );
        let knowledge = KnowledgeBase::new();

        let receipt = adapter
            .execute_command(&command(&url), &knowledge)
            .await
            .unwrap();
        let evidence = receipt.after_execution().evidence();

        assert_eq!(
            value(evidence, HttpEvidencePredicate::RESPONSE_STATUS),
            Some(&EvidenceValue::Unsigned(302))
        );
        assert_eq!(
            value(
                evidence,
                HttpEvidencePredicate::response_header("location").unwrap(),
            ),
            Some(&EvidenceValue::Text(
                "http://127.0.0.1:9/outside".to_owned()
            ))
        );
        assert_eq!(
            value(evidence, HttpEvidencePredicate::RESPONSE_FINAL_URL),
            Some(&EvidenceValue::Text(url.to_string()))
        );
        assert_eq!(accounting.snapshot().total_requests(), 1);
        assert_eq!(accounting.snapshot().response_bytes(), 0);
        let audit = accounting.dispatch_audit();
        assert_eq!(audit.omitted_receipt_count(), 0);
        let dispatch = audit.receipts().first().unwrap();
        assert_eq!(dispatch.sequence(), 0);
        assert_eq!(dispatch.action_id(), "http.probe");
        assert_eq!(dispatch.stage(), DecisionExecutionStage::Passive);
        assert_eq!(dispatch.origin(), Some(DecisionActionOrigin::Planned));
        assert_eq!(dispatch.response_bytes(), 0);
        assert_eq!(dispatch.outcome(), TransportDispatchOutcome::Completed);
    }

    #[tokio::test]
    async fn executor_rejects_out_of_scope_provider_target_before_io() {
        let allowed = Url::parse("http://127.0.0.1:1/").unwrap();
        let outside = Url::parse("http://127.0.0.1:2/").unwrap();
        let provider: Arc<dyn HttpProbeProvider> =
            Arc::new(move |_request: &DecisionExecutionRequest| {
                HttpProbe::new(outside.clone(), HttpProbeMethod::Get)
            });
        let policy = HttpEvidencePolicy::for_origin(allowed.clone()).unwrap();
        let accounting = RequestAccountingBroker::new(RuntimeBudget::default());
        let executor =
            HttpEvidenceExecutor::new_with_accounting(policy, provider, accounting.clone())
                .unwrap();
        let mut registry = DecisionExecutorRegistry::new();
        registry.register(Arc::new(executor)).unwrap();
        let adapter = DecisionRunnerAdapter::new(registry);
        let knowledge = KnowledgeBase::new();

        let error = adapter
            .execute_command(&command(&allowed), &knowledge)
            .await
            .unwrap_err();

        let failure = error.execution_failure().unwrap();
        assert_eq!(
            failure.kind(),
            DecisionExecutionFailureKind::BlockedByPolicy
        );
        assert_eq!(failure.executor_id(), HTTP_EVIDENCE_EXECUTOR_ID);
        assert_eq!(failure.action_id(), "http.probe");
        assert!(failure.diagnostic().contains("outside policy"));
        assert_eq!(knowledge.stats().evidence, 0);
        assert_eq!(accounting.snapshot().total_requests(), 0);
        assert_eq!(accounting.snapshot().response_bytes(), 0);
    }

    #[tokio::test]
    async fn provider_timeout_is_classified_without_parsing_its_diagnostic() {
        let allowed = Url::parse("http://127.0.0.1:1/").unwrap();
        let provider: Arc<dyn HttpProbeProvider> =
            Arc::new(|_request: &DecisionExecutionRequest| {
                Err(HttpEvidenceError::Timeout { timeout_ms: 25 })
            });
        let policy = HttpEvidencePolicy::for_origin(allowed.clone()).unwrap();
        let executor = HttpEvidenceExecutor::new(policy, provider).unwrap();
        let mut registry = DecisionExecutorRegistry::new();
        registry.register(Arc::new(executor)).unwrap();
        let adapter = DecisionRunnerAdapter::new(registry);
        let knowledge = KnowledgeBase::new();

        let error = adapter
            .execute_command(&command(&allowed), &knowledge)
            .await
            .unwrap_err();

        let failure = error.execution_failure().unwrap();
        assert_eq!(failure.kind(), DecisionExecutionFailureKind::RequestTimeout);
        assert_eq!(failure.executor_id(), HTTP_EVIDENCE_EXECUTOR_ID);
        assert_eq!(failure.action_id(), "http.probe");
        assert_eq!(
            failure.diagnostic(),
            "HTTP evidence request timed out after 25 ms"
        );
        assert_eq!(knowledge.stats().evidence, 0);
    }

    #[tokio::test]
    async fn metered_dispatch_failure_charges_one_request_without_response_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let url = Url::parse(&format!("http://{address}/probe")).unwrap();
        let policy = HttpEvidencePolicy::new(
            [url.clone()],
            Duration::from_millis(500),
            DEFAULT_HTTP_BODY_LIMIT,
        )
        .unwrap();
        let (adapter, accounting) = metered_adapter(&url, policy, RuntimeBudget::default());
        let knowledge = KnowledgeBase::new();

        let error = adapter
            .execute_command(&command(&url), &knowledge)
            .await
            .unwrap_err();

        let failure = error.execution_failure().unwrap();
        assert!(matches!(
            failure.kind(),
            DecisionExecutionFailureKind::TransportFailure
                | DecisionExecutionFailureKind::RequestTimeout
        ));
        assert_eq!(accounting.snapshot().total_requests(), 1);
        assert_eq!(accounting.snapshot().response_bytes(), 0);
        assert_eq!(knowledge.stats().evidence, 0);
        let audit = accounting.dispatch_audit();
        let dispatch = audit.receipts().first().unwrap();
        assert_eq!(dispatch.response_bytes(), 0);
        assert!(matches!(
            dispatch.outcome(),
            TransportDispatchOutcome::TransportFailure | TransportDispatchOutcome::RequestTimeout
        ));
    }

    #[tokio::test]
    async fn protocol_failure_is_not_implicitly_retried() {
        let server = serve_empty_response_then_watch_for_retry().await;
        let url = server.target();
        let policy = HttpEvidencePolicy::new(
            [url.clone()],
            Duration::from_secs(1),
            DEFAULT_HTTP_BODY_LIMIT,
        )
        .unwrap();
        let (adapter, accounting) = metered_adapter(&url, policy, RuntimeBudget::default());
        let knowledge = KnowledgeBase::new();

        let error = adapter
            .execute_command(&command(&url), &knowledge)
            .await
            .unwrap_err();
        tokio::time::sleep(Duration::from_millis(300)).await;

        assert_eq!(
            error.execution_failure().unwrap().kind(),
            DecisionExecutionFailureKind::TransportFailure
        );
        assert_eq!(accounting.snapshot().total_requests(), 1);
        assert_eq!(server.requests(), 1);
        assert_eq!(knowledge.stats().evidence, 0);
        assert_eq!(
            accounting.dispatch_audit().receipts()[0].outcome(),
            TransportDispatchOutcome::TransportFailure
        );
    }

    #[tokio::test]
    async fn metered_partial_body_timeout_keeps_already_retained_bytes() {
        let url = serve_partial_then_stall(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 10\r\nConnection: close\r\n\r\n0123",
        )
        .await;
        let policy = HttpEvidencePolicy::new(
            [url.clone()],
            Duration::from_millis(100),
            DEFAULT_HTTP_BODY_LIMIT,
        )
        .unwrap();
        let (adapter, accounting) = metered_adapter(&url, policy, RuntimeBudget::default());
        let knowledge = KnowledgeBase::new();

        let error = adapter
            .execute_command(&command(&url), &knowledge)
            .await
            .unwrap_err();

        let failure = error.execution_failure().unwrap();
        assert_eq!(failure.kind(), DecisionExecutionFailureKind::RequestTimeout);
        assert!(failure.diagnostic().contains("timed out"));
        assert_eq!(accounting.snapshot().total_requests(), 1);
        assert_eq!(accounting.snapshot().response_bytes(), 4);
        assert_eq!(knowledge.stats().evidence, 0);
        let audit = accounting.dispatch_audit();
        let dispatch = audit.receipts().first().unwrap();
        assert_eq!(dispatch.response_bytes(), 4);
        assert_eq!(dispatch.outcome(), TransportDispatchOutcome::RequestTimeout);
    }

    #[tokio::test]
    async fn metered_body_is_clamped_while_full_transport_chunk_is_accounted() {
        let url = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 10\r\nConnection: close\r\n\r\n0123456789",
        )
        .await;
        let policy = HttpEvidencePolicy::new(
            [url.clone()],
            Duration::from_secs(2),
            DEFAULT_HTTP_BODY_LIMIT,
        )
        .unwrap();
        let budget = RuntimeBudget::default().with_max_response_bytes(4);
        let (adapter, accounting) = metered_adapter(&url, policy, budget);
        let knowledge = KnowledgeBase::new();

        let receipt = adapter
            .execute_command(&command(&url), &knowledge)
            .await
            .unwrap();

        assert_eq!(
            value(
                receipt.evidence(),
                HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED,
            ),
            Some(&EvidenceValue::Unsigned(4))
        );
        assert_eq!(
            value(
                receipt.evidence(),
                HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED,
            ),
            Some(&EvidenceValue::Boolean(true))
        );
        assert_eq!(accounting.snapshot().total_requests(), 1);
        let observed = accounting.snapshot().response_bytes();
        assert!(
            (5..=10).contains(&observed),
            "broker must charge the complete chunk that crosses the four-byte retention limit; observed {observed}"
        );
        let audit = accounting.dispatch_audit();
        let dispatch = &audit.receipts()[0];
        assert_eq!(dispatch.response_bytes(), observed);
        assert_eq!(
            dispatch.outcome(),
            TransportDispatchOutcome::ResponseBudgetReached
        );
    }

    #[tokio::test]
    async fn collector_does_not_read_another_chunk_after_budget_is_exactly_full() {
        let (url, first_body_chunk, release_second_chunk) = serve_split_body_after_release().await;
        let budget = RuntimeBudget::default().with_max_response_bytes(4);
        let policy = HttpEvidencePolicy::for_origin(url.clone()).unwrap();
        let (adapter, accounting) = metered_adapter(&url, policy, budget);
        let target = url.clone();
        let mut execution = tokio::spawn(async move {
            adapter
                .execute_command(&command(&target), &KnowledgeBase::new())
                .await
        });

        tokio::time::timeout(Duration::from_secs(1), first_body_chunk)
            .await
            .expect("server did not deliver the first body chunk")
            .unwrap();
        let completed = tokio::time::timeout(Duration::from_secs(1), &mut execution).await;
        let _ = release_second_chunk.send(());
        let receipt = completed
            .expect("collector waited for a chunk after the response budget was full")
            .unwrap()
            .unwrap();

        assert_eq!(accounting.snapshot().response_bytes(), 4);
        assert_eq!(
            value(
                receipt.evidence(),
                HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED,
            ),
            Some(&EvidenceValue::Unsigned(4))
        );
        assert_eq!(
            value(
                receipt.evidence(),
                HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED,
            ),
            Some(&EvidenceValue::Boolean(true))
        );
    }

    #[tokio::test]
    async fn metered_runtime_limit_is_preserved_without_dispatch() {
        let url =
            serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
        let policy = HttpEvidencePolicy::for_origin(url.clone()).unwrap();
        let budget = RuntimeBudget::default().with_max_total_requests(0);
        let (adapter, accounting) = metered_adapter(&url, policy, budget);
        let knowledge = KnowledgeBase::new();

        let error = adapter
            .execute_command(&command(&url), &knowledge)
            .await
            .unwrap_err();

        let limit = error.runtime_limit().unwrap();
        assert_eq!(limit.dimension(), RuntimeBudgetDimension::TotalRequests);
        assert_eq!(accounting.snapshot().total_requests(), 0);
        assert_eq!(accounting.snapshot().response_bytes(), 0);
        assert_eq!(knowledge.stats().evidence, 0);
        assert!(accounting.dispatch_audit().is_empty());
    }

    #[tokio::test]
    async fn buffered_request_body_is_charged_and_denied_before_socket() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let allowed_server = serve_counted(response).await;
        let allowed_target = allowed_server.target();
        let (allowed_adapter, allowed_accounting) = buffered_adapter(
            &allowed_target,
            RuntimeBudget::default().with_max_request_body_bytes(9),
            b"candidate".to_vec(),
        );

        allowed_adapter
            .execute_command(&command(&allowed_target), &KnowledgeBase::new())
            .await
            .unwrap();
        assert_eq!(allowed_server.requests(), 1);
        assert_eq!(allowed_accounting.snapshot().total_requests(), 1);
        assert_eq!(allowed_accounting.snapshot().request_body_bytes(), 9);

        let denied_server = serve_counted(response).await;
        let denied_target = denied_server.target();
        let (denied_adapter, denied_accounting) = buffered_adapter(
            &denied_target,
            RuntimeBudget::default().with_max_request_body_bytes(8),
            b"candidate".to_vec(),
        );
        let error = denied_adapter
            .execute_command(&command(&denied_target), &KnowledgeBase::new())
            .await
            .unwrap_err();
        tokio::time::sleep(Duration::from_millis(25)).await;

        assert_eq!(
            error.runtime_limit().unwrap().dimension(),
            RuntimeBudgetDimension::RequestBodyBytes
        );
        assert_eq!(denied_server.requests(), 0);
        assert_eq!(denied_accounting.snapshot().total_requests(), 0);
        assert_eq!(denied_accounting.snapshot().request_body_bytes(), 0);
        assert!(denied_accounting.dispatch_audit().is_empty());
    }

    #[tokio::test]
    async fn failed_buffered_request_stays_charged_and_retry_cannot_escape_budget() {
        let server = serve_empty_response_then_watch_for_retry().await;
        let target = server.target();
        let (adapter, accounting) = buffered_adapter(
            &target,
            RuntimeBudget::default()
                .with_max_total_requests(2)
                .with_max_request_body_bytes(4),
            b"body".to_vec(),
        );
        let knowledge = KnowledgeBase::new();

        let first = adapter
            .execute_command(&command(&target), &knowledge)
            .await
            .unwrap_err();
        assert_eq!(
            first.execution_failure().unwrap().kind(),
            DecisionExecutionFailureKind::TransportFailure
        );
        assert_eq!(accounting.snapshot().total_requests(), 1);
        assert_eq!(accounting.snapshot().request_body_bytes(), 4);

        let retry = adapter
            .execute_command(&command(&target), &knowledge)
            .await
            .unwrap_err();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            retry.runtime_limit().unwrap().dimension(),
            RuntimeBudgetDimension::RequestBodyBytes
        );
        assert_eq!(server.requests(), 1);
        assert_eq!(accounting.snapshot().total_requests(), 1);
        assert_eq!(accounting.snapshot().request_body_bytes(), 4);
        assert_eq!(knowledge.stats().evidence, 0);
        let audit = accounting.dispatch_audit();
        assert_eq!(audit.receipts().len(), 1);
        assert_eq!(audit.receipts()[0].request_body_bytes(), 4);
        assert_eq!(
            audit.receipts()[0].outcome(),
            TransportDispatchOutcome::TransportFailure
        );
    }

    #[tokio::test]
    async fn multi_request_executor_cannot_exceed_budget() {
        let server =
            serve_counted(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
        let target = server.target();
        let policy = HttpEvidencePolicy::for_origin(target.clone()).unwrap();
        let accounting =
            RequestAccountingBroker::new(RuntimeBudget::default().with_max_total_requests(1));
        let requests = HttpRequestBroker::new_metered(policy, accounting.clone()).unwrap();
        let mut registry = DecisionExecutorRegistry::new();
        registry
            .register(Arc::new(MultiRequestExecutor {
                requests,
                target: target.clone(),
            }))
            .unwrap();
        let adapter = DecisionRunnerAdapter::new(registry);
        let knowledge = KnowledgeBase::new();

        let error = adapter
            .execute_command(&command(&target), &knowledge)
            .await
            .unwrap_err();

        let failure = error.execution_failure().unwrap();
        assert_eq!(failure.action_id(), "http.probe");
        assert_eq!(failure.stage(), DecisionExecutionStage::Passive);
        assert_eq!(failure.origin(), Some(DecisionActionOrigin::Planned));
        let limit = failure.runtime_limit().unwrap();
        assert_eq!(limit.dimension(), RuntimeBudgetDimension::TotalRequests);
        assert_eq!(limit.limit(), 1);
        assert_eq!(limit.observed(), 2);
        assert_eq!(accounting.snapshot().total_requests(), 1);
        assert_eq!(server.requests(), 1);
        assert_eq!(knowledge.stats().evidence, 0);
        let audit = accounting.dispatch_audit();
        assert_eq!(audit.receipts().len(), 1);
        assert_eq!(audit.receipts()[0].sequence(), 0);
        assert_eq!(audit.receipts()[0].action_id(), "http.probe");
        assert_eq!(
            audit.receipts()[0].outcome(),
            TransportDispatchOutcome::Completed
        );
    }

    #[tokio::test]
    async fn multi_request_active_executor_cannot_exceed_active_budget() {
        let server =
            serve_counted(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
        let target = server.target();
        let policy = HttpEvidencePolicy::for_origin(target.clone()).unwrap();
        let accounting =
            RequestAccountingBroker::new(RuntimeBudget::default().with_max_active_verifications(1));
        let requests = HttpRequestBroker::new_metered(policy, accounting.clone()).unwrap();
        let mut registry = DecisionExecutorRegistry::new();
        registry
            .register(Arc::new(MultiRequestExecutor {
                requests,
                target: target.clone(),
            }))
            .unwrap();
        registry
            .route_action(
                DecisionExecutionStage::Active,
                "http.probe",
                HTTP_EVIDENCE_EXECUTOR_ID,
            )
            .unwrap();
        let adapter = DecisionRunnerAdapter::new(registry);
        let knowledge = KnowledgeBase::new();
        let case = VerificationCase::new(
            "case:http:active",
            EntityId::new(format!("endpoint:{target}")).unwrap(),
            "http.probe",
            "hypothesis:http",
        )
        .unwrap();

        let error = adapter
            .execute_command(
                &DecisionLoopCommand::CollectActiveEvidence { case },
                &knowledge,
            )
            .await
            .unwrap_err();

        let failure = error.execution_failure().unwrap();
        assert_eq!(failure.stage(), DecisionExecutionStage::Active);
        let limit = failure.runtime_limit().unwrap();
        assert_eq!(
            limit.dimension(),
            RuntimeBudgetDimension::ActiveVerifications
        );
        assert_eq!(limit.limit(), 1);
        assert_eq!(limit.observed(), 2);
        assert_eq!(accounting.snapshot().total_requests(), 1);
        assert_eq!(accounting.snapshot().active_verifications(), 1);
        assert_eq!(server.requests(), 1);
        assert_eq!(knowledge.stats().evidence, 0);
        let audit = accounting.dispatch_audit();
        assert_eq!(audit.receipts().len(), 1);
        assert_eq!(audit.receipts()[0].stage(), DecisionExecutionStage::Active);
        assert_eq!(audit.receipts()[0].origin(), None);
        assert_eq!(
            audit.receipts()[0].outcome(),
            TransportDispatchOutcome::Completed
        );
    }

    #[test]
    fn probe_and_policy_reject_ambiguous_or_unbounded_inputs() {
        let url = Url::parse("https://example.test/").unwrap();
        assert!(matches!(
            HttpProbe::new(url.clone(), HttpProbeMethod::Get)
                .unwrap()
                .with_header("Host", "other.test"),
            Err(HttpEvidenceError::ForbiddenRequestHeader { .. })
        ));
        assert!(matches!(
            HttpEvidencePolicy::new([url.clone()], Duration::ZERO, 1024),
            Err(HttpEvidenceError::ZeroTimeout)
        ));
        assert!(matches!(
            HttpEvidencePolicy::for_origin(url.clone())
                .unwrap()
                .with_reliability(ConfidenceScore::NONE),
            Err(HttpEvidenceError::ZeroReliability)
        ));
        assert!(matches!(
            HttpEvidencePolicy::new([url], Duration::from_secs(1), MAX_HTTP_BODY_LIMIT + 1),
            Err(HttpEvidenceError::BodyLimitTooLarge { .. })
        ));
    }
}
