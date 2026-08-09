//! Scope-bound HTTP collection for the decision runner.
//!
//! ## Runtime scope
//!
//! - **Build:** default via `scanning`.
//! - **Execution:** Surface B (metered executor for the decision runtime).
//! - **Default `venom scan`:** no.
//! - **Support:** implemented and tested.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! This executor performs one bounded discovery request and emits immutable,
//! typed observations. It does not classify vulnerabilities, follow redirects,
//! choose follow-up actions, or mutate the knowledge base directly.

use std::{collections::BTreeMap, collections::BTreeSet, fmt, sync::Arc, time::Duration};

use async_trait::async_trait;
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Method, StatusCode, Url,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use venom_core::{
    ConfidenceScore, Evidence, EvidenceKind, EvidenceSource, EvidenceValue, HttpEvidencePredicate,
    KnowledgePredicate,
};

use crate::{
    payload_strategy::{
        PayloadSeed, PayloadStrategyLimits, PayloadStrategyRef, PayloadStrategyRegistry,
        PayloadVariantRole,
    },
    runtime_budget::RequestAccountingBroker,
    DecisionActionExecutor, DecisionExecutionFailureKind, DecisionExecutionRequest,
    DecisionExecutionStage, DecisionExecutorError,
};

mod form_controls;
mod request_broker;

use form_controls::extract_form_control_names;
pub(crate) use request_broker::{HttpRequestBroker, HttpRequestBrokerError};

/// Default maximum number of response-body bytes read by one probe.
pub const DEFAULT_HTTP_BODY_LIMIT: usize = 256 * 1024;

/// Hard guard preventing an individual evidence probe from buffering too much.
pub const MAX_HTTP_BODY_LIMIT: usize = 16 * 1024 * 1024;

const MAX_HTTP_PATH_SEGMENTS: usize = 128;
const MAX_HTTP_PATH_SEGMENT_BYTES: usize = 256;

/// Stable executor identity used by the standard HTTP evidence collector.
pub const HTTP_EVIDENCE_EXECUTOR_ID: &str = "http.evidence";

/// Discovery-only HTTP methods supported by the evidence executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HttpProbeMethod {
    /// Retrieve response headers and a bounded representation of the body.
    Get,
    /// Retrieve response headers without a response body.
    Head,
    /// Discover methods and protocol behavior exposed by the endpoint.
    Options,
}

impl HttpProbeMethod {
    fn as_reqwest(self) -> Method {
        match self {
            Self::Get => Method::GET,
            Self::Head => Method::HEAD,
            Self::Options => Method::OPTIONS,
        }
    }

    /// Returns the stable uppercase method name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
        }
    }
}

/// Response-body representation allowed to enter the knowledge base.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
#[non_exhaustive]
pub enum HttpBodyCapture {
    /// Record byte count, truncation, and SHA-256 only.
    #[default]
    MetadataOnly,
    /// Also record a bounded UTF-8 sample for textual response types.
    TextSample {
        /// Maximum Unicode scalar values retained in the sample.
        max_chars: usize,
    },
}

/// One validated, bodyless discovery request.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpProbe {
    url: Url,
    method: HttpProbeMethod,
    headers: BTreeMap<String, String>,
}

impl fmt::Debug for HttpProbe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpProbe")
            .field("url", &"<redacted>")
            .field("method", &self.method)
            .field("header_names", &self.headers.keys().collect::<Vec<_>>())
            .field("header_values", &"<redacted>")
            .finish()
    }
}

impl HttpProbe {
    /// Creates a request for one absolute HTTP or HTTPS URL.
    pub fn new(url: Url, method: HttpProbeMethod) -> Result<Self, HttpEvidenceError> {
        validate_http_url(&url)?;
        Ok(Self {
            url,
            method,
            headers: BTreeMap::new(),
        })
    }

    /// Adds or replaces a validated request header.
    ///
    /// `Host`, hop-by-hop framing headers, and proxy authorization are
    /// rejected because they can change the scoped destination or transport
    /// interpretation. Authentication and cookie headers remain explicit host
    /// choices for authorized authenticated scans.
    pub fn with_header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, HttpEvidenceError> {
        let name = name.into();
        let parsed_name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| HttpEvidenceError::InvalidHeaderName { name: name.clone() })?;
        if forbidden_request_header(&parsed_name) {
            return Err(HttpEvidenceError::ForbiddenRequestHeader {
                name: parsed_name.as_str().to_owned(),
            });
        }
        let value = value.into();
        HeaderValue::from_str(&value).map_err(|_| HttpEvidenceError::InvalidHeaderValue {
            name: parsed_name.as_str().to_owned(),
        })?;
        self.headers.insert(parsed_name.as_str().to_owned(), value);
        Ok(self)
    }

    /// Returns the absolute request URL.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Returns the discovery method.
    pub fn method(&self) -> HttpProbeMethod {
        self.method
    }

    /// Returns request headers in stable lowercase-name order.
    pub fn headers(&self) -> &BTreeMap<String, String> {
        &self.headers
    }
}

/// Host-owned mapping from a decision case to an HTTP discovery request.
pub trait HttpProbeProvider: Send + Sync {
    /// Resolves one request without performing I/O or changing decision state.
    fn probe_for(&self, request: &DecisionExecutionRequest)
        -> Result<HttpProbe, HttpEvidenceError>;
}

impl<F> HttpProbeProvider for F
where
    F: Fn(&DecisionExecutionRequest) -> Result<HttpProbe, HttpEvidenceError> + Send + Sync,
{
    fn probe_for(
        &self,
        request: &DecisionExecutionRequest,
    ) -> Result<HttpProbe, HttpEvidenceError> {
        self(request)
    }
}

/// Default provider that interprets `endpoint:<absolute-url>` subjects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubjectHttpProbeProvider {
    method: HttpProbeMethod,
}

impl SubjectHttpProbeProvider {
    /// Creates a subject-backed provider using the selected discovery method.
    pub const fn new(method: HttpProbeMethod) -> Self {
        Self { method }
    }
}

impl Default for SubjectHttpProbeProvider {
    fn default() -> Self {
        Self::new(HttpProbeMethod::Get)
    }
}

impl HttpProbeProvider for SubjectHttpProbeProvider {
    fn probe_for(
        &self,
        request: &DecisionExecutionRequest,
    ) -> Result<HttpProbe, HttpEvidenceError> {
        let subject = request.case().subject().as_str();
        let raw_url = subject.strip_prefix("endpoint:").ok_or_else(|| {
            HttpEvidenceError::InvalidEndpointSubject {
                subject: subject.to_owned(),
            }
        })?;
        let url = Url::parse(raw_url).map_err(|source| HttpEvidenceError::InvalidUrl {
            value: raw_url.to_owned(),
            source,
        })?;
        HttpProbe::new(url, self.method)
    }
}

/// Scope, resource, and evidence policy applied to every HTTP probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HttpEvidencePolicy {
    allowed_origins: BTreeSet<String>,
    request_timeout_ms: u64,
    max_body_bytes: usize,
    body_capture: HttpBodyCapture,
    captured_headers: BTreeSet<String>,
    reliability: ConfidenceScore,
}

impl HttpEvidencePolicy {
    /// Creates a policy for one or more explicitly authorized origins.
    pub fn new(
        allowed_origins: impl IntoIterator<Item = Url>,
        request_timeout: Duration,
        max_body_bytes: usize,
    ) -> Result<Self, HttpEvidenceError> {
        if request_timeout.is_zero() {
            return Err(HttpEvidenceError::ZeroTimeout);
        }
        validate_body_limit(max_body_bytes)?;

        let mut origins = BTreeSet::new();
        for url in allowed_origins {
            validate_http_url(&url)?;
            origins.insert(origin(&url)?);
        }
        if origins.is_empty() {
            return Err(HttpEvidenceError::EmptyAllowedOrigins);
        }

        Ok(Self {
            allowed_origins: origins,
            request_timeout_ms: u64::try_from(request_timeout.as_millis().max(1))
                .unwrap_or(u64::MAX),
            max_body_bytes,
            body_capture: HttpBodyCapture::MetadataOnly,
            captured_headers: default_captured_headers(),
            reliability: ConfidenceScore::MAX,
        })
    }

    /// Uses the standard timeout, body limit, headers, and maximum reliability.
    pub fn for_origin(origin: Url) -> Result<Self, HttpEvidenceError> {
        Self::new([origin], Duration::from_secs(15), DEFAULT_HTTP_BODY_LIMIT)
    }

    /// Configures optional bounded text sampling.
    pub fn with_body_capture(
        mut self,
        capture: HttpBodyCapture,
    ) -> Result<Self, HttpEvidenceError> {
        if let HttpBodyCapture::TextSample { max_chars } = capture {
            if max_chars == 0 {
                return Err(HttpEvidenceError::ZeroTextSampleLimit);
            }
            if max_chars > self.max_body_bytes {
                return Err(HttpEvidenceError::TextSampleLimitTooLarge {
                    max_chars,
                    max_body_bytes: self.max_body_bytes,
                });
            }
        }
        self.body_capture = capture;
        Ok(self)
    }

    /// Adds one response header to the evidence allowlist.
    ///
    /// Sensitive headers such as `set-cookie` are not included by default and
    /// should be enabled only when the host's storage policy permits them.
    pub fn capture_header(mut self, name: impl Into<String>) -> Result<Self, HttpEvidenceError> {
        let name = name.into();
        let parsed = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| HttpEvidenceError::InvalidHeaderName { name: name.clone() })?;
        self.captured_headers.insert(parsed.as_str().to_owned());
        Ok(self)
    }

    /// Sets a non-zero ordinal source reliability for emitted evidence.
    ///
    /// Zero-confidence observations are rejected because deterministic rules
    /// currently use declared likelihoods rather than scaling by this metadata.
    pub fn with_reliability(
        mut self,
        reliability: ConfidenceScore,
    ) -> Result<Self, HttpEvidenceError> {
        if reliability == ConfidenceScore::NONE {
            return Err(HttpEvidenceError::ZeroReliability);
        }
        self.reliability = reliability;
        Ok(self)
    }

    /// Returns normalized authorized origins.
    pub fn allowed_origins(&self) -> &BTreeSet<String> {
        &self.allowed_origins
    }

    /// Returns the total request and body-read timeout.
    pub fn request_timeout(&self) -> Duration {
        Duration::from_millis(self.request_timeout_ms)
    }

    /// Returns the maximum buffered body bytes.
    pub fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    /// Returns the body representation policy.
    pub fn body_capture(&self) -> HttpBodyCapture {
        self.body_capture
    }

    /// Returns captured response header names in stable order.
    pub fn captured_headers(&self) -> &BTreeSet<String> {
        &self.captured_headers
    }

    /// Returns the ordinal reliability attached to each observation.
    pub fn reliability(&self) -> ConfidenceScore {
        self.reliability
    }

    fn permits(&self, url: &Url) -> Result<bool, HttpEvidenceError> {
        Ok(self.allowed_origins.contains(&origin(url)?))
    }
}

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
    Reasoning(#[from] venom_core::ReasoningModelError),
}

pub(crate) fn execution_failure_kind(error: &HttpEvidenceError) -> DecisionExecutionFailureKind {
    match error {
        HttpEvidenceError::InvalidEndpointSubject { .. }
        | HttpEvidenceError::UnsupportedScheme { .. } => {
            DecisionExecutionFailureKind::NotApplicable
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
        | HttpEvidenceError::Client(_)
        | HttpEvidenceError::Reasoning(_) => DecisionExecutionFailureKind::ExecutorFailure,
    }
}

fn into_decision_executor_error(error: HttpEvidenceError) -> DecisionExecutorError {
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

/// Real HTTP executor that produces typed evidence for the decision runner.
///
/// # Examples
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use url::Url;
/// use venom_scanner::{
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
    payload: Option<HttpHeaderPayloadBinding>,
    capture_form_control_names: bool,
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
        Self::build(id, policy, probes, None)
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
        Self::build(id, policy, probes, Some(accounting))
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
        })
    }

    fn build(
        id: impl Into<String>,
        policy: HttpEvidencePolicy,
        probes: Arc<dyn HttpProbeProvider>,
        accounting: Option<RequestAccountingBroker>,
    ) -> Result<Self, HttpEvidenceError> {
        let id = validate_executor_id(id)?;
        let requests = match accounting {
            Some(accounting) => HttpRequestBroker::new_metered(policy, accounting)?,
            None => HttpRequestBroker::new_unmetered(policy)?,
        };
        Ok(Self {
            id,
            requests,
            probes,
            payload: None,
            capture_form_control_names: false,
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

    /// Binds a header-valued payload strategy this executor will materialize.
    ///
    /// The executor then advertises exact support for the binding's strategy
    /// reference and, when a decision case selects it, derives one control or
    /// candidate artifact per turn and applies it before dispatch. Actions that
    /// do not select the reference are unaffected, so an executor may serve both
    /// plain discovery and strategy-driven differential turns.
    pub fn with_payload_binding(mut self, binding: HttpHeaderPayloadBinding) -> Self {
        self.payload = Some(binding);
        self
    }

    /// Returns the bound payload strategy reference, if any.
    pub fn payload_strategy_reference(&self) -> Option<&PayloadStrategyRef> {
        self.payload
            .as_ref()
            .map(HttpHeaderPayloadBinding::reference)
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

        for cookie_name in response_cookie_names(&response.headers) {
            evidence.push(self.observation(
                decision,
                EvidenceKind::Authentication,
                HttpEvidencePredicate::COOKIE_NAME.into(),
                EvidenceValue::Text(cookie_name),
                "response-set-cookie-name",
            )?);
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
                // only when at least one name is conservatively observed.
                if self.capture_form_control_names
                    && normalized_media_type(&response.headers).as_deref() == Some("text/html")
                {
                    let names = extract_form_control_names(&sample);
                    if !names.is_empty() {
                        evidence.push(self.observation(
                            decision,
                            EvidenceKind::Content,
                            HttpEvidencePredicate::RESPONSE_FORM_CONTROL_NAMES.into(),
                            EvidenceValue::TextList(names),
                            "response-form-control-names",
                        )?);
                    }
                }

                evidence.push(self.observation(
                    decision,
                    EvidenceKind::Content,
                    HttpEvidencePredicate::RESPONSE_BODY_SAMPLE.into(),
                    EvidenceValue::Text(sample),
                    "response-body-sample",
                )?);
            }
        }

        append_rate_limit_evidence(self, decision, &response, &mut evidence)?;
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

pub(crate) struct CollectedHttpResponse {
    status: StatusCode,
    final_url: Url,
    version: String,
    headers: HeaderMap,
    body: Vec<u8>,
    body_truncated: bool,
    ttfb_ms: u64,
    total_ms: u64,
}

impl CollectedHttpResponse {
    pub(crate) fn status(&self) -> u16 {
        self.status.as_u16()
    }

    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    pub(crate) fn body_truncated(&self) -> bool {
        self.body_truncated
    }

    pub(crate) fn has_json_compatible_media_type(&self) -> bool {
        normalized_media_type(&self.headers)
            .as_deref()
            .is_some_and(json_compatible_media_type)
    }
}

fn validate_http_url(url: &Url) -> Result<(), HttpEvidenceError> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(HttpEvidenceError::UnsupportedScheme {
            scheme: url.scheme().to_owned(),
        });
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(HttpEvidenceError::EmbeddedCredentials);
    }
    Ok(())
}

fn validate_executor_id(id: impl Into<String>) -> Result<String, HttpEvidenceError> {
    let id = id.into();
    if id.trim().is_empty() {
        return Err(HttpEvidenceError::EmptyExecutorId);
    }
    Ok(id)
}

fn origin(url: &Url) -> Result<String, HttpEvidenceError> {
    validate_http_url(url)?;
    Ok(url.origin().ascii_serialization())
}

fn validate_body_limit(max_body_bytes: usize) -> Result<(), HttpEvidenceError> {
    if max_body_bytes == 0 {
        return Err(HttpEvidenceError::ZeroBodyLimit);
    }
    if max_body_bytes > MAX_HTTP_BODY_LIMIT {
        return Err(HttpEvidenceError::BodyLimitTooLarge {
            actual: max_body_bytes,
            maximum: MAX_HTTP_BODY_LIMIT,
        });
    }
    Ok(())
}

fn forbidden_request_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "host"
            | "connection"
            | "content-length"
            | "transfer-encoding"
            | "upgrade"
            | "proxy-authorization"
            | "proxy-connection"
    )
}

fn default_captured_headers() -> BTreeSet<String> {
    [
        "access-control-allow-origin",
        "allow",
        "cache-control",
        "content-length",
        "content-security-policy",
        "content-type",
        "location",
        "ratelimit-limit",
        "ratelimit-remaining",
        "ratelimit-reset",
        "retry-after",
        "server",
        "strict-transport-security",
        "vary",
        "www-authenticate",
        "x-frame-options",
        "x-powered-by",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
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

fn normalized_media_type(headers: &HeaderMap) -> Option<String> {
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

fn json_compatible_media_type(media_type: &str) -> bool {
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
        let value = raw
            .parse::<u64>()
            .map(EvidenceValue::Unsigned)
            .unwrap_or_else(|_| EvidenceValue::Text(raw));
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

fn elapsed_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use venom_core::{EntityId, EvidenceValue, HypothesisStrength};

    use super::*;
    use crate::{
        DecisionActionOrigin, DecisionExecutionStage, DecisionExecutorRegistry,
        DecisionLoopCommand, DecisionRunnerAdapter, KnowledgeBase, RuleEngine, RuntimeBudget,
        RuntimeBudgetDimension, StandardWebReasoning, TransportDispatchOutcome, VerificationCase,
    };

    #[test]
    fn form_control_extraction_reads_named_controls_sorted_and_deduplicated() {
        let names = extract_form_control_names(
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
        let names = extract_form_control_names(
            "<input type=\"submit\"><input name=\"\"><button name=\"go\">",
        );
        // Nameless/empty-name controls are skipped; button is not a target element.
        assert!(names.is_empty());
    }

    #[test]
    fn form_control_extraction_never_treats_commented_or_scripted_markup_as_controls() {
        let names = extract_form_control_names(
            "<!-- <input name=\"fake_comment\"> -->\
             <script>const x = '<input name=\"fake_script\">';</script>\
             <style>input[name=\"fake_style\"] { color: red; }</style>\
             <input name=\"real\">",
        );
        assert_eq!(names, ["real"]);
    }

    #[test]
    fn form_control_extraction_keeps_textarea_name_but_drops_its_body() {
        let names = extract_form_control_names(
            "<textarea name=\"real\">\n  <input name=\"fake_in_textarea\">\n</textarea>",
        );
        // The textarea's own name is a control; markup inside its body is text.
        assert_eq!(names, ["real"]);
    }

    #[test]
    fn form_control_extraction_records_names_never_values() {
        let names = extract_form_control_names(
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
        let names = extract_form_control_names(
            "<input data-name=\"nickname\" formname=\"x\" name=\"real\">",
        );
        assert_eq!(names, ["real"]);
    }

    #[test]
    fn form_control_extraction_respects_attribute_quote_state() {
        // A `name=` sequence inside another attribute's quoted value is text, not
        // a real attribute — the tokenizer tracks quote state so it is never read.
        assert!(extract_form_control_names("<input title=\" name='fake'\">").is_empty());
        assert!(extract_form_control_names("<input title=' name=\"fake\"'>").is_empty());
        assert_eq!(
            extract_form_control_names("<input title=\"ordinary\" name=\"real\">"),
            ["real"]
        );
    }

    #[test]
    fn form_control_extraction_preserves_name_attribute_whitespace() {
        let names = extract_form_control_names(
            "<input name=\" _token \"><input name=\" \"><input name=\"\">",
        );

        // HTML form-control names are attribute values, not space-separated
        // tokens. Preserve non-empty values exactly so a padded convention name
        // cannot be promoted into an exact `_token` observation.
        assert_eq!(names, [" ", " _token "]);
        assert!(!names.iter().any(|name| name == "_token"));
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
        assert_eq!(extract_form_control_names(&html), ["deep"]);
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

    /// Serves one `text/html` response with an auto-computed `Content-Length`, so
    /// tests can vary the HTML body without hand-counting bytes.
    async fn serve_html_once(body: impl Into<String>) -> Url {
        let body = body.into();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
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
        let probe_url = url.clone();
        let provider: Arc<dyn HttpProbeProvider> =
            Arc::new(move |_request: &DecisionExecutionRequest| {
                HttpProbe::new(probe_url.clone(), HttpProbeMethod::Get)
            });
        let policy = HttpEvidencePolicy::new([url.clone()], Duration::from_secs(2), 65_536)
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
