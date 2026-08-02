//! Scope-bound HTTP collection for the decision runner.
//!
//! This executor performs one bounded discovery request and emits immutable,
//! typed observations. It does not classify vulnerabilities, follow redirects,
//! choose follow-up actions, or mutate the knowledge base directly.

use std::{collections::BTreeMap, collections::BTreeSet, sync::Arc, time::Duration};

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
    runtime_budget::RequestAccountingBroker, DecisionActionExecutor, DecisionExecutionFailureKind,
    DecisionExecutionRequest, DecisionExecutorError,
};

mod request_broker;

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpProbe {
    url: Url,
    method: HttpProbeMethod,
    headers: BTreeMap<String, String>,
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

    /// A request header could alter destination or message framing.
    #[error("HTTP request header {name} is forbidden by evidence policy")]
    ForbiddenRequestHeader { name: String },

    /// A provider attempted to leave the authorized origin set.
    #[error("HTTP evidence target origin is outside policy: {url}")]
    TargetOutsidePolicy { url: String },

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

fn execution_failure_kind(error: &HttpEvidenceError) -> DecisionExecutionFailureKind {
    match error {
        HttpEvidenceError::InvalidEndpointSubject { .. }
        | HttpEvidenceError::UnsupportedScheme { .. } => {
            DecisionExecutionFailureKind::NotApplicable
        },
        HttpEvidenceError::EmbeddedCredentials
        | HttpEvidenceError::ForbiddenRequestHeader { .. }
        | HttpEvidenceError::TargetOutsidePolicy { .. } => {
            DecisionExecutionFailureKind::BlockedByPolicy
        },
        HttpEvidenceError::Timeout { .. } | HttpEvidenceError::Request(_) => {
            DecisionExecutionFailureKind::TransportFailure
        },
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
        | HttpEvidenceError::Client(_)
        | HttpEvidenceError::Reasoning(_) => DecisionExecutionFailureKind::ExecutorFailure,
    }
}

fn into_decision_executor_error(error: HttpEvidenceError) -> DecisionExecutorError {
    DecisionExecutorError::with_kind(execution_failure_kind(&error), error.to_string())
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
        })
    }

    fn build(
        id: impl Into<String>,
        policy: HttpEvidencePolicy,
        probes: Arc<dyn HttpProbeProvider>,
        accounting: Option<RequestAccountingBroker>,
    ) -> Result<Self, HttpEvidenceError> {
        let id = validate_executor_id(id)?;
        let requests = HttpRequestBroker::new(policy, accounting)?;
        Ok(Self {
            id,
            requests,
            probes,
        })
    }

    /// Returns the immutable execution policy.
    pub fn policy(&self) -> &HttpEvidencePolicy {
        self.requests.policy()
    }

    async fn collect(
        &self,
        decision: &DecisionExecutionRequest,
    ) -> Result<Vec<Evidence>, HttpRequestBrokerError> {
        let probe = self.probes.probe_for(decision)?;
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

    async fn execute(
        &self,
        request: &DecisionExecutionRequest,
    ) -> Result<Vec<Evidence>, DecisionExecutorError> {
        self.collect(request)
            .await
            .map_err(HttpRequestBrokerError::into_decision_executor_error)
    }
}

struct CollectedHttpResponse {
    status: StatusCode,
    final_url: Url,
    version: String,
    headers: HeaderMap,
    body: Vec<u8>,
    body_truncated: bool,
    ttfb_ms: u64,
    total_ms: u64,
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
    use venom_core::{EntityId, EvidenceValue, HypothesisStrength};

    use super::*;
    use crate::{
        DecisionActionOrigin, DecisionExecutionStage, DecisionExecutorRegistry,
        DecisionLoopCommand, DecisionRunnerAdapter, KnowledgeBase, RuleEngine, RuntimeBudget,
        RuntimeBudgetDimension, StandardWebReasoning, VerificationCase,
    };

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
        assert_eq!(
            failure.kind(),
            DecisionExecutionFailureKind::TransportFailure
        );
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
        assert_eq!(
            failure.kind(),
            DecisionExecutionFailureKind::TransportFailure
        );
        assert_eq!(accounting.snapshot().total_requests(), 1);
        assert_eq!(accounting.snapshot().response_bytes(), 0);
        assert_eq!(knowledge.stats().evidence, 0);
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
        assert_eq!(
            failure.kind(),
            DecisionExecutionFailureKind::TransportFailure
        );
        assert!(failure.diagnostic().contains("timed out"));
        assert_eq!(accounting.snapshot().total_requests(), 1);
        assert_eq!(accounting.snapshot().response_bytes(), 4);
        assert_eq!(knowledge.stats().evidence, 0);
    }

    #[tokio::test]
    async fn metered_body_is_clamped_by_the_cumulative_host_budget() {
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
        assert_eq!(accounting.snapshot().response_bytes(), 4);
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
        let requests = HttpRequestBroker::new(policy, Some(accounting.clone())).unwrap();
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
