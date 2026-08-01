//! Scope-bound HTTP collection for the decision runner.
//!
//! This executor performs one bounded discovery request and emits immutable,
//! typed observations. It does not classify vulnerabilities, follow redirects,
//! choose follow-up actions, or mutate the knowledge base directly.

use std::{collections::BTreeMap, collections::BTreeSet, sync::Arc, time::Duration};

use async_trait::async_trait;
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    redirect::Policy as RedirectPolicy,
    Client, Method, StatusCode, Url,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use venom_core::{
    ConfidenceScore, Evidence, EvidenceKind, EvidenceSource, EvidenceValue, KnowledgePredicate,
};

use crate::{DecisionActionExecutor, DecisionExecutionRequest, DecisionExecutorError};

/// Default maximum number of response-body bytes read by one probe.
pub const DEFAULT_HTTP_BODY_LIMIT: usize = 256 * 1024;

/// Hard guard preventing an individual evidence probe from buffering too much.
pub const MAX_HTTP_BODY_LIMIT: usize = 16 * 1024 * 1024;

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

    /// Sets the ordinal source reliability attached to emitted evidence.
    pub fn with_reliability(mut self, reliability: ConfidenceScore) -> Self {
        self.reliability = reliability;
        self
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
    client: Client,
    policy: HttpEvidencePolicy,
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
        let id = id.into();
        if id.trim().is_empty() {
            return Err(HttpEvidenceError::EmptyExecutorId);
        }
        let client = Client::builder()
            .redirect(RedirectPolicy::none())
            .build()
            .map_err(HttpEvidenceError::Client)?;
        Ok(Self {
            id,
            client,
            policy,
            probes,
        })
    }

    /// Returns the immutable execution policy.
    pub fn policy(&self) -> &HttpEvidencePolicy {
        &self.policy
    }

    async fn collect(
        &self,
        decision: &DecisionExecutionRequest,
    ) -> Result<Vec<Evidence>, HttpEvidenceError> {
        let probe = self.probes.probe_for(decision)?;
        validate_http_url(probe.url())?;
        if !self.policy.permits(probe.url())? {
            return Err(HttpEvidenceError::TargetOutsidePolicy {
                url: probe.url().to_string(),
            });
        }

        let request = build_request(&self.client, &probe)?;
        let started = tokio::time::Instant::now();
        let collected = tokio::time::timeout(self.policy.request_timeout(), async {
            let mut response = self
                .client
                .execute(request)
                .await
                .map_err(HttpEvidenceError::Request)?;
            let ttfb_ms = elapsed_ms(started.elapsed());
            let status = response.status();
            let final_url = response.url().clone();
            let version = format!("{:?}", response.version());
            let headers = response.headers().clone();
            let mut body = Vec::with_capacity(
                response
                    .content_length()
                    .and_then(|length| usize::try_from(length).ok())
                    .unwrap_or(0)
                    .min(self.policy.max_body_bytes()),
            );
            let mut truncated = false;

            while let Some(chunk) = response.chunk().await.map_err(HttpEvidenceError::Request)? {
                let remaining = self.policy.max_body_bytes().saturating_sub(body.len());
                if chunk.len() > remaining {
                    body.extend_from_slice(&chunk[..remaining]);
                    truncated = true;
                    break;
                }
                body.extend_from_slice(&chunk);
            }

            Ok::<_, HttpEvidenceError>(CollectedHttpResponse {
                status,
                final_url,
                version,
                headers,
                body,
                body_truncated: truncated,
                ttfb_ms,
                total_ms: elapsed_ms(started.elapsed()),
            })
        })
        .await
        .map_err(|_| HttpEvidenceError::Timeout {
            timeout_ms: self.policy.request_timeout_ms,
        })??;

        self.to_evidence(decision, &probe, collected)
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
                "http.request",
                "method",
                EvidenceValue::Text(probe.method().as_str().to_owned()),
                "request-method",
            )?,
            self.observation(
                decision,
                EvidenceKind::Http,
                "http.request",
                "url",
                EvidenceValue::Text(probe.url().to_string()),
                "request-url",
            )?,
            self.observation(
                decision,
                EvidenceKind::Http,
                "http.response",
                "status",
                EvidenceValue::Unsigned(u64::from(response.status.as_u16())),
                "response-status",
            )?,
            self.observation(
                decision,
                EvidenceKind::Http,
                "http.response",
                "final-url",
                EvidenceValue::Text(response.final_url.to_string()),
                "response-final-url",
            )?,
            self.observation(
                decision,
                EvidenceKind::Http,
                "http.response",
                "version",
                EvidenceValue::Text(response.version.clone()),
                "response-version",
            )?,
            self.observation(
                decision,
                EvidenceKind::Timing,
                "http.timing",
                "ttfb-ms",
                EvidenceValue::Unsigned(response.ttfb_ms),
                "time-to-first-byte",
            )?,
            self.observation(
                decision,
                EvidenceKind::Timing,
                "http.timing",
                "total-ms",
                EvidenceValue::Unsigned(response.total_ms),
                "total-response-time",
            )?,
        ];

        for name in self.policy.captured_headers() {
            if let Some(value) = joined_header(&response.headers, name) {
                evidence.push(self.observation(
                    decision,
                    EvidenceKind::Http,
                    "http.header",
                    name,
                    EvidenceValue::Text(value),
                    &format!("response-header:{name}"),
                )?);
            }
        }

        for cookie_name in response_cookie_names(&response.headers) {
            evidence.push(self.observation(
                decision,
                EvidenceKind::Authentication,
                "http.cookie",
                "name",
                EvidenceValue::Text(cookie_name),
                "response-set-cookie-name",
            )?);
        }

        evidence.push(self.observation(
            decision,
            EvidenceKind::Content,
            "http.response",
            "body-bytes-observed",
            EvidenceValue::Unsigned(u64::try_from(response.body.len()).unwrap_or(u64::MAX)),
            "response-body-size",
        )?);
        evidence.push(self.observation(
            decision,
            EvidenceKind::Content,
            "http.response",
            "body-truncated",
            EvidenceValue::Boolean(response.body_truncated),
            "response-body-truncation",
        )?);
        evidence.push(self.observation(
            decision,
            EvidenceKind::Content,
            "http.response",
            "body-sha256",
            EvidenceValue::Text(format!("{:x}", Sha256::digest(&response.body))),
            "response-body-sha256",
        )?);

        if let HttpBodyCapture::TextSample { max_chars } = self.policy.body_capture() {
            if textual_response(&response.headers) {
                let decoded = String::from_utf8_lossy(&response.body);
                let sample: String = decoded.chars().take(max_chars).collect();
                evidence.push(self.observation(
                    decision,
                    EvidenceKind::Content,
                    "http.response",
                    "body-sample",
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
        namespace: &str,
        name: &str,
        value: EvidenceValue,
        method: &str,
    ) -> Result<Evidence, HttpEvidenceError> {
        let source = EvidenceSource::new(self.id.clone(), method)?
            .with_correlation_id(decision.case().id())?;
        Ok(Evidence::new(
            decision.case().subject().clone(),
            kind,
            KnowledgePredicate::new(namespace, name)?,
            value,
            source,
            self.policy.reliability(),
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
            .map_err(|error| DecisionExecutorError::new(error.to_string()))
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

fn build_request(
    client: &Client,
    probe: &HttpProbe,
) -> Result<reqwest::Request, HttpEvidenceError> {
    let mut request = client.request(probe.method().as_reqwest(), probe.url().clone());
    for (name, value) in probe.headers() {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| HttpEvidenceError::InvalidHeaderName { name: name.clone() })?;
        let value =
            HeaderValue::from_str(value).map_err(|_| HttpEvidenceError::InvalidHeaderValue {
                name: name.as_str().to_owned(),
            })?;
        request = request.header(name, value);
    }
    request.build().map_err(HttpEvidenceError::Request)
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

fn append_rate_limit_evidence(
    executor: &HttpEvidenceExecutor,
    decision: &DecisionExecutionRequest,
    response: &CollectedHttpResponse,
    evidence: &mut Vec<Evidence>,
) -> Result<(), HttpEvidenceError> {
    let rate_headers = [
        ("retry-after", None, "retry-after"),
        ("ratelimit-limit", Some("x-ratelimit-limit"), "limit"),
        (
            "ratelimit-remaining",
            Some("x-ratelimit-remaining"),
            "remaining",
        ),
        ("ratelimit-reset", Some("x-ratelimit-reset"), "reset"),
    ];
    let advertised = rate_headers.iter().any(|(standard, fallback, _)| {
        response.headers.contains_key(*standard)
            || fallback.is_some_and(|header| response.headers.contains_key(header))
    });

    evidence.push(executor.observation(
        decision,
        EvidenceKind::RateLimit,
        "http.rate-limit",
        "detected",
        EvidenceValue::Boolean(response.status == StatusCode::TOO_MANY_REQUESTS),
        "rate-limit-status",
    )?);
    evidence.push(executor.observation(
        decision,
        EvidenceKind::RateLimit,
        "http.rate-limit",
        "advertised",
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
            "http.rate-limit",
            predicate,
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
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use venom_core::{EntityId, EvidenceValue, HypothesisStrength};

    use super::*;
    use crate::{
        DecisionActionOrigin, DecisionExecutorRegistry, DecisionLoopCommand, DecisionRunnerAdapter,
        KnowledgeBase, RuleEngine, StandardWebReasoning, VerificationCase,
    };

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

    fn value<'a>(evidence: &'a [Evidence], predicate: &str) -> Option<&'a EvidenceValue> {
        evidence
            .iter()
            .find(|item| item.predicate().dotted() == predicate)
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
            value(evidence, "http.response.status"),
            Some(&EvidenceValue::Unsigned(200))
        );
        assert_eq!(
            value(evidence, "http.header.content-type"),
            Some(&EvidenceValue::Text("application/json".to_owned()))
        );
        assert_eq!(
            value(evidence, "http.response.body-sample"),
            Some(&EvidenceValue::Text("{\"ok\":true}".to_owned()))
        );
        assert_eq!(
            value(evidence, "http.response.body-bytes-observed"),
            Some(&EvidenceValue::Unsigned(11))
        );
        assert!(value(evidence, "http.timing.ttfb-ms").is_some());
        assert!(value(evidence, "http.timing.total-ms").is_some());
        assert!(value(evidence, "http.header.set-cookie").is_none());
        assert_eq!(
            value(evidence, "http.cookie.name"),
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
            value(evidence, "http.response.body-bytes-observed"),
            Some(&EvidenceValue::Unsigned(4))
        );
        assert_eq!(
            value(evidence, "http.response.body-truncated"),
            Some(&EvidenceValue::Boolean(true))
        );
        assert_eq!(
            value(evidence, "http.response.body-sha256"),
            Some(&EvidenceValue::Text(format!(
                "{:x}",
                Sha256::digest(b"0123")
            )))
        );
        assert!(value(evidence, "http.response.body-sample").is_none());
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
            value(evidence, "http.response.status"),
            Some(&EvidenceValue::Unsigned(429))
        );
        assert_eq!(
            value(evidence, "http.rate-limit.detected"),
            Some(&EvidenceValue::Boolean(true))
        );
        assert_eq!(
            value(evidence, "http.rate-limit.advertised"),
            Some(&EvidenceValue::Boolean(true))
        );
        assert_eq!(
            value(evidence, "http.rate-limit.retry-after"),
            Some(&EvidenceValue::Unsigned(7))
        );
        assert_eq!(
            value(evidence, "http.rate-limit.remaining"),
            Some(&EvidenceValue::Unsigned(3))
        );
        assert_eq!(
            value(evidence, "http.rate-limit.limit"),
            Some(&EvidenceValue::Unsigned(100))
        );
    }

    #[tokio::test]
    async fn redirect_is_observed_without_following_the_location() {
        let url = serve_once(
            b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/outside\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
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
            value(evidence, "http.response.status"),
            Some(&EvidenceValue::Unsigned(302))
        );
        assert_eq!(
            value(evidence, "http.header.location"),
            Some(&EvidenceValue::Text(
                "http://127.0.0.1:9/outside".to_owned()
            ))
        );
        assert_eq!(
            value(evidence, "http.response.final-url"),
            Some(&EvidenceValue::Text(url.to_string()))
        );
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
        let executor = HttpEvidenceExecutor::new(policy, provider).unwrap();
        let mut registry = DecisionExecutorRegistry::new();
        registry.register(Arc::new(executor)).unwrap();
        let adapter = DecisionRunnerAdapter::new(registry);
        let knowledge = KnowledgeBase::new();

        let error = adapter
            .execute_command(&command(&allowed), &knowledge)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("outside policy"));
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
            HttpEvidencePolicy::new([url], Duration::from_secs(1), MAX_HTTP_BODY_LIMIT + 1),
            Err(HttpEvidenceError::BodyLimitTooLarge { .. })
        ));
    }
}
