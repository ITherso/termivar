//! Host-owned contract for source-linked native plugins.
//!
//! The opt-in `plugins` feature exposes a Rust trait boundary for trusted,
//! in-process extensions. A plugin receives a borrowed [`PluginContext`]; it
//! does not receive loose target/payload strings and cannot return findings or
//! outcomes. The host owns authorization, transport, resource limits,
//! cancellation, redaction, evidence provenance, and later verification.
//!
//! This is a cooperative capability contract, not a sandbox. Native plugin
//! code linked by a host can still use capabilities obtained outside this API.

use async_trait::async_trait;
use dashmap::{mapref::entry::Entry, DashMap};
use futures::FutureExt;
use regex::Regex;
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fmt,
    panic::AssertUnwindSafe,
    sync::{Arc, LazyLock, Mutex, MutexGuard},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio_util::sync::CancellationToken;
use url::Url;
use venom_core::{
    ConfidenceScore, EntityId, Evidence, EvidenceKind, EvidenceSource, EvidenceValue,
    KnowledgePredicate,
};

/// Source-level plugin API version supported by this host.
///
/// Preview compatibility requires the same major and minor components. The
/// `0.2` line intentionally replaces the loose-input/direct-finding `0.1`
/// contract.
pub const PLUGIN_API_VERSION: &str = "0.2.0";

const MAX_PLUGIN_ID_BYTES: usize = 128;
const MAX_PLUGIN_TEXT_BYTES: usize = 1024;
const MAX_PLUGIN_CASE_ID_BYTES: usize = 256;
const MAX_PLUGIN_REDACTION_LITERAL_COUNT: usize = 64;
const MAX_PLUGIN_REDACTION_LITERAL_BYTES: usize = 4096;
const MAX_PLUGIN_URL_BYTES: usize = 8192;
const MAX_PLUGIN_HEADERS: usize = 64;
const MAX_PLUGIN_HEADER_NAME_BYTES: usize = 128;
const MAX_PLUGIN_HEADER_VALUE_BYTES: usize = 4096;
const HARD_MAX_PLUGIN_INPUT_BYTES: usize = 1024 * 1024;
const HARD_MAX_PLUGIN_REQUESTS: u64 = 64;
const HARD_MAX_PLUGIN_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const HARD_MAX_PLUGIN_WALL_TIME: Duration = Duration::from_secs(300);
const HARD_MAX_PLUGIN_RESPONSE_BODY_BYTES: u64 = 1024 * 1024;
const HARD_MAX_PLUGIN_CUMULATIVE_BODY_BYTES: u64 = 4 * 1024 * 1024;
const HARD_MAX_PLUGIN_OBSERVATIONS: u64 = 256;
const HARD_MAX_PLUGIN_OBSERVATION_BYTES: u64 = 1024 * 1024;
const HARD_MAX_PLUGIN_TEXT_LIST_ITEMS: usize = 256;

/// Extension contract for source-linked native plugins.
///
/// Implementations record observations through [`PluginContext::record`] and
/// use [`PluginContext::request`] for host-authorized network work. Successful
/// completion grants no finding or verification authority.
#[async_trait]
pub trait Plugin: Send + Sync {
    /// Plugin API line targeted by this implementation.
    fn api_version(&self) -> &str {
        PLUGIN_API_VERSION
    }

    /// Stable plugin identity.
    fn id(&self) -> &str;

    /// Human-readable plugin name.
    fn name(&self) -> &str;

    /// Plugin implementation version.
    fn version(&self) -> &str;

    /// Human-readable description.
    fn description(&self) -> &str;

    /// Human-readable author or owner.
    fn author(&self) -> &str;

    /// Informational plugin category.
    fn category(&self) -> PluginCategory;

    /// Validates static plugin prerequisites before registration.
    fn validate(&self) -> Result<(), PluginError> {
        Ok(())
    }

    /// Executes one host-authorized invocation.
    async fn execute(&self, context: &PluginContext) -> Result<(), PluginError>;
}

/// Informational plugin categories; these do not assign severity or findings.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginCategory {
    /// Browser/reflection-related observation producer.
    XSS,
    /// Database-behavior observation producer.
    SQLi,
    /// File/path observation producer.
    LFI,
    /// XML observation producer.
    XXE,
    /// Server-side request behavior observation producer.
    SSRF,
    /// Template behavior observation producer.
    SSTI,
    /// Execution behavior observation producer.
    RCE,
    /// Host-defined observation producer.
    Custom,
}

impl PluginCategory {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::XSS => "xss",
            Self::SQLi => "sqli",
            Self::LFI => "lfi",
            Self::XXE => "xxe",
            Self::SSRF => "ssrf",
            Self::SSTI => "ssti",
            Self::RCE => "rce",
            Self::Custom => "custom",
        }
    }
}

/// Typed plugin-boundary failures.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PluginError {
    /// Plugin identity was not registered.
    #[error("plugin identity is not registered")]
    NotFound,
    /// Plugin identity is already registered.
    #[error("plugin identity is already registered")]
    DuplicateId,
    /// Plugin identity has an invocation in flight and cannot be removed.
    #[error("plugin identity has an invocation in flight")]
    InUse,
    /// Plugin descriptor, configuration, or request was invalid.
    #[error("invalid plugin configuration: {0}")]
    InvalidConfig(String),
    /// Plugin targets another Preview API line.
    #[error("incompatible plugin API version: expected {expected}, received {actual}")]
    IncompatibleApiVersion {
        /// Host API line.
        expected: String,
        /// Plugin API line.
        actual: String,
    },
    /// Host configuration disabled this plugin.
    #[error("plugin is disabled by host policy")]
    Disabled,
    /// Host cancelled the invocation.
    #[error("plugin invocation was cancelled")]
    Cancelled,
    /// The invocation crossed its wall-clock budget.
    #[error("plugin invocation exhausted its wall-clock budget")]
    WallTimeExceeded,
    /// One request crossed its timeout budget.
    #[error("plugin request exhausted its timeout budget")]
    RequestTimeout,
    /// Plugin code abandoned a polled request before the broker returned.
    #[error("plugin request was abandoned before a broker receipt")]
    RequestAbandoned,
    /// Input exceeded the immutable request budget.
    #[error("plugin input uses {actual} bytes; maximum is {maximum}")]
    InputBudgetExceeded {
        /// Actual bytes.
        actual: usize,
        /// Maximum bytes.
        maximum: usize,
    },
    /// Request dispatch count exceeded the immutable budget.
    #[error("plugin request budget is exhausted")]
    RequestBudgetExceeded,
    /// One response exceeded its delivered-body budget.
    #[error("plugin response delivered {actual} bytes; maximum is {maximum}")]
    ResponseBodyBudgetExceeded {
        /// Delivered bytes.
        actual: u64,
        /// Maximum bytes.
        maximum: u64,
    },
    /// The per-response budget grants no body-capture authority.
    #[error("plugin response body budget grants no capture authority")]
    ResponseBodyBudgetUnavailable,
    /// Invocation-wide delivered response bytes exceeded the budget.
    #[error("plugin cumulative response body budget is exhausted")]
    CumulativeBodyBudgetExceeded,
    /// Observation count exceeded the immutable budget.
    #[error("plugin observation count budget is exhausted")]
    ObservationBudgetExceeded,
    /// Observation text exceeded the immutable byte budget.
    #[error("plugin observation byte budget is exhausted")]
    ObservationBytesBudgetExceeded,
    /// A URL was outside the exact authorized HTTP(S) origin.
    #[error("plugin request is outside the authorized origin")]
    ScopeViolation,
    /// The host-owned broker rejected or failed a request.
    #[error("host plugin request broker failed: {0}")]
    BrokerFailure(String),
    /// Plugin logic returned a failure.
    #[error("plugin execution failed: {0}")]
    ExecutionFailed(String),
    /// Plugin code panicked in a registration callback or while executing.
    #[error("plugin code panicked at the host boundary")]
    Panicked,
    /// A host-supplied plugin policy callback panicked.
    #[error("host plugin policy callback panicked")]
    HostCallbackPanicked,
    /// Observation or request authority was already sealed.
    #[error("plugin context is sealed")]
    ContextSealed,
    /// System time was earlier than the Unix epoch.
    #[error("system clock is earlier than the Unix epoch")]
    ClockBeforeUnixEpoch,
    /// Internal synchronized state was poisoned.
    #[error("plugin host state is unavailable")]
    HostStateUnavailable,
}

/// Immutable invocation limits enforced by [`PluginContext`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PluginBudget {
    max_input_bytes: usize,
    max_requests: u64,
    request_timeout_ms: u64,
    max_wall_time_ms: u64,
    max_response_body_bytes: u64,
    max_cumulative_body_bytes: u64,
    max_observations: u64,
    max_observation_bytes: u64,
}

impl Default for PluginBudget {
    fn default() -> Self {
        Self {
            max_input_bytes: 64 * 1024,
            max_requests: 16,
            request_timeout_ms: 5_000,
            max_wall_time_ms: 30_000,
            max_response_body_bytes: 64 * 1024,
            max_cumulative_body_bytes: 256 * 1024,
            max_observations: 64,
            max_observation_bytes: 64 * 1024,
        }
    }
}

impl PluginBudget {
    /// Sets the input-byte ceiling. Zero allows only empty input.
    pub fn with_max_input_bytes(mut self, value: usize) -> Result<Self, PluginError> {
        if value > HARD_MAX_PLUGIN_INPUT_BYTES {
            return Err(invalid_config(
                "plugin input budget exceeds the hard maximum",
            ));
        }
        self.max_input_bytes = value;
        Ok(self)
    }

    /// Sets the request ceiling. Zero grants no transport authority.
    pub fn with_max_requests(mut self, value: u64) -> Result<Self, PluginError> {
        if value > HARD_MAX_PLUGIN_REQUESTS {
            return Err(invalid_config(
                "plugin request budget exceeds the hard maximum",
            ));
        }
        self.max_requests = value;
        Ok(self)
    }

    /// Sets the per-request timeout. Zero denies request dispatch.
    pub fn with_request_timeout(mut self, value: Duration) -> Result<Self, PluginError> {
        if value > HARD_MAX_PLUGIN_REQUEST_TIMEOUT {
            return Err(invalid_config(
                "plugin request timeout exceeds the hard maximum",
            ));
        }
        self.request_timeout_ms = duration_ms(value)?;
        Ok(self)
    }

    /// Sets the invocation wall budget. Zero denies plugin execution.
    pub fn with_max_wall_time(mut self, value: Duration) -> Result<Self, PluginError> {
        if value > HARD_MAX_PLUGIN_WALL_TIME {
            return Err(invalid_config(
                "plugin wall budget exceeds the hard maximum",
            ));
        }
        self.max_wall_time_ms = duration_ms(value)?;
        Ok(self)
    }

    /// Sets the delivered-body ceiling for one response.
    pub fn with_max_response_body_bytes(mut self, value: u64) -> Result<Self, PluginError> {
        if value > HARD_MAX_PLUGIN_RESPONSE_BODY_BYTES {
            return Err(invalid_config(
                "plugin response body budget exceeds the hard maximum",
            ));
        }
        self.max_response_body_bytes = value;
        Ok(self)
    }

    /// Sets the invocation-wide delivered response body ceiling.
    pub fn with_max_cumulative_body_bytes(mut self, value: u64) -> Result<Self, PluginError> {
        if value > HARD_MAX_PLUGIN_CUMULATIVE_BODY_BYTES {
            return Err(invalid_config(
                "plugin cumulative body budget exceeds the hard maximum",
            ));
        }
        self.max_cumulative_body_bytes = value;
        Ok(self)
    }

    /// Sets the maximum number of recorded observations.
    pub fn with_max_observations(mut self, value: u64) -> Result<Self, PluginError> {
        if value > HARD_MAX_PLUGIN_OBSERVATIONS {
            return Err(invalid_config(
                "plugin observation count exceeds the hard maximum",
            ));
        }
        self.max_observations = value;
        Ok(self)
    }

    /// Sets the aggregate raw observation-value byte ceiling.
    pub fn with_max_observation_bytes(mut self, value: u64) -> Result<Self, PluginError> {
        if value > HARD_MAX_PLUGIN_OBSERVATION_BYTES {
            return Err(invalid_config(
                "plugin observation byte budget exceeds the hard maximum",
            ));
        }
        self.max_observation_bytes = value;
        Ok(self)
    }

    /// Maximum input bytes.
    pub const fn max_input_bytes(&self) -> usize {
        self.max_input_bytes
    }

    /// Maximum broker dispatches.
    pub const fn max_requests(&self) -> u64 {
        self.max_requests
    }

    /// Per-request timeout.
    pub const fn request_timeout(&self) -> Duration {
        Duration::from_millis(self.request_timeout_ms)
    }

    /// Invocation wall budget.
    pub const fn max_wall_time(&self) -> Duration {
        Duration::from_millis(self.max_wall_time_ms)
    }

    /// Maximum delivered bytes for one response.
    pub const fn max_response_body_bytes(&self) -> u64 {
        self.max_response_body_bytes
    }

    /// Maximum invocation-wide delivered response bytes.
    pub const fn max_cumulative_body_bytes(&self) -> u64 {
        self.max_cumulative_body_bytes
    }

    /// Maximum observation count.
    pub const fn max_observations(&self) -> u64 {
        self.max_observations
    }

    /// Maximum raw observation-value bytes.
    pub const fn max_observation_bytes(&self) -> u64 {
        self.max_observation_bytes
    }
}

/// Host-owned registration configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PluginConfig {
    enabled: bool,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl PluginConfig {
    /// Creates host policy with the requested enable state.
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Returns whether host policy enables the plugin.
    pub const fn enabled(&self) -> bool {
        self.enabled
    }
}

/// Bodyless request methods exposed through the host broker.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PluginHttpMethod {
    /// Read a representation.
    Get,
    /// Read response metadata only.
    Head,
    /// Discover server-declared method support.
    Options,
}

/// Immutable request passed to the host-owned broker.
pub struct PluginHttpRequest {
    method: PluginHttpMethod,
    url: Url,
    max_response_body_bytes: u64,
    cancellation: CancellationToken,
}

impl PluginHttpRequest {
    /// Request method.
    pub const fn method(&self) -> PluginHttpMethod {
        self.method
    }

    /// Exact scoped URL.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Maximum response bytes the broker may read and retain for this request.
    ///
    /// The host derives this from both the per-response ceiling and the
    /// invocation-wide unreserved remainder. Brokers must stop body collection
    /// at this boundary and mark the response truncated when more data exists.
    pub const fn max_response_body_bytes(&self) -> u64 {
        self.max_response_body_bytes
    }

    /// Invocation-scoped cancellation signal.
    pub fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }
}

impl fmt::Debug for PluginHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginHttpRequest")
            .field("method", &self.method)
            .field("origin", &origin_string(&self.url))
            .field("path", &"[redacted]")
            .field("max_response_body_bytes", &self.max_response_body_bytes)
            .finish_non_exhaustive()
    }
}

/// Bounded response returned by a host-owned request broker.
pub struct PluginHttpResponse {
    status: u16,
    final_url: Url,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
    delivered_body_bytes: u64,
    body_truncated: bool,
}

impl PluginHttpResponse {
    /// Creates a response with no headers and exact retained/delivered length.
    pub fn new(status: u16, final_url: Url, body: Vec<u8>) -> Result<Self, PluginError> {
        if !(100..=599).contains(&status) {
            return Err(invalid_config(
                "plugin broker returned an invalid HTTP status",
            ));
        }
        if body.len() > HARD_MAX_PLUGIN_RESPONSE_BODY_BYTES as usize {
            return Err(PluginError::ResponseBodyBudgetExceeded {
                actual: u64::try_from(body.len()).unwrap_or(u64::MAX),
                maximum: HARD_MAX_PLUGIN_RESPONSE_BODY_BYTES,
            });
        }
        let delivered_body_bytes = u64::try_from(body.len()).unwrap_or(u64::MAX);
        Ok(Self {
            status,
            final_url,
            headers: BTreeMap::new(),
            body,
            delivered_body_bytes,
            body_truncated: false,
        })
    }

    /// Adds one bounded response header.
    pub fn with_header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, PluginError> {
        let name = name.into().to_ascii_lowercase();
        let value = value.into();
        validate_header(&name, &value)?;
        if !self.headers.contains_key(&name) && self.headers.len() >= MAX_PLUGIN_HEADERS {
            return Err(invalid_config(
                "plugin response header count exceeds the maximum",
            ));
        }
        self.headers.insert(name, value);
        Ok(self)
    }

    /// Sets delivered-byte accounting and truncation state reported by the host.
    pub fn with_capture_metadata(
        mut self,
        delivered_body_bytes: u64,
        body_truncated: bool,
    ) -> Result<Self, PluginError> {
        let retained = u64::try_from(self.body.len()).unwrap_or(u64::MAX);
        if delivered_body_bytes < retained {
            return Err(invalid_config(
                "delivered response bytes cannot be smaller than retained bytes",
            ));
        }
        if !body_truncated && delivered_body_bytes != retained {
            return Err(invalid_config(
                "an incomplete response body must be marked truncated",
            ));
        }
        self.delivered_body_bytes = delivered_body_bytes;
        self.body_truncated = body_truncated;
        Ok(self)
    }

    /// HTTP status.
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Final URL reported by the broker.
    pub fn final_url(&self) -> &Url {
        &self.final_url
    }

    /// Case-normalized response header value.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    /// Retained bounded body.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Bytes delivered by the broker before retention stopped.
    pub const fn delivered_body_bytes(&self) -> u64 {
        self.delivered_body_bytes
    }

    /// Whether the host truncated retention.
    pub const fn body_truncated(&self) -> bool {
        self.body_truncated
    }
}

impl fmt::Debug for PluginHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginHttpResponse")
            .field("status", &self.status)
            .field("final_origin", &origin_string(&self.final_url))
            .field("header_count", &self.headers.len())
            .field("retained_body_bytes", &self.body.len())
            .field("delivered_body_bytes", &self.delivered_body_bytes)
            .field("body_truncated", &self.body_truncated)
            .finish()
    }
}

/// Host-owned transport capability used by plugin contexts.
///
/// Implementations must not follow redirects or retry requests. They must stop
/// body collection at [`PluginHttpRequest::max_response_body_bytes`]. The
/// context independently checks the request and final response origin, capture
/// metadata, and immutable accounting envelope.
#[async_trait]
pub trait PluginRequestBroker: Send + Sync {
    /// Executes one already-scoped bodyless request.
    async fn execute(&self, request: PluginHttpRequest) -> Result<PluginHttpResponse, PluginError>;
}

/// Host redaction policy applied before any plugin observation becomes evidence.
pub trait PluginRedactionPolicy: Send + Sync {
    /// Returns a redacted replacement for untrusted observation text.
    fn redact(&self, value: &str) -> String;
}

/// Conservative redactor for common secret assignments plus host literals.
#[derive(Clone, Default)]
pub struct SecretRedactionPolicy {
    literals: Vec<String>,
}

impl SecretRedactionPolicy {
    /// Creates a policy with bounded, non-empty literal secrets to remove.
    pub fn new(literals: impl IntoIterator<Item = String>) -> Result<Self, PluginError> {
        let mut retained = Vec::new();
        for literal in literals {
            if literal.is_empty() || literal.len() > MAX_PLUGIN_REDACTION_LITERAL_BYTES {
                return Err(invalid_config("redaction literal is empty or too long"));
            }
            if retained.len() >= MAX_PLUGIN_REDACTION_LITERAL_COUNT {
                return Err(invalid_config("too many redaction literals"));
            }
            if !retained.contains(&literal) {
                retained.push(literal);
            }
        }
        retained.sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));
        Ok(Self { literals: retained })
    }
}

impl fmt::Debug for SecretRedactionPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretRedactionPolicy")
            .field("literal_count", &self.literals.len())
            .finish()
    }
}

impl PluginRedactionPolicy for SecretRedactionPolicy {
    fn redact(&self, value: &str) -> String {
        static ASSIGNMENTS: LazyLock<Option<Regex>> = LazyLock::new(|| {
            Regex::new(
                r"(?im)(authorization|proxy-authorization|cookie|set-cookie|api[-_]?key|token|password|secret)\s*[:=]\s*[^\r\n]*",
            )
            .ok()
        });

        let redacted = match ASSIGNMENTS.as_ref() {
            Some(pattern) => pattern.replace_all(value, "$1=[REDACTED]").into_owned(),
            None => "[REDACTED]".to_owned(),
        };
        redact_literals_once(&redacted, &self.literals)
    }
}

fn redact_literals_once(value: &str, literals: &[String]) -> String {
    const REDACTED: &str = "[REDACTED]";
    if literals.is_empty() {
        return value.to_owned();
    }

    // A byte mask keeps transient memory proportional to the already-bounded
    // input. Collecting every match range lets dense, overlapping literals
    // multiply memory before the recorder can enforce its retained-byte cap.
    let mut masked = vec![false; value.len()];
    for pattern in std::iter::once(REDACTED).chain(literals.iter().map(String::as_str)) {
        for (start, matched) in value.match_indices(pattern) {
            masked[start..start + matched.len()].fill(true);
        }
    }
    if !masked.iter().any(|is_masked| *is_masked) {
        return value.to_owned();
    }

    let mut output = String::with_capacity(value.len());
    let mut cursor = 0;
    while cursor < masked.len() {
        let start = cursor;
        let is_masked = masked[cursor];
        while cursor < masked.len() && masked[cursor] == is_masked {
            cursor += 1;
        }
        if is_masked {
            output.push_str(REDACTED);
        } else {
            output.push_str(&value[start..cursor]);
        }
    }
    output
}

/// Untrusted observation draft accepted by the host recorder.
pub struct PluginObservation {
    kind: EvidenceKind,
    predicate: KnowledgePredicate,
    value: EvidenceValue,
    method: String,
}

impl PluginObservation {
    /// Creates a bounded observation draft without subject or claim authority.
    pub fn new(
        kind: EvidenceKind,
        predicate: KnowledgePredicate,
        value: EvidenceValue,
        method: impl Into<String>,
    ) -> Result<Self, PluginError> {
        let method = method.into();
        validate_identifier(&method, "plugin observation method", MAX_PLUGIN_ID_BYTES)?;
        validate_identifier(
            predicate.namespace(),
            "plugin observation predicate namespace",
            MAX_PLUGIN_ID_BYTES,
        )?;
        validate_identifier(
            predicate.name(),
            "plugin observation predicate name",
            MAX_PLUGIN_ID_BYTES,
        )?;
        if let EvidenceKind::Custom(name) = &kind {
            validate_identifier(name, "plugin observation kind", MAX_PLUGIN_ID_BYTES)?;
        }
        validate_observation_value(&value)?;
        Ok(Self {
            kind,
            predicate,
            value,
            method,
        })
    }
}

impl fmt::Debug for PluginObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginObservation")
            .field("kind", &self.kind)
            .field("predicate", &self.predicate)
            .field("value", &"[redacted]")
            .field("method", &self.method)
            .finish()
    }
}

/// Host-created request for one plugin invocation.
pub struct PluginExecutionRequest {
    subject: EntityId,
    authorized_origin: Url,
    case_id: String,
    input: Vec<u8>,
    budget: PluginBudget,
    cancellation: CancellationToken,
    broker: Arc<dyn PluginRequestBroker>,
    redaction: Arc<dyn PluginRedactionPolicy>,
    reliability: ConfidenceScore,
}

impl PluginExecutionRequest {
    /// Creates a request with finite defaults, empty input, no confidence, and
    /// the default secret redaction policy.
    pub fn new(
        subject: EntityId,
        authorized_origin: Url,
        case_id: impl Into<String>,
        broker: Arc<dyn PluginRequestBroker>,
    ) -> Result<Self, PluginError> {
        validate_authorized_origin(&authorized_origin)?;
        let case_id = case_id.into();
        validate_identifier(&case_id, "plugin case id", MAX_PLUGIN_CASE_ID_BYTES)?;
        Ok(Self {
            subject,
            authorized_origin,
            case_id,
            input: Vec::new(),
            budget: PluginBudget::default(),
            cancellation: CancellationToken::new(),
            broker,
            redaction: Arc::new(SecretRedactionPolicy::default()),
            reliability: ConfidenceScore::NONE,
        })
    }

    /// Sets opaque bounded invocation input.
    pub fn with_input(mut self, input: Vec<u8>) -> Result<Self, PluginError> {
        ensure_input_budget(&input, &self.budget)?;
        self.input = input;
        Ok(self)
    }

    /// Replaces the immutable budget snapshot.
    pub fn with_budget(mut self, budget: PluginBudget) -> Result<Self, PluginError> {
        ensure_input_budget(&self.input, &budget)?;
        self.budget = budget;
        Ok(self)
    }

    /// Narrows response capture to a host execution allowance.
    ///
    /// This operation can only reduce both the per-response and cumulative
    /// ceilings already selected by the request provider.
    pub fn restrict_response_body_bytes(mut self, maximum: u64) -> Self {
        self.budget.max_response_body_bytes = self.budget.max_response_body_bytes.min(maximum);
        self.budget.max_cumulative_body_bytes = self.budget.max_cumulative_body_bytes.min(maximum);
        self
    }

    /// Uses a host-owned cancellation token; the invocation receives a child.
    pub fn with_cancellation(mut self, cancellation: CancellationToken) -> Self {
        self.cancellation = cancellation;
        self
    }

    /// Replaces the host redaction policy.
    pub fn with_redaction(mut self, redaction: Arc<dyn PluginRedactionPolicy>) -> Self {
        self.redaction = redaction;
        self
    }

    /// Sets host-assessed source reliability without granting claim authority.
    pub fn with_reliability(mut self, reliability: ConfidenceScore) -> Self {
        self.reliability = reliability;
        self
    }

    /// Authorized evidence subject selected by the host.
    pub fn subject(&self) -> &EntityId {
        &self.subject
    }

    /// Exact authorized HTTP(S) origin selected by the host.
    pub fn authorized_origin(&self) -> &Url {
        &self.authorized_origin
    }

    /// Host verification/correlation identity.
    pub fn case_id(&self) -> &str {
        &self.case_id
    }

    /// Opaque bounded input bytes.
    pub fn input(&self) -> &[u8] {
        &self.input
    }
}

impl fmt::Debug for PluginExecutionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginExecutionRequest")
            .field("subject", &"[redacted]")
            .field("authorized_origin", &origin_string(&self.authorized_origin))
            .field("case_id", &"[redacted]")
            .field("input_bytes", &self.input.len())
            .field("budget", &self.budget)
            .field("reliability", &self.reliability)
            .finish_non_exhaustive()
    }
}

/// Usage receipt for one completed plugin invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PluginUsage {
    requests: u64,
    response_body_bytes: u64,
    observations: u64,
    observation_bytes: u64,
}

impl PluginUsage {
    /// Broker dispatch attempts charged to the invocation.
    pub const fn requests(self) -> u64 {
        self.requests
    }

    /// Delivered response bytes charged to the invocation.
    pub const fn response_body_bytes(self) -> u64 {
        self.response_body_bytes
    }

    /// Evidence observations retained at successful completion.
    pub const fn observations(self) -> u64 {
        self.observations
    }

    /// Bounded observation-value representation bytes charged by the host.
    pub const fn observation_bytes(self) -> u64 {
        self.observation_bytes
    }
}

/// Successful execution receipt. Failures are returned as [`PluginError`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PluginExecutionResult {
    plugin_id: String,
    observations: Vec<Evidence>,
    usage: PluginUsage,
    elapsed_ms: u64,
}

impl PluginExecutionResult {
    /// Registered plugin identity.
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    /// Host-normalized evidence observations.
    pub fn observations(&self) -> &[Evidence] {
        &self.observations
    }

    /// Consumes the receipt and returns normalized observations.
    pub fn into_observations(self) -> Vec<Evidence> {
        self.observations
    }

    /// Bounded usage receipt.
    pub const fn usage(&self) -> PluginUsage {
        self.usage
    }

    /// Host-observed elapsed milliseconds.
    pub const fn elapsed_ms(&self) -> u64 {
        self.elapsed_ms
    }
}

struct PluginContextState {
    sealed: bool,
    failure: Option<PluginError>,
    requests: u64,
    response_body_bytes: u64,
    reserved_response_body_bytes: u64,
    observation_bytes: u64,
    observations: Vec<Evidence>,
}

/// Borrowed capability boundary for one plugin invocation.
///
/// The type intentionally does not implement `Clone`: request and recorder
/// authority remain structurally tied to the invocation future.
pub struct PluginContext {
    plugin_id: String,
    subject: EntityId,
    authorized_origin: Url,
    case_id: String,
    input: Vec<u8>,
    budget: PluginBudget,
    cancellation: CancellationToken,
    broker: Arc<dyn PluginRequestBroker>,
    redaction: Arc<dyn PluginRedactionPolicy>,
    reliability: ConfidenceScore,
    deadline: tokio::time::Instant,
    state: Mutex<PluginContextState>,
}

struct PluginRequestReservation<'a> {
    context: &'a PluginContext,
    capture_limit: u64,
    cancellation: CancellationToken,
    active: bool,
}

impl PluginRequestReservation<'_> {
    fn commit(mut self, delivered_body_bytes: u64) -> Result<(), PluginError> {
        {
            let mut state = self.context.lock_state()?;
            ensure_state_active(&state)?;
            let Some(reserved) = state
                .reserved_response_body_bytes
                .checked_sub(self.capture_limit)
            else {
                state.failure = Some(PluginError::HostStateUnavailable);
                return Err(PluginError::HostStateUnavailable);
            };
            if self.context.cancellation.is_cancelled() {
                return Err(PluginError::Cancelled);
            }
            if tokio::time::Instant::now() >= self.context.deadline {
                state.failure = Some(PluginError::WallTimeExceeded);
                return Err(PluginError::WallTimeExceeded);
            }
            let Some(cumulative) = state.response_body_bytes.checked_add(delivered_body_bytes)
            else {
                let error = PluginError::CumulativeBodyBudgetExceeded;
                state.failure = Some(error.clone());
                return Err(error);
            };
            if cumulative > self.context.budget.max_cumulative_body_bytes {
                let error = PluginError::CumulativeBodyBudgetExceeded;
                state.failure = Some(error.clone());
                return Err(error);
            }
            state.reserved_response_body_bytes = reserved;
            state.response_body_bytes = cumulative;
        }
        self.active = false;
        self.cancellation.cancel();
        Ok(())
    }
}

impl Drop for PluginRequestReservation<'_> {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if !self.active {
            return;
        }
        if let Ok(mut state) = self.context.state.lock() {
            match state
                .reserved_response_body_bytes
                .checked_sub(self.capture_limit)
            {
                Some(reserved) => state.reserved_response_body_bytes = reserved,
                None => state.failure = Some(PluginError::HostStateUnavailable),
            }
            if !state.sealed && state.failure.is_none() {
                state.failure = Some(PluginError::RequestAbandoned);
            }
        }
    }
}

impl PluginContext {
    fn from_request(
        plugin_id: String,
        request: PluginExecutionRequest,
    ) -> Result<Self, PluginError> {
        ensure_input_budget(&request.input, &request.budget)?;
        let now = tokio::time::Instant::now();
        let deadline = now
            .checked_add(request.budget.max_wall_time())
            .ok_or_else(|| invalid_config("plugin wall budget exceeds runtime clock range"))?;
        Ok(Self {
            plugin_id,
            subject: request.subject,
            authorized_origin: request.authorized_origin,
            case_id: request.case_id,
            input: request.input,
            budget: request.budget,
            cancellation: request.cancellation.child_token(),
            broker: request.broker,
            redaction: request.redaction,
            reliability: request.reliability,
            deadline,
            state: Mutex::new(PluginContextState {
                sealed: false,
                failure: None,
                requests: 0,
                response_body_bytes: 0,
                reserved_response_body_bytes: 0,
                observation_bytes: 0,
                observations: Vec::new(),
            }),
        })
    }

    /// Authorized evidence subject.
    pub fn subject(&self) -> &EntityId {
        &self.subject
    }

    /// Exact authorized HTTP(S) origin.
    pub fn authorized_origin(&self) -> &Url {
        &self.authorized_origin
    }

    /// Host verification/correlation identity.
    pub fn case_id(&self) -> &str {
        &self.case_id
    }

    /// Opaque host input bounded before plugin code is polled.
    pub fn input(&self) -> &[u8] {
        &self.input
    }

    /// Immutable resource budget.
    pub const fn budget(&self) -> &PluginBudget {
        &self.budget
    }

    /// Returns whether the host has cancelled this invocation.
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    /// Waits until the host cancels this invocation.
    pub async fn cancelled(&self) {
        self.cancellation.cancelled().await;
    }

    /// Records one observation; host provenance and redaction are mandatory.
    pub fn record(&self, observation: PluginObservation) -> Result<(), PluginError> {
        self.ensure_active()?;
        let raw_bytes = evidence_value_bytes(&observation.value);
        let redacted_value = match std::panic::catch_unwind(AssertUnwindSafe(|| {
            redact_value(self.redaction.as_ref(), observation.value)
        })) {
            Ok(value) => value,
            Err(_) => return self.fail(PluginError::HostCallbackPanicked),
        };
        let redacted_bytes = evidence_value_bytes(&redacted_value);
        if raw_bytes > self.budget.max_observation_bytes
            || redacted_bytes > self.budget.max_observation_bytes
        {
            return self.fail(PluginError::ObservationBytesBudgetExceeded);
        }
        let charged_bytes = raw_bytes.max(redacted_bytes);

        let source = EvidenceSource::new(self.plugin_id.clone(), observation.method)
            .and_then(|source| source.with_correlation_id(self.case_id.clone()))
            .map_err(|_| invalid_config("plugin observation provenance is invalid"))?;
        let evidence = Evidence::new(
            self.subject.clone(),
            observation.kind,
            observation.predicate,
            redacted_value,
            source,
            self.reliability,
        );

        let mut state = self.lock_state()?;
        ensure_state_active(&state)?;
        if state.observations.len() as u64 >= self.budget.max_observations {
            let error = PluginError::ObservationBudgetExceeded;
            state.failure = Some(error.clone());
            return Err(error);
        }
        let Some(next_bytes) = state.observation_bytes.checked_add(charged_bytes) else {
            let error = PluginError::ObservationBytesBudgetExceeded;
            state.failure = Some(error.clone());
            return Err(error);
        };
        if next_bytes > self.budget.max_observation_bytes {
            let error = PluginError::ObservationBytesBudgetExceeded;
            state.failure = Some(error.clone());
            return Err(error);
        }
        state.observation_bytes = next_bytes;
        state.observations.push(evidence);
        Ok(())
    }

    /// Dispatches one bodyless request through the host-owned bounded broker.
    pub async fn request(
        &self,
        method: PluginHttpMethod,
        url: Url,
    ) -> Result<PluginHttpResponse, PluginError> {
        if validate_scoped_url(&self.authorized_origin, &url).is_err() {
            return self.fail(PluginError::ScopeViolation);
        }
        if url.as_str().len() > MAX_PLUGIN_URL_BYTES {
            return self.fail(PluginError::ScopeViolation);
        }

        let capture_limit = {
            let mut state = self.lock_state()?;
            ensure_state_active(&state)?;
            if self.cancellation.is_cancelled() {
                return Err(PluginError::Cancelled);
            }
            if tokio::time::Instant::now() >= self.deadline {
                state.failure = Some(PluginError::WallTimeExceeded);
                return Err(PluginError::WallTimeExceeded);
            }
            if state.requests >= self.budget.max_requests {
                state.failure = Some(PluginError::RequestBudgetExceeded);
                return Err(PluginError::RequestBudgetExceeded);
            }
            let Some(committed_and_reserved) = state
                .response_body_bytes
                .checked_add(state.reserved_response_body_bytes)
            else {
                state.failure = Some(PluginError::CumulativeBodyBudgetExceeded);
                return Err(PluginError::CumulativeBodyBudgetExceeded);
            };
            let Some(remaining_cumulative) = self
                .budget
                .max_cumulative_body_bytes
                .checked_sub(committed_and_reserved)
            else {
                state.failure = Some(PluginError::CumulativeBodyBudgetExceeded);
                return Err(PluginError::CumulativeBodyBudgetExceeded);
            };
            if remaining_cumulative == 0 {
                state.failure = Some(PluginError::CumulativeBodyBudgetExceeded);
                return Err(PluginError::CumulativeBodyBudgetExceeded);
            }
            if self.budget.max_response_body_bytes == 0 {
                let error = PluginError::ResponseBodyBudgetUnavailable;
                state.failure = Some(error.clone());
                return Err(error);
            }
            let capture_limit = self
                .budget
                .max_response_body_bytes
                .min(remaining_cumulative);
            state.requests += 1;
            let Some(reserved) = state
                .reserved_response_body_bytes
                .checked_add(capture_limit)
            else {
                state.failure = Some(PluginError::CumulativeBodyBudgetExceeded);
                return Err(PluginError::CumulativeBodyBudgetExceeded);
            };
            state.reserved_response_body_bytes = reserved;
            capture_limit
        };

        let request_cancellation = self.cancellation.child_token();
        let reservation = PluginRequestReservation {
            context: self,
            capture_limit,
            cancellation: request_cancellation.clone(),
            active: true,
        };
        let request_timeout = self.budget.request_timeout();
        if request_timeout.is_zero() {
            return self.fail(PluginError::RequestTimeout);
        }
        let remaining = self
            .deadline
            .checked_duration_since(tokio::time::Instant::now())
            .unwrap_or(Duration::ZERO);
        if remaining.is_zero() {
            return self.fail(PluginError::WallTimeExceeded);
        }
        let timeout = request_timeout.min(remaining);
        let broker_request = PluginHttpRequest {
            method,
            url,
            max_response_body_bytes: capture_limit,
            cancellation: request_cancellation.clone(),
        };
        let broker = self.broker.execute(broker_request);
        tokio::pin!(broker);
        let sleep = tokio::time::sleep(timeout);
        tokio::pin!(sleep);

        let response = tokio::select! {
            biased;
            () = self.cancellation.cancelled() => {
                request_cancellation.cancel();
                return self.fail(PluginError::Cancelled);
            }
            () = &mut sleep => {
                request_cancellation.cancel();
                let error = if tokio::time::Instant::now() >= self.deadline {
                    PluginError::WallTimeExceeded
                } else {
                    PluginError::RequestTimeout
                };
                return self.fail(error);
            }
            result = &mut broker => match result {
                Ok(response) => response,
                Err(error) => {
                    let error = sanitize_error_safely(self.redaction.as_ref(), error)
                        .unwrap_or(PluginError::HostCallbackPanicked);
                    return self.fail(error);
                },
            },
        };

        if validate_scoped_url(&self.authorized_origin, response.final_url()).is_err()
            || response.final_url().as_str().len() > MAX_PLUGIN_URL_BYTES
        {
            return self.fail(PluginError::ScopeViolation);
        }
        if response.delivered_body_bytes > capture_limit {
            return self.fail(PluginError::ResponseBodyBudgetExceeded {
                actual: response.delivered_body_bytes,
                maximum: capture_limit,
            });
        }

        reservation.commit(response.delivered_body_bytes)?;
        Ok(response)
    }

    fn ensure_active(&self) -> Result<(), PluginError> {
        if self.cancellation.is_cancelled() {
            return Err(PluginError::Cancelled);
        }
        if tokio::time::Instant::now() >= self.deadline {
            return self.fail(PluginError::WallTimeExceeded);
        }
        let state = self.lock_state()?;
        ensure_state_active(&state)
    }

    fn fail<T>(&self, error: PluginError) -> Result<T, PluginError> {
        if let Ok(mut state) = self.state.lock() {
            if state.failure.is_none() {
                state.failure = Some(error.clone());
            }
        }
        Err(error)
    }

    fn discard(&self) {
        self.cancellation.cancel();
        if let Ok(mut state) = self.state.lock() {
            state.sealed = true;
            state.observations.clear();
        }
    }

    fn finish(&self) -> Result<(Vec<Evidence>, PluginUsage), PluginError> {
        let mut state = self.lock_state()?;
        ensure_state_active(&state)?;
        if self.cancellation.is_cancelled() {
            return Err(PluginError::Cancelled);
        }
        if tokio::time::Instant::now() >= self.deadline {
            return Err(PluginError::WallTimeExceeded);
        }
        if state.reserved_response_body_bytes != 0 {
            return Err(PluginError::RequestAbandoned);
        }
        state.sealed = true;
        let observations = std::mem::take(&mut state.observations);
        let usage = PluginUsage {
            requests: state.requests,
            response_body_bytes: state.response_body_bytes,
            observations: observations.len() as u64,
            observation_bytes: state.observation_bytes,
        };
        Ok((observations, usage))
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, PluginContextState>, PluginError> {
        self.state
            .lock()
            .map_err(|_| PluginError::HostStateUnavailable)
    }
}

impl fmt::Debug for PluginContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let usage = self.state.lock().ok().map(|state| PluginUsage {
            requests: state.requests,
            response_body_bytes: state.response_body_bytes,
            observations: state.observations.len() as u64,
            observation_bytes: state.observation_bytes,
        });
        formatter
            .debug_struct("PluginContext")
            .field("plugin_id", &self.plugin_id)
            .field("subject", &"[redacted]")
            .field("authorized_origin", &origin_string(&self.authorized_origin))
            .field("case_id", &"[redacted]")
            .field("input_bytes", &self.input.len())
            .field("budget", &self.budget)
            .field("usage", &usage)
            .finish_non_exhaustive()
    }
}

struct PluginStats {
    state: Mutex<PluginStatsState>,
}

#[derive(Default)]
struct PluginStatsState {
    execution_count: u64,
    success_count: u64,
    error_count: u64,
    active_invocations: u64,
}

impl PluginStats {
    fn acquire_invocation(self: &Arc<Self>) -> Result<PluginInvocationLease, PluginError> {
        let mut state = lock_stats(&self.state);
        state.active_invocations = state
            .active_invocations
            .checked_add(1)
            .ok_or(PluginError::HostStateUnavailable)?;
        Ok(PluginInvocationLease {
            stats: self.clone(),
        })
    }

    fn release_invocation(&self) {
        let mut state = lock_stats(&self.state);
        state.active_invocations = state.active_invocations.saturating_sub(1);
    }

    fn has_active_invocation(&self) -> bool {
        lock_stats(&self.state).active_invocations != 0
    }

    fn record_execution(&self) {
        let mut state = lock_stats(&self.state);
        state.execution_count = state.execution_count.saturating_add(1);
    }

    fn record_success(&self) {
        let mut state = lock_stats(&self.state);
        state.success_count = state.success_count.saturating_add(1);
    }

    fn record_error(&self) {
        let mut state = lock_stats(&self.state);
        state.error_count = state.error_count.saturating_add(1);
    }

    fn snapshot(&self) -> (u64, u64, u64) {
        let state = lock_stats(&self.state);
        (
            state.execution_count,
            state.success_count,
            state.error_count,
        )
    }
}

struct PluginInvocationLease {
    stats: Arc<PluginStats>,
}

impl Drop for PluginInvocationLease {
    fn drop(&mut self) {
        self.stats.release_invocation();
    }
}

fn lock_stats(state: &Mutex<PluginStatsState>) -> MutexGuard<'_, PluginStatsState> {
    match state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

struct PluginEntry {
    plugin: Arc<dyn Plugin>,
    config: PluginConfig,
    descriptor: PluginDescriptor,
    stats: Arc<PluginStats>,
}

#[derive(Clone)]
struct PluginDescriptor {
    id: String,
    name: String,
    version: String,
    description: String,
    author: String,
    category: PluginCategory,
    api_version: String,
    loaded_at: u64,
}

/// Consistent metadata snapshot from one registry entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PluginMetadata {
    id: String,
    name: String,
    version: String,
    description: String,
    author: String,
    category: PluginCategory,
    api_version: String,
    enabled: bool,
    loaded_at: u64,
    execution_count: u64,
    success_count: u64,
    error_count: u64,
}

impl PluginMetadata {
    /// Stable plugin identity.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Human-readable plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Plugin implementation version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Human-readable description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Human-readable author or owner.
    pub fn author(&self) -> &str {
        &self.author
    }

    /// Informational category.
    pub const fn category(&self) -> PluginCategory {
        self.category
    }

    /// Targeted plugin API line.
    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    /// Snapshotted host enable state.
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Registration timestamp in Unix seconds.
    pub const fn loaded_at(&self) -> u64 {
        self.loaded_at
    }

    /// Invocation attempts that reached execution policy.
    pub const fn execution_count(&self) -> u64 {
        self.execution_count
    }

    /// Cleanly completed invocations.
    pub const fn success_count(&self) -> u64 {
        self.success_count
    }

    /// Failed, timed-out, cancelled, or panicked invocations.
    pub const fn error_count(&self) -> u64 {
        self.error_count
    }
}

/// Atomic registry for source-linked native plugins.
#[derive(Default)]
pub struct PluginRegistry {
    entries: DashMap<String, PluginEntry>,
}

impl PluginRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one plugin and host configuration without replacement.
    pub fn register(
        &self,
        plugin: Arc<dyn Plugin>,
        config: PluginConfig,
    ) -> Result<(), PluginError> {
        self.register_at(plugin, config, SystemTime::now())
    }

    fn register_at(
        &self,
        plugin: Arc<dyn Plugin>,
        config: PluginConfig,
        now: SystemTime,
    ) -> Result<(), PluginError> {
        let descriptor = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let descriptor = plugin_descriptor(plugin.as_ref(), now)?;
            validate_plugin_descriptor(&descriptor)?;
            validate_api_version(&descriptor.api_version)?;
            plugin
                .validate()
                .map_err(|_| invalid_config("plugin validation failed"))?;
            Ok(descriptor)
        }))
        .map_err(|_| PluginError::Panicked)??;
        let id = descriptor.id.clone();
        let entry = PluginEntry {
            plugin,
            config,
            descriptor,
            stats: Arc::new(PluginStats {
                state: Mutex::new(PluginStatsState::default()),
            }),
        };
        match self.entries.entry(id) {
            Entry::Vacant(slot) => {
                slot.insert(entry);
                Ok(())
            },
            Entry::Occupied(_) => Err(PluginError::DuplicateId),
        }
    }

    /// Removes one plugin and its inseparable configuration/metadata entry.
    pub fn unregister(&self, plugin_id: &str) -> Result<(), PluginError> {
        if plugin_id.is_empty() || plugin_id.len() > MAX_PLUGIN_ID_BYTES {
            return Err(PluginError::NotFound);
        }
        match self.entries.entry(plugin_id.to_owned()) {
            Entry::Occupied(entry) if entry.get().stats.has_active_invocation() => {
                Err(PluginError::InUse)
            },
            Entry::Occupied(entry) => {
                entry.remove();
                Ok(())
            },
            Entry::Vacant(_) => Err(PluginError::NotFound),
        }
    }

    /// Returns the registered plugin trait object.
    pub fn get(&self, plugin_id: &str) -> Option<Arc<dyn Plugin>> {
        self.entries
            .get(plugin_id)
            .map(|entry| entry.plugin.clone())
    }

    /// Returns one consistent metadata snapshot.
    pub fn get_metadata(&self, plugin_id: &str) -> Option<PluginMetadata> {
        self.entries
            .get(plugin_id)
            .map(|entry| metadata_snapshot(&entry))
    }

    /// Returns one consistent host-configuration snapshot.
    pub fn get_config(&self, plugin_id: &str) -> Option<PluginConfig> {
        self.entries
            .get(plugin_id)
            .map(|entry| entry.config.clone())
    }

    /// Replaces host policy atomically for future invocations.
    pub fn update_config(&self, plugin_id: &str, config: PluginConfig) -> Result<(), PluginError> {
        let mut entry = self
            .entries
            .get_mut(plugin_id)
            .ok_or(PluginError::NotFound)?;
        entry.config = config;
        Ok(())
    }

    /// Executes one invocation and returns observation evidence only.
    pub async fn execute(
        &self,
        plugin_id: &str,
        request: PluginExecutionRequest,
    ) -> Result<PluginExecutionResult, PluginError> {
        let (plugin, stats, _invocation_lease) = {
            let entry = self.entries.get(plugin_id).ok_or(PluginError::NotFound)?;
            if !entry.config.enabled {
                return Err(PluginError::Disabled);
            }
            let stats = entry.stats.clone();
            let lease = stats.acquire_invocation()?;
            (entry.plugin.clone(), stats, lease)
        };

        let context = PluginContext::from_request(plugin_id.to_owned(), request)?;
        context.ensure_active()?;
        stats.record_execution();
        let started = Instant::now();
        let plugin_future =
            match std::panic::catch_unwind(AssertUnwindSafe(|| plugin.execute(&context))) {
                Ok(future) => future,
                Err(_) => {
                    context.discard();
                    stats.record_error();
                    return Err(PluginError::Panicked);
                },
            };
        let mut execution = Some(Box::pin(AssertUnwindSafe(plugin_future).catch_unwind()));
        let wall = tokio::time::sleep_until(context.deadline);
        tokio::pin!(wall);

        let completion = match execution.as_mut() {
            Some(execution_future) => tokio::select! {
                biased;
                () = context.cancellation.cancelled() => Err(PluginError::Cancelled),
                () = &mut wall => Err(PluginError::WallTimeExceeded),
                result = execution_future.as_mut() => match result {
                    Ok(result) => match result {
                        Ok(()) => Ok(()),
                        Err(error) => Err(sanitize_error_safely(context.redaction.as_ref(), error)
                            .unwrap_or(PluginError::HostCallbackPanicked)),
                    },
                    Err(_) => Err(PluginError::Panicked),
                },
            },
            None => Err(PluginError::HostStateUnavailable),
        };
        let drop_result = std::panic::catch_unwind(AssertUnwindSafe(|| drop(execution.take())));
        if drop_result.is_err() {
            context.discard();
            stats.record_error();
            return Err(PluginError::Panicked);
        }

        if let Err(error) = completion {
            context.discard();
            stats.record_error();
            return Err(error);
        }

        match context.finish() {
            Ok((observations, usage)) => {
                stats.record_success();
                Ok(PluginExecutionResult {
                    plugin_id: plugin_id.to_owned(),
                    observations,
                    usage,
                    elapsed_ms: elapsed_ms(started),
                })
            },
            Err(error) => {
                context.discard();
                stats.record_error();
                Err(error)
            },
        }
    }

    /// Lists consistent metadata snapshots in plugin-ID order.
    pub fn list_all(&self) -> Vec<PluginMetadata> {
        let mut metadata: Vec<_> = self
            .entries
            .iter()
            .map(|entry| metadata_snapshot(&entry))
            .collect();
        metadata.sort_by(|left, right| left.id.cmp(&right.id));
        metadata
    }

    /// Lists consistent metadata snapshots for one category.
    pub fn list_by_category(&self, category: PluginCategory) -> Vec<PluginMetadata> {
        self.list_all()
            .into_iter()
            .filter(|metadata| metadata.category == category)
            .collect()
    }

    /// Registered plugin count.
    pub fn count(&self) -> usize {
        self.entries.len()
    }
}

fn metadata_snapshot(entry: &PluginEntry) -> PluginMetadata {
    let (execution_count, success_count, error_count) = entry.stats.snapshot();
    PluginMetadata {
        id: entry.descriptor.id.clone(),
        name: entry.descriptor.name.clone(),
        version: entry.descriptor.version.clone(),
        description: entry.descriptor.description.clone(),
        author: entry.descriptor.author.clone(),
        category: entry.descriptor.category,
        api_version: entry.descriptor.api_version.clone(),
        enabled: entry.config.enabled,
        loaded_at: entry.descriptor.loaded_at,
        execution_count,
        success_count,
        error_count,
    }
}

fn plugin_descriptor(
    plugin: &dyn Plugin,
    now: SystemTime,
) -> Result<PluginDescriptor, PluginError> {
    let loaded_at = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PluginError::ClockBeforeUnixEpoch)?
        .as_secs();
    Ok(PluginDescriptor {
        id: plugin.id().to_owned(),
        name: plugin.name().to_owned(),
        version: plugin.version().to_owned(),
        description: plugin.description().to_owned(),
        author: plugin.author().to_owned(),
        category: plugin.category(),
        api_version: plugin.api_version().to_owned(),
        loaded_at,
    })
}

fn validate_plugin_descriptor(descriptor: &PluginDescriptor) -> Result<(), PluginError> {
    validate_identifier(&descriptor.id, "plugin id", MAX_PLUGIN_ID_BYTES)?;
    validate_text(&descriptor.name, "plugin name")?;
    validate_identifier(&descriptor.version, "plugin version", MAX_PLUGIN_ID_BYTES)?;
    validate_text(&descriptor.description, "plugin description")?;
    validate_text(&descriptor.author, "plugin author")?;
    Ok(())
}

fn validate_api_version(actual: &str) -> Result<(), PluginError> {
    fn line(version: &str) -> Option<(u64, u64)> {
        let mut parts = version.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let _patch: u64 = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some((major, minor))
    }
    let actual_line = line(actual);
    if actual_line.is_some() && actual_line == line(PLUGIN_API_VERSION) {
        Ok(())
    } else {
        Err(PluginError::IncompatibleApiVersion {
            expected: PLUGIN_API_VERSION.to_owned(),
            actual: if actual_line.is_some() && actual.len() <= 32 {
                actual.to_owned()
            } else {
                "[invalid]".to_owned()
            },
        })
    }
}

fn validate_authorized_origin(origin: &Url) -> Result<(), PluginError> {
    if !matches!(origin.scheme(), "http" | "https")
        || origin.host_str().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
        || origin.as_str().len() > MAX_PLUGIN_URL_BYTES
    {
        return Err(PluginError::ScopeViolation);
    }
    Ok(())
}

fn validate_scoped_url(origin: &Url, url: &Url) -> Result<(), PluginError> {
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.origin() != origin.origin()
    {
        return Err(PluginError::ScopeViolation);
    }
    Ok(())
}

fn origin_string(url: &Url) -> String {
    url.origin().ascii_serialization()
}

fn validate_header(name: &str, value: &str) -> Result<(), PluginError> {
    if name.is_empty()
        || name.len() > MAX_PLUGIN_HEADER_NAME_BYTES
        || value.len() > MAX_PLUGIN_HEADER_VALUE_BYTES
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || value.contains(['\r', '\n'])
    {
        return Err(invalid_config("plugin response header is invalid"));
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str, max: usize) -> Result<(), PluginError> {
    if value.is_empty()
        || value.len() > max
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'/')
        })
    {
        return Err(invalid_config(field));
    }
    Ok(())
}

fn validate_text(value: &str, field: &'static str) -> Result<(), PluginError> {
    if value.trim().is_empty() || value.len() > MAX_PLUGIN_TEXT_BYTES {
        return Err(invalid_config(field));
    }
    Ok(())
}

fn ensure_input_budget(input: &[u8], budget: &PluginBudget) -> Result<(), PluginError> {
    if input.len() > budget.max_input_bytes {
        return Err(PluginError::InputBudgetExceeded {
            actual: input.len(),
            maximum: budget.max_input_bytes,
        });
    }
    Ok(())
}

fn duration_ms(duration: Duration) -> Result<u64, PluginError> {
    let milliseconds = u64::try_from(duration.as_millis())
        .map_err(|_| invalid_config("plugin duration exceeds supported milliseconds"))?;
    if !duration.is_zero() && milliseconds == 0 {
        return Err(invalid_config(
            "sub-millisecond plugin durations are unsupported",
        ));
    }
    Ok(milliseconds)
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn ensure_state_active(state: &PluginContextState) -> Result<(), PluginError> {
    if state.sealed {
        return Err(PluginError::ContextSealed);
    }
    if let Some(error) = &state.failure {
        return Err(error.clone());
    }
    Ok(())
}

fn validate_observation_value(value: &EvidenceValue) -> Result<(), PluginError> {
    match value {
        EvidenceValue::Text(text) => {
            if text.len() as u64 > HARD_MAX_PLUGIN_OBSERVATION_BYTES {
                return Err(PluginError::ObservationBytesBudgetExceeded);
            }
        },
        EvidenceValue::TextList(items) => {
            if items.len() > HARD_MAX_PLUGIN_TEXT_LIST_ITEMS
                || evidence_value_bytes(value) > HARD_MAX_PLUGIN_OBSERVATION_BYTES
            {
                return Err(PluginError::ObservationBytesBudgetExceeded);
            }
        },
        EvidenceValue::Boolean(_) | EvidenceValue::Signed(_) | EvidenceValue::Unsigned(_) => {},
        _ => return Err(PluginError::ObservationBytesBudgetExceeded),
    }
    Ok(())
}

fn evidence_value_bytes(value: &EvidenceValue) -> u64 {
    match value {
        EvidenceValue::Boolean(_) => 1,
        EvidenceValue::Signed(_) | EvidenceValue::Unsigned(_) => 8,
        EvidenceValue::Text(text) => {
            8_u64.saturating_add(u64::try_from(text.len()).unwrap_or(u64::MAX))
        },
        EvidenceValue::TextList(items) => items.iter().fold(8_u64, |total, item| {
            total
                .saturating_add(8)
                .saturating_add(u64::try_from(item.len()).unwrap_or(u64::MAX))
        }),
        _ => u64::MAX,
    }
}

fn redact_value(policy: &dyn PluginRedactionPolicy, value: EvidenceValue) -> EvidenceValue {
    match value {
        EvidenceValue::Text(text) => EvidenceValue::Text(policy.redact(&text)),
        EvidenceValue::TextList(items) => {
            EvidenceValue::TextList(items.into_iter().map(|item| policy.redact(&item)).collect())
        },
        other => other,
    }
}

fn sanitize_error(policy: &dyn PluginRedactionPolicy, error: PluginError) -> PluginError {
    match error {
        PluginError::InvalidConfig(_) => PluginError::InvalidConfig(redact_host_detail(
            policy,
            "plugin rejected its configuration",
        )),
        PluginError::ExecutionFailed(_) => {
            PluginError::ExecutionFailed(redact_host_detail(policy, "plugin execution failed"))
        },
        PluginError::BrokerFailure(_) => PluginError::BrokerFailure(redact_host_detail(
            policy,
            "host plugin request broker failed",
        )),
        PluginError::IncompatibleApiVersion { .. } => PluginError::IncompatibleApiVersion {
            expected: PLUGIN_API_VERSION.to_owned(),
            actual: "[invalid]".to_owned(),
        },
        other => other,
    }
}

fn sanitize_error_safely(
    policy: &dyn PluginRedactionPolicy,
    error: PluginError,
) -> Result<PluginError, PluginError> {
    std::panic::catch_unwind(AssertUnwindSafe(|| sanitize_error(policy, error)))
        .map_err(|_| PluginError::HostCallbackPanicked)
}

fn redact_host_detail(policy: &dyn PluginRedactionPolicy, value: &'static str) -> String {
    bounded_detail(&policy.redact(value))
}

fn bounded_detail(value: &str) -> String {
    let mut end = value.len().min(MAX_PLUGIN_TEXT_BYTES);
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    value[..end].to_owned()
}

fn invalid_config(detail: &'static str) -> PluginError {
    PluginError::InvalidConfig(detail.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Barrier,
    };

    struct StaticBroker {
        calls: AtomicUsize,
        response: Mutex<Option<Result<PluginHttpResponse, PluginError>>>,
        delay: Duration,
    }

    impl StaticBroker {
        fn success(origin: &Url, body: &[u8]) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                response: Mutex::new(Some(Ok(PluginHttpResponse::new(
                    200,
                    origin.clone(),
                    body.to_vec(),
                )
                .expect("valid response")))),
                delay: Duration::ZERO,
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl PluginRequestBroker for StaticBroker {
        async fn execute(
            &self,
            _request: PluginHttpRequest,
        ) -> Result<PluginHttpResponse, PluginError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            self.response
                .lock()
                .map_err(|_| PluginError::HostStateUnavailable)?
                .take()
                .unwrap_or_else(|| Err(PluginError::BrokerFailure("no response".to_owned())))
        }
    }

    #[derive(Clone, Copy)]
    enum Behavior {
        Record,
        RecordThenPending,
        RecordThenPanic,
        Request,
        ErrorAfterRecord,
        ErrorOnly,
        LongSecretError,
        IncompatibleError,
        Pending,
        Empty,
    }

    struct TestPlugin {
        id: String,
        api: String,
        calls: Arc<AtomicUsize>,
        behavior: Behavior,
    }

    #[async_trait]
    impl Plugin for TestPlugin {
        fn api_version(&self) -> &str {
            &self.api
        }

        fn id(&self) -> &str {
            &self.id
        }

        fn name(&self) -> &str {
            "Trait Boundary Fixture"
        }

        fn version(&self) -> &str {
            "0.1.0"
        }

        fn description(&self) -> &str {
            "Records an informational observation for contract tests"
        }

        fn author(&self) -> &str {
            "Venom tests"
        }

        fn category(&self) -> PluginCategory {
            PluginCategory::Custom
        }

        async fn execute(&self, context: &PluginContext) -> Result<(), PluginError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match self.behavior {
                Behavior::Record
                | Behavior::RecordThenPending
                | Behavior::RecordThenPanic
                | Behavior::ErrorAfterRecord => {
                    context.record(observation(EvidenceValue::Text(
                        String::from_utf8_lossy(context.input()).into_owned(),
                    )))?;
                    if matches!(self.behavior, Behavior::ErrorAfterRecord) {
                        return Err(PluginError::ExecutionFailed(
                            "token=fixture-secret".to_owned(),
                        ));
                    }
                    if matches!(self.behavior, Behavior::RecordThenPending) {
                        std::future::pending::<()>().await;
                    }
                    if matches!(self.behavior, Behavior::RecordThenPanic) {
                        panic!("plugin fixture panic after staged evidence");
                    }
                },
                Behavior::ErrorOnly => {
                    return Err(PluginError::ExecutionFailed(
                        "plugin error for host sanitization".to_owned(),
                    ));
                },
                Behavior::LongSecretError => {
                    return Err(PluginError::ExecutionFailed(
                        "s".repeat(MAX_PLUGIN_TEXT_BYTES + 1),
                    ));
                },
                Behavior::IncompatibleError => {
                    return Err(PluginError::IncompatibleApiVersion {
                        expected: format!(
                            "token=plugin-secret{}",
                            "x".repeat(MAX_PLUGIN_TEXT_BYTES * 4)
                        ),
                        actual: "token=plugin-actual-secret".to_owned(),
                    });
                },
                Behavior::Request => {
                    let url = context
                        .authorized_origin()
                        .join("fixture")
                        .map_err(|_| invalid_config("fixture URL"))?;
                    let response = context.request(PluginHttpMethod::Get, url).await?;
                    context.record(observation(EvidenceValue::Unsigned(u64::from(
                        response.status(),
                    ))))?;
                },
                Behavior::Pending => std::future::pending::<()>().await,
                Behavior::Empty => {},
            }
            Ok(())
        }
    }

    fn plugin(id: &str, behavior: Behavior) -> (Arc<TestPlugin>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Arc::new(TestPlugin {
                id: id.to_owned(),
                api: PLUGIN_API_VERSION.to_owned(),
                calls: calls.clone(),
                behavior,
            }),
            calls,
        )
    }

    fn origin() -> Url {
        Url::parse("https://example.test/").expect("valid origin")
    }

    fn request(broker: Arc<dyn PluginRequestBroker>) -> PluginExecutionRequest {
        PluginExecutionRequest::new(
            EntityId::new("authorized-origin:test").expect("valid subject"),
            origin(),
            "case:plugin:test",
            broker,
        )
        .expect("valid request")
    }

    fn observation(value: EvidenceValue) -> PluginObservation {
        PluginObservation::new(
            EvidenceKind::Custom("plugin.fixture".to_owned()),
            KnowledgePredicate::new("plugin.fixture", "marker").expect("valid predicate"),
            value,
            "trait-boundary",
        )
        .expect("valid observation")
    }

    #[test]
    fn api_line_and_clock_fail_closed() {
        let registry = PluginRegistry::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let incompatible = Arc::new(TestPlugin {
            id: "old-api".to_owned(),
            api: "0.1.9".to_owned(),
            calls,
            behavior: Behavior::Empty,
        });
        assert!(matches!(
            registry.register(incompatible, PluginConfig::default()),
            Err(PluginError::IncompatibleApiVersion { .. })
        ));

        let (before_epoch, _) = plugin("clock", Behavior::Empty);
        assert_eq!(
            registry.register_at(
                before_epoch,
                PluginConfig::default(),
                UNIX_EPOCH - Duration::from_secs(1),
            ),
            Err(PluginError::ClockBeforeUnixEpoch)
        );
        assert_eq!(registry.count(), 0);

        struct PanickingDescriptor;
        #[async_trait]
        impl Plugin for PanickingDescriptor {
            fn id(&self) -> &str {
                panic!("descriptor panic")
            }
            fn name(&self) -> &str {
                "Panicking Fixture"
            }
            fn version(&self) -> &str {
                "0.1.0"
            }
            fn description(&self) -> &str {
                "Exercises registration panic isolation"
            }
            fn author(&self) -> &str {
                "Venom tests"
            }
            fn category(&self) -> PluginCategory {
                PluginCategory::Custom
            }
            async fn execute(&self, _context: &PluginContext) -> Result<(), PluginError> {
                Ok(())
            }
        }
        assert_eq!(
            registry.register(Arc::new(PanickingDescriptor), PluginConfig::default()),
            Err(PluginError::Panicked)
        );
        assert_eq!(registry.count(), 0);

        struct PanickingValidation;
        #[async_trait]
        impl Plugin for PanickingValidation {
            fn id(&self) -> &str {
                "panicking-validation"
            }
            fn name(&self) -> &str {
                "Panicking Validation Fixture"
            }
            fn version(&self) -> &str {
                "0.1.0"
            }
            fn description(&self) -> &str {
                "Exercises validation panic isolation"
            }
            fn author(&self) -> &str {
                "Venom tests"
            }
            fn category(&self) -> PluginCategory {
                PluginCategory::Custom
            }
            fn validate(&self) -> Result<(), PluginError> {
                panic!("validation panic")
            }
            async fn execute(&self, _context: &PluginContext) -> Result<(), PluginError> {
                Ok(())
            }
        }
        assert_eq!(
            registry.register(Arc::new(PanickingValidation), PluginConfig::default()),
            Err(PluginError::Panicked)
        );
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn registration_snapshots_each_descriptor_field_once() {
        struct FlappingDescriptor {
            api_calls: AtomicUsize,
            id_calls: AtomicUsize,
            name_calls: AtomicUsize,
            version_calls: AtomicUsize,
            description_calls: AtomicUsize,
            author_calls: AtomicUsize,
            category_calls: AtomicUsize,
            validate_calls: AtomicUsize,
        }

        #[async_trait]
        impl Plugin for FlappingDescriptor {
            fn api_version(&self) -> &str {
                if self.api_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    PLUGIN_API_VERSION
                } else {
                    "0.1.0"
                }
            }

            fn id(&self) -> &str {
                if self.id_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    "flapping-descriptor"
                } else {
                    ""
                }
            }

            fn name(&self) -> &str {
                if self.name_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    "Flapping Descriptor"
                } else {
                    ""
                }
            }

            fn version(&self) -> &str {
                if self.version_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    "1.0.0"
                } else {
                    ""
                }
            }

            fn description(&self) -> &str {
                if self.description_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    "Proves one-shot descriptor capture"
                } else {
                    ""
                }
            }

            fn author(&self) -> &str {
                if self.author_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    "Venom tests"
                } else {
                    ""
                }
            }

            fn category(&self) -> PluginCategory {
                if self.category_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    PluginCategory::Custom
                } else {
                    PluginCategory::RCE
                }
            }

            fn validate(&self) -> Result<(), PluginError> {
                self.validate_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }

            async fn execute(&self, _context: &PluginContext) -> Result<(), PluginError> {
                Ok(())
            }
        }

        let plugin = Arc::new(FlappingDescriptor {
            api_calls: AtomicUsize::new(0),
            id_calls: AtomicUsize::new(0),
            name_calls: AtomicUsize::new(0),
            version_calls: AtomicUsize::new(0),
            description_calls: AtomicUsize::new(0),
            author_calls: AtomicUsize::new(0),
            category_calls: AtomicUsize::new(0),
            validate_calls: AtomicUsize::new(0),
        });
        let registry = PluginRegistry::new();
        registry
            .register(plugin.clone(), PluginConfig::default())
            .expect("the first descriptor snapshot is valid");

        let metadata = registry
            .get_metadata("flapping-descriptor")
            .expect("snapshotted descriptor is registered");
        assert_eq!(metadata.api_version(), PLUGIN_API_VERSION);
        assert_eq!(metadata.name(), "Flapping Descriptor");
        assert_eq!(metadata.category(), PluginCategory::Custom);
        for calls in [
            &plugin.api_calls,
            &plugin.id_calls,
            &plugin.name_calls,
            &plugin.version_calls,
            &plugin.description_calls,
            &plugin.author_calls,
            &plugin.category_calls,
            &plugin.validate_calls,
        ] {
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn duplicate_registration_is_atomic_under_concurrency() {
        let registry = Arc::new(PluginRegistry::new());
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let registry = registry.clone();
            let barrier = barrier.clone();
            workers.push(std::thread::spawn(move || {
                let (candidate, _) = plugin("duplicate", Behavior::Empty);
                barrier.wait();
                registry.register(candidate, PluginConfig::default())
            }));
        }
        barrier.wait();
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker did not panic"))
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(PluginError::DuplicateId)))
                .count(),
            1
        );
        assert_eq!(registry.count(), 1);
        assert_eq!(registry.list_all().len(), 1);
    }

    #[tokio::test]
    async fn disabled_plugin_is_never_polled_and_metadata_stays_consistent() {
        let registry = PluginRegistry::new();
        let (candidate, calls) = plugin("disabled", Behavior::Record);
        registry
            .register(candidate, PluginConfig::new(false))
            .expect("registration succeeds");
        let broker = StaticBroker::success(&origin(), b"");
        assert_eq!(
            registry.execute("disabled", request(broker)).await,
            Err(PluginError::Disabled)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let metadata = registry.get_metadata("disabled").expect("metadata");
        assert!(!metadata.enabled());
        assert_eq!(metadata.execution_count(), 0);
        assert_eq!(metadata.success_count(), 0);
        assert_eq!(metadata.error_count(), 0);
    }

    #[tokio::test]
    async fn active_invocation_leases_prevent_unregister_reregister_aba() {
        struct HoldingPlugin {
            entered: Arc<tokio::sync::Notify>,
            release: Arc<tokio::sync::Notify>,
        }
        #[async_trait]
        impl Plugin for HoldingPlugin {
            fn id(&self) -> &str {
                "leased"
            }
            fn name(&self) -> &str {
                "Invocation Lease Fixture"
            }
            fn version(&self) -> &str {
                "0.1.0"
            }
            fn description(&self) -> &str {
                "Holds one invocation while registry mutation is attempted"
            }
            fn author(&self) -> &str {
                "Venom tests"
            }
            fn category(&self) -> PluginCategory {
                PluginCategory::Custom
            }
            async fn execute(&self, context: &PluginContext) -> Result<(), PluginError> {
                self.entered.notify_one();
                self.release.notified().await;
                context.record(observation(EvidenceValue::Text(
                    String::from_utf8_lossy(context.input()).into_owned(),
                )))
            }
        }

        let registry = Arc::new(PluginRegistry::new());
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        registry
            .register(
                Arc::new(HoldingPlugin {
                    entered: entered.clone(),
                    release: release.clone(),
                }),
                PluginConfig::default(),
            )
            .expect("registration succeeds");
        let invocation_registry = registry.clone();
        let invocation = tokio::spawn(async move {
            invocation_registry
                .execute(
                    "leased",
                    request(StaticBroker::success(&origin(), b""))
                        .with_input(b"original-entry".to_vec())
                        .expect("input"),
                )
                .await
        });
        entered.notified().await;

        assert_eq!(registry.unregister("leased"), Err(PluginError::InUse));
        let (replacement, replacement_calls) = plugin("leased", Behavior::Record);
        assert_eq!(
            registry.register(replacement, PluginConfig::default()),
            Err(PluginError::DuplicateId)
        );
        assert_eq!(replacement_calls.load(Ordering::SeqCst), 0);
        let active_metadata = registry.get_metadata("leased").expect("metadata");
        assert_eq!(active_metadata.execution_count(), 1);
        assert_eq!(active_metadata.success_count(), 0);
        assert_eq!(active_metadata.error_count(), 0);

        release.notify_one();
        let result = invocation
            .await
            .expect("invocation task did not panic")
            .expect("original invocation succeeds");
        assert_eq!(result.plugin_id(), "leased");
        let serialized = serde_json::to_string(&result).expect("result serializes");
        assert!(serialized.contains("original-entry"));
        let completed_metadata = registry.get_metadata("leased").expect("metadata");
        assert_eq!(completed_metadata.execution_count(), 1);
        assert_eq!(completed_metadata.success_count(), 1);
        assert_eq!(completed_metadata.error_count(), 0);

        registry.unregister("leased").expect("lease released");
        let (replacement, replacement_calls) = plugin("leased", Behavior::Record);
        registry
            .register(replacement, PluginConfig::default())
            .expect("same ID can be registered only after the invocation drains");
        let result = registry
            .execute(
                "leased",
                request(StaticBroker::success(&origin(), b""))
                    .with_input(b"replacement-entry".to_vec())
                    .expect("input"),
            )
            .await
            .expect("replacement invocation succeeds");
        assert_eq!(replacement_calls.load(Ordering::SeqCst), 1);
        let serialized = serde_json::to_string(&result).expect("result serializes");
        assert!(serialized.contains("replacement-entry"));
        assert!(!serialized.contains("original-entry"));
    }

    #[tokio::test]
    async fn successful_observation_has_host_owned_provenance_and_no_claim() {
        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("observer", Behavior::Record);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let broker = StaticBroker::success(&origin(), b"");
        let result = registry
            .execute(
                "observer",
                request(broker)
                    .with_input(b"marker".to_vec())
                    .expect("bounded input"),
            )
            .await
            .expect("execution succeeds");
        assert_eq!(result.observations().len(), 1);
        let evidence = &result.observations()[0];
        assert_eq!(evidence.subject().as_str(), "authorized-origin:test");
        assert_eq!(evidence.source().component(), "observer");
        assert_eq!(evidence.source().correlation_id(), Some("case:plugin:test"));
        let json = serde_json::to_string(&result).expect("serializes");
        assert!(!json.contains("finding"));
        assert!(!json.contains("outcome"));
        assert!(!json.contains("severity"));
        assert_eq!(result.usage().observations(), 1);
    }

    #[tokio::test]
    async fn redaction_removes_headers_literals_and_debug_secrets() {
        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("redactor", Behavior::Record);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let broker = StaticBroker::success(&origin(), b"");
        let redaction = Arc::new(
            SecretRedactionPolicy::new([
                "tenant".to_owned(),
                "tenant-secret".to_owned(),
                "REDACTED".to_owned(),
                "[REDACTED]-tenant-secret".to_owned(),
                "DACTED]-inside-secret".to_owned(),
            ])
            .expect("redaction policy"),
        );
        let literal_cases = [
            "tenant-secret tenant [REDACTED]",
            "[REDACTED]-tenant-secret",
            "[REDACTED]-inside-secret",
        ];
        for value in literal_cases {
            let once = redaction.redact(value);
            assert!(!once.contains("tenant-secret"));
            assert!(!once.contains("inside-secret"));
            assert_eq!(redaction.redact(&once), once);
        }
        let dense = SecretRedactionPolicy::new(
            (1..=MAX_PLUGIN_REDACTION_LITERAL_COUNT).map(|length| "a".repeat(length)),
        )
        .expect("dense overlap policy");
        let dense_input = "a".repeat(HARD_MAX_PLUGIN_OBSERVATION_BYTES as usize);
        let dense_once = dense.redact(&dense_input);
        assert_eq!(dense_once, "[REDACTED]");
        assert_eq!(dense.redact(&dense_once), dense_once);
        let execution = request(broker)
            .with_input(b"Authorization: Bearer abc\ntoken=xyz\ntenant-secret".to_vec())
            .expect("input")
            .with_redaction(redaction.clone());
        let debug = format!("{execution:?} {redaction:?}");
        assert!(!debug.contains("tenant-secret"));
        assert!(!debug.contains("Bearer"));
        let result = registry
            .execute("redactor", execution)
            .await
            .expect("execution succeeds");
        let serialized = serde_json::to_string(&result).expect("serializes");
        assert!(!serialized.contains("Bearer abc"));
        assert!(!serialized.contains("xyz"));
        assert!(!serialized.contains("tenant-secret"));
        assert!(serialized.contains("REDACTED"));

        struct ExpandingRedactor;
        impl PluginRedactionPolicy for ExpandingRedactor {
            fn redact(&self, value: &str) -> String {
                format!("{value}0123456789")
            }
        }
        struct TwoObservationPlugin;
        #[async_trait]
        impl Plugin for TwoObservationPlugin {
            fn id(&self) -> &str {
                "expanding-redactor"
            }
            fn name(&self) -> &str {
                "Expanding Redactor Fixture"
            }
            fn version(&self) -> &str {
                "0.1.0"
            }
            fn description(&self) -> &str {
                "Exercises retained observation accounting"
            }
            fn author(&self) -> &str {
                "Venom tests"
            }
            fn category(&self) -> PluginCategory {
                PluginCategory::Custom
            }
            async fn execute(&self, context: &PluginContext) -> Result<(), PluginError> {
                context.record(observation(EvidenceValue::Text("x".to_owned())))?;
                context.record(observation(EvidenceValue::Text("y".to_owned())))
            }
        }
        let registry = PluginRegistry::new();
        registry
            .register(Arc::new(TwoObservationPlugin), PluginConfig::default())
            .expect("registration succeeds");
        let budget = PluginBudget::default()
            .with_max_observation_bytes(25)
            .expect("budget");
        let execution = request(StaticBroker::success(&origin(), b""))
            .with_budget(budget)
            .expect("request")
            .with_redaction(Arc::new(ExpandingRedactor));
        assert_eq!(
            registry.execute("expanding-redactor", execution).await,
            Err(PluginError::ObservationBytesBudgetExceeded)
        );
    }

    #[tokio::test]
    async fn plugin_error_rolls_back_staged_evidence_and_redacts_detail() {
        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("rollback", Behavior::ErrorAfterRecord);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let broker = StaticBroker::success(&origin(), b"");
        let error = registry
            .execute("rollback", request(broker))
            .await
            .expect_err("execution must fail");
        assert!(!error.to_string().contains("fixture-secret"));
        assert_eq!(
            error,
            PluginError::ExecutionFailed("plugin execution failed".to_owned())
        );
        let metadata = registry.get_metadata("rollback").expect("metadata");
        assert_eq!(metadata.execution_count(), 1);
        assert_eq!(metadata.success_count(), 0);
        assert_eq!(metadata.error_count(), 1);

        let oversized = format!(
            "token=fixture-secret{}",
            "x".repeat(MAX_PLUGIN_TEXT_BYTES * 4)
        );
        let bounded = sanitize_error(
            &SecretRedactionPolicy::default(),
            PluginError::ExecutionFailed(oversized),
        );
        let detail = match bounded {
            PluginError::ExecutionFailed(detail) => detail,
            other => panic!("unexpected error: {other}"),
        };
        assert!(detail.len() <= MAX_PLUGIN_TEXT_BYTES);
        assert!(!detail.contains("fixture-secret"));
        assert_eq!(detail, "plugin execution failed");

        let boundary_secret = "s".repeat(MAX_PLUGIN_TEXT_BYTES + 1);
        let redaction = Arc::new(
            SecretRedactionPolicy::new([boundary_secret.clone()])
                .expect("boundary redaction policy"),
        );
        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("long-plugin-error", Behavior::LongSecretError);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let execution =
            request(StaticBroker::success(&origin(), b"")).with_redaction(redaction.clone());
        assert_eq!(
            registry.execute("long-plugin-error", execution).await,
            Err(PluginError::ExecutionFailed(
                "plugin execution failed".to_owned()
            ))
        );

        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("long-broker-error", Behavior::Request);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let broker = Arc::new(StaticBroker {
            calls: AtomicUsize::new(0),
            response: Mutex::new(Some(Err(PluginError::BrokerFailure(boundary_secret)))),
            delay: Duration::ZERO,
        });
        let execution = request(broker).with_redaction(redaction);
        assert_eq!(
            registry.execute("long-broker-error", execution).await,
            Err(PluginError::BrokerFailure(
                "host plugin request broker failed".to_owned()
            ))
        );

        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("plugin-api-error", Behavior::IncompatibleError);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        assert_eq!(
            registry
                .execute(
                    "plugin-api-error",
                    request(StaticBroker::success(&origin(), b"")),
                )
                .await,
            Err(PluginError::IncompatibleApiVersion {
                expected: PLUGIN_API_VERSION.to_owned(),
                actual: "[invalid]".to_owned(),
            })
        );

        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("broker-api-error", Behavior::Request);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let broker = Arc::new(StaticBroker {
            calls: AtomicUsize::new(0),
            response: Mutex::new(Some(Err(PluginError::IncompatibleApiVersion {
                expected: format!(
                    "token=broker-secret{}",
                    "x".repeat(MAX_PLUGIN_TEXT_BYTES * 4)
                ),
                actual: "token=broker-actual-secret".to_owned(),
            }))),
            delay: Duration::ZERO,
        });
        assert_eq!(
            registry.execute("broker-api-error", request(broker)).await,
            Err(PluginError::IncompatibleApiVersion {
                expected: PLUGIN_API_VERSION.to_owned(),
                actual: "[invalid]".to_owned(),
            })
        );

        struct PanickingRedactor;
        impl PluginRedactionPolicy for PanickingRedactor {
            fn redact(&self, _value: &str) -> String {
                panic!("host redaction panic")
            }
        }
        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("panicking-redactor", Behavior::ErrorOnly);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let execution = request(StaticBroker::success(&origin(), b""))
            .with_redaction(Arc::new(PanickingRedactor));
        assert_eq!(
            registry.execute("panicking-redactor", execution).await,
            Err(PluginError::HostCallbackPanicked)
        );
        let metadata = registry
            .get_metadata("panicking-redactor")
            .expect("metadata");
        assert_eq!(metadata.execution_count(), 1);
        assert_eq!(metadata.success_count(), 0);
        assert_eq!(metadata.error_count(), 1);
    }

    #[tokio::test]
    async fn timeout_cancellation_and_panic_are_typed_failures() {
        for (id, behavior, expected) in [
            (
                "timeout",
                Behavior::RecordThenPending,
                PluginError::WallTimeExceeded,
            ),
            ("panic", Behavior::RecordThenPanic, PluginError::Panicked),
        ] {
            let registry = PluginRegistry::new();
            let (candidate, _) = plugin(id, behavior);
            registry
                .register(candidate, PluginConfig::default())
                .expect("registration succeeds");
            let broker = StaticBroker::success(&origin(), b"");
            let budget = PluginBudget::default()
                .with_max_wall_time(Duration::from_millis(5))
                .expect("budget");
            let error = registry
                .execute(
                    id,
                    request(broker)
                        .with_budget(budget)
                        .and_then(|request| request.with_input(b"staged".to_vec()))
                        .expect("request"),
                )
                .await
                .expect_err("must fail");
            assert_eq!(error, expected);
            let metadata = registry.get_metadata(id).expect("metadata");
            assert_eq!(metadata.execution_count(), 1);
            assert_eq!(metadata.success_count(), 0);
            assert_eq!(metadata.error_count(), 1);
        }

        struct ConstructionPanicPlugin;
        impl Plugin for ConstructionPanicPlugin {
            fn id(&self) -> &str {
                "construction-panic"
            }
            fn name(&self) -> &str {
                "Construction Panic Fixture"
            }
            fn version(&self) -> &str {
                "0.1.0"
            }
            fn description(&self) -> &str {
                "Panics while constructing its boxed execution future"
            }
            fn author(&self) -> &str {
                "Venom tests"
            }
            fn category(&self) -> PluginCategory {
                PluginCategory::Custom
            }
            fn execute<'life0, 'life1, 'async_trait>(
                &'life0 self,
                context: &'life1 PluginContext,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = Result<(), PluginError>> + Send + 'async_trait,
                >,
            >
            where
                'life0: 'async_trait,
                'life1: 'async_trait,
                Self: 'async_trait,
            {
                context
                    .record(observation(EvidenceValue::Text("staged".to_owned())))
                    .expect("staging succeeds before construction panic");
                panic!("plugin fixture panic during future construction");
            }
        }
        let registry = PluginRegistry::new();
        registry
            .register(Arc::new(ConstructionPanicPlugin), PluginConfig::default())
            .expect("registration succeeds");
        assert_eq!(
            registry
                .execute(
                    "construction-panic",
                    request(StaticBroker::success(&origin(), b"")),
                )
                .await,
            Err(PluginError::Panicked)
        );
        let metadata = registry
            .get_metadata("construction-panic")
            .expect("metadata");
        assert_eq!(metadata.execution_count(), 1);
        assert_eq!(metadata.success_count(), 0);
        assert_eq!(metadata.error_count(), 1);

        struct DropPanicFuture {
            ready: bool,
        }
        impl std::future::Future for DropPanicFuture {
            type Output = Result<(), PluginError>;

            fn poll(
                self: std::pin::Pin<&mut Self>,
                _context: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Self::Output> {
                if self.ready {
                    std::task::Poll::Ready(Ok(()))
                } else {
                    std::task::Poll::Pending
                }
            }
        }
        impl Drop for DropPanicFuture {
            fn drop(&mut self) {
                panic!("plugin fixture panic while dropping execution future");
            }
        }
        struct DropPanicPlugin {
            id: &'static str,
            ready: bool,
        }
        impl Plugin for DropPanicPlugin {
            fn id(&self) -> &str {
                self.id
            }
            fn name(&self) -> &str {
                "Drop Panic Fixture"
            }
            fn version(&self) -> &str {
                "0.1.0"
            }
            fn description(&self) -> &str {
                "Panics while dropping its boxed execution future"
            }
            fn author(&self) -> &str {
                "Venom tests"
            }
            fn category(&self) -> PluginCategory {
                PluginCategory::Custom
            }
            fn execute<'life0, 'life1, 'async_trait>(
                &'life0 self,
                _context: &'life1 PluginContext,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = Result<(), PluginError>> + Send + 'async_trait,
                >,
            >
            where
                'life0: 'async_trait,
                'life1: 'async_trait,
                Self: 'async_trait,
            {
                Box::pin(DropPanicFuture { ready: self.ready })
            }
        }
        for (id, ready) in [("ready-drop-panic", true), ("pending-drop-panic", false)] {
            let registry = PluginRegistry::new();
            registry
                .register(
                    Arc::new(DropPanicPlugin { id, ready }),
                    PluginConfig::default(),
                )
                .expect("registration succeeds");
            let budget = PluginBudget::default()
                .with_max_wall_time(Duration::from_millis(5))
                .expect("budget");
            assert_eq!(
                registry
                    .execute(
                        id,
                        request(StaticBroker::success(&origin(), b""))
                            .with_budget(budget)
                            .expect("request"),
                    )
                    .await,
                Err(PluginError::Panicked)
            );
            let metadata = registry.get_metadata(id).expect("metadata");
            assert_eq!(metadata.execution_count(), 1);
            assert_eq!(metadata.success_count(), 0);
            assert_eq!(metadata.error_count(), 1);
        }

        struct AbandonRequestPlugin;
        #[async_trait]
        impl Plugin for AbandonRequestPlugin {
            fn id(&self) -> &str {
                "abandon-request"
            }
            fn name(&self) -> &str {
                "Abandoned Request Fixture"
            }
            fn version(&self) -> &str {
                "0.1.0"
            }
            fn description(&self) -> &str {
                "Polls and drops a broker request"
            }
            fn author(&self) -> &str {
                "Venom tests"
            }
            fn category(&self) -> PluginCategory {
                PluginCategory::Custom
            }
            async fn execute(&self, context: &PluginContext) -> Result<(), PluginError> {
                let future =
                    context.request(PluginHttpMethod::Get, context.authorized_origin().clone());
                tokio::pin!(future);
                tokio::select! {
                    biased;
                    result = &mut future => {
                        result?;
                        return Err(invalid_config("pending broker completed unexpectedly"));
                    },
                    () = tokio::task::yield_now() => {},
                }
                Ok(())
            }
        }
        struct PendingBroker {
            calls: AtomicUsize,
            cancellation: Mutex<Option<CancellationToken>>,
        }
        #[async_trait]
        impl PluginRequestBroker for PendingBroker {
            async fn execute(
                &self,
                request: PluginHttpRequest,
            ) -> Result<PluginHttpResponse, PluginError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                *self
                    .cancellation
                    .lock()
                    .map_err(|_| PluginError::HostStateUnavailable)? =
                    Some(request.cancellation().clone());
                std::future::pending().await
            }
        }
        let registry = PluginRegistry::new();
        registry
            .register(Arc::new(AbandonRequestPlugin), PluginConfig::default())
            .expect("registration succeeds");
        let pending = Arc::new(PendingBroker {
            calls: AtomicUsize::new(0),
            cancellation: Mutex::new(None),
        });
        assert_eq!(
            registry
                .execute("abandon-request", request(pending.clone()))
                .await,
            Err(PluginError::RequestAbandoned)
        );
        assert_eq!(pending.calls.load(Ordering::SeqCst), 1);
        assert!(pending
            .cancellation
            .lock()
            .expect("cancellation receipt")
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled));

        let registry = PluginRegistry::new();
        let (candidate, calls) = plugin("cancelled", Behavior::Record);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let broker = StaticBroker::success(&origin(), b"");
        assert_eq!(
            registry
                .execute("cancelled", request(broker).with_cancellation(cancellation),)
                .await,
            Err(PluginError::Cancelled)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("mid-cancel", Behavior::Pending);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let cancellation = CancellationToken::new();
        let cancellation_signal = cancellation.clone();
        let cancel_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(5)).await;
            cancellation_signal.cancel();
        });
        let broker = StaticBroker::success(&origin(), b"");
        assert_eq!(
            registry
                .execute(
                    "mid-cancel",
                    request(broker).with_cancellation(cancellation),
                )
                .await,
            Err(PluginError::Cancelled)
        );
        cancel_task.await.expect("cancellation task joins");
        assert_eq!(
            registry
                .get_metadata("mid-cancel")
                .expect("metadata")
                .error_count(),
            1
        );
    }

    #[tokio::test]
    async fn input_observation_and_request_budgets_fail_closed() {
        let broker = StaticBroker::success(&origin(), b"");
        let tiny_input = PluginBudget::default()
            .with_max_input_bytes(3)
            .expect("budget");
        assert!(matches!(
            request(broker.clone())
                .with_budget(tiny_input)
                .expect("empty input fits")
                .with_input("éé".as_bytes().to_vec()),
            Err(PluginError::InputBudgetExceeded {
                actual: 4,
                maximum: 3
            })
        ));

        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("no-request", Behavior::Request);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let zero = PluginBudget::default()
            .with_max_requests(0)
            .expect("zero authority");
        assert_eq!(
            registry
                .execute(
                    "no-request",
                    request(broker.clone()).with_budget(zero).expect("request"),
                )
                .await,
            Err(PluginError::RequestBudgetExceeded)
        );
        assert_eq!(broker.calls(), 0);

        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("no-observation", Behavior::Record);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let zero = PluginBudget::default()
            .with_max_observations(0)
            .expect("zero authority");
        assert_eq!(
            registry
                .execute(
                    "no-observation",
                    request(broker).with_budget(zero).expect("request"),
                )
                .await,
            Err(PluginError::ObservationBudgetExceeded)
        );

        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("observation-bytes", Behavior::Record);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let bytes = PluginBudget::default()
            .with_max_observation_bytes(3)
            .expect("budget");
        let execution = request(StaticBroker::success(&origin(), b""))
            .with_budget(bytes)
            .expect("request")
            .with_input(b"four".to_vec())
            .expect("input budget");
        assert_eq!(
            registry.execute("observation-bytes", execution).await,
            Err(PluginError::ObservationBytesBudgetExceeded)
        );

        struct EmptyListPlugin;
        #[async_trait]
        impl Plugin for EmptyListPlugin {
            fn id(&self) -> &str {
                "empty-list"
            }
            fn name(&self) -> &str {
                "Empty List Fixture"
            }
            fn version(&self) -> &str {
                "0.1.0"
            }
            fn description(&self) -> &str {
                "Exercises structural observation accounting"
            }
            fn author(&self) -> &str {
                "Venom tests"
            }
            fn category(&self) -> PluginCategory {
                PluginCategory::Custom
            }
            async fn execute(&self, context: &PluginContext) -> Result<(), PluginError> {
                context.record(observation(EvidenceValue::TextList(vec![
                    String::new();
                    HARD_MAX_PLUGIN_TEXT_LIST_ITEMS
                ])))
            }
        }
        let registry = PluginRegistry::new();
        registry
            .register(Arc::new(EmptyListPlugin), PluginConfig::default())
            .expect("registration succeeds");
        let zero_bytes = PluginBudget::default()
            .with_max_observation_bytes(0)
            .expect("zero byte authority");
        assert_eq!(
            registry
                .execute(
                    "empty-list",
                    request(StaticBroker::success(&origin(), b""))
                        .with_budget(zero_bytes)
                        .expect("request"),
                )
                .await,
            Err(PluginError::ObservationBytesBudgetExceeded)
        );
    }

    #[tokio::test]
    async fn scope_and_body_budgets_are_enforced_around_the_host_broker() {
        assert!(PluginHttpResponse::new(200, origin(), b"x".to_vec())
            .and_then(|response| response.with_capture_metadata(2, false))
            .is_err());

        struct ScopePlugin;
        #[async_trait]
        impl Plugin for ScopePlugin {
            fn id(&self) -> &str {
                "scope"
            }
            fn name(&self) -> &str {
                "Scope Fixture"
            }
            fn version(&self) -> &str {
                "0.1.0"
            }
            fn description(&self) -> &str {
                "Exercises broker scope"
            }
            fn author(&self) -> &str {
                "Venom tests"
            }
            fn category(&self) -> PluginCategory {
                PluginCategory::Custom
            }
            async fn execute(&self, context: &PluginContext) -> Result<(), PluginError> {
                context
                    .request(
                        PluginHttpMethod::Get,
                        Url::parse("https://other.test/").map_err(|_| invalid_config("URL"))?,
                    )
                    .await?;
                Ok(())
            }
        }
        let registry = PluginRegistry::new();
        registry
            .register(Arc::new(ScopePlugin), PluginConfig::default())
            .expect("registration succeeds");
        let broker = StaticBroker::success(&origin(), b"");
        assert_eq!(
            registry.execute("scope", request(broker.clone())).await,
            Err(PluginError::ScopeViolation)
        );
        assert_eq!(broker.calls(), 0);

        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("body", Behavior::Request);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let broker = StaticBroker::success(&origin(), b"four");
        let budget = PluginBudget::default()
            .with_max_response_body_bytes(3)
            .expect("budget");
        assert!(matches!(
            registry
                .execute(
                    "body",
                    request(broker).with_budget(budget).expect("request")
                )
                .await,
            Err(PluginError::ResponseBodyBudgetExceeded {
                actual: 4,
                maximum: 3
            })
        ));

        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("long-final-url", Behavior::Request);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let long_final = Url::parse(&format!(
            "https://example.test/{}",
            "a".repeat(MAX_PLUGIN_URL_BYTES)
        ))
        .expect("valid long URL");
        let long_final_broker = StaticBroker::success(&long_final, b"");
        assert_eq!(
            registry
                .execute("long-final-url", request(long_final_broker))
                .await,
            Err(PluginError::ScopeViolation)
        );

        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("request-timeout", Behavior::Request);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let slow = Arc::new(StaticBroker {
            calls: AtomicUsize::new(0),
            response: Mutex::new(Some(Ok(
                PluginHttpResponse::new(200, origin(), Vec::new()).expect("response")
            ))),
            delay: Duration::from_millis(50),
        });
        let budget = PluginBudget::default()
            .with_request_timeout(Duration::from_millis(5))
            .expect("budget");
        assert_eq!(
            registry
                .execute(
                    "request-timeout",
                    request(slow).with_budget(budget).expect("request"),
                )
                .await,
            Err(PluginError::RequestTimeout)
        );

        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("redirect-scope", Behavior::Request);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let other = Url::parse("https://other.test/").expect("valid URL");
        let redirected = StaticBroker::success(&other, b"");
        assert_eq!(
            registry
                .execute("redirect-scope", request(redirected.clone()))
                .await,
            Err(PluginError::ScopeViolation)
        );
        assert_eq!(redirected.calls(), 1);

        struct TwoRequestPlugin;
        #[async_trait]
        impl Plugin for TwoRequestPlugin {
            fn id(&self) -> &str {
                "cumulative"
            }
            fn name(&self) -> &str {
                "Cumulative Body Fixture"
            }
            fn version(&self) -> &str {
                "0.1.0"
            }
            fn description(&self) -> &str {
                "Exercises cumulative response accounting"
            }
            fn author(&self) -> &str {
                "Venom tests"
            }
            fn category(&self) -> PluginCategory {
                PluginCategory::Custom
            }
            async fn execute(&self, context: &PluginContext) -> Result<(), PluginError> {
                for path in ["one", "two"] {
                    let url = context
                        .authorized_origin()
                        .join(path)
                        .map_err(|_| invalid_config("fixture URL"))?;
                    context.request(PluginHttpMethod::Get, url).await?;
                }
                Ok(())
            }
        }
        struct RepeatBroker {
            calls: AtomicUsize,
            captures: Mutex<Vec<(u64, bool)>>,
        }
        #[async_trait]
        impl PluginRequestBroker for RepeatBroker {
            async fn execute(
                &self,
                request: PluginHttpRequest,
            ) -> Result<PluginHttpResponse, PluginError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.captures
                    .lock()
                    .map_err(|_| PluginError::HostStateUnavailable)?
                    .push((
                        request.max_response_body_bytes(),
                        request.cancellation().is_cancelled(),
                    ));
                PluginHttpResponse::new(200, request.url().clone(), b"abc".to_vec())
            }
        }
        let registry = PluginRegistry::new();
        registry
            .register(Arc::new(TwoRequestPlugin), PluginConfig::default())
            .expect("registration succeeds");
        let repeated = Arc::new(RepeatBroker {
            calls: AtomicUsize::new(0),
            captures: Mutex::new(Vec::new()),
        });
        let budget = PluginBudget::default()
            .with_max_response_body_bytes(3)
            .and_then(|budget| budget.with_max_cumulative_body_bytes(3))
            .expect("budget");
        assert_eq!(
            registry
                .execute(
                    "cumulative",
                    request(repeated.clone())
                        .with_budget(budget)
                        .expect("request"),
                )
                .await,
            Err(PluginError::CumulativeBodyBudgetExceeded)
        );
        assert_eq!(repeated.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *repeated.captures.lock().expect("capture log"),
            vec![(3, false)]
        );

        struct CappedBroker {
            captures: Mutex<Vec<(u64, bool)>>,
        }
        #[async_trait]
        impl PluginRequestBroker for CappedBroker {
            async fn execute(
                &self,
                request: PluginHttpRequest,
            ) -> Result<PluginHttpResponse, PluginError> {
                let limit = request.max_response_body_bytes();
                self.captures
                    .lock()
                    .map_err(|_| PluginError::HostStateUnavailable)?
                    .push((limit, request.cancellation().is_cancelled()));
                let body = b"abcd";
                let retained = usize::try_from(limit).unwrap_or(usize::MAX).min(body.len());
                PluginHttpResponse::new(200, request.url().clone(), body[..retained].to_vec())?
                    .with_capture_metadata(retained as u64, retained < body.len())
            }
        }
        let registry = PluginRegistry::new();
        registry
            .register(Arc::new(TwoRequestPlugin), PluginConfig::default())
            .expect("registration succeeds");
        let capped = Arc::new(CappedBroker {
            captures: Mutex::new(Vec::new()),
        });
        let budget = PluginBudget::default()
            .with_max_response_body_bytes(4)
            .and_then(|budget| budget.with_max_cumulative_body_bytes(6))
            .expect("budget");
        let result = registry
            .execute(
                "cumulative",
                request(capped.clone())
                    .with_budget(budget)
                    .expect("request"),
            )
            .await
            .expect("a compliant broker stays inside the shared envelope");
        assert_eq!(result.usage().response_body_bytes(), 6);
        assert_eq!(
            *capped.captures.lock().expect("capture log"),
            vec![(4, false), (2, false)]
        );

        struct ConcurrentRequestPlugin;
        #[async_trait]
        impl Plugin for ConcurrentRequestPlugin {
            fn id(&self) -> &str {
                "concurrent-capture"
            }
            fn name(&self) -> &str {
                "Concurrent Capture Fixture"
            }
            fn version(&self) -> &str {
                "0.1.0"
            }
            fn description(&self) -> &str {
                "Exercises in-flight cumulative reservations"
            }
            fn author(&self) -> &str {
                "Venom tests"
            }
            fn category(&self) -> PluginCategory {
                PluginCategory::Custom
            }
            async fn execute(&self, context: &PluginContext) -> Result<(), PluginError> {
                let one = context
                    .authorized_origin()
                    .join("one")
                    .map_err(|_| invalid_config("fixture URL"))?;
                let two = context
                    .authorized_origin()
                    .join("two")
                    .map_err(|_| invalid_config("fixture URL"))?;
                tokio::try_join!(
                    context.request(PluginHttpMethod::Get, one),
                    context.request(PluginHttpMethod::Get, two),
                )?;
                Ok(())
            }
        }
        struct ConcurrentCaptureBroker {
            barrier: tokio::sync::Barrier,
            captures: Mutex<Vec<u64>>,
        }
        #[async_trait]
        impl PluginRequestBroker for ConcurrentCaptureBroker {
            async fn execute(
                &self,
                request: PluginHttpRequest,
            ) -> Result<PluginHttpResponse, PluginError> {
                let limit = request.max_response_body_bytes();
                self.captures
                    .lock()
                    .map_err(|_| PluginError::HostStateUnavailable)?
                    .push(limit);
                self.barrier.wait().await;
                PluginHttpResponse::new(
                    200,
                    request.url().clone(),
                    vec![b'x'; usize::try_from(limit).unwrap_or(usize::MAX)],
                )
            }
        }
        let registry = PluginRegistry::new();
        registry
            .register(Arc::new(ConcurrentRequestPlugin), PluginConfig::default())
            .expect("registration succeeds");
        let concurrent = Arc::new(ConcurrentCaptureBroker {
            barrier: tokio::sync::Barrier::new(2),
            captures: Mutex::new(Vec::new()),
        });
        let budget = PluginBudget::default()
            .with_max_response_body_bytes(4)
            .and_then(|budget| budget.with_max_cumulative_body_bytes(6))
            .expect("budget");
        let result = registry
            .execute(
                "concurrent-capture",
                request(concurrent.clone())
                    .with_budget(budget)
                    .expect("request"),
            )
            .await
            .expect("concurrent captures stay inside the shared envelope");
        let mut captures = concurrent.captures.lock().expect("capture log").clone();
        captures.sort_unstable();
        assert_eq!(captures, vec![2, 4]);
        assert_eq!(result.usage().response_body_bytes(), 6);
    }

    #[tokio::test]
    async fn configuration_and_metadata_share_one_entry() {
        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("metadata", Behavior::Empty);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        assert!(registry
            .get_config("metadata")
            .expect("configuration")
            .enabled());
        registry
            .update_config("metadata", PluginConfig::new(false))
            .expect("configuration update");
        assert!(!registry
            .get_metadata("metadata")
            .expect("metadata")
            .enabled());
        registry.unregister("metadata").expect("unregister");
        assert!(registry.get("metadata").is_none());
        assert!(registry.get_config("metadata").is_none());
        assert!(registry.get_metadata("metadata").is_none());

        struct YieldingPlugin;
        #[async_trait]
        impl Plugin for YieldingPlugin {
            fn id(&self) -> &str {
                "coherent-stats"
            }
            fn name(&self) -> &str {
                "Coherent Stats Fixture"
            }
            fn version(&self) -> &str {
                "0.1.0"
            }
            fn description(&self) -> &str {
                "Exercises concurrent metadata snapshots"
            }
            fn author(&self) -> &str {
                "Venom tests"
            }
            fn category(&self) -> PluginCategory {
                PluginCategory::Custom
            }
            async fn execute(&self, _context: &PluginContext) -> Result<(), PluginError> {
                for _ in 0..4 {
                    tokio::task::yield_now().await;
                }
                Ok(())
            }
        }
        let registry = Arc::new(PluginRegistry::new());
        registry
            .register(Arc::new(YieldingPlugin), PluginConfig::default())
            .expect("registration succeeds");
        let mut tasks = Vec::new();
        for _ in 0..32 {
            let registry = registry.clone();
            tasks.push(tokio::spawn(async move {
                registry
                    .execute(
                        "coherent-stats",
                        request(StaticBroker::success(&origin(), b"")),
                    )
                    .await
            }));
        }
        while tasks.iter().any(|task| !task.is_finished()) {
            let metadata = registry.get_metadata("coherent-stats").expect("metadata");
            assert!(
                metadata.execution_count()
                    >= metadata
                        .success_count()
                        .saturating_add(metadata.error_count())
            );
            tokio::task::yield_now().await;
        }
        for task in tasks {
            task.await
                .expect("execution task joins")
                .expect("execution succeeds");
        }
        let metadata = registry.get_metadata("coherent-stats").expect("metadata");
        assert_eq!(metadata.execution_count(), 32);
        assert_eq!(metadata.success_count(), 32);
        assert_eq!(metadata.error_count(), 0);
    }
}
