use async_trait::async_trait;
use serde::Serialize;
use std::{collections::BTreeMap, fmt};
use tokio_util::sync::CancellationToken;
use url::Url;

use super::{
    limits::{
        invalid_config, HARD_MAX_PLUGIN_RESPONSE_BODY_BYTES, MAX_PLUGIN_HEADERS,
        MAX_PLUGIN_HEADER_NAME_BYTES, MAX_PLUGIN_HEADER_VALUE_BYTES, MAX_PLUGIN_URL_BYTES,
    },
    PluginError,
};

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
    pub(super) method: PluginHttpMethod,
    pub(super) url: Url,
    pub(super) max_response_body_bytes: u64,
    pub(super) cancellation: CancellationToken,
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
    pub(super) delivered_body_bytes: u64,
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

pub(super) fn validate_authorized_origin(origin: &Url) -> Result<(), PluginError> {
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

pub(super) fn validate_scoped_url(origin: &Url, url: &Url) -> Result<(), PluginError> {
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

pub(super) fn origin_string(url: &Url) -> String {
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
