use std::{collections::BTreeMap, fmt};

use reqwest::{
    header::{HeaderName, HeaderValue},
    Method, Url,
};
use serde::{Deserialize, Serialize};

use crate::DecisionExecutionRequest;

use super::{
    policy::{forbidden_request_header, validate_http_url},
    HttpEvidenceError,
};

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
    pub(super) fn as_reqwest(self) -> Method {
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

    pub(super) fn url_mut(&mut self) -> &mut Url {
        &mut self.url
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
