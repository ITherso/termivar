use std::{collections::BTreeSet, time::Duration};

use reqwest::{header::HeaderName, Url};
use serde::Serialize;
use venom_core::ConfidenceScore;

use super::HttpEvidenceError;

/// Default maximum number of response-body bytes read by one probe.
pub const DEFAULT_HTTP_BODY_LIMIT: usize = 256 * 1024;

/// Hard guard preventing an individual evidence probe from buffering too much.
pub const MAX_HTTP_BODY_LIMIT: usize = 16 * 1024 * 1024;

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

    /// Returns this policy narrowed to the exact origin of `target`.
    ///
    /// All non-scope settings are preserved. The target must already be covered
    /// by this policy, so narrowing can never turn an unauthorized target into
    /// an authorized one. Bounded origin-level runtimes use this seam to ensure
    /// that an explicitly broader host policy cannot silently expand discovery.
    pub(crate) fn restricted_to_exact_origin(
        &self,
        target: &Url,
    ) -> Result<Self, HttpEvidenceError> {
        self.require_permitted_target(target)?;

        let mut restricted = self.clone();
        restricted.allowed_origins = BTreeSet::from([origin(target)?]);
        Ok(restricted)
    }

    /// Narrows a policy for the names-only assessment observer.
    ///
    /// The assessment is never allowed to inherit text sampling or a
    /// caller-added sensitive response header. The response body remains
    /// transient inside the sealed executor observer. No raw response header
    /// value enters assessment discovery evidence; normalized media type has
    /// its own bounded predicate.
    pub(crate) fn restricted_for_web_assessment(
        &self,
        target: &Url,
        max_body_bytes: usize,
    ) -> Result<Self, HttpEvidenceError> {
        validate_body_limit(max_body_bytes)?;
        let mut restricted = self.restricted_to_exact_origin(target)?;
        restricted.max_body_bytes = restricted.max_body_bytes.min(max_body_bytes);
        restricted.body_capture = HttpBodyCapture::MetadataOnly;
        // Even Content-Type parameters are untrusted and may contain tokens.
        // Discovery uses only RESPONSE_MEDIA_TYPE's normalized essence.
        restricted.captured_headers.clear();
        Ok(restricted)
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

    /// Validates the complete request URL and enforces this policy's scope.
    ///
    /// Callers must use this typed seam instead of comparing serialized origins:
    /// origin equality alone does not reject unsupported schemes or embedded
    /// credentials.
    pub(crate) fn require_permitted_target(&self, target: &Url) -> Result<(), HttpEvidenceError> {
        if !self.permits(target)? {
            return Err(HttpEvidenceError::TargetOutsidePolicy {
                url: target.to_string(),
            });
        }
        Ok(())
    }
}

pub(super) fn validate_http_url(url: &Url) -> Result<(), HttpEvidenceError> {
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

pub(super) fn forbidden_request_header(name: &HeaderName) -> bool {
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
