use reqwest::{header::HeaderMap, StatusCode, Url};

use super::{json_compatible_media_type, normalized_media_type};

/// Closed defensive interpretation used by the explicit authorization child.
#[cfg(feature = "authorization-review")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorizationResponseDefense {
    Clear,
    RateLimited,
    Challenge,
}

pub(crate) struct CollectedHttpResponse {
    pub(super) status: StatusCode,
    pub(super) final_url: Url,
    pub(super) version: String,
    pub(super) headers: HeaderMap,
    pub(super) body: Vec<u8>,
    pub(super) body_truncated: bool,
    pub(super) body_complete: bool,
    pub(super) ttfb_ms: u64,
    pub(super) total_ms: u64,
}

impl CollectedHttpResponse {
    pub(crate) fn status(&self) -> u16 {
        self.status.as_u16()
    }

    #[cfg(any(
        feature = "legacy-scanner",
        feature = "authorization-review",
        feature = "openapi-review"
    ))]
    pub(crate) fn final_url(&self) -> &Url {
        &self.final_url
    }

    #[cfg(feature = "legacy-scanner")]
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name)?.to_str().ok()
    }

    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    pub(crate) fn body_truncated(&self) -> bool {
        self.body_truncated
    }

    #[cfg(any(
        feature = "graphql-review",
        feature = "authorization-review",
        feature = "openapi-review"
    ))]
    pub(crate) fn body_complete(&self) -> bool {
        self.body_complete && !self.body_truncated
    }

    #[cfg(any(
        feature = "graphql-review",
        feature = "authorization-review",
        feature = "openapi-review"
    ))]
    pub(crate) fn normalized_media_type(&self) -> Option<String> {
        normalized_media_type(&self.headers)
    }

    pub(crate) fn has_json_compatible_media_type(&self) -> bool {
        normalized_media_type(&self.headers)
            .as_deref()
            .is_some_and(json_compatible_media_type)
    }

    /// Reuses the current bounded defense observer without exposing response
    /// headers or body bytes outside the HTTP evidence boundary. A fingerprint
    /// alone is deliberately not execution authority or interference.
    #[cfg(feature = "authorization-review")]
    pub(crate) fn authorization_response_defense(&self) -> AuthorizationResponseDefense {
        let signal = super::bounded_assessment_defense_signal(
            self.status(),
            crate::HttpProbeMethod::Get,
            &self.headers,
            self.body_complete,
            &self.body,
        );
        if signal.state().is_rate_limited() {
            AuthorizationResponseDefense::RateLimited
        } else if signal.state().is_challenged() {
            AuthorizationResponseDefense::Challenge
        } else {
            AuthorizationResponseDefense::Clear
        }
    }

    #[cfg(feature = "openapi-review")]
    pub(crate) fn openapi_defense_signal(&self) -> crate::web_runtime::AssessmentDefenseSignal {
        super::bounded_assessment_defense_signal(
            self.status(),
            crate::HttpProbeMethod::Get,
            &self.headers,
            self.body_complete,
            &self.body,
        )
    }
}
