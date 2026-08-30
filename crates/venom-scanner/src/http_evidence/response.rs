use reqwest::{header::HeaderMap, StatusCode, Url};

use super::{json_compatible_media_type, normalized_media_type};

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

    #[cfg(feature = "legacy-scanner")]
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

    pub(crate) fn has_json_compatible_media_type(&self) -> bool {
        normalized_media_type(&self.headers)
            .as_deref()
            .is_some_and(json_compatible_media_type)
    }
}
