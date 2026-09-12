use reqwest::{header::HeaderMap, StatusCode, Url};

use super::{json_compatible_media_type, normalized_media_type};

#[cfg(feature = "wordpress-review")]
pub(super) fn content_length_matches_body(headers: &HeaderMap, body_length: u64) -> bool {
    let mut values = headers.get_all(reqwest::header::CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return true;
    };
    if values.next().is_some() {
        return false;
    }
    let Ok(value) = value.to_str() else {
        return false;
    };
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u64>() == Ok(body_length)
}

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
        feature = "openapi-review",
        feature = "ssrf-oast-review",
        feature = "wordpress-review"
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
        feature = "openapi-review",
        feature = "ssrf-oast-review",
        feature = "wordpress-review"
    ))]
    pub(crate) fn body_complete(&self) -> bool {
        self.body_complete && !self.body_truncated
    }

    #[cfg(any(
        feature = "graphql-review",
        feature = "authorization-review",
        feature = "openapi-review",
        feature = "wordpress-review"
    ))]
    pub(crate) fn normalized_media_type(&self) -> Option<String> {
        normalized_media_type(&self.headers)
    }

    /// Whether the response carried no Content-Encoding field at all.
    ///
    /// Fingerprinting requires this stricter assurance even though the current
    /// reqwest build disables every automatic content decoder. Treating an
    /// unrecognised or empty coding as identity would make the byte contract
    /// depend on transport-library behavior, so any field occurrence rejects
    /// the representation.
    #[cfg(feature = "wordpress-review")]
    pub(crate) fn content_encoding_is_absent(&self) -> bool {
        !self.headers.contains_key(reqwest::header::CONTENT_ENCODING)
    }

    /// Checks a present Content-Length against the complete retained bytes.
    /// Missing length is valid for EOF-delimited or chunked responses; an
    /// ambiguous, invalid, or contradictory declaration is not.
    #[cfg(feature = "wordpress-review")]
    pub(crate) fn content_length_is_consistent(&self) -> bool {
        content_length_matches_body(
            &self.headers,
            u64::try_from(self.body.len()).unwrap_or(u64::MAX),
        )
    }

    /// Returns complete uncoded bytes only after the broker observed stream
    /// EOF. A retained prefix, even one with a committed SHA-256 observation,
    /// never crosses this fingerprinting seam.
    #[cfg(feature = "wordpress-review")]
    pub(crate) fn complete_identity_content_body(&self) -> Option<&[u8]> {
        (self.body_complete()
            && self.content_encoding_is_absent()
            && self.content_length_is_consistent())
        .then_some(self.body())
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

    #[cfg(feature = "ssrf-oast-review")]
    pub(crate) fn ssrf_oast_defense_signal(&self) -> crate::web_runtime::AssessmentDefenseSignal {
        super::bounded_assessment_defense_signal(
            self.status(),
            crate::HttpProbeMethod::Get,
            &self.headers,
            self.body_complete,
            &self.body,
        )
    }
}

#[cfg(all(test, feature = "wordpress-review"))]
mod tests {
    use reqwest::header::{HeaderMap, HeaderValue, CONTENT_ENCODING, CONTENT_LENGTH};

    use super::{CollectedHttpResponse, StatusCode, Url};

    fn response(headers: HeaderMap, body: &[u8], body_complete: bool) -> CollectedHttpResponse {
        CollectedHttpResponse {
            status: StatusCode::OK,
            final_url: Url::parse("https://example.test/wp-content/plugins/sample/app.js").unwrap(),
            version: "HTTP/1.1".to_owned(),
            headers,
            body: body.to_vec(),
            body_truncated: false,
            body_complete,
            ttfb_ms: 1,
            total_ms: 2,
        }
    }

    #[test]
    fn identity_content_requires_eof_absent_coding_and_consistent_length() {
        let bytes = b"\xef\xbb\xbfconst exact = '\r\n';\r\n";
        let mut exact_headers = HeaderMap::new();
        exact_headers.insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&bytes.len().to_string()).unwrap(),
        );
        assert_eq!(
            response(exact_headers, bytes, true).complete_identity_content_body(),
            Some(bytes.as_slice())
        );

        assert!(response(HeaderMap::new(), bytes, false)
            .complete_identity_content_body()
            .is_none());

        let mut coded = HeaderMap::new();
        coded.insert(CONTENT_ENCODING, HeaderValue::from_static("identity"));
        assert!(response(coded, bytes, true)
            .complete_identity_content_body()
            .is_none());

        let mut wrong_length = HeaderMap::new();
        wrong_length.insert(CONTENT_LENGTH, HeaderValue::from_static("1"));
        assert!(response(wrong_length, bytes, true)
            .complete_identity_content_body()
            .is_none());
    }

    #[test]
    fn content_length_rejects_invalid_or_ambiguous_declarations() {
        for value in ["", "not-a-number", "+4", "4, 4"] {
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_LENGTH, HeaderValue::from_str(value).unwrap());
            assert!(!response(headers, b"test", true).content_length_is_consistent());
        }

        let mut duplicate = HeaderMap::new();
        duplicate.append(CONTENT_LENGTH, HeaderValue::from_static("4"));
        duplicate.append(CONTENT_LENGTH, HeaderValue::from_static("4"));
        assert!(!response(duplicate, b"test", true).content_length_is_consistent());
    }
}
