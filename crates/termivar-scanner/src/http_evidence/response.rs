use reqwest::{header::HeaderMap, StatusCode, Url};

use super::{json_compatible_media_type, normalized_media_type};

#[cfg(feature = "supplied-session-review")]
use crate::supplied_session_review::{
    SuppliedSessionCookieError, SuppliedSessionCookies, SuppliedSessionPolicy,
};

#[cfg(feature = "supplied-session-review")]
const MAX_SUPPLIED_SESSION_SET_COOKIE_FIELDS: usize = 16;
#[cfg(feature = "supplied-session-review")]
const MAX_SUPPLIED_SESSION_SET_COOKIE_FIELD_BYTES: usize = 4 * 1024;
#[cfg(feature = "supplied-session-review")]
const MAX_SUPPLIED_SESSION_SET_COOKIE_TOTAL_BYTES: usize = 16 * 1024;

/// Value-free classification of response cookie updates for a supplied-cookie
/// session. The transport boundary never exposes names or values to the
/// runtime; it retains only the counts needed for fail-closed scheduling.
#[cfg(feature = "supplied-session-review")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SuppliedSessionCookieUpdateClassification {
    None,
    UnselectedOnly,
    Selected,
    Unusable,
}

#[cfg(feature = "supplied-session-review")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SuppliedSessionCookieUpdateObservation {
    classification: SuppliedSessionCookieUpdateClassification,
    selected_count: u8,
    unselected_count: u8,
}

#[cfg(feature = "supplied-session-review")]
impl SuppliedSessionCookieUpdateObservation {
    pub(crate) const fn classification(self) -> SuppliedSessionCookieUpdateClassification {
        self.classification
    }

    pub(crate) const fn selected_count(self) -> u8 {
        self.selected_count
    }

    pub(crate) const fn unselected_count(self) -> u8 {
        self.unselected_count
    }
}

#[cfg(any(feature = "wordpress-review", feature = "secret-exposure-review"))]
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
        feature = "supplied-session-review",
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
        feature = "supplied-session-review",
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

    /// Reduces every separate `Set-Cookie` field to selected/unselected counts.
    ///
    /// Values and attributes never leave this transport-owned object. An
    /// incomplete body, malformed field, or exceeded bound is unusable so the
    /// caller can stop without applying or silently ignoring a possible
    /// credential update.
    #[cfg(feature = "supplied-session-review")]
    pub(crate) fn supplied_session_cookie_updates(
        &self,
        policy: &SuppliedSessionPolicy,
    ) -> SuppliedSessionCookieUpdateObservation {
        use reqwest::header::SET_COOKIE;

        if !self.body_complete() {
            return SuppliedSessionCookieUpdateObservation {
                classification: SuppliedSessionCookieUpdateClassification::Unusable,
                selected_count: 0,
                unselected_count: 0,
            };
        }
        let mut selected = 0_u8;
        let mut unselected = 0_u8;
        let mut total_bytes = 0_usize;
        let mut fields = 0_usize;
        for field in self.headers.get_all(SET_COOKIE).iter() {
            fields = fields.saturating_add(1);
            let bytes = field.as_bytes();
            total_bytes = total_bytes.saturating_add(bytes.len());
            if fields > MAX_SUPPLIED_SESSION_SET_COOKIE_FIELDS
                || bytes.is_empty()
                || bytes.len() > MAX_SUPPLIED_SESSION_SET_COOKIE_FIELD_BYTES
                || total_bytes > MAX_SUPPLIED_SESSION_SET_COOKIE_TOTAL_BYTES
            {
                return SuppliedSessionCookieUpdateObservation {
                    classification: SuppliedSessionCookieUpdateClassification::Unusable,
                    selected_count: 0,
                    unselected_count: 0,
                };
            }
            let Some(name) = valid_set_cookie_name(bytes) else {
                return SuppliedSessionCookieUpdateObservation {
                    classification: SuppliedSessionCookieUpdateClassification::Unusable,
                    selected_count: 0,
                    unselected_count: 0,
                };
            };
            if policy.is_selected_cookie_name(name) {
                selected = selected.saturating_add(1);
            } else {
                unselected = unselected.saturating_add(1);
            }
        }
        let classification = if selected > 0 {
            SuppliedSessionCookieUpdateClassification::Selected
        } else if unselected > 0 {
            SuppliedSessionCookieUpdateClassification::UnselectedOnly
        } else {
            SuppliedSessionCookieUpdateClassification::None
        };
        SuppliedSessionCookieUpdateObservation {
            classification,
            selected_count: selected,
            unselected_count: unselected,
        }
    }

    /// Whether any response cookie was present. V3's initial login-page GET
    /// deliberately does not support pre-authentication cookie state.
    #[cfg(feature = "supplied-session-review")]
    pub(crate) fn supplied_session_has_set_cookie_fields(&self) -> bool {
        self.headers
            .get_all(reqwest::header::SET_COOKIE)
            .iter()
            .next()
            .is_some()
    }

    /// Acquires the exact policy-declared host-only V3 session cookies.
    #[cfg(feature = "supplied-session-review")]
    pub(crate) fn supplied_session_form_login_cookies(
        &self,
        policy: &SuppliedSessionPolicy,
        now_unix_seconds: i64,
    ) -> Result<SuppliedSessionCookies, SuppliedSessionCookieError> {
        if !self.body_complete() || self.status() != 200 {
            return Err(SuppliedSessionCookieError::MalformedSecret);
        }
        SuppliedSessionCookies::from_form_login_set_cookie_fields(
            policy,
            self.headers
                .get_all(reqwest::header::SET_COOKIE)
                .iter()
                .map(reqwest::header::HeaderValue::as_bytes),
            now_unix_seconds,
        )
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

#[cfg(feature = "supplied-session-review")]
const fn cookie_name_byte(byte: u8) -> bool {
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

#[cfg(feature = "supplied-session-review")]
fn valid_set_cookie_name(field: &[u8]) -> Option<&str> {
    let mut sections = field.split(|byte| *byte == b';');
    let pair = sections.next()?;
    let equals = pair.iter().position(|byte| *byte == b'=')?;
    let name = &pair[..equals];
    let value = &pair[equals + 1..];
    if name.is_empty() || !name.iter().copied().all(cookie_name_byte) {
        return None;
    }
    let value_is_valid = if value.first() == Some(&b'"') || value.last() == Some(&b'"') {
        value.len() >= 2
            && value.first() == Some(&b'"')
            && value.last() == Some(&b'"')
            && value[1..value.len() - 1]
                .iter()
                .copied()
                .all(cookie_value_byte)
    } else {
        value.iter().copied().all(cookie_value_byte)
    };
    if !value_is_valid {
        return None;
    }
    for section in sections {
        let attribute = section
            .iter()
            .position(|byte| *byte != b' ')
            .map_or(&[][..], |start| &section[start..]);
        if attribute.is_empty() {
            return None;
        }
        let attribute_name_end = attribute
            .iter()
            .position(|byte| *byte == b'=')
            .unwrap_or(attribute.len());
        if attribute_name_end == 0
            || !attribute[..attribute_name_end]
                .iter()
                .copied()
                .all(cookie_name_byte)
            || !attribute[attribute_name_end..]
                .iter()
                .copied()
                .all(cookie_attribute_byte)
        {
            return None;
        }
    }
    std::str::from_utf8(name).ok()
}

#[cfg(feature = "supplied-session-review")]
const fn cookie_value_byte(byte: u8) -> bool {
    matches!(byte, 0x21 | 0x23..=0x2b | 0x2d..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e)
}

#[cfg(feature = "supplied-session-review")]
const fn cookie_attribute_byte(byte: u8) -> bool {
    matches!(byte, 0x20..=0x3a | 0x3c..=0x7e)
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

#[cfg(all(test, feature = "supplied-session-review"))]
mod supplied_session_tests {
    use reqwest::header::{HeaderMap, HeaderValue, SET_COOKIE};

    use super::{
        CollectedHttpResponse, StatusCode, SuppliedSessionCookieUpdateClassification, Url,
        MAX_SUPPLIED_SESSION_SET_COOKIE_FIELDS, MAX_SUPPLIED_SESSION_SET_COOKIE_FIELD_BYTES,
        MAX_SUPPLIED_SESSION_SET_COOKIE_TOTAL_BYTES,
    };
    use crate::supplied_session_review::SuppliedSessionPolicy;

    fn policy() -> SuppliedSessionPolicy {
        SuppliedSessionPolicy::parse_toml(
            &Url::parse("https://example.test/app/").unwrap(),
            br#"schema = "security.supplied-session-policy/v2"
principal_alias = "fixture-user"
credential_mechanism = "cookie_jar"
cookie_update_policy = "stop_on_selected_cookie"
health_path = "/app/health"
health_json_field = "authenticated"
resources = ["/app/private"]
max_session_requests = 3
max_total_response_bytes = 65536
max_response_body_bytes = 16384
max_wall_time_ms = 5000

[[cookies]]
id = "fixture-session"
name = "session"
domain = "example.test"
host_only = true
path = "/app/"
secure = true
http_only = true
same_site = "lax"
"#,
        )
        .unwrap()
    }

    fn response(headers: HeaderMap, complete: bool) -> CollectedHttpResponse {
        CollectedHttpResponse {
            status: StatusCode::OK,
            final_url: Url::parse("https://example.test/app/private").unwrap(),
            version: "HTTP/1.1".to_owned(),
            headers,
            body: b"{}".to_vec(),
            body_truncated: false,
            body_complete: complete,
            ttfb_ms: 1,
            total_ms: 2,
        }
    }

    #[test]
    fn set_cookie_classification_is_case_sensitive_value_free_and_bounded() {
        let policy = policy();
        let none = response(HeaderMap::new(), true).supplied_session_cookie_updates(&policy);
        assert_eq!(
            none.classification(),
            SuppliedSessionCookieUpdateClassification::None
        );
        assert_eq!(none.selected_count(), 0);
        assert_eq!(none.unselected_count(), 0);

        let mut mixed = HeaderMap::new();
        mixed.append(
            SET_COOKIE,
            HeaderValue::from_static("session=SECRET-MUST-NOT-LEAVE-TRANSPORT; Path=/app/"),
        );
        mixed.append(
            SET_COOKIE,
            HeaderValue::from_static("Session=case-sensitive-other; Path=/app/"),
        );
        mixed.append(
            SET_COOKIE,
            HeaderValue::from_static("analytics=unselected; Path=/"),
        );
        let mixed = response(mixed, true).supplied_session_cookie_updates(&policy);
        assert_eq!(
            mixed.classification(),
            SuppliedSessionCookieUpdateClassification::Selected
        );
        assert_eq!(mixed.selected_count(), 1);
        assert_eq!(mixed.unselected_count(), 2);

        let mut unselected = HeaderMap::new();
        unselected.insert(
            SET_COOKIE,
            HeaderValue::from_static("analytics=value; Path=/"),
        );
        let unselected = response(unselected, true).supplied_session_cookie_updates(&policy);
        assert_eq!(
            unselected.classification(),
            SuppliedSessionCookieUpdateClassification::UnselectedOnly
        );
        assert_eq!(unselected.selected_count(), 0);
        assert_eq!(unselected.unselected_count(), 1);

        let incomplete = response(HeaderMap::new(), false).supplied_session_cookie_updates(&policy);
        assert_eq!(
            incomplete.classification(),
            SuppliedSessionCookieUpdateClassification::Unusable
        );

        for malformed in [
            "no-equals",
            "=empty-name",
            "bad name=value",
            "analytics=bad value",
            "analytics=\"bad value\"",
            "analytics=value, session=rotated",
            "analytics=value; Bad Attribute=true",
            "analytics=value;",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(SET_COOKIE, HeaderValue::from_str(malformed).unwrap());
            assert_eq!(
                response(headers, true)
                    .supplied_session_cookie_updates(&policy)
                    .classification(),
                SuppliedSessionCookieUpdateClassification::Unusable
            );
        }

        let mut too_many = HeaderMap::new();
        for _ in 0..=MAX_SUPPLIED_SESSION_SET_COOKIE_FIELDS {
            too_many.append(SET_COOKIE, HeaderValue::from_static("analytics=value"));
        }
        assert_eq!(
            response(too_many, true)
                .supplied_session_cookie_updates(&policy)
                .classification(),
            SuppliedSessionCookieUpdateClassification::Unusable
        );

        let mut oversized = HeaderMap::new();
        oversized.insert(
            SET_COOKIE,
            HeaderValue::from_str(&format!(
                "analytics={}",
                "a".repeat(MAX_SUPPLIED_SESSION_SET_COOKIE_FIELD_BYTES)
            ))
            .unwrap(),
        );
        assert_eq!(
            response(oversized, true)
                .supplied_session_cookie_updates(&policy)
                .classification(),
            SuppliedSessionCookieUpdateClassification::Unusable
        );

        let mut aggregate_oversized = HeaderMap::new();
        for index in 0..5 {
            let field = format!("analytics{index}={}", "a".repeat(4_080));
            assert!(field.len() <= MAX_SUPPLIED_SESSION_SET_COOKIE_FIELD_BYTES);
            aggregate_oversized.append(SET_COOKIE, HeaderValue::from_str(&field).unwrap());
        }
        assert!(
            aggregate_oversized
                .get_all(SET_COOKIE)
                .iter()
                .map(|field| field.as_bytes().len())
                .sum::<usize>()
                > MAX_SUPPLIED_SESSION_SET_COOKIE_TOTAL_BYTES
        );
        assert_eq!(
            response(aggregate_oversized, true)
                .supplied_session_cookie_updates(&policy)
                .classification(),
            SuppliedSessionCookieUpdateClassification::Unusable
        );
    }
}
