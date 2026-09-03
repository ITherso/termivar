//! Bounded, value-free response projection for native differential review.
//!
//! Raw request and response header values remain borrowed inside this module.
//! The resulting projection contains only fixed-vocabulary relations and is
//! therefore safe to retain in a decision audit trail. Hitting any occurrence,
//! value, or query ceiling fails closed to the corresponding invalid relation.

use reqwest::{
    header::{HeaderMap, HeaderValue},
    Url,
};

use super::HttpProbe;

pub(crate) const MAX_REVIEW_HEADER_OCCURRENCES: usize = 4;
pub(crate) const MAX_REVIEW_HEADER_VALUE_BYTES: usize = 1024;
pub(crate) const MAX_REVIEW_QUERY_PAIRS: usize = 32;
pub(crate) const MAX_REVIEW_QUERY_VALUE_BYTES: usize = 2048;

const ACCESS_CONTROL_ALLOW_ORIGIN: &str = "access-control-allow-origin";
const ACCESS_CONTROL_ALLOW_CREDENTIALS: &str = "access-control-allow-credentials";
const VARY: &str = "vary";
const LOCATION: &str = "location";
const ORIGIN: &str = "origin";

#[cfg(test)]
pub(crate) const EMPTY_REVIEW_RESPONSE_PROJECTION: ReviewResponseProjection =
    ReviewResponseProjection::empty();

/// Relationship between ACAO and the request's bounded `Origin` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CorsAllowOriginRelation {
    Missing,
    ExactRequestOrigin,
    Wildcard,
    Other,
    InvalidOrMultiple,
}

/// Parsed, value-free Access-Control-Allow-Credentials state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CorsAllowCredentialsRelation {
    Missing,
    True,
    Other,
    InvalidOrMultiple,
}

/// Parsed, value-free relationship of `Vary` to `Origin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VaryOriginRelation {
    Missing,
    ContainsOrigin,
    Wildcard,
    Other,
    Invalid,
}

/// Relationship between `Location` and a validated external query value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocationRelation {
    Missing,
    ExactExternalQueryValue,
    Other,
    InvalidOrMultiple,
}

/// Complete fixed-vocabulary projection for one differential response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReviewResponseProjection {
    access_control_allow_origin: CorsAllowOriginRelation,
    access_control_allow_credentials: CorsAllowCredentialsRelation,
    vary_origin: VaryOriginRelation,
    location: LocationRelation,
}

impl ReviewResponseProjection {
    #[cfg(test)]
    pub(crate) const fn empty() -> Self {
        Self {
            access_control_allow_origin: CorsAllowOriginRelation::Missing,
            access_control_allow_credentials: CorsAllowCredentialsRelation::Missing,
            vary_origin: VaryOriginRelation::Missing,
            location: LocationRelation::Missing,
        }
    }

    pub(crate) const fn access_control_allow_origin(&self) -> CorsAllowOriginRelation {
        self.access_control_allow_origin
    }

    pub(crate) const fn access_control_allow_credentials(&self) -> CorsAllowCredentialsRelation {
        self.access_control_allow_credentials
    }

    pub(crate) const fn vary_origin(&self) -> VaryOriginRelation {
        self.vary_origin
    }

    pub(crate) const fn location(&self) -> LocationRelation {
        self.location
    }
}

/// Projects raw response headers against the exact dispatched probe.
///
/// The function performs no I/O, never follows `Location`, and does not retain
/// any raw request, response, or query value.
pub(crate) fn project_review_response(
    probe: &HttpProbe,
    headers: &HeaderMap,
) -> ReviewResponseProjection {
    ReviewResponseProjection {
        access_control_allow_origin: project_allow_origin(probe, headers),
        access_control_allow_credentials: project_allow_credentials(headers),
        vary_origin: project_vary_origin(headers),
        location: project_location(probe, headers),
    }
}

fn project_allow_origin(probe: &HttpProbe, headers: &HeaderMap) -> CorsAllowOriginRelation {
    let value = match bounded_single_value(headers, ACCESS_CONTROL_ALLOW_ORIGIN) {
        Ok(None) => return CorsAllowOriginRelation::Missing,
        Ok(Some(value)) => value,
        Err(()) => return CorsAllowOriginRelation::InvalidOrMultiple,
    };
    let Ok(value) = value.to_str() else {
        return CorsAllowOriginRelation::InvalidOrMultiple;
    };
    if value == "*" {
        return CorsAllowOriginRelation::Wildcard;
    }
    if value == "null" {
        return CorsAllowOriginRelation::Other;
    }
    if !is_canonical_http_origin(value) {
        return CorsAllowOriginRelation::InvalidOrMultiple;
    }

    match bounded_request_origin(probe) {
        Ok(Some(request_origin)) if request_origin == value => {
            CorsAllowOriginRelation::ExactRequestOrigin
        },
        Ok(_) => CorsAllowOriginRelation::Other,
        Err(()) => CorsAllowOriginRelation::InvalidOrMultiple,
    }
}

fn project_allow_credentials(headers: &HeaderMap) -> CorsAllowCredentialsRelation {
    let value = match bounded_single_value(headers, ACCESS_CONTROL_ALLOW_CREDENTIALS) {
        Ok(None) => return CorsAllowCredentialsRelation::Missing,
        Ok(Some(value)) => value,
        Err(()) => return CorsAllowCredentialsRelation::InvalidOrMultiple,
    };
    let Ok(value) = value.to_str() else {
        return CorsAllowCredentialsRelation::InvalidOrMultiple;
    };
    if value == "true" {
        CorsAllowCredentialsRelation::True
    } else if !value.is_empty()
        && value
            .bytes()
            .all(|byte| (0x21..=0x7e).contains(&byte) && byte != b',')
    {
        CorsAllowCredentialsRelation::Other
    } else {
        CorsAllowCredentialsRelation::InvalidOrMultiple
    }
}

fn project_vary_origin(headers: &HeaderMap) -> VaryOriginRelation {
    let values = match bounded_values(headers, VARY) {
        Ok(values) if values.is_empty() => return VaryOriginRelation::Missing,
        Ok(values) => values,
        Err(()) => return VaryOriginRelation::Invalid,
    };
    let mut contains_origin = false;
    for value in values {
        let Ok(value) = value.to_str() else {
            return VaryOriginRelation::Invalid;
        };
        for token in value.split(',') {
            let token = token.trim_matches([' ', '\t']);
            if !valid_header_token(token) {
                return VaryOriginRelation::Invalid;
            }
            if token == "*" {
                return VaryOriginRelation::Wildcard;
            }
            contains_origin |= token.eq_ignore_ascii_case("origin");
        }
    }
    if contains_origin {
        VaryOriginRelation::ContainsOrigin
    } else {
        VaryOriginRelation::Other
    }
}

fn project_location(probe: &HttpProbe, headers: &HeaderMap) -> LocationRelation {
    let value = match bounded_single_value(headers, LOCATION) {
        Ok(None) => return LocationRelation::Missing,
        Ok(Some(value)) => value,
        Err(()) => return LocationRelation::InvalidOrMultiple,
    };
    let Ok(value) = value.to_str() else {
        return LocationRelation::InvalidOrMultiple;
    };
    if !valid_location_reference(probe.url(), value) {
        return LocationRelation::InvalidOrMultiple;
    }

    let external_query_value = match exact_external_query_value(probe.url()) {
        Ok(value) => value,
        Err(()) => return LocationRelation::InvalidOrMultiple,
    };
    if external_query_value.is_some_and(|candidate| candidate.as_bytes() == value.as_bytes()) {
        LocationRelation::ExactExternalQueryValue
    } else {
        LocationRelation::Other
    }
}

fn bounded_request_origin(probe: &HttpProbe) -> Result<Option<&str>, ()> {
    let Some(value) = probe.headers().get(ORIGIN) else {
        return Ok(None);
    };
    if value.len() > MAX_REVIEW_HEADER_VALUE_BYTES || !is_canonical_http_origin(value) {
        return Err(());
    }
    Ok(Some(value))
}

fn bounded_single_value<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<Option<&'a HeaderValue>, ()> {
    let values = bounded_values(headers, name)?;
    match values.as_slice() {
        [] => Ok(None),
        [value] => Ok(Some(*value)),
        _ => Err(()),
    }
}

fn bounded_values<'a>(headers: &'a HeaderMap, name: &str) -> Result<Vec<&'a HeaderValue>, ()> {
    let values: Vec<_> = headers
        .get_all(name)
        .iter()
        .take(MAX_REVIEW_HEADER_OCCURRENCES + 1)
        .collect();
    if values.len() > MAX_REVIEW_HEADER_OCCURRENCES
        || values
            .iter()
            .any(|value| value.as_bytes().len() > MAX_REVIEW_HEADER_VALUE_BYTES)
    {
        return Err(());
    }
    Ok(values)
}

/// Returns one unambiguous validated external query value, or `None` when no
/// query value meets the contract. Any ceiling breach or multiple candidates
/// invalidates the relation rather than selecting one opportunistically.
fn exact_external_query_value(url: &Url) -> Result<Option<std::borrow::Cow<'_, str>>, ()> {
    let mut candidate = None;
    let mut pairs = url.query_pairs();
    for _ in 0..MAX_REVIEW_QUERY_PAIRS {
        let Some((name, value)) = pairs.next() else {
            return Ok(candidate);
        };
        if name.len() > MAX_REVIEW_QUERY_VALUE_BYTES || value.len() > MAX_REVIEW_QUERY_VALUE_BYTES {
            return Err(());
        }
        if is_safe_invalid_https_url(&value) {
            if candidate.is_some() {
                return Err(());
            }
            candidate = Some(value);
        }
    }
    if pairs.next().is_some() {
        Err(())
    } else {
        Ok(candidate)
    }
}

fn is_canonical_http_origin(value: &str) -> bool {
    if value.is_empty() || !value.is_ascii() {
        return false;
    }
    let Ok(parsed) = Url::parse(value) else {
        return false;
    };
    matches!(parsed.scheme(), "http" | "https") && parsed.origin().ascii_serialization() == value
}

fn is_safe_invalid_https_url(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_REVIEW_QUERY_VALUE_BYTES
        || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return false;
    }
    let Ok(parsed) = Url::parse(value) else {
        return false;
    };
    if parsed.scheme() != "https"
        || parsed.fragment().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || authority_contains_userinfo(value)
    {
        return false;
    }
    parsed
        .domain()
        .is_some_and(|domain| domain.len() > ".invalid".len() && domain.ends_with(".invalid"))
}

fn valid_location_reference(base: &Url, value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        && base.join(value).is_ok()
}

fn authority_contains_userinfo(value: &str) -> bool {
    let Some((_, remainder)) = value.split_once("://") else {
        return false;
    };
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    remainder[..authority_end].contains('@')
}

fn valid_header_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
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
        })
}

#[cfg(test)]
mod tests {
    use reqwest::header::{HeaderName, HeaderValue};

    use super::*;
    use crate::http_evidence::HttpProbeMethod;

    fn probe(raw_url: &str, origin: Option<&str>) -> HttpProbe {
        let probe = HttpProbe::new(Url::parse(raw_url).unwrap(), HttpProbeMethod::Get).unwrap();
        match origin {
            Some(origin) => probe.with_header(ORIGIN, origin).unwrap(),
            None => probe,
        }
    }

    fn headers(values: &[(&str, &[u8])]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in values {
            headers.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_bytes(value).unwrap(),
            );
        }
        headers
    }

    #[test]
    fn missing_headers_project_to_missing_relations() {
        let projection =
            project_review_response(&probe("https://target.test/", None), &HeaderMap::new());
        assert_eq!(
            projection.access_control_allow_origin(),
            CorsAllowOriginRelation::Missing
        );
        assert_eq!(
            projection.access_control_allow_credentials(),
            CorsAllowCredentialsRelation::Missing
        );
        assert_eq!(projection.vary_origin(), VaryOriginRelation::Missing);
        assert_eq!(projection.location(), LocationRelation::Missing);
    }

    #[test]
    fn cors_relations_are_exact_and_value_free() {
        let probe = probe("https://target.test/", Some("https://nonce.review.invalid"));
        let projection = project_review_response(
            &probe,
            &headers(&[
                (ACCESS_CONTROL_ALLOW_ORIGIN, b"https://nonce.review.invalid"),
                (ACCESS_CONTROL_ALLOW_CREDENTIALS, b"true"),
                (VARY, b"Accept-Encoding, Origin"),
            ]),
        );
        assert_eq!(
            projection.access_control_allow_origin(),
            CorsAllowOriginRelation::ExactRequestOrigin
        );
        assert_eq!(
            projection.access_control_allow_credentials(),
            CorsAllowCredentialsRelation::True
        );
        assert_eq!(projection.vary_origin(), VaryOriginRelation::ContainsOrigin);
        let debug = format!("{projection:?}");
        assert!(!debug.contains("nonce.review.invalid"));
    }

    #[test]
    fn cors_wildcard_and_other_are_not_exact_origin() {
        let probe = probe("https://target.test/", Some("https://candidate.invalid"));
        let wildcard = project_review_response(
            &probe,
            &headers(&[
                (ACCESS_CONTROL_ALLOW_ORIGIN, b"*"),
                (ACCESS_CONTROL_ALLOW_CREDENTIALS, b"false"),
                (VARY, b"*"),
            ]),
        );
        assert_eq!(
            wildcard.access_control_allow_origin(),
            CorsAllowOriginRelation::Wildcard
        );
        assert_eq!(
            wildcard.access_control_allow_credentials(),
            CorsAllowCredentialsRelation::Other
        );
        assert_eq!(wildcard.vary_origin(), VaryOriginRelation::Wildcard);

        let other = project_review_response(
            &probe,
            &headers(&[(ACCESS_CONTROL_ALLOW_ORIGIN, b"https://different.invalid")]),
        );
        assert_eq!(
            other.access_control_allow_origin(),
            CorsAllowOriginRelation::Other
        );
    }

    #[test]
    fn cors_invalid_and_multiple_values_fail_closed() {
        let probe = probe("https://target.test/", Some("https://candidate.invalid"));
        for name in [
            ACCESS_CONTROL_ALLOW_ORIGIN,
            ACCESS_CONTROL_ALLOW_CREDENTIALS,
        ] {
            let projection =
                project_review_response(&probe, &headers(&[(name, b"one"), (name, b"two")]));
            if name == ACCESS_CONTROL_ALLOW_ORIGIN {
                assert_eq!(
                    projection.access_control_allow_origin(),
                    CorsAllowOriginRelation::InvalidOrMultiple
                );
            } else {
                assert_eq!(
                    projection.access_control_allow_credentials(),
                    CorsAllowCredentialsRelation::InvalidOrMultiple
                );
            }
        }

        let malformed = project_review_response(
            &probe,
            &headers(&[
                (ACCESS_CONTROL_ALLOW_ORIGIN, b"https://candidate.invalid/"),
                (ACCESS_CONTROL_ALLOW_CREDENTIALS, b"true,false"),
                (VARY, b"Origin,,Accept"),
            ]),
        );
        assert_eq!(
            malformed.access_control_allow_origin(),
            CorsAllowOriginRelation::InvalidOrMultiple
        );
        assert_eq!(
            malformed.access_control_allow_credentials(),
            CorsAllowCredentialsRelation::InvalidOrMultiple
        );
        assert_eq!(malformed.vary_origin(), VaryOriginRelation::Invalid);
    }

    #[test]
    fn vary_combines_bounded_occurrences_case_insensitively() {
        let projection = project_review_response(
            &probe("https://target.test/", None),
            &headers(&[(VARY, b"Accept"), (VARY, b"oRiGiN")]),
        );
        assert_eq!(projection.vary_origin(), VaryOriginRelation::ContainsOrigin);
        let other = project_review_response(
            &probe("https://target.test/", None),
            &headers(&[(VARY, b"Accept-Encoding")]),
        );
        assert_eq!(other.vary_origin(), VaryOriginRelation::Other);
    }

    #[test]
    fn location_matches_one_decoded_safe_external_query_value_exactly() {
        let probe = probe(
            "https://target.test/?next=https%3A%2F%2Fnonce.review.invalid%2Flanding%3Fcase%3D7",
            None,
        );
        let exact = project_review_response(
            &probe,
            &headers(&[(LOCATION, b"https://nonce.review.invalid/landing?case=7")]),
        );
        assert_eq!(exact.location(), LocationRelation::ExactExternalQueryValue);

        let changed = project_review_response(
            &probe,
            &headers(&[(LOCATION, b"https://nonce.review.invalid/other")]),
        );
        assert_eq!(changed.location(), LocationRelation::Other);
    }

    #[test]
    fn location_requires_https_invalid_without_credentials_or_fragment() {
        for query_value in [
            "http%3A%2F%2Fnonce.invalid%2F",
            "https%3A%2F%2Fexample.test%2F",
            "https%3A%2F%2F127.0.0.1%2F",
            "https%3A%2F%2Fuser%40nonce.invalid%2F",
            "https%3A%2F%2Fnonce.invalid%2F%23fragment",
        ] {
            let probe = probe(&format!("https://target.test/?next={query_value}"), None);
            let projection =
                project_review_response(&probe, &headers(&[(LOCATION, b"https://nonce.invalid/")]));
            assert_eq!(projection.location(), LocationRelation::Other);
        }
    }

    #[test]
    fn multiple_external_candidates_and_locations_fail_closed() {
        let ambiguous_probe = probe(
            "https://target.test/?a=https%3A%2F%2Fa.invalid%2F&b=https%3A%2F%2Fb.invalid%2F",
            None,
        );
        let ambiguous = project_review_response(
            &ambiguous_probe,
            &headers(&[(LOCATION, b"https://a.invalid/")]),
        );
        assert_eq!(ambiguous.location(), LocationRelation::InvalidOrMultiple);

        let multiple = project_review_response(
            &probe("https://target.test/?next=https%3A%2F%2Fa.invalid%2F", None),
            &headers(&[
                (LOCATION, b"https://a.invalid/"),
                (LOCATION, b"https://b.invalid/"),
            ]),
        );
        assert_eq!(multiple.location(), LocationRelation::InvalidOrMultiple);
    }

    #[test]
    fn malformed_location_fails_closed_but_valid_relative_location_is_other() {
        let probe = probe(
            "https://target.test/?next=https%3A%2F%2Fcandidate.invalid%2F",
            None,
        );
        for malformed in [b"".as_slice(), b"has a space", b"https://[invalid"] {
            let projection = project_review_response(&probe, &headers(&[(LOCATION, malformed)]));
            assert_eq!(projection.location(), LocationRelation::InvalidOrMultiple);
        }

        let relative = project_review_response(&probe, &headers(&[(LOCATION, b"/elsewhere")]));
        assert_eq!(relative.location(), LocationRelation::Other);
    }

    #[test]
    fn header_occurrence_and_value_ceilings_fail_closed() {
        let probe = probe("https://target.test/", Some("https://candidate.invalid"));
        let mut too_many = HeaderMap::new();
        for _ in 0..=MAX_REVIEW_HEADER_OCCURRENCES {
            too_many.append(VARY, HeaderValue::from_static("Origin"));
        }
        assert_eq!(
            project_review_response(&probe, &too_many).vary_origin(),
            VaryOriginRelation::Invalid
        );

        let oversized = vec![b'a'; MAX_REVIEW_HEADER_VALUE_BYTES + 1];
        let oversized = headers(&[(ACCESS_CONTROL_ALLOW_ORIGIN, &oversized)]);
        assert_eq!(
            project_review_response(&probe, &oversized).access_control_allow_origin(),
            CorsAllowOriginRelation::InvalidOrMultiple
        );
    }

    #[test]
    fn query_pair_and_decoded_value_ceilings_fail_closed() {
        let too_many_query = format!(
            "https://target.test/?{}",
            (0..=MAX_REVIEW_QUERY_PAIRS)
                .map(|index| format!("p{index}=x"))
                .collect::<Vec<_>>()
                .join("&")
        );
        let projection = project_review_response(
            &probe(&too_many_query, None),
            &headers(&[(LOCATION, b"https://candidate.invalid/")]),
        );
        assert_eq!(projection.location(), LocationRelation::InvalidOrMultiple);

        let oversized = "x".repeat(MAX_REVIEW_QUERY_VALUE_BYTES + 1);
        let projection = project_review_response(
            &probe(&format!("https://target.test/?next={oversized}"), None),
            &headers(&[(LOCATION, b"https://candidate.invalid/")]),
        );
        assert_eq!(projection.location(), LocationRelation::InvalidOrMultiple);
    }

    #[test]
    fn opaque_header_bytes_fail_closed_without_entering_debug() {
        let probe = probe("https://target.test/", Some("https://candidate.invalid"));
        let projection = project_review_response(
            &probe,
            &headers(&[
                (ACCESS_CONTROL_ALLOW_ORIGIN, &[0x80]),
                (ACCESS_CONTROL_ALLOW_CREDENTIALS, &[0x80]),
                (VARY, &[0x80]),
                (LOCATION, &[0x80]),
            ]),
        );
        assert_eq!(
            projection.access_control_allow_origin(),
            CorsAllowOriginRelation::InvalidOrMultiple
        );
        assert_eq!(
            projection.access_control_allow_credentials(),
            CorsAllowCredentialsRelation::InvalidOrMultiple
        );
        assert_eq!(projection.vary_origin(), VaryOriginRelation::Invalid);
        assert_eq!(projection.location(), LocationRelation::InvalidOrMultiple);
        assert!(!format!("{projection:?}").contains(char::from(0x80)));
    }
}
