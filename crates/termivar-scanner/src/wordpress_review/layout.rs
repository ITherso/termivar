//! Strict, bounded operator declarations for WordPress deployment locations.
//!
//! A layout binds inert same-origin directory roles to one selected
//! application. It neither authenticates server configuration nor grants
//! transport authority; discovery still requires an eligible observed asset.

use std::fmt;

use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use url::Url;

use super::{parse_bounded_json, WordPressReviewError, MAX_WORDPRESS_REFERENCE_BYTES};

pub const WORDPRESS_DISCOVERY_LAYOUT_SCHEMA: &str = "security.wordpress-layout/v1";
pub const MAX_WORDPRESS_DISCOVERY_LAYOUT_BYTES: usize = 16 * 1024;
const MAX_LAYOUT_JSON_NODES: usize = 32;
const MAX_LAYOUT_JSON_MEMBERS: usize = 8;

#[derive(Clone, Eq, PartialEq)]
pub struct WordPressDiscoveryLayout {
    application_url: Url,
    core_base_url: Option<Url>,
    themes_base_url: Option<Url>,
    plugins_base_url: Option<Url>,
    byte_length: usize,
    sha256: [u8; 32],
}

impl fmt::Debug for WordPressDiscoveryLayout {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WordPressDiscoveryLayout")
            .field("application_url", &"<redacted>")
            .field("has_core_base_url", &self.core_base_url.is_some())
            .field("has_themes_base_url", &self.themes_base_url.is_some())
            .field("has_plugins_base_url", &self.plugins_base_url.is_some())
            .field("byte_length", &self.byte_length)
            .field("sha256", &"<redacted>")
            .finish()
    }
}

impl WordPressDiscoveryLayout {
    #[must_use]
    pub const fn application_url(&self) -> &Url {
        &self.application_url
    }

    #[must_use]
    pub const fn core_base_url(&self) -> Option<&Url> {
        self.core_base_url.as_ref()
    }

    #[must_use]
    pub const fn themes_base_url(&self) -> Option<&Url> {
        self.themes_base_url.as_ref()
    }

    #[must_use]
    pub const fn plugins_base_url(&self) -> Option<&Url> {
        self.plugins_base_url.as_ref()
    }

    #[must_use]
    pub const fn byte_length(&self) -> usize {
        self.byte_length
    }

    #[must_use]
    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}

pub fn parse_wordpress_discovery_layout(
    bytes: &[u8],
) -> Result<WordPressDiscoveryLayout, WordPressReviewError> {
    let value = parse_bounded_json(
        bytes,
        MAX_WORDPRESS_DISCOVERY_LAYOUT_BYTES,
        MAX_LAYOUT_JSON_NODES,
        MAX_LAYOUT_JSON_MEMBERS,
        WordPressReviewError::DiscoveryLayoutTooLarge,
    )?;
    if value
        .as_object()
        .and_then(|object| object.get("schema"))
        .and_then(serde_json::Value::as_str)
        != Some(WORDPRESS_DISCOVERY_LAYOUT_SCHEMA)
    {
        return Err(WordPressReviewError::UnsupportedSchema);
    }
    let wire: LayoutWire =
        serde_json::from_value(value).map_err(|_| WordPressReviewError::InvalidDiscoveryLayout)?;
    let application_url =
        validate_directory_url(&wire.application_url, DirectoryRole::Application)?;
    let core_base_url = wire
        .core_base_url
        .as_deref()
        .map(|value| validate_directory_url(value, DirectoryRole::Core))
        .transpose()?;
    let themes_base_url = wire
        .themes_base_url
        .as_deref()
        .map(|value| validate_directory_url(value, DirectoryRole::Themes))
        .transpose()?;
    let plugins_base_url = wire
        .plugins_base_url
        .as_deref()
        .map(|value| validate_directory_url(value, DirectoryRole::Plugins))
        .transpose()?;
    if core_base_url.is_none() && themes_base_url.is_none() && plugins_base_url.is_none() {
        return Err(WordPressReviewError::InvalidDiscoveryLayout);
    }
    for base in [
        core_base_url.as_ref(),
        themes_base_url.as_ref(),
        plugins_base_url.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        if base.origin() != application_url.origin() {
            return Err(WordPressReviewError::InvalidDiscoveryLayout);
        }
    }
    if core_base_url.as_ref() == Some(&application_url)
        && themes_base_url.is_none()
        && plugins_base_url.is_none()
    {
        return Err(WordPressReviewError::InvalidDiscoveryLayout);
    }
    if themes_base_url
        .as_ref()
        .zip(plugins_base_url.as_ref())
        .is_some_and(|(themes, plugins)| {
            directory_is_segment_prefix(themes, plugins)
                || directory_is_segment_prefix(plugins, themes)
        })
    {
        return Err(WordPressReviewError::InvalidDiscoveryLayout);
    }
    Ok(WordPressDiscoveryLayout {
        application_url,
        core_base_url,
        themes_base_url,
        plugins_base_url,
        byte_length: bytes.len(),
        sha256: Sha256::digest(bytes).into(),
    })
}

#[derive(Clone, Copy)]
enum DirectoryRole {
    Application,
    Core,
    Themes,
    Plugins,
}

fn validate_directory_url(value: &str, role: DirectoryRole) -> Result<Url, WordPressReviewError> {
    if value.is_empty()
        || value.len() > MAX_WORDPRESS_REFERENCE_BYTES
        || value.chars().any(|character| {
            character == '\\' || character.is_control() || character.is_whitespace()
        })
        || value.as_bytes().contains(&b'%')
    {
        return Err(WordPressReviewError::InvalidDiscoveryLayout);
    }
    let Some(raw_path) = raw_http_directory_path(value) else {
        return Err(WordPressReviewError::InvalidDiscoveryLayout);
    };
    if raw_path.starts_with("//")
        || raw_path.split('/').enumerate().any(|(index, segment)| {
            matches!(segment, "." | "..")
                || (segment.is_empty() && index != 0 && index + 1 != raw_path.split('/').count())
                || is_device_like_segment(segment)
        })
    {
        return Err(WordPressReviewError::InvalidDiscoveryLayout);
    }
    let url = Url::parse(value).map_err(|_| WordPressReviewError::InvalidDiscoveryLayout)?;
    if url.as_str() != value
        || !matches!(url.scheme(), "http" | "https")
        || !url.has_host()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.path().ends_with('/')
        || (matches!(role, DirectoryRole::Themes | DirectoryRole::Plugins) && url.path() == "/")
    {
        return Err(WordPressReviewError::InvalidDiscoveryLayout);
    }
    Ok(url)
}

fn is_device_like_segment(segment: &str) -> bool {
    if segment.is_empty() {
        return false;
    }
    let normalized = segment.trim_end_matches(['.', ' ']);
    if normalized.is_empty() || normalized != segment || normalized.contains(':') {
        return true;
    }
    let stem = normalized
        .split_once('.')
        .map_or(normalized, |(stem, _)| stem)
        .to_ascii_lowercase();
    matches!(stem.as_str(), "con" | "prn" | "aux" | "nul")
        || stem
            .strip_prefix("com")
            .or_else(|| stem.strip_prefix("lpt"))
            .is_some_and(|number| number.len() == 1 && matches!(number.as_bytes()[0], b'1'..=b'9'))
        || stem.len() == 2 && stem.as_bytes()[0].is_ascii_alphabetic() && stem.as_bytes()[1] == b'|'
}

fn raw_http_directory_path(value: &str) -> Option<&str> {
    let scheme_bytes = if value
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
    {
        7
    } else if value
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
    {
        8
    } else {
        return None;
    };
    let authority_and_path = value.get(scheme_bytes..)?;
    let path_offset = authority_and_path.find('/')?;
    let authority = &authority_and_path[..path_offset];
    let path = &authority_and_path[path_offset..];
    if authority.is_empty()
        || authority
            .chars()
            .any(|character| matches!(character, '@' | '?' | '#'))
        || !path.starts_with('/')
        || !path.ends_with('/')
    {
        return None;
    }
    Some(path)
}

fn directory_is_segment_prefix(left: &Url, right: &Url) -> bool {
    if left.origin() != right.origin() {
        return false;
    }
    let Some(left) = left.path_segments() else {
        return false;
    };
    let Some(right) = right.path_segments() else {
        return false;
    };
    let left = left
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    let right = right
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    left.len() <= right.len() && left.iter().zip(&right).all(|(left, right)| left == right)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LayoutWire {
    #[allow(dead_code)]
    schema: String,
    application_url: String,
    #[serde(default, deserialize_with = "deserialize_present_url")]
    core_base_url: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_url")]
    themes_base_url: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_url")]
    plugins_base_url: Option<String>,
}

fn deserialize_present_url<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_layout_retains_exact_input_identity() {
        let bytes = br#"{
          "schema":"security.wordpress-layout/v1",
          "application_url":"https://example.test/blog/",
          "core_base_url":"https://example.test/cms/",
          "themes_base_url":"https://example.test/site-content/themes/",
          "plugins_base_url":"https://example.test/modules/"
        }"#;
        let layout = parse_wordpress_discovery_layout(bytes).unwrap();
        assert_eq!(layout.application_url().path(), "/blog/");
        assert_eq!(layout.core_base_url().unwrap().path(), "/cms/");
        assert_eq!(
            layout.themes_base_url().unwrap().path(),
            "/site-content/themes/"
        );
        assert_eq!(layout.plugins_base_url().unwrap().path(), "/modules/");
        assert_eq!(layout.byte_length(), bytes.len());
        let expected: [u8; 32] = Sha256::digest(bytes).into();
        assert_eq!(layout.sha256(), &expected);
    }

    #[test]
    fn layout_rejects_ambiguous_or_authority_widening_shapes() {
        for document in [
            r#"{"schema":"security.wordpress-layout/v1","application_url":"https://example.test/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"https://example.test/","themes_base_url":"https://other.test/themes/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"https://example.test/","themes_base_url":"https://example.test/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"https://example.test/","themes_base_url":"https://example.test/content/","plugins_base_url":"https://example.test/content/plugins/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"https://example.test/","core_base_url":"https://example.test/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"https://user@example.test/","core_base_url":"https://example.test/cms/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"https://example.test/blog","core_base_url":"https://example.test/cms/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"https://example.test/a/../","core_base_url":"https://example.test/cms/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"https://example.test/%252e%252e/","core_base_url":"https://example.test/cms/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"https://example.test/%2e%2e/","core_base_url":"https://example.test/cms/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"https://example.test/%00/","core_base_url":"https://example.test/cms/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"https://example.test//blog/","core_base_url":"https://example.test/cms/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"https://example.test/blog//child/","core_base_url":"https://example.test/cms/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"file:///C:/blog/","core_base_url":"file:///C:/cms/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"https://example.test/C:/blog/","core_base_url":"https://example.test/cms/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"https://example.test/C%3a/blog/","core_base_url":"https://example.test/cms/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"https://example.test/C|/blog/","core_base_url":"https://example.test/cms/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"https://example.test/blog/","core_base_url":"https://example.test/CON/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"https://example.test/blog/","core_base_url":"https://example.test/lpt1.data/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"https://example.test/blog/","core_base_url":"https://example.test/content./"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"https://example.test/blog/","themes_base_url":"https://example.test/content/themes/","plugins_base_url":"https://example.test/content/%74hemes/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"https://example.test/blog/?mode=1","core_base_url":"https://example.test/cms/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"https:example.test/blog/","core_base_url":"https://example.test/cms/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"https:/example.test/blog/","core_base_url":"https://example.test/cms/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"https:///example.test/blog/","core_base_url":"https://example.test/cms/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":" https://example.test/blog/","core_base_url":"https://example.test/cms/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"https://@example.test/blog/","core_base_url":"https://example.test/cms/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"https://%65xample.test/blog/","core_base_url":"https://example.test/cms/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"https://EXAMPLE.test/blog/","core_base_url":"https://example.test/cms/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"https://bücher.example/blog/","core_base_url":"https://example.test/cms/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"http://2130706433/blog/","core_base_url":"http://127.0.0.1/cms/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"http://127.1/blog/","core_base_url":"http://127.0.0.1/cms/"}"#,
            r#"{"schema":"security.wordpress-layout/v1","application_url":"http://example.test:80/blog/","core_base_url":"http://example.test/cms/"}"#,
            r##"{"schema":"security.wordpress-layout/v1","application_url":"https://example.test/blog/#fragment","core_base_url":"https://example.test/cms/"}"##,
        ] {
            assert!(
                parse_wordpress_discovery_layout(document.as_bytes()).is_err(),
                "{document}"
            );
        }
        let unicode_control = "{\"schema\":\"security.wordpress-layout/v1\",\"application_url\":\"https://example.test/blog/\",\"core_base_url\":\"https://example.test/control\u{85}/\"}";
        assert_eq!(
            parse_wordpress_discovery_layout(unicode_control.as_bytes()).unwrap_err(),
            WordPressReviewError::InvalidDiscoveryLayout
        );
    }

    #[test]
    fn layout_requires_canonical_ports_and_one_exact_effective_origin() {
        let accepted = br#"{
          "schema":"security.wordpress-layout/v1",
          "application_url":"https://example.test:8443/blog/",
          "core_base_url":"https://example.test:8443/cms/"
        }"#;
        assert!(parse_wordpress_discovery_layout(accepted).is_ok());

        let default_port = br#"{
          "schema":"security.wordpress-layout/v1",
          "application_url":"https://example.test/blog/",
          "core_base_url":"https://example.test:443/cms/"
        }"#;
        assert_eq!(
            parse_wordpress_discovery_layout(default_port).unwrap_err(),
            WordPressReviewError::InvalidDiscoveryLayout
        );

        let alternate_port = br#"{
          "schema":"security.wordpress-layout/v1",
          "application_url":"https://example.test:8443/blog/",
          "core_base_url":"https://example.test/cms/"
        }"#;
        assert_eq!(
            parse_wordpress_discovery_layout(alternate_port).unwrap_err(),
            WordPressReviewError::InvalidDiscoveryLayout
        );
    }

    #[test]
    fn layout_rejects_duplicates_unknowns_and_limit_plus_one() {
        let duplicate = br#"{"schema":"security.wordpress-layout/v1","application_url":"https://example.test/","application_url":"https://example.test/blog/","core_base_url":"https://example.test/cms/"}"#;
        assert_eq!(
            parse_wordpress_discovery_layout(duplicate).unwrap_err(),
            WordPressReviewError::DuplicateKey
        );
        let unknown = br#"{"schema":"security.wordpress-layout/v1","application_url":"https://example.test/","core_base_url":"https://example.test/cms/","paths":[]}"#;
        assert_eq!(
            parse_wordpress_discovery_layout(unknown).unwrap_err(),
            WordPressReviewError::InvalidDiscoveryLayout
        );
        for explicit_null in [
            br#"{"schema":"security.wordpress-layout/v1","application_url":"https://example.test/","core_base_url":null}"#.as_slice(),
            br#"{"schema":"security.wordpress-layout/v1","application_url":"https://example.test/","themes_base_url":null}"#.as_slice(),
            br#"{"schema":"security.wordpress-layout/v1","application_url":"https://example.test/","plugins_base_url":null}"#.as_slice(),
        ] {
            assert_eq!(
                parse_wordpress_discovery_layout(explicit_null).unwrap_err(),
                WordPressReviewError::InvalidDiscoveryLayout
            );
        }
        let oversized_reference = format!(
            r#"{{"schema":"security.wordpress-layout/v1","application_url":"https://example.test/","core_base_url":"https://example.test/{}/"}}"#,
            "a".repeat(MAX_WORDPRESS_REFERENCE_BYTES)
        );
        assert_eq!(
            parse_wordpress_discovery_layout(oversized_reference.as_bytes()).unwrap_err(),
            WordPressReviewError::JsonLimitExceeded
        );
        assert_eq!(
            parse_wordpress_discovery_layout(&vec![b' '; MAX_WORDPRESS_DISCOVERY_LAYOUT_BYTES + 1])
                .unwrap_err(),
            WordPressReviewError::DiscoveryLayoutTooLarge
        );
    }

    #[test]
    fn layout_debug_redacts_operator_urls() {
        let sentinel = "layout-private-host.invalid/operator-secret-path";
        let document = format!(
            r#"{{"schema":"security.wordpress-layout/v1","application_url":"https://{sentinel}/","core_base_url":"https://{sentinel}/private-core/"}}"#
        );
        let debug = format!(
            "{:?}",
            parse_wordpress_discovery_layout(document.as_bytes()).unwrap()
        );
        assert!(!debug.contains("layout-private-host"), "{debug}");
        assert!(!debug.contains("operator-secret-path"), "{debug}");
        assert!(!debug.contains("private-core"), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");
        assert!(debug.contains("has_core_base_url: true"), "{debug}");
    }
}
