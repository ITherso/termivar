//! Bounded source-level attribute reflection intelligence.
//!
//! This finite-state source pass supplements the tree parser. It recognizes
//! only one exact scanner-owned marker in one supported start-tag attribute
//! value and retains no source slice or attribute value.

use std::fmt;

use super::{reflection_context::attribute_context, ExactHtmlReflectionContext};
use crate::MAX_HTTP_BODY_LIMIT;

const MAX_ATTRIBUTE_SOURCE_ELEMENT_NAME_BYTES: usize = 128;
const MAX_ATTRIBUTE_SOURCE_ATTRIBUTE_NAME_BYTES: usize = 128;
const MAX_ATTRIBUTE_SOURCE_MARKER_BYTES: usize = 128;
const MAX_ATTRIBUTE_SOURCE_ATTRIBUTES_PER_TAG: usize = 256;
const NO_ATTRIBUTE_SOURCE_VALUE: &str = "none";

/// Original source delimiter for one exact attribute-value reflection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(in crate::web_runtime) enum AttributeQuoteMode {
    DoubleQuoted,
    SingleQuoted,
    Unquoted,
}

impl AttributeQuoteMode {
    pub(in crate::web_runtime) const fn stable_id(self) -> &'static str {
        match self {
            Self::DoubleQuoted => "double-quoted",
            Self::SingleQuoted => "single-quoted",
            Self::Unquoted => "unquoted",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "double-quoted" => Some(Self::DoubleQuoted),
            "single-quoted" => Some(Self::SingleQuoted),
            "unquoted" => Some(Self::Unquoted),
            _ => None,
        }
    }
}

/// Non-secret structural source anchor cross-checked against the HTML DOM.
#[derive(Clone, PartialEq, Eq)]
pub(in crate::web_runtime) struct AttributeReflectionAnchor {
    quote_mode: AttributeQuoteMode,
    element_local_name: String,
    attribute_local_name: String,
    context: ExactHtmlReflectionContext,
}

impl AttributeReflectionAnchor {
    pub(in crate::web_runtime) const fn quote_mode(&self) -> AttributeQuoteMode {
        self.quote_mode
    }

    pub(in crate::web_runtime) fn element_local_name(&self) -> &str {
        &self.element_local_name
    }

    pub(in crate::web_runtime) fn attribute_local_name(&self) -> &str {
        &self.attribute_local_name
    }

    pub(in crate::web_runtime) const fn context(&self) -> ExactHtmlReflectionContext {
        self.context
    }
}

impl fmt::Debug for AttributeReflectionAnchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttributeReflectionAnchor")
            .field("quote_mode", &self.quote_mode)
            .field("element_local_name", &"<bounded-name>")
            .field("attribute_local_name", &"<bounded-name>")
            .field("context", &self.context)
            .finish()
    }
}

/// Fail-closed result from one bounded source pass.
#[derive(Clone, PartialEq, Eq)]
pub(in crate::web_runtime) enum AttributeSourceResult {
    Absent,
    ExactAttributeAnchor(AttributeReflectionAnchor),
    Ambiguous,
    Unsupported,
    Incomplete,
}

impl AttributeSourceResult {
    pub(in crate::web_runtime) const fn exact_anchor(&self) -> Option<&AttributeReflectionAnchor> {
        match self {
            Self::ExactAttributeAnchor(anchor) => Some(anchor),
            Self::Absent | Self::Ambiguous | Self::Unsupported | Self::Incomplete => None,
        }
    }

    pub(in crate::web_runtime) const fn status_id(&self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::ExactAttributeAnchor(_) => "exact-attribute-anchor",
            Self::Ambiguous => "ambiguous",
            Self::Unsupported => "unsupported",
            Self::Incomplete => "incomplete",
        }
    }

    pub(in crate::web_runtime) fn quote_mode_id(&self) -> &'static str {
        self.exact_anchor()
            .map_or(NO_ATTRIBUTE_SOURCE_VALUE, |anchor| {
                anchor.quote_mode().stable_id()
            })
    }

    pub(in crate::web_runtime) fn element_name_id(&self) -> &str {
        self.exact_anchor()
            .map_or(NO_ATTRIBUTE_SOURCE_VALUE, |anchor| {
                anchor.element_local_name()
            })
    }

    pub(in crate::web_runtime) fn attribute_name_id(&self) -> &str {
        self.exact_anchor()
            .map_or(NO_ATTRIBUTE_SOURCE_VALUE, |anchor| {
                anchor.attribute_local_name()
            })
    }

    pub(in crate::web_runtime) fn context_id(&self) -> &'static str {
        self.exact_anchor()
            .map_or(NO_ATTRIBUTE_SOURCE_VALUE, |anchor| {
                anchor.context.stable_id()
            })
    }

    /// Reconstructs the typed result from the bounded evidence vocabulary.
    pub(in crate::web_runtime) fn from_evidence_fields(
        status: &str,
        quote_mode: &str,
        element_name: &str,
        attribute_name: &str,
        context: &str,
    ) -> Option<Self> {
        if status != "exact-attribute-anchor" {
            if [quote_mode, element_name, attribute_name, context]
                .into_iter()
                .any(|value| value != NO_ATTRIBUTE_SOURCE_VALUE)
            {
                return None;
            }
            return match status {
                "absent" => Some(Self::Absent),
                "ambiguous" => Some(Self::Ambiguous),
                "unsupported" => Some(Self::Unsupported),
                "incomplete" => Some(Self::Incomplete),
                _ => None,
            };
        }
        let quote_mode = AttributeQuoteMode::parse(quote_mode)?;
        let context = match context {
            "attribute-value" => ExactHtmlReflectionContext::AttributeValue,
            "uri-attribute" => ExactHtmlReflectionContext::UriAttribute,
            "event-handler-attribute" => ExactHtmlReflectionContext::EventHandlerAttribute,
            _ => return None,
        };
        if !is_normalized_name(element_name, MAX_ATTRIBUTE_SOURCE_ELEMENT_NAME_BYTES)
            || !is_normalized_name(attribute_name, MAX_ATTRIBUTE_SOURCE_ATTRIBUTE_NAME_BYTES)
            || attribute_context(attribute_name) != context
        {
            return None;
        }
        Some(Self::ExactAttributeAnchor(AttributeReflectionAnchor {
            quote_mode,
            element_local_name: element_name.to_owned(),
            attribute_local_name: attribute_name.to_owned(),
            context,
        }))
    }
}

impl fmt::Debug for AttributeSourceResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExactAttributeAnchor(anchor) => formatter
                .debug_tuple("ExactAttributeAnchor")
                .field(anchor)
                .finish(),
            Self::Absent => formatter.write_str("Absent"),
            Self::Ambiguous => formatter.write_str("Ambiguous"),
            Self::Unsupported => formatter.write_str("Unsupported"),
            Self::Incomplete => formatter.write_str("Incomplete"),
        }
    }
}

/// Runs one source pass, then requires exact agreement with the existing DOM
/// context before exposing a usable anchor.
pub(in crate::web_runtime) fn cross_validate_attribute_reflection_source(
    html: &str,
    marker: &str,
    dom_context: ExactHtmlReflectionContext,
) -> AttributeSourceResult {
    match analyze_attribute_reflection_source(html, marker) {
        AttributeSourceResult::ExactAttributeAnchor(anchor) if anchor.context() == dom_context => {
            AttributeSourceResult::ExactAttributeAnchor(anchor)
        },
        AttributeSourceResult::ExactAttributeAnchor(_) => AttributeSourceResult::Incomplete,
        other => other,
    }
}

/// Locates one exact marker inside one supported source attribute value.
fn analyze_attribute_reflection_source(html: &str, marker: &str) -> AttributeSourceResult {
    if html.len() > MAX_HTTP_BODY_LIMIT
        || marker.is_empty()
        || marker.len() > MAX_ATTRIBUTE_SOURCE_MARKER_BYTES
        || !marker.is_ascii()
    {
        return AttributeSourceResult::Incomplete;
    }
    let mut occurrences = html.match_indices(marker).map(|(offset, _)| offset);
    let Some(marker_offset) = occurrences.next() else {
        return AttributeSourceResult::Absent;
    };
    if occurrences.next().is_some() {
        return AttributeSourceResult::Ambiguous;
    }

    let bytes = html.as_bytes();
    let mut cursor = 0_usize;
    let mut raw_text: Option<&'static [u8]> = None;
    while cursor < bytes.len() {
        if let Some(raw_name) = raw_text {
            let Some(relative) = find_raw_text_close(&bytes[cursor..], raw_name) else {
                return AttributeSourceResult::Incomplete;
            };
            cursor = cursor.saturating_add(relative);
            raw_text = None;
        }
        if bytes[cursor] != b'<' {
            cursor += 1;
            continue;
        }
        if bytes[cursor..].starts_with(b"<!--") {
            let Some(end) = find_bytes(&bytes[cursor + 4..], b"-->") else {
                return AttributeSourceResult::Incomplete;
            };
            cursor = cursor + 4 + end + 3;
            continue;
        }
        if bytes[cursor..].starts_with(b"<!") || bytes[cursor..].starts_with(b"<?") {
            let Some(end) = bytes[cursor + 2..].iter().position(|byte| *byte == b'>') else {
                return AttributeSourceResult::Incomplete;
            };
            cursor = cursor + 2 + end + 1;
            continue;
        }
        if bytes[cursor..].starts_with(b"</") {
            let Some(end) = bytes[cursor + 2..].iter().position(|byte| *byte == b'>') else {
                return AttributeSourceResult::Incomplete;
            };
            cursor = cursor + 2 + end + 1;
            continue;
        }
        if cursor + 1 >= bytes.len() || !bytes[cursor + 1].is_ascii_alphabetic() {
            cursor += 1;
            continue;
        }
        match parse_start_tag(bytes, cursor, marker_offset, marker.len()) {
            StartTagResult::Parsed {
                next,
                anchor,
                raw_text_name,
            } => {
                if let Some(anchor) = anchor {
                    return AttributeSourceResult::ExactAttributeAnchor(anchor);
                }
                cursor = next;
                raw_text = raw_text_name;
            },
            StartTagResult::Unsupported => return AttributeSourceResult::Unsupported,
            StartTagResult::Incomplete => return AttributeSourceResult::Incomplete,
        }
    }
    AttributeSourceResult::Absent
}

enum StartTagResult {
    Parsed {
        next: usize,
        anchor: Option<AttributeReflectionAnchor>,
        raw_text_name: Option<&'static [u8]>,
    },
    Unsupported,
    Incomplete,
}

fn parse_start_tag(
    bytes: &[u8],
    start: usize,
    marker_offset: usize,
    marker_len: usize,
) -> StartTagResult {
    let mut cursor = start + 1;
    let tag_start = cursor;
    while cursor < bytes.len() && is_name_byte(bytes[cursor]) {
        cursor += 1;
    }
    if cursor == tag_start {
        return StartTagResult::Incomplete;
    }
    let Some(element_name) = normalized_name(
        &bytes[tag_start..cursor],
        MAX_ATTRIBUTE_SOURCE_ELEMENT_NAME_BYTES,
    ) else {
        return StartTagResult::Incomplete;
    };
    let mut attributes = 0_usize;
    let mut self_closing = false;
    let mut pending_anchor = None;
    loop {
        skip_html_whitespace(bytes, &mut cursor);
        if cursor >= bytes.len() {
            return StartTagResult::Incomplete;
        }
        if bytes[cursor] == b'>' {
            cursor += 1;
            break;
        }
        if bytes[cursor] == b'/' && bytes.get(cursor + 1) == Some(&b'>') {
            self_closing = true;
            cursor += 2;
            break;
        }
        let name_start = cursor;
        while cursor < bytes.len()
            && !is_html_whitespace(bytes[cursor])
            && !matches!(bytes[cursor], b'=' | b'>' | b'/')
        {
            cursor += 1;
        }
        if cursor == name_start {
            return StartTagResult::Incomplete;
        }
        attributes = attributes.saturating_add(1);
        if attributes > MAX_ATTRIBUTE_SOURCE_ATTRIBUTES_PER_TAG {
            return StartTagResult::Incomplete;
        }
        let attribute_bytes = &bytes[name_start..cursor];
        skip_html_whitespace(bytes, &mut cursor);
        if bytes.get(cursor) != Some(&b'=') {
            continue;
        }
        cursor += 1;
        skip_html_whitespace(bytes, &mut cursor);
        if cursor >= bytes.len() {
            return StartTagResult::Incomplete;
        }
        let (quote_mode, value_start, value_end, next) = match bytes[cursor] {
            b'"' => {
                let value_start = cursor + 1;
                let Some(relative_end) = bytes[value_start..].iter().position(|byte| *byte == b'"')
                else {
                    return StartTagResult::Incomplete;
                };
                let value_end = value_start + relative_end;
                (
                    AttributeQuoteMode::DoubleQuoted,
                    value_start,
                    value_end,
                    value_end + 1,
                )
            },
            b'\'' => {
                let value_start = cursor + 1;
                let Some(relative_end) =
                    bytes[value_start..].iter().position(|byte| *byte == b'\'')
                else {
                    return StartTagResult::Incomplete;
                };
                let value_end = value_start + relative_end;
                (
                    AttributeQuoteMode::SingleQuoted,
                    value_start,
                    value_end,
                    value_end + 1,
                )
            },
            _ => {
                let value_start = cursor;
                while cursor < bytes.len()
                    && !is_html_whitespace(bytes[cursor])
                    && bytes[cursor] != b'>'
                {
                    if matches!(bytes[cursor], b'"' | b'\'' | b'<' | b'=' | b'`') {
                        return StartTagResult::Incomplete;
                    }
                    cursor += 1;
                }
                if cursor == value_start {
                    return StartTagResult::Incomplete;
                }
                (AttributeQuoteMode::Unquoted, value_start, cursor, cursor)
            },
        };
        cursor = next;
        let marker_end = marker_offset.saturating_add(marker_len);
        if marker_offset < value_start || marker_end > value_end {
            continue;
        }
        let Some(attribute_name) =
            normalized_name(attribute_bytes, MAX_ATTRIBUTE_SOURCE_ATTRIBUTE_NAME_BYTES)
        else {
            return StartTagResult::Incomplete;
        };
        let context = attribute_context(&attribute_name);
        if !matches!(
            context,
            ExactHtmlReflectionContext::AttributeValue
                | ExactHtmlReflectionContext::UriAttribute
                | ExactHtmlReflectionContext::EventHandlerAttribute
        ) {
            return StartTagResult::Unsupported;
        }
        pending_anchor = Some((quote_mode, attribute_name, context));
    }
    let raw_text_name = if self_closing {
        None
    } else if element_name == "script" {
        Some(b"</script".as_slice())
    } else if element_name == "style" {
        Some(b"</style".as_slice())
    } else {
        None
    };
    StartTagResult::Parsed {
        next: cursor,
        anchor: pending_anchor.map(|(quote_mode, attribute_local_name, context)| {
            AttributeReflectionAnchor {
                quote_mode,
                element_local_name: element_name,
                attribute_local_name,
                context,
            }
        }),
        raw_text_name,
    }
}

fn normalized_name(bytes: &[u8], maximum: usize) -> Option<String> {
    if bytes.is_empty()
        || bytes.len() > maximum
        || !bytes.iter().copied().all(is_name_byte)
        || !bytes[0].is_ascii_alphabetic()
    {
        return None;
    }
    Some(
        bytes
            .iter()
            .map(|byte| byte.to_ascii_lowercase() as char)
            .collect(),
    )
}

fn is_normalized_name(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value.bytes().all(is_name_byte)
        && value.bytes().all(|byte| !byte.is_ascii_uppercase())
}

const fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'-' | b'.')
}

const fn is_html_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0c | b'\r')
}

fn skip_html_whitespace(bytes: &[u8], cursor: &mut usize) {
    while *cursor < bytes.len() && is_html_whitespace(bytes[*cursor]) {
        *cursor += 1;
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn find_raw_text_close(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .enumerate()
        .find_map(|(offset, window)| {
            let exact_name = window
                .iter()
                .zip(needle)
                .all(|(left, right)| left.eq_ignore_ascii_case(right));
            let delimiter = haystack
                .get(offset + needle.len())
                .is_some_and(|byte| is_html_whitespace(*byte) || matches!(*byte, b'/' | b'>'));
            (exact_name && delimiter).then_some(offset)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web_runtime::web_assessment::classify_exact_html_reflection;

    const MARKER: &str = "venom-reflection-candidate-0123456789abcdef-end";

    fn exact(html: &str) -> AttributeReflectionAnchor {
        let context = classify_exact_html_reflection(html, MARKER);
        let AttributeSourceResult::ExactAttributeAnchor(anchor) =
            cross_validate_attribute_reflection_source(html, MARKER, context)
        else {
            panic!("expected exact attribute anchor");
        };
        anchor
    }

    #[test]
    fn quote_modes_and_supported_contexts_are_exact_and_normalized() {
        let cases = [
            (
                format!("<DIV TITLE=\"{MARKER}\"></DIV>"),
                "div",
                "title",
                AttributeQuoteMode::DoubleQuoted,
                ExactHtmlReflectionContext::AttributeValue,
            ),
            (
                format!("<a HREF='{MARKER}'>x</a>"),
                "a",
                "href",
                AttributeQuoteMode::SingleQuoted,
                ExactHtmlReflectionContext::UriAttribute,
            ),
            (
                format!("<button ONCLICK={MARKER}>x</button>"),
                "button",
                "onclick",
                AttributeQuoteMode::Unquoted,
                ExactHtmlReflectionContext::EventHandlerAttribute,
            ),
        ];
        for (html, element, attribute, quote, context) in cases {
            let anchor = exact(&html);
            assert_eq!(anchor.element_local_name(), element);
            assert_eq!(anchor.attribute_local_name(), attribute);
            assert_eq!(anchor.quote_mode(), quote);
            assert_eq!(anchor.context(), context);
        }
    }

    #[test]
    fn every_supported_context_accepts_each_quote_mode() {
        for (element, attribute, context) in [
            ("div", "title", ExactHtmlReflectionContext::AttributeValue),
            ("a", "href", ExactHtmlReflectionContext::UriAttribute),
            (
                "button",
                "onclick",
                ExactHtmlReflectionContext::EventHandlerAttribute,
            ),
        ] {
            for (value, quote) in [
                (format!("\"{MARKER}\""), AttributeQuoteMode::DoubleQuoted),
                (format!("'{MARKER}'"), AttributeQuoteMode::SingleQuoted),
                (MARKER.to_owned(), AttributeQuoteMode::Unquoted),
            ] {
                let html = format!("<{element} {attribute}={value}></{element}>");
                let anchor = exact(&html);
                assert_eq!(anchor.quote_mode(), quote);
                assert_eq!(anchor.context(), context);
            }
        }
    }

    #[test]
    fn whitespace_quoted_gt_and_self_closing_forms_remain_lexically_bounded() {
        for html in [
            format!("<div\ttitle \n=\r\"before>{MARKER}\">x</div>"),
            format!("<input\x0ctitle='{MARKER}' />"),
            format!("<input title={MARKER}/>"),
        ] {
            assert!(matches!(
                cross_validate_attribute_reflection_source(
                    &html,
                    MARKER,
                    classify_exact_html_reflection(&html, MARKER),
                ),
                AttributeSourceResult::ExactAttributeAnchor(_)
            ));
        }
    }

    #[test]
    fn marker_outside_an_attribute_value_never_becomes_an_anchor() {
        for html in [
            format!("<p>{MARKER}</p>"),
            format!("<!--{MARKER}-->"),
            format!("<!DOCTYPE {MARKER}>"),
            format!("<?{MARKER}?>"),
            format!("<script>{MARKER}</script>"),
            format!("<style>{MARKER}</style>"),
            format!("<{MARKER} title=x></div>"),
            format!("<div {MARKER}=x></div>"),
        ] {
            assert_eq!(
                analyze_attribute_reflection_source(&html, MARKER),
                AttributeSourceResult::Absent
            );
        }
    }

    #[test]
    fn malformed_and_over_limit_source_fails_closed() {
        for html in [
            format!("<div title=\"{MARKER}"),
            format!("<div title='{MARKER}"),
            format!("<div title=bad\"{MARKER}>"),
            format!("<div title={MARKER}"),
        ] {
            assert_eq!(
                analyze_attribute_reflection_source(&html, MARKER),
                AttributeSourceResult::Incomplete
            );
        }
        let too_many_attributes = format!(
            "<div {} title=\"{MARKER}\"></div>",
            (0..MAX_ATTRIBUTE_SOURCE_ATTRIBUTES_PER_TAG)
                .map(|index| format!("a{index}=x"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        assert_eq!(
            analyze_attribute_reflection_source(&too_many_attributes, MARKER),
            AttributeSourceResult::Incomplete
        );
        let at_attribute_limit = format!(
            "<div {} title=\"{MARKER}\"></div>",
            (0..MAX_ATTRIBUTE_SOURCE_ATTRIBUTES_PER_TAG - 1)
                .map(|index| format!("a{index}=x"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        assert!(matches!(
            analyze_attribute_reflection_source(&at_attribute_limit, MARKER),
            AttributeSourceResult::ExactAttributeAnchor(_)
        ));
        assert_eq!(
            analyze_attribute_reflection_source(&"x".repeat(MAX_HTTP_BODY_LIMIT + 1), MARKER),
            AttributeSourceResult::Incomplete
        );
    }

    #[test]
    fn ambiguity_is_global_and_conservative() {
        for html in [
            format!("<div title='{MARKER}' data-x='{MARKER}'></div>"),
            format!("<p>{MARKER}</p><div title='{MARKER}'></div>"),
        ] {
            assert_eq!(
                analyze_attribute_reflection_source(&html, MARKER),
                AttributeSourceResult::Ambiguous
            );
        }
    }

    #[test]
    fn source_and_dom_context_must_agree_exactly() {
        let html = format!("<a href=\"{MARKER}\">x</a>");
        assert!(matches!(
            cross_validate_attribute_reflection_source(
                &html,
                MARKER,
                ExactHtmlReflectionContext::UriAttribute,
            ),
            AttributeSourceResult::ExactAttributeAnchor(_)
        ));
        for mismatch in [
            ExactHtmlReflectionContext::AttributeValue,
            ExactHtmlReflectionContext::EventHandlerAttribute,
            ExactHtmlReflectionContext::HtmlText,
        ] {
            assert_eq!(
                cross_validate_attribute_reflection_source(&html, MARKER, mismatch),
                AttributeSourceResult::Incomplete
            );
        }
    }

    #[test]
    fn raw_text_requires_one_real_delimited_closing_tag() {
        let decoy = format!("<script>const x = '</scripty>'; {MARKER}</script>");
        assert_eq!(
            analyze_attribute_reflection_source(&decoy, MARKER),
            AttributeSourceResult::Absent
        );
        assert_eq!(
            analyze_attribute_reflection_source(&format!("<script>{MARKER}"), MARKER,),
            AttributeSourceResult::Incomplete
        );
    }

    #[test]
    fn unsupported_attribute_contexts_never_expose_an_anchor() {
        for html in [
            format!("<div style=\"{MARKER}\"></div>"),
            format!("<iframe srcdoc=\"{MARKER}\"></iframe>"),
        ] {
            assert_eq!(
                analyze_attribute_reflection_source(&html, MARKER),
                AttributeSourceResult::Unsupported
            );
        }
    }

    #[test]
    fn evidence_round_trip_is_typed_and_debug_never_contains_source_names() {
        let html = format!("<a href='{MARKER}'>x</a>");
        let result = AttributeSourceResult::ExactAttributeAnchor(exact(&html));
        let replayed = AttributeSourceResult::from_evidence_fields(
            result.status_id(),
            result.quote_mode_id(),
            result.element_name_id(),
            result.attribute_name_id(),
            result.context_id(),
        )
        .unwrap();
        assert_eq!(replayed, result);
        let debug = format!("{result:?}");
        assert!(!debug.contains("href"));
        assert!(!debug.contains(MARKER));
    }

    #[test]
    fn deterministic_bounded_corpus_never_panics_or_creates_empty_names() {
        let alphabet = *b"<>='\"/ a0";
        for seed in 0..2_048_usize {
            let mut state = seed as u64 + 1;
            let mut bytes = Vec::with_capacity(96);
            for _ in 0..96 {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                bytes.push(alphabet[(state as usize) % alphabet.len()]);
            }
            let input = String::from_utf8(bytes).unwrap();
            let first = analyze_attribute_reflection_source(&input, MARKER);
            let second = analyze_attribute_reflection_source(&input, MARKER);
            assert_eq!(first, second);
            if let Some(anchor) = first.exact_anchor() {
                assert!(!anchor.element_local_name().is_empty());
                assert!(!anchor.attribute_local_name().is_empty());
                assert!(matches!(
                    anchor.context(),
                    ExactHtmlReflectionContext::AttributeValue
                        | ExactHtmlReflectionContext::UriAttribute
                        | ExactHtmlReflectionContext::EventHandlerAttribute
                ));
            }
        }
    }
}
