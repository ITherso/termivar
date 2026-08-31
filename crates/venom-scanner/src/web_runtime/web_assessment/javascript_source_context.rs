//! Bounded JavaScript source-context intelligence for one exact reflection.
//!
//! HTML tree construction remains the authority for identifying an inline
//! script host. This module adds a deliberately narrow, non-evaluating lexical
//! pass over that already-bounded script body. It retains only typed context
//! and host facts; raw JavaScript and source slices never cross this boundary.

use std::fmt;

use html5ever::{ns, parse_document, tendril::TendrilSink, ParseOpts};
use markup5ever_rcdom::{Handle, NodeData, RcDom};

use super::{reflection_context::MAX_REFLECTION_DOM_NODES, ExactHtmlReflectionContext};
use crate::MAX_HTTP_BODY_LIMIT;

const MAX_JAVASCRIPT_MARKER_BYTES: usize = 128;
const MAX_SCRIPT_ELEMENTS: usize = 64;
const MAX_SCRIPT_ATTRIBUTES: usize = 256;
const MAX_HTML_NAME_BYTES: usize = 128;
const MAX_INLINE_SCRIPT_BYTES: usize = 256 * 1024;
const MAX_JAVASCRIPT_TOKENS: usize = 32_768;
const MAX_JAVASCRIPT_NESTING: usize = 64;
const NO_JAVASCRIPT_SOURCE_VALUE: &str = "none";

/// Closed script-host kind retained without source attributes or body text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(in crate::web_runtime) enum JavaScriptScriptKind {
    ClassicJavaScript,
    ModuleJavaScript,
    DataBlock,
    ExternalScript,
    Unsupported,
}

impl JavaScriptScriptKind {
    pub(in crate::web_runtime) const fn stable_id(self) -> &'static str {
        match self {
            Self::ClassicJavaScript => "classic-javascript",
            Self::ModuleJavaScript => "module-javascript",
            Self::DataBlock => "data-block",
            Self::ExternalScript => "external-script",
            Self::Unsupported => "unsupported",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "classic-javascript" => Some(Self::ClassicJavaScript),
            "module-javascript" => Some(Self::ModuleJavaScript),
            "data-block" => Some(Self::DataBlock),
            "external-script" => Some(Self::ExternalScript),
            "unsupported" => Some(Self::Unsupported),
            _ => None,
        }
    }

    const fn is_executable_inline(self) -> bool {
        matches!(self, Self::ClassicJavaScript | Self::ModuleJavaScript)
    }
}

/// Exact lexical placement of one scanner-owned marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(in crate::web_runtime) enum JavaScriptReflectionContext {
    SingleQuotedString,
    DoubleQuotedString,
    TemplateLiteralText,
    TemplateExpression,
    ExpressionOrCode,
    LineComment,
    BlockComment,
    RegexLiteral,
    RegexCharacterClass,
}

impl JavaScriptReflectionContext {
    pub(in crate::web_runtime) const fn stable_id(self) -> &'static str {
        match self {
            Self::SingleQuotedString => "single-quoted-string",
            Self::DoubleQuotedString => "double-quoted-string",
            Self::TemplateLiteralText => "template-literal-text",
            Self::TemplateExpression => "template-expression",
            Self::ExpressionOrCode => "expression-or-code",
            Self::LineComment => "line-comment",
            Self::BlockComment => "block-comment",
            Self::RegexLiteral => "regex-literal",
            Self::RegexCharacterClass => "regex-character-class",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "single-quoted-string" => Some(Self::SingleQuotedString),
            "double-quoted-string" => Some(Self::DoubleQuotedString),
            "template-literal-text" => Some(Self::TemplateLiteralText),
            "template-expression" => Some(Self::TemplateExpression),
            "expression-or-code" => Some(Self::ExpressionOrCode),
            "line-comment" => Some(Self::LineComment),
            "block-comment" => Some(Self::BlockComment),
            "regex-literal" => Some(Self::RegexLiteral),
            "regex-character-class" => Some(Self::RegexCharacterClass),
            _ => None,
        }
    }
}

/// Non-secret identity of one supported inline script and marker context.
#[derive(Clone, PartialEq, Eq)]
pub(in crate::web_runtime) struct JavaScriptReflectionAnchor {
    script_kind: JavaScriptScriptKind,
    script_ordinal: u16,
    context: JavaScriptReflectionContext,
}

impl JavaScriptReflectionAnchor {
    pub(in crate::web_runtime) const fn script_kind(&self) -> JavaScriptScriptKind {
        self.script_kind
    }

    pub(in crate::web_runtime) const fn script_ordinal(&self) -> u16 {
        self.script_ordinal
    }

    pub(in crate::web_runtime) const fn context(&self) -> JavaScriptReflectionContext {
        self.context
    }
}

impl fmt::Debug for JavaScriptReflectionAnchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JavaScriptReflectionAnchor")
            .field("script_kind", &self.script_kind)
            .field("script_ordinal", &self.script_ordinal)
            .field("context", &self.context)
            .finish_non_exhaustive()
    }
}

/// Fail-closed result from one bounded HTML-host and JavaScript lexical pass.
#[derive(Clone, PartialEq, Eq)]
pub(in crate::web_runtime) enum JavaScriptSourceResult {
    Absent,
    ExactScriptAnchor(JavaScriptReflectionAnchor),
    Ambiguous,
    Unsupported(JavaScriptScriptKind),
    Incomplete,
}

/// Exact bounded lexical result for one scanner-owned boundary/tail pair.
///
/// The matcher accepts only complete block-comment tokens on the exact inline
/// script host established by [`JavaScriptReflectionAnchor`]. Raw substring
/// presence, a token in another script, or a token retained inside a string or
/// template is never a match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::web_runtime) enum ExactJavaScriptBoundaryMatch {
    Absent,
    Matched,
    Ambiguous,
    Incomplete,
}

impl JavaScriptSourceResult {
    pub(in crate::web_runtime) const fn exact_anchor(&self) -> Option<&JavaScriptReflectionAnchor> {
        match self {
            Self::ExactScriptAnchor(anchor) => Some(anchor),
            Self::Absent | Self::Ambiguous | Self::Unsupported(_) | Self::Incomplete => None,
        }
    }

    pub(in crate::web_runtime) const fn status_id(&self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::ExactScriptAnchor(_) => "exact-script-anchor",
            Self::Ambiguous => "ambiguous",
            Self::Unsupported(_) => "unsupported",
            Self::Incomplete => "incomplete",
        }
    }

    pub(in crate::web_runtime) const fn script_kind_id(&self) -> &'static str {
        match self {
            Self::ExactScriptAnchor(anchor) => anchor.script_kind().stable_id(),
            Self::Unsupported(kind) => kind.stable_id(),
            Self::Absent | Self::Ambiguous | Self::Incomplete => NO_JAVASCRIPT_SOURCE_VALUE,
        }
    }

    pub(in crate::web_runtime) const fn context_id(&self) -> &'static str {
        match self {
            Self::ExactScriptAnchor(anchor) => anchor.context().stable_id(),
            Self::Absent | Self::Ambiguous | Self::Unsupported(_) | Self::Incomplete => {
                NO_JAVASCRIPT_SOURCE_VALUE
            },
        }
    }

    pub(in crate::web_runtime) fn script_ordinal_id(&self) -> String {
        self.exact_anchor().map_or_else(
            || NO_JAVASCRIPT_SOURCE_VALUE.to_owned(),
            |anchor| anchor.script_ordinal().to_string(),
        )
    }

    /// Reconstructs only the closed bounded evidence vocabulary.
    pub(in crate::web_runtime) fn from_evidence_fields(
        status: &str,
        script_kind: &str,
        context: &str,
        script_ordinal: &str,
    ) -> Option<Self> {
        match status {
            "exact-script-anchor" => {
                let script_kind = JavaScriptScriptKind::parse(script_kind)?;
                if !script_kind.is_executable_inline() {
                    return None;
                }
                let context = JavaScriptReflectionContext::parse(context)?;
                let script_ordinal_value = script_ordinal.parse::<u16>().ok()?;
                if script_ordinal_value.to_string() != script_ordinal
                    || usize::from(script_ordinal_value) >= MAX_SCRIPT_ELEMENTS
                {
                    return None;
                }
                Some(Self::ExactScriptAnchor(JavaScriptReflectionAnchor {
                    script_kind,
                    script_ordinal: script_ordinal_value,
                    context,
                }))
            },
            "unsupported" => {
                if context != NO_JAVASCRIPT_SOURCE_VALUE
                    || script_ordinal != NO_JAVASCRIPT_SOURCE_VALUE
                {
                    return None;
                }
                let kind = JavaScriptScriptKind::parse(script_kind)?;
                (!kind.is_executable_inline()).then_some(Self::Unsupported(kind))
            },
            "absent" | "ambiguous" | "incomplete" => {
                if script_kind != NO_JAVASCRIPT_SOURCE_VALUE
                    || context != NO_JAVASCRIPT_SOURCE_VALUE
                    || script_ordinal != NO_JAVASCRIPT_SOURCE_VALUE
                {
                    return None;
                }
                match status {
                    "absent" => Some(Self::Absent),
                    "ambiguous" => Some(Self::Ambiguous),
                    "incomplete" => Some(Self::Incomplete),
                    _ => None,
                }
            },
            _ => None,
        }
    }
}

impl fmt::Debug for JavaScriptSourceResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExactScriptAnchor(anchor) => formatter
                .debug_tuple("ExactScriptAnchor")
                .field(anchor)
                .finish(),
            Self::Unsupported(kind) => formatter.debug_tuple("Unsupported").field(kind).finish(),
            Self::Absent => formatter.write_str("Absent"),
            Self::Ambiguous => formatter.write_str("Ambiguous"),
            Self::Incomplete => formatter.write_str("Incomplete"),
        }
    }
}

/// Requires agreement with the existing parser-driven script context before
/// exposing an executable inline-script anchor.
pub(in crate::web_runtime) fn cross_validate_javascript_reflection_source(
    html: &str,
    marker: &str,
    dom_context: ExactHtmlReflectionContext,
) -> JavaScriptSourceResult {
    let result = analyze_javascript_reflection_source(html, marker);
    match (&result, dom_context) {
        (
            JavaScriptSourceResult::ExactScriptAnchor(_),
            ExactHtmlReflectionContext::ScriptElementContent,
        ) => result,
        (JavaScriptSourceResult::ExactScriptAnchor(_), _) => JavaScriptSourceResult::Incomplete,
        (JavaScriptSourceResult::Absent, ExactHtmlReflectionContext::ScriptElementContent) => {
            JavaScriptSourceResult::Incomplete
        },
        _ => result,
    }
}

fn analyze_javascript_reflection_source(html: &str, marker: &str) -> JavaScriptSourceResult {
    if html.len() > MAX_HTTP_BODY_LIMIT
        || marker.is_empty()
        || marker.len() > MAX_JAVASCRIPT_MARKER_BYTES
        || !marker.bytes().all(is_scanner_marker_byte)
    {
        return JavaScriptSourceResult::Incomplete;
    }
    let mut raw_occurrences = html.match_indices(marker).map(|(offset, _)| offset);
    let Some(marker_offset) = raw_occurrences.next() else {
        return JavaScriptSourceResult::Absent;
    };
    if raw_occurrences.next().is_some() {
        return JavaScriptSourceResult::Ambiguous;
    }

    let host = match locate_source_script_host(html, marker_offset, marker.len()) {
        SourceScriptResult::Absent => return JavaScriptSourceResult::Absent,
        SourceScriptResult::Exact(host) => host,
        SourceScriptResult::Incomplete => return JavaScriptSourceResult::Incomplete,
    };
    if !cross_validate_dom_script_host(html, marker, &host) {
        return JavaScriptSourceResult::Incomplete;
    }
    if !host.kind.is_executable_inline() {
        return JavaScriptSourceResult::Unsupported(host.kind);
    }
    let Some(source) = html.get(host.body_start..host.body_end) else {
        return JavaScriptSourceResult::Incomplete;
    };
    match classify_javascript_lexical_context(source, marker) {
        LexicalResult::Exact(context) => {
            JavaScriptSourceResult::ExactScriptAnchor(JavaScriptReflectionAnchor {
                script_kind: host.kind,
                script_ordinal: host.ordinal,
                context,
            })
        },
        LexicalResult::Ambiguous => JavaScriptSourceResult::Ambiguous,
        LexicalResult::Incomplete => JavaScriptSourceResult::Incomplete,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SourceScriptHost {
    kind: JavaScriptScriptKind,
    ordinal: u16,
    body_start: usize,
    body_end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceScriptResult {
    Absent,
    Exact(SourceScriptHost),
    Incomplete,
}

fn locate_source_script_host(
    html: &str,
    marker_offset: usize,
    marker_len: usize,
) -> SourceScriptResult {
    let marker_end = marker_offset.saturating_add(marker_len);
    let mut matched = None;
    if visit_source_script_hosts(html, |host| {
        if marker_offset >= host.body_start && marker_end <= host.body_end {
            matched = Some(host);
        }
    })
    .is_err()
    {
        return SourceScriptResult::Incomplete;
    }
    matched.map_or(SourceScriptResult::Absent, SourceScriptResult::Exact)
}

/// Visits each bounded source-level script host in document order. This is
/// shared by reflection classification and lexical boundary matching so both
/// paths use the same ordinal, type, raw-text, and limit contract.
fn visit_source_script_hosts(
    html: &str,
    mut visitor: impl FnMut(SourceScriptHost),
) -> Result<(), ()> {
    let bytes = html.as_bytes();
    let mut cursor = 0_usize;
    let mut script_ordinal = 0_usize;
    while cursor < bytes.len() {
        if bytes[cursor] != b'<' {
            cursor += 1;
            continue;
        }
        if bytes[cursor..].starts_with(b"<!--") {
            let Some(end) = find_bytes(&bytes[cursor + 4..], b"-->") else {
                return Err(());
            };
            cursor = cursor + 4 + end + 3;
            continue;
        }
        if bytes[cursor..].starts_with(b"<!") || bytes[cursor..].starts_with(b"<?") {
            let Some(end) = bytes[cursor + 2..].iter().position(|byte| *byte == b'>') else {
                return Err(());
            };
            cursor = cursor + 2 + end + 1;
            continue;
        }
        if bytes[cursor..].starts_with(b"</") {
            let Some(end) = bytes[cursor + 2..].iter().position(|byte| *byte == b'>') else {
                return Err(());
            };
            cursor = cursor + 2 + end + 1;
            continue;
        }
        if cursor + 1 >= bytes.len() || !bytes[cursor + 1].is_ascii_alphabetic() {
            cursor += 1;
            continue;
        }
        let start_tag = match parse_source_start_tag(bytes, cursor) {
            Ok(tag) => tag,
            Err(()) => return Err(()),
        };
        cursor = start_tag.next;
        if start_tag.name != "script" {
            if start_tag.name == "style" && !start_tag.self_closing {
                let Some(close) = find_raw_text_close(&bytes[cursor..], b"</style") else {
                    return Err(());
                };
                let close_start = cursor + close;
                let Some(close_end) = bytes[close_start..].iter().position(|byte| *byte == b'>')
                else {
                    return Err(());
                };
                cursor = close_start + close_end + 1;
            }
            continue;
        }
        if start_tag.self_closing || script_ordinal >= MAX_SCRIPT_ELEMENTS {
            return Err(());
        }
        let body_start = cursor;
        let Some(close) = find_raw_text_close(&bytes[body_start..], b"</script") else {
            return Err(());
        };
        let body_end = body_start + close;
        let close_start = body_end;
        let Some(close_end) = bytes[close_start..].iter().position(|byte| *byte == b'>') else {
            return Err(());
        };
        if body_end.saturating_sub(body_start) > MAX_INLINE_SCRIPT_BYTES {
            return Err(());
        }
        visitor(SourceScriptHost {
            kind: start_tag.script_kind,
            ordinal: u16::try_from(script_ordinal).expect("compiled script-element bound fits u16"),
            body_start,
            body_end,
        });
        script_ordinal = script_ordinal.saturating_add(1);
        cursor = close_start + close_end + 1;
    }
    Ok(())
}

struct SourceStartTag {
    next: usize,
    name: String,
    self_closing: bool,
    script_kind: JavaScriptScriptKind,
}

fn parse_source_start_tag(bytes: &[u8], start: usize) -> Result<SourceStartTag, ()> {
    let mut cursor = start + 1;
    let name_start = cursor;
    while cursor < bytes.len() && is_html_name_byte(bytes[cursor]) {
        cursor += 1;
    }
    let name = normalize_html_name(&bytes[name_start..cursor]).ok_or(())?;
    let mut attributes = 0_usize;
    let mut type_value: Option<&[u8]> = None;
    let mut language_value: Option<&[u8]> = None;
    let mut src_seen = false;
    let mut self_closing = false;
    loop {
        skip_html_space(bytes, &mut cursor);
        match bytes.get(cursor).copied() {
            Some(b'>') => {
                cursor += 1;
                break;
            },
            Some(b'/') if bytes.get(cursor + 1) == Some(&b'>') => {
                self_closing = true;
                cursor += 2;
                break;
            },
            Some(_) => {},
            None => return Err(()),
        }
        let attribute_start = cursor;
        while cursor < bytes.len()
            && !is_html_space_byte(bytes[cursor])
            && !matches!(bytes[cursor], b'=' | b'>' | b'/')
        {
            cursor += 1;
        }
        let attribute = normalize_html_name(&bytes[attribute_start..cursor]).ok_or(())?;
        attributes = attributes.saturating_add(1);
        if attributes > MAX_SCRIPT_ATTRIBUTES {
            return Err(());
        }
        skip_html_space(bytes, &mut cursor);
        let value = if bytes.get(cursor) == Some(&b'=') {
            cursor += 1;
            skip_html_space(bytes, &mut cursor);
            parse_source_attribute_value(bytes, &mut cursor)?
        } else {
            &[][..]
        };
        match attribute.as_str() {
            "type" if type_value.is_some() => return Err(()),
            "type" => type_value = Some(value),
            "language" if language_value.is_some() => return Err(()),
            "language" => language_value = Some(value),
            "src" if src_seen => return Err(()),
            "src" => src_seen = true,
            _ => {},
        }
    }
    let script_kind = if name != "script" {
        JavaScriptScriptKind::Unsupported
    } else if src_seen {
        JavaScriptScriptKind::ExternalScript
    } else {
        classify_source_script_type(type_value, language_value)
    };
    Ok(SourceStartTag {
        next: cursor,
        name,
        self_closing,
        script_kind,
    })
}

fn parse_source_attribute_value<'a>(bytes: &'a [u8], cursor: &mut usize) -> Result<&'a [u8], ()> {
    let Some(first) = bytes.get(*cursor).copied() else {
        return Err(());
    };
    if matches!(first, b'"' | b'\'') {
        let quote = first;
        *cursor += 1;
        let start = *cursor;
        let Some(length) = bytes[start..].iter().position(|byte| *byte == quote) else {
            return Err(());
        };
        let end = start + length;
        *cursor = end + 1;
        return Ok(&bytes[start..end]);
    }
    let start = *cursor;
    while *cursor < bytes.len() && !is_html_space_byte(bytes[*cursor]) && bytes[*cursor] != b'>' {
        if matches!(bytes[*cursor], b'"' | b'\'' | b'<' | b'=' | b'`') {
            return Err(());
        }
        *cursor += 1;
    }
    (*cursor > start)
        .then_some(&bytes[start..*cursor])
        .ok_or(())
}

fn classify_source_script_type(
    value: Option<&[u8]>,
    language: Option<&[u8]>,
) -> JavaScriptScriptKind {
    let Some(value) = value else {
        return classify_legacy_script_language(language);
    };
    let Ok(value) = std::str::from_utf8(value) else {
        return JavaScriptScriptKind::Unsupported;
    };
    let normalized = value.trim_matches(is_html_space);
    if normalized.is_empty() {
        JavaScriptScriptKind::ClassicJavaScript
    } else if normalized.eq_ignore_ascii_case("module") {
        JavaScriptScriptKind::ModuleJavaScript
    } else if is_supported_javascript_mime(normalized) {
        JavaScriptScriptKind::ClassicJavaScript
    } else if normalized.is_ascii() {
        JavaScriptScriptKind::DataBlock
    } else {
        JavaScriptScriptKind::Unsupported
    }
}

fn cross_validate_dom_script_host(html: &str, marker: &str, host: &SourceScriptHost) -> bool {
    let dom = parse_document(RcDom::default(), ParseOpts::default()).one(html);
    // Keep the RcDom root owned while traversing its shared handles. Moving
    // `document` out drops the remaining tree state and makes valid script
    // hosts appear absent.
    let mut pending = vec![dom.document.clone()];
    let mut visited = 0_usize;
    let mut script_ordinal = 0_usize;
    let mut matched = 0_usize;

    while let Some(handle) = pending.pop() {
        visited = visited.saturating_add(1);
        if visited > MAX_REFLECTION_DOM_NODES {
            return false;
        }
        if let NodeData::Element { name, attrs, .. } = &handle.data {
            if name.ns == ns!(html) && name.local.as_ref() == "script" {
                if script_ordinal >= MAX_SCRIPT_ELEMENTS {
                    return false;
                }
                let kind = classify_script_kind(&attrs.borrow());
                let Some(script_body) = collect_inline_script_body(&handle) else {
                    return false;
                };
                if script_body.contains(marker) {
                    matched = matched.saturating_add(1);
                    if matched > 1
                        || script_ordinal != usize::from(host.ordinal)
                        || kind != host.kind
                    {
                        return false;
                    }
                }
                script_ordinal = script_ordinal.saturating_add(1);
            }
        }
        pending.extend(handle.children.borrow().iter().rev().cloned());
    }

    matched == 1
}

fn classify_script_kind(attributes: &[html5ever::Attribute]) -> JavaScriptScriptKind {
    if attributes
        .iter()
        .any(|attribute| attribute.name.ns == ns!() && attribute.name.local.as_ref() == "src")
    {
        return JavaScriptScriptKind::ExternalScript;
    }
    let script_type = attributes.iter().find_map(|attribute| {
        (attribute.name.ns == ns!() && attribute.name.local.as_ref() == "type")
            .then_some(attribute.value.as_ref())
    });
    let Some(script_type) = script_type else {
        let language = attributes.iter().find_map(|attribute| {
            (attribute.name.ns == ns!() && attribute.name.local.as_ref() == "language")
                .then_some(attribute.value.as_ref().as_bytes())
        });
        return classify_legacy_script_language(language);
    };
    let normalized = script_type.trim_matches(is_html_space);
    if normalized.is_empty() {
        JavaScriptScriptKind::ClassicJavaScript
    } else if normalized.eq_ignore_ascii_case("module") {
        JavaScriptScriptKind::ModuleJavaScript
    } else if is_supported_javascript_mime(normalized) {
        JavaScriptScriptKind::ClassicJavaScript
    } else if normalized.is_ascii() {
        JavaScriptScriptKind::DataBlock
    } else {
        JavaScriptScriptKind::Unsupported
    }
}

fn classify_legacy_script_language(language: Option<&[u8]>) -> JavaScriptScriptKind {
    let Some(language) = language else {
        return JavaScriptScriptKind::ClassicJavaScript;
    };
    let Ok(language) = std::str::from_utf8(language) else {
        return JavaScriptScriptKind::Unsupported;
    };
    let normalized = language.trim_matches(is_html_space);
    if normalized.is_empty()
        || normalized.eq_ignore_ascii_case("javascript")
        || normalized.eq_ignore_ascii_case("ecmascript")
    {
        JavaScriptScriptKind::ClassicJavaScript
    } else if normalized.is_ascii() {
        JavaScriptScriptKind::DataBlock
    } else {
        JavaScriptScriptKind::Unsupported
    }
}

fn is_supported_javascript_mime(value: &str) -> bool {
    [
        "text/javascript",
        "application/javascript",
        "text/ecmascript",
        "application/ecmascript",
    ]
    .into_iter()
    .any(|supported| value.eq_ignore_ascii_case(supported))
}

const fn is_html_space(character: char) -> bool {
    matches!(
        character,
        '\u{0009}' | '\u{000A}' | '\u{000C}' | '\u{000D}' | '\u{0020}'
    )
}

const fn is_html_space_byte(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0c | b'\r')
}

fn skip_html_space(bytes: &[u8], cursor: &mut usize) {
    while bytes
        .get(*cursor)
        .is_some_and(|byte| is_html_space_byte(*byte))
    {
        *cursor += 1;
    }
}

const fn is_html_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'-' | b'.')
}

fn normalize_html_name(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty()
        || bytes.len() > MAX_HTML_NAME_BYTES
        || !bytes[0].is_ascii_alphabetic()
        || !bytes.iter().copied().all(is_html_name_byte)
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
                .is_some_and(|byte| is_html_space_byte(*byte) || matches!(*byte, b'/' | b'>'));
            (exact_name && delimiter).then_some(offset)
        })
}

fn collect_inline_script_body(handle: &Handle) -> Option<String> {
    let children = handle.children.borrow();
    let mut body = String::new();
    for child in children.iter() {
        match &child.data {
            NodeData::Text { contents } => {
                let contents = contents.borrow();
                if body.len().saturating_add(contents.len()) > MAX_INLINE_SCRIPT_BYTES {
                    return None;
                }
                body.push_str(contents.as_ref());
            },
            NodeData::Comment { .. } => return None,
            _ => {},
        }
    }
    Some(body)
}

/// Matches one exact scanner-owned JavaScript block-comment boundary pair on
/// the same source/DOM script host established by the initial reflection.
///
/// `boundary_comment` and `tail_comment` are the exact production-derived
/// block-comment tokens, including `/*` and `*/`. Their inner values must use
/// the same bounded scanner-marker alphabet as the reflection analyzer.
pub(in crate::web_runtime) fn match_exact_xss_javascript_boundary_document(
    html: &str,
    boundary_comment: &str,
    tail_comment: &str,
    anchor: &JavaScriptReflectionAnchor,
) -> ExactJavaScriptBoundaryMatch {
    if html.len() > MAX_HTTP_BODY_LIMIT
        || !valid_exact_block_comment(boundary_comment)
        || !valid_exact_block_comment(tail_comment)
        || boundary_comment == tail_comment
        || !anchor.script_kind().is_executable_inline()
    {
        return ExactJavaScriptBoundaryMatch::Incomplete;
    }
    let mut expected_host = None;
    if visit_source_script_hosts(html, |host| {
        if host.ordinal == anchor.script_ordinal() {
            expected_host = Some(host);
        }
    })
    .is_err()
    {
        return ExactJavaScriptBoundaryMatch::Incomplete;
    }
    let Some(host) = expected_host else {
        return ExactJavaScriptBoundaryMatch::Incomplete;
    };
    if host.kind != anchor.script_kind() {
        return ExactJavaScriptBoundaryMatch::Incomplete;
    }
    let Some(source) = html.get(host.body_start..host.body_end) else {
        return ExactJavaScriptBoundaryMatch::Incomplete;
    };
    let Some(dom_source) = collect_exact_dom_script_host_body(html, anchor) else {
        return ExactJavaScriptBoundaryMatch::Incomplete;
    };
    let boundary_count = html.match_indices(boundary_comment).take(2).count();
    let tail_count = html.match_indices(tail_comment).take(2).count();
    match (boundary_count, tail_count) {
        (0, 0) => {
            return if javascript_source_is_complete(source) {
                ExactJavaScriptBoundaryMatch::Absent
            } else {
                ExactJavaScriptBoundaryMatch::Incomplete
            };
        },
        (1, 1) => {},
        _ => return ExactJavaScriptBoundaryMatch::Ambiguous,
    }
    if !source.contains(boundary_comment) || !source.contains(tail_comment) {
        // Current-case artifacts outside the source-anchored host cannot be
        // correlated to this probe.
        return ExactJavaScriptBoundaryMatch::Ambiguous;
    }
    if dom_source.match_indices(boundary_comment).take(2).count() != 1
        || dom_source.match_indices(tail_comment).take(2).count() != 1
    {
        return ExactJavaScriptBoundaryMatch::Incomplete;
    }
    inspect_exact_javascript_boundary_source(source, boundary_comment, tail_comment)
}

/// Validates production candidate bytes against the exact lexical contract
/// before they can be installed into an executor.
pub(in crate::web_runtime) fn validate_exact_xss_javascript_boundary_candidate(
    candidate: &str,
    boundary_comment: &str,
    tail_comment: &str,
    context: JavaScriptReflectionContext,
) -> ExactJavaScriptBoundaryMatch {
    let delimiter = match context {
        JavaScriptReflectionContext::SingleQuotedString => "'",
        JavaScriptReflectionContext::DoubleQuotedString => "\"",
        JavaScriptReflectionContext::TemplateLiteralText => "`",
        JavaScriptReflectionContext::TemplateExpression
        | JavaScriptReflectionContext::ExpressionOrCode
        | JavaScriptReflectionContext::LineComment
        | JavaScriptReflectionContext::BlockComment
        | JavaScriptReflectionContext::RegexLiteral
        | JavaScriptReflectionContext::RegexCharacterClass => {
            return ExactJavaScriptBoundaryMatch::Incomplete;
        },
    };
    let source = format!("{delimiter}{candidate}{delimiter}");
    inspect_exact_javascript_boundary_source(&source, boundary_comment, tail_comment)
}

fn valid_exact_block_comment(comment: &str) -> bool {
    let Some(inner) = comment
        .strip_prefix("/*")
        .and_then(|value| value.strip_suffix("*/"))
    else {
        return false;
    };
    !inner.is_empty()
        && inner.len() <= MAX_JAVASCRIPT_MARKER_BYTES
        && inner.bytes().all(is_scanner_marker_byte)
}

fn inspect_exact_javascript_boundary_source(
    source: &str,
    boundary_comment: &str,
    tail_comment: &str,
) -> ExactJavaScriptBoundaryMatch {
    if source.len() > MAX_INLINE_SCRIPT_BYTES
        || !valid_exact_block_comment(boundary_comment)
        || !valid_exact_block_comment(tail_comment)
        || boundary_comment == tail_comment
    {
        return ExactJavaScriptBoundaryMatch::Incomplete;
    }
    let mut boundary_occurrences = source
        .match_indices(boundary_comment)
        .map(|(offset, _)| offset);
    let boundary_start = boundary_occurrences.next();
    let boundary_duplicate = boundary_occurrences.next().is_some();
    let mut tail_occurrences = source.match_indices(tail_comment).map(|(offset, _)| offset);
    let tail_start = tail_occurrences.next();
    let tail_duplicate = tail_occurrences.next().is_some();
    let (Some(boundary_start), Some(tail_start)) = (boundary_start, tail_start) else {
        return if boundary_start.is_none() && tail_start.is_none() {
            ExactJavaScriptBoundaryMatch::Absent
        } else {
            ExactJavaScriptBoundaryMatch::Ambiguous
        };
    };
    if boundary_duplicate || tail_duplicate {
        return ExactJavaScriptBoundaryMatch::Ambiguous;
    }
    let boundary_end = boundary_start.saturating_add(boundary_comment.len());
    let tail_end = tail_start.saturating_add(tail_comment.len());
    if boundary_end > tail_start || source.get(boundary_end..tail_start) != Some("+") {
        return ExactJavaScriptBoundaryMatch::Ambiguous;
    }

    // Target only the safe scanner-owned comment interiors. Starting a target
    // at `/` would first classify it as code before the lexer recognizes the
    // complete block-comment token.
    let mut targets = [
        LexicalTarget {
            start: boundary_start + 2,
            end: boundary_end - 2,
            found: None,
            exact_block_comment: Some((boundary_start, boundary_end)),
        },
        LexicalTarget {
            start: tail_start + 2,
            end: tail_end - 2,
            found: None,
            exact_block_comment: Some((tail_start, tail_end)),
        },
    ];
    let mut lexer = MarkerLexer {
        source: source.as_bytes(),
        targets: &mut targets,
        cursor: 0,
        tokens: 0,
        nesting: 0,
    };
    match lexer.scan_code(false, false) {
        Ok(()) if lexer.cursor == lexer.source.len() => {
            match (lexer.targets[0].found, lexer.targets[1].found) {
                (
                    Some(JavaScriptReflectionContext::BlockComment),
                    Some(JavaScriptReflectionContext::BlockComment),
                ) => ExactJavaScriptBoundaryMatch::Matched,
                (Some(left), Some(right)) if left == right => ExactJavaScriptBoundaryMatch::Absent,
                (Some(_), Some(_)) => ExactJavaScriptBoundaryMatch::Ambiguous,
                _ => ExactJavaScriptBoundaryMatch::Incomplete,
            }
        },
        Ok(()) | Err(LexerFailure::Incomplete) => ExactJavaScriptBoundaryMatch::Incomplete,
        Err(LexerFailure::Ambiguous) => ExactJavaScriptBoundaryMatch::Ambiguous,
    }
}

fn collect_exact_dom_script_host_body(
    html: &str,
    anchor: &JavaScriptReflectionAnchor,
) -> Option<String> {
    let dom = parse_document(RcDom::default(), ParseOpts::default()).one(html);
    let mut pending = vec![dom.document.clone()];
    let mut visited = 0_usize;
    let mut script_ordinal = 0_usize;
    let mut matched = None;
    while let Some(handle) = pending.pop() {
        visited = visited.saturating_add(1);
        if visited > MAX_REFLECTION_DOM_NODES {
            return None;
        }
        if let NodeData::Element { name, attrs, .. } = &handle.data {
            if name.ns == ns!(html) && name.local.as_ref() == "script" {
                if script_ordinal >= MAX_SCRIPT_ELEMENTS {
                    return None;
                }
                if script_ordinal == usize::from(anchor.script_ordinal()) {
                    let kind = classify_script_kind(&attrs.borrow());
                    let script_body = collect_inline_script_body(&handle)?;
                    if kind != anchor.script_kind() {
                        return None;
                    }
                    matched = Some(script_body);
                }
                script_ordinal = script_ordinal.saturating_add(1);
            }
        }
        pending.extend(handle.children.borrow().iter().rev().cloned());
    }
    matched
}

fn javascript_source_is_complete(source: &str) -> bool {
    if source.len() > MAX_INLINE_SCRIPT_BYTES {
        return false;
    }
    let mut targets = [];
    let mut lexer = MarkerLexer {
        source: source.as_bytes(),
        targets: &mut targets,
        cursor: 0,
        tokens: 0,
        nesting: 0,
    };
    matches!(lexer.scan_code(false, false), Ok(())) && lexer.cursor == lexer.source.len()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LexicalResult {
    Exact(JavaScriptReflectionContext),
    Ambiguous,
    Incomplete,
}

fn classify_javascript_lexical_context(source: &str, marker: &str) -> LexicalResult {
    let mut occurrences = source.match_indices(marker).map(|(offset, _)| offset);
    let Some(marker_start) = occurrences.next() else {
        return LexicalResult::Incomplete;
    };
    if occurrences.next().is_some() {
        return LexicalResult::Ambiguous;
    }
    let mut targets = [LexicalTarget {
        start: marker_start,
        end: marker_start.saturating_add(marker.len()),
        found: None,
        exact_block_comment: None,
    }];
    let mut lexer = MarkerLexer {
        source: source.as_bytes(),
        targets: &mut targets,
        cursor: 0,
        tokens: 0,
        nesting: 0,
    };
    match lexer.scan_code(false, false) {
        Ok(()) if lexer.cursor == lexer.source.len() => lexer.targets[0]
            .found
            .map_or(LexicalResult::Incomplete, LexicalResult::Exact),
        Ok(()) | Err(LexerFailure::Incomplete) => LexicalResult::Incomplete,
        Err(LexerFailure::Ambiguous) => LexicalResult::Ambiguous,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LexerFailure {
    Ambiguous,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LexicalTarget {
    start: usize,
    end: usize,
    found: Option<JavaScriptReflectionContext>,
    /// Exact token bounds required when this target is classified as a block
    /// comment. Reflection markers use containment; scanner boundary tokens
    /// must coincide with the lexer-opened comment itself.
    exact_block_comment: Option<(usize, usize)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlashGoal {
    RegexAllowed,
    DivisionOnly,
    Ambiguous,
}

struct MarkerLexer<'source, 'targets> {
    source: &'source [u8],
    targets: &'targets mut [LexicalTarget],
    cursor: usize,
    tokens: usize,
    nesting: usize,
}

impl MarkerLexer<'_, '_> {
    fn scan_code(
        &mut self,
        stop_at_template_brace: bool,
        template_expression: bool,
    ) -> Result<(), LexerFailure> {
        self.enter_nesting()?;
        let result = self.scan_code_inner(stop_at_template_brace, template_expression);
        self.nesting = self.nesting.saturating_sub(1);
        result
    }

    fn scan_code_inner(
        &mut self,
        stop_at_template_brace: bool,
        template_expression: bool,
    ) -> Result<(), LexerFailure> {
        let mut slash_goal = SlashGoal::RegexAllowed;
        let mut delimiters = Vec::new();
        while self.cursor < self.source.len() {
            self.record_point(if template_expression {
                JavaScriptReflectionContext::TemplateExpression
            } else {
                JavaScriptReflectionContext::ExpressionOrCode
            })?;
            let byte = self.source[self.cursor];
            if let Some(length) = line_terminator_len(self.source, self.cursor) {
                self.cursor += length;
                if slash_goal == SlashGoal::DivisionOnly {
                    slash_goal = SlashGoal::Ambiguous;
                }
                continue;
            }
            if is_javascript_space(byte) {
                self.cursor += 1;
                continue;
            }
            if self.source[self.cursor..].starts_with(b"<!--")
                || self.source[self.cursor..].starts_with(b"-->")
                || (self.cursor == 0 && self.source.starts_with(b"#!"))
            {
                return Err(LexerFailure::Ambiguous);
            }
            self.bump_token()?;
            match byte {
                b'\'' => {
                    self.scan_string(b'\'', JavaScriptReflectionContext::SingleQuotedString)?;
                    slash_goal = SlashGoal::DivisionOnly;
                },
                b'"' => {
                    self.scan_string(b'"', JavaScriptReflectionContext::DoubleQuotedString)?;
                    slash_goal = SlashGoal::DivisionOnly;
                },
                b'`' => {
                    self.scan_template()?;
                    slash_goal = SlashGoal::DivisionOnly;
                },
                b'/' if self.peek(1) == Some(b'/') => self.scan_line_comment()?,
                b'/' if self.peek(1) == Some(b'*') => self.scan_block_comment()?,
                b'/' => match slash_goal {
                    SlashGoal::RegexAllowed => {
                        self.scan_regex()?;
                        slash_goal = SlashGoal::DivisionOnly;
                    },
                    SlashGoal::DivisionOnly => {
                        if self.slash_may_enclose_marker() {
                            return Err(LexerFailure::Ambiguous);
                        }
                        self.cursor += usize::from(self.peek(1) == Some(b'=')) + 1;
                        slash_goal = SlashGoal::RegexAllowed;
                    },
                    SlashGoal::Ambiguous => return Err(LexerFailure::Ambiguous),
                },
                b'(' | b'[' | b'{' => {
                    delimiters.push(byte);
                    if delimiters.len().saturating_add(self.nesting) > MAX_JAVASCRIPT_NESTING {
                        return Err(LexerFailure::Incomplete);
                    }
                    self.cursor += 1;
                    slash_goal = SlashGoal::RegexAllowed;
                },
                b')' => {
                    if delimiters.pop() != Some(b'(') {
                        return Err(LexerFailure::Incomplete);
                    }
                    self.cursor += 1;
                    // Whether a slash after `)` begins a regular expression or
                    // divides a grouping expression requires grammar. The
                    // focused lexer deliberately refuses to guess.
                    slash_goal = SlashGoal::Ambiguous;
                },
                b']' => {
                    if delimiters.pop() != Some(b'[') {
                        return Err(LexerFailure::Incomplete);
                    }
                    self.cursor += 1;
                    slash_goal = SlashGoal::DivisionOnly;
                },
                b'}' => {
                    if delimiters.last() == Some(&b'{') {
                        delimiters.pop();
                        self.cursor += 1;
                        slash_goal = SlashGoal::Ambiguous;
                    } else if stop_at_template_brace && delimiters.is_empty() {
                        self.cursor += 1;
                        return Ok(());
                    } else {
                        return Err(LexerFailure::Incomplete);
                    }
                },
                byte if is_identifier_start(byte) => {
                    let start = self.cursor;
                    self.cursor += 1;
                    while self
                        .source
                        .get(self.cursor)
                        .is_some_and(|byte| is_identifier_continue(*byte))
                    {
                        self.cursor += 1;
                    }
                    let identifier = &self.source[start..self.cursor];
                    self.record_marker_start_in_range(
                        start,
                        self.cursor,
                        if template_expression {
                            JavaScriptReflectionContext::TemplateExpression
                        } else {
                            JavaScriptReflectionContext::ExpressionOrCode
                        },
                    )?;
                    slash_goal = keyword_slash_goal(identifier);
                },
                b'0'..=b'9' => {
                    let start = self.cursor;
                    self.scan_number();
                    self.record_marker_start_in_range(
                        start,
                        self.cursor,
                        if template_expression {
                            JavaScriptReflectionContext::TemplateExpression
                        } else {
                            JavaScriptReflectionContext::ExpressionOrCode
                        },
                    )?;
                    slash_goal = SlashGoal::DivisionOnly;
                },
                b'+' | b'-' if self.peek(1) == Some(byte) => {
                    self.cursor += 2;
                    slash_goal = SlashGoal::DivisionOnly;
                },
                b';' | b',' | b':' | b'?' | b'=' | b'!' | b'~' | b'+' | b'-' | b'*' | b'%'
                | b'&' | b'|' | b'^' | b'<' | b'>' => {
                    self.cursor += 1;
                    slash_goal = SlashGoal::RegexAllowed;
                },
                b'.' => {
                    self.cursor += 1;
                    slash_goal = SlashGoal::RegexAllowed;
                },
                _ => return Err(LexerFailure::Incomplete),
            }
        }
        if stop_at_template_brace || !delimiters.is_empty() {
            Err(LexerFailure::Incomplete)
        } else {
            Ok(())
        }
    }

    fn scan_string(
        &mut self,
        quote: u8,
        context: JavaScriptReflectionContext,
    ) -> Result<(), LexerFailure> {
        self.cursor += 1;
        let content_start = self.cursor;
        while let Some(byte) = self.source.get(self.cursor).copied() {
            if byte == quote {
                self.record_range(content_start, self.cursor, context)?;
                self.cursor += 1;
                return Ok(());
            }
            if line_terminator_len(self.source, self.cursor).is_some() {
                return Err(LexerFailure::Incomplete);
            }
            if byte == b'\\' {
                self.cursor += 1;
                match self.source.get(self.cursor).copied() {
                    Some(_) if line_terminator_len(self.source, self.cursor).is_some() => {
                        self.cursor +=
                            line_terminator_len(self.source, self.cursor).expect("checked above");
                    },
                    Some(_) => self.cursor += 1,
                    None => return Err(LexerFailure::Incomplete),
                }
            } else {
                self.cursor += 1;
            }
        }
        Err(LexerFailure::Incomplete)
    }

    fn scan_template(&mut self) -> Result<(), LexerFailure> {
        self.enter_nesting()?;
        self.cursor += 1;
        let mut segment_start = self.cursor;
        let result = loop {
            let Some(byte) = self.source.get(self.cursor).copied() else {
                break Err(LexerFailure::Incomplete);
            };
            match byte {
                b'`' => {
                    self.record_range(
                        segment_start,
                        self.cursor,
                        JavaScriptReflectionContext::TemplateLiteralText,
                    )?;
                    self.cursor += 1;
                    break Ok(());
                },
                b'\\' => {
                    self.cursor += 1;
                    if self.source.get(self.cursor).is_none() {
                        break Err(LexerFailure::Incomplete);
                    }
                    self.cursor += line_terminator_len(self.source, self.cursor).unwrap_or(1);
                },
                b'$' if self.peek(1) == Some(b'{') => {
                    self.record_range(
                        segment_start,
                        self.cursor,
                        JavaScriptReflectionContext::TemplateLiteralText,
                    )?;
                    self.cursor += 2;
                    self.scan_code(true, true)?;
                    segment_start = self.cursor;
                },
                _ => self.cursor += 1,
            }
        };
        self.nesting = self.nesting.saturating_sub(1);
        result
    }

    fn scan_line_comment(&mut self) -> Result<(), LexerFailure> {
        let start = self.cursor;
        self.cursor += 2;
        while self.cursor < self.source.len()
            && line_terminator_len(self.source, self.cursor).is_none()
        {
            self.cursor += 1;
        }
        self.record_range(start, self.cursor, JavaScriptReflectionContext::LineComment)
    }

    fn scan_block_comment(&mut self) -> Result<(), LexerFailure> {
        let start = self.cursor;
        self.cursor += 2;
        while self.cursor + 1 < self.source.len() {
            if self.source[self.cursor] == b'*' && self.source[self.cursor + 1] == b'/' {
                self.cursor += 2;
                return self.record_range(
                    start,
                    self.cursor,
                    JavaScriptReflectionContext::BlockComment,
                );
            }
            self.cursor += 1;
        }
        Err(LexerFailure::Incomplete)
    }

    fn scan_regex(&mut self) -> Result<(), LexerFailure> {
        let start = self.cursor;
        self.cursor += 1;
        let mut class_start = None;
        while let Some(byte) = self.source.get(self.cursor).copied() {
            match byte {
                b'\\' => {
                    self.cursor += 1;
                    if self.source.get(self.cursor).is_none()
                        || line_terminator_len(self.source, self.cursor).is_some()
                    {
                        return Err(LexerFailure::Incomplete);
                    }
                    self.cursor += 1;
                },
                b'[' if class_start.is_none() => {
                    class_start = Some(self.cursor);
                    self.cursor += 1;
                },
                b']' if class_start.is_some() => {
                    let class_start = class_start.take().expect("checked above");
                    self.cursor += 1;
                    self.record_range(
                        class_start,
                        self.cursor,
                        JavaScriptReflectionContext::RegexCharacterClass,
                    )?;
                },
                b'/' if class_start.is_none() => {
                    self.cursor += 1;
                    while self
                        .source
                        .get(self.cursor)
                        .is_some_and(|byte| is_identifier_continue(*byte))
                    {
                        self.cursor += 1;
                    }
                    self.record_regex_range(start, self.cursor)?;
                    return Ok(());
                },
                _ if line_terminator_len(self.source, self.cursor).is_some() => {
                    return Err(LexerFailure::Incomplete);
                },
                _ => self.cursor += 1,
            }
        }
        Err(LexerFailure::Incomplete)
    }

    fn scan_number(&mut self) {
        self.cursor += 1;
        while self
            .source
            .get(self.cursor)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_'))
        {
            self.cursor += 1;
        }
    }

    fn slash_may_enclose_marker(&self) -> bool {
        self.targets
            .iter()
            .any(|target| self.slash_may_enclose_target(*target))
    }

    fn slash_may_enclose_target(&self, target: LexicalTarget) -> bool {
        if target.start <= self.cursor {
            return false;
        }
        let mut cursor = self.cursor + 1;
        let mut in_class = false;
        while let Some(byte) = self.source.get(cursor).copied() {
            if line_terminator_len(self.source, cursor).is_some() {
                return false;
            }
            match byte {
                b'\\' => cursor = cursor.saturating_add(2),
                b'[' if !in_class => {
                    in_class = true;
                    cursor += 1;
                },
                b']' if in_class => {
                    in_class = false;
                    cursor += 1;
                },
                b'/' if !in_class => {
                    return target.start > self.cursor
                        && target.end <= cursor
                        && target.start < cursor;
                },
                _ => cursor += 1,
            }
        }
        false
    }

    fn record_point(&mut self, context: JavaScriptReflectionContext) -> Result<(), LexerFailure> {
        for index in 0..self.targets.len() {
            if self.cursor == self.targets[index].start {
                self.set_context(index, context)?;
            }
        }
        Ok(())
    }

    fn record_range(
        &mut self,
        start: usize,
        end: usize,
        context: JavaScriptReflectionContext,
    ) -> Result<(), LexerFailure> {
        for index in 0..self.targets.len() {
            let target = self.targets[index];
            if target.start >= start && target.end <= end {
                if context == JavaScriptReflectionContext::BlockComment
                    && target
                        .exact_block_comment
                        .is_some_and(|expected| expected != (start, end))
                {
                    return Err(LexerFailure::Ambiguous);
                }
                self.set_context(index, context)?;
            } else if target.start < end && target.end > start {
                return Err(LexerFailure::Incomplete);
            }
        }
        Ok(())
    }

    fn record_marker_start_in_range(
        &mut self,
        start: usize,
        end: usize,
        context: JavaScriptReflectionContext,
    ) -> Result<(), LexerFailure> {
        for index in 0..self.targets.len() {
            let marker_start = self.targets[index].start;
            if marker_start >= start && marker_start < end {
                self.set_context(index, context)?;
            }
        }
        Ok(())
    }

    fn record_regex_range(&mut self, start: usize, end: usize) -> Result<(), LexerFailure> {
        for index in 0..self.targets.len() {
            let target = self.targets[index];
            if target.start >= start && target.end <= end {
                if target.found != Some(JavaScriptReflectionContext::RegexCharacterClass) {
                    self.set_context(index, JavaScriptReflectionContext::RegexLiteral)?;
                }
            } else if target.start < end && target.end > start {
                return Err(LexerFailure::Incomplete);
            }
        }
        Ok(())
    }

    fn set_context(
        &mut self,
        index: usize,
        context: JavaScriptReflectionContext,
    ) -> Result<(), LexerFailure> {
        match self.targets[index].found {
            None => self.targets[index].found = Some(context),
            Some(existing) if existing == context => {},
            Some(_) => return Err(LexerFailure::Ambiguous),
        }
        Ok(())
    }

    fn bump_token(&mut self) -> Result<(), LexerFailure> {
        self.tokens = self.tokens.saturating_add(1);
        (self.tokens <= MAX_JAVASCRIPT_TOKENS)
            .then_some(())
            .ok_or(LexerFailure::Incomplete)
    }

    fn enter_nesting(&mut self) -> Result<(), LexerFailure> {
        self.nesting = self.nesting.saturating_add(1);
        (self.nesting <= MAX_JAVASCRIPT_NESTING)
            .then_some(())
            .ok_or(LexerFailure::Incomplete)
    }

    fn peek(&self, offset: usize) -> Option<u8> {
        self.source.get(self.cursor.saturating_add(offset)).copied()
    }
}

const fn is_javascript_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | 0x0b | 0x0c)
}

fn line_terminator_len(source: &[u8], cursor: usize) -> Option<usize> {
    match source.get(cursor..)? {
        [b'\r', b'\n', ..] => Some(2),
        [b'\r' | b'\n', ..] => Some(1),
        [0xe2, 0x80, 0xa8 | 0xa9, ..] => Some(3),
        _ => None,
    }
}

const fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$' | b'\\') || byte >= 0x80
}

const fn is_identifier_continue(byte: u8) -> bool {
    is_identifier_start(byte) || byte.is_ascii_digit()
}

const fn is_scanner_marker_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
}

fn keyword_slash_goal(identifier: &[u8]) -> SlashGoal {
    match identifier {
        // A focused lexer cannot prove whether a reserved/contextual word is
        // acting as grammar or as an allowed identifier/property in every
        // script kind. Refuse slash interpretation after one; punctuation
        // such as `=` still establishes the narrow regex goal we support.
        b"await" | b"break" | b"case" | b"catch" | b"class" | b"const" | b"continue"
        | b"debugger" | b"default" | b"delete" | b"do" | b"else" | b"enum" | b"export"
        | b"extends" | b"false" | b"finally" | b"for" | b"function" | b"if" | b"import" | b"in"
        | b"instanceof" | b"let" | b"new" | b"null" | b"of" | b"return" | b"static" | b"super"
        | b"switch" | b"this" | b"throw" | b"true" | b"try" | b"typeof" | b"var" | b"void"
        | b"while" | b"with" | b"yield" => SlashGoal::Ambiguous,
        _ => SlashGoal::DivisionOnly,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web_runtime::web_assessment::classify_exact_html_reflection;

    const MARKER: &str = "venom-reflection-candidate-0123456789abcdef-end";

    fn html(script_attributes: &str, source: &str) -> String {
        format!("<!doctype html><script{script_attributes}>{source}</script>")
    }

    fn result(script_attributes: &str, source: &str) -> JavaScriptSourceResult {
        cross_validate_javascript_reflection_source(
            &html(script_attributes, source),
            MARKER,
            ExactHtmlReflectionContext::ScriptElementContent,
        )
    }

    fn exact(script_attributes: &str, source: &str) -> JavaScriptReflectionAnchor {
        let result = result(script_attributes, source);
        result
            .exact_anchor()
            .unwrap_or_else(|| {
                panic!("fixture should establish one exact script anchor: {result:?}")
            })
            .clone()
    }

    #[test]
    fn supported_inline_script_kinds_are_closed() {
        for (attributes, expected) in [
            ("", JavaScriptScriptKind::ClassicJavaScript),
            (
                " type=\"text/javascript\"",
                JavaScriptScriptKind::ClassicJavaScript,
            ),
            (
                " type=\" APPLICATION/ECMASCRIPT \"",
                JavaScriptScriptKind::ClassicJavaScript,
            ),
            (" type=\"module\"", JavaScriptScriptKind::ModuleJavaScript),
            (
                " language=\"javascript\"",
                JavaScriptScriptKind::ClassicJavaScript,
            ),
            (
                " language=\"ECMAScript\"",
                JavaScriptScriptKind::ClassicJavaScript,
            ),
            (" language=\"\"", JavaScriptScriptKind::ClassicJavaScript),
            (
                " type=module language=json",
                JavaScriptScriptKind::ModuleJavaScript,
            ),
        ] {
            assert_eq!(
                exact(attributes, &format!("const value = '{MARKER}';")).script_kind(),
                expected
            );
        }
        assert_eq!(
            result(" src=\"/app.js\"", &format!("'{MARKER}'")),
            JavaScriptSourceResult::Unsupported(JavaScriptScriptKind::ExternalScript)
        );
        for script_type in [
            "application/json",
            "application/ld+json",
            "importmap",
            "speculationrules",
            "text/x-custom-data",
        ] {
            assert_eq!(
                result(
                    &format!(" type=\"{script_type}\""),
                    &format!("\"{MARKER}\"")
                ),
                JavaScriptSourceResult::Unsupported(JavaScriptScriptKind::DataBlock)
            );
        }
        assert_eq!(
            result(
                " type=\"text/javascript\" type=\"module\"",
                &format!("'{MARKER}'")
            ),
            JavaScriptSourceResult::Incomplete
        );
        assert_eq!(
            result(" type==module", &format!("'{MARKER}'")),
            JavaScriptSourceResult::Incomplete
        );
        assert_eq!(
            result(" type=\"text/ĵavascript\"", &format!("'{MARKER}'")),
            JavaScriptSourceResult::Unsupported(JavaScriptScriptKind::Unsupported)
        );
        assert_eq!(
            result(" language=json", &format!("'{MARKER}'")),
            JavaScriptSourceResult::Unsupported(JavaScriptScriptKind::DataBlock)
        );
        assert_eq!(
            result(
                " language=javascript language=ecmascript",
                &format!("'{MARKER}'")
            ),
            JavaScriptSourceResult::Incomplete
        );
    }

    #[test]
    fn evidence_vocabulary_is_closed_and_round_trips_every_typed_context() {
        for kind in [
            JavaScriptScriptKind::ClassicJavaScript,
            JavaScriptScriptKind::ModuleJavaScript,
            JavaScriptScriptKind::DataBlock,
            JavaScriptScriptKind::ExternalScript,
            JavaScriptScriptKind::Unsupported,
        ] {
            assert_eq!(JavaScriptScriptKind::parse(kind.stable_id()), Some(kind));
        }
        assert_eq!(JavaScriptScriptKind::parse("unknown"), None);

        for context in [
            JavaScriptReflectionContext::SingleQuotedString,
            JavaScriptReflectionContext::DoubleQuotedString,
            JavaScriptReflectionContext::TemplateLiteralText,
            JavaScriptReflectionContext::TemplateExpression,
            JavaScriptReflectionContext::ExpressionOrCode,
            JavaScriptReflectionContext::LineComment,
            JavaScriptReflectionContext::BlockComment,
            JavaScriptReflectionContext::RegexLiteral,
            JavaScriptReflectionContext::RegexCharacterClass,
        ] {
            assert_eq!(
                JavaScriptReflectionContext::parse(context.stable_id()),
                Some(context)
            );
            let result = JavaScriptSourceResult::ExactScriptAnchor(JavaScriptReflectionAnchor {
                script_kind: JavaScriptScriptKind::ClassicJavaScript,
                script_ordinal: 1,
                context,
            });
            assert_eq!(result.status_id(), "exact-script-anchor");
            assert_eq!(result.script_kind_id(), "classic-javascript");
            assert_eq!(result.context_id(), context.stable_id());
            assert_eq!(result.script_ordinal_id(), "1");
            assert_eq!(
                JavaScriptSourceResult::from_evidence_fields(
                    result.status_id(),
                    result.script_kind_id(),
                    result.context_id(),
                    &result.script_ordinal_id(),
                ),
                Some(result)
            );
        }
        assert_eq!(JavaScriptReflectionContext::parse("unknown"), None);

        for result in [
            JavaScriptSourceResult::Absent,
            JavaScriptSourceResult::Ambiguous,
            JavaScriptSourceResult::Unsupported(JavaScriptScriptKind::DataBlock),
            JavaScriptSourceResult::Unsupported(JavaScriptScriptKind::ExternalScript),
            JavaScriptSourceResult::Unsupported(JavaScriptScriptKind::Unsupported),
            JavaScriptSourceResult::Incomplete,
        ] {
            assert!(result.exact_anchor().is_none());
            assert!(!format!("{result:?}").contains(MARKER));
        }
    }

    #[test]
    fn strings_comments_and_code_have_exact_lexical_contexts() {
        for (source, expected) in [
            (
                format!("const value = '{MARKER}';"),
                JavaScriptReflectionContext::SingleQuotedString,
            ),
            (
                format!("const value = \"{MARKER}\";"),
                JavaScriptReflectionContext::DoubleQuotedString,
            ),
            (
                format!("const value = {MARKER};"),
                JavaScriptReflectionContext::ExpressionOrCode,
            ),
            (
                format!("// {MARKER}\nconst value = 1;"),
                JavaScriptReflectionContext::LineComment,
            ),
            (
                format!("/* {MARKER} */ const value = 1;"),
                JavaScriptReflectionContext::BlockComment,
            ),
        ] {
            assert_eq!(exact("", &source).context(), expected, "{source}");
        }
    }

    #[test]
    fn escapes_do_not_change_string_or_comment_context() {
        for (source, expected) in [
            (
                format!(r"const value = 'escaped \' {MARKER}';"),
                JavaScriptReflectionContext::SingleQuotedString,
            ),
            (
                format!(r#"const value = "escaped \" {MARKER}";"#),
                JavaScriptReflectionContext::DoubleQuotedString,
            ),
            (
                format!("const value = 'continued \\\n+{MARKER}';"),
                JavaScriptReflectionContext::SingleQuotedString,
            ),
            (
                format!("const value = '// not a comment {MARKER}';"),
                JavaScriptReflectionContext::SingleQuotedString,
            ),
            (
                format!("const value = \"/* not a comment {MARKER} */\";"),
                JavaScriptReflectionContext::DoubleQuotedString,
            ),
            (
                format!(r"const value = 'escaped \\ before {MARKER}';"),
                JavaScriptReflectionContext::SingleQuotedString,
            ),
            (
                format!(r"const value = '{MARKER} before \\ tail';"),
                JavaScriptReflectionContext::SingleQuotedString,
            ),
        ] {
            assert_eq!(exact("", &source).context(), expected, "{source}");
        }
    }

    #[test]
    fn templates_distinguish_text_expression_and_nested_constructs() {
        for (source, expected) in [
            (
                format!("const value = `text {MARKER}`;"),
                JavaScriptReflectionContext::TemplateLiteralText,
            ),
            (
                format!(r"const value = `escaped \` text {MARKER}`;"),
                JavaScriptReflectionContext::TemplateLiteralText,
            ),
            (
                format!(r"const value = `escaped \${{ text }} {MARKER}`;"),
                JavaScriptReflectionContext::TemplateLiteralText,
            ),
            (
                format!("const value = `text ${{{{ value: {MARKER} }}}}`;"),
                JavaScriptReflectionContext::TemplateExpression,
            ),
            (
                format!("const value = `outer ${{`inner {MARKER}`}}`;"),
                JavaScriptReflectionContext::TemplateLiteralText,
            ),
            (
                format!("const value = `outer ${{'{MARKER}'}}`;"),
                JavaScriptReflectionContext::SingleQuotedString,
            ),
        ] {
            assert_eq!(exact("", &source).context(), expected, "{source}");
        }
    }

    #[test]
    fn regex_contexts_are_proven_only_under_a_closed_lexical_goal() {
        assert_eq!(
            exact("", &format!("const value = /before{MARKER}after/u;")).context(),
            JavaScriptReflectionContext::RegexLiteral
        );
        assert_eq!(
            exact("", &format!("const value = /[a-{MARKER}]/u;")).context(),
            JavaScriptReflectionContext::RegexCharacterClass
        );
        assert_eq!(
            result("", &format!("if (ready) /{MARKER}/.test(value);")),
            JavaScriptSourceResult::Ambiguous
        );
        for source in [
            format!("export default /'{MARKER}'/;"),
            format!("class A extends /'{MARKER}'/.constructor {{}}"),
            format!("for (const value of /'{MARKER}'/) {{}}"),
            format!("debugger\n/'{MARKER}'/;"),
            format!("export default /'{MARKER}'"),
            format!("class A extends /'{MARKER}'"),
            format!("for (const value of /'{MARKER}') {{}}"),
            format!("const value = object.in / '{MARKER}' / divisor;"),
        ] {
            assert_eq!(
                result(" type=module", &source),
                JavaScriptSourceResult::Ambiguous,
                "{source}"
            );
        }
        assert_eq!(
            result(
                "",
                &format!("var await = 1; const value = await / '{MARKER}' / divisor;")
            ),
            JavaScriptSourceResult::Ambiguous
        );
        assert_eq!(
            exact(
                "",
                &format!("value++ / divisor; const before{MARKER}after = 1;")
            )
            .context(),
            JavaScriptReflectionContext::ExpressionOrCode
        );
    }

    #[test]
    fn malformed_or_unterminated_lexical_input_fails_closed() {
        for source in [
            format!("const value = '{MARKER}"),
            format!("const value = \"{MARKER}"),
            format!("const value = `{MARKER}"),
            format!("/* {MARKER}"),
            format!("const value = /{MARKER}"),
            format!("const value = /\\\n{MARKER}/;"),
            format!("const value = /\\\r{MARKER}/;"),
            format!("const value = /\\\u{2028}{MARKER}/;"),
        ] {
            assert_eq!(result("", &source), JavaScriptSourceResult::Incomplete);
        }
    }

    #[test]
    fn marker_correlation_and_dom_cross_validation_fail_closed() {
        assert_eq!(
            cross_validate_javascript_reflection_source(
                "<p>absent</p>",
                MARKER,
                ExactHtmlReflectionContext::Absent,
            ),
            JavaScriptSourceResult::Absent
        );
        assert_eq!(
            cross_validate_javascript_reflection_source(
                &format!("<p>{MARKER}</p>"),
                MARKER,
                ExactHtmlReflectionContext::HtmlText,
            ),
            JavaScriptSourceResult::Absent
        );
        for html in [
            format!("<!--{MARKER}-->"),
            format!("<style>.value::after {{ content: '{MARKER}' }}</style>"),
            format!("<div title=\"{MARKER}\"></div>"),
            format!("<{MARKER} title=value>"),
        ] {
            let context = classify_exact_html_reflection(&html, MARKER);
            assert_eq!(
                cross_validate_javascript_reflection_source(&html, MARKER, context),
                JavaScriptSourceResult::Absent
            );
        }
        assert_eq!(
            cross_validate_javascript_reflection_source(
                &html("", &format!("'{MARKER}'")),
                MARKER,
                ExactHtmlReflectionContext::HtmlText,
            ),
            JavaScriptSourceResult::Incomplete
        );
        assert_eq!(
            cross_validate_javascript_reflection_source(
                &format!("<script>'{MARKER}'</script><p>{MARKER}</p>"),
                MARKER,
                ExactHtmlReflectionContext::ScriptElementContent,
            ),
            JavaScriptSourceResult::Ambiguous
        );
        assert_eq!(
            cross_validate_javascript_reflection_source(
                &format!("<script>'{MARKER}'</script><script>\"{MARKER}\"</script>"),
                MARKER,
                ExactHtmlReflectionContext::ScriptElementContent,
            ),
            JavaScriptSourceResult::Ambiguous
        );
        assert_eq!(
            cross_validate_javascript_reflection_source(
                &format!("<script>'{MARKER}{MARKER}'</script>"),
                MARKER,
                ExactHtmlReflectionContext::ScriptElementContent,
            ),
            JavaScriptSourceResult::Ambiguous
        );
        assert_eq!(
            result(
                " type=application/json",
                &format!("{{\"value\":\"{MARKER}\"}}")
            ),
            JavaScriptSourceResult::Unsupported(JavaScriptScriptKind::DataBlock)
        );
        assert_eq!(
            cross_validate_javascript_reflection_source(
                &format!("<svg><script>'{MARKER}'</script></svg>"),
                MARKER,
                ExactHtmlReflectionContext::ScriptElementContent,
            ),
            JavaScriptSourceResult::Incomplete
        );
        assert_eq!(
            cross_validate_javascript_reflection_source(
                &format!("<script>const value = '{MARKER}"),
                MARKER,
                ExactHtmlReflectionContext::ScriptElementContent,
            ),
            JavaScriptSourceResult::Incomplete
        );
        assert_eq!(
            result("", &format!("const value = '{MARKER}</script>'")),
            JavaScriptSourceResult::Incomplete
        );

        let exact_html = html("", &format!("const value = '{MARKER}';"));
        let marker_offset = exact_html.find(MARKER).expect("marker is present");
        let SourceScriptResult::Exact(mut wrong_ordinal) =
            locate_source_script_host(&exact_html, marker_offset, MARKER.len())
        else {
            panic!("source fixture must establish an exact script host");
        };
        wrong_ordinal.ordinal = wrong_ordinal.ordinal.saturating_add(1);
        assert!(!cross_validate_dom_script_host(
            &exact_html,
            MARKER,
            &wrong_ordinal
        ));
    }

    #[test]
    fn source_evidence_round_trip_is_closed_and_debug_is_redacted() {
        const SECRET: &str = "VENOM-JS-XSS-MUST-NOT-LEAK-SECRET-123";
        let anchor = exact(" type=module", &format!("const value = '{MARKER}';"));
        let round_tripped = JavaScriptSourceResult::ExactScriptAnchor(anchor.clone());
        assert_eq!(
            JavaScriptSourceResult::from_evidence_fields(
                round_tripped.status_id(),
                round_tripped.script_kind_id(),
                round_tripped.context_id(),
                &round_tripped.script_ordinal_id(),
            ),
            Some(round_tripped.clone())
        );
        let debug = format!("{round_tripped:?}");
        assert!(!debug.contains(MARKER));
        assert!(!debug.contains("const value"));
        assert_eq!(anchor.script_ordinal(), 0);

        assert_eq!(
            JavaScriptSourceResult::from_evidence_fields(
                "unsupported",
                "data-block",
                "none",
                "none",
            ),
            Some(JavaScriptSourceResult::Unsupported(
                JavaScriptScriptKind::DataBlock
            ))
        );
        for malformed in [
            ("absent", "classic-javascript", "none", "none"),
            ("exact-script-anchor", "data-block", "line-comment", "0"),
            ("exact-script-anchor", "classic-javascript", "unknown", "0"),
            (
                "exact-script-anchor",
                "classic-javascript",
                "line-comment",
                "64",
            ),
            (
                "exact-script-anchor",
                "classic-javascript",
                "line-comment",
                "00",
            ),
            (
                "exact-script-anchor",
                "classic-javascript",
                "line-comment",
                "+0",
            ),
        ] {
            assert!(JavaScriptSourceResult::from_evidence_fields(
                malformed.0,
                malformed.1,
                malformed.2,
                malformed.3,
            )
            .is_none());
        }

        let secret_result = result("", &format!("const secret = '{SECRET}{MARKER}';"));
        assert!(!format!("{secret_result:?}").contains(SECRET));
    }

    #[test]
    fn repeated_analysis_is_deterministic_and_bounded() {
        let source = format!("const value = `prefix {MARKER} suffix`;");
        let first = result("", &source);
        for _ in 0..32 {
            assert_eq!(result("", &source), first);
        }

        let too_many_scripts = format!(
            "{}<script>'{MARKER}'</script>",
            "<script></script>".repeat(MAX_SCRIPT_ELEMENTS)
        );
        assert_eq!(
            cross_validate_javascript_reflection_source(
                &too_many_scripts,
                MARKER,
                ExactHtmlReflectionContext::ScriptElementContent,
            ),
            JavaScriptSourceResult::Incomplete
        );

        let last_supported = format!(
            "{}<script>'{MARKER}'</script>",
            "<script></script>".repeat(MAX_SCRIPT_ELEMENTS - 1)
        );
        let anchor = cross_validate_javascript_reflection_source(
            &last_supported,
            MARKER,
            ExactHtmlReflectionContext::ScriptElementContent,
        )
        .exact_anchor()
        .expect("the final supported script ordinal remains exact")
        .clone();
        assert_eq!(
            usize::from(anchor.script_ordinal()),
            MAX_SCRIPT_ELEMENTS - 1
        );

        let oversized = format!(
            "<script>{}'{MARKER}'</script>",
            " ".repeat(MAX_INLINE_SCRIPT_BYTES)
        );
        assert_eq!(
            cross_validate_javascript_reflection_source(
                &oversized,
                MARKER,
                ExactHtmlReflectionContext::ScriptElementContent,
            ),
            JavaScriptSourceResult::Incomplete
        );

        let too_many_tokens = format!(
            "<script>{} '{MARKER}'</script>",
            "value;".repeat(MAX_JAVASCRIPT_TOKENS + 1)
        );
        assert_eq!(
            cross_validate_javascript_reflection_source(
                &too_many_tokens,
                MARKER,
                ExactHtmlReflectionContext::ScriptElementContent,
            ),
            JavaScriptSourceResult::Incomplete
        );

        let nested = format!(
            "<script>{}'{MARKER}'{}</script>",
            "(".repeat(MAX_JAVASCRIPT_NESTING + 1),
            ")".repeat(MAX_JAVASCRIPT_NESTING + 1)
        );
        assert_eq!(
            cross_validate_javascript_reflection_source(
                &nested,
                MARKER,
                ExactHtmlReflectionContext::ScriptElementContent,
            ),
            JavaScriptSourceResult::Incomplete
        );

        let attributes = (0..=MAX_SCRIPT_ATTRIBUTES)
            .map(|index| format!(" data-{index}=value"))
            .collect::<String>();
        assert_eq!(
            result(&attributes, &format!("'{MARKER}'")),
            JavaScriptSourceResult::Incomplete
        );
        assert_eq!(
            analyze_javascript_reflection_source(&"x".repeat(MAX_HTTP_BODY_LIMIT + 1), MARKER),
            JavaScriptSourceResult::Incomplete
        );
    }

    #[test]
    fn bounded_utf8_corpus_never_panics_and_is_deterministic() {
        let mut state = 0x5eed_cafe_u64;
        for _ in 0..1_024 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let length = usize::try_from((state >> 24) % 96).unwrap();
            let mut source = String::with_capacity(length);
            for _ in 0..length {
                state = state.rotate_left(9).wrapping_add(0x9e37_79b9);
                let scalar = match state % 12 {
                    0 => '\'',
                    1 => '"',
                    2 => '`',
                    3 => '/',
                    4 => '\\',
                    5 => '{',
                    6 => '}',
                    7 => 'é',
                    8 => '\u{2028}',
                    9 => '\u{2029}',
                    _ => char::from_u32(0x20 + u32::try_from(state % 0x5f).unwrap())
                        .expect("generated ASCII scalar is valid"),
                };
                source.push(scalar);
            }
            let html = html("", &format!("{source}'{MARKER}'"));
            let first = cross_validate_javascript_reflection_source(
                &html,
                MARKER,
                ExactHtmlReflectionContext::ScriptElementContent,
            );
            let second = cross_validate_javascript_reflection_source(
                &html,
                MARKER,
                ExactHtmlReflectionContext::ScriptElementContent,
            );
            assert_eq!(first, second);
            if let Some(anchor) = first.exact_anchor() {
                assert!(anchor.script_kind().is_executable_inline());
                assert!(usize::from(anchor.script_ordinal()) < MAX_SCRIPT_ELEMENTS);
            }
        }
    }

    const XSS_IDENTITY: &str = "0123456789abcdef0123456789abcdef";

    fn xss_boundary_comment() -> String {
        format!("/*venom-xss-js-boundary-{XSS_IDENTITY}*/")
    }

    fn xss_tail_comment() -> String {
        format!("/*venom-xss-js-tail-{XSS_IDENTITY}*/")
    }

    fn xss_candidate(delimiter: char) -> String {
        format!(
            "{delimiter}{}+{}{delimiter}",
            xss_boundary_comment(),
            xss_tail_comment()
        )
    }

    fn script_anchor_for(delimiter: char, attributes: &str) -> JavaScriptReflectionAnchor {
        exact(
            attributes,
            &format!("const value = {delimiter}{MARKER}{delimiter};"),
        )
    }

    #[test]
    fn production_shaped_script_candidates_create_exact_block_comment_boundaries() {
        for (delimiter, context) in [
            ('\'', JavaScriptReflectionContext::SingleQuotedString),
            ('"', JavaScriptReflectionContext::DoubleQuotedString),
            ('`', JavaScriptReflectionContext::TemplateLiteralText),
        ] {
            let candidate = xss_candidate(delimiter);
            assert_eq!(
                validate_exact_xss_javascript_boundary_candidate(
                    &candidate,
                    &xss_boundary_comment(),
                    &xss_tail_comment(),
                    context,
                ),
                ExactJavaScriptBoundaryMatch::Matched,
                "{delimiter}"
            );

            let attributes = if delimiter == '"' {
                " type=\"module\""
            } else {
                ""
            };
            let anchor = script_anchor_for(delimiter, attributes);
            let candidate_html = html(
                attributes,
                &format!("const value = {delimiter}{candidate}{delimiter};"),
            );
            assert_eq!(
                match_exact_xss_javascript_boundary_document(
                    &candidate_html,
                    &xss_boundary_comment(),
                    &xss_tail_comment(),
                    &anchor,
                ),
                ExactJavaScriptBoundaryMatch::Matched,
                "{delimiter}"
            );
        }
    }

    #[test]
    fn raw_comment_shapes_inside_original_string_are_not_lexical_boundaries() {
        let anchor = script_anchor_for('\'', "");
        let retained = html(
            "",
            &format!(
                "const value = '{}+{}';",
                xss_boundary_comment(),
                xss_tail_comment()
            ),
        );
        assert_eq!(
            match_exact_xss_javascript_boundary_document(
                &retained,
                &xss_boundary_comment(),
                &xss_tail_comment(),
                &anchor,
            ),
            ExactJavaScriptBoundaryMatch::Absent
        );
    }

    #[test]
    fn duplicate_partial_reordered_and_wrong_host_artifacts_fail_closed() {
        let anchor = script_anchor_for('\'', "");
        let candidate = xss_candidate('\'');
        let positive_source = format!("const value = '{candidate}';");
        let duplicate = html("", &format!("{positive_source}{positive_source}"));
        assert_eq!(
            match_exact_xss_javascript_boundary_document(
                &duplicate,
                &xss_boundary_comment(),
                &xss_tail_comment(),
                &anchor,
            ),
            ExactJavaScriptBoundaryMatch::Ambiguous
        );

        let enclosing_comment = html(
            "",
            &format!(
                "/*unrelated-prefix {}+{}''",
                xss_boundary_comment(),
                xss_tail_comment()
            ),
        );
        assert_eq!(
            match_exact_xss_javascript_boundary_document(
                &enclosing_comment,
                &xss_boundary_comment(),
                &xss_tail_comment(),
                &anchor,
            ),
            ExactJavaScriptBoundaryMatch::Ambiguous,
            "scanner text contained in a different lexer-opened comment is not an exact token"
        );

        let partial = html(
            "",
            &format!("const value = ''{}+'';", xss_boundary_comment()),
        );
        assert_eq!(
            match_exact_xss_javascript_boundary_document(
                &partial,
                &xss_boundary_comment(),
                &xss_tail_comment(),
                &anchor,
            ),
            ExactJavaScriptBoundaryMatch::Ambiguous
        );

        let reordered = html(
            "",
            &format!(
                "const value = ''{}+{}'';",
                xss_tail_comment(),
                xss_boundary_comment()
            ),
        );
        assert_eq!(
            match_exact_xss_javascript_boundary_document(
                &reordered,
                &xss_boundary_comment(),
                &xss_tail_comment(),
                &anchor,
            ),
            ExactJavaScriptBoundaryMatch::Ambiguous
        );

        let wrong_host =
            format!("<script>const value = 'safe';</script><script>{positive_source}</script>");
        assert_eq!(
            match_exact_xss_javascript_boundary_document(
                &wrong_host,
                &xss_boundary_comment(),
                &xss_tail_comment(),
                &anchor,
            ),
            ExactJavaScriptBoundaryMatch::Ambiguous
        );
    }

    #[test]
    fn missing_invalid_malformed_and_host_kind_mismatch_are_not_positive() {
        let anchor = script_anchor_for('\'', "");
        assert_eq!(
            match_exact_xss_javascript_boundary_document(
                &html("", "const value = 'safe';"),
                &xss_boundary_comment(),
                &xss_tail_comment(),
                &anchor,
            ),
            ExactJavaScriptBoundaryMatch::Absent
        );
        assert_eq!(
            match_exact_xss_javascript_boundary_document(
                &html("", "const value = 'unterminated"),
                &xss_boundary_comment(),
                &xss_tail_comment(),
                &anchor,
            ),
            ExactJavaScriptBoundaryMatch::Incomplete,
            "absence is accepted only after the expected host is lexically complete"
        );
        assert_eq!(
            match_exact_xss_javascript_boundary_document(
                &html("", "const value = 'safe';"),
                "/*not a scanner token*/",
                &xss_tail_comment(),
                &anchor,
            ),
            ExactJavaScriptBoundaryMatch::Incomplete
        );

        let candidate = xss_candidate('\'');
        assert_eq!(
            match_exact_xss_javascript_boundary_document(
                &html("", &format!("const value = '{candidate}'; 'unterminated")),
                &xss_boundary_comment(),
                &xss_tail_comment(),
                &anchor,
            ),
            ExactJavaScriptBoundaryMatch::Incomplete
        );
        assert_eq!(
            match_exact_xss_javascript_boundary_document(
                &html(" type=\"module\"", &format!("const value = '{candidate}';"),),
                &xss_boundary_comment(),
                &xss_tail_comment(),
                &anchor,
            ),
            ExactJavaScriptBoundaryMatch::Incomplete
        );
    }
}
