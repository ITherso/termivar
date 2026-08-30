//! Bounded parser-driven classification of exact scanner-owned reflections.
//!
//! The typed vocabulary is intentionally usable by future payload-family
//! selection. No variant represents JavaScript execution or XSS confirmation.

use html5ever::{ns, parse_document, tendril::TendrilSink, ParseOpts};
use markup5ever_rcdom::{NodeData, RcDom};

const MAX_REFLECTION_DOM_NODES: usize = 4_096;
const MAX_REFLECTION_OCCURRENCES: usize = 32;

/// Strongest exact context observed in one complete bounded HTML document.
///
/// Attribute quote syntax is deliberately absent: `html5ever` normalizes the
/// DOM and does not preserve whether an attribute was quoted. Future payload
/// catalogs must select only from context facts this parser actually retains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::web_runtime) enum ExactHtmlReflectionContext {
    Absent,
    HtmlComment,
    HtmlText,
    AttributeValue,
    UriAttribute,
    StyleAttribute,
    StyleElementContent,
    EventHandlerAttribute,
    ScriptElementContent,
    EmbeddedHtmlAttribute,
    /// The response is explicitly outside structured HTML analysis.
    NotApplicable,
    /// Parsing or a compiled traversal/occurrence bound was inconclusive.
    Incomplete,
}

impl ExactHtmlReflectionContext {
    pub(in crate::web_runtime) const fn stable_id(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::HtmlComment => "html-comment",
            Self::HtmlText => "html-text",
            Self::AttributeValue => "attribute-value",
            Self::UriAttribute => "uri-attribute",
            Self::StyleAttribute => "style-attribute",
            Self::StyleElementContent => "style-element-content",
            Self::EventHandlerAttribute => "event-handler-attribute",
            Self::ScriptElementContent => "script-element-content",
            Self::EmbeddedHtmlAttribute => "embedded-html-attribute",
            Self::NotApplicable => "not-applicable",
            Self::Incomplete => "incomplete",
        }
    }
}

/// Parses once, walks once, retains no DOM or raw value, and deterministically
/// returns the strongest context when a marker occurs more than once.
pub(in crate::web_runtime) fn classify_exact_html_reflection(
    html: &str,
    candidate: &str,
) -> ExactHtmlReflectionContext {
    if candidate.is_empty() {
        return ExactHtmlReflectionContext::Incomplete;
    }
    let raw_contains_candidate = html.contains(candidate);
    let dom = parse_document(RcDom::default(), ParseOpts::default()).one(html);
    let mut pending = vec![(dom.document.clone(), ParentContext::Ordinary)];
    let mut nodes = 0_usize;
    let mut occurrences = 0_usize;
    let mut strongest = ExactHtmlReflectionContext::Absent;

    while let Some((handle, parent)) = pending.pop() {
        nodes = nodes.saturating_add(1);
        if nodes > MAX_REFLECTION_DOM_NODES {
            return ExactHtmlReflectionContext::Incomplete;
        }
        let mut child_parent = parent;
        match &handle.data {
            NodeData::Element { name, attrs, .. } if name.ns == ns!(html) => {
                child_parent = match name.local.as_ref() {
                    "script" => ParentContext::Script,
                    "style" => ParentContext::Style,
                    _ => ParentContext::Ordinary,
                };
                for attribute in attrs.borrow().iter() {
                    let count = bounded_count(
                        attribute.value.as_ref(),
                        candidate,
                        MAX_REFLECTION_OCCURRENCES.saturating_sub(occurrences),
                    );
                    occurrences = occurrences.saturating_add(count);
                    if occurrences > MAX_REFLECTION_OCCURRENCES {
                        return ExactHtmlReflectionContext::Incomplete;
                    }
                    if count != 0 {
                        strongest = strongest.max(attribute_context(attribute.name.local.as_ref()));
                    }
                }
            },
            NodeData::Text { contents } => {
                let count = bounded_count(
                    contents.borrow().as_ref(),
                    candidate,
                    MAX_REFLECTION_OCCURRENCES.saturating_sub(occurrences),
                );
                occurrences = occurrences.saturating_add(count);
                if occurrences > MAX_REFLECTION_OCCURRENCES {
                    return ExactHtmlReflectionContext::Incomplete;
                }
                if count != 0 {
                    strongest = strongest.max(match parent {
                        ParentContext::Ordinary => ExactHtmlReflectionContext::HtmlText,
                        ParentContext::Style => ExactHtmlReflectionContext::StyleElementContent,
                        ParentContext::Script => ExactHtmlReflectionContext::ScriptElementContent,
                    });
                }
            },
            NodeData::Comment { contents } => {
                let count = bounded_count(
                    contents,
                    candidate,
                    MAX_REFLECTION_OCCURRENCES.saturating_sub(occurrences),
                );
                occurrences = occurrences.saturating_add(count);
                if occurrences > MAX_REFLECTION_OCCURRENCES {
                    return ExactHtmlReflectionContext::Incomplete;
                }
                if count != 0 {
                    strongest = strongest.max(ExactHtmlReflectionContext::HtmlComment);
                }
            },
            _ => {},
        }
        pending.extend(
            handle
                .children
                .borrow()
                .iter()
                .rev()
                .cloned()
                .map(|child| (child, child_parent)),
        );
    }

    if strongest == ExactHtmlReflectionContext::Absent && raw_contains_candidate {
        // The parser discarded or transformed marker-bearing malformed source;
        // absence from the recovered DOM is not evidence of a safe context.
        ExactHtmlReflectionContext::Incomplete
    } else {
        strongest
    }
}

#[derive(Debug, Clone, Copy)]
enum ParentContext {
    Ordinary,
    Style,
    Script,
}

fn bounded_count(haystack: &str, needle: &str, remaining: usize) -> usize {
    haystack
        .match_indices(needle)
        .take(remaining.saturating_add(1))
        .count()
}

fn attribute_context(name: &str) -> ExactHtmlReflectionContext {
    if name == "srcdoc" {
        ExactHtmlReflectionContext::EmbeddedHtmlAttribute
    } else if name.starts_with("on") {
        ExactHtmlReflectionContext::EventHandlerAttribute
    } else if name == "style" {
        ExactHtmlReflectionContext::StyleAttribute
    } else if matches!(
        name,
        "action"
            | "cite"
            | "data"
            | "formaction"
            | "href"
            | "longdesc"
            | "manifest"
            | "poster"
            | "profile"
            | "src"
            | "usemap"
            | "xlink:href"
    ) {
        ExactHtmlReflectionContext::UriAttribute
    } else {
        ExactHtmlReflectionContext::AttributeValue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MARKER: &str = "venom-reflection-candidate-0123456789abcdef-end";

    #[test]
    fn parser_distinguishes_closed_context_vocabulary() {
        let cases = [
            ("<p>ordinary</p>", ExactHtmlReflectionContext::Absent),
            (
                &format!("<!--{MARKER}-->"),
                ExactHtmlReflectionContext::HtmlComment,
            ),
            (
                &format!("<p>{MARKER}</p>"),
                ExactHtmlReflectionContext::HtmlText,
            ),
            (
                &format!("<div title=\"{MARKER}\"></div>"),
                ExactHtmlReflectionContext::AttributeValue,
            ),
            (
                &format!("<a href=\"{MARKER}\">x</a>"),
                ExactHtmlReflectionContext::UriAttribute,
            ),
            (
                &format!("<div style=\"{MARKER}\"></div>"),
                ExactHtmlReflectionContext::StyleAttribute,
            ),
            (
                &format!("<style>{MARKER}</style>"),
                ExactHtmlReflectionContext::StyleElementContent,
            ),
            (
                &format!("<button onclick=\"{MARKER}\">x</button>"),
                ExactHtmlReflectionContext::EventHandlerAttribute,
            ),
            (
                &format!("<script>{MARKER}</script>"),
                ExactHtmlReflectionContext::ScriptElementContent,
            ),
            (
                &format!("<iframe srcdoc=\"{MARKER}\"></iframe>"),
                ExactHtmlReflectionContext::EmbeddedHtmlAttribute,
            ),
        ];
        for (html, expected) in cases {
            assert_eq!(classify_exact_html_reflection(html, MARKER), expected);
        }
    }

    #[test]
    fn strongest_context_is_deterministic_and_bounds_fail_closed() {
        let mixed = format!(
            "<p>{MARKER}</p><!--{MARKER}--><a href='{MARKER}'>x</a><script>{MARKER}</script>"
        );
        assert_eq!(
            classify_exact_html_reflection(&mixed, MARKER),
            ExactHtmlReflectionContext::ScriptElementContent
        );
        assert_eq!(
            classify_exact_html_reflection(&mixed, MARKER),
            classify_exact_html_reflection(&mixed, MARKER)
        );
        let too_many = format!("<p>{}</p>", MARKER.repeat(MAX_REFLECTION_OCCURRENCES + 1));
        assert_eq!(
            classify_exact_html_reflection(&too_many, MARKER),
            ExactHtmlReflectionContext::Incomplete
        );
    }

    #[test]
    fn malformed_marker_source_is_not_misclassified_as_absent() {
        let malformed = format!("<![CDATA[{MARKER}]]>");
        let context = classify_exact_html_reflection(&malformed, MARKER);
        assert_ne!(context, ExactHtmlReflectionContext::Absent);
    }
}
