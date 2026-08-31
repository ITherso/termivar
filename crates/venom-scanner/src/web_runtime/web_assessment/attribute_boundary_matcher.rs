//! Exact bounded DOM evidence for quote-aware inert attribute boundaries.

use html5ever::{ns, parse_document, tendril::TendrilSink, Attribute, ParseOpts};
use markup5ever_rcdom::{Handle, NodeData, RcDom};

use super::{
    attribute_source_context::AttributeReflectionAnchor,
    reflection_context::{is_canonical_xss_identity, MAX_REFLECTION_DOM_NODES},
};

const XSS_BOUNDARY_ATTRIBUTE: &str = "data-venom-xss-boundary-token";
const XSS_TAIL_ATTRIBUTE: &str = "data-venom-xss-tail-token";

/// Exact bounded DOM result for one source-anchored inert attribute boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::web_runtime) enum ExactXssAttributeBoundaryMatch {
    Absent,
    Matched,
    Ambiguous,
    Incomplete,
}

/// Requires both exact scanner-owned attributes on one exact HTML host/sink.
pub(in crate::web_runtime) fn match_exact_xss_attribute_boundary_document(
    html: &str,
    identity: &str,
    anchor: &AttributeReflectionAnchor,
) -> ExactXssAttributeBoundaryMatch {
    if !is_canonical_xss_identity(identity) {
        return ExactXssAttributeBoundaryMatch::Incomplete;
    }
    let dom = parse_document(RcDom::default(), ParseOpts::default()).one(html);
    inspect_exact_xss_attribute_boundary(&dom.document, identity, anchor)
}

fn inspect_exact_xss_attribute_boundary(
    root: &Handle,
    identity: &str,
    anchor: &AttributeReflectionAnchor,
) -> ExactXssAttributeBoundaryMatch {
    let mut pending = vec![root.clone()];
    let mut nodes = 0_usize;
    let mut matches = 0_usize;
    let mut conflicting_artifacts = 0_usize;
    while let Some(handle) = pending.pop() {
        nodes = nodes.saturating_add(1);
        if nodes > MAX_REFLECTION_DOM_NODES {
            return ExactXssAttributeBoundaryMatch::Incomplete;
        }
        if let NodeData::Element { name, attrs, .. } = &handle.data {
            let attributes = attrs.borrow();
            let boundary =
                has_exact_scanner_attribute(&attributes, XSS_BOUNDARY_ATTRIBUTE, identity);
            let tail = has_exact_scanner_attribute(&attributes, XSS_TAIL_ATTRIBUTE, identity);
            if boundary || tail {
                let expected_host = name.ns == ns!(html)
                    && name.local.as_ref() == anchor.element_local_name()
                    && has_exact_sink_attribute(&attributes, anchor.attribute_local_name());
                if boundary && tail && expected_host {
                    matches = matches.saturating_add(1);
                } else {
                    conflicting_artifacts = conflicting_artifacts.saturating_add(1);
                }
                if matches > 1 || conflicting_artifacts > 0 {
                    return ExactXssAttributeBoundaryMatch::Ambiguous;
                }
            }
        }
        pending.extend(handle.children.borrow().iter().rev().cloned());
    }
    if matches == 1 {
        ExactXssAttributeBoundaryMatch::Matched
    } else {
        ExactXssAttributeBoundaryMatch::Absent
    }
}

fn has_exact_scanner_attribute(attributes: &[Attribute], local_name: &str, identity: &str) -> bool {
    attributes.iter().any(|attribute| {
        attribute.name.ns == ns!()
            && attribute.name.prefix.is_none()
            && attribute.name.local.as_ref() == local_name
            && attribute.value.as_ref() == identity
    })
}

fn has_exact_sink_attribute(attributes: &[Attribute], source_name: &str) -> bool {
    attributes.iter().any(|attribute| {
        attribute.name.ns == ns!()
            && attribute.name.prefix.is_none()
            && attribute.name.local.as_ref() == source_name
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web_runtime::web_assessment::{
        cross_validate_attribute_reflection_source, AttributeSourceResult,
        ExactHtmlReflectionContext,
    };

    const MARKER: &str = "venom-reflection-candidate-0123456789abcdef-end";
    const IDENTITY: &str = "0123456789abcdef0123456789abcdef";

    fn anchor(html: &str, context: ExactHtmlReflectionContext) -> AttributeReflectionAnchor {
        let AttributeSourceResult::ExactAttributeAnchor(anchor) =
            cross_validate_attribute_reflection_source(html, MARKER, context)
        else {
            panic!("expected exact source anchor");
        };
        anchor
    }

    #[test]
    fn exact_host_sink_boundary_and_tail_are_required() {
        let source = format!("<a href=\"{MARKER}\">x</a>");
        let anchor = anchor(&source, ExactHtmlReflectionContext::UriAttribute);
        let positive = format!(
            "<a href=\"\" data-venom-xss-boundary-token=\"{IDENTITY}\" data-venom-xss-tail-token=\"{IDENTITY}\">x</a>"
        );
        assert_eq!(
            match_exact_xss_attribute_boundary_document(&positive, IDENTITY, &anchor),
            ExactXssAttributeBoundaryMatch::Matched
        );
        for negative in [
            format!(
                "<div href=\"\" data-venom-xss-boundary-token=\"{IDENTITY}\" data-venom-xss-tail-token=\"{IDENTITY}\"></div>"
            ),
            format!(
                "<a title=\"\" data-venom-xss-boundary-token=\"{IDENTITY}\" data-venom-xss-tail-token=\"{IDENTITY}\"></a>"
            ),
            "<a href=\"\" data-venom-xss-boundary-token=\"wrong\" data-venom-xss-tail-token=\"wrong\"></a>".to_owned(),
            format!(
                "<a href=\"\" data-venom-xss-boundary-token=\"{IDENTITY}\"></a>"
            ),
        ] {
            assert_ne!(
                match_exact_xss_attribute_boundary_document(&negative, IDENTITY, &anchor),
                ExactXssAttributeBoundaryMatch::Matched
            );
        }
    }

    #[test]
    fn duplicate_or_partial_current_case_artifacts_fail_closed() {
        let source = format!("<div title='{MARKER}'></div>");
        let anchor = anchor(&source, ExactHtmlReflectionContext::AttributeValue);
        let host = format!(
            "<div title='' data-venom-xss-boundary-token='{IDENTITY}' data-venom-xss-tail-token='{IDENTITY}'></div>"
        );
        assert_eq!(
            match_exact_xss_attribute_boundary_document(
                &format!("{host}{host}"),
                IDENTITY,
                &anchor,
            ),
            ExactXssAttributeBoundaryMatch::Ambiguous
        );
        assert_eq!(
            match_exact_xss_attribute_boundary_document(
                &format!("<div title='' data-venom-xss-boundary-token='{IDENTITY}'></div>"),
                IDENTITY,
                &anchor,
            ),
            ExactXssAttributeBoundaryMatch::Ambiguous
        );
    }

    #[test]
    fn html_colon_named_sink_uses_exact_no_namespace_local_name() {
        let source = format!("<div xlink:href=\"{MARKER}\"></div>");
        let anchor = anchor(&source, ExactHtmlReflectionContext::UriAttribute);
        let candidate = format!(
            "<div xlink:href=\"\" data-venom-xss-boundary-token=\"{IDENTITY}\" data-venom-xss-tail-token=\"{IDENTITY}\"></div>"
        );
        assert_eq!(
            match_exact_xss_attribute_boundary_document(&candidate, IDENTITY, &anchor),
            ExactXssAttributeBoundaryMatch::Matched
        );
    }

    #[test]
    fn canonical_identity_and_traversal_bound_fail_closed() {
        let source = format!("<button onclick={MARKER}></button>");
        let anchor = anchor(&source, ExactHtmlReflectionContext::EventHandlerAttribute);
        assert_eq!(
            match_exact_xss_attribute_boundary_document("<button></button>", "bad", &anchor),
            ExactXssAttributeBoundaryMatch::Incomplete
        );
        assert_eq!(
            match_exact_xss_attribute_boundary_document(
                &"<i></i>".repeat(MAX_REFLECTION_DOM_NODES + 1),
                IDENTITY,
                &anchor,
            ),
            ExactXssAttributeBoundaryMatch::Incomplete
        );
    }
}
