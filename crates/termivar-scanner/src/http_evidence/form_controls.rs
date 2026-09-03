//! Pure, bounded-sample HTML form-control-name extraction.

use std::collections::BTreeSet;

use html5ever::{ns, parse_document, tendril::TendrilSink, ParseOpts};
use markup5ever_rcdom::{Handle, NodeData, RcDom};

/// Maximum UTF-8 byte length handed to the HTML form-control parser.
///
/// Body capture remains governed by the host's independent HTTP evidence
/// policy. Samples above this derivation-specific ceiling are retained as body
/// evidence but are not parsed for form-control names.
pub(crate) const MAX_FORM_CONTROL_PARSE_BYTES: usize = 64 * 1024;

/// Result of attempting bounded form-control-name extraction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FormControlExtraction {
    /// The complete supplied sample was parsed. The list may be empty because
    /// absence of an observation never proves that no control exists.
    Observed(Vec<String>),
    /// The sample exceeded [`MAX_FORM_CONTROL_PARSE_BYTES`] and was not parsed.
    SampleTooLarge,
}

/// Conservatively extracts named HTML form-control names (`input`, `select`,
/// `textarea` `name` attributes) from a bounded response sample.
///
/// A real, spec-compliant HTML parser (`html5ever`, via an `RcDom` tree) drives
/// the extraction, so attribute quote-state, comments, `script`/`style` raw
/// text, and `textarea`/`title` RCDATA are handled by tree construction:
/// markup-looking text inside a comment, a script string, a textarea body, or
/// another element's quoted attribute value is never mistaken for a control.
/// Only the unqualified `name` attribute of an HTML-namespace
/// `input`/`select`/`textarea` element is read; foreign SVG/MathML elements with
/// the same local name are not HTML controls. Non-empty names are preserved
/// exactly, deduplicated, and returned in deterministic (sorted) order. Control
/// *values* are never copied here. An empty observation means no control was
/// observed; it never asserts that none exist. Oversized samples are classified
/// before parsing rather than being silently truncated.
pub(crate) fn extract_form_control_names(sample: &str) -> FormControlExtraction {
    if sample.len() > MAX_FORM_CONTROL_PARSE_BYTES {
        return FormControlExtraction::SampleTooLarge;
    }

    let dom = parse_document(RcDom::default(), ParseOpts::default())
        .from_utf8()
        .one(sample.as_bytes());
    let mut names = BTreeSet::new();
    collect_form_control_names(&dom.document, &mut names);
    FormControlExtraction::Observed(names.into_iter().collect())
}

fn collect_form_control_names(handle: &Handle, names: &mut BTreeSet<String>) {
    let mut pending = vec![handle.clone()];
    while let Some(handle) = pending.pop() {
        if let NodeData::Element { name, attrs, .. } = &handle.data {
            if name.ns == ns!(html)
                && matches!(name.local.as_ref(), "input" | "select" | "textarea")
            {
                for attr in attrs.borrow().iter() {
                    if attr.name.ns == ns!() && attr.name.local.as_ref() == "name" {
                        let value = attr.value.as_ref();
                        if !value.is_empty() {
                            names.insert(value.to_owned());
                        }
                    }
                }
            }
        }
        pending.extend(handle.children.borrow().iter().cloned());
    }
}
