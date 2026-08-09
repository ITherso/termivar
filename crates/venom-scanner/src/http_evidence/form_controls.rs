//! Pure, bounded-sample HTML form-control-name extraction.

use std::collections::BTreeSet;

use html5ever::{parse_document, tendril::TendrilSink, ParseOpts};
use markup5ever_rcdom::{Handle, NodeData, RcDom};

/// Conservatively extracts named HTML form-control names (`input`, `select`,
/// `textarea` `name` attributes) from a bounded response sample.
///
/// A real, spec-compliant HTML parser (`html5ever`, via an `RcDom` tree) drives
/// the extraction, so attribute quote-state, comments, `script`/`style` raw
/// text, and `textarea`/`title` RCDATA are handled by tree construction:
/// markup-looking text inside a comment, a script string, a textarea body, or
/// another element's quoted attribute value is never mistaken for a control.
/// Only the `name` attribute of an `input`/`select`/`textarea` element is read;
/// non-empty names are preserved exactly, deduplicated, and returned in
/// deterministic (sorted) order. Control *values* are never copied here. An
/// empty result means no control was observed; it never asserts that none exist.
pub(crate) fn extract_form_control_names(sample: &str) -> Vec<String> {
    let dom = parse_document(RcDom::default(), ParseOpts::default())
        .from_utf8()
        .one(sample.as_bytes());
    let mut names = BTreeSet::new();
    collect_form_control_names(&dom.document, &mut names);
    names.into_iter().collect()
}

fn collect_form_control_names(handle: &Handle, names: &mut BTreeSet<String>) {
    let mut pending = vec![handle.clone()];
    while let Some(handle) = pending.pop() {
        if let NodeData::Element { name, attrs, .. } = &handle.data {
            if matches!(name.local.as_ref(), "input" | "select" | "textarea") {
                for attr in attrs.borrow().iter() {
                    if attr.name.local.as_ref() == "name" {
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
