#![forbid(unsafe_code)]
//! Deterministic semantic oracles shared by Venom-owned fuzz targets.

use std::collections::BTreeSet;

use html5ever::{parse_document, tendril::TendrilSink, ParseOpts};
use markup5ever_rcdom::{NodeData, RcDom};

mod authority;
mod semantic;

pub use authority::{check_decision_loop_authority, MAX_AUTHORITY_FUZZ_INPUT_BYTES};
pub use semantic::{
    check_declarative_policy_wire, check_expression_semantics, MAX_EXPRESSION_FUZZ_DEPTH,
    MAX_EXPRESSION_FUZZ_NODES, MAX_SEMANTIC_FUZZ_INPUT_BYTES, MAX_SEMANTIC_FUZZ_STRING_BYTES,
};

// Compile the exact private production extractor into this fuzz-only crate.
// The scanner wires the same source as `http_evidence::form_controls`; this
// keeps the normal production API private while avoiding a copied harness.
#[path = "../../../crates/venom-scanner/src/http_evidence/form_controls.rs"]
mod form_controls;

/// Maximum byte buffer accepted by the HTML semantic harness.
pub const MAX_HTML_FUZZ_INPUT_BYTES: usize = 64 * 1024;

/// Exercises the exact Venom HTML form-control contract for one bounded input.
///
/// A failure means one of the product-owned properties changed: exact HTML
/// `name` preservation, element/attribute attribution, deterministic ordering,
/// deduplication, or the names-only privacy boundary.
pub fn check_html_form_controls(data: &[u8]) {
    if data.len() > MAX_HTML_FUZZ_INPUT_BYTES {
        return;
    }

    let sample = String::from_utf8_lossy(data);
    let actual = form_controls::extract_form_control_names(&sample);
    let repeated = form_controls::extract_form_control_names(&sample);
    let expected = reference_form_control_names(&sample);

    assert_eq!(actual, repeated, "identical HTML must be deterministic");
    assert_eq!(
        actual, expected,
        "Venom must preserve only parser-recognized, exact name attributes"
    );
    assert!(actual.iter().all(|name| !name.is_empty()));
    assert!(actual.windows(2).all(|pair| pair[0] < pair[1]));

    check_structured_name_contract(data);

    // Keep the minimized production reproducer in every campaign, independent
    // of mutation quality or corpus scheduling.
    assert_eq!(
        form_controls::extract_form_control_names(
            "<input name=\" _token \"><input name=\" \"><input name=\"\">"
        ),
        [" ", " _token "]
    );
}

fn reference_form_control_names(sample: &str) -> Vec<String> {
    let dom = parse_document(RcDom::default(), ParseOpts::default())
        .from_utf8()
        .one(sample.as_bytes());
    let mut names = BTreeSet::new();
    let mut pending = vec![dom.document.clone()];

    while let Some(handle) = pending.pop() {
        if let NodeData::Element { name, attrs, .. } = &handle.data {
            if matches!(name.local.as_ref(), "input" | "select" | "textarea") {
                for attr in attrs.borrow().iter() {
                    if attr.name.local.as_ref() == "name" && !attr.value.is_empty() {
                        names.insert(attr.value.to_string());
                    }
                }
            }
        }
        pending.extend(handle.children.borrow().iter().cloned());
    }

    names.into_iter().collect()
}

fn check_structured_name_contract(data: &[u8]) {
    let candidate = semantic_name(data);
    let html = format!(
        "<form>\
         <!-- <input name=\"comment-decoy\"> -->\
         <script>const x = '<input name=\"script-decoy\">';</script>\
         <style>input[name=\"style-decoy\"] {{ color: red; }}</style>\
         <input title=\" name='quote-decoy'\" name=\"{candidate}\" \
                value=\"VENOM_VALUE_SECRET\">\
         <select name=\"{candidate}\"><option>VENOM_OPTION_SECRET</option></select>\
         <textarea name=\"{candidate}\"><input name=\"textarea-decoy\"></textarea>\
         </form>"
    );
    let actual = form_controls::extract_form_control_names(&html);
    let expected = if candidate.is_empty() {
        Vec::new()
    } else {
        vec![candidate]
    };

    assert_eq!(actual, expected);
    assert!(!actual.iter().any(|name| {
        name.contains("VENOM_VALUE_SECRET")
            || name.contains("VENOM_OPTION_SECRET")
            || name.contains("decoy")
    }));
}

fn semantic_name(data: &[u8]) -> String {
    data.iter()
        .take(128)
        .map(|byte| match byte % 42 {
            0 => ' ',
            1 => '_',
            2 => '-',
            3 => '.',
            4 => '\u{00e9}',
            5 => '\u{540d}',
            value @ 6..=15 => char::from(b'0' + (value - 6)),
            value => char::from(b'a' + (value - 16)),
        })
        .collect()
}
