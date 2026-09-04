#![forbid(unsafe_code)]
//! Deterministic semantic oracles shared by Termivar-owned fuzz targets.

use std::collections::BTreeSet;

mod authority;
mod native_oast;
mod oast;
mod semantic;

pub use authority::{check_decision_loop_authority, MAX_AUTHORITY_FUZZ_INPUT_BYTES};
pub use native_oast::{check_native_oast_provider, MAX_NATIVE_OAST_FUZZ_INPUT_BYTES};
pub use oast::{check_oast_correlation, MAX_OAST_FUZZ_INPUT_BYTES};
pub use semantic::{
    check_declarative_policy_wire, check_expression_semantics, MAX_EXPRESSION_FUZZ_DEPTH,
    MAX_EXPRESSION_FUZZ_NODES, MAX_SEMANTIC_FUZZ_INPUT_BYTES, MAX_SEMANTIC_FUZZ_STRING_BYTES,
};

/// Maximum byte buffer accepted by the OpenAPI contract-catalog harness.
pub const MAX_OPENAPI_FUZZ_INPUT_BYTES: usize =
    termivar_scanner::openapi_review::MAX_OPENAPI_DOCUMENT_BYTES;

/// Exercises the exact bounded, transport-neutral OpenAPI parser on arbitrary bytes.
pub fn check_openapi_review(data: &[u8]) {
    use termivar_scanner::openapi_review::OpenApiDocument;

    if data.len() > MAX_OPENAPI_FUZZ_INPUT_BYTES {
        return;
    }

    let first = OpenApiDocument::parse_json(data);
    let repeated = OpenApiDocument::parse_json(data);
    assert_eq!(
        first, repeated,
        "identical OpenAPI input must be deterministic"
    );

    if let Ok(document) = first {
        let operations = document.catalog().operations();
        assert!(operations.windows(2).all(|pair| {
            (pair[0].path(), pair[0].method()) <= (pair[1].path(), pair[1].method())
        }));
        assert!(operations.iter().all(|operation| {
            operation.source_document_identity() == document.semantic_digest()
        }));
    }
}

// Compile the exact private production extractor into this fuzz-only crate.
// The scanner wires the same source as `http_evidence::form_controls`; this
// keeps the normal production API private while avoiding a copied harness.
#[path = "../../../crates/termivar-scanner/src/http_evidence/form_controls.rs"]
mod form_controls;

/// Maximum byte buffer accepted by the HTML semantic harness.
pub const MAX_HTML_FUZZ_INPUT_BYTES: usize = form_controls::MAX_FORM_CONTROL_PARSE_BYTES;

/// Exercises the exact Termivar HTML form-control contract for one bounded input.
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

    assert_eq!(actual, repeated, "identical HTML must be deterministic");
    match &actual {
        form_controls::FormControlExtraction::Observed(names) => {
            assert!(sample.len() <= form_controls::MAX_FORM_CONTROL_PARSE_BYTES);
            assert!(names.iter().all(|name| !name.is_empty()));
            assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
        },
        form_controls::FormControlExtraction::SampleTooLarge => {
            assert!(sample.len() > form_controls::MAX_FORM_CONTROL_PARSE_BYTES);
        },
    }

    check_structured_name_contract(data);

    // Keep the minimized production reproducer in every campaign, independent
    // of mutation quality or corpus scheduling.
    assert_eq!(
        form_controls::extract_form_control_names(
            "<input name=\" _token \"><input name=\" \"><input name=\"\">"
        ),
        form_controls::FormControlExtraction::Observed(vec![" ".to_owned(), " _token ".to_owned()])
    );
}

fn check_structured_name_contract(data: &[u8]) {
    let suffix = semantic_name(data);
    let input_name = format!("input-{suffix}");
    let select_name = format!("select-{suffix}");
    let textarea_name = format!("textarea-{suffix}");
    let foreign_object_name = format!("foreign-object-{suffix}");
    let math_text_name = format!("math-text-{suffix}");
    let html = format!(
        "<form>\
         <!-- <input name=\"comment-decoy\"> -->\
         <script>const x = '<input name=\"script-decoy\">';</script>\
         <style>input[name=\"style-decoy\"] {{ color: red; }}</style>\
         <input title=\" name='quote-decoy'\" name=\"{input_name}\" \
                value=\"VENOM_VALUE_SECRET\">\
         <input name=\"{input_name}\">\
         <input name=\"\">\
         <select name=\"{select_name}\"><option>VENOM_OPTION_SECRET</option></select>\
         <textarea name=\"{textarea_name}\"><input name=\"textarea-decoy\"></textarea>\
         </form>\
         <button name=\"button-decoy\"></button>\
         <svg><input name=\"svg-input-decoy\"></input>\
              <select name=\"svg-select-decoy\"></select>\
              <textarea name=\"svg-textarea-decoy\"></textarea>\
              <foreignObject><input name=\"{foreign_object_name}\">\
                <svg><input name=\"nested-svg-decoy\"></svg>\
              </foreignObject></svg>\
         <math><input name=\"math-input-decoy\"></input>\
               <select name=\"math-select-decoy\"></select>\
               <textarea name=\"math-textarea-decoy\"></textarea>\
               <mtext><select name=\"{math_text_name}\"></select></mtext></math>"
    );
    let actual = observed_form_control_names(&html);
    let expected: Vec<_> = BTreeSet::from([
        input_name,
        select_name,
        textarea_name,
        foreign_object_name,
        math_text_name,
    ])
    .into_iter()
    .collect();

    assert_eq!(actual, expected);
    for forbidden in [
        "comment-decoy",
        "script-decoy",
        "style-decoy",
        "quote-decoy",
        "textarea-decoy",
        "button-decoy",
        "svg-input-decoy",
        "svg-select-decoy",
        "svg-textarea-decoy",
        "nested-svg-decoy",
        "math-input-decoy",
        "math-select-decoy",
        "math-textarea-decoy",
    ] {
        assert!(!actual.iter().any(|name| name == forbidden));
    }
    assert!(
        actual
            .iter()
            .all(|name| !name.contains("VENOM_VALUE_SECRET")
                && !name.contains("VENOM_OPTION_SECRET")),
        "control values and option text must never enter name evidence"
    );
}

fn observed_form_control_names(sample: &str) -> Vec<String> {
    match form_controls::extract_form_control_names(sample) {
        form_controls::FormControlExtraction::Observed(names) => names,
        form_controls::FormControlExtraction::SampleTooLarge => {
            panic!("bounded structured fixture unexpectedly exceeded the parser limit")
        },
    }
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
