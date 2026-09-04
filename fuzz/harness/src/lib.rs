#![forbid(unsafe_code)]
//! Deterministic semantic oracles shared by Termivar-owned fuzz targets.

use std::collections::BTreeSet;

mod authority;
mod native_oast;
mod native_oast_adapter;
#[path = "oast.rs"]
mod oast_harness;
mod semantic;

// Harness-local friend seam for the exact private adapter source below. The
// product token is owned by `web_runtime::authority`; this parallel test-only
// shape keeps fuzz compilation exact without widening the scanner API.
pub(crate) mod web_runtime {
    pub(crate) struct NativeOastProviderMintToken(NativeOastProviderMintSeal);

    struct NativeOastProviderMintSeal;

    pub(crate) fn mint_native_oast_provider_token_for_fuzz() -> NativeOastProviderMintToken {
        NativeOastProviderMintToken(NativeOastProviderMintSeal)
    }
}

// Compile the exact private scanner adapter into this fuzz-only crate. The
// module's `pub(crate)` seams remain inaccessible to product consumers while
// the harness can exercise the production permit and sequencing contracts.
pub(crate) mod verification {
    pub use termivar_scanner::VerificationCase;
}
#[path = "../../../crates/termivar-scanner/src/oast.rs"]
pub(crate) mod oast;
pub(crate) mod runtime_budget {
    use std::sync::{Arc, Mutex};

    pub(crate) use termivar_scanner::TransportDispatchOutcome;
    use termivar_scanner::{DecisionExecutionStage, RuntimeBudget, RuntimeLimitExceeded};

    /// Minimal fuzz-host implementation of the scanner-private broker seam.
    ///
    /// The production adapter source is compiled unchanged below. This host
    /// supplies only the private parent-accounting interface needed to exercise
    /// construction and pure lifecycle decisions without dispatching network
    /// requests or widening the scanner's public API.
    #[derive(Debug, Clone)]
    pub(crate) struct RequestAccountingBroker {
        budget: RuntimeBudget,
        snapshot: Arc<Mutex<RequestAccountingSnapshot>>,
    }

    impl RequestAccountingBroker {
        pub(crate) fn new(budget: RuntimeBudget) -> Self {
            Self {
                budget,
                snapshot: Arc::new(Mutex::new(RequestAccountingSnapshot::default())),
            }
        }

        pub(crate) fn snapshot(&self) -> RequestAccountingSnapshot {
            *self
                .snapshot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }

        pub(crate) fn try_begin_with_request_body_bytes(
            &self,
            _action_id: &str,
            _stage: DecisionExecutionStage,
            _origin: Option<termivar_scanner::DecisionActionOrigin>,
            request_body_bytes: u64,
        ) -> Result<RequestAccountingLease, RuntimeLimitExceeded> {
            // Adapter fuzzing never dispatches. Keep the signature exact so
            // production code compiles while any accidental dispatch remains
            // visible through the snapshot and lease.
            let mut snapshot = self
                .snapshot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            snapshot.total_requests = snapshot.total_requests.saturating_add(1);
            drop(snapshot);
            Ok(RequestAccountingLease {
                broker: self.clone(),
                response_bytes: 0,
                _request_body_bytes: request_body_bytes.min(self.budget.max_request_body_bytes()),
            })
        }
    }

    #[derive(Debug, Clone, Copy, Default)]
    pub(crate) struct RequestAccountingSnapshot {
        total_requests: u32,
        response_bytes: u64,
    }

    impl RequestAccountingSnapshot {
        pub(crate) const fn total_requests(self) -> u32 {
            self.total_requests
        }

        pub(crate) const fn response_bytes(self) -> u64 {
            self.response_bytes
        }
    }

    #[derive(Debug)]
    pub(crate) struct RequestAccountingLease {
        broker: RequestAccountingBroker,
        response_bytes: u64,
        _request_body_bytes: u64,
    }

    impl RequestAccountingLease {
        pub(crate) fn remaining_response_bytes(&self) -> u64 {
            self.broker
                .budget
                .max_response_bytes()
                .saturating_sub(self.broker.snapshot().response_bytes())
        }

        pub(crate) fn observe_response_bytes(&mut self, bytes: u64) -> u64 {
            self.response_bytes = self.response_bytes.saturating_add(bytes);
            let mut snapshot = self
                .broker
                .snapshot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let remaining = self
                .broker
                .budget
                .max_response_bytes()
                .saturating_sub(snapshot.response_bytes);
            let retained = bytes.min(remaining);
            snapshot.response_bytes = snapshot.response_bytes.saturating_add(bytes);
            retained
        }

        pub(crate) fn finish(&mut self, _outcome: TransportDispatchOutcome) {}
    }
}
pub(crate) use termivar_scanner::{
    DecisionExecutionStage, RuntimeBudget, RuntimeBudgetDimension, RuntimeLimitExceeded,
    VerificationCase,
};
#[path = "../../../crates/termivar-scanner/src/native_oast_provider.rs"]
mod scanner_native_oast_provider;

pub use authority::{check_decision_loop_authority, MAX_AUTHORITY_FUZZ_INPUT_BYTES};
pub use native_oast::{check_native_oast_provider, MAX_NATIVE_OAST_FUZZ_INPUT_BYTES};
pub use native_oast_adapter::{
    check_native_oast_adapter, MAX_NATIVE_OAST_ADAPTER_FUZZ_INPUT_BYTES,
};
pub use oast_harness::{check_oast_correlation, MAX_OAST_FUZZ_INPUT_BYTES};
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
