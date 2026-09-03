#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    termivar_fuzz_harness::check_html_form_controls(data);
});
