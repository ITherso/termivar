#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    termivar_fuzz_harness::check_oast_correlation(data);
});
