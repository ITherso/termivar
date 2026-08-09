#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    venom_fuzz_harness::check_declarative_policy_wire(data);
});
