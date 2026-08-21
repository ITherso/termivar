# Coverage evidence

The checker generates this report; do not fill it by hand. An accepted report
is the canonical rendering of its matching JSON evidence record.

- Source commit: `<full 40-character commit SHA>`
- Rust: `1.88.0`
- cargo-tarpaulin: `0.37.2`
- Runner target: `x86_64-unknown-linux-gnu`
- Command: `cargo tarpaulin --locked --workspace --all-features --ignore-tests --ignore-config --out Xml --timeout 300`
- Cargo.lock SHA-256: `<64 lowercase hexadecimal characters>`
- Cobertura SHA-256: `<64 lowercase hexadecimal characters>`
- Workflow run: `<GitHub Actions run URL>`
- Artifact: `coverage-evidence`

## Result

The generated report records calibration or enforcement status, the accepted
baseline path when one exists, exact aggregate counts, and exact base-to-head
patch counts. A zero-coverable-line patch is N/A rather than `0%`.

## Scope

The generated report repeats the fixed include/exclude contract, followed by a
path-sorted table of covered and coverable integer counts for every measured
file and a path-sorted list of omitted in-scope files.

This file is documentation of the generated shape, not accepted numeric
evidence and not an accepted baseline pointer.
