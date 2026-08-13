# {{ project-name }}

{{ scanner_description }}

This project composes application-owned historical phases through `ScannerSdk`.
The generated dependency explicitly enables Venom's non-default
`legacy-scanner` feature; it is not an extension loaded by the canonical bounded
`venom scan` runtime. Detection logic stays in `ScanPhase` implementations;
Venom owns phase ordering, timeout, cancellation, events, and typed run-report
construction. Raw phase strings do not cross the SDK boundary: unresolved
legacy records are projected as informational `Unknown` observations with zero
confidence and no fabricated evidence IDs. Direct-I/O resource dimensions are
reported as unmetered.

```bash
cargo run -- https://target-you-are-authorized-to-test.example
```

The template tracks Venom `main` during alpha. Pin a release tag or commit before
publishing or distributing a scanner.
