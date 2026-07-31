# {{ project-name }}

{{ scanner_description }}

This project composes application-owned phases through `ScannerSdk`. Detection
logic stays in `ScanPhase` implementations; Venom owns phase ordering, timeout,
events, telemetry, and finding aggregation.

```bash
cargo run -- https://target-you-are-authorized-to-test.example
```

The template tracks Venom `main` during alpha. Pin a release tag or commit before
publishing or distributing a scanner.
