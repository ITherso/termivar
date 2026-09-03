# {{ project-name }}

{{ plugin_description }}

This crate was generated from Termivar's alpha plugin template. Its
`GeneratedPlugin` is an INFO-only, no-I/O marker fixture that exercises the
source-level trait boundary. It is not a detector, does not return findings or
outcomes, and makes no security claim.

Plugins receive a host-owned `PluginContext`. Network work must use its bounded
request broker, and observations must use its recorder so the host retains
scope, cancellation, budget, redaction, provenance, and correlation authority.
Recorded observations require host reasoning and verification before any later
finding projection.

The trusted broker must not follow redirects or retry. Each request supplies a
host-derived response-capture ceiling; stop body collection at that ceiling and
report truncation. The context independently validates origin, capture
metadata, and accounting. Native execution is in-process: timeout and
cancellation are cooperative, and this API provides no CPU, memory, or process
isolation.

Replace the inert fixture only after defining the observation vocabulary,
authorization boundary, request/body budgets, redaction rules, negative
controls, and host verifier that will consume its evidence. Successful plugin
execution means only that the invocation completed.

## Verify

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The template tracks Termivar's `main` branch during the alpha period. Pin the
dependency to a release tag or commit before publishing a plugin.

Termivar checks the plugin API major/minor line during registration. The current
`0.2` line intentionally replaces the original loose target/payload and direct
finding contract. Public plugin types are pre-stable; use constructors and
wildcard match arms where documented.
