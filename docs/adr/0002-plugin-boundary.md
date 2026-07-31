# ADR 0002: Keep plugins behind a source-level Rust trait boundary

- Status: Accepted
- Date: 2026-07-31

## Context

The runner must execute extensions without knowing their concrete implementation. Rust shared-library ABIs are not stable, and runtime discovery introduces signing, trust, isolation, capability, and version-negotiation requirements that are not resolved for the alpha release.

## Decision

Plugins are Rust types implementing `Plugin` and are registered as `Arc<dyn Plugin>`. The registry operates only on the trait, serializable configuration, structured findings, and versioned errors. Public plugin enums and output/configuration structs are non-exhaustive.

The preview host and plugin API lines must match at major and minor version. Patch releases may add compatible behavior and defaulted trait methods; incompatible changes require a new alpha minor line. Runtime dynamic loading is explicitly out of scope until an ABI and trust model are accepted in a later ADR.

## Consequences

- External crates can implement plugins without exposing concrete types to the runner.
- Plugins are linked by a host; the stock CLI does not discover arbitrary binaries.
- Adding enum variants does not force exhaustive downstream matches.
- Version mismatch is rejected during registration rather than failing later during execution.

## Alternatives considered

- Stable C ABI: deferred because ownership and async boundaries would require a separate FFI design.
- WebAssembly plugins: promising for isolation, but deferred until capability and performance requirements are measured.
- In-process dynamic Rust libraries: rejected for the preview because Rust does not promise a stable ABI.
