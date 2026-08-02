# Plugin API and SemVer policy

The native plugin API is a source-level Rust **Preview**. It is versioned separately from a plugin crate's own package version through `PLUGIN_API_VERSION`.

## Preview compatibility

- Host and plugin API versions must have the same major and minor components.
- A `0.x` minor release may contain incompatible contract changes.
- Patch releases preserve source compatibility and may add defaulted trait methods or non-exhaustive variants.
- Registration rejects an incompatible API line before plugin execution.
- Plugin crates should pin a Venom release tag or commit; tracking `main` is for development only.

Public plugin enums and data types use `#[non_exhaustive]` so hosts can add variants and fields without making downstream exhaustive matches part of the contract. Consumers must use constructors/defaults where provided and include wildcard match arms.

`PLUGIN_API_VERSION` negotiation covers the `Plugin` registration contract; it
does not establish source compatibility for the entire `venom-scanner` crate
or `ScanContext`. Scanner context construction follows
[ADR 0007](adr/0007-scan-context-construction-boundary.md), and its blocking
compatibility baseline remains pending as documented in
[Repository health](repository-health.md).

## Stable API target

Before `1.0`, Venom must define a versioned execution context, capability declarations, compatibility tests across released SDK versions, and an isolation/trust model. A stable major release will reserve breaking changes for major versions and will publish a deprecation window for supported plugin API lines.

This policy covers source compatibility. It does not promise a Rust dynamic-library ABI.
