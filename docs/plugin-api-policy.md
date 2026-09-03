# Plugin API and SemVer policy

The native plugin API is a source-level Rust **Preview**. It is versioned
separately from a plugin crate's package version through
`PLUGIN_API_VERSION`; the current line is `0.2.0`.

## Preview compatibility

- Host and plugin API versions must have the same major and minor components.
- A `0.x` minor line may contain incompatible contract changes.
- Patch releases preserve source compatibility and may add defaulted trait
  methods or non-exhaustive variants.
- Registration rejects an incompatible API line before plugin execution.
- Plugin crates should pin a Termivar release tag or commit; tracking `main` is for
  development only.

Public plugin enums and data types use `#[non_exhaustive]` where downstream
exhaustive matching would freeze the Preview contract. Consumers must use
constructors/defaults where provided and include wildcard match arms.

`PLUGIN_API_VERSION` negotiation covers only `Plugin` registration. It does not
establish source compatibility for the rest of `termivar-scanner`, `ScanContext`,
or a Rust dynamic-library ABI. Scanner context construction follows
[ADR 0007](adr/0007-scan-context-construction-boundary.md), and the scanner's
blocking compatibility baseline remains pending in
[Repository health](repository-health.md).

## Current breaking transition

The host-owned context and evidence-only output contract intentionally replace
the first Preview API's loose `target`/`payload` invocation and plugin-authored
`ScanFinding` return. A plugin written against that earlier minor line is
incompatible and must be migrated; the host fails registration instead of
silently adapting claim semantics.

The current contract also removes `retry_count`. Automatic replay cannot be
added as a decorative configuration field: a future retry contract must declare
idempotency and charge every broker dispatch. See
[ADR 0019](adr/0019-host-own-plugin-execution.md).

## Stable API target

Before `1.0`, Termivar must publish capability declarations, compatibility tests
across released SDK versions, a scanner/plugin compatibility baseline, and an
isolation/trust model. A stable major release will reserve breaking changes for
major versions and publish a deprecation window for supported plugin API lines.

This policy covers source compatibility only. It does not promise runtime
discovery or a Rust dynamic-library ABI.
