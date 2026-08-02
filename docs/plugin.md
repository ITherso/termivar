# Plugin SDK preview

Native plugins implement `Plugin` and are stored as `Arc<dyn Plugin>` in `PluginRegistry`. The registry owns validation, lookup, configuration, execution accounting, and error normalization; it does not inspect concrete plugin types.

The API is **Preview**. It is currently a source-level Rust extension API, not a stable dynamic ABI. A host application must link and register third-party plugin crates explicitly.

Compatibility is defined in the [Plugin API and SemVer policy](plugin-api-policy.md). Public plugin enums and configuration/result types are non-exhaustive, and registration rejects plugins targeting a different preview API line.

## Generate a plugin

Install [`cargo-generate`](https://cargo-generate.github.io/cargo-generate/) and expand the repository template:

```bash
cargo install cargo-generate
cargo xtask generate plugin my-venom-plugin
cd my-venom-plugin
cargo test
```

The template asks for a stable plugin ID, implements the complete trait, and includes a registry/execution test. The command is a repository-local wrapper around `cargo-generate`. During alpha the generated dependency tracks Venom `main`; pin it to a tag or commit before publishing.

## Contract

```rust
#[async_trait::async_trait]
pub trait Plugin: Send + Sync {
    fn api_version(&self) -> &str { PLUGIN_API_VERSION }
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn description(&self) -> &str;
    fn author(&self) -> &str;
    fn category(&self) -> PluginCategory;
    fn enabled(&self) -> bool;
    async fn execute(
        &self,
        target: &str,
        payload: &str,
    ) -> Result<Vec<ScanFinding>, PluginError>;
}
```

The generated crate contains a compilable implementation. The public Rust API documentation also contains an inline trait example.

## Host integration

Add the generated crate to a host application and register it:

```rust
use std::sync::Arc;
use my_venom_plugin::GeneratedPlugin;
use venom_scanner::PluginRegistry;

let registry = PluginRegistry::new();
registry
    .register(Arc::new(GeneratedPlugin))
    .expect("plugin must validate");
```

The stock CLI does not discover arbitrary shared libraries or crates at runtime. Dynamic discovery requires an explicit ABI, signing/trust policy, version negotiation, and sandbox decision; those are pre-stable design work.

## Design rules

- Runner and registry code may call `Plugin::execute`; it must not branch on concrete plugin types.
- Plugins communicate through inputs, findings, errors, and versioned public events.
- Plugins must not render reports, start transports, mutate registry internals, or assume dashboard availability.
- Plugin IDs are stable machine identifiers; display names are not identifiers.
- Configuration must be explicit and serializable where practical.
- `PluginRegistry` enforces its snapshotted `timeout_ms`, `max_payload_size`, and host-side `enabled` policy before or around every invocation. Hosts remain responsible for target authorization and for network/resource policy inside plugin implementations.
- `retry_count` is reserved during Preview. The registry does not silently replay plugin code because the current trait cannot declare whether an invocation is idempotent.

## Lifecycle

```text
generate -> implement -> test -> validate -> register -> execute -> collect findings
```

## Stable SDK exit criteria

- Replace target/payload strings with a versioned request context.
- Converge the plugin and ordered phase execution paths.
- Define capability declarations and API-version negotiation.
- Add compatibility tests across released SDK versions.
- Decide whether runtime plugins are linked, process-isolated, WebAssembly, or another sandboxed format.
