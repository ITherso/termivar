# Plugin SDK preview

Native plugins implement `Plugin` and are stored as `Arc<dyn Plugin>` in `PluginRegistry`. The registry owns validation, lookup, configuration, execution accounting, and error normalization; it does not inspect concrete plugin types.

The API is **Preview**. It is currently a source-level Rust extension API, not a stable dynamic ABI. A host application must link and register third-party plugin crates explicitly.

## Generate a plugin

Install [`cargo-generate`](https://cargo-generate.github.io/cargo-generate/) and expand the repository template:

```bash
cargo install cargo-generate
cargo generate \
  --git https://github.com/ITherso/venom \
  --subfolder templates/venom-plugin \
  --name my-venom-plugin
cd my-venom-plugin
cargo test
```

The template asks for a stable plugin ID, implements the complete trait, and includes a registry/execution test. During alpha it tracks Venom `main`; pin the dependency to a tag or commit before publishing.

## Contract

```rust
#[async_trait::async_trait]
pub trait Plugin: Send + Sync {
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
- Hosts must enforce timeout, payload-size, and authorization policies at the execution boundary.

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
