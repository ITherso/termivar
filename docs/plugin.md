# Plugin system

Native plugins implement the `Plugin` trait and are stored as `Arc<dyn Plugin>` in `PluginRegistry`. The registry owns lookup, configuration, execution metrics, and error normalization.

## Contract

```rust
#[async_trait::async_trait]
pub trait Plugin: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn enabled(&self) -> bool;
    async fn execute(
        &self,
        target: &str,
        payload: &str,
    ) -> Result<Vec<ScanFinding>, PluginError>;
}
```

Metadata and validation methods are omitted here for brevity; `src/plugin.rs` is authoritative during the alpha period.

## Design rules

- The runner must not inspect plugin concrete types.
- A plugin communicates through inputs, findings, errors, and public events.
- A plugin must not render reports, start transports, or mutate registry internals.
- Configuration is explicit and serializable where practical.
- Plugin IDs are stable identifiers; display names are not identifiers.
- Timeouts and payload limits must be enforced at the execution boundary.

## Lifecycle

```text
construct → validate → register → execute → collect findings → update metrics
```

## Stability

The plugin API is Preview. Before a stable SDK, Venom needs a dedicated contracts module, capability declarations, API-version negotiation, and compatibility tests for third-party plugins.
