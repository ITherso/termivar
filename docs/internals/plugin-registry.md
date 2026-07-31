# Plugin registry internals

`PluginRegistry` stores `Arc<dyn Plugin>` values in concurrent maps keyed by stable plugin ID. The registry depends only on the `Plugin` trait; it does not inspect concrete plugin types.

## Registration

Registration performs three steps:

1. compare the plugin's declared API line with `PLUGIN_API_VERSION`;
2. call `Plugin::validate`;
3. snapshot configuration and metadata, then store the trait object.

Preview compatibility currently requires matching major and minor components. Registering the same ID replaces the existing plugin and metadata; callers that need duplicate rejection must check ownership before registration until the contract is tightened.

## Execution

```text
lookup by ID
    |
check enabled
    |
Plugin::execute(target, payload)
    |
normalize result + elapsed time
    |
increment success/error counters
```

A plugin-returned error is represented as a successful registry call containing `success: false` and an error string. Registry-level failures such as a missing, disabled, incompatible, or invalid plugin return `PluginError` directly.

## Current constraints

- Registry configuration records timeout, payload size, retries, and enabled state, but `execute` does not yet enforce those values.
- Plugin execution is in-process with no sandbox or crash isolation.
- There is no runtime discovery, signature verification, capability declaration, or dependency resolution.
- Metrics are process-local counters and reset on restart.
- Target and payload are raw strings rather than a versioned execution context.

These gaps are why the API remains Preview. See [Plugin development](../plugin.md) and the [Plugin API policy](../plugin-api-policy.md) before publishing an external plugin.
