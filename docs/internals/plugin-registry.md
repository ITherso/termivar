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
load the registered host configuration
    |
check trait + host enabled flags
    |
reject payloads above max_payload_size
    |
run Plugin::execute(target, payload) under timeout_ms
    |
normalize result + elapsed time
    |
increment success/error counters
```

A plugin-returned error or elapsed deadline is represented as a successful registry call containing `success: false` and an error string. Registry-level failures such as a missing, disabled, incompatible, invalid, or oversized invocation return `PluginError` directly before plugin code runs. Timeout drops the in-process plugin future and increments the error counter; it is cancellation, not process isolation.

## Current constraints

- Registry execution enforces `timeout_ms`, `max_payload_size`, and the host-side `enabled` flag. `retry_count` remains reserved metadata: the registry does not automatically replay a potentially side-effecting plugin call.
- Plugin execution is in-process with no sandbox or crash isolation.
- A plugin can still create its own network client. This legacy registry is not covered by the standard runtime's host-owned request broker or `RuntimeBudget` accounting.
- There is no runtime discovery, signature verification, capability declaration, or dependency resolution.
- Metrics are process-local counters and reset on restart.
- Target and payload are raw strings rather than a versioned execution context.

These gaps are why the API remains Preview. See [Plugin development](../plugin.md) and the [Plugin API policy](../plugin-api-policy.md) before publishing an external plugin.
