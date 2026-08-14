# Plugin registry internals

`PluginRegistry` stores linked `Arc<dyn Plugin>` implementations by stable
plugin ID. It depends on the trait rather than concrete plugin types. No stock
detectors are registered, and the stock CLI does not discover crates or shared
libraries at runtime.

## Registration

Registration is a fail-closed transaction:

1. validate the non-empty plugin identity and declared API line;
2. run `Plugin::validate` and snapshot host configuration and metadata;
3. reject an existing ID without changing its plugin, configuration, or
   metadata;
4. publish one consistent registered entry.

Preview compatibility requires matching major and minor components. Timestamp
acquisition is fallible and cannot panic registration. Unregistration removes
the complete entry rather than coordinating independent maps. Each execution
acquires an entry-scoped lease while the registry shard is held; unregistering
an in-use entry fails, preventing same-ID replacement from rebinding an older
invocation's provenance or statistics.

## Host context

The host constructs a `PluginExecutionRequest` for every authorized invocation.
The registry validates it and materializes a `PluginContext` that binds the
subject, exact origin, case/correlation identity, cancellation, immutable
budget, bounded request broker, evidence recorder, and redaction policy. A
plugin receives no loose target/payload pair.

The request broker is the plugin contract's only transport authority. For each
dispatch, the context supplies a capture ceiling equal to the smaller of the
per-response limit and the invocation's unreserved cumulative remainder. The
trusted broker contract forbids redirects and retries, requires collection to
stop at that ceiling, and reports delivered bytes and truncation. The context
independently validates the requested and final response origins, capture
metadata, and request/body accounting before returning bounded data.
Cancellation and deadline are host policy, not target observations.

The recorder accepts observation drafts, then applies host-owned subject,
source, correlation, reliability, size/count bounds, and redaction. It does not
accept `ScanFinding`, `Outcome`, or a hypothesis transition.

## Execution

```text
lookup registered entry
    |
check trait + host enabled policy
    |
validate host-built PluginExecutionRequest
    |
materialize invocation PluginContext
    |
run Plugin::execute(context) under cancellation + deadline
    |
seal bounded recorded observations
    |
return execution receipt and update metadata
```

A plugin error, cancellation, or elapsed deadline records a failed invocation.
Pre-execution policy rejection does not call plugin code. Execution success
means only that the invocation completed; an empty observation set is valid.
The registry never promotes evidence to a finding.

There is no automatic retry. The removed `retry_count` field had no idempotency
semantics and performed no work. A future retry design must require an explicit
idempotency declaration and account every broker attempt independently.

## Claim path

```text
plugin observation
      |
      v
host evidence recorder
      |
      v
knowledge / reasoning
      |
      v
host verifier
      |
      v
optional finding projection
```

The last edge is owned by the host's verified reporting path. No repository
plugin fixture installs a reasoning rule or verifier, so executing a fixture
cannot create a confirmed finding.

## Current constraints

- Plugin execution is trusted native code in the host process; the context is
  not a sandbox or crash-isolation mechanism. Timeout and cancellation are
  cooperative, so a non-yielding async poll or blocking native call can stall
  the host thread. There is no CPU, memory, or process isolation.
- There is no runtime discovery, signature verification, capability
  declaration, dependency resolution, or stable ABI.
- Metrics are process-local and reset on restart.
- Plugin execution is separate from both stock CLI scan orchestration paths.
- A malicious linked crate could ignore the contract and use capabilities it
  compiled for itself. Hosts must review and trust native plugin code.

See [Plugin development](../plugin.md), the
[Plugin API policy](../plugin-api-policy.md), and
[ADR 0019](../adr/0019-host-own-plugin-execution.md).
