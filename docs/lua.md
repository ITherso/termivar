# Lua

Lua support is an optional scripting boundary compiled with the scanner's `plugins` feature. It is Preview and should be treated as untrusted-input infrastructure.

## Intended boundary

Lua scripts receive a limited `LuaContext`, produce a `LuaExecutionResult`, and are managed through `LuaScriptRegistry`. Scripts should not receive direct references to runner, registry, event-bus, or transport internals.

## Required controls

- load scripts only from an approved root;
- reject path traversal and symlink escapes;
- cap memory, execution time, output size, and retained history;
- expose an allowlist of host functions;
- do not expose process execution, arbitrary filesystem access, or unrestricted network access;
- attach script ID and version to findings and audit events;
- fail closed when validation or limit enforcement fails.

## Configuration

`LuaEngineConfig` controls retained history, maximum VM memory, and default timeout. Production-like deployments should use explicit values rather than relying on alpha defaults.

## Compatibility

Lua-facing APIs are not stable in `0.9.0-alpha`. Script authors should pin to a Venom commit and include tests. Legacy Lua fixtures are being migrated to the current safe-construction API.
