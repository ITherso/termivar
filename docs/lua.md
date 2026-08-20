# Lua

Lua support is an optional, Experimental registry scaffold compiled only with
the scanner's independent `lua` feature. It is not enabled by `plugins`, and
neither extension surface is part of a CLI scan runtime. Registered source
loading is not implemented: `LuaScript::execute` fails closed, reports no return
value, and runs no script.

## Intended boundary

`LuaContext`, `LuaExecutionResult`, and `LuaScriptRegistry` model an intended
host boundary. The current implementation registers metadata but does not load
or evaluate registered script files. A future executable host must not give
scripts direct references to runner, registry, event-bus, or transport
internals.

## Controls required before execution exists

- load scripts only from an approved root;
- reject path traversal and symlink escapes;
- cap memory, execution time, output size, and retained history;
- expose an allowlist of host functions;
- do not expose process execution, arbitrary filesystem access, or unrestricted network access;
- attach script ID and version to retained results and audit records;
- fail closed when validation or limit enforcement fails.

## Configuration

`LuaEngineConfig` models retained history, maximum VM memory, and default
timeout. Those values do not turn the current fail-closed registry into an
executable or isolated scripting runtime.

## Compatibility

Lua-facing APIs are not stable in `0.10.0-alpha.1`. Hosts should pin to a Venom
commit and must not treat the current registry as script execution support.
