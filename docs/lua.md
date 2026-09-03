# Lua execution

Lua is an opt-in, Experimental and implemented host-library contract. Build
`termivar-scanner` with the independent `lua` feature to obtain a bounded script
registry and executor. The feature is absent from default, `scanning`,
`legacy-scanner`, `plugins`, and CLI builds; no repository command or plugin
path registers or executes Lua.

These are cooperative in-process controls, not process isolation, an
operating-system sandbox, or a security boundary against a hostile native
process. A host must explicitly
choose an approved source root, construct a registry, register source, supply
context, and call the async execution API.

## Registration and provenance

`LuaScript::new_safe` and `new_safe_with_config` accept UTF-8 text from a
caller-approved root. Registration rejects traversal outside the canonical
root, symbolic-link components, non-regular files, oversized source, and a
file that changes during the bounded read/recheck sequence. The opaque
`LuaScript` retains a private source snapshot; execution never reopens the
path.

These checks assume that the approved root and its ancestors remain trusted
and non-writable by an attacker throughout registration. Filesystem namespace
changes can race canonicalization and reading, so this is a TOCTOU assumption,
not a hostile-writer containment guarantee. Hosts should stage reviewed source
in a dedicated immutable or otherwise access-controlled tree.

Manifests, execution results, and retained receipts expose `source_sha256`.
This is an unkeyed, deterministic, linkable source digest for provenance—not
encryption, redaction, authentication, or confidentiality. Script source must
not contain embedded secrets, and hosts must treat the digest together with
script ID/version as sensitive, pseudonymous metadata.

## VM and host API

Each invocation creates a fresh vendored Lua 5.4 VM with no Lua standard
libraries, applies the configured VM memory ceiling and instruction hook, and
loads one text-mode chunk into a private environment. Binary chunks, ambient
globals, package loading, coroutines, OS, I/O, debug, filesystem, network,
process, and thread access are not exposed.

The private environment contains only:

- `type(value)`;
- `emit(value)` for bounded UTF-8 scalar output; and
- immutable `context.target`, `context.payload`, `context.parameter_count`,
  `context.parameter(key)`, and `context.parameter_at(index)` projections.

The executor accepts zero or one return value. `nil` becomes no value; Boolean,
integer, finite number, and bounded UTF-8 string values project to
`LuaReturnValue`. Tables, functions, threads, userdata, light userdata,
non-finite numbers, invalid UTF-8, over-limit strings, and multiple return
values fail with a typed `LuaExecutionError`. `emit` accepts bounded Boolean,
integer, finite number, and UTF-8 string values and rejects other types.

Context target, payload, parameters, emitted output, and return values are
caller-visible data. Debug projections omit their contents, but that does not
redact values obtained through getters. Hosts must remove secrets before
execution and control downstream storage and logging.

## Budgets, cancellation, and history

`LuaEngineConfig` validates nonzero configurable limits against hard ceilings
for source and total retained source, context fields and aggregate context,
VM memory, instructions and hook interval, wall-clock timeout, output, return
value, scripts, concurrent executions, and retained history entries/bytes.
Registration, admission, execution projection, and history retention fail
closed when their relevant limits cannot be preserved.

Execution runs through Tokio's blocking pool. A monotonic deadline, instruction
ceiling, and cloneable `LuaCancellationToken` are checked by the Lua instruction
hook and again after result projection. These controls are cooperative: the
hook cannot hard-preempt parsing, allocation, a native callback, or a Lua/host
defect between hook checks. Dropping the Rust future does not stop its detached
`spawn_blocking` work; a host that abandons a call must retain and cancel its
token. Calling without a Tokio runtime returns the typed `HostFailure` result.

Registry history retains bounded receipts, not source text, context, output,
return values, or filesystem paths. Receipts still retain status/error,
elapsed time, stable script ID/version, and the linkable source digest. Duration
can be input-dependent, so a receipt is sensitive metadata rather than a
confidential or fully sanitized audit record.

History is a best-effort bounded ring buffer, not a complete or durable audit
log. Entry, per-script-byte, and registry-wide-byte caps silently evict older
receipts. If the host configures a byte cap smaller than one receipt, that
receipt is not retained at all. Hosts that require complete audit retention
must copy receipts into their own bounded, protected persistence contract.

All limits are per registry or per execution. They do not bound source/context
allocation performed by the caller, values cloned out of results, allocator
overhead, the number of registries, or total process memory. Hosts must budget
configured VM memory times concurrency, registry count, caller-owned data, and
ordinary allocator failure.

## Integration boundary

The API provides neither process isolation nor a script service, transport,
authentication, authorization, persistent registry, filesystem watcher,
automatic reload, CLI command, plugin bridge, scanner phase, finding creation,
or verdict authority. A stronger untrusted-code boundary requires a separately
supervised process or comparable OS isolation with its own IPC, resource, and
shutdown contract.

See the [runtime map](internals/runtime-map.md), [scanner feature map](scanner.md),
and [ADR 0022](adr/0022-bound-host-lua-and-distributed-execution.md).
