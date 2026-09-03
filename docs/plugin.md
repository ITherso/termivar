# Plugin SDK preview

Native plugins implement `Plugin` and are linked into a host that registers
them with `PluginRegistry`. The API is a source-level Rust **Preview**, not a
stable dynamic ABI, and the stock CLI does not discover arbitrary plugin crates
at runtime. The current Preview API line is `0.2.0`.

Termivar ships no detector plugins. The six former SQL, XSS, LFI, XXE, SSRF, and
SSTI marker types were removed from the production namespace because substring
matches did not verify vulnerabilities. The harmless types under
[`examples/plugin-fixtures/`](https://github.com/ITherso/venom/tree/main/examples/plugin-fixtures) exist only
to exercise this trait boundary.

Compatibility is defined in the [Plugin API and SemVer policy](plugin-api-policy.md).
The host rejects plugins targeting another Preview API line before execution.

## Generate a plugin

Install [`cargo-generate`](https://cargo-generate.github.io/cargo-generate/)
and expand the repository template:

```bash
cargo install cargo-generate
cargo xtask generate plugin my-termivar-plugin
cd my-termivar-plugin
cargo test
```

The template records one fixed INFO observation to demonstrate the API. It is
not a detector and makes no security claim. During alpha the generated
dependency tracks Termivar `main`; pin it to a tag or commit before publishing.

## Host-owned execution

A plugin no longer receives loose `target` and `payload` strings. The host
creates one `PluginExecutionRequest` for an authorized invocation; the registry
validates it and materializes the `PluginContext` passed to the plugin. That
immutable boundary binds:

- the authorized subject and exact origin;
- cancellation and the current correlation/case identity;
- request, body, observation, and execution limits;
- a host-owned bounded request broker;
- an evidence recorder and redaction policy.

The registry validates the API line and plugin self-check, rejects duplicate IDs
without replacing existing state, applies the host enable flag and deadline,
and updates one consistent metadata record. There is no automatic retry: the
public config does not advertise a retry count while the trait has no
idempotency contract.

A conforming plugin performs network work only through the context broker and
records observations through the context recorder. It cannot return
`ScanFinding`, `Outcome`, or a hypothesis transition. The host owns subject,
source, correlation, reliability, redaction, knowledge insertion, verification,
and any later finding projection.

For each request, the context derives a response-capture ceiling as the smaller
of the per-response limit and the invocation's unreserved cumulative remainder.
The trusted broker contract forbids redirects and retries, requires body
collection to stop at that ceiling, and reports truncation. The context
independently validates both request and final-response origin, capture
metadata, and accounting before returning the response to plugin code.

```text
host authorization + case
          |
          v
   PluginContext
      |       |
      |       +----> bounded request broker
      v
 Plugin::execute
      |
      v
 evidence recorder ---> host reasoning / verification ---> optional reporting
```

Successful execution means that the trait call completed. It does not mean an
observation was recorded, a hypothesis was supported, or a vulnerability was
confirmed.

## Register and execute

The generated crate includes a complete registration/execution test using a
local, no-I/O host context. See its source for the exact constructors on the
current Preview API line:

- [`templates/termivar-plugin/src/lib.rs`](https://github.com/ITherso/venom/blob/main/templates/termivar-plugin/src/lib.rs)
- [`examples/custom_plugin.rs`](https://github.com/ITherso/venom/blob/main/examples/custom_plugin.rs)

Hosts must construct authorization, budgets, request policy, cancellation,
redaction, and correlation explicitly. Do not synthesize those values inside a
plugin or infer authorization from same-origin alone.

## Design rules

- Registry and host code call the `Plugin` trait; they do not branch on a
  concrete fixture or plugin type.
- Plugin IDs are stable machine identities. Duplicate registration fails.
  Unregistration also fails while that exact entry has an invocation in
  flight, so the ID cannot be rebound around an older execution receipt.
- Plugins record bounded observations. They do not render reports or declare
  findings, outcomes, hypotheses, severities, or vulnerability status.
- Plugin transport goes through the host broker. A broker scope rejection is a
  policy result, not evidence about the target.
- Raw or sensitive values are subject to host redaction before evidence is
  retained. Plugins must not copy them into errors, IDs, metadata, or logs.
- Cancellation, deadline, request limits, and body limits fail closed. Work
  already charged at the broker boundary is not refunded.
- Native plugins execute in-process. The context is an authority contract, not
  a sandbox or crash-isolation mechanism; hosts must trust linked plugin code.
  Timeout and cancellation are cooperative: a non-yielding async poll or
  blocking native call can stall its host thread. The API provides no CPU,
  memory, or process isolation.

## Lifecycle

```text
generate -> implement -> test -> validate -> register -> execute
                                                     -> record observations
                                                     -> host verification
```

## Stable SDK exit criteria

- Define capability declarations and compatibility tests across released SDK
  versions.
- Publish a scanner/plugin compatibility baseline and migration window.
- Decide whether a future runtime plugin format is linked, process-isolated,
  WebAssembly-based, or another sandboxed form.
- Define signing, trust, discovery, and dependency-resolution policy before any
  dynamic loading claim.

See [ADR 0019](adr/0019-host-own-plugin-execution.md) for the execution and
claim-ownership decision.
