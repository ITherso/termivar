# ADR 0019: Make plugin execution host-owned and evidence-only

- Status: Accepted
- Date: 2026-08-14
- Supersedes: the plugin execution input and structured-finding output decisions in [ADR 0002](0002-plugin-boundary.md)

## Context

The first Preview plugin contract passed loose `target` and `payload` strings to
in-process code and accepted arbitrary `ScanFinding` values in return. The
registry bounded the input string and wall-clock time, but it did not own target
authorization, request accounting, response retention, cancellation,
redaction, or evidence provenance. A plugin could therefore bypass the
deterministic runtime's transport boundary and label a substring match as a
vulnerability.

The repository also exposed six concrete types as built-in vulnerability
scanners. Those types only matched marker strings and returned HIGH or CRITICAL
records. They were trait examples, not verified detectors, and keeping them in
the production namespace made the public surface overstate runtime capability.

ADR 0002 remains authoritative for the source-level Rust trait boundary, linked
registration, API-line negotiation, and the decision not to promise a dynamic
Rust ABI. This record replaces only its execution-input and plugin-output
decisions.

## Decision

Plugin execution receives a host-authorized `PluginContext` materialized by the
registry from a host-created `PluginExecutionRequest`. The context binds one
authorized subject and exact origin, a cancellation token, immutable resource
limits, a host-owned bounded request broker, an evidence recorder, a redaction
policy, and the current correlation/case identity.

Plugins may request transport only through the context broker. Each broker
request carries a capture ceiling equal to the smaller of the per-response
limit and the invocation's unreserved cumulative remainder. The trusted broker
contract forbids redirects and retries, stops collection at that ceiling, and
reports truncation; the context independently validates requested and final
origins, capture metadata, and request/body accounting. The broker does not
expose its underlying HTTP client. Plugins record bounded observations through
the context recorder; the host assigns subject, source, correlation,
reliability, and redaction semantics. A plugin cannot return a finding, an
outcome, or a hypothesis transition. Recorded evidence must pass through host
reasoning and a verifier before any later reporting path can make a stronger
claim.

The registry rejects a duplicate plugin ID without changing the existing
plugin, configuration, or metadata. An entry-scoped invocation lease prevents
unregistration and same-ID replacement until every invocation using that entry
has drained. Public execution configuration contains no retry count while the
trait has no idempotency declaration; a future retry policy requires an
explicit idempotency contract and a separately accounted broker dispatch for
every attempt. Registration and metadata accounting must remain consistent
when clock acquisition or execution fails.

No concrete detector plugin ships in `venom-scanner`. Harmless INFO-only marker
fixtures may live under `examples/plugin-fixtures/`, with names and descriptions
that state they exercise the trait boundary and make no security claim.

## Consequences

- Existing plugins targeting the original Preview API must migrate and
  recompile against the new API line.
- Hosts retain authorization, transport, budget, cancellation, provenance,
  redaction, verification, and finding-projection authority.
- In-process plugins remain trusted native code; a context boundary is not a
  sandbox or crash-isolation mechanism. Timeout and cancellation are
  cooperative, and non-yielding or blocking native code can stall the host;
  there is no CPU, memory, or process isolation.
- A successful plugin invocation means only that the invocation completed. It
  does not mean that an observation was produced or a vulnerability was
  confirmed.
- The stock CLI still does not discover or dynamically load plugin crates.

## Alternatives considered

- Keep `target`/`payload` and document host responsibility: rejected because
  documentation cannot enforce authorization, accounting, or claim ownership.
- Continue accepting `ScanFinding` and downgrade its severity: rejected because
  the output type still grants plugins finding authority before verification.
- Keep the six marker implementations in the production namespace: rejected
  because their names and outputs imply detector behavior they do not prove.
- Add automatic retries immediately: rejected until plugins can explicitly
  declare idempotency and every attempt can be charged and audited.
