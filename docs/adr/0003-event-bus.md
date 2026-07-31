# ADR 0003: Separate event contracts from event delivery

- Status: Accepted
- Date: 2026-07-31

## Context

CLI output, dashboards, telemetry, distributed workers, and reports need scan lifecycle facts. If event payloads depend on scanner behavior, lower-level consumers cannot share them and event delivery can become a hidden execution-control channel.

## Decision

`Event`, `EventType`, `EventSeverity`, and `EventBuilder` are transport-neutral contracts in `venom-core`. `EventBus` and subscription behavior remain in `venom-scanner`. Events describe immutable lifecycle facts; subscribers observe them and do not control runner execution through callbacks.

Event wire names and schema versions are explicit. Cancellation and scheduling use dedicated contracts instead of special event handlers.

## Consequences

- API, proxy, scanner, and product layers share one event vocabulary without a reverse dependency.
- Event delivery can be replaced without changing serialized contracts.
- Consumers must tolerate new event variants and schema versions.
- Commands and state mutation require explicit APIs rather than event side effects.

## Alternatives considered

- Scanner-owned event payloads: rejected because they leak behavior into shared types.
- One global command/event channel: rejected because facts and commands have different reliability and authorization requirements.
