# Event bus internals

`EventBus` is an in-process publish/subscribe component shared through `Arc`. Subscribers are grouped by `EventType` in a concurrent map, and published events are retained in an in-memory history grouped by type.

## Publication path

```text
Event
  |-- increment total count
  |-- append to per-type history
  `-- invoke matching handlers in the publisher's thread
```

Handlers are synchronous `Fn(&Event)` callbacks. A slow handler delays the publisher. A panicking handler can unwind through `publish`; panic isolation and asynchronous delivery are not implemented by the current bus. Handlers must therefore stay fast, non-blocking, and panic-free.

## Correlation and ordering

- Every event has an event ID, correlation ID, timestamp, version, source, severity, type, and string data map.
- Correlation queries scan all retained history.
- `get_events_sorted` sorts a snapshot by timestamp.
- `get_all_events` does not promise cross-type insertion order.
- `clear_history` removes retained events but does not reset the lifetime event counter.

## Lifecycle and limits

History is unbounded until explicitly cleared. There is no persistence, replay cursor, backpressure, delivery acknowledgement, or cross-process transport. Hosts that need those properties should subscribe with a small adapter and move work to a bounded external queue.

Adding a durable broker must not change the domain `Event` contract merely to expose a transport implementation. Record such a boundary change in an ADR.
