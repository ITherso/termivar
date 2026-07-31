# Internals

These notes explain the implementation boundaries that contributors most often need before changing execution code. They describe the current alpha behavior, including limitations; they are not promises of a stable internal API.

## Map

```text
ScannerSdk
    |
    v
ScanRunner -----> EventBus
    |
    v
ScanPhase

Plugin host ----> PluginRegistry ----> Plugin::execute

Task producer --> TaskQueue --> WorkerPool --> WorkerNode
```

- [Scheduler](scheduler.md): queue, worker scoring, assignment, retry, and heartbeat boundaries.
- [Event bus](event-bus.md): synchronous publication, subscriptions, history, and correlation.
- [Runner](runner.md): ordered phase execution, timeouts, cancellation, and partial results.
- [Plugin registry](plugin-registry.md): validation, compatibility, lookup, execution, and accounting.

Cross-boundary changes should start in [Architecture Decisions](../adr/README.md). Public contract changes must also follow the [Plugin API policy](../plugin-api-policy.md).
